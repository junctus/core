//! `neo-routing` — path selection and circuit construction.
//!
//! Picks node-disjoint paths through a set of known relays, freshly randomized
//! **per request** so no two requests share a route, and picks *disjoint* paths
//! for the k-of-n shares of a sliced flow (see `neo-slicing`) so no relay sees
//! more than one fragment.
//!
//! M2 uses a static relay list and OS randomness. Milestone M11 replaces the
//! randomness with a **VRF** so selection is verifiably unbiasable and an
//! adversary cannot herd a client onto attacker-controlled paths.

#![forbid(unsafe_code)]

use neo_core::net::{group_by_subnet, prioritize_distinct_subnets, SubnetKey};
use neo_core::{Error, NodeId, Result};

pub mod exit;
pub use exit::{Destination, ExitPolicy, ExitSelector, RouteRegistry};

/// A known relay that can carry (a layer of) neo traffic.
#[derive(Clone, Debug)]
pub struct Relay {
    /// The relay's stable node identifier (also its Sphinx routing address).
    pub id: NodeId,
    /// The relay's X25519 public key, raw bytes (for classical key agreement).
    pub kex: [u8; 32],
    /// The relay's Ristretto routing key, raw bytes (for Sphinx).
    pub sphinx: [u8; 32],
    /// A dialable transport address (e.g. `host:port`).
    pub addr: String,
}

impl Relay {
    /// The relay's subnet ([`SubnetKey`]) for Sybil-diversity checks (M36), or an
    /// empty vector if its address is not an IP literal. Shaped for
    /// [`prioritize_distinct_subnets`].
    pub(crate) fn subnet_keys(&self) -> Vec<SubnetKey> {
        SubnetKey::from_addr(&self.addr).into_iter().collect()
    }

    /// The relay's single subnet, if its address is an IP literal.
    pub(crate) fn subnet(&self) -> Option<SubnetKey> {
        SubnetKey::from_addr(&self.addr)
    }
}

/// A static set of relays to route through.
#[derive(Clone, Debug, Default)]
pub struct Router {
    relays: Vec<Relay>,
}

impl Router {
    /// Build a router over a fixed relay set.
    ///
    /// **Deduplicates by `NodeId`**: the node-disjoint guarantee is what stops a
    /// single relay from ever holding ≥ 2 of a flow's k shares. Selection is
    /// disjoint over *indices*, so a relay list containing one identity twice
    /// (e.g. a Sybil advertising two addresses) could otherwise place the same
    /// node on two "disjoint" paths. Keeping the first entry per id makes
    /// index-disjoint imply node-disjoint.
    pub fn new(relays: Vec<Relay>) -> Self {
        let mut seen = std::collections::HashSet::new();
        let relays = relays.into_iter().filter(|r| seen.insert(r.id)).collect();
        Self { relays }
    }

    /// Number of known relays.
    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// Whether the relay set is empty.
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// Select one fresh, node-disjoint path of `hops` relays.
    pub fn select_path(&self, hops: usize) -> Result<Vec<Relay>> {
        if hops == 0 {
            return Err(Error::Config("a path needs at least one hop".into()));
        }
        if hops > self.relays.len() {
            return Err(Error::Config(format!(
                "need {hops} relays for a path, know only {}",
                self.relays.len()
            )));
        }
        let order = shuffled_indices(self.relays.len())?;
        let shuffled: Vec<Relay> = order.into_iter().map(|i| self.relays[i].clone()).collect();
        // Front-load subnet-distinct relays so the chosen hops span as many /24s as
        // available (M36) — one operator shouldn't own two hops of a circuit.
        let diverse = prioritize_distinct_subnets(shuffled, Relay::subnet_keys);
        Ok(diverse.into_iter().take(hops).collect())
    }

    /// Select `paths` mutually node-disjoint paths of `hops` relays each.
    ///
    /// Used to route the k-of-n shares of one flow so no relay handles more than
    /// one share. Requires at least `paths * hops` known relays.
    pub fn select_disjoint_paths(&self, paths: usize, hops: usize) -> Result<Vec<Vec<Relay>>> {
        if paths == 0 || hops == 0 {
            return Err(Error::Config("paths and hops must be > 0".into()));
        }
        let needed = paths
            .checked_mul(hops)
            .ok_or_else(|| Error::Config("path count overflow".into()))?;
        if needed > self.relays.len() {
            return Err(Error::Config(format!(
                "need {needed} distinct relays for {paths} disjoint {hops}-hop paths, know only {}",
                self.relays.len()
            )));
        }
        let order = shuffled_indices(self.relays.len())?;
        let shuffled: Vec<Relay> = order.into_iter().map(|i| self.relays[i].clone()).collect();
        // For k-of-n shares each path carries one share, so the leak to avoid is an
        // operator straddling *two* paths (it would see two shares). Grouping
        // same-subnet relays contiguously before chunking keeps each subnet inside
        // a single path when possible, minimizing that cross-path spread. When at
        // least `paths * hops` distinct subnets exist the paths are fully
        // subnet-disjoint; with fewer, collisions are confined to as few paths as
        // possible rather than smeared across all of them (an operator repeated
        // within one path still sees only that path's single share). Best-effort —
        // never fails on a small network. Note: front-loading distinct subnets
        // here (the single-path strategy) would be *wrong* — it spreads each subnet
        // across paths, the opposite of what shares want.
        let grouped = group_by_subnet(shuffled, Relay::subnet_keys);
        Ok(grouped
            .chunks(hops)
            .take(paths)
            .map(|chunk| chunk.to_vec())
            .collect())
    }

    /// Select a path *deterministically* from a 32-byte seed — e.g. a VRF output
    /// (see `neo-verify`). Because the seed is verifiable and unbiasable, the
    /// chosen path is reproducible and cannot be ground by an adversary (M11).
    ///
    /// The permutation is driven by a keyed BLAKE3 XOF over the **full 32-byte**
    /// seed with rejection sampling — so all 256 bits of VRF entropy bind the
    /// path (a 64-bit PRNG could not even reach most permutations once there are
    /// ≳21 relays) and there is no modulo bias.
    pub fn select_path_seeded(&self, seed: &[u8; 32], hops: usize) -> Result<Vec<Relay>> {
        if hops == 0 {
            return Err(Error::Config("a path needs at least one hop".into()));
        }
        if hops > self.relays.len() {
            return Err(Error::Config(format!(
                "need {hops} relays for a path, know only {}",
                self.relays.len()
            )));
        }
        let n = self.relays.len();
        let mut reader = blake3::Hasher::new_keyed(seed).finalize_xof();
        let mut order: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            let j = draw_below(&mut reader, i as u64 + 1) as usize;
            order.swap(i, j);
        }
        let permuted: Vec<Relay> = order.into_iter().map(|i| self.relays[i].clone()).collect();
        // Subnet diversity is applied as a deterministic reorder of the seeded
        // permutation, so the result stays reproducible and VRF-verifiable: a
        // verifier with the same relay set and seed derives the same path (M36).
        let diverse = prioritize_distinct_subnets(permuted, Relay::subnet_keys);
        Ok(diverse.into_iter().take(hops).collect())
    }
}

/// Draw a uniform value in `0..bound` from a BLAKE3 XOF with rejection sampling
/// (no modulo bias). `bound` is small (a relay count), so rejections are rare.
fn draw_below(reader: &mut blake3::OutputReader, bound: u64) -> u64 {
    debug_assert!(bound > 0);
    // Largest multiple of `bound` that fits in u64; reject draws at or above it.
    let limit = u64::MAX - (u64::MAX % bound);
    loop {
        let mut b = [0u8; 8];
        reader.fill(&mut b);
        let v = u64::from_le_bytes(b);
        if v < limit {
            return v % bound;
        }
    }
}

/// A uniformly random permutation of `0..n` from OS randomness (Fisher–Yates).
fn shuffled_indices(n: usize) -> Result<Vec<usize>> {
    let mut idx: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rand_below(i + 1)?;
        idx.swap(i, j);
    }
    Ok(idx)
}

/// A random value in `0..bound`. Modulo bias is negligible for realistic relay
/// counts; M11's VRF selection replaces this with a verifiable construction.
pub(crate) fn rand_below(bound: usize) -> Result<usize> {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
    Ok((u64::from_le_bytes(b) % bound as u64) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_core::NodeIdentity;

    fn relays(n: usize) -> Vec<Relay> {
        (0..n)
            .map(|i| {
                let id = NodeIdentity::generate().unwrap();
                let pubkey = id.public();
                Relay {
                    id: pubkey.id,
                    kex: *pubkey.kex.as_bytes(),
                    sphinx: pubkey.sphinx,
                    addr: format!("10.0.0.{i}:9000"),
                }
            })
            .collect()
    }

    /// One relay per entry; the entry is the /24's third octet, so equal entries
    /// share a subnet and distinct entries are distinct /24s. The host octet varies
    /// with the index so node ids (and addresses) are always distinct.
    fn relays_in_subnets(subnets: &[u8]) -> Vec<Relay> {
        subnets
            .iter()
            .enumerate()
            .map(|(i, &s)| {
                let id = NodeIdentity::generate().unwrap();
                let pubkey = id.public();
                Relay {
                    id: pubkey.id,
                    kex: *pubkey.kex.as_bytes(),
                    sphinx: pubkey.sphinx,
                    addr: format!("10.0.{s}.{i}:9000"),
                }
            })
            .collect()
    }

    fn distinct_subnets(relays: &[Relay]) -> usize {
        relays
            .iter()
            .filter_map(|r| SubnetKey::from_addr(&r.addr))
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    #[test]
    fn path_has_requested_length_and_is_distinct() {
        let router = Router::new(relays(8));
        let path = router.select_path(3).unwrap();
        assert_eq!(path.len(), 3);
        let ids: std::collections::HashSet<_> = path.iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), 3, "hops within a path must be distinct");
    }

    #[test]
    fn path_needs_enough_relays() {
        let router = Router::new(relays(2));
        assert!(router.select_path(3).is_err());
    }

    #[test]
    fn duplicate_node_ids_are_deduplicated() {
        // The same relay listed twice must not let index-disjoint selection put
        // one node on two "disjoint" paths.
        let base = relays(1).pop().unwrap();
        let dup = base.clone();
        let router = Router::new(vec![base, dup]);
        assert_eq!(router.len(), 1, "duplicate NodeId collapsed to one relay");
    }

    #[test]
    fn disjoint_paths_share_no_relays() {
        let router = Router::new(relays(9));
        let paths = router.select_disjoint_paths(3, 3).unwrap();
        assert_eq!(paths.len(), 3);
        let mut seen = std::collections::HashSet::new();
        for path in &paths {
            assert_eq!(path.len(), 3);
            for relay in path {
                assert!(seen.insert(relay.id), "paths must be node-disjoint");
            }
        }
        assert_eq!(seen.len(), 9);
    }

    #[test]
    fn seeded_path_is_deterministic_and_verifiable() {
        let router = Router::new(relays(8));
        let seed = [7u8; 32];
        let path_a = router.select_path_seeded(&seed, 3).unwrap();
        let path_b = router.select_path_seeded(&seed, 3).unwrap();
        let ids = |p: &[Relay]| p.iter().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(
            ids(&path_a),
            ids(&path_b),
            "same seed reproduces the same path"
        );
        assert_eq!(path_a.len(), 3);

        let hops: std::collections::HashSet<_> = path_a.iter().map(|r| r.id).collect();
        assert_eq!(hops.len(), 3, "hops are distinct");
    }

    #[test]
    fn path_prefers_distinct_subnets_when_available() {
        // 6 relays across 5 distinct /24s (two collide in subnet 1); a 4-hop path
        // should land in 4 distinct subnets.
        let router = Router::new(relays_in_subnets(&[1, 1, 2, 3, 4, 5]));
        let path = router.select_path_seeded(&[9u8; 32], 4).unwrap();
        assert_eq!(distinct_subnets(&path), 4, "path spans 4 distinct /24s");
    }

    #[test]
    fn disjoint_share_paths_prefer_distinct_subnets() {
        // The k-of-n case: two disjoint 3-hop paths across 6 distinct /24s must not
        // route two shares through one operator's subnet.
        let router = Router::new(relays_in_subnets(&[1, 2, 3, 4, 5, 6]));
        let paths = router.select_disjoint_paths(2, 3).unwrap();
        let all: Vec<Relay> = paths.into_iter().flatten().collect();
        assert_eq!(
            distinct_subnets(&all),
            6,
            "all six share-hops in distinct /24s"
        );
    }

    #[test]
    fn disjoint_share_paths_confine_collisions_when_subnets_are_scarce() {
        // Review finding H1: with only 3 subnets for 2×3 hops, full disjointness is
        // impossible — but grouping must keep each operator inside ONE path (so it
        // sees one share), never spread across both (two shares to correlate).
        for _ in 0..64 {
            let router = Router::new(relays_in_subnets(&[1, 1, 2, 2, 3, 3]));
            let paths = router.select_disjoint_paths(2, 3).unwrap();
            let subnets_of = |p: &[Relay]| -> std::collections::HashSet<SubnetKey> {
                p.iter()
                    .filter_map(|r| SubnetKey::from_addr(&r.addr))
                    .collect()
            };
            let a = subnets_of(&paths[0]);
            let b = subnets_of(&paths[1]);
            let straddlers = a.intersection(&b).count();
            // 3 subnets, 2 paths of 3 distinct hops → exactly one subnet must be
            // shared, but never more than one.
            assert!(
                straddlers <= 1,
                "at most one operator may span both share-paths, got {straddlers}"
            );
        }
    }

    #[test]
    fn selection_falls_back_when_subnets_are_exhausted() {
        // All four relays share one /24: diversity is impossible, but a full path
        // must still be built (best-effort, not a hard filter).
        let router = Router::new(relays_in_subnets(&[9, 9, 9, 9]));
        let path = router.select_path(3).unwrap();
        assert_eq!(path.len(), 3, "still builds a full path with no diversity");
        let ids: std::collections::HashSet<_> = path.iter().map(|r| r.id).collect();
        assert_eq!(
            ids.len(),
            3,
            "hops remain node-distinct even without subnet diversity"
        );
    }
}
