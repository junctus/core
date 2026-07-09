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

/// A static set of relays to route through.
#[derive(Clone, Debug, Default)]
pub struct Router {
    relays: Vec<Relay>,
}

impl Router {
    /// Build a router over a fixed relay set.
    pub fn new(relays: Vec<Relay>) -> Self {
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
        Ok(order
            .into_iter()
            .take(hops)
            .map(|i| self.relays[i].clone())
            .collect())
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
        Ok(order
            .chunks(hops)
            .take(paths)
            .map(|chunk| chunk.iter().map(|&i| self.relays[i].clone()).collect())
            .collect())
    }

    /// Select a path *deterministically* from a 32-byte seed — e.g. a VRF output
    /// (see `neo-verify`). Because the seed is verifiable and unbiasable, the
    /// chosen path is reproducible and cannot be ground by an adversary (M11).
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
        let mut state = u64::from_le_bytes(seed[..8].try_into().expect("32-byte seed"));
        let n = self.relays.len();
        let mut order: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            let j = (splitmix64(&mut state) % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }
        Ok(order
            .into_iter()
            .take(hops)
            .map(|i| self.relays[i].clone())
            .collect())
    }
}

/// A small deterministic PRNG (SplitMix64) for reproducible seeded selection.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
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
}
