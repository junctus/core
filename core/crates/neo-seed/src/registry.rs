//! The witnessed relay registry.
//!
//! Holds the relay records this seed has verified and (optionally) confirmed
//! reachable, and mints signed [`SignedSnapshot`]s over them. A record is only
//! admitted if it is self-certifying and node-signed; it is only *attested* if
//! a dial-back handshake proved the operator controls the advertised address
//! and the record's signing key. Everything is in memory — a seed holds no
//! durable user state.

use std::collections::HashMap;

use neo_core::net::SubnetKey;
use neo_core::{NodeId, NodeIdentity, Result};
use neo_discovery::snapshot::{SignedSnapshot, Snapshot};
use neo_discovery::{now_unix, PeerRecord};

/// How long a freshly signed snapshot stays valid (seconds).
pub const SNAPSHOT_TTL: u64 = 3600;
/// Consecutive failed health checks before a relay is dropped.
pub const MAX_STRIKES: u32 = 3;
/// Maximum relays a seed will hold, bounding memory against a registration flood.
/// New registrations beyond this are refused until entries age out (strikes /
/// expiry); already-known relays may still refresh.
pub const MAX_ENTRIES: usize = 100_000;
/// Maximum relays the seed will *attest* per public subnet (M36). Registration is
/// unbounded (up to [`MAX_ENTRIES`]), but only this many relays per IPv4 /24 or
/// IPv6 /64 are listed in a snapshot, so one network can't flood the set clients
/// pick circuit hops from. A generous small cluster is allowed; a flood is not.
/// This is a coarse anti-Sybil measure — an adversary spanning many /24s defeats
/// it. Loopback / internal addresses (dev/test only; never dial-back-attestable in
/// production) are exempt so they aren't collapsed into one subnet.
pub const MAX_ATTESTED_PER_SUBNET: usize = 2;

/// A registry entry: the record plus this seed's health accounting.
#[derive(Clone, Debug)]
struct Entry {
    record: PeerRecord,
    /// Whether the last dial-back health check succeeded.
    healthy: bool,
    /// Consecutive failed checks; at [`MAX_STRIKES`] the entry is dropped.
    strikes: u32,
    /// The advertised address the last dial-back actually verified. Only this
    /// address is *proven* to belong to the operator, so only **its** subnet may
    /// count toward the per-subnet cap — a record can pad `addrs` with IPs in a
    /// victim's /24 it does not control, and those must never be counted (M36).
    verified_addr: Option<String>,
    /// When this identity was first admitted (unix seconds). The per-subnet cap
    /// keeps the earliest-registered relays, so a freshly-ground low node-id can't
    /// displace an established incumbent that shares its subnet.
    registered_at: u64,
}

/// A verified, health-tracked set of relay records.
#[derive(Default)]
pub struct Registry {
    entries: HashMap<NodeId, Entry>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of known relays (healthy or not).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry holds no relays.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Admit or refresh a record. Verifies it (self-certification, signature,
    /// expiry) and requires the `relay` flag; rejects a stale `seq`. A new
    /// entry starts unhealthy — it is not attested until a health check
    /// confirms it. Refreshing an existing healthy relay preserves its health
    /// so a re-registration doesn't briefly drop it from snapshots.
    ///
    /// Returns `true` if the record was stored (new or newer).
    pub fn admit(&mut self, record: PeerRecord) -> Result<bool> {
        // Registration requires the full record (with its ML-KEM key): the seed
        // keeps full records so it can both serve the DHT and derive the compact
        // snapshot form. A compact record here would carry no key to attest.
        record.verify_full(now_unix())?;
        if !record.relay {
            return Err(neo_core::Error::Config(
                "only relay-capable records may register with a seed".into(),
            ));
        }
        match self.entries.get(&record.id) {
            Some(existing) if existing.record.seq >= record.seq => Ok(false),
            Some(existing) => {
                let healthy = existing.healthy;
                let registered_at = existing.registered_at;
                // Keep the verified address only if the refreshed record still
                // advertises it; otherwise it must be re-proven by a dial-back.
                let verified_addr = existing
                    .verified_addr
                    .clone()
                    .filter(|a| record.addrs.contains(a));
                self.entries.insert(
                    record.id,
                    Entry {
                        record,
                        healthy,
                        strikes: 0,
                        verified_addr,
                        registered_at,
                    },
                );
                Ok(true)
            }
            None => {
                if self.entries.len() >= MAX_ENTRIES {
                    return Err(neo_core::Error::Config(
                        "seed registry is at capacity".into(),
                    ));
                }
                self.entries.insert(
                    record.id,
                    Entry {
                        record,
                        healthy: false,
                        strikes: 0,
                        verified_addr: None,
                        registered_at: now_unix(),
                    },
                );
                Ok(true)
            }
        }
    }

    /// All records due a health check: every known relay whose record hasn't
    /// expired. Returned as owned clones so the check can run without holding
    /// a lock on the registry.
    pub fn due_for_check(&self) -> Vec<PeerRecord> {
        let now = now_unix();
        self.entries
            .values()
            .filter(|e| !e.record.is_expired(now))
            .map(|e| e.record.clone())
            .collect()
    }

    /// Record the outcome of a health check. `verified_addr` is the address the
    /// dial-back actually completed a handshake against (`Some`) or `None` on
    /// failure. A success clears strikes, marks the relay attestable, and records
    /// the proven address; [`MAX_STRIKES`] consecutive failures evict it entirely.
    pub fn record_health(&mut self, id: &NodeId, verified_addr: Option<String>) {
        if let Some(entry) = self.entries.get_mut(id) {
            match verified_addr {
                Some(addr) => {
                    entry.healthy = true;
                    entry.strikes = 0;
                    entry.verified_addr = Some(addr);
                }
                None => {
                    entry.healthy = false;
                    entry.strikes += 1;
                    if entry.strikes >= MAX_STRIKES {
                        self.entries.remove(id);
                    }
                }
            }
        }
    }

    /// Drop expired records (called periodically).
    pub fn prune_expired(&mut self) {
        let now = now_unix();
        self.entries.retain(|_, e| !e.record.is_expired(now));
    }

    /// The healthy, unexpired relay records this seed will attest to, in
    /// **canonical ascending-id order**. The order is deterministic (not
    /// HashMap iteration order) so a snapshot re-signs to byte-identical bodies
    /// across restarts, and so a client reconstructing a set from a diff and the
    /// seed that signed it agree on the exact bytes the witnesses signed.
    ///
    /// Applies the per-subnet Sybil cap (M36): at most [`MAX_ATTESTED_PER_SUBNET`]
    /// relays per public subnet. The cap counts a relay against **only the subnet
    /// of the address its dial-back verified** — never an unverified advertised
    /// address, which a record could set to a victim's /24 to evict honest relays
    /// there. Cap slots go to the earliest-registered relays, so a freshly-ground
    /// low node-id can't displace an established incumbent sharing its subnet.
    pub fn attestable(&self) -> Vec<PeerRecord> {
        let now = now_unix();
        let mut healthy: Vec<(u64, PeerRecord, Option<SubnetKey>)> = self
            .entries
            .values()
            .filter(|e| e.healthy && !e.record.is_expired(now))
            .map(|e| (e.registered_at, e.record.clone(), verified_subnet(e)))
            .collect();
        // Process oldest-first (id as a stable tiebreak) so incumbents keep the
        // scarce per-subnet slots.
        healthy.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.id.as_bytes().cmp(b.1.id.as_bytes()))
        });
        let mut per_subnet: HashMap<SubnetKey, usize> = HashMap::new();
        let mut kept: Vec<PeerRecord> = healthy
            .into_iter()
            .filter_map(|(_, record, subnet)| match subnet {
                // No verified *public* subnet (loopback/dev, or not yet re-verified
                // after an address change) → not counted against any subnet.
                None => Some(record),
                Some(s) => {
                    let count = per_subnet.entry(s).or_insert(0);
                    if *count >= MAX_ATTESTED_PER_SUBNET {
                        None
                    } else {
                        *count += 1;
                        Some(record)
                    }
                }
            })
            .collect();
        // Canonical ascending-id order for deterministic snapshot bytes.
        kept.sort_unstable_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
        kept
    }

    /// Build a snapshot of the attestable relays and sign it as `witness`.
    pub fn sign_snapshot(&self, witness: &NodeIdentity) -> SignedSnapshot {
        let now = now_unix();
        let snapshot = Snapshot {
            created_at: now,
            expires_at: now + SNAPSHOT_TTL,
            relays: self.attestable(),
        };
        let signatures = vec![snapshot.sign(witness)];
        SignedSnapshot {
            snapshot,
            signatures,
        }
    }
}

/// The subnet an entry counts against for the per-subnet cap: the subnet of the
/// address its dial-back **verified**, or `None` if that address is not a public
/// IP literal (loopback / internal dev addresses are exempt) or nothing has been
/// verified yet. Crucially this is *not* derived from all advertised addresses —
/// only the proven one — so a record can't pad its `addrs` with a victim's /24 to
/// consume that subnet's cap slots (M36, review finding C1).
fn verified_subnet(entry: &Entry) -> Option<SubnetKey> {
    let addr = entry.verified_addr.as_ref()?;
    if !neo_core::net::is_safe_dial_target(addr, false) {
        return None;
    }
    SubnetKey::from_addr(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_record(identity: &NodeIdentity, seq: u64) -> PeerRecord {
        PeerRecord::build_signed(
            identity,
            vec!["127.0.0.1:9000".into()],
            true,
            false,
            now_unix() + 3600,
            seq,
        )
        .unwrap()
    }

    fn relay_record_at(identity: &NodeIdentity, addr: &str, seq: u64) -> PeerRecord {
        PeerRecord::build_signed(
            identity,
            vec![addr.into()],
            true,
            false,
            now_unix() + 3600,
            seq,
        )
        .unwrap()
    }

    #[test]
    fn admits_verified_relays_and_tracks_health() {
        let mut reg = Registry::new();
        let id = NodeIdentity::generate().unwrap();
        assert!(reg.admit(relay_record(&id, 1)).unwrap());

        // Not attestable until a health check passes.
        assert!(reg.attestable().is_empty());
        reg.record_health(&id.id(), Some("127.0.0.1:9000".into()));
        assert_eq!(reg.attestable().len(), 1);
    }

    #[test]
    fn rejects_non_relay_and_tampered_records() {
        let mut reg = Registry::new();
        let id = NodeIdentity::generate().unwrap();

        let client =
            PeerRecord::build_signed(&id, vec![], false, false, now_unix() + 3600, 1).unwrap();
        assert!(reg.admit(client).is_err());

        let mut forged = relay_record(&id, 1);
        forged.exit = true;
        assert!(reg.admit(forged).is_err());
    }

    #[test]
    fn newer_seq_replaces_older_and_keeps_health() {
        let mut reg = Registry::new();
        let id = NodeIdentity::generate().unwrap();
        reg.admit(relay_record(&id, 1)).unwrap();
        reg.record_health(&id.id(), Some("127.0.0.1:9000".into()));

        // A refresh (higher seq) keeps the relay attestable, no health gap.
        assert!(reg.admit(relay_record(&id, 2)).unwrap());
        assert_eq!(reg.attestable().len(), 1);

        // A stale seq is ignored.
        assert!(!reg.admit(relay_record(&id, 1)).unwrap());
    }

    #[test]
    fn strikes_evict_unreachable_relays() {
        let mut reg = Registry::new();
        let id = NodeIdentity::generate().unwrap();
        reg.admit(relay_record(&id, 1)).unwrap();
        reg.record_health(&id.id(), Some("127.0.0.1:9000".into()));

        for _ in 0..MAX_STRIKES {
            reg.record_health(&id.id(), None);
        }
        assert!(reg.is_empty(), "relay should be evicted after max strikes");
    }

    #[test]
    fn snapshot_contains_only_attestable_relays() {
        let mut reg = Registry::new();
        let healthy = NodeIdentity::generate().unwrap();
        let unchecked = NodeIdentity::generate().unwrap();
        reg.admit(relay_record(&healthy, 1)).unwrap();
        reg.admit(relay_record(&unchecked, 1)).unwrap();
        reg.record_health(&healthy.id(), Some("127.0.0.1:9000".into()));

        let witness = NodeIdentity::generate().unwrap();
        let signed = reg.sign_snapshot(&witness);
        let trusted = [witness.public().signing.to_bytes()];
        signed.verify(&trusted, 1, now_unix()).unwrap();
        assert_eq!(signed.snapshot.relays.len(), 1);
        assert_eq!(signed.snapshot.relays[0].id, healthy.id());
    }

    #[test]
    fn attestation_is_capped_per_public_subnet() {
        let mut reg = Registry::new();
        // Three healthy relays in one real public /24 (45.33.32.0/24) ...
        for host in ["45.33.32.10", "45.33.32.11", "45.33.32.12"] {
            let id = NodeIdentity::generate().unwrap();
            reg.admit(relay_record_at(&id, &format!("{host}:443"), 1))
                .unwrap();
            reg.record_health(&id.id(), Some(format!("{host}:443")));
        }
        // ... plus one in a different /24.
        let other = NodeIdentity::generate().unwrap();
        reg.admit(relay_record_at(&other, "9.9.9.7:443", 1))
            .unwrap();
        reg.record_health(&other.id(), Some("9.9.9.7:443".into()));

        let attested = reg.attestable();
        // Only MAX_ATTESTED_PER_SUBNET from the flooded /24, plus the lone relay.
        assert_eq!(attested.len(), MAX_ATTESTED_PER_SUBNET + 1);
        let in_flooded = attested
            .iter()
            .filter(|r| r.addrs[0].starts_with("45.33.32."))
            .count();
        assert_eq!(in_flooded, MAX_ATTESTED_PER_SUBNET);
        assert!(attested.iter().any(|r| r.addrs[0] == "9.9.9.7:443"));
    }

    #[test]
    fn padding_addrs_with_a_victim_subnet_cannot_evict_honest_relays() {
        // Review finding C1: the cap must count only the dial-back-*verified*
        // address, never an unverified advertised one — else an attacker fills a
        // victim /24's cap slots by naming IPs it doesn't control.
        let mut reg = Registry::new();
        // Two honest relays fill the victim /24 (to the cap), each verified at its
        // own address.
        for host in ["45.33.32.10", "45.33.32.11"] {
            let id = NodeIdentity::generate().unwrap();
            reg.admit(relay_record_at(&id, &format!("{host}:443"), 1))
                .unwrap();
            reg.record_health(&id.id(), Some(format!("{host}:443")));
        }
        // An attacker advertises its real address PLUS two IPs in the victim /24 it
        // does not control; only its real address answers the dial-back.
        let attacker = NodeIdentity::generate().unwrap();
        let padded = PeerRecord::build_signed(
            &attacker,
            vec![
                "9.9.9.9:443".into(),
                "45.33.32.20:443".into(),
                "45.33.32.21:443".into(),
            ],
            true,
            false,
            now_unix() + 3600,
            1,
        )
        .unwrap();
        reg.admit(padded).unwrap();
        reg.record_health(&attacker.id(), Some("9.9.9.9:443".into()));

        let attested = reg.attestable();
        // Both honest relays survive — the padding consumed no victim-/24 slots —
        // and the attacker attests only in its own /24.
        assert!(attested.iter().any(|r| r.addrs[0] == "45.33.32.10:443"));
        assert!(attested.iter().any(|r| r.addrs[0] == "45.33.32.11:443"));
        assert!(attested.iter().any(|r| r.addrs[0] == "9.9.9.9:443"));
        assert_eq!(attested.len(), 3);
    }

    #[test]
    fn loopback_relays_are_exempt_from_the_subnet_cap() {
        // All test relays share 127.0.0.0/24 but must not be capped — loopback is
        // never a real public subnet and would break local multi-relay setups.
        let mut reg = Registry::new();
        for _ in 0..MAX_ATTESTED_PER_SUBNET + 2 {
            let id = NodeIdentity::generate().unwrap();
            reg.admit(relay_record(&id, 1)).unwrap();
            reg.record_health(&id.id(), Some("127.0.0.1:9000".into()));
        }
        assert_eq!(reg.attestable().len(), MAX_ATTESTED_PER_SUBNET + 2);
    }
}
