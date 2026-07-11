//! The witnessed relay registry.
//!
//! Holds the relay records this seed has verified and (optionally) confirmed
//! reachable, and mints signed [`SignedSnapshot`]s over them. A record is only
//! admitted if it is self-certifying and node-signed; it is only *attested* if
//! a dial-back handshake proved the operator controls the advertised address
//! and the record's signing key. Everything is in memory — a seed holds no
//! durable user state.

use std::collections::HashMap;

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
                self.entries.insert(
                    record.id,
                    Entry {
                        record,
                        healthy,
                        strikes: 0,
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

    /// Record the outcome of a health check. A success clears strikes and
    /// marks the relay attestable; [`MAX_STRIKES`] consecutive failures evict
    /// it entirely.
    pub fn record_health(&mut self, id: &NodeId, ok: bool) {
        if let Some(entry) = self.entries.get_mut(id) {
            if ok {
                entry.healthy = true;
                entry.strikes = 0;
            } else {
                entry.healthy = false;
                entry.strikes += 1;
                if entry.strikes >= MAX_STRIKES {
                    self.entries.remove(id);
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
    pub fn attestable(&self) -> Vec<PeerRecord> {
        let now = now_unix();
        let mut relays: Vec<PeerRecord> = self
            .entries
            .values()
            .filter(|e| e.healthy && !e.record.is_expired(now))
            .map(|e| e.record.clone())
            .collect();
        relays.sort_unstable_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
        cap_per_subnet(relays)
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

/// Keep at most [`MAX_ATTESTED_PER_SUBNET`] relays per public subnet, preserving
/// input order (so the canonical ascending-id order is retained and the kept
/// relays are deterministic). A relay is dropped if *any* of its public subnets is
/// already full — so a multi-homed record can't slip a full subnet past the cap by
/// also advertising a spare one. Records with no public subnet (loopback / internal
/// dev addresses) are never capped: they can't be dial-back-attested in production
/// anyway, and collapsing them into one bucket would break local multi-relay tests.
fn cap_per_subnet(relays: Vec<PeerRecord>) -> Vec<PeerRecord> {
    let mut per_subnet: HashMap<neo_core::net::SubnetKey, usize> = HashMap::new();
    relays
        .into_iter()
        .filter(|r| {
            let subnets = public_subnets(r);
            if subnets.is_empty() {
                return true;
            }
            if subnets
                .iter()
                .any(|s| per_subnet.get(s).copied().unwrap_or(0) >= MAX_ATTESTED_PER_SUBNET)
            {
                return false;
            }
            for s in subnets {
                *per_subnet.entry(s).or_insert(0) += 1;
            }
            true
        })
        .collect()
}

/// The distinct **public** subnets a record advertises (internal / loopback
/// addresses excluded from the Sybil cap). Deduped so a record advertising two
/// addresses in one /24 counts that subnet once.
fn public_subnets(record: &PeerRecord) -> Vec<neo_core::net::SubnetKey> {
    let mut seen = std::collections::HashSet::new();
    record
        .addrs
        .iter()
        .filter(|a| neo_core::net::is_safe_dial_target(a, false))
        .filter_map(|a| neo_core::net::SubnetKey::from_addr(a))
        .filter(|k| seen.insert(*k))
        .collect()
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
        reg.record_health(&id.id(), true);
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
        reg.record_health(&id.id(), true);

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
        reg.record_health(&id.id(), true);

        for _ in 0..MAX_STRIKES {
            reg.record_health(&id.id(), false);
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
        reg.record_health(&healthy.id(), true);

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
            reg.record_health(&id.id(), true);
        }
        // ... plus one in a different /24.
        let other = NodeIdentity::generate().unwrap();
        reg.admit(relay_record_at(&other, "9.9.9.7:443", 1))
            .unwrap();
        reg.record_health(&other.id(), true);

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
    fn loopback_relays_are_exempt_from_the_subnet_cap() {
        // All test relays share 127.0.0.0/24 but must not be capped — loopback is
        // never a real public subnet and would break local multi-relay setups.
        let mut reg = Registry::new();
        for _ in 0..MAX_ATTESTED_PER_SUBNET + 2 {
            let id = NodeIdentity::generate().unwrap();
            reg.admit(relay_record(&id, 1)).unwrap();
            reg.record_health(&id.id(), true);
        }
        assert_eq!(reg.attestable().len(), MAX_ATTESTED_PER_SUBNET + 2);
    }
}
