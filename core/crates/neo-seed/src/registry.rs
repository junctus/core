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
        record.verify(now_unix())?;
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

    /// The healthy, unexpired relay records this seed will attest to.
    pub fn attestable(&self) -> Vec<PeerRecord> {
        let now = now_unix();
        self.entries
            .values()
            .filter(|e| e.healthy && !e.record.is_expired(now))
            .map(|e| e.record.clone())
            .collect()
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
}
