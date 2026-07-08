//! `neo-discovery` — decentralized discovery and NAT traversal.
//!
//! Defines the [`Discovery`] interface (announce / lookup / sample relays /
//! bootstrap), the NAT-traversal [`connection_ladder`] (Direct → hole-punch →
//! relay), and a tested in-memory [`LocalRegistry`] that stands in for the DHT
//! in tests and local multi-node runs.
//!
//! The **production backend is `rust-libp2p`** — Kademlia DHT for trackerless
//! discovery, DCUtR for hole-punching, and Circuit Relay v2 for the fallback —
//! implemented as another `Discovery` impl behind this same interface. It is a
//! large integration that needs a real network to exercise, so it is a focused
//! follow-up rather than part of this in-memory milestone. Rendezvous uses DoH
//! (domain fronting is dead); user data never rides the DHT.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use neo_core::{Error, NodeId, Result};

#[cfg(feature = "libp2p")]
pub mod libp2p_backend;

/// A discoverable peer or relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    /// Stable node identifier.
    pub id: NodeId,
    /// X25519 public key (for classical key agreement).
    pub kex: [u8; 32],
    /// Ristretto routing key (for Sphinx).
    pub sphinx: [u8; 32],
    /// Dialable transport addresses.
    pub addrs: Vec<String>,
    /// Whether the peer relays traffic for others.
    pub relay: bool,
    /// Whether the peer offers clearnet exit (opt-in).
    pub exit: bool,
}

impl PeerRecord {
    /// Serialize the record (e.g. as a DHT value).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.kex);
        out.extend_from_slice(&self.sphinx);
        out.push((self.relay as u8) | ((self.exit as u8) << 1));
        out.extend_from_slice(&(self.addrs.len() as u16).to_be_bytes());
        for addr in &self.addrs {
            out.extend_from_slice(&(addr.len() as u16).to_be_bytes());
            out.extend_from_slice(addr.as_bytes());
        }
        out
    }

    /// Parse a record from [`to_bytes`](Self::to_bytes) output. Bounds-checked so
    /// it never panics on arbitrary input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if cur.len() < n {
                return Err(Error::Decode("truncated peer record".into()));
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }

        let mut cur = bytes;
        let mut id = [0u8; 32];
        id.copy_from_slice(take(&mut cur, 32)?);
        let mut kex = [0u8; 32];
        kex.copy_from_slice(take(&mut cur, 32)?);
        let mut sphinx = [0u8; 32];
        sphinx.copy_from_slice(take(&mut cur, 32)?);
        let flags = take(&mut cur, 1)?[0];
        let count = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;

        let mut addrs = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let len = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
            let raw = take(&mut cur, len)?;
            let text = std::str::from_utf8(raw)
                .map_err(|_| Error::Decode("address is not valid UTF-8".into()))?;
            addrs.push(text.to_string());
        }

        Ok(PeerRecord {
            id: NodeId::from_bytes(id),
            kex,
            sphinx,
            addrs,
            relay: flags & 1 != 0,
            exit: flags & 2 != 0,
        })
    }
}

/// One attempt in the NAT-traversal ladder for reaching a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectStrategy {
    /// Dial an advertised address directly.
    Direct,
    /// Coordinate a simultaneous-open hole punch (libp2p DCUtR in production).
    HolePunch,
    /// Fall back to relaying through another node (Circuit Relay v2 in production).
    Relay {
        /// The relay to route through.
        via: NodeId,
    },
}

/// Ordered connection attempts for reaching `peer`: direct if it advertises an
/// address, then a hole punch, then a relay fallback if one is known.
pub fn connection_ladder(peer: &PeerRecord, relays: &[PeerRecord]) -> Vec<ConnectStrategy> {
    let mut ladder = Vec::new();
    if !peer.addrs.is_empty() {
        ladder.push(ConnectStrategy::Direct);
    }
    ladder.push(ConnectStrategy::HolePunch);
    if let Some(relay) = relays.iter().find(|r| r.relay && r.id != peer.id) {
        ladder.push(ConnectStrategy::Relay { via: relay.id });
    }
    ladder
}

/// The discovery interface every backend implements.
#[allow(async_fn_in_trait)]
pub trait Discovery {
    /// Publish this node's record.
    async fn announce(&self, record: PeerRecord) -> Result<()>;
    /// Look up a peer by id.
    async fn lookup(&self, id: &NodeId) -> Result<Option<PeerRecord>>;
    /// Sample up to `n` random relay-capable peers (for building paths).
    async fn sample_relays(&self, n: usize) -> Result<Vec<PeerRecord>>;
    /// Seed the local view from known bootstrap records.
    async fn bootstrap(&self, seeds: &[PeerRecord]) -> Result<()>;
}

/// In-memory DHT stand-in. Clones share one registry, simulating many nodes on
/// one network — useful for tests and local multi-node runs.
#[derive(Clone, Default)]
pub struct LocalRegistry {
    inner: Arc<Mutex<HashMap<NodeId, PeerRecord>>>,
}

impl LocalRegistry {
    /// A new, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of known records.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("registry lock").len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Discovery for LocalRegistry {
    async fn announce(&self, record: PeerRecord) -> Result<()> {
        self.inner
            .lock()
            .expect("registry lock")
            .insert(record.id, record);
        Ok(())
    }

    async fn lookup(&self, id: &NodeId) -> Result<Option<PeerRecord>> {
        Ok(self.inner.lock().expect("registry lock").get(id).cloned())
    }

    async fn sample_relays(&self, n: usize) -> Result<Vec<PeerRecord>> {
        let mut relays: Vec<PeerRecord> = self
            .inner
            .lock()
            .expect("registry lock")
            .values()
            .filter(|r| r.relay)
            .cloned()
            .collect();
        for i in (1..relays.len()).rev() {
            relays.swap(i, rand_below(i + 1)?);
        }
        relays.truncate(n);
        Ok(relays)
    }

    async fn bootstrap(&self, seeds: &[PeerRecord]) -> Result<()> {
        let mut guard = self.inner.lock().expect("registry lock");
        for seed in seeds {
            guard.insert(seed.id, seed.clone());
        }
        Ok(())
    }
}

fn rand_below(bound: usize) -> Result<usize> {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
    Ok((u64::from_le_bytes(b) % bound as u64) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_core::NodeIdentity;

    fn record(relay: bool, exit: bool, addr: bool) -> PeerRecord {
        let p = NodeIdentity::generate().unwrap().public();
        PeerRecord {
            id: p.id,
            kex: *p.kex.as_bytes(),
            sphinx: p.sphinx,
            addrs: if addr {
                vec!["1.2.3.4:9000".into()]
            } else {
                vec![]
            },
            relay,
            exit,
        }
    }

    #[test]
    fn peer_record_roundtrips_and_survives_garbage() {
        let rec = record(true, true, true);
        assert_eq!(PeerRecord::from_bytes(&rec.to_bytes()).unwrap(), rec);

        // Arbitrary input must never panic (fuzz-lite).
        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..3000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (seed >> 40) as usize % 160;
            let bytes: Vec<u8> = (0..len).map(|i| (seed >> (i % 8 * 8)) as u8).collect();
            let _ = PeerRecord::from_bytes(&bytes);
        }
    }

    #[tokio::test]
    async fn announce_is_visible_to_other_nodes_on_the_network() {
        let node_a = LocalRegistry::new();
        let node_b = node_a.clone(); // same "DHT"
        let rec = record(true, false, true);
        node_a.announce(rec.clone()).await.unwrap();
        assert_eq!(node_b.lookup(&rec.id).await.unwrap(), Some(rec));
    }

    #[tokio::test]
    async fn sample_relays_returns_only_relays() {
        let dht = LocalRegistry::new();
        for _ in 0..4 {
            dht.announce(record(true, false, true)).await.unwrap();
        }
        dht.announce(record(false, false, true)).await.unwrap(); // a non-relay
        let sample = dht.sample_relays(3).await.unwrap();
        assert!(sample.len() <= 3);
        assert!(!sample.is_empty());
        assert!(sample.iter().all(|r| r.relay));
    }

    #[test]
    fn ladder_is_direct_then_holepunch_then_relay() {
        let peer = record(false, false, true);
        let relays = vec![record(true, false, true)];
        let ladder = connection_ladder(&peer, &relays);
        assert_eq!(ladder.first(), Some(&ConnectStrategy::Direct));
        assert!(matches!(ladder.last(), Some(ConnectStrategy::Relay { .. })));
    }

    #[test]
    fn ladder_skips_direct_without_an_address() {
        let peer = record(false, false, false); // no advertised address
        let ladder = connection_ladder(&peer, &[]);
        assert_eq!(ladder, vec![ConnectStrategy::HolePunch]);
    }
}
