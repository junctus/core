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
use std::time::{SystemTime, UNIX_EPOCH};

use neo_core::{Error, NodeId, NodeIdentity, Result, KEM_PUBLIC_LEN, SIGNATURE_LEN};

pub mod bootstrap;
#[cfg(feature = "libp2p")]
pub mod libp2p_backend;
pub mod snapshot;

/// Wire-format version of a **full** serialized [`PeerRecord`] — carries the
/// 1184-byte ML-KEM key. Used for DHT values and seed registration.
const RECORD_VERSION_FULL: u8 = 3;
/// Wire-format version of a **compact** [`PeerRecord`] — omits the ML-KEM key
/// (~85% of a record). The record `id` is `BLAKE3(signing, kex, kem)`, so it
/// already commits to the omitted key; a dialing client recovers the real key
/// from the relay's handshake message and checks `id` against it. Compact
/// records are for witness-signed snapshots, never the DHT (no immediate
/// handshake follows a DHT lookup to re-derive the key).
const RECORD_VERSION_COMPACT: u8 = 4;
/// Domain separator for record signatures. The signed body commits to `id`
/// (which commits to the keys) but **not** the raw ML-KEM bytes, so one
/// signature is valid for both the full and compact encodings.
const RECORD_SIG_DOMAIN: &[u8] = b"neo-peer-record-sig-v3";
/// Upper bound on advertised addresses per record.
pub const MAX_ADDRS: usize = 8;
/// Upper bound on a single advertised address string.
pub const MAX_ADDR_LEN: usize = 256;

/// How a node participates in discovery.
///
/// The split is a privacy boundary, not just a capability flag: **clients
/// must be invisible**. A client never listens, never announces a record, and
/// never serves DHT queries, so joining the network as a consumer adds nothing
/// enumerable. Only relays — which are publicly dialable by design — enter the
/// DHT in server mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    /// A consumer: queries only, announces nothing, serves nothing.
    Client,
    /// A relay/seed: dialable, announces its record, serves DHT queries.
    Relay,
}

/// Current unix time in whole seconds (the timestamp base for records).
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A discoverable peer or relay.
///
/// Records are **self-certifying and signed**: they carry the node's full
/// public-key set, the id must equal `NodeId::from_keys(...)` over those keys,
/// and the whole record is Ed25519-signed by the node it describes. Verifiers
/// call [`verify`](Self::verify) before trusting or caching a record, so a
/// record cannot be forged, tampered with, or published under someone else's
/// id — an adversary can only replay a node's own signed statements, and
/// `expires_at` + `seq` bound how long a replay stays useful.
///
/// A record has two wire encodings. The **full** form ([`to_bytes`](Self::to_bytes))
/// carries the 1184-byte ML-KEM key and fully self-certifies. The **compact**
/// form ([`to_compact_bytes`](Self::to_compact_bytes)) omits that key — ~85% of
/// a record — for witness-signed snapshots, which a client downloads in bulk.
/// The signature covers `id` (a BLAKE3 commitment to the keys) rather than the
/// raw key, so it is valid for both forms and a seed can emit the compact form
/// from a node's full record without the node re-signing. The dropped key is
/// not lost: the relay sends it in its handshake, and the client checks the
/// re-derived NodeId against the `id` it trusted from the snapshot — so a
/// compact record's key commitment is verified at *dial* time rather than at
/// *parse* time. Compact records are snapshot-only; the DHT uses the full form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    /// Stable node identifier (BLAKE3 over the public keys).
    pub id: NodeId,
    /// Ed25519 verifying key — authenticates this record and the handshake.
    pub signing: [u8; 32],
    /// X25519 public key (for classical key agreement).
    pub kex: [u8; 32],
    /// ML-KEM-768 encapsulation key (post-quantum key agreement).
    pub kem: Vec<u8>,
    /// Ristretto routing key (for Sphinx).
    pub sphinx: [u8; 32],
    /// Dialable transport addresses.
    pub addrs: Vec<String>,
    /// Whether the peer relays traffic for others.
    pub relay: bool,
    /// Whether the peer offers clearnet exit (opt-in).
    pub exit: bool,
    /// Unix time (seconds) after which the record is invalid.
    pub expires_at: u64,
    /// Monotonic per-node sequence number; higher replaces lower.
    pub seq: u64,
    /// Ed25519 signature by `signing` over the record body.
    pub sig: [u8; SIGNATURE_LEN],
}

impl PeerRecord {
    /// Build and sign a record for `identity`.
    pub fn build_signed(
        identity: &NodeIdentity,
        addrs: Vec<String>,
        relay: bool,
        exit: bool,
        expires_at: u64,
        seq: u64,
    ) -> Result<Self> {
        let public = identity.public();
        let mut record = PeerRecord {
            id: public.id,
            signing: public.signing.to_bytes(),
            kex: *public.kex.as_bytes(),
            kem: public.kem_bytes(),
            sphinx: public.sphinx,
            addrs,
            relay,
            exit,
            expires_at,
            seq,
            sig: [0u8; SIGNATURE_LEN],
        };
        record.check_limits()?;
        record.sig = identity.sign(&record.signable_bytes()).to_bytes();
        Ok(record)
    }

    /// Verify the record at time `now`: structural limits, key/id
    /// self-certification, expiry, and the signature. Anything from the
    /// network must pass this before being cached or used.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.verify_static()?;
        if self.expires_at <= now {
            return Err(Error::Crypto("peer record has expired".into()));
        }
        Ok(())
    }

    /// Like [`verify`](Self::verify) but additionally requires the **full** form.
    /// Compact records (no ML-KEM key) are snapshot-only: a client re-derives and
    /// checks their key commitment during the handshake that immediately follows
    /// dialing. The DHT and seed registration have no such following handshake,
    /// so they must reject compact records and keep the self-certifying full form.
    pub fn verify_full(&self, now: u64) -> Result<()> {
        if self.is_compact() {
            return Err(Error::Decode(
                "compact records are snapshot-only and not valid here".into(),
            ));
        }
        self.verify(now)
    }

    /// The time-independent checks: structural limits, key/id
    /// self-certification, and the signature — everything except expiry.
    /// Snapshot verification uses this to treat a *forged* record as fatal
    /// while merely filtering records that have aged out.
    pub fn verify_static(&self) -> Result<()> {
        self.check_limits()?;
        // A full record self-certifies: id must equal BLAKE3 over its keys. A
        // compact record carries no kem, so this commitment cannot be checked
        // here; it is enforced when a client dials the relay and re-derives the
        // NodeId from the ML-KEM key the handshake supplies (see module docs).
        // The signature below still binds `id` (and thus the committed key),
        // signing/kex/sphinx, addrs, expiry and seq to the node's signing key.
        if !self.is_compact() {
            let expected = NodeId::from_keys(&self.signing, &self.kex, &self.kem)?;
            if expected != self.id {
                return Err(Error::Crypto(
                    "peer record id does not match its keys".into(),
                ));
            }
        }
        neo_core::verify_signature(&self.signing, &self.signable_bytes(), &self.sig)
    }

    /// Whether the record is past its expiry at time `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at <= now
    }

    /// Whether this record is the compact form (no ML-KEM key). A compact record
    /// carries an empty `kem`; a full record's `kem` is exactly [`KEM_PUBLIC_LEN`].
    pub fn is_compact(&self) -> bool {
        self.kem.is_empty()
    }

    fn check_limits(&self) -> Result<()> {
        // A full record must carry a well-formed ML-KEM key; a compact record
        // carries none (empty), and its key is validated at handshake time.
        if !self.kem.is_empty() && self.kem.len() != KEM_PUBLIC_LEN {
            return Err(Error::Decode("bad ML-KEM key length".into()));
        }
        if self.addrs.len() > MAX_ADDRS {
            return Err(Error::Decode("too many addresses".into()));
        }
        if self.addrs.iter().any(|a| a.len() > MAX_ADDR_LEN) {
            return Err(Error::Decode("address too long".into()));
        }
        Ok(())
    }

    /// The bytes covered by the record signature: a domain tag, then `id`, the
    /// signing/kex/sphinx keys, and the record metadata — but **not** the raw
    /// ML-KEM key (which `id` commits to) and **not** the wire version byte. That
    /// omission is what lets one signature cover both the full and compact forms.
    fn signable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECORD_SIG_DOMAIN.len() + 256);
        out.extend_from_slice(RECORD_SIG_DOMAIN);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.signing);
        out.extend_from_slice(&self.kex);
        self.encode_tail(&mut out);
        out
    }

    /// The wire fields from `sphinx` onward — identical across the full and
    /// compact encodings and the signed body, so it is factored out.
    fn encode_tail(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sphinx);
        out.push((self.relay as u8) | ((self.exit as u8) << 1));
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&(self.addrs.len() as u16).to_be_bytes());
        for addr in &self.addrs {
            out.extend_from_slice(&(addr.len() as u16).to_be_bytes());
            out.extend_from_slice(addr.as_bytes());
        }
    }

    /// Serialize the **full** record — carries the ML-KEM key. Use for DHT values
    /// and seed registration, where no handshake immediately follows to supply
    /// the key. See [`to_compact_bytes`](Self::to_compact_bytes) for snapshots.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1500);
        out.push(RECORD_VERSION_FULL);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.signing);
        out.extend_from_slice(&self.kex);
        out.extend_from_slice(&self.kem);
        self.encode_tail(&mut out);
        out.extend_from_slice(&self.sig);
        out
    }

    /// Serialize the **compact** record — omits the ML-KEM key (~85% smaller).
    /// The signature is byte-for-byte the one on the full record (it never
    /// covered the raw key), so a holder of the full record — e.g. a seed
    /// building a snapshot — can emit this form without the node re-signing.
    pub fn to_compact_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(RECORD_VERSION_COMPACT);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.signing);
        out.extend_from_slice(&self.kex);
        self.encode_tail(&mut out);
        out.extend_from_slice(&self.sig);
        out
    }

    /// Parse a record from [`to_bytes`](Self::to_bytes) output. Bounds-checked so
    /// it never panics on arbitrary input. Parsing does **not** verify — call
    /// [`verify`](Self::verify) on anything untrusted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if cur.len() < n {
                return Err(Error::Decode("truncated peer record".into()));
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        fn take_u16(cur: &mut &[u8]) -> Result<usize> {
            Ok(u16::from_be_bytes(take(cur, 2)?.try_into().expect("2 bytes")) as usize)
        }
        fn take_u64(cur: &mut &[u8]) -> Result<u64> {
            Ok(u64::from_be_bytes(
                take(cur, 8)?.try_into().expect("8 bytes"),
            ))
        }

        let mut cur = bytes;
        let version = take(&mut cur, 1)?[0];
        let compact = match version {
            RECORD_VERSION_FULL => false,
            RECORD_VERSION_COMPACT => true,
            other => {
                return Err(Error::Decode(format!(
                    "unsupported peer record version {other}"
                )))
            }
        };
        let mut id = [0u8; 32];
        id.copy_from_slice(take(&mut cur, 32)?);
        let mut signing = [0u8; 32];
        signing.copy_from_slice(take(&mut cur, 32)?);
        let mut kex = [0u8; 32];
        kex.copy_from_slice(take(&mut cur, 32)?);
        // The compact form omits the ML-KEM key entirely; leave it empty.
        let kem = if compact {
            Vec::new()
        } else {
            take(&mut cur, KEM_PUBLIC_LEN)?.to_vec()
        };
        let mut sphinx = [0u8; 32];
        sphinx.copy_from_slice(take(&mut cur, 32)?);
        let flags = take(&mut cur, 1)?[0];
        let expires_at = take_u64(&mut cur)?;
        let seq = take_u64(&mut cur)?;
        let count = take_u16(&mut cur)?;
        if count > MAX_ADDRS {
            return Err(Error::Decode("too many addresses".into()));
        }

        let mut addrs = Vec::with_capacity(count);
        for _ in 0..count {
            let len = take_u16(&mut cur)?;
            if len > MAX_ADDR_LEN {
                return Err(Error::Decode("address too long".into()));
            }
            let raw = take(&mut cur, len)?;
            let text = std::str::from_utf8(raw)
                .map_err(|_| Error::Decode("address is not valid UTF-8".into()))?;
            addrs.push(text.to_string());
        }

        let mut sig = [0u8; SIGNATURE_LEN];
        sig.copy_from_slice(take(&mut cur, SIGNATURE_LEN)?);
        if !cur.is_empty() {
            return Err(Error::Decode("trailing bytes after peer record".into()));
        }

        Ok(PeerRecord {
            id: NodeId::from_bytes(id),
            signing,
            kex,
            kem,
            sphinx,
            addrs,
            relay: flags & 1 != 0,
            exit: flags & 2 != 0,
            expires_at,
            seq,
            sig,
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

/// A node's own network reachability, as determined by AutoNAT (M16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reachability {
    /// Publicly dialable (has a routable, port-forwarded address).
    Public,
    /// Behind a NAT / firewall — not directly dialable from the internet.
    Private,
    /// Not yet determined (too few AutoNAT probes).
    Unknown,
}

/// Ordered connection attempts for reaching `peer`: direct if it advertises an
/// address, then a hole punch, then a relay fallback if one is known.
pub fn connection_ladder(peer: &PeerRecord, relays: &[PeerRecord]) -> Vec<ConnectStrategy> {
    connection_ladder_for(Reachability::Unknown, peer, relays)
}

/// A reachability-aware connection ladder (M16).
///
/// - A **direct** dial is tried first whenever the peer advertises an address.
/// - A **hole punch** (DCUtR) is only useful when at least one side is behind a
///   NAT that a coordinated simultaneous-open can traverse; if *we* are public
///   and the peer advertises an address, a direct dial suffices and hole-punch
///   is skipped.
/// - A **relay** (Circuit Relay v2) is the last resort when neither direct nor
///   hole-punch can work (e.g. a peer with no dialable address behind a
///   symmetric NAT).
pub fn connection_ladder_for(
    local: Reachability,
    peer: &PeerRecord,
    relays: &[PeerRecord],
) -> Vec<ConnectStrategy> {
    let mut ladder = Vec::new();
    let peer_dialable = !peer.addrs.is_empty();
    if peer_dialable {
        ladder.push(ConnectStrategy::Direct);
    }
    // Hole-punching helps unless we are already public *and* the peer is
    // directly dialable (then Direct is enough).
    let direct_suffices = local == Reachability::Public && peer_dialable;
    if !direct_suffices {
        ladder.push(ConnectStrategy::HolePunch);
    }
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

impl LocalRegistry {
    /// Verify a record and insert it, keeping the highest `seq` per node.
    fn upsert_verified(guard: &mut HashMap<NodeId, PeerRecord>, record: PeerRecord) -> Result<()> {
        record.verify_full(now_unix())?;
        match guard.get(&record.id) {
            Some(existing) if existing.seq >= record.seq => Ok(()),
            _ => {
                guard.insert(record.id, record);
                Ok(())
            }
        }
    }
}

impl Discovery for LocalRegistry {
    async fn announce(&self, record: PeerRecord) -> Result<()> {
        let mut guard = self.inner.lock().expect("registry lock");
        Self::upsert_verified(&mut guard, record)
    }

    async fn lookup(&self, id: &NodeId) -> Result<Option<PeerRecord>> {
        let now = now_unix();
        Ok(self
            .inner
            .lock()
            .expect("registry lock")
            .get(id)
            .filter(|r| !r.is_expired(now))
            .cloned())
    }

    async fn sample_relays(&self, n: usize) -> Result<Vec<PeerRecord>> {
        let now = now_unix();
        let mut relays: Vec<PeerRecord> = self
            .inner
            .lock()
            .expect("registry lock")
            .values()
            .filter(|r| r.relay && !r.is_expired(now))
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
            Self::upsert_verified(&mut guard, seed.clone())?;
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

    fn signed_record(relay: bool, exit: bool, addr: bool) -> PeerRecord {
        let identity = NodeIdentity::generate().unwrap();
        let addrs = if addr {
            vec!["1.2.3.4:9000".into()]
        } else {
            vec![]
        };
        PeerRecord::build_signed(&identity, addrs, relay, exit, now_unix() + 3600, 1).unwrap()
    }

    fn record(relay: bool, exit: bool, addr: bool) -> PeerRecord {
        signed_record(relay, exit, addr)
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
            let len = (seed >> 40) as usize % 2000;
            let bytes: Vec<u8> = (0..len).map(|i| (seed >> (i % 8 * 8)) as u8).collect();
            let _ = PeerRecord::from_bytes(&bytes);
        }
    }

    #[test]
    fn signed_records_verify() {
        let rec = record(true, false, true);
        assert!(rec.verify(now_unix()).is_ok());
        // And still verify after a serialization round-trip.
        let parsed = PeerRecord::from_bytes(&rec.to_bytes()).unwrap();
        assert!(parsed.verify(now_unix()).is_ok());
    }

    #[test]
    fn tampered_records_are_rejected() {
        let now = now_unix();

        // Flipping the exit flag invalidates the signature.
        let mut rec = record(true, false, true);
        rec.exit = true;
        assert!(rec.verify(now).is_err());

        // Swapping in a different address invalidates the signature.
        let mut rec = record(true, false, true);
        rec.addrs = vec!["6.6.6.6:6666".into()];
        assert!(rec.verify(now).is_err());

        // Bumping seq (a replay-forward attempt) invalidates the signature.
        let mut rec = record(true, false, true);
        rec.seq += 1;
        assert!(rec.verify(now).is_err());
    }

    #[test]
    fn records_under_a_foreign_id_are_rejected() {
        // Keys from one identity presented under another identity's id.
        let victim = NodeIdentity::generate().unwrap();
        let mut rec = record(true, false, true);
        rec.id = victim.id();
        assert!(rec.verify(now_unix()).is_err());
    }

    #[test]
    fn compact_record_roundtrips_and_verifies() {
        // A compact record parses back with no kem and still verifies: the
        // signature covers `id` (which commits to the key), not the raw key.
        let full = record(true, false, true);
        let compact = PeerRecord::from_bytes(&full.to_compact_bytes()).unwrap();
        assert!(compact.is_compact());
        assert!(compact.kem.is_empty());
        assert!(compact.verify(now_unix()).is_ok());
        // Everything except the dropped kem survives the round trip.
        assert_eq!(compact.id, full.id);
        assert_eq!(compact.signing, full.signing);
        assert_eq!(compact.kex, full.kex);
        assert_eq!(compact.sphinx, full.sphinx);
        assert_eq!(compact.addrs, full.addrs);
        assert_eq!(compact.seq, full.seq);
    }

    #[test]
    fn full_and_compact_share_one_signature() {
        // The point of signing over `id` and not the raw kem: a holder of the
        // full record (a seed) emits the compact form with no re-signing.
        let full = record(true, false, true);
        let compact = PeerRecord::from_bytes(&full.to_compact_bytes()).unwrap();
        assert_eq!(full.sig, compact.sig, "one signature covers both forms");
        assert!(full.verify(now_unix()).is_ok());
        assert!(compact.verify(now_unix()).is_ok());
    }

    #[test]
    fn compact_record_is_far_smaller() {
        let full = record(true, false, true);
        let f = full.to_bytes().len();
        let c = full.to_compact_bytes().len();
        // Exactly the ML-KEM key (1184 bytes) is dropped; the result is well
        // under half the full size.
        assert_eq!(f - c, KEM_PUBLIC_LEN);
        assert!(c * 3 < f, "compact should be far smaller (~85% off)");
    }

    #[test]
    fn tampered_compact_records_are_rejected() {
        let now = now_unix();
        // Tampering the id breaks the signature (id is in the signed body), so a
        // compact record still cannot be re-pointed at another identity.
        let mut rec =
            PeerRecord::from_bytes(&record(true, false, true).to_compact_bytes()).unwrap();
        rec.id = NodeId::from_bytes([0x55; 32]);
        assert!(rec.verify(now).is_err());
        // Tampering an address likewise.
        let mut rec =
            PeerRecord::from_bytes(&record(true, false, true).to_compact_bytes()).unwrap();
        rec.addrs = vec!["6.6.6.6:6666".into()];
        assert!(rec.verify(now).is_err());
    }

    #[test]
    fn version_byte_distinguishes_full_from_compact() {
        let full = record(true, false, true);
        assert_eq!(full.to_bytes()[0], RECORD_VERSION_FULL);
        assert_eq!(full.to_compact_bytes()[0], RECORD_VERSION_COMPACT);
        assert!(!PeerRecord::from_bytes(&full.to_bytes())
            .unwrap()
            .is_compact());
        assert!(PeerRecord::from_bytes(&full.to_compact_bytes())
            .unwrap()
            .is_compact());
    }

    #[test]
    fn expired_records_are_rejected() {
        let identity = NodeIdentity::generate().unwrap();
        let stale =
            PeerRecord::build_signed(&identity, vec!["1.2.3.4:9000".into()], true, false, 1, 1)
                .unwrap();
        assert!(stale.verify(now_unix()).is_err());
        assert!(stale.is_expired(now_unix()));
    }

    #[tokio::test]
    async fn registry_rejects_invalid_and_keeps_newest_seq() {
        let dht = LocalRegistry::new();
        let identity = NodeIdentity::generate().unwrap();
        let expires = now_unix() + 3600;

        let v1 =
            PeerRecord::build_signed(&identity, vec!["1.1.1.1:1".into()], true, false, expires, 1)
                .unwrap();
        let v2 =
            PeerRecord::build_signed(&identity, vec!["2.2.2.2:2".into()], true, false, expires, 2)
                .unwrap();

        // A tampered record never lands.
        let mut forged = v1.clone();
        forged.exit = true;
        assert!(dht.announce(forged).await.is_err());
        assert!(dht.is_empty());

        // Newer seq replaces older; older never downgrades newer.
        dht.announce(v2.clone()).await.unwrap();
        dht.announce(v1).await.unwrap();
        assert_eq!(dht.lookup(&identity.id()).await.unwrap(), Some(v2));
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

    #[test]
    fn public_local_to_dialable_peer_needs_only_a_direct_dial() {
        let peer = record(false, false, true); // dialable
        let ladder = connection_ladder_for(Reachability::Public, &peer, &[]);
        assert_eq!(
            ladder,
            vec![ConnectStrategy::Direct],
            "no hole-punch needed"
        );
    }

    #[test]
    fn private_local_still_tries_hole_punch_then_relay() {
        let peer = record(false, false, true);
        let relays = vec![record(true, false, true)];
        let ladder = connection_ladder_for(Reachability::Private, &peer, &relays);
        assert_eq!(ladder[0], ConnectStrategy::Direct);
        assert_eq!(ladder[1], ConnectStrategy::HolePunch);
        assert!(matches!(ladder[2], ConnectStrategy::Relay { .. }));
    }

    #[test]
    fn undialable_peer_relies_on_hole_punch_and_relay() {
        let peer = record(false, false, false); // no address
        let relays = vec![record(true, false, true)];
        let ladder = connection_ladder_for(Reachability::Public, &peer, &relays);
        assert_eq!(ladder[0], ConnectStrategy::HolePunch);
        assert!(matches!(ladder[1], ConnectStrategy::Relay { .. }));
    }
}
