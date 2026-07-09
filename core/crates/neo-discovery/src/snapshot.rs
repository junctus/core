//! Witnessed relay snapshots — the client-facing discovery format.
//!
//! Clients do not query the DHT for individual relays: a per-relay lookup
//! leaks *which* relays a client is about to use to whoever answers it. They
//! fetch one **snapshot** of the whole relay set instead — fetching everything
//! reveals nothing about the path a client will build (the same reasoning
//! behind Tor's full consensus download).
//!
//! Integrity is separated from distribution: a snapshot is signed by one or
//! more **witnesses** (seed operators whose keys ship with the client), so it
//! can be served from any untrusted mirror — a seed's HTTPS endpoint, a CDN, a
//! file copied out-of-band — without that host being able to forge or edit it.
//! A witness attests only to records that are themselves self-certifying and
//! node-signed ([`PeerRecord::verify`]), so even a colluding witness set can
//! at worst *omit* relays, never impersonate them.

use std::collections::HashSet;

use neo_core::{Error, NodeIdentity, Result, SIGNATURE_LEN};

use crate::PeerRecord;

/// Wire-format version of a serialized [`SignedSnapshot`].
const SNAPSHOT_VERSION: u8 = 1;
/// Domain separator for witness signatures over a snapshot body.
const SNAPSHOT_SIG_DOMAIN: &[u8] = b"neo-snapshot-sig-v1";
/// Upper bound on relays in one snapshot (a parse-time memory bound).
pub const MAX_SNAPSHOT_RELAYS: usize = 4096;
/// Upper bound on witness signatures on one snapshot.
pub const MAX_WITNESSES: usize = 64;

/// The relay set at a moment in time, as observed by the signing witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Unix time (seconds) the snapshot was built.
    pub created_at: u64,
    /// Unix time (seconds) after which the snapshot must be refetched.
    pub expires_at: u64,
    /// The verified relay records the witnesses attest to.
    pub relays: Vec<PeerRecord>,
}

/// One witness's signature over a snapshot body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessSignature {
    /// The witness's Ed25519 verifying key.
    pub witness: [u8; 32],
    /// Ed25519 signature over the domain-tagged snapshot body.
    pub sig: [u8; SIGNATURE_LEN],
}

/// A snapshot plus the witness signatures that make it distributable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSnapshot {
    /// The snapshot body.
    pub snapshot: Snapshot,
    /// Signatures from witnesses (verified against a trusted set).
    pub signatures: Vec<WitnessSignature>,
}

impl Snapshot {
    /// The bytes a witness signs (domain-tagged canonical body).
    fn signable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SNAPSHOT_SIG_DOMAIN.len() + 64);
        out.extend_from_slice(SNAPSHOT_SIG_DOMAIN);
        self.encode_body(&mut out);
        out
    }

    fn encode_body(&self, out: &mut Vec<u8>) {
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&(self.relays.len() as u32).to_be_bytes());
        for relay in &self.relays {
            let bytes = relay.to_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
    }

    /// Sign the snapshot as a witness.
    pub fn sign(&self, witness: &NodeIdentity) -> WitnessSignature {
        WitnessSignature {
            witness: witness.public().signing.to_bytes(),
            sig: witness.sign(&self.signable_bytes()).to_bytes(),
        }
    }
}

impl SignedSnapshot {
    /// Verify the snapshot against a trusted witness set at time `now`.
    ///
    /// Requires at least `threshold` *distinct* trusted witnesses with valid
    /// signatures; signatures from unknown keys and invalid signatures are
    /// ignored (k-of-n tolerates a bad or rotated witness). Any **forged**
    /// relay record — bad self-certification or node signature — is fatal:
    /// honest witnesses never attest one. Records that are merely expired are
    /// left for [`relays`](Self::relays) to filter.
    pub fn verify(&self, trusted: &[[u8; 32]], threshold: usize, now: u64) -> Result<()> {
        if threshold == 0 || threshold > trusted.len() {
            return Err(Error::Config(format!(
                "witness threshold {threshold} impossible with {} trusted witnesses",
                trusted.len()
            )));
        }
        if self.snapshot.expires_at <= now {
            return Err(Error::Crypto("snapshot has expired".into()));
        }
        if self.snapshot.created_at >= self.snapshot.expires_at {
            return Err(Error::Crypto("snapshot validity window is empty".into()));
        }

        let body = self.snapshot.signable_bytes();
        let mut valid: HashSet<[u8; 32]> = HashSet::new();
        for signature in &self.signatures {
            if !trusted.contains(&signature.witness) || valid.contains(&signature.witness) {
                continue;
            }
            if neo_core::verify_signature(&signature.witness, &body, &signature.sig).is_ok() {
                valid.insert(signature.witness);
            }
        }
        if valid.len() < threshold {
            return Err(Error::Crypto(format!(
                "snapshot has {} valid witness signatures, {threshold} required",
                valid.len()
            )));
        }

        for relay in &self.snapshot.relays {
            relay.verify_static()?;
        }
        Ok(())
    }

    /// The attested relays still valid at time `now`. Call after
    /// [`verify`](Self::verify).
    pub fn relays(&self, now: u64) -> Vec<&PeerRecord> {
        self.snapshot
            .relays
            .iter()
            .filter(|r| !r.is_expired(now))
            .collect()
    }

    /// Serialize for serving from a mirror or caching on disk.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.snapshot.encode_body(&mut out);
        out.extend_from_slice(&(self.signatures.len() as u16).to_be_bytes());
        for signature in &self.signatures {
            out.extend_from_slice(&signature.witness);
            out.extend_from_slice(&signature.sig);
        }
        out
    }

    /// Parse [`to_bytes`](Self::to_bytes) output. Bounds-checked so it never
    /// panics on arbitrary input; does **not** verify — call
    /// [`verify`](Self::verify) on anything untrusted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if cur.len() < n {
                return Err(Error::Decode("truncated snapshot".into()));
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }

        let mut cur = bytes;
        let version = take(&mut cur, 1)?[0];
        if version != SNAPSHOT_VERSION {
            return Err(Error::Decode(format!(
                "unsupported snapshot version {version}"
            )));
        }
        let created_at = u64::from_be_bytes(take(&mut cur, 8)?.try_into().expect("8 bytes"));
        let expires_at = u64::from_be_bytes(take(&mut cur, 8)?.try_into().expect("8 bytes"));

        let relay_count =
            u32::from_be_bytes(take(&mut cur, 4)?.try_into().expect("4 bytes")) as usize;
        if relay_count > MAX_SNAPSHOT_RELAYS {
            return Err(Error::Decode("too many relays in snapshot".into()));
        }
        let mut relays = Vec::with_capacity(relay_count.min(256));
        for _ in 0..relay_count {
            let len = u32::from_be_bytes(take(&mut cur, 4)?.try_into().expect("4 bytes")) as usize;
            if len > 8192 {
                return Err(Error::Decode("relay record too large".into()));
            }
            relays.push(PeerRecord::from_bytes(take(&mut cur, len)?)?);
        }

        let sig_count =
            u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
        if sig_count > MAX_WITNESSES {
            return Err(Error::Decode("too many witness signatures".into()));
        }
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let mut witness = [0u8; 32];
            witness.copy_from_slice(take(&mut cur, 32)?);
            let mut sig = [0u8; SIGNATURE_LEN];
            sig.copy_from_slice(take(&mut cur, SIGNATURE_LEN)?);
            signatures.push(WitnessSignature { witness, sig });
        }
        if !cur.is_empty() {
            return Err(Error::Decode("trailing bytes after snapshot".into()));
        }

        Ok(SignedSnapshot {
            snapshot: Snapshot {
                created_at,
                expires_at,
                relays,
            },
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::now_unix;

    fn relay(identity: &NodeIdentity) -> PeerRecord {
        PeerRecord::build_signed(
            identity,
            vec!["1.2.3.4:9000".into()],
            true,
            false,
            now_unix() + 3600,
            1,
        )
        .unwrap()
    }

    fn witnessed(witnesses: &[&NodeIdentity], relays: Vec<PeerRecord>) -> SignedSnapshot {
        let snapshot = Snapshot {
            created_at: now_unix(),
            expires_at: now_unix() + 86_400,
            relays,
        };
        let signatures = witnesses.iter().map(|w| snapshot.sign(w)).collect();
        SignedSnapshot {
            snapshot,
            signatures,
        }
    }

    fn key(identity: &NodeIdentity) -> [u8; 32] {
        identity.public().signing.to_bytes()
    }

    #[test]
    fn snapshot_signs_verifies_and_roundtrips() {
        let w1 = NodeIdentity::generate().unwrap();
        let w2 = NodeIdentity::generate().unwrap();
        let r1 = NodeIdentity::generate().unwrap();
        let r2 = NodeIdentity::generate().unwrap();

        let signed = witnessed(&[&w1, &w2], vec![relay(&r1), relay(&r2)]);
        let trusted = [key(&w1), key(&w2)];
        let now = now_unix();

        signed.verify(&trusted, 1, now).unwrap();
        signed.verify(&trusted, 2, now).unwrap();
        assert_eq!(signed.relays(now).len(), 2);

        let parsed = SignedSnapshot::from_bytes(&signed.to_bytes()).unwrap();
        assert_eq!(parsed, signed);
        parsed.verify(&trusted, 2, now).unwrap();
    }

    #[test]
    fn unknown_witnesses_do_not_count() {
        let rogue = NodeIdentity::generate().unwrap();
        let trusted_witness = NodeIdentity::generate().unwrap();
        let signed = witnessed(&[&rogue], vec![]);
        assert!(signed
            .verify(&[key(&trusted_witness)], 1, now_unix())
            .is_err());
    }

    #[test]
    fn duplicate_witness_signatures_count_once() {
        let w = NodeIdentity::generate().unwrap();
        let other = NodeIdentity::generate().unwrap();
        let mut signed = witnessed(&[&w], vec![]);
        let dup = signed.signatures[0].clone();
        signed.signatures.push(dup);
        // One witness signing twice must not satisfy a threshold of two.
        assert!(signed
            .verify(&[key(&w), key(&other)], 2, now_unix())
            .is_err());
        signed
            .verify(&[key(&w), key(&other)], 1, now_unix())
            .unwrap();
    }

    #[test]
    fn tampered_snapshots_are_rejected() {
        let w = NodeIdentity::generate().unwrap();
        let r = NodeIdentity::generate().unwrap();
        let trusted = [key(&w)];
        let now = now_unix();

        // Stretching the validity window breaks the witness signature.
        let mut signed = witnessed(&[&w], vec![relay(&r)]);
        signed.snapshot.expires_at += 1;
        assert!(signed.verify(&trusted, 1, now).is_err());

        // Injecting a relay breaks the witness signature.
        let mut signed = witnessed(&[&w], vec![relay(&r)]);
        let intruder = NodeIdentity::generate().unwrap();
        signed.snapshot.relays.push(relay(&intruder));
        assert!(signed.verify(&trusted, 1, now).is_err());
    }

    #[test]
    fn a_witnessed_forged_record_is_fatal() {
        // Even if a (compromised) witness signs a snapshot containing a record
        // with a bad node signature, clients reject the whole snapshot.
        let w = NodeIdentity::generate().unwrap();
        let r = NodeIdentity::generate().unwrap();
        let mut forged = relay(&r);
        forged.exit = true; // breaks the record's own signature
        let signed = witnessed(&[&w], vec![forged]);
        assert!(signed.verify(&[key(&w)], 1, now_unix()).is_err());
    }

    #[test]
    fn expired_snapshots_and_records_age_out() {
        let w = NodeIdentity::generate().unwrap();
        let r = NodeIdentity::generate().unwrap();
        let now = now_unix();

        // Expired snapshot: rejected outright.
        let snapshot = Snapshot {
            created_at: now - 100,
            expires_at: now - 1,
            relays: vec![],
        };
        let signatures = vec![snapshot.sign(&w)];
        let signed = SignedSnapshot {
            snapshot,
            signatures,
        };
        assert!(signed.verify(&[key(&w)], 1, now).is_err());

        // Valid snapshot holding an expired record: verifies, but the record
        // is filtered out of the usable relay list.
        let stale = PeerRecord::build_signed(
            &r,
            vec!["1.2.3.4:9000".into()],
            true,
            false,
            now.saturating_sub(1).max(1),
            1,
        )
        .unwrap();
        let signed = witnessed(&[&w], vec![stale]);
        signed.verify(&[key(&w)], 1, now).unwrap();
        assert!(signed.relays(now).is_empty());
    }

    #[test]
    fn impossible_thresholds_are_rejected() {
        let w = NodeIdentity::generate().unwrap();
        let signed = witnessed(&[&w], vec![]);
        assert!(signed.verify(&[key(&w)], 0, now_unix()).is_err());
        assert!(signed.verify(&[key(&w)], 2, now_unix()).is_err());
        assert!(signed.verify(&[], 1, now_unix()).is_err());
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed = 0xdead_beef_cafe_f00du64;
        for _ in 0..3000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (seed >> 40) as usize % 4000;
            let bytes: Vec<u8> = (0..len).map(|i| (seed >> (i % 8 * 8)) as u8).collect();
            let _ = SignedSnapshot::from_bytes(&bytes);
        }
    }
}
