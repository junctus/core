//! Signed bootstrap records for DoH rendezvous (M18).
//!
//! A client needs *some* first contact (mirrors to fetch snapshots from, and the
//! witness keys to trust). Baking those into the binary works but can't rotate
//! without a rebuild, and a fixed mirror list is easy to block. A **bootstrap
//! record** decouples the two: a long-lived **bootstrap key** (baked into the
//! client) signs a small record listing the *current* mirrors and witnesses,
//! published in DNS and fetched over **DNS-over-HTTPS** so the lookup is
//! encrypted and hard to censor. Operators rotate mirrors/witnesses by
//! re-signing the record; only the bootstrap key stays fixed.
//!
//! This module is the (network-free, fully testable) record format + signature
//! verification. The DoH transport lives in the CLI (it needs an HTTP client).

use neo_core::{verify_signature, Error, NodeIdentity, Result, SIGNATURE_LEN};

/// Wire/version tag for a serialized bootstrap record.
const BOOTSTRAP_VERSION: u8 = 1;
/// Domain separator for the bootstrap signature.
const BOOTSTRAP_DOMAIN: &[u8] = b"neo-bootstrap-v1";
/// Bound on mirrors / witnesses in one record (keeps a TXT record small).
const MAX_MIRRORS: usize = 16;
const MAX_WITNESSES: usize = 16;

/// A signed list of current discovery mirrors and trusted witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapRecord {
    /// Unix seconds the record was signed (for rollback/freshness checks).
    pub created_at: u64,
    /// Discovery mirror base URLs (untrusted transports; witnesses give integrity).
    pub mirrors: Vec<String>,
    /// Ed25519 witness keys a snapshot must be signed by.
    pub witnesses: Vec<[u8; 32]>,
    /// The bootstrap key that signed this record.
    pub bootstrap_key: [u8; 32],
    /// Signature by `bootstrap_key` over the record body.
    pub sig: [u8; SIGNATURE_LEN],
}

impl BootstrapRecord {
    /// Build and sign a record with the bootstrap `identity`.
    pub fn sign(
        identity: &NodeIdentity,
        created_at: u64,
        mirrors: Vec<String>,
        witnesses: Vec<[u8; 32]>,
    ) -> Result<Self> {
        let mut record = Self {
            created_at,
            mirrors,
            witnesses,
            bootstrap_key: identity.public().signing.to_bytes(),
            sig: [0u8; SIGNATURE_LEN],
        };
        record.check_limits()?;
        record.sig = identity.sign(&record.signable()).to_bytes();
        Ok(record)
    }

    /// Verify the record against a set of trusted bootstrap keys at time `now`.
    /// The signing key must be trusted and the signature valid; `not_before`
    /// (a previously-seen `created_at`) rejects rollback to an older record.
    pub fn verify(&self, trusted_keys: &[[u8; 32]], not_before: u64) -> Result<()> {
        self.check_limits()?;
        if !trusted_keys.contains(&self.bootstrap_key) {
            return Err(Error::Crypto(
                "bootstrap record signed by an untrusted key".into(),
            ));
        }
        if self.created_at < not_before {
            return Err(Error::Crypto(
                "bootstrap record is older than the last seen".into(),
            ));
        }
        verify_signature(&self.bootstrap_key, &self.signable(), &self.sig)
    }

    fn check_limits(&self) -> Result<()> {
        if self.mirrors.is_empty() || self.mirrors.len() > MAX_MIRRORS {
            return Err(Error::Config("bootstrap mirror count out of range".into()));
        }
        if self.witnesses.is_empty() || self.witnesses.len() > MAX_WITNESSES {
            return Err(Error::Config("bootstrap witness count out of range".into()));
        }
        if self.mirrors.iter().any(|m| m.len() > 255) {
            return Err(Error::Config("bootstrap mirror URL too long".into()));
        }
        Ok(())
    }

    fn signable(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(BOOTSTRAP_DOMAIN);
        self.encode_body(&mut out);
        out
    }

    fn encode_body(&self, out: &mut Vec<u8>) {
        out.push(BOOTSTRAP_VERSION);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.bootstrap_key);
        out.push(self.mirrors.len() as u8);
        for m in &self.mirrors {
            out.push(m.len() as u8);
            out.extend_from_slice(m.as_bytes());
        }
        out.push(self.witnesses.len() as u8);
        for w in &self.witnesses {
            out.extend_from_slice(w);
        }
    }

    /// Encode to hex for a DNS TXT record (verifiers hex-decode + [`verify`]).
    pub fn to_txt(&self) -> String {
        let mut body = Vec::new();
        self.encode_body(&mut body);
        body.extend_from_slice(&self.sig);
        hex::encode(body)
    }

    /// Parse a hex TXT value. Does **not** verify — call [`verify`](Self::verify).
    pub fn from_txt(txt: &str) -> Result<Self> {
        let bytes =
            hex::decode(txt.trim()).map_err(|_| Error::Decode("bootstrap not hex".into()))?;
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if cur.len() < n {
                return Err(Error::Decode("truncated bootstrap record".into()));
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }

        let mut cur = bytes;
        if take(&mut cur, 1)?[0] != BOOTSTRAP_VERSION {
            return Err(Error::Decode("unsupported bootstrap version".into()));
        }
        let created_at = u64::from_be_bytes(take(&mut cur, 8)?.try_into().expect("8 bytes"));
        let mut bootstrap_key = [0u8; 32];
        bootstrap_key.copy_from_slice(take(&mut cur, 32)?);

        let n_mirrors = take(&mut cur, 1)?[0] as usize;
        if n_mirrors > MAX_MIRRORS {
            return Err(Error::Decode("too many mirrors".into()));
        }
        let mut mirrors = Vec::with_capacity(n_mirrors);
        for _ in 0..n_mirrors {
            let len = take(&mut cur, 1)?[0] as usize;
            let raw = take(&mut cur, len)?;
            mirrors.push(
                std::str::from_utf8(raw)
                    .map_err(|_| Error::Decode("mirror not UTF-8".into()))?
                    .to_string(),
            );
        }

        let n_witnesses = take(&mut cur, 1)?[0] as usize;
        if n_witnesses > MAX_WITNESSES {
            return Err(Error::Decode("too many witnesses".into()));
        }
        let mut witnesses = Vec::with_capacity(n_witnesses);
        for _ in 0..n_witnesses {
            let mut w = [0u8; 32];
            w.copy_from_slice(take(&mut cur, 32)?);
            witnesses.push(w);
        }

        let mut sig = [0u8; SIGNATURE_LEN];
        sig.copy_from_slice(take(&mut cur, SIGNATURE_LEN)?);
        if !cur.is_empty() {
            return Err(Error::Decode(
                "trailing bytes after bootstrap record".into(),
            ));
        }

        Ok(Self {
            created_at,
            mirrors,
            witnesses,
            bootstrap_key,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(identity: &NodeIdentity) -> BootstrapRecord {
        BootstrapRecord::sign(
            identity,
            1000,
            vec!["https://discovery.junctus.org".into()],
            vec![[7u8; 32], [9u8; 32]],
        )
        .unwrap()
    }

    #[test]
    fn signs_verifies_and_roundtrips_through_txt() {
        let boot = NodeIdentity::generate().unwrap();
        let rec = record(&boot);
        let trusted = [boot.public().signing.to_bytes()];

        rec.verify(&trusted, 0).unwrap();
        let parsed = BootstrapRecord::from_txt(&rec.to_txt()).unwrap();
        assert_eq!(parsed, rec);
        parsed.verify(&trusted, 0).unwrap();
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let boot = NodeIdentity::generate().unwrap();
        let other = NodeIdentity::generate().unwrap();
        let rec = record(&boot);
        assert!(rec.verify(&[other.public().signing.to_bytes()], 0).is_err());
    }

    #[test]
    fn tampering_and_rollback_are_rejected() {
        let boot = NodeIdentity::generate().unwrap();
        let trusted = [boot.public().signing.to_bytes()];

        // Tampering with a mirror breaks the signature.
        let mut rec = record(&boot);
        rec.mirrors[0] = "https://evil.example".into();
        assert!(rec.verify(&trusted, 0).is_err());

        // A record older than the last seen is rejected (anti-rollback).
        let rec = record(&boot); // created_at = 1000
        assert!(rec.verify(&trusted, 2000).is_err());
        assert!(rec.verify(&trusted, 500).is_ok());
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed = 0xabcd_1234_5678_9012u64;
        for _ in 0..2000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = (seed >> 40) as usize % 400;
            let bytes: Vec<u8> = (0..len).map(|i| (seed >> (i % 8 * 8)) as u8).collect();
            let _ = BootstrapRecord::from_txt(&hex::encode(&bytes));
        }
    }
}
