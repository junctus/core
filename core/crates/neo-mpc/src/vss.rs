//! Verifiable committee sessions (M20) — advancing the committee exit toward
//! MPC-TLS.
//!
//! The base committee ([`crate`] root) threshold-shares the request body and
//! detects a corrupted share, but cannot say *which* member supplied it, and it
//! shares the plaintext body directly. This module strengthens that:
//!
//! - The request is AEAD-encrypted under a fresh random **session key**; only
//!   the *key* is shared, so the ciphertext can be handed to the whole committee
//!   (Krawczyk SSMS composition).
//! - The key is shared with **Feldman verifiable secret sharing** over Ristretto:
//!   the dealer publishes commitments to the sharing polynomial, so every member
//!   can *verify its own share* against public data, and a member offering a
//!   corrupted share is detected **and attributed** at combination time.
//! - Any `k-1` members learn nothing about the key (Shamir's information-theoretic
//!   secrecy), hence nothing about the request; any `k` recover the key and
//!   decrypt.
//!
//! **Honest boundary (still deferred):** this is the *trust-split + verifiable
//! custody* core. Full MPC-TLS — computing the TLS session under multi-party
//! computation so the plaintext is never assembled at a single point, including
//! the send to the real server — remains research (TLSNotary/`mpz` lineage).
//! Here, key reconstruction does assemble the key (and thus the request) in one
//! place at decrypt time.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use curve25519_dalek::Scalar;
use neo_core::{Error, Result};

use crate::{ClearnetRequest, CommitteeConfig};

const NONCE: [u8; 12] = *b"neo-mpc-v1\0\0";

/// One member's verifiable share of the session key: an evaluation point.
#[derive(Clone, Debug)]
pub struct KeyShare {
    /// Member index `x` (1..=n), the polynomial evaluation point.
    pub member: u8,
    /// The share `f(x)`.
    pub value: Scalar,
}

/// Public Feldman commitments to the sharing polynomial's coefficients. Every
/// member checks its share against these — no trusted channel required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCommitments(pub Vec<CompressedRistretto>);

impl KeyShare {
    /// Verify this share against the public commitments: `f(x)·G == Σ_j c_j·x^j`.
    /// A member that fails this was handed (or is offering) a bad share.
    pub fn verify(&self, commitments: &KeyCommitments) -> bool {
        // x = 0 is the polynomial's constant term — the *secret itself*, not a
        // share index. A share claiming member 0 would test `value·G == c_0`
        // (i.e. value == secret) and must never be accepted as a valid share.
        if self.member == 0 {
            return false;
        }
        let Some(coeffs): Option<Vec<RistrettoPoint>> = commitments
            .0
            .iter()
            .map(|c| c.decompress())
            .collect::<Option<_>>()
        else {
            return false;
        };
        let x = Scalar::from(self.member as u64);
        let mut acc = RistrettoPoint::identity();
        let mut x_pow = Scalar::ONE;
        for c in &coeffs {
            acc += c * x_pow;
            x_pow *= x;
        }
        RISTRETTO_BASEPOINT_POINT * self.value == acc
    }

    /// Serialize as `member (1) || value (32)` = 33 bytes.
    ///
    /// The share value is **secret** key material — serialize it only to deliver
    /// it to its own member over a private/encrypted channel (e.g. the DKG
    /// dealing round), never in the clear.
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = self.member;
        out[1..33].copy_from_slice(self.value.as_bytes());
        out
    }

    /// Parse [`to_bytes`](Self::to_bytes). Rejects member 0 and non-canonical scalars.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = bytes;
        let member = take(&mut cur, 1)?[0];
        if member == 0 {
            return Err(Error::Decode("key share member index 0 is invalid".into()));
        }
        let value = scalar_from(take(&mut cur, 32)?)?;
        if !cur.is_empty() {
            return Err(Error::Decode("trailing bytes after key share".into()));
        }
        Ok(KeyShare { member, value })
    }
}

impl KeyCommitments {
    /// Serialize as `count (u16 BE) || count × 32-byte points`. Public data.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.0.len() * 32);
        out.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        for point in &self.0 {
            out.extend_from_slice(point.as_bytes());
        }
        out
    }

    /// Parse [`to_bytes`](Self::to_bytes). Bounds the commitment count (a degree
    /// bounded by [`MAX_MEMBERS`](crate::MAX_MEMBERS)) so a forged count can't
    /// trigger an unbounded allocation; point validity is checked when used.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = bytes;
        let count = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
        if count == 0 || count > crate::MAX_MEMBERS {
            return Err(Error::Decode("invalid commitment count".into()));
        }
        let mut points = Vec::with_capacity(count);
        for _ in 0..count {
            points.push(CompressedRistretto(
                take(&mut cur, 32)?.try_into().expect("32 bytes"),
            ));
        }
        if !cur.is_empty() {
            return Err(Error::Decode("trailing bytes after commitments".into()));
        }
        Ok(KeyCommitments(points))
    }
}

/// A committee session: the encrypted request plus verifiable key shares.
pub struct CommitteeSession {
    /// The AEAD-encrypted request (safe to give the whole committee).
    pub ciphertext: Vec<u8>,
    /// Public commitments for verifying shares.
    pub commitments: KeyCommitments,
    shares: Vec<KeyShare>,
    cfg: CommitteeConfig,
}

impl CommitteeSession {
    /// Deal a verifiable committee session for `request`.
    pub fn deal(request: &ClearnetRequest, cfg: CommitteeConfig) -> Result<Self> {
        cfg.validate()?;

        // 1. Random session key; AEAD-encrypt the request under it.
        let key_scalar = random_scalar()?;
        let aead_key = aead_key_from(&key_scalar);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&NONCE), request.body()?.as_slice())
            .map_err(|_| Error::Crypto("committee AEAD encrypt failed".into()))?;

        // 2. Feldman-share the key scalar: random degree-(k-1) polynomial with
        //    constant term = key_scalar; commitments c_j = coeff_j·G.
        let k = cfg.threshold;
        let mut coeffs = Vec::with_capacity(k);
        coeffs.push(key_scalar);
        for _ in 1..k {
            coeffs.push(random_scalar()?);
        }
        let commitments = KeyCommitments(
            coeffs
                .iter()
                .map(|a| (RISTRETTO_BASEPOINT_POINT * a).compress())
                .collect(),
        );

        let mut shares = Vec::with_capacity(cfg.members);
        for member in 1..=cfg.members as u8 {
            let x = Scalar::from(member as u64);
            // Horner evaluation of the polynomial at x.
            let mut value = Scalar::ZERO;
            for coeff in coeffs.iter().rev() {
                value = value * x + coeff;
            }
            shares.push(KeyShare { member, value });
        }

        Ok(Self {
            ciphertext,
            commitments,
            shares,
            cfg,
        })
    }

    /// The share held by the member at 0-based committee position `i`.
    pub fn share_of(&self, i: usize) -> Option<&KeyShare> {
        self.shares.get(i)
    }

    /// Reconstruct the key from `>= threshold` **verified** shares and decrypt
    /// the request.
    ///
    /// A share that fails Feldman verification is **skipped and attributed**, not
    /// treated as fatal: as long as `threshold` honest shares are present the open
    /// still succeeds, so a single malicious member cannot veto reconstruction by
    /// injecting one bad share (robustness). It fails only if fewer than the
    /// threshold *valid* shares remain — and then names the members whose shares
    /// were rejected.
    pub fn open(&self, offered: &[KeyShare]) -> Result<ClearnetRequest> {
        let mut verified: Vec<&KeyShare> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut rejected: Vec<u8> = Vec::new();
        for share in offered {
            if !share.verify(&self.commitments) {
                if !rejected.contains(&share.member) {
                    rejected.push(share.member);
                }
                continue;
            }
            if seen.insert(share.member) {
                verified.push(share);
            }
        }
        if verified.len() < self.cfg.threshold {
            let attribution = if rejected.is_empty() {
                String::new()
            } else {
                let names: Vec<String> = rejected.iter().map(|m| format!("member {m}")).collect();
                format!(" (invalid shares from {})", names.join(", "))
            };
            return Err(Error::Crypto(format!(
                "need {} verified shares, have {}{}",
                self.cfg.threshold,
                verified.len(),
                attribution
            )));
        }

        let key_scalar = lagrange_at_zero(&verified[..self.cfg.threshold])?;
        let aead_key = aead_key_from(&key_scalar);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
        let wire = cipher
            .decrypt(Nonce::from_slice(&NONCE), self.ciphertext.as_slice())
            .map_err(|_| {
                Error::Crypto("committee decrypt failed (wrong/insufficient shares)".into())
            })?;
        ClearnetRequest::from_body(&wire)
    }
}

/// Lagrange interpolation of the shared polynomial at `x = 0` (the secret):
/// `secret = Σ_i y_i · λ_i(0)`, where `λ_i(0) = ∏_{j≠i} (-x_j)/(x_i - x_j)`.
fn lagrange_at_zero(shares: &[&KeyShare]) -> Result<Scalar> {
    let mut secret = Scalar::ZERO;
    for (i, si) in shares.iter().enumerate() {
        let xi = Scalar::from(si.member as u64);
        let mut lambda = Scalar::ONE;
        for (j, sj) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = Scalar::from(sj.member as u64);
            // Member indices must be distinct (open() de-duplicates and rejects
            // index 0), so xi - xj is non-zero. Guard anyway: a zero denominator
            // would otherwise invert to zero and silently corrupt the secret.
            let denom = xi - xj;
            if denom == Scalar::ZERO {
                return Err(Error::Crypto(
                    "duplicate committee member index in reconstruction".into(),
                ));
            }
            lambda *= (Scalar::ZERO - xj) * denom.invert();
        }
        secret += si.value * lambda;
    }
    Ok(secret)
}

fn aead_key_from(scalar: &Scalar) -> [u8; 32] {
    blake3::derive_key("neo-mpc-session-key-v1", scalar.as_bytes())
}

fn random_scalar() -> Result<Scalar> {
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

/// Split `n` bytes off the front of `cur`, erroring (not panicking) if short.
fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if cur.len() < n {
        return Err(Error::Decode("truncated committee encoding".into()));
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

/// Parse a canonical 32-byte scalar, rejecting a non-canonical encoding.
fn scalar_from(bytes: &[u8]) -> Result<Scalar> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Decode("scalar must be 32 bytes".into()))?;
    Option::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| Error::Decode("non-canonical scalar".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ClearnetRequest {
        ClearnetRequest {
            destination: "example.com:443".into(),
            payload: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        }
    }

    fn cfg() -> CommitteeConfig {
        CommitteeConfig {
            members: 5,
            threshold: 3,
        }
    }

    #[test]
    fn threshold_verified_shares_open_the_request() {
        let session = CommitteeSession::deal(&request(), cfg()).unwrap();
        let shares: Vec<KeyShare> = [0, 2, 4]
            .iter()
            .map(|&i| session.share_of(i).unwrap().clone())
            .collect();
        assert_eq!(session.open(&shares).unwrap(), request());
    }

    #[test]
    fn every_share_verifies_against_the_public_commitments() {
        let session = CommitteeSession::deal(&request(), cfg()).unwrap();
        for i in 0..5 {
            assert!(session.share_of(i).unwrap().verify(&session.commitments));
        }
    }

    #[test]
    fn a_minority_cannot_open() {
        let session = CommitteeSession::deal(&request(), cfg()).unwrap();
        let shares: Vec<KeyShare> = [0, 1]
            .iter()
            .map(|&i| session.share_of(i).unwrap().clone())
            .collect();
        assert!(session.open(&shares).is_err());
    }

    #[test]
    fn a_corrupted_share_is_detected_and_attributed() {
        let session = CommitteeSession::deal(&request(), cfg()).unwrap();
        let mut shares: Vec<KeyShare> = [0, 2, 4]
            .iter()
            .map(|&i| session.share_of(i).unwrap().clone())
            .collect();
        let victim = shares[1].member;
        shares[1].value += Scalar::ONE; // corrupt one member's share

        assert!(!shares[1].verify(&session.commitments));
        let err = session.open(&shares).unwrap_err();
        assert!(
            format!("{err}").contains(&format!("member {victim}")),
            "the bad share must be attributed to its member"
        );
    }

    #[test]
    fn one_bad_share_cannot_veto_a_reconstruction_with_a_quorum() {
        // Robustness: offer a full quorum of honest shares plus one corrupted
        // share. The bad share is skipped, not fatal, so the open still succeeds.
        let session = CommitteeSession::deal(&request(), cfg()).unwrap();
        let mut shares: Vec<KeyShare> = [0, 1, 2, 4]
            .iter()
            .map(|&i| session.share_of(i).unwrap().clone())
            .collect();
        shares[3].value += Scalar::ONE; // corrupt member 5; members 1,2,3 remain (== threshold)

        assert_eq!(
            session.open(&shares).unwrap(),
            request(),
            "a quorum of honest shares opens despite one injected bad share"
        );
    }

    #[test]
    fn a_share_claiming_member_zero_never_verifies() {
        // x = 0 is the secret's own evaluation point, not a share index.
        let session = CommitteeSession::deal(&request(), cfg()).unwrap();
        let mut forged = session.share_of(0).unwrap().clone();
        forged.member = 0;
        assert!(
            !forged.verify(&session.commitments),
            "a share at index 0 must be rejected outright"
        );
    }

    #[test]
    fn key_share_and_commitments_roundtrip_and_reject_junk() {
        let session = CommitteeSession::deal(&request(), cfg()).unwrap();
        let share = session.share_of(0).unwrap().clone();

        let parsed = KeyShare::from_bytes(&share.to_bytes()).unwrap();
        assert_eq!(parsed.member, share.member);
        assert!(parsed.verify(&session.commitments));

        let commitments = KeyCommitments::from_bytes(&session.commitments.to_bytes()).unwrap();
        assert_eq!(commitments.0, session.commitments.0);
        assert!(share.verify(&commitments));

        // Rejections: member 0, a short buffer, and a zero commitment count.
        let mut bad = share.to_bytes();
        bad[0] = 0;
        assert!(KeyShare::from_bytes(&bad).is_err());
        assert!(KeyShare::from_bytes(&share.to_bytes()[..20]).is_err());
        assert!(KeyCommitments::from_bytes(&[0, 0]).is_err());
    }

    #[test]
    fn no_single_share_reveals_the_key_material() {
        // A single (verifiable) share is a random-looking scalar; it does not
        // let a member decrypt (needs threshold), which `a_minority_cannot_open`
        // covers. Here we sanity-check distinct members get distinct shares.
        let session = CommitteeSession::deal(&request(), cfg()).unwrap();
        let s0 = session.share_of(0).unwrap().value;
        let s1 = session.share_of(1).unwrap().value;
        assert_ne!(s0, s1);
    }
}
