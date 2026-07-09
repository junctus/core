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
#[derive(Clone, Debug)]
pub struct KeyCommitments(pub Vec<CompressedRistretto>);

impl KeyShare {
    /// Verify this share against the public commitments: `f(x)·G == Σ_j c_j·x^j`.
    /// A member that fails this was handed (or is offering) a bad share.
    pub fn verify(&self, commitments: &KeyCommitments) -> bool {
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
    /// the request. Rejects any share that fails Feldman verification (with
    /// attribution), and fails if fewer than the threshold remain.
    pub fn open(&self, offered: &[KeyShare]) -> Result<ClearnetRequest> {
        // Verify + de-duplicate by member index; a bad share is attributable.
        let mut verified: Vec<&KeyShare> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for share in offered {
            if !share.verify(&self.commitments) {
                return Err(Error::Crypto(format!(
                    "committee member {} offered an invalid share",
                    share.member
                )));
            }
            if seen.insert(share.member) {
                verified.push(share);
            }
        }
        if verified.len() < self.cfg.threshold {
            return Err(Error::Crypto(format!(
                "need {} verified shares, have {}",
                self.cfg.threshold,
                verified.len()
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
            // xi != xj because member indices are distinct, so invert is safe.
            lambda *= (Scalar::ZERO - xj) * (xi - xj).invert();
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
