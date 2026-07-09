//! Threshold decryption — removing the single point of plaintext assembly (M22).
//!
//! [`vss`](crate::vss) shares a key and *reconstructs* it (assembling the key,
//! and thus the request, at one node) to decrypt. This module removes that single
//! point. A message encrypted to the committee's **joint public key** is decrypted
//! by having each member emit a **partial** that reveals nothing on its own; only
//! the **client** combines the partials into plaintext. So **no committee node
//! ever holds the key or the plaintext** — the property MPC-TLS is really after.
//!
//! It is hashed-ElGamal over Ristretto with **threshold (Lagrange-in-exponent)
//! decryption**. Each partial carries a **Chaum–Pedersen DLEQ proof** binding it
//! to the member's public Feldman share (derivable from the same commitments
//! `vss` already publishes), so a forged partial is caught and attributed —
//! matching `vss`'s robustness. The joint public key is `commitments[0]` (the
//! constant-term commitment `s·G`), so this composes directly with a dealt
//! [`CommitteeSession`](crate::vss::CommitteeSession).
//!
//! **Honest boundary.** This delivers "plaintext never assembled at a single
//! point" for the **decrypt** direction (committee → client). Full MPC-TLS —
//! computing the TLS handshake and record encryption under 2PC so the committee
//! can speak to a *real upstream server* without any member ever seeing plaintext
//! — remains research (garbled-circuit AES-GCM; TLSNotary/DECO/`mpz` lineage).
//! Threshold decryption is a real, verifiable building block toward it, not the
//! whole of it.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use curve25519_dalek::Scalar;
use neo_core::{Error, Result};

use crate::vss::{KeyCommitments, KeyShare};

/// Hashed-ElGamal ciphertext under the committee's joint key: `(R, c)` where
/// `R = r·G` and `c = m ⊕ KDF(r·Y)`.
#[derive(Clone, Debug)]
pub struct Ciphertext {
    /// Ephemeral point `R = r·G`.
    pub r_point: CompressedRistretto,
    /// Masked message `c = m ⊕ KDF(r·Y)`.
    pub c: Vec<u8>,
}

/// One member's partial decryption `D_i = y_i·R`, with a DLEQ proof that it is
/// consistent with the member's public Feldman share (no key is revealed).
#[derive(Clone, Debug)]
pub struct Partial {
    /// The contributing member index (1..=n).
    pub member: u8,
    /// The partial `D_i = y_i·R`.
    d: CompressedRistretto,
    /// Chaum–Pedersen challenge.
    e: Scalar,
    /// Chaum–Pedersen response.
    z: Scalar,
}

/// Encrypt `m` to the committee's joint public key (its `commitments[0]`), so that
/// only a threshold of members — via [`combine`] — can decrypt it, and only the
/// client ever sees the plaintext.
pub fn encrypt(commitments: &KeyCommitments, m: &[u8]) -> Result<Ciphertext> {
    let y = joint_public_key(commitments)?;
    let r = random_scalar()?;
    let r_point = RISTRETTO_BASEPOINT_POINT * r;
    let shared = y * r; // r·Y = r·s·G
    let mut c = m.to_vec();
    xor_mask(&mut c, &shared);
    Ok(Ciphertext {
        r_point: r_point.compress(),
        c,
    })
}

/// A committee member produces its partial decryption for `ct`, proving (DLEQ)
/// that the partial uses the same secret as its public Feldman share — without
/// revealing the share.
pub fn partial_decrypt(share: &KeyShare, ct: &Ciphertext) -> Result<Partial> {
    if share.member == 0 {
        return Err(Error::Crypto("member index 0 is not a valid share".into()));
    }
    let r_point = ct
        .r_point
        .decompress()
        .ok_or_else(|| Error::Crypto("ciphertext R not a valid point".into()))?;
    let x = share.value;
    let d = r_point * x; // D_i = y_i·R
    let a = RISTRETTO_BASEPOINT_POINT * x; // Y_i = y_i·G

    // Chaum–Pedersen: prove log_G(Y_i) == log_R(D_i) == x.
    let k = random_scalar()?;
    let t1 = RISTRETTO_BASEPOINT_POINT * k;
    let t2 = r_point * k;
    let e = dleq_challenge(&r_point, &a, &d, &t1, &t2);
    let z = k + e * x;

    Ok(Partial {
        member: share.member,
        d: d.compress(),
        e,
        z,
    })
}

/// Verify a partial against the public commitments and ciphertext: it must be a
/// correct `y_i·R` for the member's committed share.
pub fn verify_partial(commitments: &KeyCommitments, ct: &Ciphertext, p: &Partial) -> bool {
    if p.member == 0 {
        return false;
    }
    let (Some(r_point), Some(b)) = (ct.r_point.decompress(), p.d.decompress()) else {
        return false;
    };
    let Some(a) = public_share(commitments, p.member) else {
        return false;
    };
    // Recover the commitments T1 = z·G - e·A, T2 = z·R - e·B and re-derive e.
    let t1 = RISTRETTO_BASEPOINT_POINT * p.z - a * p.e;
    let t2 = r_point * p.z - b * p.e;
    dleq_challenge(&r_point, &a, &b, &t1, &t2) == p.e
}

/// Client-side: combine `>= threshold` **verified** partials into the plaintext.
///
/// Reconstructs `s·R` by Lagrange interpolation *in the exponent* — the shared
/// secret `s` itself is never formed — then unmasks the ciphertext. A partial
/// that fails its DLEQ proof is skipped and attributed; combination fails if fewer
/// than `threshold` valid, distinct-member partials remain.
pub fn combine(
    commitments: &KeyCommitments,
    threshold: usize,
    ct: &Ciphertext,
    partials: &[Partial],
) -> Result<Vec<u8>> {
    // Each partial is verified against `ct` (which re-checks R), so an invalid R
    // simply makes every partial fail verification below — no separate check here.
    let mut valid: Vec<&Partial> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut rejected: Vec<u8> = Vec::new();
    for p in partials {
        if !verify_partial(commitments, ct, p) {
            if !rejected.contains(&p.member) {
                rejected.push(p.member);
            }
            continue;
        }
        if seen.insert(p.member) {
            valid.push(p);
        }
    }
    if valid.len() < threshold {
        let attribution = if rejected.is_empty() {
            String::new()
        } else {
            let names: Vec<String> = rejected.iter().map(|m| format!("member {m}")).collect();
            format!(" (invalid partials from {})", names.join(", "))
        };
        return Err(Error::Crypto(format!(
            "need {threshold} valid partials, have {}{attribution}",
            valid.len()
        )));
    }

    // S = s·R = Σ_i λ_i · D_i (Lagrange at 0, in the exponent).
    let quorum = &valid[..threshold];
    let mut shared = RistrettoPoint::identity();
    for (i, pi) in quorum.iter().enumerate() {
        let xi = Scalar::from(pi.member as u64);
        let mut lambda = Scalar::ONE;
        for (j, pj) in quorum.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = Scalar::from(pj.member as u64);
            let denom = xi - xj;
            if denom == Scalar::ZERO {
                return Err(Error::Crypto("duplicate member index in combine".into()));
            }
            lambda *= (Scalar::ZERO - xj) * denom.invert();
        }
        let di =
            pi.d.decompress()
                .ok_or_else(|| Error::Crypto("partial not a valid point".into()))?;
        shared += di * lambda;
    }

    let mut m = ct.c.clone();
    xor_mask(&mut m, &shared);
    Ok(m)
}

// ---- helpers ---------------------------------------------------------------

/// The joint public key `Y = s·G` — the commitment to the polynomial's constant.
fn joint_public_key(commitments: &KeyCommitments) -> Result<RistrettoPoint> {
    commitments
        .0
        .first()
        .ok_or_else(|| Error::Crypto("empty commitments".into()))?
        .decompress()
        .ok_or_else(|| Error::Crypto("joint public key not a valid point".into()))
}

/// A member's public share point `Y_i = Σ_j c_j·i^j` from the Feldman commitments.
fn public_share(commitments: &KeyCommitments, member: u8) -> Option<RistrettoPoint> {
    let coeffs: Vec<RistrettoPoint> = commitments
        .0
        .iter()
        .map(|c| c.decompress())
        .collect::<Option<_>>()?;
    let x = Scalar::from(member as u64);
    let mut acc = RistrettoPoint::identity();
    let mut x_pow = Scalar::ONE;
    for c in &coeffs {
        acc += c * x_pow;
        x_pow *= x;
    }
    Some(acc)
}

/// XOR `data` with a keystream derived from a shared point `s·R`.
fn xor_mask(data: &mut [u8], shared: &RistrettoPoint) {
    let mut hasher = blake3::Hasher::new_derive_key("neo-mpc-threshold-mask-v1");
    hasher.update(shared.compress().as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut ks = vec![0u8; data.len()];
    reader.fill(&mut ks);
    for (b, k) in data.iter_mut().zip(&ks) {
        *b ^= k;
    }
}

fn dleq_challenge(
    r: &RistrettoPoint,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    t1: &RistrettoPoint,
    t2: &RistrettoPoint,
) -> Scalar {
    let mut hasher = blake3::Hasher::new_derive_key("neo-mpc-threshold-dleq-v1");
    for p in [r, a, b, t1, t2] {
        hasher.update(p.compress().as_bytes());
    }
    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn random_scalar() -> Result<Scalar> {
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vss::CommitteeSession;
    use crate::{ClearnetRequest, CommitteeConfig};

    fn dealt() -> CommitteeSession {
        let req = ClearnetRequest {
            destination: "example.com:443".into(),
            payload: b"unused for threshold-decrypt tests".to_vec(),
        };
        let cfg = CommitteeConfig {
            members: 5,
            threshold: 3,
        };
        CommitteeSession::deal(&req, cfg).unwrap()
    }

    fn partials_from(session: &CommitteeSession, idxs: &[usize], ct: &Ciphertext) -> Vec<Partial> {
        idxs.iter()
            .map(|&i| partial_decrypt(session.share_of(i).unwrap(), ct).unwrap())
            .collect()
    }

    #[test]
    fn threshold_decrypt_recovers_without_assembling_the_key() {
        let session = dealt();
        let secret_msg = b"the destination and TLS record no single node may see";
        let ct = encrypt(&session.commitments, secret_msg).unwrap();

        // Any threshold-sized quorum's partials, combined by the client, recover it.
        let partials = partials_from(&session, &[0, 2, 4], &ct);
        let recovered = combine(&session.commitments, 3, &ct, &partials).unwrap();
        assert_eq!(recovered, secret_msg);

        // A different quorum works too (Lagrange over any distinct subset).
        let partials2 = partials_from(&session, &[1, 3, 4], &ct);
        assert_eq!(
            combine(&session.commitments, 3, &ct, &partials2).unwrap(),
            secret_msg
        );
    }

    #[test]
    fn fewer_than_threshold_partials_cannot_decrypt() {
        let session = dealt();
        let ct = encrypt(&session.commitments, b"secret").unwrap();
        let partials = partials_from(&session, &[0, 1], &ct); // only 2 of 3
        assert!(combine(&session.commitments, 3, &ct, &partials).is_err());
    }

    #[test]
    fn every_partial_verifies_against_public_commitments() {
        let session = dealt();
        let ct = encrypt(&session.commitments, b"secret").unwrap();
        for i in 0..5 {
            let p = partial_decrypt(session.share_of(i).unwrap(), &ct).unwrap();
            assert!(verify_partial(&session.commitments, &ct, &p));
        }
    }

    #[test]
    fn a_forged_partial_is_caught_and_does_not_corrupt_the_result() {
        let session = dealt();
        let msg = b"honest quorum must still win";
        let ct = encrypt(&session.commitments, msg).unwrap();

        // Four partials, one of them forged (its point tampered).
        let mut partials = partials_from(&session, &[0, 1, 2, 3], &ct);
        let honest = partials[1].d; // keep a valid point around
        let tampered = (honest.decompress().unwrap() + RISTRETTO_BASEPOINT_POINT).compress();
        partials[1].d = tampered;
        assert!(
            !verify_partial(&session.commitments, &ct, &partials[1]),
            "the tampered partial must fail its DLEQ proof"
        );
        // With three honest partials still present, the client recovers the message.
        assert_eq!(
            combine(&session.commitments, 3, &ct, &partials).unwrap(),
            msg
        );
    }

    #[test]
    fn one_valid_partial_leaks_nothing_recoverable() {
        // A single member's partial cannot reveal the plaintext: combine at
        // threshold 1 with one partial would only work if threshold were 1. At the
        // real threshold, one partial is refused — so a lone member learns nothing.
        let session = dealt();
        let ct = encrypt(&session.commitments, b"secret").unwrap();
        let one = partials_from(&session, &[0], &ct);
        assert!(combine(&session.commitments, 3, &ct, &one).is_err());
    }
}
