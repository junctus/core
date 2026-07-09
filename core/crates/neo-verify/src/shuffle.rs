//! Zero-knowledge verifiable shuffle (M19).
//!
//! A mix proves its output tags are a **permutation** of its input tags —
//! nothing dropped, injected, or altered — **without revealing the
//! permutation**. This upgrades [`proof_of_mixing`](crate::proof_of_mixing)'s
//! non-ZK conservation check to a real zero-knowledge argument.
//!
//! ## Construction
//!
//! A grand-product argument for **multiset equality**, over the Ristretto group
//! with Pedersen commitments and Fiat–Shamir:
//!
//! 1. The prover commits to each input `a_i` and output `b_i`:
//!    `A_i = a_i·G + r_i·H`, `B_i = b_i·G + s_i·H` (hiding).
//! 2. A challenge `x = H(all commitments)` is drawn *after* they are fixed.
//! 3. `{a_i}` and `{b_i}` are equal multisets iff `∏(a_i+x) = ∏(b_i+x)`
//!    (Schwartz–Zippel: a differing multiset fails for all but ≤ n out of ~2²⁵²
//!    challenges). Using the homomorphism `A_i + x·G = Com(a_i+x; r_i)`, the
//!    prover proves this product equality in zero knowledge via **running-product
//!    commitments** linked by ZK **multiplication proofs**, then proves the two
//!    final products are equal.
//!
//! Each sub-proof is an HVZK sigma protocol made non-interactive with
//! Fiat–Shamir, so the verifier learns nothing about the tags or the
//! permutation. Soundness rests on the discrete-log (Pedersen-binding)
//! assumption in the random-oracle model; proof size is `O(n)`.
//!
//! **Honest scope:** this is a from-scratch argument, unit-tested for
//! completeness and soundness but **not** independently audited, and not a
//! succinct (constant-size) proof. The tags are scalars; binding them to actual
//! mix packets is the integration step.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::Scalar;
use neo_core::{Error, Result};

const H_DOMAIN: &[u8] = b"neo-shuffle-pedersen-H-v1";
const CHALLENGE_DOMAIN: &[u8] = b"neo-shuffle-challenge-v1";

/// The second Pedersen generator `H`, a nothing-up-my-sleeve point independent
/// of `G` (its discrete log w.r.t. `G` is unknown).
fn pedersen_h() -> RistrettoPoint {
    let mut wide = [0u8; 64];
    let mut xof = blake3::Hasher::new_derive_key("neo-shuffle-H-derive-v1");
    xof.update(H_DOMAIN);
    xof.finalize_xof().fill(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

fn commit(h: &RistrettoPoint, value: &Scalar, blind: &Scalar) -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT * value + h * blind
}

fn random_scalar() -> Result<Scalar> {
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

/// A Fiat–Shamir transcript over compressed points and scalars.
struct Transcript(blake3::Hasher);

impl Transcript {
    fn new() -> Self {
        let mut h = blake3::Hasher::new();
        h.update(CHALLENGE_DOMAIN);
        Transcript(h)
    }
    fn point(&mut self, p: &CompressedRistretto) {
        self.0.update(p.as_bytes());
    }
    fn points(&mut self, ps: &[CompressedRistretto]) {
        for p in ps {
            self.point(p);
        }
    }
    fn challenge(&self) -> Scalar {
        let mut wide = [0u8; 64];
        self.0.clone().finalize_xof().fill(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

/// A ZK proof that `value(R) = value(P)·value(Q)` for Pedersen commitments
/// `P`, `Q`, `R` (the prover knows the openings). It proves `P` and `R` share
/// the same scalar under bases `(G,H)` and `(Q,H)` respectively.
#[derive(Clone)]
struct MulProof {
    t1: CompressedRistretto,
    t2: CompressedRistretto,
    zp: Scalar,
    zrp: Scalar,
    zrq: Scalar,
}

impl MulProof {
    /// Prove `value(r_commit) = p_val · q_val`. Inputs are the commitments and
    /// the prover's secret openings.
    #[allow(clippy::too_many_arguments)]
    fn prove(
        h: &RistrettoPoint,
        p_commit: &RistrettoPoint,
        q_commit: &RistrettoPoint,
        r_commit: &RistrettoPoint,
        p_val: &Scalar,
        p_blind: &Scalar,
        q_blind: &Scalar,
        r_blind: &Scalar,
    ) -> Result<Self> {
        // R = p·Q + r'·H  where r' = r_blind - p·q_blind, and P = p·G + p_blind·H.
        let r_prime = r_blind - p_val * q_blind;
        let (kp, krp, krq) = (random_scalar()?, random_scalar()?, random_scalar()?);
        let t1 = RISTRETTO_BASEPOINT_POINT * kp + h * krp;
        let t2 = q_commit * kp + h * krq;

        let mut t = Transcript::new();
        for pt in [p_commit, q_commit, r_commit, &t1, &t2] {
            t.point(&pt.compress());
        }
        let e = t.challenge();

        Ok(Self {
            t1: t1.compress(),
            t2: t2.compress(),
            zp: kp + e * p_val,
            zrp: krp + e * p_blind,
            zrq: krq + e * r_prime,
        })
    }

    fn verify(
        &self,
        h: &RistrettoPoint,
        p_commit: &RistrettoPoint,
        q_commit: &RistrettoPoint,
        r_commit: &RistrettoPoint,
    ) -> bool {
        let (Some(t1), Some(t2)) = (self.t1.decompress(), self.t2.decompress()) else {
            return false;
        };
        let mut t = Transcript::new();
        for pt in [p_commit, q_commit, r_commit, &t1, &t2] {
            t.point(&pt.compress());
        }
        let e = t.challenge();

        let lhs1 = RISTRETTO_BASEPOINT_POINT * self.zp + h * self.zrp;
        let rhs1 = t1 + p_commit * e;
        let lhs2 = q_commit * self.zp + h * self.zrq;
        let rhs2 = t2 + r_commit * e;
        lhs1 == rhs1 && lhs2 == rhs2
    }
}

/// A ZK proof that a commitment `D` opens to zero (i.e. `D = d·H`).
#[derive(Clone)]
struct ZeroProof {
    t: CompressedRistretto,
    z: Scalar,
}

impl ZeroProof {
    fn prove(h: &RistrettoPoint, d_commit: &RistrettoPoint, d_blind: &Scalar) -> Result<Self> {
        let k = random_scalar()?;
        let t = h * k;
        let mut tr = Transcript::new();
        tr.point(&d_commit.compress());
        tr.point(&t.compress());
        let e = tr.challenge();
        Ok(Self {
            t: t.compress(),
            z: k + e * d_blind,
        })
    }

    fn verify(&self, h: &RistrettoPoint, d_commit: &RistrettoPoint) -> bool {
        let Some(t) = self.t.decompress() else {
            return false;
        };
        let mut tr = Transcript::new();
        tr.point(&d_commit.compress());
        tr.point(&t.compress());
        let e = tr.challenge();
        h * self.z == t + d_commit * e
    }
}

/// A zero-knowledge proof that the committed outputs are a permutation of the
/// committed inputs. Self-contained: it carries the input/output commitments
/// (the public statement) plus the argument.
#[derive(Clone)]
pub struct ShuffleProof {
    a_comms: Vec<CompressedRistretto>,
    b_comms: Vec<CompressedRistretto>,
    /// Running-product commitments for the input side (index 1..n; index 0 is
    /// derived as `A_0 + x·G`).
    lu: Vec<CompressedRistretto>,
    lv: Vec<CompressedRistretto>,
    mul_u: Vec<MulProof>,
    mul_v: Vec<MulProof>,
    final_zero: ZeroProof,
}

/// Prove that `outputs` is a permutation of `inputs` in zero knowledge.
/// Returns an error if the lengths differ or are empty. (The proof it produces
/// only *verifies* when `outputs` really is a permutation of `inputs`; an honest
/// prover fed a non-permutation produces a proof that fails verification.)
pub fn prove(inputs: &[Scalar], outputs: &[Scalar]) -> Result<ShuffleProof> {
    let n = inputs.len();
    if n == 0 || outputs.len() != n {
        return Err(Error::Config(
            "shuffle needs equal, non-empty input/output lengths".into(),
        ));
    }
    let h = pedersen_h();

    // 1. Commit to inputs and outputs.
    let mut r = Vec::with_capacity(n);
    let mut s = Vec::with_capacity(n);
    let mut a_pts = Vec::with_capacity(n);
    let mut b_pts = Vec::with_capacity(n);
    for i in 0..n {
        let ri = random_scalar()?;
        let si = random_scalar()?;
        a_pts.push(commit(&h, &inputs[i], &ri));
        b_pts.push(commit(&h, &outputs[i], &si));
        r.push(ri);
        s.push(si);
    }
    let a_comms: Vec<_> = a_pts.iter().map(|p| p.compress()).collect();
    let b_comms: Vec<_> = b_pts.iter().map(|p| p.compress()).collect();

    // 2. Challenge x, bound to all commitments.
    let mut tr = Transcript::new();
    tr.points(&a_comms);
    tr.points(&b_comms);
    let x = tr.challenge();

    // 3. Grand products of (a_i + x) and (b_i + x).
    let (lu, mul_u, prod_blind_u) = grand_product(&h, &a_pts, inputs, &r, &x)?;
    let (lv, mul_v, prod_blind_v) = grand_product(&h, &b_pts, outputs, &s, &x)?;

    // 4. Final products equal: LU_n - LV_n opens to zero.
    let lu_last = lu.last().unwrap().decompress().unwrap();
    let lv_last = lv.last().unwrap().decompress().unwrap();
    let d = lu_last - lv_last;
    let final_zero = ZeroProof::prove(&h, &d, &(prod_blind_u - prod_blind_v))?;

    Ok(ShuffleProof {
        a_comms,
        b_comms,
        lu,
        lv,
        mul_u,
        mul_v,
        final_zero,
    })
}

/// Build the running-product commitments and the linking multiplication proofs
/// for the sequence `u_i = value_i + x`. Returns `LU_0..LU_{n-1}` (compressed),
/// the `n-1` multiplication proofs, and the blinding of the final running
/// product (needed for the cross-side equality proof).
#[allow(clippy::type_complexity)]
fn grand_product(
    h: &RistrettoPoint,
    commits: &[RistrettoPoint],
    values: &[Scalar],
    blinds: &[Scalar],
    x: &Scalar,
) -> Result<(Vec<CompressedRistretto>, Vec<MulProof>, Scalar)> {
    let n = values.len();
    // U_i = commit_i + x·G  (value = value_i + x, randomness = blinds_i).
    let u_commits: Vec<RistrettoPoint> = commits
        .iter()
        .map(|c| c + RISTRETTO_BASEPOINT_POINT * x)
        .collect();
    let u_vals: Vec<Scalar> = values.iter().map(|v| v + x).collect();

    // Running products and their (fresh) blindings; LU_0 = U_0.
    let mut lu_pts = Vec::with_capacity(n);
    let mut prod_val = u_vals[0];
    let mut prod_blind = blinds[0];
    lu_pts.push(u_commits[0]);

    let mut mul = Vec::with_capacity(n.saturating_sub(1));
    for k in 1..n {
        let new_val = prod_val * u_vals[k];
        let new_blind = random_scalar()?;
        let new_commit = commit(h, &new_val, &new_blind);

        // Prove value(new_commit) = value(LU_{k-1}) · value(U_k).
        let proof = MulProof::prove(
            h,
            &lu_pts[k - 1],
            &u_commits[k],
            &new_commit,
            &prod_val,
            &prod_blind,
            &blinds[k],
            &new_blind,
        )?;
        mul.push(proof);

        lu_pts.push(new_commit);
        prod_val = new_val;
        prod_blind = new_blind;
    }

    Ok((
        lu_pts.iter().map(|p| p.compress()).collect(),
        mul,
        prod_blind,
    ))
}

/// Verify a shuffle proof: the committed outputs are a permutation of the
/// committed inputs, in zero knowledge.
pub fn verify(proof: &ShuffleProof) -> bool {
    let n = proof.a_comms.len();
    if n == 0
        || proof.b_comms.len() != n
        || proof.lu.len() != n
        || proof.lv.len() != n
        || proof.mul_u.len() != n - 1
        || proof.mul_v.len() != n - 1
    {
        return false;
    }
    let h = pedersen_h();

    // Recompute the challenge x from the commitments.
    let mut tr = Transcript::new();
    tr.points(&proof.a_comms);
    tr.points(&proof.b_comms);
    let x = tr.challenge();

    let Some((lu, mul_ok_u)) = check_grand_product(&h, &proof.a_comms, &proof.lu, &proof.mul_u, &x)
    else {
        return false;
    };
    let Some((lv, mul_ok_v)) = check_grand_product(&h, &proof.b_comms, &proof.lv, &proof.mul_v, &x)
    else {
        return false;
    };
    if !mul_ok_u || !mul_ok_v {
        return false;
    }

    // Final products equal: LU_n - LV_n opens to zero.
    let d = lu[n - 1] - lv[n - 1];
    proof.final_zero.verify(&h, &d)
}

/// Recompute `U_i = A_i + x·G`, check `LU_0 = U_0`, and verify each linking
/// multiplication proof. Returns the decompressed running products and whether
/// all mul proofs held.
fn check_grand_product(
    h: &RistrettoPoint,
    comms: &[CompressedRistretto],
    lu: &[CompressedRistretto],
    mul: &[MulProof],
    x: &Scalar,
) -> Option<(Vec<RistrettoPoint>, bool)> {
    let n = comms.len();
    let mut u = Vec::with_capacity(n);
    for c in comms {
        let p = c.decompress()?;
        if p.is_identity() {
            return None;
        }
        u.push(p + RISTRETTO_BASEPOINT_POINT * x);
    }
    let lu_pts: Vec<RistrettoPoint> = lu.iter().map(|c| c.decompress()).collect::<Option<_>>()?;

    // LU_0 must equal U_0 exactly.
    if lu_pts[0] != u[0] {
        return Some((lu_pts, false));
    }
    let mut ok = true;
    for k in 1..n {
        if !mul[k - 1].verify(h, &lu_pts[k - 1], &u[k], &lu_pts[k]) {
            ok = false;
        }
    }
    Some((lu_pts, ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(n: usize) -> Vec<Scalar> {
        (0..n).map(|i| Scalar::from((i as u64 + 1) * 7)).collect()
    }

    #[test]
    fn a_real_permutation_verifies() {
        let a = tags(6);
        // Reverse permutation.
        let b: Vec<Scalar> = a.iter().rev().copied().collect();
        let proof = prove(&a, &b).unwrap();
        assert!(verify(&proof), "a genuine shuffle must verify");
    }

    #[test]
    fn identity_permutation_verifies() {
        let a = tags(4);
        let proof = prove(&a, &a).unwrap();
        assert!(verify(&proof));
    }

    #[test]
    fn a_dropped_or_altered_tag_is_rejected() {
        let a = tags(5);
        // Replace one output tag with a value not in the input multiset.
        let mut b: Vec<Scalar> = a.clone();
        b[2] = Scalar::from(9999u64);
        let proof = prove(&a, &b).unwrap();
        assert!(!verify(&proof), "a non-permutation must be rejected");
    }

    #[test]
    fn a_duplicated_tag_is_rejected() {
        let a = tags(5);
        // Multiset differs: duplicate one tag, drop another.
        let mut b = a.clone();
        b[4] = b[0];
        let proof = prove(&a, &b).unwrap();
        assert!(!verify(&proof));
    }

    #[test]
    fn tampering_with_a_commitment_breaks_the_proof() {
        let a = tags(4);
        let b: Vec<Scalar> = a.iter().rev().copied().collect();
        let mut proof = prove(&a, &b).unwrap();
        // Swap a commitment for another point → challenge changes, proof fails.
        proof.b_comms[0] = (RISTRETTO_BASEPOINT_POINT * Scalar::from(42u64)).compress();
        assert!(!verify(&proof));
    }

    #[test]
    fn single_element_shuffle_works() {
        let a = tags(1);
        let proof = prove(&a, &a).unwrap();
        assert!(verify(&proof));
    }

    #[test]
    fn mismatched_lengths_error() {
        assert!(prove(&tags(3), &tags(2)).is_err());
        assert!(prove(&[], &[]).is_err());
    }
}
