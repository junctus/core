//! Multiplicative-to-additive (MtA) share conversion over the scalar field — the
//! **workhorse of DECO's ECtF** (EC point→field) conversion.
//!
//! Two parties hold private field elements `a` (party A) and `b` (party B); MtA
//! gives them **additive shares** `(u, v)` of the product, `u + v ≡ a·b (mod l)`,
//! with neither party learning the other's input. It is the building block DECO's
//! point→x-coordinate conversion composes (the `x3 = λ² − x1 − x2` formula becomes
//! local additions plus a handful of MtA products), so it is the concrete next
//! brick toward the EC point-share half of the conversion — the half A2B
//! ([`convert`](super::convert)) does not cover.
//!
//! Construction: **Gilboa's OT-based MtA**. Write `b = Σ bᵢ·2ⁱ`. For each bit the
//! sender offers, via 1-of-2 OT, `(tᵢ, tᵢ + a·2ⁱ)` for a fresh random `tᵢ`; the
//! receiver, choosing with `bᵢ`, gets `mᵢ = tᵢ + bᵢ·a·2ⁱ`. Then `u = −Σ tᵢ` and
//! `v = Σ mᵢ` satisfy `u + v = Σ bᵢ·a·2ⁱ = a·b`. Runs over the crate's
//! **maliciously-secure OT** ([`kos`]); scalars are 32 bytes so each OT message is
//! split into a low/high 16-byte half (two OT columns sharing the same choice bits).
//!
//! **OT is malicious ([`kos`]); the MtA *protocol* is still semi-honest**: an MtA
//! consistency check (that the receiver used consistent choice bits and the sender a
//! consistent `a` across the two columns, à la DKLs) is the remaining hardening. The
//! real-field version used by the conversion is [`ectf::mta_fp`](super::ectf); this is
//! the Ristretto-scalar sibling.

use curve25519_dalek::Scalar;
use neo_core::{Error, Result};

use super::kos;

/// Multiplicative-to-additive share conversion over `Z_l`: given `a` (party A) and
/// `b` (party B), returns additive shares `(u, v)` with `u + v ≡ a·b (mod l)`.
pub fn mta(a: &Scalar, b: &Scalar) -> Result<(Scalar, Scalar)> {
    let zero = Scalar::from(0u64);
    let b_bytes = b.to_bytes(); // 32-byte canonical little-endian
    let bits: Vec<bool> = (0..256)
        .map(|i| (b_bytes[i / 8] >> (i % 8)) & 1 == 1)
        .collect();

    // For each bit i: OT pair (tᵢ, tᵢ + a·2ⁱ), split low/high 16 bytes.
    let mut pow2a = *a; // a·2⁰, doubled each step
    let mut t_sum = zero;
    let mut lo_pairs: Vec<([u8; 16], [u8; 16])> = Vec::with_capacity(256);
    let mut hi_pairs: Vec<([u8; 16], [u8; 16])> = Vec::with_capacity(256);
    for _ in 0..256 {
        let mut t_raw = [0u8; 32];
        getrandom::getrandom(&mut t_raw).map_err(|e| Error::Rng(e.to_string()))?;
        let t = Scalar::from_bytes_mod_order(t_raw);
        t_sum += t;
        let m1 = t + pow2a; // tᵢ + a·2ⁱ
        let (t_b, m1_b) = (t.to_bytes(), m1.to_bytes());
        lo_pairs.push((half(&t_b, 0), half(&m1_b, 0)));
        hi_pairs.push((half(&t_b, 16), half(&m1_b, 16)));
        pow2a += pow2a; // a·2^(i+1)
    }

    // Two OT columns over the same choice bits recover both halves of `mᵢ`.
    let lo_recv = kos::extend(&bits, &lo_pairs)?;
    let hi_recv = kos::extend(&bits, &hi_pairs)?;

    let mut v = zero;
    for i in 0..256 {
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(&lo_recv[i]);
        m[16..].copy_from_slice(&hi_recv[i]);
        v += Scalar::from_bytes_mod_order(m); // canonical, so exact
    }
    Ok((-t_sum, v))
}

fn half(bytes: &[u8; 32], off: usize) -> [u8; 16] {
    let mut o = [0u8; 16];
    o.copy_from_slice(&bytes[off..off + 16]);
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_scalar() -> Scalar {
        let mut wide = [0u8; 64];
        getrandom::getrandom(&mut wide).unwrap();
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    #[test]
    fn mta_yields_additive_shares_of_the_product() {
        for _ in 0..5 {
            let a = rand_scalar();
            let b = rand_scalar();
            let (u, v) = mta(&a, &b).unwrap();
            assert_eq!(u + v, a * b, "u + v == a·b (mod l)");
        }
        // Edge cases: 0·b and 1·b.
        let b = rand_scalar();
        let (u, v) = mta(&Scalar::from(0u64), &b).unwrap();
        assert_eq!(u + v, Scalar::from(0u64), "0·b = 0");
        let (u, v) = mta(&Scalar::from(1u64), &b).unwrap();
        assert_eq!(u + v, b, "1·b = b");
    }
}
