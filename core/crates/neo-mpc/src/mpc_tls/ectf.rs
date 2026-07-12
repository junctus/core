//! **ECtF** — the elliptic-curve point→field-element share conversion, DECO's
//! step-1 (the half [`convert`](super::convert)'s A2B does *not* cover). This is the
//! piece that turns [`session::shared_ecdhe`](super::session::shared_ecdhe)'s
//! additive **point** shares into an additive share of the shared secret's
//! **x-coordinate** — under 2PC, so neither party ever holds the ECDHE point.
//!
//! # The protocol
//!
//! Party A holds point `P1 = (x1, y1)`, party B holds `P2 = (x2, y2)` on a short
//! Weierstrass curve over `F_p`; the real shared secret is the x-coordinate of
//! `P = P1 + P2`. For distinct points the chord formula gives
//!
//! ```text
//!     λ  = (y2 − y1) / (x2 − x1)          x3 = λ² − x1 − x2
//! ```
//! (independent of the curve's `a`, `b` — those only enter *doubling*). The parties
//! never learn `λ`, `x3`, or each other's point; they end with additive shares
//! `s1 + s2 ≡ x3 (mod p)`.
//!
//! Everything is built from one gadget: **multiply two additively-shared field
//! elements into additive shares of the product** ([`mul_shared`]), whose only
//! interactive part is [`mta_fp`] — **Gilboa MtA over `F_p`**, run on the crate's
//! maliciously-secure OT ([`kos`](super::kos)). With it:
//!
//! 1. `Δx = x2 − x1`, `Δy = y2 − y1` are additive shares for free (A holds `−x1,−y1`,
//!    B holds `x2, y2`).
//! 2. `A = Δx²`, `B = Δy²` — two [`mul_shared`] squarings.
//! 3. **Masked inversion** (Bar-Ilan–Beaver): draw a joint random `r`, compute and
//!    **reveal** `d = A·r` (reveals nothing about `A`: `r` is uniform), so
//!    `Δx⁻² = A⁻¹ = r·d⁻¹`. Then `λ² = B·A⁻¹ = (B·r)·d⁻¹` — a second [`mul_shared`]
//!    for `B·r`, scaled by the *public* `d⁻¹`.
//! 4. Each party subtracts its own `x`: `s1 = λ²-share_A − x1`, `s2 = λ²-share_B − x2`.
//!
//! Four [`mul_shared`] calls (`A`, `B`, `A·r`, `B·r`), one public reveal.
//!
//! # Honest boundary
//!
//! - **Correctness is what's proven here**: the test validates the reconstructed
//!   x-coordinate share against **P-256 point addition computed by the vetted `p256`
//!   crate** — an independent oracle, not our own reference. It runs on the real
//!   P-256 prime.
//! - **OT is now KOS** ([`kos`](super::kos)), maliciously-secure — so a cheating
//!   receiver in the MtA OTs aborts. This is *necessary but not sufficient* for a
//!   malicious ECtF: Gilboa MtA also needs its own **consistency check** (a malicious
//!   sender could use an inconsistent `a` across the bit-OTs, à la DKLs), which is not
//!   yet built. The composition is malicious at the OT layer, semi-honest at the MtA
//!   layer.
//! - The `F_p` arithmetic uses `num-bigint` (variable-time). A production build wants
//!   a **constant-time** field; this module demonstrates and validates the *protocol*,
//!   which is field-implementation-agnostic.

use neo_core::{Error, Result};
use num_bigint::BigUint;

use super::kos;

/// ECtF: given party A's point `(x1, y1)` and party B's point `(x2, y2)` — each
/// coordinate a 32-byte **big-endian** field element in `[0, p)` — return additive
/// shares `(s1, s2)` of the x-coordinate of `P1 + P2`, i.e. `s1 + s2 ≡ x3 (mod p)`.
///
/// Requires `x1 ≠ x2` (distinct points, `P1 ≠ ±P2`) — the chord case, as in a real
/// ECDHE where the two shares are independent random points.
pub fn ectf(
    p1: (&[u8; 32], &[u8; 32]),
    p2: (&[u8; 32], &[u8; 32]),
    prime: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    let p = BigUint::from_bytes_be(prime);
    let (x1, y1) = (BigUint::from_bytes_be(p1.0), BigUint::from_bytes_be(p1.1));
    let (x2, y2) = (BigUint::from_bytes_be(p2.0), BigUint::from_bytes_be(p2.1));

    // Δx = x2 − x1, Δy = y2 − y1 as additive shares (A: −x1,−y1 ; B: x2,y2).
    let dxa = neg(&x1, &p);
    let dxb = x2.clone();
    let dya = neg(&y1, &p);
    let dyb = y2.clone();

    // A = Δx², B = Δy².
    let (a_sh_a, a_sh_b) = mul_shared(&dxa, &dxa, &dxb, &dxb, &p)?;
    let (b_sh_a, b_sh_b) = mul_shared(&dya, &dya, &dyb, &dyb, &p)?;

    // Masked inversion of A: joint random r, reveal d = A·r, so A⁻¹ = r·d⁻¹.
    let ra = rand_fp(&p)?;
    let rb = rand_fp(&p)?;
    let (ar_a, ar_b) = mul_shared(&a_sh_a, &ra, &a_sh_b, &rb, &p)?;
    let d = (&ar_a + &ar_b) % &p; // public
    if d == BigUint::ZERO {
        return Err(Error::Crypto(
            "ECtF: degenerate masked inversion (d = 0)".into(),
        ));
    }
    let dinv = modinv(&d, &p)?;

    // λ² = B·A⁻¹ = (B·r)·d⁻¹ ; scale each B·r share by the public d⁻¹.
    let (br_a, br_b) = mul_shared(&b_sh_a, &ra, &b_sh_b, &rb, &p)?;
    let lam2_a = (&br_a * &dinv) % &p;
    let lam2_b = (&br_b * &dinv) % &p;

    // x3 = λ² − x1 − x2 ; each party subtracts its own x.
    let s1 = sub(&lam2_a, &x1, &p);
    let s2 = sub(&lam2_b, &x2, &p);
    Ok((to_be32(&s1), to_be32(&s2)))
}

/// Multiply two additively-shared field elements into additive shares of the
/// product: given `u = ua + ub` and `w = wa + wb`, returns `(pa, pb)` with
/// `pa + pb ≡ u·w (mod p)`. The two cross terms `ua·wb` and `wa·ub` go through
/// [`mta_fp`]; the same-party terms are local.
fn mul_shared(
    ua: &BigUint,
    wa: &BigUint,
    ub: &BigUint,
    wb: &BigUint,
    p: &BigUint,
) -> Result<(BigUint, BigUint)> {
    let (c1, d1) = mta_fp(ua, wb, p)?; // ua·wb
    let (c2, d2) = mta_fp(wa, ub, p)?; // wa·ub
    let pa = (&((ua * wa) % p) + &c1 + &c2) % p;
    let pb = (&((ub * wb) % p) + &d1 + &d2) % p;
    Ok((pa, pb))
}

/// **Gilboa multiplicative-to-additive over `F_p`**: party A holds `a`, party B holds
/// `b`; returns additive shares `(u, v)` with `u + v ≡ a·b (mod p)`. Generalises
/// [`mta`](super::mta::mta) (which is fixed to the Ristretto scalar field) to an
/// arbitrary 256-bit prime. Each of `b`'s 256 bits drives one OT of the pair
/// `(tᵢ, tᵢ + a·2ⁱ)`; field elements are 32 bytes, split into a low/high 16-byte half
/// (two OT columns over the same choice bits) for [`kos`](super::kos).
fn mta_fp(a: &BigUint, b: &BigUint, p: &BigUint) -> Result<(BigUint, BigUint)> {
    let b_be = to_be32(b);
    let bit = |i: usize| (b_be[31 - i / 8] >> (i % 8)) & 1 == 1; // 2^i, big-endian bytes

    let two = BigUint::from(2u32);
    let mut pow2a = a % p; // a·2⁰
    let mut t_sum = BigUint::ZERO;
    let mut lo: Vec<([u8; 16], [u8; 16])> = Vec::with_capacity(256);
    let mut hi: Vec<([u8; 16], [u8; 16])> = Vec::with_capacity(256);
    for _ in 0..256 {
        let t = rand_fp(p)?;
        t_sum = (&t_sum + &t) % p;
        let m1 = (&t + &pow2a) % p; // tᵢ + a·2ⁱ
        let (tb, mb) = (to_be32(&t), to_be32(&m1));
        lo.push((half(&tb, 0), half(&mb, 0)));
        hi.push((half(&tb, 16), half(&mb, 16)));
        pow2a = (&pow2a * &two) % p;
    }

    let bits: Vec<bool> = (0..256).map(bit).collect();
    let lo_recv = kos::extend(&bits, &lo)?;
    let hi_recv = kos::extend(&bits, &hi)?;

    let mut v = BigUint::ZERO;
    for i in 0..256 {
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(&lo_recv[i]);
        m[16..].copy_from_slice(&hi_recv[i]);
        v = (&v + &BigUint::from_bytes_be(&m)) % p;
    }
    let u = (p - &t_sum) % p; // −Σtᵢ mod p
    Ok((u, v))
}

// ── field helpers (num-bigint, variable-time — see the honest boundary) ──

fn neg(a: &BigUint, p: &BigUint) -> BigUint {
    if a == &BigUint::ZERO {
        BigUint::ZERO
    } else {
        p - (a % p)
    }
}

fn sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a + &neg(&(b % p), p)) % p
}

/// Modular inverse via Fermat (`p` prime): `a⁻¹ = a^(p−2) mod p`.
fn modinv(a: &BigUint, p: &BigUint) -> Result<BigUint> {
    if a == &BigUint::ZERO {
        return Err(Error::Crypto("ECtF: inverse of zero".into()));
    }
    Ok(a.modpow(&(p - 2u32), p))
}

fn rand_fp(p: &BigUint) -> Result<BigUint> {
    let mut buf = [0u8; 48]; // 384 bits ≫ 256: reduction bias is negligible
    getrandom::getrandom(&mut buf).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(BigUint::from_bytes_be(&buf) % p)
}

fn to_be32(x: &BigUint) -> [u8; 32] {
    let v = x.to_bytes_be();
    let mut o = [0u8; 32];
    o[32 - v.len()..].copy_from_slice(&v); // x < p < 2^256 ⇒ v.len() ≤ 32
    o
}

fn half(bytes: &[u8; 32], off: usize) -> [u8; 16] {
    let mut o = [0u8; 16];
    o.copy_from_slice(&bytes[off..off + 16]);
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::ProjectivePoint;

    /// P-256 base field prime, big-endian.
    const P256_PRIME_BE: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    fn coords(pt: &p256::AffinePoint) -> ([u8; 32], [u8; 32]) {
        let enc = pt.to_encoded_point(false);
        let x = <[u8; 32]>::try_from(enc.x().unwrap().as_slice()).unwrap();
        let y = <[u8; 32]>::try_from(enc.y().unwrap().as_slice()).unwrap();
        (x, y)
    }

    #[test]
    fn ectf_x_share_matches_p256_point_addition() {
        // Ground truth from the vetted `p256` crate: small multiples of the
        // generator as the two point shares, their sum's x-coordinate the target.
        let g = ProjectivePoint::GENERATOR;
        let mut mult = vec![g];
        for _ in 0..8 {
            let last = *mult.last().unwrap();
            mult.push(last + g);
        }
        let p = BigUint::from_bytes_be(&P256_PRIME_BE);

        for (i, j) in [(0usize, 1usize), (2, 5), (1, 7)] {
            let p1 = mult[i].to_affine();
            let p2 = mult[j].to_affine();
            let sum = (mult[i] + mult[j]).to_affine();
            let (x1, y1) = coords(&p1);
            let (x2, y2) = coords(&p2);
            let (sx, _) = coords(&sum);

            let (s1, s2) = ectf((&x1, &y1), (&x2, &y2), &P256_PRIME_BE).unwrap();
            let recon = (&(BigUint::from_bytes_be(&s1) + BigUint::from_bytes_be(&s2)) % &p).clone();
            assert_eq!(
                to_be32(&recon),
                sx,
                "ECtF x-coordinate share must reconstruct P-256's ({i}G)+({j}G)"
            );
        }
    }

    #[test]
    fn mta_fp_yields_additive_shares_of_the_product() {
        let p = BigUint::from_bytes_be(&P256_PRIME_BE);
        for _ in 0..3 {
            let a = rand_fp(&p).unwrap();
            let b = rand_fp(&p).unwrap();
            let (u, v) = mta_fp(&a, &b, &p).unwrap();
            assert_eq!((&u + &v) % &p, (&a * &b) % &p, "u + v ≡ a·b (mod p)");
        }
    }
}
