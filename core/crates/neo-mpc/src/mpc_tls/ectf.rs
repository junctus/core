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
//!   receiver in the MtA OTs aborts. For the *sender*-consistency half, [`spdz`](super::spdz)
//!   adds the MASCOT/SPDZ machinery — authenticated arithmetic shares with a global MAC,
//!   MAC-checked opens, Beaver multiplication, and the **triple sacrifice** check (a
//!   maliciously wrong product is caught). What remains is **wiring** this ECtF's
//!   [`mul_shared`] onto the authenticated Beaver online (rather than direct MtA); the
//!   pieces are built and tested.
//! - The `F_p` arithmetic runs over **`crypto-bigint`'s constant-time** Montgomery
//!   residues (`DynResidue`), not variable-time bignum — so field ops don't leak the
//!   secret shares through timing. The protocol is field-implementation-agnostic; the
//!   tests validate it against **two independent references** (the `p256` crate for the
//!   point addition, `num-bigint` for the field reconstruction).

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Encoding, U256};
use neo_core::{Error, Result};

use super::kos;

/// A field element of `F_p`, a **constant-time** Montgomery residue.
type F = DynResidue<{ U256::LIMBS }>;

/// The prime field `F_p` (`p` odd, 256-bit), holding crypto-bigint's constant-time
/// modular parameters plus the raw modulus (for uniform sampling).
#[derive(Clone, Copy)]
struct Field {
    params: DynResidueParams<{ U256::LIMBS }>,
    modulus: U256,
}

impl Field {
    fn new(prime_be: &[u8; 32]) -> Self {
        let modulus = U256::from_be_bytes(*prime_be);
        Field {
            params: DynResidueParams::new(&modulus),
            modulus,
        }
    }

    fn load_be(&self, b: &[u8; 32]) -> F {
        DynResidue::new(&U256::from_be_bytes(*b), self.params)
    }

    fn zero(&self) -> F {
        DynResidue::zero(self.params)
    }

    /// A uniform field element via rejection sampling — unbiased, and since `p` is
    /// within a whisker of `2²⁵⁶` it almost always accepts the first draw.
    fn rand(&self) -> Result<F> {
        loop {
            let mut b = [0u8; 32];
            getrandom::getrandom(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
            let u = U256::from_be_bytes(b);
            if u < self.modulus {
                return Ok(DynResidue::new(&u, self.params));
            }
        }
    }
}

fn to_be(x: &F) -> [u8; 32] {
    x.retrieve().to_be_bytes()
}

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
    let f = Field::new(prime);
    let x1 = f.load_be(p1.0);
    let y1 = f.load_be(p1.1);
    let x2 = f.load_be(p2.0);
    let y2 = f.load_be(p2.1);

    // Δx = x2 − x1, Δy = y2 − y1 as additive shares (A: −x1,−y1 ; B: x2,y2).
    let dxa = x1.neg();
    let dxb = x2;
    let dya = y1.neg();
    let dyb = y2;

    // A = Δx², B = Δy².
    let (a_sh_a, a_sh_b) = mul_shared(&dxa, &dxa, &dxb, &dxb, &f)?;
    let (b_sh_a, b_sh_b) = mul_shared(&dya, &dya, &dyb, &dyb, &f)?;

    // Masked inversion of A: joint random r, reveal d = A·r, so A⁻¹ = r·d⁻¹.
    let ra = f.rand()?;
    let rb = f.rand()?;
    let (ar_a, ar_b) = mul_shared(&a_sh_a, &ra, &a_sh_b, &rb, &f)?;
    let d = ar_a + ar_b; // public
    if d.retrieve() == U256::ZERO {
        return Err(Error::Crypto(
            "ECtF: degenerate masked inversion (d = 0)".into(),
        ));
    }
    let dinv = d.invert().0; // d ≠ 0 (guarded) ⇒ the inverse exists

    // λ² = B·A⁻¹ = (B·r)·d⁻¹ ; scale each B·r share by the public d⁻¹.
    let (br_a, br_b) = mul_shared(&b_sh_a, &ra, &b_sh_b, &rb, &f)?;
    let lam2_a = br_a * dinv;
    let lam2_b = br_b * dinv;

    // x3 = λ² − x1 − x2 ; each party subtracts its own x.
    let s1 = lam2_a - x1;
    let s2 = lam2_b - x2;
    Ok((to_be(&s1), to_be(&s2)))
}

/// Multiply two additively-shared field elements into additive shares of the
/// product: given `u = ua + ub` and `w = wa + wb`, returns `(pa, pb)` with
/// `pa + pb ≡ u·w (mod p)`. The two cross terms `ua·wb` and `wa·ub` go through
/// [`mta_fp`]; the same-party terms are local.
fn mul_shared(ua: &F, wa: &F, ub: &F, wb: &F, f: &Field) -> Result<(F, F)> {
    let (c1, d1) = mta_fp(ua, wb, f)?; // ua·wb
    let (c2, d2) = mta_fp(wa, ub, f)?; // wa·ub
    let pa = (*ua * *wa) + c1 + c2;
    let pb = (*ub * *wb) + d1 + d2;
    Ok((pa, pb))
}

/// **Gilboa multiplicative-to-additive over `F_p`**: party A holds `a`, party B holds
/// `b`; returns additive shares `(u, v)` with `u + v ≡ a·b (mod p)`. Generalises
/// [`mta`](super::mta::mta) (which is fixed to the Ristretto scalar field) to an
/// arbitrary 256-bit prime. Each of `b`'s 256 bits drives one OT of the pair
/// `(tᵢ, tᵢ + a·2ⁱ)`; field elements are 32 bytes, split into a low/high 16-byte half
/// (two OT columns over the same choice bits) for [`kos`](super::kos).
fn mta_fp(a: &F, b: &F, f: &Field) -> Result<(F, F)> {
    let b_be = to_be(b);
    let bit = |i: usize| (b_be[31 - i / 8] >> (i % 8)) & 1 == 1; // 2^i, big-endian bytes

    let mut pow2a = *a; // a·2⁰
    let mut t_sum = f.zero();
    let mut lo: Vec<([u8; 16], [u8; 16])> = Vec::with_capacity(256);
    let mut hi: Vec<([u8; 16], [u8; 16])> = Vec::with_capacity(256);
    for _ in 0..256 {
        let t = f.rand()?;
        t_sum += t;
        let m1 = t + pow2a; // tᵢ + a·2ⁱ
        let (tb, mb) = (to_be(&t), to_be(&m1));
        lo.push((half(&tb, 0), half(&mb, 0)));
        hi.push((half(&tb, 16), half(&mb, 16)));
        pow2a += pow2a; // a·2^(i+1)
    }

    let bits: Vec<bool> = (0..256).map(bit).collect();
    let lo_recv = kos::extend(&bits, &lo)?;
    let hi_recv = kos::extend(&bits, &hi)?;

    let mut v = f.zero();
    for i in 0..256 {
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(&lo_recv[i]);
        m[16..].copy_from_slice(&hi_recv[i]);
        v += f.load_be(&m);
    }
    Ok((t_sum.neg(), v)) // (−Σtᵢ, Σmᵢ)
}

fn half(bytes: &[u8; 32], off: usize) -> [u8; 16] {
    let mut o = [0u8; 16];
    o.copy_from_slice(&bytes[off..off + 16]);
    o
}

// ── Networked ECtF: the two parties run the same protocol over a `Channel`, each
//    holding only its own point-share. `mta_fp`'s OT maps directly onto the networked
//    KOS COT ([`kos::cot_sender`]/[`kos::cot_receiver`]); the masked inversion's reveal is
//    one field-element exchange. This is the ECDHE step of the networked live handshake.

use super::live::channel::Channel;

/// Gilboa MtA — **sender** side (holds `a`): offers `(tᵢ, tᵢ + a·2ⁱ)` for each bit over the
/// networked OT and returns its share `−Σtᵢ`.
fn mta_fp_sender(ch: &mut dyn Channel, a: &F, f: &Field) -> Result<F> {
    let mut pow2a = *a;
    let mut t_sum = f.zero();
    let mut lo = Vec::with_capacity(256);
    let mut hi = Vec::with_capacity(256);
    for _ in 0..256 {
        let t = f.rand()?;
        t_sum += t;
        let m1 = t + pow2a;
        let (tb, mb) = (to_be(&t), to_be(&m1));
        lo.push((half(&tb, 0), half(&mb, 0)));
        hi.push((half(&tb, 16), half(&mb, 16)));
        pow2a += pow2a;
    }
    kos::cot_sender(ch, &lo)?;
    kos::cot_sender(ch, &hi)?;
    Ok(t_sum.neg())
}

/// Gilboa MtA — **receiver** side (holds `b`): chooses by the bits of `b` and returns its
/// share `Σ(chosen) = Σtᵢ + a·b`.
fn mta_fp_receiver(ch: &mut dyn Channel, b: &F, f: &Field) -> Result<F> {
    let b_be = to_be(b);
    let bits: Vec<bool> = (0..256)
        .map(|i| (b_be[31 - i / 8] >> (i % 8)) & 1 == 1)
        .collect();
    let lo_recv = kos::cot_receiver(ch, &bits)?;
    let hi_recv = kos::cot_receiver(ch, &bits)?;
    let mut v = f.zero();
    for i in 0..256 {
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(&lo_recv[i]);
        m[16..].copy_from_slice(&hi_recv[i]);
        v += f.load_be(&m);
    }
    Ok(v)
}

/// Networked [`mul_shared`] — party A's role (sender for both cross terms).
fn mul_shared_a(ch: &mut dyn Channel, ua: &F, wa: &F, f: &Field) -> Result<F> {
    let c1 = mta_fp_sender(ch, ua, f)?; // ↔ B.receiver(wb)
    let c2 = mta_fp_sender(ch, wa, f)?; // ↔ B.receiver(ub)
    Ok((*ua * *wa) + c1 + c2)
}

/// Networked [`mul_shared`] — party B's role (receiver for both cross terms).
fn mul_shared_b(ch: &mut dyn Channel, ub: &F, wb: &F, f: &Field) -> Result<F> {
    let d1 = mta_fp_receiver(ch, wb, f)?; // ↔ A.sender(ua)
    let d2 = mta_fp_receiver(ch, ub, f)?; // ↔ A.sender(wa)
    Ok((*ub * *wb) + d1 + d2)
}

/// Open a shared field element (symmetric): send our share, receive the peer's, sum.
fn open_field(ch: &mut dyn Channel, share: &F, f: &Field) -> Result<F> {
    ch.send(&to_be(share))?;
    let peer = ch.recv_exact(32)?;
    Ok(*share + f.load_be(&peer.try_into().expect("32 bytes")))
}

/// **Networked ECtF — party A** (holds point-share `P1 = (x1, y1)`). Runs the same
/// protocol as [`ectf`] over `ch`, returning A's additive share of `x(P1+P2)`.
pub fn ectf_a(
    ch: &mut dyn Channel,
    p1: (&[u8; 32], &[u8; 32]),
    prime: &[u8; 32],
) -> Result<[u8; 32]> {
    let f = Field::new(prime);
    let x1 = f.load_be(p1.0);
    let y1 = f.load_be(p1.1);
    let (dxa, dya) = (x1.neg(), y1.neg());

    let a_sh_a = mul_shared_a(ch, &dxa, &dxa, &f)?; // Δx² share
    let b_sh_a = mul_shared_a(ch, &dya, &dya, &f)?; // Δy² share
    let ra = f.rand()?;
    let ar_a = mul_shared_a(ch, &a_sh_a, &ra, &f)?;
    let d = open_field(ch, &ar_a, &f)?;
    if d.retrieve() == U256::ZERO {
        return Err(Error::Crypto(
            "ECtF-net: degenerate masked inversion (d = 0)".into(),
        ));
    }
    let dinv = d.invert().0;
    let br_a = mul_shared_a(ch, &b_sh_a, &ra, &f)?;
    let s1 = (br_a * dinv) - x1; // λ² share − x1
    Ok(to_be(&s1))
}

/// **Networked ECtF — party B** (holds point-share `P2 = (x2, y2)`).
pub fn ectf_b(
    ch: &mut dyn Channel,
    p2: (&[u8; 32], &[u8; 32]),
    prime: &[u8; 32],
) -> Result<[u8; 32]> {
    let f = Field::new(prime);
    let x2 = f.load_be(p2.0);
    let y2 = f.load_be(p2.1);
    let (dxb, dyb) = (x2, y2);

    let a_sh_b = mul_shared_b(ch, &dxb, &dxb, &f)?;
    let b_sh_b = mul_shared_b(ch, &dyb, &dyb, &f)?;
    let rb = f.rand()?;
    let ar_b = mul_shared_b(ch, &a_sh_b, &rb, &f)?;
    let d = open_field(ch, &ar_b, &f)?;
    if d.retrieve() == U256::ZERO {
        return Err(Error::Crypto(
            "ECtF-net: degenerate masked inversion (d = 0)".into(),
        ));
    }
    let dinv = d.invert().0;
    let br_b = mul_shared_b(ch, &b_sh_b, &rb, &f)?;
    let s2 = (br_b * dinv) - x2;
    Ok(to_be(&s2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::ProjectivePoint;

    /// Independent (num-bigint) big-endian serialization — a second bignum library, so
    /// the crypto-bigint field is cross-checked, not compared against itself.
    fn bu_to_be32(x: &BigUint) -> [u8; 32] {
        let v = x.to_bytes_be();
        let mut o = [0u8; 32];
        o[32 - v.len()..].copy_from_slice(&v);
        o
    }

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
            let recon = (BigUint::from_bytes_be(&s1) + BigUint::from_bytes_be(&s2)) % &p;
            assert_eq!(
                bu_to_be32(&recon),
                sx,
                "ECtF x-coordinate share must reconstruct P-256's ({i}G)+({j}G)"
            );
        }
    }

    #[test]
    fn networked_ectf_matches_p256_over_tcp() {
        // The two parties run ECtF over a real TCP socket (each holds only its own point
        // share); the reconstructed x-coordinate must equal P-256's — the networked ECDHE
        // conversion for the live 2PC-TLS handshake.
        use super::super::live::channel::TcpChannel;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let g = ProjectivePoint::GENERATOR;
        let p1 = (g + g).to_affine(); // 2G
        let p2 = (g + g + g + g + g).to_affine(); // 5G
        let sum = (g + g + g + g + g + g + g).to_affine(); // 7G
        let (x1, y1) = coords(&p1);
        let (x2, y2) = coords(&p2);
        let (sx, _) = coords(&sum);
        let p = BigUint::from_bytes_be(&P256_PRIME_BE);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (bx, by) = (x2, y2);
        let b = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            ectf_b(&mut ch, (&bx, &by), &P256_PRIME_BE).unwrap()
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let s1 = ectf_a(&mut ch, (&x1, &y1), &P256_PRIME_BE).unwrap();
        let s2 = b.join().unwrap();

        let recon = (BigUint::from_bytes_be(&s1) + BigUint::from_bytes_be(&s2)) % &p;
        assert_eq!(
            bu_to_be32(&recon),
            sx,
            "networked ECtF reconstructs P-256 x(2G+5G)"
        );
    }

    #[test]
    fn mta_fp_yields_additive_shares_of_the_product() {
        let f = Field::new(&P256_PRIME_BE);
        let p = BigUint::from_bytes_be(&P256_PRIME_BE);
        for _ in 0..3 {
            let a = f.rand().unwrap();
            let b = f.rand().unwrap();
            let (u, v) = mta_fp(&a, &b, &f).unwrap();
            // Reconstruct u+v (crypto-bigint) and compare to a·b computed with the
            // independent num-bigint reference.
            let got = to_be(&(u + v));
            let ba = BigUint::from_bytes_be(&to_be(&a));
            let bb = BigUint::from_bytes_be(&to_be(&b));
            assert_eq!(got, bu_to_be32(&((ba * bb) % &p)), "u + v ≡ a·b (mod p)");
        }
    }
}
