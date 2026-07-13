//! Share conversion for the MPC-TLS key schedule — the arithmetic→boolean half of
//! DECO's EC point→bit conversion.
//!
//! DECO's additively-shared ECDHE leaves the two parties with an **additive share of
//! the ECDHE point**. The TLS key schedule ([`sha256`](super::sha256) under 2PC)
//! consumes a **bit-share of the pre-master secret** (the point's x-coordinate).
//! Bridging the two is a two-step conversion, and **both steps are now built**:
//!
//! 1. additive EC *point* shares → an additive *x-coordinate* share (mod the curve
//!    prime) — EC addition under MPC on the real curve: [`ectf`](super::ectf::ectf).
//! 2. that additive field-element share → a **bit-share** — an **arithmetic-to-
//!    boolean (A2B)** conversion: [`a2b_shared`], **this module**.
//!
//! [`a2b_shared`] is the step-2 primitive: given two additive shares of a value
//! `x = (share_a + share_b) mod prime` (each share in `[0, prime)`), it computes,
//! under 2PC, XOR-shares of the bits of `x` — without either party assembling `x`.
//! [`premaster_hash_from_point_shares`] chains both steps into the key-schedule
//! circuit: **EC point shares → `SHA-256(x-coordinate)` under 2PC**, x never assembled
//! (validated end-to-end against the `p256` crate and the NIST-KAT SHA-256 reference).
//!
//! Semi-honest at the MtA layer (OT is `kos`), like the rest of the 2PC session.

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::{Builder, Circuit};
use super::ectf::ectf;
use super::garble;
use super::poly1305::{mux, pad, sub_circuit};
use super::sha256::digest_shared;

/// Arithmetic-to-boolean share conversion mod `prime` (256-bit, little-endian). The
/// parties hold additive shares `share_a`, `share_b ∈ [0, prime)` of a secret
/// `x = (share_a + share_b) mod prime`; returns XOR-shares of the 256 bits of `x`
/// (`out_a ⊕ out_b = x`), computed under 2PC so `x` is never assembled.
pub fn a2b_shared(
    share_a: &[u8; 32],
    share_b: &[u8; 32],
    prime: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    let circuit = a2b_circuit(prime);
    // Layout: shareA[256] ‖ shareB[256] ‖ maskA[256] = 768.
    let mut inputs = vec![false; 768];
    write_bits(&mut inputs[0..256], share_a);
    write_bits(&mut inputs[256..512], share_b);
    let mut mask = [0u8; 32];
    getrandom::getrandom(&mut mask).map_err(|e| Error::Rng(e.to_string()))?;
    write_bits(&mut inputs[512..768], &mask);

    // The evaluator owns shareB; the garbler owns shareA and maskA.
    let evaluator_wires: HashSet<usize> = (256..512).collect();
    let out = garble::eval_2pc(&circuit, &evaluator_wires, &inputs)?; // x ⊕ maskA
    Ok((mask, bits_to_32(&out)))
}

/// **End-to-end pre-master conversion under 2PC**: additive EC *point* shares →
/// XOR-shares of `SHA-256(x-coordinate)` — the pre-master (the point's x-coordinate)
/// is **never assembled at either party**. Chains the three built stages:
///
/// 1. [`ectf`](super::ectf::ectf) — point shares → additive x-coordinate share (mod the
///    curve prime), big-endian.
/// 2. [`a2b_shared`] — additive field share → XOR **bit**-shares (on the real 256-bit
///    curve prime, not a toy modulus).
/// 3. [`digest_shared`](super::sha256::digest_shared) — `SHA-256(shareA ⊕ shareB)` under
///    2PC, i.e. `SHA-256(x)`.
///
/// This is the concrete "EC point → key-schedule input" bridge: it feeds the shared
/// ECDHE secret into the SHA-256 (HKDF-core) circuit without either party ever holding
/// the x-coordinate. `p1/p2` are each `(x, y)` as 32-byte **big-endian** field elements;
/// `prime` is the curve prime, big-endian. Semi-honest at the MtA layer (OT is `kos`);
/// the SHA-256 core here stands in for the full HKDF-Expand-Label schedule.
pub fn premaster_hash_from_point_shares(
    p1: (&[u8; 32], &[u8; 32]),
    p2: (&[u8; 32], &[u8; 32]),
    prime: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    // 1. ECtF → additive x-coordinate shares (big-endian).
    let (s1_be, s2_be) = ectf(p1, p2, prime)?;
    // 2. A2B works little-endian: reverse the shares and the prime.
    let (a_le, b_le) = a2b_shared(&reverse32(&s1_be), &reverse32(&s2_be), &reverse32(prime))?;
    // `a_le ⊕ b_le = x` in little-endian bytes. `digest_shared` hashes `shareA ⊕ shareB`
    // as big-endian words, so reverse both shares → they XOR to `x` big-endian, and it
    // computes SHA-256(x) with `x` in its canonical wire (big-endian) form.
    digest_shared(&reverse32(&a_le), &reverse32(&b_le))
}

/// Networked [`a2b_shared`]: the arithmetic→boolean share conversion run as two parties
/// over a [`Channel`](super::live::channel::Channel) via [`masked_eval`](super::netengine::masked_eval).
/// `share_le` is this party's additive share (little-endian, `∈ [0, prime)`); returns this
/// party's XOR bit-share of `x = (shareA + shareB) mod prime` (little-endian).
pub fn a2b_shared_net(
    ch: &mut dyn super::live::channel::Channel,
    party: super::netengine::Party,
    share_le: &[u8; 32],
    prime: &[u8; 32],
) -> Result<[u8; 32]> {
    let circuit = a2b_circuit(prime);
    let mut sh = vec![false; 256];
    write_bits(&mut sh, share_le);
    Ok(bits_to_32(&super::netengine::masked_eval(
        ch, party, &circuit, &sh,
    )?))
}

fn reverse32(x: &[u8; 32]) -> [u8; 32] {
    let mut o = *x;
    o.reverse();
    o
}

/// The A2B circuit: `x = (a + b) mod prime`, then XOR-mask the 256-bit result.
fn a2b_circuit(prime: &[u8; 32]) -> Circuit {
    let mut b = Builder::new(768);
    let zero = b.zero();
    let one = b.one();
    let a_share: Vec<usize> = (0..256).collect();
    let b_share: Vec<usize> = (256..512).collect();

    // sum = a + b in 257 bits: both shares < prime < 2^256, so sum < 2^257.
    let sum = b.add_mod(&pad(&a_share, 257, zero), &pad(&b_share, 257, zero));
    // sum ∈ [0, 2·prime) ⇒ a single conditional subtract of prime reduces it.
    let p_bits = const_bits_bytes(prime, 257, zero, one);
    let (diff, borrow) = sub_circuit(&mut b, &sum, &p_bits);
    // borrow == 1 ⇒ sum < prime ⇒ keep sum; borrow == 0 ⇒ sum ≥ prime ⇒ use diff.
    let reduced: Vec<usize> = (0..257)
        .map(|i| mux(&mut b, &sum[i], &diff[i], borrow))
        .collect();

    // Output the low 256 bits, XOR-masked with maskA.
    let outputs: Vec<usize> = (0..256).map(|i| b.xor(reduced[i], 512 + i)).collect();
    b.build(768, outputs)
}

/// Little-endian constant bits from a byte string (padded to `n` with zeros).
fn const_bits_bytes(bytes: &[u8], n: usize, zero: usize, one: usize) -> Vec<usize> {
    (0..n)
        .map(|i| {
            let set = (i / 8) < bytes.len() && (bytes[i / 8] >> (i % 8)) & 1 == 1;
            if set {
                one
            } else {
                zero
            }
        })
        .collect()
}

fn write_bits(dst: &mut [bool], bytes: &[u8]) {
    for (i, slot) in dst.iter_mut().enumerate() {
        *slot = (bytes[i / 8] >> (i % 8)) & 1 == 1;
    }
}

fn bits_to_32(bits: &[bool]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, &b) in bits.iter().take(256).enumerate() {
        if b {
            o[i / 8] |= 1 << (i % 8);
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u64_le32(v: u64) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[..8].copy_from_slice(&v.to_le_bytes());
        o
    }
    fn le32_u64(b: &[u8; 32]) -> u64 {
        u64::from_le_bytes(b[..8].try_into().unwrap())
    }

    #[test]
    fn a2b_reconstructs_the_field_element_from_additive_shares() {
        // A 63-bit modulus so the reference arithmetic fits in u128 independently of
        // the circuit — covering both the no-wrap and the wrap (conditional-subtract)
        // regimes.
        let m: u64 = 0x7FFF_FFFF_FFFF_FFE7;
        let cases = [
            (1u64, 2u64),       // no wrap
            (m - 1, m - 1),     // wraps: 2m-2 → m-2
            (m - 10, 100),      // wraps just over m
            (m / 2, m / 2 + 3), // wraps
            (0, m - 1),         // no wrap, max
        ];
        for (a, b) in cases {
            let x = ((a as u128 + b as u128) % m as u128) as u64;
            let (out_a, out_b) = a2b_shared(&u64_le32(a), &u64_le32(b), &u64_le32(m)).unwrap();
            let recovered: [u8; 32] = core::array::from_fn(|i| out_a[i] ^ out_b[i]);
            assert_eq!(le32_u64(&recovered), x, "A2B: ({a} + {b}) mod m");
            assert!(
                recovered[8..].iter().all(|&byte| byte == 0),
                "high bytes are zero for a 63-bit modulus"
            );
        }
    }

    /// P-256 base field prime, little-endian (A2B works little-endian).
    fn p256_prime_le() -> [u8; 32] {
        let be: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        let mut le = be;
        le.reverse();
        le
    }

    #[test]
    fn a2b_reconstructs_at_the_full_p256_prime() {
        use num_bigint::BigUint;
        let p_le = p256_prime_le();
        let p = BigUint::from_bytes_le(&p_le);
        let half: BigUint = &p >> 1u32;
        // Additive-share pairs mod the real 256-bit prime: small, high-byte, and a
        // wrap (half + half + 10 ≥ p ⇒ conditional-subtract path at full width).
        let cases = [
            (BigUint::from(7u32), BigUint::from(9u32)),
            (half.clone(), &half + 10u32),
            (&p - 1u32, BigUint::from(5u32)),
        ];
        for (a, b) in cases {
            let a = a % &p;
            let b = b % &p;
            let x = (&a + &b) % &p;
            let (oa, ob) = a2b_shared(&le32(&a), &le32(&b), &p_le).unwrap();
            let recovered: [u8; 32] = core::array::from_fn(|i| oa[i] ^ ob[i]);
            assert_eq!(
                BigUint::from_bytes_le(&recovered),
                x,
                "256-bit A2B reconstructs (a+b) mod p_256"
            );
        }
    }

    fn le32(x: &num_bigint::BigUint) -> [u8; 32] {
        let v = x.to_bytes_le();
        let mut o = [0u8; 32];
        o[..v.len()].copy_from_slice(&v);
        o
    }

    #[test]
    fn point_shares_to_premaster_hash_end_to_end() {
        // The full bridge: real P-256 point shares → SHA-256(x-coordinate) under 2PC,
        // validated against the vetted `p256` crate (ground-truth x) and the
        // NIST-KAT-verified `sha256` reference. The x-coordinate is never assembled.
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::ProjectivePoint;

        let be: [u8; 32] = {
            let mut b = p256_prime_le();
            b.reverse();
            b
        };
        let g = ProjectivePoint::GENERATOR;
        let p1 = g.to_affine(); // G
        let p2 = (g + g).to_affine(); // 2G
        let sum = (g + (g + g)).to_affine(); // 3G = G + 2G
        let coords = |pt: &p256::AffinePoint| -> ([u8; 32], [u8; 32]) {
            let e = pt.to_encoded_point(false);
            (
                <[u8; 32]>::try_from(e.x().unwrap().as_slice()).unwrap(),
                <[u8; 32]>::try_from(e.y().unwrap().as_slice()).unwrap(),
            )
        };
        let (x1, y1) = coords(&p1);
        let (x2, y2) = coords(&p2);
        let (sx, _) = coords(&sum);

        let (h_a, h_b) = premaster_hash_from_point_shares((&x1, &y1), (&x2, &y2), &be).unwrap();
        let got: [u8; 32] = core::array::from_fn(|i| h_a[i] ^ h_b[i]);
        assert_eq!(
            got,
            super::super::sha256::sha256(&sx),
            "2PC pipeline yields SHA-256 of P-256's real (G+2G) x-coordinate"
        );
    }

    #[test]
    fn shared_ecdhe_point_shares_feed_the_premaster_pipeline() {
        // DECO shared ECDHE on real P-256: the client scalar is additively split
        // c = c1 + c2; each party computes its point share Zi = ci·S locally from the
        // server's public S, so Z1 + Z2 = c·S is the ECDHE secret — and neither party
        // holds it. The pipeline then hashes its x-coordinate under 2PC. (A *live*
        // handshake that sends C = c·G to a real server and receives S is the remaining
        // step-4 integration; here S is a fixed public point.)
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::{ProjectivePoint, Scalar};

        let be: [u8; 32] = {
            let mut b = p256_prime_le();
            b.reverse();
            b
        };
        let s_pub = ProjectivePoint::GENERATOR * Scalar::from(5u64); // "server" public S = 5G
        let c1 = Scalar::from(1_234_567u64);
        let c2 = Scalar::from(7_654_321u64);
        let z1 = (s_pub * c1).to_affine(); // party 1's point share c1·S
        let z2 = (s_pub * c2).to_affine(); // party 2's point share c2·S
        let z = (s_pub * (c1 + c2)).to_affine(); // the real ECDHE secret (c1+c2)·S

        let coords = |pt: &p256::AffinePoint| -> ([u8; 32], [u8; 32]) {
            let e = pt.to_encoded_point(false);
            (
                <[u8; 32]>::try_from(e.x().unwrap().as_slice()).unwrap(),
                <[u8; 32]>::try_from(e.y().unwrap().as_slice()).unwrap(),
            )
        };
        let (x1, y1) = coords(&z1);
        let (x2, y2) = coords(&z2);
        let (zx, _) = coords(&z);

        let (h_a, h_b) = premaster_hash_from_point_shares((&x1, &y1), (&x2, &y2), &be).unwrap();
        let got: [u8; 32] = core::array::from_fn(|i| h_a[i] ^ h_b[i]);
        assert_eq!(
            got,
            super::super::sha256::sha256(&zx),
            "pipeline hashes the real shared-ECDHE secret's x-coordinate under 2PC"
        );
    }
}
