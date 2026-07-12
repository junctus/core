//! Share conversion for the MPC-TLS key schedule — the arithmetic→boolean half of
//! DECO's EC point→bit conversion.
//!
//! DECO's [`session::shared_ecdhe`](super::session::shared_ecdhe) leaves the two
//! parties with an **additive share of the ECDHE point**. The TLS key schedule
//! ([`sha256`](super::sha256) under 2PC) consumes a **bit-share of the pre-master
//! secret** (the point's x-coordinate). Bridging the two is a two-step conversion:
//!
//! 1. additive EC *point* shares → an additive *x-coordinate* share (mod the curve
//!    prime) — EC addition under MPC on the real curve. This is the harder,
//!    still-**research** half (real-curve field arithmetic + inversion in-circuit).
//! 2. that additive field-element share → a **bit-share** — an **arithmetic-to-
//!    boolean (A2B)** conversion. **This module.**
//!
//! [`a2b_shared`] is the step-2 primitive: given two additive shares of a value
//! `x = (share_a + share_b) mod prime` (each share in `[0, prime)`), it computes,
//! under 2PC, XOR-shares of the bits of `x` — without either party ever assembling
//! `x`. It is exactly what feeds the key-schedule circuit once step 1 lands.
//!
//! Semi-honest, like the rest of the 2PC session.

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::{Builder, Circuit};
use super::garble;
use super::poly1305::{mux, pad, sub_circuit};

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
            (1u64, 2u64),           // no wrap
            (m - 1, m - 1),         // wraps: 2m-2 → m-2
            (m - 10, 100),          // wraps just over m
            (m / 2, m / 2 + 3),     // wraps
            (0, m - 1),             // no wrap, max
        ];
        for (a, b) in cases {
            let x = ((a as u128 + b as u128) % m as u128) as u64;
            let (out_a, out_b) =
                a2b_shared(&u64_le32(a), &u64_le32(b), &u64_le32(m)).unwrap();
            let recovered: [u8; 32] = core::array::from_fn(|i| out_a[i] ^ out_b[i]);
            assert_eq!(le32_u64(&recovered), x, "A2B: ({a} + {b}) mod m");
            assert!(
                recovered[8..].iter().all(|&byte| byte == 0),
                "high bytes are zero for a 63-bit modulus"
            );
        }
    }
}
