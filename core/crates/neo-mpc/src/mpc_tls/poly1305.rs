//! **Poly1305 one-time MAC** — the authenticator half of ChaCha20-Poly1305 — as a
//! reference and, under 2PC, a **shared tag**. Poly1305 is arithmetic in the prime
//! field `GF(2¹³⁰−5)`: `tag = (Σ blockᵢ · r^i mod p) + s (mod 2¹²⁸)`.
//!
//! The reference here is verified against the RFC 8439 §2.5.2 known-answer test.
//! [`tag_shared`] then computes the tag under 2PC: the one-time key `(r, s)` and
//! the message are XOR-shared between the two parties, the polynomial evaluation
//! runs inside the garbled circuit, and the parties come away with XOR-shares of
//! the tag — the key and message never assembled at either party. Together with
//! `session`'s ChaCha keystream under 2PC, this is **ChaCha20-Poly1305 AEAD with
//! neither the key nor the plaintext ever at one place**.
//!
//! Boundary: the field multiply + `mod 2¹³⁰−5` reduction is the heaviest gadget in
//! the stack; it is built on the same adder as everything else and verified
//! against the reference. `tag_shared`/`tag_circuit` handle a **single 16-byte
//! block only** (the high bit is hard-coded at position 128, so a partial final
//! block would be mis-padded). Multi-block messages would iterate the same circuit
//! by Horner — that iteration is **not** implemented here.

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::{Builder, Circuit};
use super::engine::{eval_circuit, EngineKind};
use super::garble;

/// 288-bit little-endian bignum as nine 32-bit limbs (holds products < 2²⁶⁰).
type Big = [u64; 9];

/// `p = 2¹³⁰ − 5`.
const P: Big = [
    0xffff_fffb,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0x0000_0003,
    0,
    0,
    0,
    0,
];

// ---- reference -------------------------------------------------------------

/// Poly1305 over `msg` with 32-byte one-time `key = r ‖ s` — checked against the
/// RFC 8439 KAT.
pub fn poly1305(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let r = clamp(&key[..16]);
    let s = from_le(&key[16..32]);

    let mut acc = [0u64; 9];
    for chunk in msg.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1; // the appended high bit
        acc = add(&acc, &from_le(&block));
        acc = reduce(&mul(&acc, &r));
    }
    acc = add(&acc, &s);
    to_le16(&acc)
}

fn clamp(r: &[u8]) -> Big {
    let mut b = [0u8; 16];
    b.copy_from_slice(r);
    b[3] &= 15;
    b[7] &= 15;
    b[11] &= 15;
    b[15] &= 15;
    b[4] &= 252;
    b[8] &= 252;
    b[12] &= 252;
    from_le(&b)
}

fn from_le(bytes: &[u8]) -> Big {
    let mut o = [0u64; 9];
    for (i, &byte) in bytes.iter().enumerate() {
        o[i / 4] |= (byte as u64) << ((i % 4) * 8);
    }
    o
}

fn to_le16(a: &Big) -> [u8; 16] {
    let mut o = [0u8; 16];
    for (i, byte) in o.iter_mut().enumerate() {
        *byte = ((a[i / 4] >> ((i % 4) * 8)) & 0xff) as u8;
    }
    o
}

fn add(a: &Big, b: &Big) -> Big {
    let mut o = [0u64; 9];
    let mut c = 0u64;
    for i in 0..9 {
        let s = a[i] + b[i] + c;
        o[i] = s & 0xffff_ffff;
        c = s >> 32;
    }
    o
}

fn mul(a: &Big, b: &Big) -> Big {
    let mut o = [0u64; 9];
    for i in 0..9 {
        if a[i] == 0 {
            continue;
        }
        let mut carry = 0u64;
        for j in 0..9 - i {
            let cur = o[i + j] + a[i] * b[j] + carry;
            o[i + j] = cur & 0xffff_ffff;
            carry = cur >> 32;
        }
    }
    o
}

/// Reduce `mod p = 2¹³⁰ − 5` using `2¹³⁰ ≡ 5`.
fn reduce(v: &Big) -> Big {
    let mut v = *v;
    loop {
        let hi = shr130(&v);
        if hi.iter().all(|&l| l == 0) {
            break;
        }
        v = add(&low130(&v), &mul(&hi, &[5, 0, 0, 0, 0, 0, 0, 0, 0]));
    }
    if ge(&v, &P) {
        v = sub(&v, &P);
    }
    v
}

fn low130(a: &Big) -> Big {
    let mut o = *a;
    o[4] &= 0x3;
    for l in o.iter_mut().skip(5) {
        *l = 0;
    }
    o
}

fn shr130(a: &Big) -> Big {
    // a >> 128 (drop 4 limbs), then >> 2.
    let mut t = [0u64; 9];
    t[..5].copy_from_slice(&a[4..9]);
    let mut o = [0u64; 9];
    for k in 0..9 {
        let hi = if k + 1 < 9 { (t[k + 1] & 0x3) << 30 } else { 0 };
        o[k] = ((t[k] >> 2) | hi) & 0xffff_ffff;
    }
    o
}

fn ge(a: &Big, b: &Big) -> bool {
    for i in (0..9).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub(a: &Big, b: &Big) -> Big {
    let mut o = [0u64; 9];
    let mut borrow = 0i64;
    for i in 0..9 {
        let d = a[i] as i64 - b[i] as i64 - borrow;
        if d < 0 {
            o[i] = (d + (1 << 32)) as u64;
            borrow = 1;
        } else {
            o[i] = d as u64;
            borrow = 0;
        }
    }
    o
}

// ---- 2PC tag ---------------------------------------------------------------

/// Compute a Poly1305 tag for a single 16-byte `block` under 2PC. The one-time key
/// `(r, s)` and the block are each XOR-shared between the two parties (`*_a ⊕
/// *_b`); the parties come away with XOR-shares of the 16-byte tag, with the key,
/// message, and tag never assembled at either party.
///
/// One block is the core field operation `tag = ((block·r) mod p + s) mod 2¹²⁸`;
/// multi-block messages iterate the same circuit (Horner over the blocks).
pub fn tag_shared(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    block_a: &[u8; 16],
    block_b: &[u8; 16],
) -> Result<([u8; 16], [u8; 16])> {
    let circuit = tag_circuit();

    // Wire layout: keyA[256] ‖ keyB[256] ‖ blockA[128] ‖ blockB[128] ‖ maskA[128].
    let mut inputs = vec![false; 896];
    write_bits(&mut inputs[0..256], key_a);
    write_bits(&mut inputs[256..512], key_b);
    write_bits(&mut inputs[512..640], block_a);
    write_bits(&mut inputs[640..768], block_b);
    let mut mask = [0u8; 16];
    getrandom::getrandom(&mut mask).map_err(|e| Error::Rng(e.to_string()))?;
    write_bits(&mut inputs[768..896], &mask);

    // Evaluator owns keyB and blockB; garbler owns keyA, blockA, maskA.
    let evaluator_wires: HashSet<usize> = (256..512).chain(640..768).collect();
    let out = garble::eval_2pc(&circuit, &evaluator_wires, &inputs)?; // tag ⊕ maskA

    Ok((mask, bits_to_16(&out)))
}

/// Circuit for the single-block shared tag: form `r`, `s`, `block` from the two
/// parties' XOR-shares, compute `((block·r) mod p + s) mod 2¹²⁸`, XOR-mask it.
fn tag_circuit() -> Circuit {
    let mut b = Builder::new(896);

    // Reconstruct the shared inputs.
    let r_raw: Vec<usize> = (0..128).map(|i| b.xor(i, 256 + i)).collect(); // key[0..16]
    let s: Vec<usize> = (0..128).map(|i| b.xor(128 + i, 384 + i)).collect(); // key[16..32]
    let block: Vec<usize> = (0..128).map(|i| b.xor(512 + i, 640 + i)).collect();

    // Clamp r (force the clamped bits to 0 by routing them to the zero wire).
    let zero = b.zero();
    let mut r = r_raw;
    for &bit in &clamp_zero_bits() {
        r[bit] = zero;
    }

    // block' = block + 2^128  (append the high bit).
    let one = b.one();
    let mut block_hi = block.clone();
    block_hi.push(one); // bit 128 = 1
    while block_hi.len() < 131 {
        block_hi.push(zero);
    }

    // acc = (block' * r) mod p, then + s, then mod 2^128.
    let prod = mul_circuit(&mut b, &block_hi, &pad(&r, 131, zero));
    let acc = reduce_circuit(&mut b, &prod, zero, one);
    let summed = b.add_mod(&pad(&acc, 128, zero), &s); // (acc + s) mod 2^128 (low 128 bits)

    // XOR-mask the 128-bit tag with maskA.
    let outputs: Vec<usize> = (0..128).map(|i| b.xor(summed[i], 768 + i)).collect();
    b.build(896, outputs)
}

/// Compute the shared Poly1305 tag over **`blocks.len()` message blocks** (the full
/// RFC 8439 case: AAD-pad ‖ ciphertext-pad ‖ length block). The one-time key
/// `(r, s)` is XOR-shared between the two parties (never assembled); the message
/// blocks are **public** (AAD + ciphertext + lengths are all public in an AEAD, so
/// each block goes in one party's share with the other zero). Returns XOR-shares of
/// the 16-byte tag. Each block is a full 16-byte block (high bit at 128), which is
/// exactly the RFC AEAD framing — no partial-block padding subtlety.
pub fn tag_shared_multi(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    blocks: &[[u8; 16]],
) -> Result<([u8; 16], [u8; 16])> {
    tag_shared_multi_engine(EngineKind::Semihonest, key_a, key_b, blocks)
}

/// [`tag_shared_multi`] under a chosen 2PC [`EngineKind`] (semi-honest or the malicious
/// authenticated-garbling online).
pub fn tag_shared_multi_engine(
    engine: EngineKind,
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    blocks: &[[u8; 16]],
) -> Result<([u8; 16], [u8; 16])> {
    let n = blocks.len();
    if n == 0 {
        return Err(Error::Crypto("poly1305 needs at least one block".into()));
    }
    let circuit = tag_circuit_multi(n);
    let n_inputs = 512 + n * 256 + 128;

    // Layout: keyA[256] ‖ keyB[256] ‖ n×(blockA[128] ‖ blockB[128]) ‖ maskA[128].
    let mut inputs = vec![false; n_inputs];
    write_bits(&mut inputs[0..256], key_a);
    write_bits(&mut inputs[256..512], key_b);
    // Evaluator owns keyB and every blockB (the blocks are public, split as
    // (block, 0) — blockB stays zero and belongs to the evaluator, mirroring the
    // single-block call).
    let mut evaluator_wires: HashSet<usize> = (256..512).collect();
    for (i, blk) in blocks.iter().enumerate() {
        let base_a = 512 + i * 256;
        let base_b = base_a + 128;
        write_bits(&mut inputs[base_a..base_a + 128], blk); // blockA = the public block
        evaluator_wires.extend(base_b..base_b + 128); // blockB = 0, evaluator's
    }
    let mut mask = [0u8; 16];
    getrandom::getrandom(&mut mask).map_err(|e| Error::Rng(e.to_string()))?;
    let mask_base = 512 + n * 256;
    write_bits(&mut inputs[mask_base..mask_base + 128], &mask);

    let out = eval_circuit(engine, &circuit, &evaluator_wires, &inputs)?; // tag ⊕ maskA
    Ok((mask, bits_to_16(&out)))
}

/// The multi-block tag circuit: reconstruct `(r, s)` from the two key shares, then
/// Horner-accumulate `acc = ((acc + blockᵢ') · r) mod p` over the blocks, finally
/// `(acc + s) mod 2¹²⁸` XOR-masked. `tag_circuit_multi(1)` is structurally the
/// single-block [`tag_circuit`].
fn tag_circuit_multi(n_blocks: usize) -> Circuit {
    let n_inputs = 512 + n_blocks * 256 + 128;
    let mut b = Builder::new(n_inputs);
    let zero = b.zero();
    let one = b.one();

    let r_raw: Vec<usize> = (0..128).map(|i| b.xor(i, 256 + i)).collect(); // key[0..16]
    let s: Vec<usize> = (0..128).map(|i| b.xor(128 + i, 384 + i)).collect(); // key[16..32]
    let mut r = r_raw;
    for &bit in &clamp_zero_bits() {
        r[bit] = zero;
    }
    // acc, block', and sum live in 132 bits: acc < 2^130, block' < 2^131, so
    // acc+block' < 2^132 (no overflow), and (sum·r) < 2^256 stays in reduce's range.
    let r132 = pad(&r, 132, zero);
    let mut acc = vec![zero; 132];
    for blk in 0..n_blocks {
        let base_a = 512 + blk * 256;
        let base_b = base_a + 128;
        let block: Vec<usize> = (0..128).map(|i| b.xor(base_a + i, base_b + i)).collect();
        let mut block_hi = block;
        block_hi.push(one); // bit 128 = 1 (the appended high bit)
        let block_hi = pad(&block_hi, 132, zero);
        let sum = b.add_mod(&acc, &block_hi); // acc + block'
        let prod = mul_circuit(&mut b, &sum, &r132); // (acc + block') · r
        acc = pad(&reduce_circuit(&mut b, &prod, zero, one), 132, zero); // mod p
    }
    let summed = b.add_mod(&pad(&acc, 128, zero), &s); // (acc + s) mod 2^128
    let mask_base = 512 + n_blocks * 256;
    let outputs: Vec<usize> = (0..128).map(|i| b.xor(summed[i], mask_base + i)).collect();
    b.build(n_inputs, outputs)
}

/// Schoolbook multiply of little-endian bit vectors → `x.len()+y.len()` bits.
fn mul_circuit(b: &mut Builder, x: &[usize], y: &[usize]) -> Vec<usize> {
    let zero = b.zero();
    let width = x.len() + y.len();
    let mut acc = vec![zero; width];
    for (i, &yi) in y.iter().enumerate() {
        // partial = (x AND yi) << i, zero-padded to `width`.
        let mut partial = vec![zero; width];
        for (k, &xk) in x.iter().enumerate() {
            partial[i + k] = b.and(xk, yi);
        }
        acc = b.add_mod(&acc, &partial);
    }
    acc
}

/// Reduce a wide value `mod 2¹³⁰−5` in-circuit: fold `high·5 + low` until `high`
/// is a couple of bits, then a final conditional subtract of `p`.
fn reduce_circuit(b: &mut Builder, v: &[usize], zero: usize, one: usize) -> Vec<usize> {
    let mut v = v.to_vec();
    // A few folds bring the value below 2^131.
    for _ in 0..4 {
        if v.len() <= 130 {
            break;
        }
        let low = pad(&v[..130], 134, zero);
        let high = &v[130..];
        // high*5 = (high<<2) + high
        let mut hi4 = vec![zero, zero];
        hi4.extend_from_slice(high);
        let hi5 = b.add_mod(&pad(&hi4, 134, zero), &pad(high, 134, zero));
        v = b.add_mod(&low, &hi5);
    }
    v.truncate(131);
    v = pad(&v, 131, zero);

    // Final: if v >= p, subtract p. Compute v - p and select on the borrow.
    let p_bits = const_bits(&P, 131, zero, one);
    let (diff, borrow) = sub_circuit(b, &v, &p_bits);
    // borrow == 0  ⇒  v >= p  ⇒  use diff; else keep v.
    (0..131)
        .map(|i| mux(b, &v[i], &diff[i], borrow))
        .collect::<Vec<_>>()[..130]
        .to_vec()
}

/// Subtract `y` from `x` (same width); returns `(x-y mod 2^n, borrow_out)`.
pub(crate) fn sub_circuit(b: &mut Builder, x: &[usize], y: &[usize]) -> (Vec<usize>, usize) {
    let mut borrow = b.zero();
    let mut out = Vec::with_capacity(x.len());
    for i in 0..x.len() {
        // d = x ^ y ^ borrow ; borrow' = (!x & y) | (!x & borrow) | (y & borrow)
        let xy = b.xor(x[i], y[i]);
        let d = b.xor(xy, borrow);
        let nx = b.inv(x[i]);
        let nx_y = b.and(nx, y[i]);
        let nx_bo = b.and(nx, borrow);
        let y_bo = b.and(y[i], borrow);
        let t = b.or(nx_y, nx_bo);
        borrow = b.or(t, y_bo);
        out.push(d);
    }
    (out, borrow)
}

/// `sel==1 ? one_wire : zero_wire`, per bit: `out = z ^ (sel & (o ^ z))` inverted…
/// here `mux(z_val, o_val, sel)` returns `sel ? o_val : z_val`.
pub(crate) fn mux(b: &mut Builder, z_val: &usize, o_val: &usize, sel: usize) -> usize {
    // sel==1 keeps z_val (v), sel==0 keeps o_val (diff): borrow=1 means v<p → keep v.
    let x = b.xor(*z_val, *o_val);
    let g = b.and(sel, x);
    b.xor(*o_val, g)
}

pub(crate) fn pad(v: &[usize], n: usize, zero: usize) -> Vec<usize> {
    let mut o = v.to_vec();
    o.truncate(n);
    while o.len() < n {
        o.push(zero);
    }
    o
}

fn const_bits(big: &Big, n: usize, zero: usize, one: usize) -> Vec<usize> {
    (0..n)
        .map(|i| {
            let bit = (big[i / 32] >> (i % 32)) & 1 == 1;
            if bit {
                one
            } else {
                zero
            }
        })
        .collect()
}

/// The bit indices of r (128-bit, little-endian) that clamping forces to zero.
fn clamp_zero_bits() -> Vec<usize> {
    let mut bits = Vec::new();
    // bytes 3,7,11,15: clear top 4 bits (bits 4..8 of the byte).
    for &byte in &[3usize, 7, 11, 15] {
        for bit in 4..8 {
            bits.push(byte * 8 + bit);
        }
    }
    // bytes 4,8,12: clear low 2 bits.
    for &byte in &[4usize, 8, 12] {
        for bit in 0..2 {
            bits.push(byte * 8 + bit);
        }
    }
    bits
}

fn write_bits(dst: &mut [bool], bytes: &[u8]) {
    for (i, slot) in dst.iter_mut().enumerate() {
        *slot = (bytes[i / 8] >> (i % 8)) & 1 == 1;
    }
}

fn bits_to_16(bits: &[bool]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for (i, &b) in bits.iter().take(128).enumerate() {
        if b {
            o[i / 8] |= 1 << (i % 8);
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poly1305_reference_matches_rfc8439_kat() {
        // RFC 8439 §2.5.2.
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(poly1305(msg, &key), expected);
    }

    #[test]
    fn single_block_tag_runs_under_2pc_into_shares() {
        let key_a: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let key_b: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x3c);
        let block_a: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(5));
        let block_b: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ 0x99);

        let (share_a, share_b) = tag_shared(&key_a, &key_b, &block_a, &block_b).unwrap();

        // Combined shares == Poly1305 of the single (16-byte) reconstructed block.
        let key: [u8; 32] = core::array::from_fn(|i| key_a[i] ^ key_b[i]);
        let block: [u8; 16] = core::array::from_fn(|i| block_a[i] ^ block_b[i]);
        let combined: [u8; 16] = core::array::from_fn(|i| share_a[i] ^ share_b[i]);
        assert_eq!(combined, poly1305(&block, &key));
        assert_ne!(share_a, combined, "neither share alone is the tag");
    }
}
