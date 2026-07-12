//! **HKDF-Expand-Label under 2PC** — the TLS 1.3 key schedule with a **secret
//! XOR-shared across the two parties** and a **public** label/context, computed under
//! garbled-circuit 2PC so neither party ever holds the traffic secret.
//!
//! TLS 1.3 derives every key with `HKDF-Expand-Label(Secret, Label, Context, L)`
//! (RFC 8446 §7.1), which is `HKDF-Expand(Secret, HkdfLabel, L)` and, for `L ≤ 32`,
//! one `HMAC-SHA256(Secret, HkdfLabel ‖ 0x01)`. In 2PC-TLS the `Secret` is the shared
//! ECDHE-derived value (never assembled — see [`convert::premaster_hash_from_point_shares`](super::convert)),
//! and the label/context are public protocol constants. So the whole schedule reduces
//! to **HMAC-SHA256 with a shared key and public message**, which this module runs
//! inside the same garbled SHA-256 circuit ([`sha256`](super::sha256)) used elsewhere.
//!
//! [`hmac_sha256_shared`] is the core: `HMAC-SHA256(kA ⊕ kB, msg)` into XOR-shares,
//! via `H((K⊕opad) ‖ H((K⊕ipad) ‖ msg))` with the ipad/opad key blocks carrying the
//! shared key and every message/padding block a public constant. [`hkdf_expand_label_shared`]
//! builds the public `HkdfLabel` and wraps it.
//!
//! # Honest boundary
//! - **Validated against RustCrypto**: the tests match the 2PC output byte-for-byte
//!   against the vetted `hmac`/`hkdf` crates — an independent oracle.
//! - **Semi-honest** garbled-circuit 2PC (the OT for evaluator inputs is the crate's;
//!   the online here uses the [`garble`](super::garble) evaluator), both parties
//!   modelled in-process; the malicious-secure online is [`wrk17`](super::wrk17).
//! - This is the *crypto* of the key schedule; wiring it to a live TLS socket (the
//!   handshake state machine, record layer, a real server) is the remaining
//!   integration, not this module.

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::{Builder, Circuit};
use super::garble;
use super::sha256::{compress_circuit, H0};

/// `HMAC-SHA256(kA ⊕ kB, msg)` under 2PC: the key is XOR-shared (`kA` party A, `kB`
/// party B), `msg` is public. Returns XOR-shares `(outA, outB)` of the 32-byte tag,
/// so neither party learns the key or the tag.
pub fn hmac_sha256_shared(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    msg: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    let circuit = hmac_circuit(msg);

    // Layout: keyA[256] ‖ keyB[256] ‖ maskA[256] = 768 (mirrors sha256::digest_shared).
    let mut inputs = vec![false; 768];
    write_be_words(&mut inputs[0..256], key_a);
    write_be_words(&mut inputs[256..512], key_b);
    let mut mask_bits = vec![false; 256];
    let mut mask_raw = [0u8; 32];
    getrandom::getrandom(&mut mask_raw).map_err(|e| Error::Rng(e.to_string()))?;
    for (i, bit) in mask_bits.iter_mut().enumerate() {
        *bit = (mask_raw[i / 8] >> (i % 8)) & 1 == 1;
    }
    inputs[512..768].copy_from_slice(&mask_bits);

    let evaluator_wires: HashSet<usize> = (256..512).collect(); // keyB
    let out = garble::eval_2pc(&circuit, &evaluator_wires, &inputs)?; // tag ⊕ maskA
    Ok((bytes_from_be_words(&mask_bits), bytes_from_be_words(&out)))
}

/// `HKDF-Expand-Label(secret, label, context, length)` under 2PC (RFC 8446 §7.1), for
/// `length ≤ 32`. The secret is XOR-shared; the label/context are public. Returns
/// XOR-shares of the 32-byte `HMAC-SHA256(secret, HkdfLabel ‖ 0x01)`; the first
/// `length` bytes are the derived key (each share truncated identically).
pub fn hkdf_expand_label_shared(
    secret_a: &[u8; 32],
    secret_b: &[u8; 32],
    label: &[u8],
    context: &[u8],
    length: u16,
) -> Result<([u8; 32], [u8; 32])> {
    let info = hkdf_label(label, context, length);
    let mut msg = info;
    msg.push(0x01); // HKDF-Expand T(1) counter
    hmac_sha256_shared(secret_a, secret_b, &msg)
}

/// The public `HkdfLabel` struct: `uint16 length ‖ (len‖"tls13 "+label) ‖ (len‖context)`.
fn hkdf_label(label: &[u8], context: &[u8], length: u16) -> Vec<u8> {
    let full_label = [b"tls13 ".as_slice(), label].concat();
    let mut out = Vec::with_capacity(4 + full_label.len() + context.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.push(full_label.len() as u8);
    out.extend_from_slice(&full_label);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}

/// Build the HMAC-SHA256 circuit for a public `msg`: inputs `keyA[256] ‖ keyB[256] ‖
/// maskA[256]`, output `HMAC ⊕ maskA` (256 bits).
fn hmac_circuit(msg: &[u8]) -> Circuit {
    let mut b = Builder::new(768);

    // key = keyA ⊕ keyB, 8 big-endian 32-bit words (each LSB-first over 32 wires).
    let key: Vec<Vec<usize>> = (0..8)
        .map(|w| {
            (0..32)
                .map(|j| b.xor(w * 32 + j, 256 + w * 32 + j))
                .collect()
        })
        .collect();
    let h0: Vec<Vec<usize>> = H0.iter().map(|&h| b.word_const(h)).collect();

    // Inner: H((K⊕ipad) ‖ msg). Block 0 = K⊕0x36…36 (words 0-7 shared, 8-15 public).
    let ipad_block = key_pad_block(&mut b, &key, 0x36);
    let mut h = compress_circuit(&mut b, &h0, &ipad_block);
    for block in public_blocks(msg, 64) {
        let cblock: Vec<Vec<usize>> = (0..16).map(|w| b.word_const(be_word(&block, w))).collect();
        h = compress_circuit(&mut b, &h, &cblock);
    }
    let inner_digest = h; // 8 words, shared

    // Outer: H((K⊕opad) ‖ inner_digest). Block 0 = K⊕0x5c…5c; final block = digest+pad.
    let opad_block = key_pad_block(&mut b, &key, 0x5c);
    let mut ho = compress_circuit(&mut b, &h0, &opad_block);
    let mut final_block: Vec<Vec<usize>> = inner_digest;
    final_block.push(b.word_const(0x8000_0000)); // 0x80 after the 32-byte digest
    for _ in 9..15 {
        final_block.push(b.word_const(0));
    }
    final_block.push(b.word_const((64 + 32) * 8)); // bit length = 768
    ho = compress_circuit(&mut b, &ho, &final_block);

    // Output HMAC ⊕ maskA.
    let outputs: Vec<usize> = ho
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(i, wire)| b.xor(wire, 512 + i))
        .collect();
    b.build(768, outputs)
}

/// The 64-byte key block `K ‖ 0…0` XORed with a repeated pad byte: words 0-7 are the
/// shared key XORed with `pad·4`, words 8-15 the public constant `pad·4`.
fn key_pad_block(b: &mut Builder, key: &[Vec<usize>], pad: u8) -> Vec<Vec<usize>> {
    let padw = u32::from_be_bytes([pad; 4]);
    let pad_word = b.word_const(padw);
    let mut block: Vec<Vec<usize>> = (0..8)
        .map(|w| (0..32).map(|j| b.xor(key[w][j], pad_word[j])).collect())
        .collect();
    for _ in 8..16 {
        block.push(b.word_const(padw));
    }
    block
}

/// The public blocks that follow a `prefix_len`-byte (already-compressed) block: `msg`
/// plus SHA-256 padding for the total length `prefix_len + msg.len()`, as 64-byte
/// blocks. (`prefix_len` is a multiple of 64 — here the 64-byte ipad key block.)
fn public_blocks(msg: &[u8], prefix_len: usize) -> Vec<[u8; 64]> {
    let bitlen = ((prefix_len + msg.len()) as u64) * 8;
    let mut rem = msg.to_vec();
    rem.push(0x80);
    while (prefix_len + rem.len()) % 64 != 56 {
        rem.push(0);
    }
    rem.extend_from_slice(&bitlen.to_be_bytes()); // now (prefix_len + rem.len()) % 64 == 0
    rem.chunks(64)
        .map(|c| {
            let mut blk = [0u8; 64];
            blk.copy_from_slice(c);
            blk
        })
        .collect()
}

fn be_word(block: &[u8; 64], w: usize) -> u32 {
    u32::from_be_bytes(block[w * 4..w * 4 + 4].try_into().expect("4 bytes"))
}

fn write_be_words(dst: &mut [bool], bytes: &[u8; 32]) {
    for w in 0..8 {
        let word = u32::from_be_bytes(bytes[w * 4..w * 4 + 4].try_into().expect("4 bytes"));
        for j in 0..32 {
            dst[w * 32 + j] = (word >> j) & 1 == 1;
        }
    }
}

fn bytes_from_be_words(bits: &[bool]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for w in 0..8 {
        let mut word = 0u32;
        for j in 0..32 {
            if bits[w * 32 + j] {
                word |= 1 << j;
            }
        }
        out[w * 4..w * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn combine(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        core::array::from_fn(|i| a[i] ^ b[i])
    }

    #[test]
    fn hmac_under_2pc_matches_rustcrypto() {
        // Shared key + public messages of varied lengths (crossing the 1- and 2-block
        // boundaries of the inner hash), matched against the vetted `hmac` crate.
        let key_a = [0x11u8; 32];
        let key_b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0xa5);
        let key = combine(&key_a, &key_b);
        for msg in [
            b"".as_slice(),
            b"abc",
            b"tls13 key\x00\x01",
            &[0x5au8; 55],  // inner: prefix(64)+55 -> 1 public block
            &[0x5au8; 120], // inner: -> 2 public blocks
        ] {
            let (oa, ob) = hmac_sha256_shared(&key_a, &key_b, msg).unwrap();
            let got = combine(&oa, &ob);

            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
            mac.update(msg);
            let want = mac.finalize().into_bytes();
            assert_eq!(
                &got[..],
                want.as_slice(),
                "HMAC-SHA256 under 2PC (msg len {})",
                msg.len()
            );
        }
    }

    #[test]
    fn hkdf_expand_label_under_2pc_matches_rustcrypto() {
        // The TLS 1.3 key schedule step, matched against the vetted `hkdf` crate over
        // the same HkdfLabel info.
        let secret_a: [u8; 32] = core::array::from_fn(|i| i as u8);
        let secret_b: [u8; 32] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
        let secret = combine(&secret_a, &secret_b);

        let cases: [(&[u8], &[u8], u16); 3] = [
            (b"key", b"", 16),
            (b"iv", b"", 12),
            (b"c hs traffic", &[0xabu8; 32], 32),
        ];
        for (label, context, length) in cases {
            let (oa, ob) =
                hkdf_expand_label_shared(&secret_a, &secret_b, label, context, length).unwrap();
            let got = combine(&oa, &ob);

            // Reference: HKDF-Expand(secret, HkdfLabel, length) via the hkdf crate.
            let info = hkdf_label(label, context, length);
            let hk = Hkdf::<Sha256>::from_prk(&secret).unwrap();
            let mut okm = vec![0u8; length as usize];
            hk.expand(&info, &mut okm).unwrap();
            assert_eq!(
                &got[..length as usize],
                &okm[..],
                "HKDF-Expand-Label({}) under 2PC",
                String::from_utf8_lossy(label)
            );
        }
    }
}
