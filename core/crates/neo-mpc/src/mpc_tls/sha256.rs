//! **SHA-256 as a boolean circuit** and the TLS **key-schedule primitive under
//! 2PC**. TLS 1.3 derives its traffic keys with HKDF-SHA256; the non-linear heart
//! of that is the SHA-256 compression function, which this builds as a circuit
//! (reusing the 32-bit adder) and verifies against the NIST KAT.
//!
//! [`digest_shared`] then computes SHA-256 of a **secret-shared** input under 2PC:
//! two parties holding XOR-shares of a 32-byte secret come away with XOR-shares of
//! its digest, the secret never assembled at either party — i.e. a key derivation
//! run inside the garbled circuit. HKDF/HMAC is this compression composed a fixed
//! number of times (the same machinery), noted as the layering step in the parent
//! module's boundary.

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::{Builder, Circuit};
use super::garble;

/// SHA-256 initial hash values.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 round constants.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

// ---- reference (the correctness oracle) ------------------------------------

/// Plaintext SHA-256 with padding — checked against the NIST KAT.
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut m = msg.to_vec();
    let bitlen = (msg.len() as u64) * 8;
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bitlen.to_be_bytes());

    let mut h = H0;
    for block in m.chunks(64) {
        let mut b = [0u8; 64];
        b.copy_from_slice(block);
        h = compress_ref(h, &b);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

/// One SHA-256 compression (`h' = h + block-mixing`), the reference for the circuit.
fn compress_ref(h: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let mut w = [0u32; 64];
    for (i, wi) in w.iter_mut().take(16).enumerate() {
        *wi = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    for t in 16..64 {
        w[t] = ssig1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(ssig0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }
    let mut s = h;
    for t in 0..64 {
        let t1 = s[7]
            .wrapping_add(bsig1(s[4]))
            .wrapping_add(ch(s[4], s[5], s[6]))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = bsig0(s[0]).wrapping_add(maj(s[0], s[1], s[2]));
        s = [
            t1.wrapping_add(t2),
            s[0],
            s[1],
            s[2],
            s[3].wrapping_add(t1),
            s[4],
            s[5],
            s[6],
        ];
    }
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = h[i].wrapping_add(s[i]);
    }
    out
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}
fn bsig0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn bsig1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
fn ssig0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
fn ssig1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// ---- circuit ---------------------------------------------------------------

/// A SHA-256 compression as a circuit: inputs `h_in[256] ‖ block[512]` (768),
/// output the 256-bit updated chaining value. Verified against [`compress_ref`].
pub fn sha256_compress_circuit() -> Circuit {
    let mut b = Builder::new(768);
    let h_in: Vec<Vec<usize>> = (0..8).map(|i| (i * 32..i * 32 + 32).collect()).collect();
    let block: Vec<Vec<usize>> = (0..16)
        .map(|i| (256 + i * 32..256 + i * 32 + 32).collect())
        .collect();
    let out = compress_circuit(&mut b, &h_in, &block);
    let outputs: Vec<usize> = out.into_iter().flatten().collect();
    b.build(768, outputs)
}

/// The compression as circuit gates over 32-bit words (LSB-first wire vectors).
fn compress_circuit(b: &mut Builder, h_in: &[Vec<usize>], block: &[Vec<usize>]) -> Vec<Vec<usize>> {
    // Message schedule W[0..64].
    let mut w: Vec<Vec<usize>> = block.to_vec();
    for t in 16..64 {
        let s1 = c_ssig1(b, &w[t - 2]);
        let s0 = c_ssig0(b, &w[t - 15]);
        let a1 = b.add_mod(&s1, &w[t - 7]);
        let a2 = b.add_mod(&a1, &s0);
        let wt = b.add_mod(&a2, &w[t - 16]);
        w.push(wt);
    }

    let mut s: Vec<Vec<usize>> = h_in.to_vec(); // a..h
    for (t, wt) in w.iter().enumerate().take(64) {
        let bs1 = c_bsig1(b, &s[4]);
        let chv = c_ch(b, &s[4], &s[5], &s[6]);
        let kt = b.word_const(K[t]);
        let x1 = b.add_mod(&s[7], &bs1);
        let x2 = b.add_mod(&x1, &chv);
        let x3 = b.add_mod(&x2, &kt);
        let t1 = b.add_mod(&x3, wt);
        let bs0 = c_bsig0(b, &s[0]);
        let mjv = c_maj(b, &s[0], &s[1], &s[2]);
        let t2 = b.add_mod(&bs0, &mjv);
        let e_new = b.add_mod(&s[3], &t1);
        let a_new = b.add_mod(&t1, &t2);
        s = vec![
            a_new,
            s[0].clone(),
            s[1].clone(),
            s[2].clone(),
            e_new,
            s[4].clone(),
            s[5].clone(),
            s[6].clone(),
        ];
    }
    (0..8).map(|i| b.add_mod(&h_in[i], &s[i])).collect()
}

fn xor_w(b: &mut Builder, x: &[usize], y: &[usize]) -> Vec<usize> {
    (0..32).map(|i| b.xor(x[i], y[i])).collect()
}
fn and_w(b: &mut Builder, x: &[usize], y: &[usize]) -> Vec<usize> {
    (0..32).map(|i| b.and(x[i], y[i])).collect()
}
fn not_w(b: &mut Builder, x: &[usize]) -> Vec<usize> {
    (0..32).map(|i| b.inv(x[i])).collect()
}
fn rotr(w: &[usize], n: usize) -> Vec<usize> {
    (0..32).map(|j| w[(j + n) % 32]).collect()
}
fn shr(b: &mut Builder, w: &[usize], n: usize) -> Vec<usize> {
    let z = b.zero();
    (0..32)
        .map(|j| if j + n < 32 { w[j + n] } else { z })
        .collect()
}
fn c_ch(b: &mut Builder, x: &[usize], y: &[usize], z: &[usize]) -> Vec<usize> {
    let xy = and_w(b, x, y);
    let nx = not_w(b, x);
    let nxz = and_w(b, &nx, z);
    xor_w(b, &xy, &nxz)
}
fn c_maj(b: &mut Builder, x: &[usize], y: &[usize], z: &[usize]) -> Vec<usize> {
    let xy = and_w(b, x, y);
    let xz = and_w(b, x, z);
    let yz = and_w(b, y, z);
    let t = xor_w(b, &xy, &xz);
    xor_w(b, &t, &yz)
}
fn c_bsig0(b: &mut Builder, x: &[usize]) -> Vec<usize> {
    let (a, c, d) = (rotr(x, 2), rotr(x, 13), rotr(x, 22));
    let t = xor_w(b, &a, &c);
    xor_w(b, &t, &d)
}
fn c_bsig1(b: &mut Builder, x: &[usize]) -> Vec<usize> {
    let (a, c, d) = (rotr(x, 6), rotr(x, 11), rotr(x, 25));
    let t = xor_w(b, &a, &c);
    xor_w(b, &t, &d)
}
fn c_ssig0(b: &mut Builder, x: &[usize]) -> Vec<usize> {
    let (a, c) = (rotr(x, 7), rotr(x, 18));
    let d = shr(b, x, 3);
    let t = xor_w(b, &a, &c);
    xor_w(b, &t, &d)
}
fn c_ssig1(b: &mut Builder, x: &[usize]) -> Vec<usize> {
    let (a, c) = (rotr(x, 17), rotr(x, 19));
    let d = shr(b, x, 10);
    let t = xor_w(b, &a, &c);
    xor_w(b, &t, &d)
}

// ---- key schedule under 2PC ------------------------------------------------

/// SHA-256 of a **secret-shared** 32-byte input, computed under 2PC. The two
/// parties hold XOR-shares `secret_a`, `secret_b` (`secret = a ⊕ b`); they come
/// away with XOR-shares of `SHA-256(secret)` — the secret and digest never
/// assembled at either party. This is a key derivation run inside the circuit.
pub fn digest_shared(secret_a: &[u8; 32], secret_b: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let circuit = digest_2pc_circuit();

    let mut inputs = vec![false; 768];
    write_be_words(&mut inputs[0..256], secret_a);
    write_be_words(&mut inputs[256..512], secret_b);
    let mut mask_bits = vec![false; 256];
    let mut mask_raw = [0u8; 32];
    getrandom::getrandom(&mut mask_raw).map_err(|e| Error::Rng(e.to_string()))?;
    for (i, bit) in mask_bits.iter_mut().enumerate() {
        *bit = (mask_raw[i / 8] >> (i % 8)) & 1 == 1;
    }
    inputs[512..768].copy_from_slice(&mask_bits);

    let evaluator_wires: HashSet<usize> = (256..512).collect(); // secret_b
    let out = garble::eval_2pc(&circuit, &evaluator_wires, &inputs)?; // digest ⊕ maskA

    Ok((bytes_from_be_words(&mask_bits), bytes_from_be_words(&out)))
}

/// Circuit: inputs `secretA[256] ‖ secretB[256] ‖ maskA[256]` (768); forms
/// `secret = secretA ⊕ secretB`, hashes the single padded block, outputs
/// `SHA-256(secret) ⊕ maskA`.
fn digest_2pc_circuit() -> Circuit {
    let mut b = Builder::new(768);
    let secret: Vec<usize> = (0..256).map(|i| b.xor(i, 256 + i)).collect();

    let mut block: Vec<Vec<usize>> = (0..8)
        .map(|w| secret[w * 32..w * 32 + 32].to_vec())
        .collect();
    // Public single-block padding for a 32-byte (256-bit) message.
    block.push(b.word_const(0x8000_0000)); // word 8: the 0x80 pad byte
    for _ in 9..15 {
        block.push(b.word_const(0)); // words 9..14
    }
    block.push(b.word_const(256)); // word 15: bit length = 256

    let h_in: Vec<Vec<usize>> = H0.iter().map(|&h| b.word_const(h)).collect();
    let digest = compress_circuit(&mut b, &h_in, &block);

    // XOR-mask the digest so the evaluator learns only digest ⊕ maskA.
    let outputs: Vec<usize> = digest
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(i, wire)| b.xor(wire, 512 + i))
        .collect();
    b.build(768, outputs)
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
        let word = bits[w * 32..w * 32 + 32]
            .iter()
            .enumerate()
            .fold(0u32, |acc, (j, &b)| acc | ((b as u32) << j));
        out[w * 4..w * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_reference_matches_nist_kats() {
        // NIST FIPS 180-4 examples.
        assert_eq!(
            sha256(b"abc"),
            hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            sha256(b""),
            hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex32("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
    }

    #[test]
    fn sha256_compression_circuit_matches_reference() {
        let circuit = sha256_compress_circuit();
        let block: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));

        let mut inputs = vec![false; 768];
        for (i, &h) in H0.iter().enumerate() {
            for j in 0..32 {
                inputs[i * 32 + j] = (h >> j) & 1 == 1;
            }
        }
        for w in 0..16 {
            let word = u32::from_be_bytes(block[w * 4..w * 4 + 4].try_into().unwrap());
            for j in 0..32 {
                inputs[256 + w * 32 + j] = (word >> j) & 1 == 1;
            }
        }
        let out = circuit.eval(&inputs);
        let got: Vec<u32> = (0..8)
            .map(|w| {
                out[w * 32..w * 32 + 32]
                    .iter()
                    .enumerate()
                    .fold(0u32, |a, (j, &b)| a | ((b as u32) << j))
            })
            .collect();
        assert_eq!(got, compress_ref(H0, &block).to_vec());
    }

    #[test]
    fn key_schedule_runs_under_2pc_into_shares() {
        let secret_a: [u8; 32] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(2));
        let secret_b: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x7c);

        let (share_a, share_b) = digest_shared(&secret_a, &secret_b).unwrap();

        // Combined shares == SHA-256(secret_a ⊕ secret_b) ...
        let secret: [u8; 32] = core::array::from_fn(|i| secret_a[i] ^ secret_b[i]);
        let combined: [u8; 32] = core::array::from_fn(|i| share_a[i] ^ share_b[i]);
        assert_eq!(combined, sha256(&secret));
        // ... and neither party's share alone is the derived key.
        assert_ne!(share_a, combined);
        assert_ne!(share_b, combined);
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
}
