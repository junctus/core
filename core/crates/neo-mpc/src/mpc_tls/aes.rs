//! **AES-128 as a boolean circuit** — the block cipher `TLS_AES_128_GCM_SHA256` needs,
//! built for evaluation under 2PC ([`garble`](super::garble) / [`authgarble`](super::authgarble)).
//!
//! The only nonlinear part of AES is the S-box, and the only nonlinear part of *that* is
//! the multiplicative inverse in `GF(2^8)`. We build it **correct-by-construction** rather
//! than transcribing a hand-optimised gate list: the inverse is `x^254` (Fermat, since
//! `x^255 = 1` for `x ≠ 0`, and `0^254 = 0` matches AES's `S(0)=0x63`), computed by
//! square-and-multiply from a schoolbook `GF(2^8)` multiplier ([`gf_mul`]) and a *linear*
//! squaring ([`gf_square`], zero AND gates). Everything else — ShiftRows, MixColumns
//! (`xtime`), AddRoundKey, the S-box affine map, key expansion — is `GF(2)`-linear (XOR/
//! NOT only). The result is validated **byte-for-byte against the vetted `aes` crate** on
//! the NIST FIPS-197 vector (see the tests).
//!
//! Bytes are 8 wires, **LSB-first** (`bit i` = coefficient of `x^i`). The circuit input is
//! `key[128] ‖ block[128]` (16 bytes each, byte `j` at wires `j·8 + i`); the output is the
//! 128-bit ciphertext in the same layout.
//!
//! # Honest boundary
//! - A **correct** AES-128 circuit (validated vs `aes`); ~larger than a hand-tuned S-box
//!   (Boyar–Peralta 32-AND) because it uses the algebraic inverse — an optimisation, not a
//!   correctness, gap. GCM (GHASH) assembly + a 2PC keystream gadget are the next step;
//!   `GF(2^128)` mult for GHASH already exists in [`kos`](super::kos).

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::{Builder, Circuit};
use super::engine::{eval_circuit, EngineKind};

/// A `GF(2^8)` element: 8 wires, LSB-first.
type Byte = [usize; 8];

/// Reduce a degree-≤14 polynomial `p` (15 coefficient wires) modulo the AES field
/// polynomial `m(x) = x^8 + x^4 + x^3 + x + 1` in place; afterwards `p[0..8]` is the
/// result. Purely linear: `x^k ≡ x^{k-4} + x^{k-5} + x^{k-7} + x^{k-8}` for `k ≥ 8`.
fn reduce(b: &mut Builder, p: &mut [usize]) {
    for k in (8..15).rev() {
        let hi = p[k];
        for &off in &[4usize, 5, 7, 8] {
            p[k - off] = b.xor(p[k - off], hi);
        }
    }
}

/// `GF(2^8)` multiply (schoolbook, 64 AND gates + linear reduction).
fn gf_mul(b: &mut Builder, x: &Byte, y: &Byte) -> Byte {
    let zero = b.zero();
    let mut p = vec![zero; 15];
    for i in 0..8 {
        for j in 0..8 {
            let and = b.and(x[i], y[j]);
            p[i + j] = b.xor(p[i + j], and);
        }
    }
    reduce(b, &mut p);
    core::array::from_fn(|i| p[i])
}

/// `GF(2^8)` squaring — **linear** (squaring spreads `a_i` to position `2i`, no AND gates).
fn gf_square(b: &mut Builder, x: &Byte) -> Byte {
    let zero = b.zero();
    let mut p = vec![zero; 15];
    for i in 0..8 {
        p[2 * i] = x[i];
    }
    reduce(b, &mut p);
    core::array::from_fn(|i| p[i])
}

/// Multiplicative inverse in `GF(2^8)` as `x^254` (and `0 ↦ 0`), by square-and-multiply:
/// `x^254 = x^2 · x^4 · x^8 · x^16 · x^32 · x^64 · x^128`.
fn gf_inverse(b: &mut Builder, x: &Byte) -> Byte {
    let mut power = gf_square(b, x); // x^2
    let mut acc = power; // accumulate x^2
    for _ in 0..6 {
        power = gf_square(b, &power); // x^4, x^8, …, x^128
        acc = gf_mul(b, &acc, &power);
    }
    acc
}

/// The AES S-box affine map over the inverse: `s_i = b_i ⊕ b_{i+4} ⊕ b_{i+5} ⊕ b_{i+6} ⊕
/// b_{i+7} ⊕ c_i` (indices mod 8), constant `c = 0x63`.
fn affine(b: &mut Builder, inv: &Byte) -> Byte {
    let one = b.one();
    let c = 0x63u8;
    core::array::from_fn(|i| {
        let mut acc = inv[i];
        for &d in &[4usize, 5, 6, 7] {
            acc = b.xor(acc, inv[(i + d) % 8]);
        }
        if (c >> i) & 1 == 1 {
            acc = b.xor(acc, one);
        }
        acc
    })
}

/// The AES S-box: `affine(inverse(x))`.
fn sbox(b: &mut Builder, x: &Byte) -> Byte {
    let inv = gf_inverse(b, x);
    affine(b, &inv)
}

/// `GF(2^8)` multiply-by-2 (`xtime`), linear:
/// `x·a = [a7, a0⊕a7, a1, a2⊕a7, a3⊕a7, a4, a5, a6]`.
fn xtime(b: &mut Builder, a: &Byte) -> Byte {
    [
        a[7],
        b.xor(a[0], a[7]),
        a[1],
        b.xor(a[2], a[7]),
        b.xor(a[3], a[7]),
        a[4],
        a[5],
        a[6],
    ]
}

fn xor_byte(b: &mut Builder, x: &Byte, y: &Byte) -> Byte {
    core::array::from_fn(|i| b.xor(x[i], y[i]))
}

/// A public constant byte as 8 constant wires (LSB-first).
fn const_byte(b: &mut Builder, v: u8) -> Byte {
    let one = b.one();
    let zero = b.zero();
    core::array::from_fn(|i| if (v >> i) & 1 == 1 { one } else { zero })
}

/// SubBytes on the 16-byte state.
fn sub_bytes(b: &mut Builder, s: &[Byte; 16]) -> [Byte; 16] {
    core::array::from_fn(|i| sbox(b, &s[i]))
}

/// ShiftRows: row `r` (bytes `r, r+4, r+8, r+12`) rotates left by `r` (column-major state).
fn shift_rows(s: &[Byte; 16]) -> [Byte; 16] {
    core::array::from_fn(|i| {
        let r = i % 4;
        let c = i / 4;
        s[r + 4 * ((c + r) % 4)]
    })
}

/// MixColumns: each column `[s0,s1,s2,s3] ↦ [2·s0⊕3·s1⊕s2⊕s3, …]`.
fn mix_columns(b: &mut Builder, s: &[Byte; 16]) -> [Byte; 16] {
    let mut out = *s;
    for c in 0..4 {
        let s0 = s[4 * c];
        let s1 = s[4 * c + 1];
        let s2 = s[4 * c + 2];
        let s3 = s[4 * c + 3];
        let (t0, t1, t2, t3) = (xtime(b, &s0), xtime(b, &s1), xtime(b, &s2), xtime(b, &s3));
        // 3·x = 2·x ⊕ x.
        let m3 = |b: &mut Builder, t: &Byte, x: &Byte| xor_byte(b, t, x);
        let (m3_1, m3_2, m3_3, m3_0) = (
            m3(b, &t1, &s1),
            m3(b, &t2, &s2),
            m3(b, &t3, &s3),
            m3(b, &t0, &s0),
        );
        // s0' = 2s0 ⊕ 3s1 ⊕ s2 ⊕ s3
        out[4 * c] = {
            let a = xor_byte(b, &t0, &m3_1);
            let a = xor_byte(b, &a, &s2);
            xor_byte(b, &a, &s3)
        };
        // s1' = s0 ⊕ 2s1 ⊕ 3s2 ⊕ s3
        out[4 * c + 1] = {
            let a = xor_byte(b, &s0, &t1);
            let a = xor_byte(b, &a, &m3_2);
            xor_byte(b, &a, &s3)
        };
        // s2' = s0 ⊕ s1 ⊕ 2s2 ⊕ 3s3
        out[4 * c + 2] = {
            let a = xor_byte(b, &s0, &s1);
            let a = xor_byte(b, &a, &t2);
            xor_byte(b, &a, &m3_3)
        };
        // s3' = 3s0 ⊕ s1 ⊕ s2 ⊕ 2s3
        out[4 * c + 3] = {
            let a = xor_byte(b, &m3_0, &s1);
            let a = xor_byte(b, &a, &s2);
            xor_byte(b, &a, &t3)
        };
    }
    out
}

fn add_round_key(b: &mut Builder, s: &[Byte; 16], k: &[Byte; 16]) -> [Byte; 16] {
    core::array::from_fn(|i| xor_byte(b, &s[i], &k[i]))
}

/// AES-128 key expansion: the 11 round keys (each 16 bytes) from the 16-byte key words.
fn key_expansion(b: &mut Builder, key: &[Byte; 16]) -> [[Byte; 16]; 11] {
    // 44 words of 4 bytes each; w[0..4] = the key.
    let mut w: Vec<[Byte; 4]> = (0..4)
        .map(|i| core::array::from_fn(|j| key[4 * i + j]))
        .collect();
    // Rcon[i] leading byte (i = 1..=10); the rest are zero.
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            // RotWord then SubWord then ⊕ Rcon.
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for byte in temp.iter_mut() {
                *byte = sbox(b, byte);
            }
            let rcon = const_byte(b, RCON[i / 4 - 1]);
            temp[0] = xor_byte(b, &temp[0], &rcon);
        }
        let prev = w[i - 4];
        w.push(core::array::from_fn(|j| xor_byte(b, &prev[j], &temp[j])));
    }
    // Round key r = words [4r..4r+4], flattened to 16 bytes.
    core::array::from_fn(|r| {
        let mut rk = [[0usize; 8]; 16];
        for word in 0..4 {
            for byte in 0..4 {
                rk[4 * word + byte] = w[4 * r + word][byte];
            }
        }
        rk
    })
}

/// Build the AES-128 encryption circuit: input `key[128] ‖ block[128]` (16 bytes each,
/// LSB-first per byte), output the 128-bit ciphertext (same layout). The key/block split
/// is a caller convention; a 2PC gadget XOR-shares the key across the two parties.
pub fn aes128_circuit() -> Circuit {
    let mut b = Builder::new(256);
    let key: [Byte; 16] = core::array::from_fn(|j| core::array::from_fn(|i| j * 8 + i));
    let block: [Byte; 16] = core::array::from_fn(|j| core::array::from_fn(|i| 128 + j * 8 + i));

    let round_keys = key_expansion(&mut b, &key);
    let mut s = add_round_key(&mut b, &block, &round_keys[0]);
    for rk in round_keys.iter().take(10).skip(1) {
        s = sub_bytes(&mut b, &s);
        s = shift_rows(&s);
        s = mix_columns(&mut b, &s);
        s = add_round_key(&mut b, &s, rk);
    }
    // Final round: no MixColumns.
    s = sub_bytes(&mut b, &s);
    s = shift_rows(&s);
    s = add_round_key(&mut b, &s, &round_keys[10]);

    let outputs: Vec<usize> = s.iter().flat_map(|byte| byte.iter().copied()).collect();
    b.build(256, outputs)
}

/// The masked 2PC AES-128 circuit: inputs `keyA[128] ‖ keyB[128] ‖ block[128] ‖ maskA[128]`
/// (512 wires); output `AES128(keyA⊕keyB, block) ⊕ maskA`. The key is XOR-shared, the block
/// (the CTR counter) public, and the mask the garbler's output share.
fn aes128_masked_circuit() -> Circuit {
    let mut b = Builder::new(512);
    let key: [Byte; 16] = core::array::from_fn(|j| {
        core::array::from_fn(|i| b.xor(j * 8 + i, 128 + j * 8 + i)) // keyA ⊕ keyB
    });
    let block: [Byte; 16] = core::array::from_fn(|j| core::array::from_fn(|i| 256 + j * 8 + i));

    let round_keys = key_expansion(&mut b, &key);
    let mut s = add_round_key(&mut b, &block, &round_keys[0]);
    for rk in round_keys.iter().take(10).skip(1) {
        s = sub_bytes(&mut b, &s);
        s = shift_rows(&s);
        s = mix_columns(&mut b, &s);
        s = add_round_key(&mut b, &s, rk);
    }
    s = sub_bytes(&mut b, &s);
    s = shift_rows(&s);
    s = add_round_key(&mut b, &s, &round_keys[10]);

    // Output ⊕ maskA (maskA at wires 384..512, byte j bit i → 384 + j·8 + i).
    let outputs: Vec<usize> = (0..16)
        .flat_map(|j| (0..8).map(move |i| (j, i)))
        .map(|(j, i)| b.xor(s[j][i], 384 + j * 8 + i))
        .collect();
    b.build(512, outputs)
}

fn bytes_to_bits(dst: &mut [bool], bytes: &[u8; 16]) {
    for (j, &v) in bytes.iter().enumerate() {
        for i in 0..8 {
            dst[j * 8 + i] = (v >> i) & 1 == 1;
        }
    }
}

fn bits_to_bytes(bits: &[bool]) -> [u8; 16] {
    core::array::from_fn(|j| {
        let mut v = 0u8;
        for i in 0..8 {
            if bits[j * 8 + i] {
                v |= 1 << i;
            }
        }
        v
    })
}

/// One AES-128 **CTR keystream block** under 2PC into XOR-shares: with the key XOR-shared
/// (`key_a`/`key_b`) and the 16-byte counter `block` public, the two parties come away with
/// XOR-shares of `AES128(key, block)` — neither learns the key or the keystream. This is
/// the AES-GCM counterpart of [`share_keystream`](super::session::share_keystream) (which
/// is ChaCha20). Semi-honest by default; see [`share_aes_keystream_engine`].
pub fn share_aes_keystream(
    key_a: &[u8; 16],
    key_b: &[u8; 16],
    block: &[u8; 16],
) -> Result<([u8; 16], [u8; 16])> {
    share_aes_keystream_engine(EngineKind::Semihonest, key_a, key_b, block)
}

/// [`share_aes_keystream`] under a chosen 2PC [`EngineKind`].
pub fn share_aes_keystream_engine(
    engine: EngineKind,
    key_a: &[u8; 16],
    key_b: &[u8; 16],
    block: &[u8; 16],
) -> Result<([u8; 16], [u8; 16])> {
    let circuit = aes128_masked_circuit();
    let mut inputs = vec![false; 512];
    bytes_to_bits(&mut inputs[0..128], key_a);
    bytes_to_bits(&mut inputs[128..256], key_b);
    bytes_to_bits(&mut inputs[256..384], block);
    let mut mask = [0u8; 16];
    getrandom::getrandom(&mut mask).map_err(|e| Error::Rng(e.to_string()))?;
    bytes_to_bits(&mut inputs[384..512], &mask);

    let evaluator_wires: HashSet<usize> = (128..256).collect(); // keyB
    let out = eval_circuit(engine, &circuit, &evaluator_wires, &inputs)?; // AES ⊕ maskA
    Ok((mask, bits_to_bytes(&out)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;

    /// Pack 16 key + 16 block bytes into the 256 input bits (LSB-first per byte).
    fn inputs(key: &[u8; 16], block: &[u8; 16]) -> Vec<bool> {
        let mut v = vec![false; 256];
        for (j, &kb) in key.iter().enumerate() {
            for i in 0..8 {
                v[j * 8 + i] = (kb >> i) & 1 == 1;
            }
        }
        for (j, &bb) in block.iter().enumerate() {
            for i in 0..8 {
                v[128 + j * 8 + i] = (bb >> i) & 1 == 1;
            }
        }
        v
    }

    fn circuit_encrypt(circuit: &Circuit, key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        let out = circuit.eval(&inputs(key, block));
        core::array::from_fn(|j| {
            let mut byte = 0u8;
            for i in 0..8 {
                if out[j * 8 + i] {
                    byte |= 1 << i;
                }
            }
            byte
        })
    }

    fn stock(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        let mut b = GenericArray::clone_from_slice(block);
        Aes128::new(GenericArray::from_slice(key)).encrypt_block(&mut b);
        b.into()
    }

    #[test]
    fn aes128_circuit_matches_stock_aes() {
        let circuit = aes128_circuit();
        // FIPS-197 §C.1 known-answer test.
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let block: [u8; 16] = core::array::from_fn(|i| (i as u8) * 0x11);
        let fips_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let fips_block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let fips_ct = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        assert_eq!(
            circuit_encrypt(&circuit, &fips_key, &fips_block),
            fips_ct,
            "AES-128 circuit vs FIPS-197 §C.1 known answer"
        );
        // A handful of arbitrary (key, block) pairs vs the stock `aes` crate.
        for t in 0..8u8 {
            let k: [u8; 16] =
                core::array::from_fn(|i| key[i].wrapping_mul(t.wrapping_add(1)) ^ i as u8);
            let m: [u8; 16] = core::array::from_fn(|i| block[i] ^ t ^ (i as u8) << 1);
            assert_eq!(
                circuit_encrypt(&circuit, &k, &m),
                stock(&k, &m),
                "AES-128 circuit vs stock aes (trial {t})"
            );
        }
        eprintln!("AES-128 circuit: {} AND gates", circuit.and_gates());
    }

    #[test]
    fn aes_keystream_under_2pc_matches_stock() {
        // The 2PC AES-CTR keystream: XOR-shares of AES128(key, counter) with the key split
        // across the two parties, validated against the stock aes crate (CTR keystream block
        // = AES-ECB of the counter). Neither party's share alone is the keystream.
        let key_a = [0x11u8; 16];
        let key_b: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0xa5);
        let key: [u8; 16] = core::array::from_fn(|i| key_a[i] ^ key_b[i]);
        let counter: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ 0x3c);

        let (sa, sb) = share_aes_keystream(&key_a, &key_b, &counter).unwrap();
        let ks: [u8; 16] = core::array::from_fn(|i| sa[i] ^ sb[i]);
        assert_eq!(
            ks,
            stock(&key, &counter),
            "2PC AES keystream == AES(key, counter)"
        );
        assert_ne!(sa, ks, "party A's share alone is not the keystream");
        assert_ne!(sb, ks, "party B's share alone is not the keystream");
    }
}
