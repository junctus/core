//! **IKNP oblivious-transfer extension**: turn a fixed `k = 128` base OTs
//! ([`ot`](super::ot), the expensive public-key part) into *arbitrarily many*
//! cheap OTs using only a correlation-robust hash and a PRG. This is what makes
//! garbling a large circuit (tens of thousands of evaluator-input OTs) practical
//! instead of one Diffie–Hellman per bit.
//!
//! Semi-honest IKNP03. The roles are **reversed** for the base OTs (the extension
//! receiver is the base *sender*), which is the trick that lets a single `s` mask
//! every extended OT. Modelled in-process as one function running the real base
//! OTs; the transport is the caller's.
//!
//! **Semi-honest only.** There is no receiver-consistency check, so a malicious
//! receiver that sends inconsistent `u` columns can leak bits of the sender's `s`
//! (a selective-failure channel). The maliciously-secure variant (a correlation
//! check / KOS-style consistency test) is the hardening step.

use neo_core::{Error, Result};

use super::ot;

/// Base-OT / security parameter.
pub const K: usize = 128;

/// Produce `m = choices.len()` 1-of-2 OTs of `L`-byte messages via IKNP over `K`
/// base OTs. `messages[i] = (m0, m1)` are the sender's messages; `choices[i]` the
/// receiver's bit. Returns the receiver's chosen messages `mᵢ[choicesᵢ]`.
pub fn extend(choices: &[bool], messages: &[([u8; 16], [u8; 16])]) -> Result<Vec<[u8; 16]>> {
    let m = choices.len();
    assert_eq!(messages.len(), m, "one message pair per OT");
    let col_bytes = m.div_ceil(8);

    // Extension-sender picks a secret selector s ∈ {0,1}^K.
    let s = random_bits(K)?;

    // Extension-receiver picks K seed pairs and expands each to an m-bit column.
    let mut seed0 = vec![[0u8; 16]; K];
    let mut seed1 = vec![[0u8; 16]; K];
    for j in 0..K {
        getrandom::getrandom(&mut seed0[j]).map_err(|e| Error::Rng(e.to_string()))?;
        getrandom::getrandom(&mut seed1[j]).map_err(|e| Error::Rng(e.to_string()))?;
    }
    let t0: Vec<Vec<u8>> = seed0.iter().map(|s| prg(s, col_bytes)).collect();
    let t1: Vec<Vec<u8>> = seed1.iter().map(|s| prg(s, col_bytes)).collect();

    // K base OTs, roles reversed: the extension-sender (choice sⱼ) learns seed_{sⱼ}ⱼ.
    let mut qseed = vec![[0u8; 16]; K];
    for j in 0..K {
        let setup = ot::sender_setup()?; // extension-receiver = base sender
        let rc = ot::receiver_choose(&setup.s, s[j])?; // extension-sender = base receiver
        let (e0, e1) = ot::sender_send(&setup, &rc.r, &seed0[j], &seed1[j]);
        qseed[j] = ot::receiver_finish(&rc, &setup.s, &e0, &e1);
    }

    // Receiver sends uⱼ = t0ⱼ ⊕ t1ⱼ ⊕ r (r = the choice vector).
    let r_bytes = bits_to_bytes(choices);
    let u: Vec<Vec<u8>> = (0..K)
        .map(|j| {
            (0..col_bytes)
                .map(|b| t0[j][b] ^ t1[j][b] ^ r_bytes[b])
                .collect()
        })
        .collect();

    // Sender forms column qⱼ = PRG(seed_{sⱼ}ⱼ) ⊕ (sⱼ · uⱼ); then per row qᵢ = tᵢ ⊕ rᵢ·s.
    let q: Vec<Vec<u8>> = (0..K)
        .map(|j| {
            let base = prg(&qseed[j], col_bytes);
            (0..col_bytes)
                .map(|b| base[b] ^ if s[j] { u[j][b] } else { 0 })
                .collect()
        })
        .collect();

    // Per OT i: sender masks (x0,x1) under H(i, qᵢ) and H(i, qᵢ⊕s); receiver
    // unmasks the one it chose under H(i, tᵢ) (which equals whichever it needs).
    let s_bytes = bits_to_bytes(&s);
    let mut out = Vec::with_capacity(m);
    for i in 0..m {
        let q_row = row(&q, i);
        let t_row = row(&t0, i);
        let q_xor_s: [u8; 16] = core::array::from_fn(|b| q_row[b] ^ s_bytes[b]);

        let y0 = xor16(&messages[i].0, &h(i, &q_row));
        let y1 = xor16(&messages[i].1, &h(i, &q_xor_s));

        let pad = h(i, &t_row);
        let chosen = if choices[i] { &y1 } else { &y0 };
        out.push(xor16(chosen, &pad));
    }
    Ok(out)
}

/// Extract row `i` (K bits → 16 bytes) from a set of K columns.
fn row(cols: &[Vec<u8>], i: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (j, col) in cols.iter().enumerate() {
        if (col[i / 8] >> (i % 8)) & 1 == 1 {
            out[j / 8] |= 1 << (j % 8);
        }
    }
    out
}

/// Correlation-robust hash `H(i, row)` → 16 bytes.
fn h(i: usize, row: &[u8; 16]) -> [u8; 16] {
    let mut hh = blake3::Hasher::new_derive_key("neo-iknp-v1");
    hh.update(&(i as u64).to_le_bytes());
    hh.update(row);
    let mut o = [0u8; 16];
    o.copy_from_slice(&hh.finalize().as_bytes()[..16]);
    o
}

/// PRG: expand a 16-byte seed to `nbytes` via BLAKE3 XOF.
fn prg(seed: &[u8; 16], nbytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; nbytes];
    blake3::Hasher::new_keyed(&pad32(seed))
        .finalize_xof()
        .fill(&mut out);
    out
}

fn pad32(seed: &[u8; 16]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(seed);
    k
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

fn random_bits(n: usize) -> Result<Vec<bool>> {
    let mut bytes = vec![0u8; n.div_ceil(8)];
    getrandom::getrandom(&mut bytes).map_err(|e| Error::Rng(e.to_string()))?;
    Ok((0..n).map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(seed: u8) -> ([u8; 16], [u8; 16]) {
        (
            core::array::from_fn(|i| seed.wrapping_add(i as u8)),
            core::array::from_fn(|i| seed.wrapping_mul(3).wrapping_add(i as u8)),
        )
    }

    #[test]
    fn extension_delivers_exactly_the_chosen_messages() {
        // More OTs than base OTs (m > K) — the point of extension.
        let m = 300;
        let choices: Vec<bool> = (0..m).map(|i| i % 3 == 0).collect();
        let messages: Vec<_> = (0..m).map(|i| msg(i as u8)).collect();

        let got = extend(&choices, &messages).unwrap();
        for i in 0..m {
            let want = if choices[i] {
                messages[i].1
            } else {
                messages[i].0
            };
            assert_eq!(got[i], want, "OT {i} must deliver the chosen message");
        }
    }

    #[test]
    fn works_for_a_single_and_small_batches() {
        for m in [1usize, 7, 128, 129] {
            let choices: Vec<bool> = (0..m).map(|i| i % 2 == 1).collect();
            let messages: Vec<_> = (0..m).map(|i| msg((i as u8) ^ 0xa5)).collect();
            let got = extend(&choices, &messages).unwrap();
            for i in 0..m {
                let want = if choices[i] {
                    messages[i].1
                } else {
                    messages[i].0
                };
                assert_eq!(got[i], want, "m={m} OT {i}");
            }
        }
    }
}
