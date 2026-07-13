//! **KOS15 maliciously-secure OT extension** — the foundation the whole 2PC stack
//! is only as strong as. [`ot_ext`](super::ot_ext) is semi-honest IKNP: a cheating
//! *receiver* that sends inconsistent `u` columns opens a **selective-failure
//! channel** that leaks bits of the sender's secret `s`. KOS (Keller–Orsini–Scholl,
//! CRYPTO 2015) closes it with a **correlation check** over `GF(2^κ)` — for a
//! negligible extra cost, one round after the `u` columns. A receiver trying to leak
//! `t` bits of `s` via selective failure is caught except with probability `2^{−t}`,
//! so any non-trivial deviation aborts with overwhelming probability, and the only
//! residual is a bounded handful of `s`-bits that KOS's analysis shows is harmless
//! (so the check is not a deterministic catch of *every* single-bit deviation).
//!
//! # The check
//!
//! IKNP leaves the sender with rows `qᵢ = t0ᵢ ⊕ (rᵢ · s)` (`s ∈ {0,1}^κ` its base-OT
//! secret, `rᵢ` the receiver's choice bit, `t0ᵢ` the receiver's row). A cheating
//! receiver can instead force `qᵢ = t0ᵢ ⊕ (s ∧ dᵢ)` for an arbitrary per-column
//! deviation `dᵢ` — the leak. The check pins the receiver to a *consistent* `rᵢ`:
//!
//! 1. After `u` is sent, both derive random weights `χᵢ ∈ GF(2^κ)` bound to `u`
//!    (Fiat–Shamir, so the receiver cannot adapt `u` to the challenge).
//! 2. Receiver sends `x = Σ χᵢ·rᵢ` and `t = Σ χᵢ ⊗ t0ᵢ` (`⊗` = `GF(2^κ)` mult).
//! 3. Sender checks `Σ χᵢ ⊗ qᵢ  ==  t ⊕ (x ⊗ s)`.
//!
//! For an honest receiver `qᵢ ⊕ t0ᵢ = rᵢ·s`, so `Σχᵢ⊗qᵢ = t ⊕ (Σχᵢrᵢ)⊗s = t ⊕ x⊗s`
//! — it passes. A receiver whose `dᵢ ≠ rᵢ·1` cannot make the (field-nonlinear in `s`)
//! deviation look like the affine `x⊗s ⊕ t` for the sender's unknown `s`, except by
//! guessing bits of `s` — each guess risking abort. `κ+σ` extra rows with random
//! choices blind `(x, t)` so the check itself leaks nothing about the real `rᵢ`.
//!
//! # Honest boundary
//!
//! - This is the **maliciously-secure OT** the stack was missing: [`extend`] is a
//!   drop-in for [`ot_ext::extend`](super::ot_ext::extend) that **aborts on a cheating
//!   receiver** (tested). It closes the OT layer's malicious gap.
//! - It rests on the **semi-honest base OT** ([`ot`]) being run honestly; KOS's own
//!   proof assumes an ideal/committed base OT (`κ` of them, the cheap public-key
//!   part). The correlation-robust hash is BLAKE3, as elsewhere.
//! - [`extend`] models both parties **in-process** (as most of this crate). The
//!   **networked** two-party form is [`cot_sender`]/[`cot_receiver`]: the identical
//!   extension (base OTs, the `u` columns, the `(x, t)` check flight, the masked outputs)
//!   run over a [`Channel`](super::live::channel::Channel) with each party holding only
//!   its own secrets — the foundation of [`netprep`](super::netprep)'s networked
//!   authenticated bits, tested over real TCP incl. the cheating-receiver abort.
//! - **Roy22 caveat (for the audit):** this is the *original* KOS15 correlation check.
//!   Roy (SoftSpokenOT, CRYPTO 2022) found a **subtle gap** in KOS15's proof that stood
//!   for ~a decade; the fix is small and uses the same random-linear-combination idea.
//!   This module ships the pedagogically-standard KOS15 form (as in the reference it
//!   follows); an auditor should apply the Roy22 correction before production reliance.
//! - Correctness and cheating-receiver **detection** are what the tests establish;
//!   the formal malicious-OT guarantee is KOS's proof (with the Roy22 fix) + the audit.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use neo_core::{Error, Result};

use super::live::channel::Channel;
use super::ot;

/// Base-OT / security parameter (field width `κ = 128`).
pub const K: usize = 128;

/// Statistical parameter: extra random rows that blind the check's `(x, t)`.
const SIGMA: usize = 64;

/// `GF(2^128)` reduction: `x^128 ≡ x^7 + x^2 + x + 1` (the AES-GCM polynomial,
/// irreducible), low byte `0x87`.
const GF_REDUCE: u128 = 0x87;

/// Multiplication in `GF(2^128)` (poly `x^128 + x^7 + x^2 + x + 1`). Bit `i` of a
/// value is the coefficient of `x^i`; the field structure is what the check's
/// soundness rests on (a non-field product would let a cheater pass).
fn gf_mul(a: u128, mut b: u128) -> u128 {
    let mut a = a;
    let mut res = 0u128;
    for _ in 0..128 {
        if b & 1 == 1 {
            res ^= a;
        }
        b >>= 1;
        let overflow = a >> 127 == 1;
        a <<= 1;
        if overflow {
            a ^= GF_REDUCE;
        }
    }
    res
}

/// Maliciously-secure 1-of-2 OT extension: same interface as
/// [`ot_ext::extend`](super::ot_ext::extend) — `m` OTs of 16-byte messages, returns
/// the receiver's chosen messages — but runs the KOS correlation check and **returns
/// an error (abort) if the receiver deviated**.
pub fn extend(choices: &[bool], messages: &[([u8; 16], [u8; 16])]) -> Result<Vec<[u8; 16]>> {
    extend_core(choices, messages, |_u| {})
}

/// The extension body, with a `cheat` hook that may mutate the receiver's `u` columns
/// before the check — used by tests to model a malicious receiver.
fn extend_core(
    choices: &[bool],
    messages: &[([u8; 16], [u8; 16])],
    cheat: impl Fn(&mut [Vec<u8>]),
) -> Result<Vec<[u8; 16]>> {
    let m = choices.len();
    assert_eq!(messages.len(), m, "one message pair per OT");

    // Extend to ℓ = m + κ + σ rows; the last κ+σ carry random choices (check-only).
    let ell = m + K + SIGMA;
    let col_bytes = ell.div_ceil(8);

    // Receiver's choice column r: real for [0,m), random blinders for [m,ℓ).
    let mut r = choices.to_vec();
    r.extend(random_bits(K + SIGMA)?);

    // Sender's base-OT secret s ∈ {0,1}^κ.
    let s = random_bits(K)?;

    // Receiver's K seed pairs → the t0/t1 columns (ℓ bits each).
    let mut seed0 = vec![[0u8; 16]; K];
    let mut seed1 = vec![[0u8; 16]; K];
    for j in 0..K {
        getrandom::getrandom(&mut seed0[j]).map_err(|e| Error::Rng(e.to_string()))?;
        getrandom::getrandom(&mut seed1[j]).map_err(|e| Error::Rng(e.to_string()))?;
    }
    let t0: Vec<Vec<u8>> = seed0.iter().map(|s| prg(s, col_bytes)).collect();
    let t1: Vec<Vec<u8>> = seed1.iter().map(|s| prg(s, col_bytes)).collect();

    // K base OTs, roles reversed (extension-receiver is base sender): the
    // extension-sender (choice sⱼ) learns seed_{sⱼ}ⱼ.
    let mut qseed = vec![[0u8; 16]; K];
    for j in 0..K {
        let setup = ot::sender_setup()?;
        let rc = ot::receiver_choose(&setup.s, s[j])?;
        let (e0, e1) = ot::sender_send(&setup, &rc.r, &seed0[j], &seed1[j]);
        qseed[j] = ot::receiver_finish(&rc, &setup.s, &e0, &e1);
    }

    // Receiver sends uⱼ = t0ⱼ ⊕ t1ⱼ ⊕ r.
    let r_bytes = bits_to_bytes(&r);
    let mut u: Vec<Vec<u8>> = (0..K)
        .map(|j| {
            (0..col_bytes)
                .map(|b| t0[j][b] ^ t1[j][b] ^ r_bytes[b])
                .collect()
        })
        .collect();
    cheat(&mut u); // honest run: no-op; a malicious receiver deviates here.

    // Sender forms qⱼ = seed_{sⱼ}ⱼ ⊕ (sⱼ · uⱼ); row-wise qᵢ = t0ᵢ ⊕ rᵢ·s (honest).
    let q: Vec<Vec<u8>> = (0..K)
        .map(|j| {
            let base = prg(&qseed[j], col_bytes);
            (0..col_bytes)
                .map(|b| base[b] ^ if s[j] { u[j][b] } else { 0 })
                .collect()
        })
        .collect();

    // ── KOS correlation check over GF(2^128) ──
    let chi = derive_chi(&u, ell);
    // Receiver: x = Σ χᵢ·rᵢ, t = Σ χᵢ ⊗ t0ᵢ.
    let mut x = 0u128;
    let mut t_val = 0u128;
    for (i, &chi_i) in chi.iter().enumerate() {
        if r[i] {
            x ^= chi_i;
        }
        t_val ^= gf_mul(chi_i, row_u128(&t0, i));
    }
    // Sender: q_val = Σ χᵢ ⊗ qᵢ, check q_val == t ⊕ x⊗s.
    let mut q_val = 0u128;
    for (i, &chi_i) in chi.iter().enumerate() {
        q_val ^= gf_mul(chi_i, row_u128(&q, i));
    }
    let s_field = u128::from_be_bytes(bits_to_bytes16(&s));
    if q_val != t_val ^ gf_mul(x, s_field) {
        return Err(Error::Crypto(
            "KOS: correlation check failed — cheating receiver detected (abort)".into(),
        ));
    }

    // ── output OTs for the first m rows ──
    let s_bytes = bits_to_bytes16(&s);
    let mut out = Vec::with_capacity(m);
    for i in 0..m {
        let q_row = row16(&q, i);
        let t_row = row16(&t0, i);
        let q_xor_s: [u8; 16] = core::array::from_fn(|b| q_row[b] ^ s_bytes[b]);
        let y0 = xor16(&messages[i].0, &h(i, &q_row));
        let y1 = xor16(&messages[i].1, &h(i, &q_xor_s));
        let pad = h(i, &t_row);
        let chosen = if choices[i] { &y1 } else { &y0 };
        out.push(xor16(chosen, &pad));
    }
    Ok(out)
}

// ── Networked KOS-COT: the same extension as `extend`, but the two parties are
//    separate state machines exchanging messages over a `Channel`, each holding only its
//    own secrets (neither function sees both sides). `extend` above is the in-process
//    reference; these run the identical computation, split by role. Used to generate
//    authenticated bits (`super::netprep`) between two networked parties.

fn point_bytes(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

fn read_point(buf: &[u8]) -> Result<RistrettoPoint> {
    let c = CompressedRistretto::from_slice(buf)
        .map_err(|_| Error::Crypto("KOS-net: bad point length".into()))?;
    c.decompress()
        .ok_or_else(|| Error::Crypto("KOS-net: invalid Ristretto point".into()))
}

/// Networked KOS OT-extension — **receiver** role (holds the choice bits). Runs the
/// full extension (base OTs, `u` columns, GF(2^128) correlation check, output recovery)
/// over `ch`, returning the receiver's chosen messages. In a correlated OT (COT) for
/// authenticated bits, `choices` are the bits and the returned values are the MACs
/// `Mᵢ = Kᵢ ⊕ choiceᵢ·Δ`. Aborts if the sender signals a failed check.
pub fn cot_receiver(ch: &mut dyn Channel, choices: &[bool]) -> Result<Vec<[u8; 16]>> {
    cot_receiver_core(ch, choices, |_| {})
}

/// [`cot_receiver`] with a `cheat` hook that may tamper the `u` columns before they are
/// sent — used by tests to model a malicious receiver the sender's check must catch.
fn cot_receiver_core(
    ch: &mut dyn Channel,
    choices: &[bool],
    cheat: impl Fn(&mut [u8]),
) -> Result<Vec<[u8; 16]>> {
    let m = choices.len();
    let ell = m + K + SIGMA;
    let col_bytes = ell.div_ceil(8);

    // Choice column r: real for [0,m), random blinders for the check rows.
    let mut r = choices.to_vec();
    r.extend(random_bits(K + SIGMA)?);

    // K seed pairs → t0/t1 columns; the receiver is the base-OT *sender*.
    let mut seed0 = vec![[0u8; 16]; K];
    let mut seed1 = vec![[0u8; 16]; K];
    for j in 0..K {
        getrandom::getrandom(&mut seed0[j]).map_err(|e| Error::Rng(e.to_string()))?;
        getrandom::getrandom(&mut seed1[j]).map_err(|e| Error::Rng(e.to_string()))?;
    }
    let t0: Vec<Vec<u8>> = seed0.iter().map(|s| prg(s, col_bytes)).collect();
    let t1: Vec<Vec<u8>> = seed1.iter().map(|s| prg(s, col_bytes)).collect();

    // Base OTs: send K setup points, receive K response points, send K ciphertexts.
    let setups: Vec<ot::SenderSetup> = (0..K).map(|_| ot::sender_setup()).collect::<Result<_>>()?;
    let mut s_pts = Vec::with_capacity(K * 32);
    for st in &setups {
        s_pts.extend_from_slice(&point_bytes(&st.s));
    }
    ch.send(&s_pts)?; // [send1]

    let r_pts_raw = ch.recv_exact(K * 32)?; // [recv1]
    let mut e_bytes = Vec::with_capacity(K * 32);
    for j in 0..K {
        let r_pt = read_point(&r_pts_raw[j * 32..j * 32 + 32])?;
        let (e0, e1) = ot::sender_send(&setups[j], &r_pt, &seed0[j], &seed1[j]);
        e_bytes.extend_from_slice(&e0);
        e_bytes.extend_from_slice(&e1);
    }
    ch.send(&e_bytes)?; // [send2]

    // uⱼ = t0ⱼ ⊕ t1ⱼ ⊕ r; send all columns.
    let r_bytes = bits_to_bytes(&r);
    let u: Vec<Vec<u8>> = (0..K)
        .map(|j| {
            (0..col_bytes)
                .map(|b| t0[j][b] ^ t1[j][b] ^ r_bytes[b])
                .collect()
        })
        .collect();
    let mut u_flat = Vec::with_capacity(K * col_bytes);
    for col in &u {
        u_flat.extend_from_slice(col);
    }
    cheat(&mut u_flat); // honest run: no-op; a malicious receiver deviates here.
    ch.send(&u_flat)?; // [send3]

    // Both parties bind χ to the *sent* `u` (Fiat–Shamir); the receiver still opens its
    // HONEST (t0, r) below, so a cheater who altered `u` makes the sender's q inconsistent
    // and the check fails — the KOS malicious guarantee, now over the wire.
    let u_sent: Vec<Vec<u8>> = (0..K)
        .map(|j| u_flat[j * col_bytes..(j + 1) * col_bytes].to_vec())
        .collect();
    let chi = derive_chi(&u_sent, ell);
    let mut x = 0u128;
    let mut t_val = 0u128;
    for (i, &chi_i) in chi.iter().enumerate() {
        if r[i] {
            x ^= chi_i;
        }
        t_val ^= gf_mul(chi_i, row_u128(&t0, i));
    }
    let mut check = Vec::with_capacity(32);
    check.extend_from_slice(&x.to_be_bytes());
    check.extend_from_slice(&t_val.to_be_bytes());
    ch.send(&check)?; // [send4]

    // Sender's verdict, then the masked outputs.
    let status = ch.recv_exact(1)?; // [recv2]
    if status[0] != 1 {
        return Err(Error::Crypto(
            "KOS-net: sender reported correlation-check failure (abort)".into(),
        ));
    }
    let y = ch.recv_exact(m * 32)?; // [recv3]
    let mut out = Vec::with_capacity(m);
    for i in 0..m {
        let y0: [u8; 16] = y[i * 32..i * 32 + 16].try_into().expect("16");
        let y1: [u8; 16] = y[i * 32 + 16..i * 32 + 32].try_into().expect("16");
        let pad = h(i, &row16(&t0, i));
        let chosen = if choices[i] { &y1 } else { &y0 };
        out.push(xor16(chosen, &pad));
    }
    Ok(out)
}

/// Networked KOS OT-extension — **sender** role (holds the `messages` pairs). Runs the
/// extension over `ch` and, if the receiver's correlation check passes, delivers the
/// masked outputs; **returns an error (abort) if the check fails**. In a COT the caller
/// supplies `messages[i] = (Kᵢ, Kᵢ⊕Δ)` and keeps the `Kᵢ` as its per-bit keys — the
/// sender learns nothing new, so this returns `()` on success.
pub fn cot_sender(ch: &mut dyn Channel, messages: &[([u8; 16], [u8; 16])]) -> Result<()> {
    let m = messages.len();
    let ell = m + K + SIGMA;
    let col_bytes = ell.div_ceil(8);

    // Base-OT secret s; the sender is the base-OT *receiver* (choice sⱼ learns seed_{sⱼ}ⱼ).
    let s = random_bits(K)?;
    let s_pts_raw = ch.recv_exact(K * 32)?; // [recv1]
    let mut choices_rc = Vec::with_capacity(K);
    let mut r_pts = Vec::with_capacity(K * 32);
    let mut setup_s = Vec::with_capacity(K);
    for j in 0..K {
        let sp = read_point(&s_pts_raw[j * 32..j * 32 + 32])?;
        let rc = ot::receiver_choose(&sp, s[j])?;
        r_pts.extend_from_slice(&point_bytes(&rc.r));
        choices_rc.push(rc);
        setup_s.push(sp);
    }
    ch.send(&r_pts)?; // [send1]

    let e_raw = ch.recv_exact(K * 32)?; // [recv2]
    let mut qseed = vec![[0u8; 16]; K];
    for j in 0..K {
        let e0: [u8; 16] = e_raw[j * 32..j * 32 + 16].try_into().expect("16");
        let e1: [u8; 16] = e_raw[j * 32 + 16..j * 32 + 32].try_into().expect("16");
        qseed[j] = ot::receiver_finish(&choices_rc[j], &setup_s[j], &e0, &e1);
    }

    // Receive u; qⱼ = PRG(seed_{sⱼ}ⱼ) ⊕ (sⱼ · uⱼ).
    let u_flat = ch.recv_exact(K * col_bytes)?; // [recv3]
    let u: Vec<Vec<u8>> = (0..K)
        .map(|j| u_flat[j * col_bytes..(j + 1) * col_bytes].to_vec())
        .collect();
    let q: Vec<Vec<u8>> = (0..K)
        .map(|j| {
            let base = prg(&qseed[j], col_bytes);
            (0..col_bytes)
                .map(|b| base[b] ^ if s[j] { u[j][b] } else { 0 })
                .collect()
        })
        .collect();

    // Correlation check: q_val == t ⊕ x⊗s.
    let chi = derive_chi(&u, ell);
    let check = ch.recv_exact(32)?; // [recv4]
    let x = u128::from_be_bytes(check[0..16].try_into().expect("16"));
    let t_val = u128::from_be_bytes(check[16..32].try_into().expect("16"));
    let mut q_val = 0u128;
    for (i, &chi_i) in chi.iter().enumerate() {
        q_val ^= gf_mul(chi_i, row_u128(&q, i));
    }
    let s_field = u128::from_be_bytes(bits_to_bytes16(&s));
    if q_val != t_val ^ gf_mul(x, s_field) {
        let _ = ch.send(&[0u8]); // signal abort to the receiver (best-effort)
        return Err(Error::Crypto(
            "KOS-net: correlation check failed — cheating receiver detected (abort)".into(),
        ));
    }
    ch.send(&[1u8])?; // [send2] check passed

    // Masked outputs y0ᵢ = m0ᵢ ⊕ H(i, qᵢ), y1ᵢ = m1ᵢ ⊕ H(i, qᵢ⊕s).
    let s_bytes = bits_to_bytes16(&s);
    let mut y = Vec::with_capacity(m * 32);
    for (i, msg) in messages.iter().enumerate() {
        let q_row = row16(&q, i);
        let q_xor_s: [u8; 16] = core::array::from_fn(|b| q_row[b] ^ s_bytes[b]);
        y.extend_from_slice(&xor16(&msg.0, &h(i, &q_row)));
        y.extend_from_slice(&xor16(&msg.1, &h(i, &q_xor_s)));
    }
    ch.send(&y)?; // [send3]
    Ok(())
}

/// Fiat–Shamir weights `χᵢ ∈ GF(2^128)` bound to the committed `u` columns, so the
/// receiver cannot choose `u` after seeing the challenge.
fn derive_chi(u: &[Vec<u8>], ell: usize) -> Vec<u128> {
    let mut seed_h = blake3::Hasher::new_derive_key("neo-kos-chi-v1");
    for col in u {
        seed_h.update(col);
    }
    let seed = seed_h.finalize();
    (0..ell)
        .map(|i| {
            let mut hh = blake3::Hasher::new_keyed(seed.as_bytes());
            hh.update(&(i as u64).to_le_bytes());
            let mut b = [0u8; 16];
            b.copy_from_slice(&hh.finalize().as_bytes()[..16]);
            u128::from_be_bytes(b)
        })
        .collect()
}

/// Row `i` (K bits → 16 bytes) from K columns; bit `j` ← `cols[j]` bit `i`.
fn row16(cols: &[Vec<u8>], i: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (j, col) in cols.iter().enumerate() {
        if (col[i / 8] >> (i % 8)) & 1 == 1 {
            out[j / 8] |= 1 << (j % 8);
        }
    }
    out
}

fn row_u128(cols: &[Vec<u8>], i: usize) -> u128 {
    u128::from_be_bytes(row16(cols, i))
}

/// Correlation-robust hash `H(i, row)` → 16 bytes (matches the IKNP convention).
fn h(i: usize, row: &[u8; 16]) -> [u8; 16] {
    let mut hh = blake3::Hasher::new_derive_key("neo-iknp-v1");
    hh.update(&(i as u64).to_le_bytes());
    hh.update(row);
    let mut o = [0u8; 16];
    o.copy_from_slice(&hh.finalize().as_bytes()[..16]);
    o
}

fn prg(seed: &[u8; 16], nbytes: usize) -> Vec<u8> {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(seed);
    let mut out = vec![0u8; nbytes];
    blake3::Hasher::new_keyed(&k).finalize_xof().fill(&mut out);
    out
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

/// The K-bit `s` packed into exactly 16 bytes (bit `j` ← `s[j]`), matching [`row16`].
fn bits_to_bytes16(bits: &[bool]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (j, &b) in bits.iter().enumerate().take(K) {
        if b {
            out[j / 8] |= 1 << (j % 8);
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
    use super::super::live::channel::TcpChannel;
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn msg(seed: u8) -> ([u8; 16], [u8; 16]) {
        (
            core::array::from_fn(|i| seed.wrapping_add(i as u8)),
            core::array::from_fn(|i| seed.wrapping_mul(3).wrapping_add(i as u8)),
        )
    }

    /// Run a networked COT over a loopback TCP pair: sender (messages) on a thread,
    /// receiver (choices, possibly cheating) on this thread. Returns both results.
    fn run_net_cot(
        choices: Vec<bool>,
        messages: Vec<([u8; 16], [u8; 16])>,
        cheat: impl Fn(&mut [u8]),
    ) -> (Result<()>, Result<Vec<[u8; 16]>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sender = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            cot_sender(&mut ch, &messages)
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let recv = cot_receiver_core(&mut ch, &choices, cheat);
        (sender.join().unwrap(), recv)
    }

    #[test]
    fn cot_net_stress_never_false_aborts() {
        // Honest COT over TCP, many runs with large/varying m and fully random messages +
        // choices. The correlation check is EXACT for honest parties, so an honest run must
        // never abort — this reproduces intermittent aborts that only surface across the
        // ~100+ COT calls of a full handshake (not the handful in the small-cert tests).
        for iter in 0..200usize {
            let m = 200 + (iter * 41) % 500;
            let choices: Vec<bool> = (0..m)
                .map(|i| i.wrapping_mul(2_654_435_761).wrapping_add(iter) % 3 == 0)
                .collect();
            let messages: Vec<([u8; 16], [u8; 16])> = (0..m)
                .map(|_| {
                    let mut a = [0u8; 16];
                    let mut b = [0u8; 16];
                    getrandom::getrandom(&mut a).unwrap();
                    getrandom::getrandom(&mut b).unwrap();
                    (a, b)
                })
                .collect();
            let (send, recv) = run_net_cot(choices.clone(), messages.clone(), |_| {});
            assert!(
                send.is_ok(),
                "iter {iter} m={m}: honest sender aborted — false correlation-check failure"
            );
            let out = recv.expect("receiver");
            for i in 0..m {
                let want = if choices[i] { messages[i].1 } else { messages[i].0 };
                assert_eq!(out[i], want, "iter {iter} m={m} OT {i}");
            }
        }
    }

    #[test]
    fn networked_cot_matches_the_correlation_and_aborts_on_cheat() {
        // Honest run: the receiver's chosen outputs equal the sender's messages for the
        // chosen bits (this is exactly the COT correlation the aBit layer relies on).
        let choices = vec![true, false, true, true, false, false, true, false];
        let messages: Vec<([u8; 16], [u8; 16])> =
            (0..choices.len()).map(|i| msg(i as u8)).collect();

        let (send_res, recv_res) = run_net_cot(choices.clone(), messages.clone(), |_| {});
        send_res.expect("honest sender completes");
        let out = recv_res.expect("honest receiver completes");
        for (i, &c) in choices.iter().enumerate() {
            let want = if c { messages[i].1 } else { messages[i].0 };
            assert_eq!(out[i], want, "COT output {i} = chosen message");
        }

        // Cheating receiver (selective-failure): flip one row's bit across K/2 columns of
        // `u` before sending. Passing the check would need guessing K/2 = 64 bits of the
        // sender's secret s, so it aborts except w.p. ~2^-64 — the KOS malicious guarantee,
        // now enforced over the wire by the sender's GF(2^128) check.
        let col_bytes = (choices.len() + K + SIGMA).div_ceil(8);
        let row = 3usize;
        let cheat = move |u: &mut [u8]| {
            for j in 0..K / 2 {
                u[j * col_bytes + row / 8] ^= 1 << (row % 8);
            }
        };
        let (send_res, _recv_res) = run_net_cot(choices, messages, cheat);
        assert!(
            send_res.is_err(),
            "a tampered u must trip the KOS correlation check on the sender"
        );
    }

    #[test]
    fn gf_mul_is_a_field() {
        // Identity, commutativity, distributivity, associativity on sample values.
        let vals: [u128; 5] = [1, 2, 0x1234_5678_9abc_def0, u128::MAX, 0x87 << 100];
        for &a in &vals {
            assert_eq!(gf_mul(a, 1), a, "a·1 = a");
            assert_eq!(gf_mul(1, a), a, "1·a = a");
            assert_eq!(gf_mul(a, 0), 0, "a·0 = 0");
            for &b in &vals {
                assert_eq!(gf_mul(a, b), gf_mul(b, a), "commutative");
                for &c in &vals {
                    // distributive: a·(b⊕c) = a·b ⊕ a·c
                    assert_eq!(
                        gf_mul(a, b ^ c),
                        gf_mul(a, b) ^ gf_mul(a, c),
                        "distributive"
                    );
                    // associative: (a·b)·c = a·(b·c)
                    assert_eq!(
                        gf_mul(gf_mul(a, b), c),
                        gf_mul(a, gf_mul(b, c)),
                        "associative"
                    );
                }
            }
        }
    }

    #[test]
    fn honest_extension_delivers_the_chosen_messages() {
        // m > K, so this genuinely exercises extension and the ℓ = m+κ+σ padding.
        let m = 200;
        let choices: Vec<bool> = (0..m).map(|i| i % 3 == 0).collect();
        let messages: Vec<_> = (0..m).map(|i| msg(i as u8)).collect();
        let got = extend(&choices, &messages).unwrap();
        for i in 0..m {
            let want = if choices[i] {
                messages[i].1
            } else {
                messages[i].0
            };
            assert_eq!(got[i], want, "OT {i} delivers the chosen message");
        }
    }

    #[test]
    fn works_for_single_and_small_batches() {
        for m in [1usize, 7, 129] {
            let choices: Vec<bool> = (0..m).map(|i| i % 2 == 1).collect();
            let messages: Vec<_> = (0..m).map(|i| msg((i as u8) ^ 0x5a)).collect();
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

    #[test]
    fn a_cheating_receiver_is_caught_by_the_correlation_check() {
        // Selective-failure attack: for one row, use an *inconsistent* choice across
        // half the columns (flip u[j] at that row's bit). This forces the receiver to
        // guess K/2 = 64 bits of s to pass, so the check aborts except with
        // probability ~2^-64. (Flipping a *single* column would be only a 1-bit guess,
        // caught with probability 1/2 — KOS bounds leakage, it is not a per-bit
        // deterministic catch; that is why the attack spans many columns.)
        let m = 64;
        let messages: Vec<_> = (0..m).map(|i| msg(i as u8)).collect();
        for trial in 0..8 {
            let choices: Vec<bool> = (0..m).map(|i| (i + trial) % 2 == 0).collect();
            let row = 3 + trial; // some real row
            let res = extend_core(&choices, &messages, |u| {
                for uj in u.iter_mut().take(K / 2) {
                    uj[row / 8] ^= 1 << (row % 8); // inconsistent r on these columns
                }
            });
            assert!(
                res.is_err(),
                "trial {trial}: an inconsistent-choice receiver must be detected"
            );
        }
    }

    #[test]
    fn a_broadly_inconsistent_receiver_is_caught() {
        // A receiver that scrambles many (row, column) positions — a large deviation
        // — must abort with overwhelming probability.
        let m = 48;
        let messages: Vec<_> = (0..m).map(|i| msg(i as u8)).collect();
        let choices: Vec<bool> = (0..m).map(|i| i % 3 == 0).collect();
        let res = extend_core(&choices, &messages, |u| {
            // Flip a spread-out set of bits across half the columns and several rows.
            for (j, uj) in u.iter_mut().enumerate().take(K / 2) {
                let row = (j * 7 + 5) % m;
                uj[row / 8] ^= 1 << (row % 8);
            }
        });
        assert!(
            res.is_err(),
            "a broadly inconsistent receiver must be detected"
        );
    }
}
