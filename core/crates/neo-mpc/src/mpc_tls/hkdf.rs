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
use super::engine::{eval_circuit, EngineKind};
use super::sha256::{compress_circuit, hmac_key_state, sha256_from_block_state, H0};

/// `HMAC-SHA256(kA ⊕ kB, msg)` under 2PC: the key is XOR-shared (`kA` party A, `kB`
/// party B), `msg` is public. Returns XOR-shares `(outA, outB)` of the 32-byte tag,
/// so neither party learns the key or the tag. Semi-honest; see
/// [`hmac_sha256_shared_engine`] for the malicious online.
pub fn hmac_sha256_shared(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    msg: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    hmac_sha256_shared_engine(EngineKind::Semihonest, key_a, key_b, msg)
}

/// [`hmac_sha256_shared`] under a chosen 2PC [`EngineKind`] — the same masked circuit run
/// on the semi-honest garbler or the malicious authenticated-garbling online.
pub fn hmac_sha256_shared_engine(
    engine: EngineKind,
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
    let out = eval_circuit(engine, &circuit, &evaluator_wires, &inputs)?; // tag ⊕ maskA
    Ok((bytes_from_be_words(&mask_bits), bytes_from_be_words(&out)))
}

/// `HKDF-Expand-Label(secret, label, context, length)` under 2PC (RFC 8446 §7.1), for
/// `length ≤ 32`. The secret is XOR-shared; the label/context are public. Returns
/// XOR-shares of the 32-byte `HMAC-SHA256(secret, HkdfLabel ‖ 0x01)`; the first
/// `length` bytes are the derived key (each share truncated identically). Semi-honest;
/// see [`hkdf_expand_label_shared_engine`].
pub fn hkdf_expand_label_shared(
    secret_a: &[u8; 32],
    secret_b: &[u8; 32],
    label: &[u8],
    context: &[u8],
    length: u16,
) -> Result<([u8; 32], [u8; 32])> {
    hkdf_expand_label_shared_engine(
        EngineKind::Semihonest,
        secret_a,
        secret_b,
        label,
        context,
        length,
    )
}

/// [`hkdf_expand_label_shared`] under a chosen 2PC [`EngineKind`].
pub fn hkdf_expand_label_shared_engine(
    engine: EngineKind,
    secret_a: &[u8; 32],
    secret_b: &[u8; 32],
    label: &[u8],
    context: &[u8],
    length: u16,
) -> Result<([u8; 32], [u8; 32])> {
    let info = hkdf_label(label, context, length);
    let mut msg = info;
    msg.push(0x01); // HKDF-Expand T(1) counter
    hmac_sha256_shared_engine(engine, secret_a, secret_b, &msg)
}

/// `HKDF-Extract(salt, IKM)` under 2PC where the **salt is public** and the 32-byte
/// **IKM is XOR-shared** (`ikm_a` party A, `ikm_b` party B) — the mirror of
/// [`hmac_sha256_shared`], which shares the HMAC *key* rather than the message. This is
/// the one key-schedule step TLS 1.3 needs in this direction: the **Handshake Secret**
/// `= HKDF-Extract(Derived, (EC)DHE)`, where the salt `Derived` is public but the ECDHE
/// shared secret (the ECtF/A2B x-coordinate shares) is held between the two parties.
/// Returns XOR-shares of the 32-byte PRK, so neither party learns the ECDHE secret or
/// the resulting Handshake Secret.
pub fn hkdf_extract_shared(
    salt: &[u8; 32],
    ikm_a: &[u8; 32],
    ikm_b: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    hkdf_extract_shared_engine(EngineKind::Semihonest, salt, ikm_a, ikm_b)
}

/// [`hkdf_extract_shared`] under a chosen 2PC [`EngineKind`].
pub fn hkdf_extract_shared_engine(
    engine: EngineKind,
    salt: &[u8; 32],
    ikm_a: &[u8; 32],
    ikm_b: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    let circuit = hmac_pub_key_circuit(salt);

    // Layout: ikmA[256] ‖ ikmB[256] ‖ maskA[256] = 768 (mirrors hmac_sha256_shared).
    let mut inputs = vec![false; 768];
    write_be_words(&mut inputs[0..256], ikm_a);
    write_be_words(&mut inputs[256..512], ikm_b);
    let mut mask_bits = vec![false; 256];
    let mut mask_raw = [0u8; 32];
    getrandom::getrandom(&mut mask_raw).map_err(|e| Error::Rng(e.to_string()))?;
    for (i, bit) in mask_bits.iter_mut().enumerate() {
        *bit = (mask_raw[i / 8] >> (i % 8)) & 1 == 1;
    }
    inputs[512..768].copy_from_slice(&mask_bits);

    let evaluator_wires: HashSet<usize> = (256..512).collect(); // ikmB
    let out = eval_circuit(engine, &circuit, &evaluator_wires, &inputs)?; // PRK ⊕ maskA
    Ok((bytes_from_be_words(&mask_bits), bytes_from_be_words(&out)))
}

// ---- networked (two-party, over-the-wire) gadgets -----------------------------
//
// The over-the-wire counterparts of the `*_engine` gadgets above: instead of assembling
// both parties' shares in-process and calling `eval_circuit`, each party runs its side of
// the same masked circuit over a `Channel` via `netengine::masked_eval` (constant-round
// garbled online). Each returns **only this party's XOR-share** of the result. Validated
// against the stock key schedule over TCP in `live::netschedule`.

use super::live::channel::Channel;
use super::netengine::{masked_eval, Party};

/// Networked [`hmac_sha256_shared`]: `HMAC-SHA256(kA ⊕ kB, msg)` run as two parties over
/// `ch`. `key_share` is this party's share of the key; returns this party's share of the tag.
pub fn hmac_sha256_shared_net(
    ch: &mut dyn Channel,
    party: Party,
    key_share: &[u8; 32],
    msg: &[u8],
) -> Result<[u8; 32]> {
    let circuit = hmac_circuit(msg);
    let mut share = vec![false; 256];
    write_be_words(&mut share, key_share);
    Ok(bytes_from_be_words(&masked_eval(ch, party, &circuit, &share)?))
}

/// Networked [`hkdf_extract_shared`]: `HKDF-Extract(public salt, shared IKM)` over `ch`.
/// `ikm_share` is this party's share of the IKM; returns this party's share of the PRK.
pub fn hkdf_extract_shared_net(
    ch: &mut dyn Channel,
    party: Party,
    salt: &[u8; 32],
    ikm_share: &[u8; 32],
) -> Result<[u8; 32]> {
    let circuit = hmac_pub_key_circuit(salt);
    let mut share = vec![false; 256];
    write_be_words(&mut share, ikm_share);
    Ok(bytes_from_be_words(&masked_eval(ch, party, &circuit, &share)?))
}

/// Networked [`hkdf_expand_label_shared`]: `HKDF-Expand-Label(shared secret, public label,
/// public context, length)` over `ch`. Returns this party's share of the 32-byte output.
pub fn hkdf_expand_label_shared_net(
    ch: &mut dyn Channel,
    party: Party,
    secret_share: &[u8; 32],
    label: &[u8],
    context: &[u8],
    length: u16,
) -> Result<[u8; 32]> {
    let mut msg = hkdf_label(label, context, length);
    msg.push(0x01); // HKDF-Expand T(1) counter
    hmac_sha256_shared_net(ch, party, secret_share, &msg)
}

// ── HMAC key precomputation (DECO / Garble-then-Prove, eprint 2023/964) ──
//
// A key `K` used for several HMACs (TLS 1.3's `handshake_secret` keys 3 derivations,
// `master` keys 2, each `*_ap` keys its key+iv) recomputed `compress(H0, K⊕ipad)` and
// `compress(H0, K⊕opad)` every time. Precompute them ONCE per key, and — the DECO trick —
// **open the inner state** so the message-side inner hash finishes in the clear, leaving
// only the single outer compression under 2PC per HMAC. Net: ~4 garbled compressions per
// HMAC → ~1 (+2 one-time per key), the dominant key-schedule cost.

/// The two key-derived HMAC chaining states, precomputed once per key. The **inner** state
/// is **opened** (public): `ipad_state = compress(H0, K⊕ipad)` is a one-way image of `K`, so
/// revealing it leaks neither `K` nor any derived secret (each derived secret is
/// `compress(opad_state, inner)`, which still needs the secret outer state). The **outer**
/// state stays **secret-shared** — keeping `opad_state` split is exactly what keeps every
/// secret derived from `K` (down to the application traffic keys) split across the two
/// parties, so no single member can reconstruct it.
pub struct PreparedKey {
    /// `compress(H0, K⊕ipad)` — OPENED to both parties (public).
    ipad_state: [u8; 32],
    /// This party's XOR-share of `compress(H0, K⊕opad)` — NEVER opened.
    opad_state_share: [u8; 32],
}

/// Precompute a shared HMAC key's chaining states over `ch`: two garbled compressions
/// (`ipad_state`, `opad_state`) plus one open of the inner state. Reuse the result across
/// every HMAC under this key via [`hmac_prepared_net`] / [`expand_label_prepared_net`].
///
/// SECURITY: only `ipad_state` is opened; `opad_state` is returned as a share and must stay
/// shared (see [`PreparedKey`]).
pub fn prepare_key_net(
    ch: &mut dyn Channel,
    party: Party,
    key_share: &[u8; 32],
) -> Result<PreparedKey> {
    let mut share = vec![false; 256];
    write_be_words(&mut share, key_share);

    // ipad_state = compress(H0, K⊕ipad), then OPEN it (safe: one-way image of K).
    let ipad_share = bytes_from_be_words(&masked_eval(ch, party, &key_state_circuit(0x36), &share)?);
    let ipad_state = open_shared(ch, &ipad_share)?;

    // opad_state = compress(H0, K⊕opad), kept SHARED.
    let opad_state_share =
        bytes_from_be_words(&masked_eval(ch, party, &key_state_circuit(0x5c), &share)?);

    Ok(PreparedKey { ipad_state, opad_state_share })
}

/// `HMAC-SHA256(K, msg)` for a [`PreparedKey`] and a **public** `msg`: the inner hash
/// `H((K⊕ipad)‖msg)` finishes in the clear from the opened `ipad_state`, and only the single
/// outer compression `compress(opad_state, inner)` runs under 2PC. Returns this party's share
/// of the tag.
pub fn hmac_prepared_net(
    ch: &mut dyn Channel,
    party: Party,
    prepared: &PreparedKey,
    msg: &[u8],
) -> Result<[u8; 32]> {
    let inner = sha256_from_block_state(&prepared.ipad_state, msg); // cleartext inner hash
    let mut share = vec![false; 256];
    write_be_words(&mut share, &prepared.opad_state_share);
    Ok(bytes_from_be_words(&masked_eval(
        ch,
        party,
        &outer_from_opad_circuit(&inner),
        &share,
    )?))
}

/// `HKDF-Expand-Label` for a [`PreparedKey`] (the common case: same secret, many labels).
pub fn expand_label_prepared_net(
    ch: &mut dyn Channel,
    party: Party,
    prepared: &PreparedKey,
    label: &[u8],
    context: &[u8],
    length: u16,
) -> Result<[u8; 32]> {
    let mut msg = hkdf_label(label, context, length);
    msg.push(0x01); // HKDF-Expand T(1) counter
    hmac_prepared_net(ch, party, prepared, &msg)
}

/// XOR-open a 32-byte shared value (send our share, receive the peer's, combine).
fn open_shared(ch: &mut dyn Channel, share: &[u8; 32]) -> Result<[u8; 32]> {
    ch.send(share)?;
    let peer = ch.recv_exact(32)?;
    Ok(core::array::from_fn(|i| share[i] ^ peer[i]))
}

/// The public `HkdfLabel` struct: `uint16 length ‖ (len‖"tls13 "+label) ‖ (len‖context)`.
pub(crate) fn hkdf_label(label: &[u8], context: &[u8], length: u16) -> Vec<u8> {
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

/// Garble `compress(H0, K⊕pad_block)` — the key-dependent HMAC chaining state for `pad`
/// (`0x36` = ipad, `0x5c` = opad). Inputs `keyA[256] ‖ keyB[256] ‖ maskA[256]`, output the
/// 256-bit state ⊕ maskA. **One** compression (vs the 4 in a full [`hmac_circuit`]).
fn key_state_circuit(pad: u8) -> Circuit {
    let mut b = Builder::new(768);
    let key: Vec<Vec<usize>> = (0..8)
        .map(|w| (0..32).map(|j| b.xor(w * 32 + j, 256 + w * 32 + j)).collect())
        .collect();
    let h0: Vec<Vec<usize>> = H0.iter().map(|&h| b.word_const(h)).collect();
    let pad_block = key_pad_block(&mut b, &key, pad);
    let state = compress_circuit(&mut b, &h0, &pad_block);
    let outputs: Vec<usize> = state
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(i, wire)| b.xor(wire, 512 + i))
        .collect();
    b.build(768, outputs)
}

/// Garble the HMAC **outer** compression `compress(opad_state, inner‖pad)` for a PUBLIC
/// `inner` digest. Inputs `opadA[256] ‖ opadB[256] ‖ maskA[256]` (the shared opad state),
/// output the 256-bit HMAC tag ⊕ maskA. **One** compression; the inner hash is done in the
/// clear (see [`hmac_prepared_net`]).
fn outer_from_opad_circuit(inner: &[u8; 32]) -> Circuit {
    let mut b = Builder::new(768);
    let state: Vec<Vec<usize>> = (0..8)
        .map(|w| (0..32).map(|j| b.xor(w * 32 + j, 256 + w * 32 + j)).collect())
        .collect();
    // Final block = inner digest (public) ‖ 0x80 ‖ 0-pad ‖ bit length (64+32)*8 = 768.
    let mut inner_block = [0u8; 64];
    inner_block[..32].copy_from_slice(inner);
    let mut final_block: Vec<Vec<usize>> =
        (0..8).map(|w| b.word_const(be_word(&inner_block, w))).collect();
    final_block.push(b.word_const(0x8000_0000));
    for _ in 9..15 {
        final_block.push(b.word_const(0));
    }
    final_block.push(b.word_const((64 + 32) * 8));
    let ho = compress_circuit(&mut b, &state, &final_block);
    let outputs: Vec<usize> = ho
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(i, wire)| b.xor(wire, 512 + i))
        .collect();
    b.build(768, outputs)
}

/// HMAC-SHA256 with a **public** key and a **shared** 32-byte message (`HKDF-Extract`
/// direction): inputs `msgA[256] ‖ msgB[256] ‖ maskA[256]`, output `HMAC ⊕ maskA`
/// (256 bits). The key `K` (≤ 32 bytes, zero-padded to the 64-byte block) is baked in as
/// public constants; only the 32-byte message is shared, so both pad blocks
/// (`K⊕ipad`, `K⊕opad`) are public and the inner/outer message blocks carry the shares.
fn hmac_pub_key_circuit(key: &[u8; 32]) -> Circuit {
    // The key is PUBLIC, so both HMAC key-block chaining states are computed in the CLEAR and
    // baked in as constants — the circuit garbles only the two MESSAGE compressions (inner
    // over the shared msg, outer over the shared inner digest), not the two key-block ones.
    let ipad_state = hmac_key_state(key, 0x36);
    let opad_state = hmac_key_state(key, 0x5c);
    let state_words = |s: &[u8; 32], b: &mut Builder| -> Vec<Vec<usize>> {
        (0..8)
            .map(|w| b.word_const(u32::from_be_bytes(s[w * 4..w * 4 + 4].try_into().expect("4"))))
            .collect()
    };

    let mut b = Builder::new(768);
    // msg = msgA ⊕ msgB, 8 big-endian 32-bit words (one SHA-256 block of shared data).
    let msg: Vec<Vec<usize>> = (0..8)
        .map(|w| (0..32).map(|j| b.xor(w * 32 + j, 256 + w * 32 + j)).collect())
        .collect();

    // Inner: compress(ipad_state, msg ‖ pad) — ipad_state precomputed (public key).
    let ipad_cv = state_words(&ipad_state, &mut b);
    let mut inner_block: Vec<Vec<usize>> = msg;
    inner_block.push(b.word_const(0x8000_0000)); // 0x80 after the 32-byte message
    for _ in 9..15 {
        inner_block.push(b.word_const(0));
    }
    inner_block.push(b.word_const((64 + 32) * 8)); // bit length = 768
    let inner_digest = compress_circuit(&mut b, &ipad_cv, &inner_block);

    // Outer: compress(opad_state, inner_digest ‖ pad).
    let opad_cv = state_words(&opad_state, &mut b);
    let mut final_block: Vec<Vec<usize>> = inner_digest;
    final_block.push(b.word_const(0x8000_0000));
    for _ in 9..15 {
        final_block.push(b.word_const(0));
    }
    final_block.push(b.word_const((64 + 32) * 8));
    let ho = compress_circuit(&mut b, &opad_cv, &final_block);

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
    fn networked_hmac_over_constant_round_garbling_matches_stock() {
        // A real TLS key-schedule gadget (HMAC-SHA256) run as a **networked** 2PC over the
        // constant-round garbled online (`garble_net`), each party on its own TCP socket:
        // the garbler feeds keyA + its output mask, the evaluator feeds keyB and decodes
        // `HMAC ⊕ maskA`; combined they equal the stock HMAC. Proves the live-TLS gadgets
        // compose over the networked constant-round engine (a fixed 3 flights), not just a
        // toy circuit.
        use super::super::garble_net::{evaluator_run, garbler_run};
        use super::super::live::channel::TcpChannel;
        use std::collections::HashSet;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let key_a = [0x11u8; 32];
        let key_b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0xa5);
        let key = combine(&key_a, &key_b);
        let msg = b"tls13 c hs traffic\x00\x01";
        let circuit = hmac_circuit(msg);
        let ev: HashSet<usize> = (256..512).collect(); // keyB is the evaluator's

        // Garbler's output-mask share.
        let mask: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13) ^ 0x5a);
        let mut g_in = vec![false; 768];
        write_be_words(&mut g_in[0..256], &key_a);
        write_be_words(&mut g_in[512..768], &mask);
        let mut e_in = vec![false; 768];
        write_be_words(&mut e_in[256..512], &key_b);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (c_g, ev_g) = (circuit.clone(), ev.clone());
        let g = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            garbler_run(&mut ch, &c_g, &ev_g, &g_in).unwrap();
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let out = evaluator_run(&mut ch, &circuit, &ev, &e_in).unwrap(); // HMAC ⊕ maskA
        g.join().unwrap();

        let ev_share = bytes_from_be_words(&out);
        let tag: [u8; 32] = core::array::from_fn(|i| mask[i] ^ ev_share[i]);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(msg);
        assert_eq!(
            &tag[..],
            mac.finalize().into_bytes().as_slice(),
            "networked HMAC over the constant-round garbled online == stock HMAC"
        );
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

    #[test]
    fn prepared_key_expand_matches_rustcrypto_and_reuses() {
        // The DECO/Garble-then-Prove prepared-key path over two networked parties: prepare
        // ONCE (reveal ipad_state, keep opad_state shared), then several HKDF-Expand-Label
        // calls under the SAME key. Each combined output must equal the stock hkdf crate
        // byte-for-byte — validating the reveal-inner-state construction, the outer-only
        // gadget, and key reuse across labels.
        use super::super::live::channel::TcpChannel;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let secret_a: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(2));
        let secret_b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(9) ^ 0x3c);
        let secret = combine(&secret_a, &secret_b);
        let cases: Vec<(Vec<u8>, Vec<u8>, u16)> = vec![
            (b"c hs traffic".to_vec(), vec![0xab; 32], 32),
            (b"s hs traffic".to_vec(), vec![0xab; 32], 32),
            (b"derived".to_vec(), vec![], 32),
            (b"key".to_vec(), vec![], 16),
        ];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cases_a = cases.clone();
        let a = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            let pk = prepare_key_net(&mut ch, Party::A, &secret_a).unwrap();
            cases_a
                .iter()
                .map(|(l, c, n)| expand_label_prepared_net(&mut ch, Party::A, &pk, l, c, *n).unwrap())
                .collect::<Vec<_>>()
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let pk = prepare_key_net(&mut ch, Party::B, &secret_b).unwrap();
        let shares_b: Vec<[u8; 32]> = cases
            .iter()
            .map(|(l, c, n)| expand_label_prepared_net(&mut ch, Party::B, &pk, l, c, *n).unwrap())
            .collect();
        let shares_a = a.join().unwrap();

        for (i, (label, context, length)) in cases.iter().enumerate() {
            let got = combine(&shares_a[i], &shares_b[i]);
            let info = hkdf_label(label, context, *length);
            let hk = Hkdf::<Sha256>::from_prk(&secret).unwrap();
            let mut okm = vec![0u8; *length as usize];
            hk.expand(&info, &mut okm).unwrap();
            assert_eq!(
                &got[..*length as usize],
                &okm[..],
                "prepared HKDF-Expand-Label({}) matches stock",
                String::from_utf8_lossy(label)
            );
        }
    }

    #[test]
    fn hkdf_extract_under_2pc_matches_rustcrypto() {
        // The Handshake-Secret direction: HKDF-Extract(public salt, shared IKM) =
        // HMAC(key=salt, msg=IKM). The salt is public; the 32-byte IKM (the ECDHE shared
        // secret) is XOR-shared. Matched against the vetted `hkdf` crate's Extract.
        let salt: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(9));
        let ikm_a: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11));
        let ikm_b: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x3c);
        let ikm = combine(&ikm_a, &ikm_b);

        let (oa, ob) = hkdf_extract_shared(&salt, &ikm_a, &ikm_b).unwrap();
        let got = combine(&oa, &ob);

        let (prk, _) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(&got[..], prk.as_slice(), "HKDF-Extract under 2PC");
    }
}
