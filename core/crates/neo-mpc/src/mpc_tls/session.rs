//! The 2PC-TLS **session**: it ties the primitives into the three properties that
//! make a TLS session "computed under MPC" with no single point of plaintext
//! assembly.
//!
//! 1. [`shared_ecdhe`] — a **DECO-style additively-shared ECDHE**: the two client
//!    parties end up holding additive shares `Z = Z₁ + Z₂` of the pre-master
//!    secret point, while the (unmodified) server computes the same `Z = s·X`.
//!    **Neither party learns `Z`.**
//! 2. [`share_keystream`] — the record **keystream computed under 2PC into
//!    XOR-shares**: the two parties hold XOR-shares of the ChaCha20 key, run the
//!    garbled [`chacha20_block_2pc`] circuit, and come away with XOR-shares of the
//!    keystream. **Neither learns the key or the keystream.**
//! 3. [`local_cipher_share`] / [`combine_ciphertext`] — the **record channel**:
//!    with the plaintext also XOR-shared, each party forms its ciphertext share
//!    locally and only their XOR — the real record ciphertext — is ever assembled.
//!    **Neither party ever holds the plaintext or the keystream.**
//!
//! Beyond these three, [`seal_record_shared`] composes ChaCha20 + a single-block
//! Poly1305 under 2PC, and [`seal_aead_shared`] the **full RFC 8439 ChaCha20-
//! Poly1305 AEAD** (multi-block Poly1305 over AAD + ciphertext + length block,
//! matched against the stock crate), which [`seal_tls13_record_shared`] frames into
//! a real **TLS 1.3 record**. The parties are modelled as in-process functions
//! running the real OT and garbling; the network transport is the caller's. See the
//! parent module for the honest boundary (full malicious security, EC point-share
//! conversion, live server).

use std::collections::HashSet;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::Scalar;
use neo_core::{Error, Result};

use super::circuit::{chacha20_block_2pc, chacha20_output_bytes};
use super::engine::{eval_circuit, EngineKind};
use super::garble_net::{evaluator_run, garbler_run};
use super::live::channel::Channel;
use super::netengine::Party;
use super::poly1305;

/// Additive shares of the ECDHE pre-master point: `Z = share1 + share2`.
pub struct PreMasterShares {
    /// Client party 1's share `Z₁ = x₁·Y`.
    pub share1: RistrettoPoint,
    /// Client party 2's share `Z₂ = x₂·Y`.
    pub share2: RistrettoPoint,
}

impl PreMasterShares {
    /// The reconstructed pre-master `Z = Z₁ + Z₂` (used only to *check* against
    /// the server; neither party forms this in the protocol).
    pub fn combined(&self) -> RistrettoPoint {
        self.share1 + self.share2
    }
}

/// Run a DECO-style two-party ECDHE against a server whose ephemeral secret is
/// `server_secret` (public `Y = server_secret·G`). Returns the client ephemeral
/// `X = (x₁+x₂)·G` that is sent to the server, the server's computed pre-master
/// `Z = server_secret·X`, and the two client parties' additive shares of `Z`.
///
/// Neither client party knows `Z`: party *i* holds only `Zᵢ = xᵢ·Y`.
///
/// **Modelling note:** this is a self-contained *simulation* of the two client
/// parties and the server — the server's secret is supplied locally to check the
/// share math — not a live handshake against a remote server on its real curve.
pub fn shared_ecdhe(
    server_secret: &Scalar,
) -> Result<(RistrettoPoint, RistrettoPoint, PreMasterShares)> {
    let y = G * server_secret; // the server's (ephemeral) public key
    let x1 = random_scalar()?;
    let x2 = random_scalar()?;
    let x_pub = G * x1 + G * x2; // client ephemeral X = (x1+x2)·G, sent to the server
    let z_server = x_pub * server_secret; // server side: Z = s·X
    let shares = PreMasterShares {
        share1: y * x1, // x1·Y = s·x1·G
        share2: y * x2, // x2·Y = s·x2·G
    };
    Ok((x_pub, z_server, shares))
}

/// XOR-shares of a 64-byte ChaCha20 keystream block: `KS = share_a ⊕ share_b`.
pub struct KeystreamShares {
    /// The garbler party's share (its output mask).
    pub share_a: [u8; 64],
    /// The evaluator party's share (`KS ⊕ share_a`).
    pub share_b: [u8; 64],
}

impl KeystreamShares {
    /// The reconstructed keystream `KS = share_a ⊕ share_b` (used only to check;
    /// neither party forms this in the protocol).
    pub fn combined(&self) -> [u8; 64] {
        core::array::from_fn(|i| self.share_a[i] ^ self.share_b[i])
    }
}

/// Two client parties holding XOR-shares `key_a`, `key_b` of the ChaCha20 key
/// (`key = key_a ⊕ key_b`) compute XOR-shares of the keystream block for
/// `(counter, nonce)` **under 2PC** — neither party ever learns the key or the
/// keystream. `counter`/`nonce` are public record-layer values.
pub fn share_keystream(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
) -> Result<KeystreamShares> {
    share_keystream_engine(EngineKind::Semihonest, key_a, key_b, counter, nonce)
}

/// [`share_keystream`] under a chosen 2PC [`EngineKind`] (semi-honest garbler or the
/// malicious authenticated-garbling online).
pub fn share_keystream_engine(
    engine: EngineKind,
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
) -> Result<KeystreamShares> {
    let circuit = chacha20_block_2pc();

    // Garbler owns keyA, counter, nonce, and a random output mask; the evaluator
    // owns keyB (fetched via OT). Wire layout: keyA[0..256], keyB[256..512],
    // counter[512..544], nonce[544..640], maskA[640..1152].
    let mut mask_bits = vec![false; 512];
    let mut mask_raw = [0u8; 64];
    getrandom::getrandom(&mut mask_raw).map_err(|e| Error::Rng(e.to_string()))?;
    for (i, bit) in mask_bits.iter_mut().enumerate() {
        *bit = (mask_raw[i / 8] >> (i % 8)) & 1 == 1;
    }

    let mut inputs = vec![false; 1152];
    write_key_bits(&mut inputs[0..256], key_a);
    write_key_bits(&mut inputs[256..512], key_b);
    write_word_bits(&mut inputs[512..544], counter);
    for k in 0..3 {
        let w = u32::from_le_bytes(nonce[k * 4..k * 4 + 4].try_into().expect("4 bytes"));
        write_word_bits(&mut inputs[544 + k * 32..544 + k * 32 + 32], w);
    }
    inputs[640..1152].copy_from_slice(&mask_bits);

    let evaluator_wires: HashSet<usize> = (256..512).collect(); // keyB
    let out_bits = eval_circuit(engine, &circuit, &evaluator_wires, &inputs)?; // = KS ⊕ maskA

    Ok(KeystreamShares {
        share_a: chacha20_output_bytes(&mask_bits), // maskA
        share_b: chacha20_output_bytes(&out_bits),  // KS ⊕ maskA
    })
}

/// A party's local ciphertext share: `plaintext_share ⊕ keystream_share`. XOR of
/// both parties' shares is the real record ciphertext `C = P ⊕ KS` (see
/// [`combine_ciphertext`]) — and neither party ever holds `P` or `KS`.
pub fn local_cipher_share(plaintext_share: &[u8], keystream_share: &[u8]) -> Vec<u8> {
    xor_bytes(plaintext_share, keystream_share)
}

/// Combine the two parties' ciphertext shares into the record ciphertext. This is
/// the only value ever assembled at one place — and it is ciphertext, not
/// plaintext.
pub fn combine_ciphertext(share1: &[u8], share2: &[u8]) -> Vec<u8> {
    xor_bytes(share1, share2)
}

/// **End-to-end**: seal a 16-byte `plaintext` (XOR-shared as `pt_a ⊕ pt_b`) as a
/// **ChaCha20-Poly1305 record, entirely under 2PC**. The two parties, holding
/// only XOR-shares of the traffic key, derive the Poly1305 one-time key from
/// keystream block 0, encrypt with block 1, and MAC the ciphertext — every
/// non-linear step inside the garbled circuit — so **neither ever holds the key,
/// the keystream, or the plaintext**. Returns the public record `(ciphertext, tag)`.
///
/// **Not the RFC 8439 AEAD tag.** The tag here is a single-block Poly1305 over the
/// bare 16-byte ciphertext; it verifies against a stock **Poly1305**, not a stock
/// ChaCha20-Poly1305 AEAD. For the full AEAD (AAD + multi-block ciphertext + length
/// block, matched against the stock crate) use [`seal_aead_shared`]; this simpler
/// form is kept for the single-block record path.
pub fn seal_record_shared(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    nonce: &[u8; 12],
    pt_a: &[u8; 16],
    pt_b: &[u8; 16],
) -> Result<([u8; 16], [u8; 16])> {
    // Poly1305 one-time key = keystream block 0, first 32 bytes (kept in shares).
    let ks0 = share_keystream(key_a, key_b, 0, nonce)?;
    let poly_a: [u8; 32] = ks0.share_a[..32].try_into().expect("32 bytes");
    let poly_b: [u8; 32] = ks0.share_b[..32].try_into().expect("32 bytes");

    // Encrypt under keystream block 1; only the ciphertext is ever assembled.
    let ks1 = share_keystream(key_a, key_b, 1, nonce)?;
    let ct_a: [u8; 16] = core::array::from_fn(|i| pt_a[i] ^ ks1.share_a[i]);
    let ct_b: [u8; 16] = core::array::from_fn(|i| pt_b[i] ^ ks1.share_b[i]);
    let ciphertext: [u8; 16] = core::array::from_fn(|i| ct_a[i] ^ ct_b[i]);

    // MAC the (public) ciphertext under the shared one-time key, under 2PC.
    let (tag_a, tag_b) = poly1305::tag_shared(&poly_a, &poly_b, &ciphertext, &[0u8; 16])?;
    let tag: [u8; 16] = core::array::from_fn(|i| tag_a[i] ^ tag_b[i]);
    Ok((ciphertext, tag))
}

/// The **full RFC 8439 ChaCha20-Poly1305 AEAD** under 2PC — the record-framing step
/// [`seal_record_shared`] deferred. Encrypts a variable-length plaintext (XOR-shared
/// between the two parties) under ChaCha20 (the Poly1305 one-time key from counter 0,
/// encryption from counters 1, 2, …), then authenticates the RFC message
/// `AAD ‖ pad ‖ CT ‖ pad ‖ len(AAD) ‖ len(CT)` with **multi-block Poly1305** under
/// 2PC — so neither party ever holds the key, the keystream, or the plaintext.
/// Returns the public `(ciphertext, tag)`.
///
/// Unlike [`seal_record_shared`] (single-block Poly1305 of the bare ciphertext), this
/// verifies against a **stock ChaCha20-Poly1305 AEAD**. It is **semi-honest**: a
/// cheating garbler is not yet caught here (that is authenticated garbling, WRK17).
pub fn seal_aead_shared(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt_a: &[u8],
    pt_b: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    seal_aead_shared_engine(EngineKind::Semihonest, key_a, key_b, nonce, aad, pt_a, pt_b)
}

/// [`seal_aead_shared`] under a chosen 2PC [`EngineKind`]. `Malicious` routes every
/// keystream + Poly1305 circuit through the authenticated-garbling online (aborts on a
/// cheating party).
#[allow(clippy::too_many_arguments)]
pub fn seal_aead_shared_engine(
    engine: EngineKind,
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt_a: &[u8],
    pt_b: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    if pt_a.len() != pt_b.len() {
        return Err(Error::Crypto("plaintext shares differ in length".into()));
    }
    let ptlen = pt_a.len();

    // Poly1305 one-time key = keystream block 0, first 32 bytes (kept in shares).
    let ks0 = share_keystream_engine(engine, key_a, key_b, 0, nonce)?;
    let poly_a: [u8; 32] = ks0.share_a[..32].try_into().expect("32 bytes");
    let poly_b: [u8; 32] = ks0.share_b[..32].try_into().expect("32 bytes");

    // Encrypt under keystream blocks 1, 2, … (64 bytes each); only the ciphertext is
    // ever assembled from the two shares.
    let mut ct_a = vec![0u8; ptlen];
    let mut ct_b = vec![0u8; ptlen];
    for j in 0..ptlen.div_ceil(64) {
        let ks = share_keystream_engine(engine, key_a, key_b, 1 + j as u32, nonce)?;
        let off = j * 64;
        let end = (off + 64).min(ptlen);
        for i in off..end {
            ct_a[i] = pt_a[i] ^ ks.share_a[i - off];
            ct_b[i] = pt_b[i] ^ ks.share_b[i - off];
        }
    }
    let ciphertext: Vec<u8> = ct_a.iter().zip(&ct_b).map(|(a, b)| a ^ b).collect();

    // Public Poly1305 message: AAD ‖ pad16 ‖ CT ‖ pad16 ‖ len(AAD) LE ‖ len(CT) LE.
    let mut mac_data = Vec::new();
    mac_data.extend_from_slice(aad);
    while mac_data.len() % 16 != 0 {
        mac_data.push(0);
    }
    mac_data.extend_from_slice(&ciphertext);
    while mac_data.len() % 16 != 0 {
        mac_data.push(0);
    }
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    let blocks: Vec<[u8; 16]> = mac_data
        .chunks(16)
        .map(|c| {
            let mut b = [0u8; 16];
            b[..c.len()].copy_from_slice(c);
            b
        })
        .collect();

    let (tag_a, tag_b) = poly1305::tag_shared_multi_engine(engine, &poly_a, &poly_b, &blocks)?;
    let tag: [u8; 16] = core::array::from_fn(|i| tag_a[i] ^ tag_b[i]);
    Ok((ciphertext, tag))
}

// ---- networked (two-party, over-the-wire) record layer ------------------------------
//
// The over-the-wire counterparts of `share_keystream_engine` / `seal_aead_shared_engine`:
// each party runs its side of the ChaCha20 keystream + Poly1305 gadgets over a `Channel`
// via the constant-round garbled online, exchanging only the **public** ciphertext and tag
// (never the key, keystream, or plaintext). Validated against the stock ChaCha20-Poly1305
// AEAD over TCP (see the tests).

/// Networked [`share_keystream`]: this party's XOR-share of the 64-byte ChaCha20 keystream
/// block for the public `(counter, nonce)`. `key_share` is this party's share of the key.
pub fn share_keystream_net(
    ch: &mut dyn Channel,
    party: Party,
    key_share: &[u8; 32],
    counter: u32,
    nonce: &[u8; 12],
) -> Result<[u8; 64]> {
    let circuit = chacha20_block_2pc();
    let ev: HashSet<usize> = (256..512).collect(); // keyB
    match party {
        Party::A => {
            // Garbler owns keyA, the public counter/nonce, and a random output mask.
            let mut mask_bits = vec![false; 512];
            let mut mask_raw = [0u8; 64];
            getrandom::getrandom(&mut mask_raw).map_err(|e| Error::Rng(e.to_string()))?;
            for (i, bit) in mask_bits.iter_mut().enumerate() {
                *bit = (mask_raw[i / 8] >> (i % 8)) & 1 == 1;
            }
            let mut g = vec![false; 1152];
            write_key_bits(&mut g[0..256], key_share);
            write_word_bits(&mut g[512..544], counter);
            for k in 0..3 {
                let w = u32::from_le_bytes(nonce[k * 4..k * 4 + 4].try_into().expect("4 bytes"));
                write_word_bits(&mut g[544 + k * 32..544 + k * 32 + 32], w);
            }
            g[640..1152].copy_from_slice(&mask_bits);
            garbler_run(ch, &circuit, &ev, &g)?;
            Ok(chacha20_output_bytes(&mask_bits)) // share_a = maskA
        }
        Party::B => {
            let mut e = vec![false; 1152];
            write_key_bits(&mut e[256..512], key_share);
            let out = evaluator_run(ch, &circuit, &ev, &e)?; // KS ⊕ maskA
            Ok(chacha20_output_bytes(&out))
        }
    }
}

/// Send this party's byte-share, receive the peer's, and XOR — opening a value that is
/// **public** in the protocol (the record ciphertext, or the tag). Symmetric: both parties
/// call it with equal-length inputs.
fn open_shared_bytes(ch: &mut dyn Channel, mine: &[u8]) -> Result<Vec<u8>> {
    ch.send(mine)?;
    let peer = ch.recv_exact(mine.len())?;
    Ok(mine.iter().zip(&peer).map(|(a, b)| a ^ b).collect())
}

/// The public Poly1305 message for RFC 8439: `AAD ‖ pad16 ‖ CT ‖ pad16 ‖ len(AAD) ‖ len(CT)`,
/// as 16-byte blocks.
fn poly_message_blocks(aad: &[u8], ciphertext: &[u8]) -> Vec<[u8; 16]> {
    let mut data = Vec::new();
    data.extend_from_slice(aad);
    while data.len() % 16 != 0 {
        data.push(0);
    }
    data.extend_from_slice(ciphertext);
    while data.len() % 16 != 0 {
        data.push(0);
    }
    data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    data.chunks(16)
        .map(|c| {
            let mut b = [0u8; 16];
            b[..c.len()].copy_from_slice(c);
            b
        })
        .collect()
}

/// **Networked [`seal_aead_shared`]** — the full RFC 8439 ChaCha20-Poly1305 AEAD run as two
/// parties over `ch`. `pt_share` is this party's XOR-share of the plaintext; `aad`/`nonce`
/// are public. Returns the public `(ciphertext, tag)` — identical on both parties. Neither
/// party ever holds the key, the keystream, or the plaintext.
pub fn seal_aead_net(
    ch: &mut dyn Channel,
    party: Party,
    key_share: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt_share: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    let ptlen = pt_share.len();
    // Poly1305 one-time key = keystream block 0, first 32 bytes (kept in shares).
    let ks0 = share_keystream_net(ch, party, key_share, 0, nonce)?;
    let poly_share: [u8; 32] = ks0[..32].try_into().expect("32 bytes");

    // Encrypt under blocks 1, 2, … — each party holds only its ciphertext share.
    let mut ct_share = vec![0u8; ptlen];
    for j in 0..ptlen.div_ceil(64) {
        let ks = share_keystream_net(ch, party, key_share, 1 + j as u32, nonce)?;
        let off = j * 64;
        let end = (off + 64).min(ptlen);
        for i in off..end {
            ct_share[i] = pt_share[i] ^ ks[i - off];
        }
    }
    // Open the (public) ciphertext, then MAC it under the shared one-time key over `ch`.
    let ciphertext = open_shared_bytes(ch, &ct_share)?;
    let blocks = poly_message_blocks(aad, &ciphertext);
    let tag_share = poly1305::tag_shared_multi_net(ch, party, &poly_share, &blocks)?;
    let tag: [u8; 16] = open_shared_bytes(ch, &tag_share)?
        .try_into()
        .expect("16-byte tag");
    Ok((ciphertext, tag))
}

/// **Networked AEAD open/decrypt** — verify the tag and decrypt over `ch`. Given the public
/// `ciphertext`/`tag`/`aad`/`nonce`, returns this party's XOR-share of the plaintext (the
/// plaintext stays shared) and whether the tag verified. Neither party holds the key or
/// keystream; the plaintext is never assembled at one place.
pub fn open_aead_net(
    ch: &mut dyn Channel,
    party: Party,
    key_share: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<(Vec<u8>, bool)> {
    let ks0 = share_keystream_net(ch, party, key_share, 0, nonce)?;
    let poly_share: [u8; 32] = ks0[..32].try_into().expect("32 bytes");

    // Recompute + open the tag, compare (constant-time) to the received one.
    let blocks = poly_message_blocks(aad, ciphertext);
    let tag_share = poly1305::tag_shared_multi_net(ch, party, &poly_share, &blocks)?;
    let computed = open_shared_bytes(ch, &tag_share)?;
    let tag_ok = computed.len() == 16 && computed.iter().zip(tag).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0;

    // Decrypt: pt = C ⊕ KS. Party A carries the public ciphertext in its share, B carries 0,
    // so pt_a ⊕ pt_b = C ⊕ ks_a ⊕ ks_b = C ⊕ KS.
    let ctlen = ciphertext.len();
    let mut pt_share = vec![0u8; ctlen];
    for j in 0..ctlen.div_ceil(64) {
        let ks = share_keystream_net(ch, party, key_share, 1 + j as u32, nonce)?;
        let off = j * 64;
        let end = (off + 64).min(ctlen);
        for i in off..end {
            let c = if party == Party::A { ciphertext[i] } else { 0 };
            pt_share[i] = c ^ ks[i - off];
        }
    }
    Ok((pt_share, tag_ok))
}

/// Seal one **TLS 1.3 record** under 2PC (RFC 8446 §5.2) — the "wiring to a real TLS
/// socket" framing on top of [`seal_aead_shared`]. Appends the real `content_type`
/// to the shared plaintext (forming the `TLSInnerPlaintext`), derives the
/// per-record nonce `static_iv XOR seq` (§5.3), authenticates the record header as
/// the AEAD AAD, and AEAD-seals under 2PC. Returns the exact bytes a TLS 1.3 peer
/// puts on the wire: `opaque_type(0x17) ‖ 0x0303 ‖ length ‖ ciphertext ‖ tag`, which
/// a stock TLS 1.3 stack decrypts.
///
/// The plaintext `content` is shared between the parties; `content_type`, `iv`, and
/// `seq` are public. Semi-honest, like [`seal_aead_shared`].
pub fn seal_tls13_record_shared(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    static_iv: &[u8; 12],
    seq: u64,
    content_type: u8,
    pt_a: &[u8],
    pt_b: &[u8],
) -> Result<Vec<u8>> {
    seal_tls13_record_shared_engine(
        EngineKind::Semihonest,
        key_a,
        key_b,
        static_iv,
        seq,
        content_type,
        pt_a,
        pt_b,
    )
}

/// [`seal_tls13_record_shared`] under a chosen 2PC [`EngineKind`].
#[allow(clippy::too_many_arguments)]
pub fn seal_tls13_record_shared_engine(
    engine: EngineKind,
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    static_iv: &[u8; 12],
    seq: u64,
    content_type: u8,
    pt_a: &[u8],
    pt_b: &[u8],
) -> Result<Vec<u8>> {
    if pt_a.len() != pt_b.len() {
        return Err(Error::Crypto("plaintext shares differ in length".into()));
    }
    // TLSInnerPlaintext = content ‖ content_type (no zero padding). The content is
    // shared; the public content_type goes in share A, zero in share B.
    let mut inner_a = pt_a.to_vec();
    inner_a.push(content_type);
    let mut inner_b = pt_b.to_vec();
    inner_b.push(0);

    let nonce = tls13_nonce(static_iv, seq);
    // TLSCiphertext length = TLSInnerPlaintext + 16-byte tag; AAD = the 5-byte header.
    let length = (inner_a.len() + 16) as u16;
    let header = [0x17, 0x03, 0x03, (length >> 8) as u8, length as u8];

    let (ciphertext, tag) =
        seal_aead_shared_engine(engine, key_a, key_b, &nonce, &header, &inner_a, &inner_b)?;
    let mut record = Vec::with_capacity(5 + ciphertext.len() + 16);
    record.extend_from_slice(&header);
    record.extend_from_slice(&ciphertext);
    record.extend_from_slice(&tag);
    Ok(record)
}

/// The TLS 1.3 per-record nonce (RFC 8446 §5.3): the 64-bit record sequence number,
/// big-endian, left-padded to the 12-byte IV length and XORed with the static IV.
fn tls13_nonce(static_iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *static_iv;
    let seq_be = seq.to_be_bytes(); // 8 bytes, into the low 8 of the 12-byte nonce
    for (n, s) in nonce[4..].iter_mut().zip(seq_be) {
        *n ^= s;
    }
    nonce
}

// ---- internals -------------------------------------------------------------

fn write_key_bits(dst: &mut [bool], key: &[u8; 32]) {
    for k in 0..8 {
        let word = u32::from_le_bytes(key[k * 4..k * 4 + 4].try_into().expect("4 bytes"));
        write_word_bits(&mut dst[k * 32..k * 32 + 32], word);
    }
}

fn write_word_bits(dst: &mut [bool], word: u32) {
    for (j, b) in dst.iter_mut().enumerate() {
        *b = (word >> j) & 1 == 1;
    }
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

fn random_scalar() -> Result<Scalar> {
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

#[cfg(test)]
mod tests {
    use super::super::circuit::chacha20_block_ref;
    use super::*;

    #[test]
    fn networked_aead_matches_stock_chacha20poly1305_over_tcp() {
        // The full ChaCha20-Poly1305 record layer run as two parties over a real TCP socket:
        // party A garbles, party B evaluates, each holding only its key + plaintext share.
        // seal_aead_net must reproduce the stock AEAD; open_aead_net must recover the
        // plaintext (as shares) and verify the tag — proving the record layer networks, so
        // the exit never holds the key, keystream, or plaintext.
        use super::super::live::channel::TcpChannel;
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let key_a = [0x11u8; 32];
        let key_b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x5a);
        let key: [u8; 32] = core::array::from_fn(|i| key_a[i] ^ key_b[i]);
        let nonce = [0x24u8; 12];
        let aad = b"neo-2pc-tls record header".as_slice();
        // Multi-block, non-64-aligned plaintext.
        let plaintext: Vec<u8> = (0..100u8).map(|i| i.wrapping_mul(3).wrapping_add(1)).collect();
        let pt_a: Vec<u8> = plaintext.iter().map(|&b| b ^ 0xa5).collect();
        let pt_b: Vec<u8> = plaintext.iter().zip(&pt_a).map(|(p, a)| p ^ a).collect();

        // --- networked seal ---
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ka, na, aad_a, pta) = (key_a, nonce, aad.to_vec(), pt_a.clone());
        let a = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            seal_aead_net(&mut ch, Party::A, &ka, &na, &aad_a, &pta).unwrap()
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let (ct, tag) = seal_aead_net(&mut ch, Party::B, &key_b, &nonce, aad, &pt_b).unwrap();
        let (ct_a, tag_a) = a.join().unwrap();
        assert_eq!(ct, ct_a, "both parties agree on the ciphertext");
        assert_eq!(tag, tag_a, "both parties agree on the tag");

        // Stock reference.
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad })
            .unwrap();
        assert_eq!(&ct[..], &sealed[..sealed.len() - 16], "networked ciphertext == stock");
        assert_eq!(&tag[..], &sealed[sealed.len() - 16..], "networked tag == stock");

        // --- networked open ---
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ka, na, aad_a, ct_a2, tag2) = (key_a, nonce, aad.to_vec(), ct.clone(), tag);
        let a = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            open_aead_net(&mut ch, Party::A, &ka, &na, &aad_a, &ct_a2, &tag2).unwrap()
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let (pts_b, ok_b) = open_aead_net(&mut ch, Party::B, &key_b, &nonce, aad, &ct, &tag).unwrap();
        let (pts_a, ok_a) = a.join().unwrap();
        assert!(ok_a && ok_b, "tag verified on both parties");
        let recovered: Vec<u8> = pts_a.iter().zip(&pts_b).map(|(a, b)| a ^ b).collect();
        assert_eq!(recovered, plaintext, "networked open recovers the plaintext from shares");

        // A tampered tag must fail verification.
        let mut bad = tag;
        bad[0] ^= 1;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ka, na, aad_a, ct_a3) = (key_a, nonce, aad.to_vec(), ct.clone());
        let a = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            open_aead_net(&mut ch, Party::A, &ka, &na, &aad_a, &ct_a3, &bad).unwrap()
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let (_pt, ok) = open_aead_net(&mut ch, Party::B, &key_b, &nonce, aad, &ct, &bad).unwrap();
        let (_pta, ok_a2) = a.join().unwrap();
        assert!(!ok && !ok_a2, "tampered tag is rejected");
    }

    #[test]
    fn full_aead_under_2pc_matches_stock_chacha20poly1305() {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        // A real key + nonce + AAD + a multi-block, non-16-aligned plaintext (so the
        // test exercises >1 ChaCha block AND ciphertext zero-padding in the MAC).
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let aad: &[u8] = b"tls-1.3-record-header-ish-aad";
        let plaintext: Vec<u8> = (0..100u8).collect();

        // Stock reference: ciphertext ‖ 16-byte tag.
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad,
                },
            )
            .unwrap();
        let (stock_ct, stock_tag) = sealed.split_at(sealed.len() - 16);

        // Split the key and plaintext into two XOR-shares (the 2PC inputs).
        let mut ka = [0u8; 32];
        getrandom::getrandom(&mut ka).unwrap();
        let kb: [u8; 32] = core::array::from_fn(|i| key[i] ^ ka[i]);
        let mut pa = vec![0u8; plaintext.len()];
        getrandom::getrandom(&mut pa).unwrap();
        let pb: Vec<u8> = plaintext.iter().zip(&pa).map(|(p, a)| p ^ a).collect();

        let (ct, tag) = seal_aead_shared(&ka, &kb, &nonce, aad, &pa, &pb).unwrap();
        assert_eq!(ct.as_slice(), stock_ct, "2PC ciphertext == stock AEAD");
        assert_eq!(&tag, stock_tag, "2PC tag == full RFC 8439 AEAD tag");
    }

    #[test]
    fn tls13_record_under_2pc_frames_and_seals_correctly() {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        // Pin the per-record nonce derivation (RFC 8446 §5.3) with an explicit KAT,
        // so the framing isn't merely self-consistent with the reference below.
        let iv = [0x11u8; 12];
        let seq = 5u64;
        let mut want_nonce = [0x11u8; 12];
        want_nonce[11] ^= 0x05; // seq 5 lands in the last byte
        assert_eq!(tls13_nonce(&iv, seq), want_nonce, "nonce = iv XOR seq");

        let key = [0x33u8; 32];
        let content_type = 0x17u8; // application_data
        let content: Vec<u8> = (0..50u8).collect();

        // 2PC shares of key + content.
        let mut ka = [0u8; 32];
        getrandom::getrandom(&mut ka).unwrap();
        let kb: [u8; 32] = core::array::from_fn(|i| key[i] ^ ka[i]);
        let mut pa = vec![0u8; content.len()];
        getrandom::getrandom(&mut pa).unwrap();
        let pb: Vec<u8> = content.iter().zip(&pa).map(|(c, a)| c ^ a).collect();

        let record = seal_tls13_record_shared(&ka, &kb, &iv, seq, content_type, &pa, &pb).unwrap();

        // Independent RFC-8446 reference framing + the stock AEAD.
        let mut inner = content.clone();
        inner.push(content_type);
        let length = (inner.len() + 16) as u16;
        let header = [0x17, 0x03, 0x03, (length >> 8) as u8, length as u8];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&want_nonce),
                Payload {
                    msg: &inner,
                    aad: &header,
                },
            )
            .unwrap();
        let mut expected = header.to_vec();
        expected.extend_from_slice(&sealed);

        assert_eq!(&record[..3], &[0x17, 0x03, 0x03], "TLS 1.3 record header");
        assert_eq!(
            record, expected,
            "2PC TLS record == stock AEAD + RFC framing"
        );
    }

    #[test]
    fn ecdhe_is_additively_shared_and_matches_the_server() {
        let server_secret = random_scalar().unwrap();
        let (_x_pub, z_server, shares) = shared_ecdhe(&server_secret).unwrap();

        // The parties' shares sum to exactly the server's pre-master secret...
        assert_eq!(shares.combined(), z_server);
        // ...but neither party's share alone is the pre-master (no single point).
        assert_ne!(shares.share1, z_server);
        assert_ne!(shares.share2, z_server);
    }

    #[test]
    fn keystream_is_computed_under_2pc_into_xor_shares() {
        let key_a: [u8; 32] = core::array::from_fn(|i| i as u8);
        let key_b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8) ^ 0x5a);
        let counter = 7u32;

        let shares = share_keystream(&key_a, &key_b, counter, &nonce).unwrap();

        // Combining the shares yields exactly ChaCha20(key_a ⊕ key_b) ...
        let key: [u8; 32] = core::array::from_fn(|i| key_a[i] ^ key_b[i]);
        assert_eq!(shares.combined(), chacha20_block_ref(&key, counter, &nonce));
        // ... while neither party's share alone is the keystream.
        assert_ne!(shares.share_a, shares.combined());
        assert_ne!(shares.share_b, shares.combined());
    }

    #[test]
    fn a_record_encrypts_with_plaintext_never_assembled() {
        // Key XOR-shared between the two parties; keystream via 2PC; plaintext also
        // XOR-shared. Each party forms its ciphertext share locally; only the
        // ciphertext C = P ⊕ KS is ever combined.
        let key_a: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(9));
        let key_b: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x33);
        let nonce = [0u8; 12];
        let counter = 1u32;
        let ks = share_keystream(&key_a, &key_b, counter, &nonce).unwrap();

        let plaintext: [u8; 64] = core::array::from_fn(|i| {
            b"the request no single MPC party may ever see in full!!!!!!!!!!!!"[i]
        });
        // XOR-share the plaintext across the two parties.
        let mut p1 = [0u8; 64];
        getrandom::getrandom(&mut p1).unwrap();
        let p2: [u8; 64] = core::array::from_fn(|i| plaintext[i] ^ p1[i]);

        // Each party locally forms its ciphertext share.
        let c1 = local_cipher_share(&p1, &ks.share_a);
        let c2 = local_cipher_share(&p2, &ks.share_b);
        let ciphertext = combine_ciphertext(&c1, &c2); // C = P ⊕ KS

        // The ciphertext decrypts correctly under the (combined) keystream...
        let ks_full = ks.combined();
        let decrypted = xor_bytes(&ciphertext, &ks_full);
        assert_eq!(decrypted, plaintext);

        // ...yet no single party ever held the plaintext or the keystream.
        assert_ne!(c1, plaintext.to_vec());
        assert_ne!(c2, plaintext.to_vec());
        assert_ne!(ks.share_a.to_vec(), ks_full.to_vec());
    }

    #[test]
    fn chacha20_poly1305_record_seals_under_2pc_and_verifies() {
        use super::super::circuit::chacha20_block_ref;
        use super::super::poly1305::poly1305;

        let key_a: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(4));
        let key_b: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x5e);
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_add(1));
        let plaintext: [u8; 16] = *b"attack at 06:00!";
        let mut pt_a = [0u8; 16];
        getrandom::getrandom(&mut pt_a).unwrap();
        let pt_b: [u8; 16] = core::array::from_fn(|i| plaintext[i] ^ pt_a[i]);

        // The two parties, each holding only a key share, seal the record under 2PC.
        let (ciphertext, tag) = seal_record_shared(&key_a, &key_b, &nonce, &pt_a, &pt_b).unwrap();

        // It matches the ChaCha20-Poly1305 *primitives* (not the full RFC AEAD tag):
        // poly key = block 0, encrypt under block 1, raw Poly1305 over the ciphertext.
        let key: [u8; 32] = core::array::from_fn(|i| key_a[i] ^ key_b[i]);
        let block0 = chacha20_block_ref(&key, 0, &nonce);
        let poly_key: [u8; 32] = block0[..32].try_into().unwrap();
        let block1 = chacha20_block_ref(&key, 1, &nonce);
        let ref_ct: [u8; 16] = core::array::from_fn(|i| plaintext[i] ^ block1[i]);
        let ref_tag = poly1305(&ref_ct, &poly_key);

        assert_eq!(ciphertext, ref_ct, "2PC ciphertext matches ChaCha20");
        assert_eq!(tag, ref_tag, "2PC tag matches Poly1305");

        // A receiver holding the key decrypts and authenticates it normally.
        assert_eq!(poly1305(&ciphertext, &poly_key), tag, "tag authenticates");
        let recovered: [u8; 16] = core::array::from_fn(|i| ciphertext[i] ^ block1[i]);
        assert_eq!(recovered, plaintext, "decrypts to the plaintext");
    }
}
