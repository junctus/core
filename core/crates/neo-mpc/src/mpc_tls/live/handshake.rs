//! The live TLS 1.3 client **handshake state machine** (co-client / 2PC), driven over a
//! [`Channel`](super::channel::Channel) against a real server, negotiating
//! `TLS_CHACHA20_POLY1305_SHA256` + `secp256r1`.
//!
//! The two client parties jointly play one TLS 1.3 client: they emit a ClientHello whose
//! `key_share` is the split-scalar sum point ([`ecdhe`](super::ecdhe)), parse the server
//! flight, drive the [`schedule`](super::schedule) from the **public** transcript hash and
//! the **shared** ECDHE secret, verify the server's `CertificateVerify` and `Finished`,
//! emit their own `Finished` (its MAC computed under 2PC), and rekey to the application
//! epoch — after which application data flows through the 2PC [`record`](super::record)
//! layer. No traffic key is ever assembled at one party.
//!
//! # Honest boundary
//!
//! - **Interop-tested against a live stock `rustls` TLS 1.3 server** (see the tests): the
//!   server accepts the ClientHello, its flight decrypts under the 2PC-derived server
//!   handshake key, its `Finished` verifies against the 2PC-derived MAC, and it decrypts
//!   the client `Finished` + application data protected under the 2PC-derived client keys.
//!   That an independent implementation completes the session end-to-end is the oracle.
//! - **Server authentication**: the server `Finished` (bound to the ECDHE secret) is
//!   verified, and the `CertificateVerify` ECDSA-P256 signature over the transcript is
//!   verified against the leaf certificate's key — extracted by a **proper DER
//!   `SubjectPublicKeyInfo` parse** ([`leaf_p256_point`]) that validates the
//!   `{id-ecPublicKey, prime256v1}` algorithm OIDs, not a byte search. Verification is a
//!   pluggable [`ServerCertVerifier`](super::verify::ServerCertVerifier): the default
//!   [`LeafKeyVerifier`](super::verify::LeafKeyVerifier) authenticates the leaf key + the
//!   transcript signature (which, with the ECDHE-bound Finished, stops a passive or
//!   key-substituting MITM), while [`client_handshake_verified`] +
//!   [`WebpkiVerifier`](super::verify) (feature `live-tls-webpki`) do **full X.509
//!   chain-building** to trust anchors (issuer-signature path validation, validity,
//!   subject name) via vetted `rustls-webpki`.
//! - **KeyUpdate** (RFC 8446 §7.2) is supported ([`AppSession::send_key_update`] +
//!   inbound handling in [`recv_application`]): the traffic secret is advanced under 2PC.
//! - **Ciphersuite/curve**: `TLS_CHACHA20_POLY1305_SHA256` + `secp256r1` only.
//!   AES-GCM and x25519 would each need a new 2PC primitive (an AES circuit, a
//!   Montgomery-curve ECtF) — new crypto, not hardening.
//! - Engine-selectable ([`client_handshake`] is semi-honest; [`client_handshake_with_engine`]
//!   runs the whole session under the malicious authenticated-garbling online). In-process
//!   party model — see [`super`]'s boundary.

use neo_core::{Error, Result};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, PublicKey, Scalar};

use super::super::engine::EngineKind;
use super::super::netengine::Party;
use super::super::session::{open_tls13_record_net, seal_tls13_record_net};
use super::super::sha256::sha256;
use super::channel::{read_tls_record, Channel};
use super::ecdhe::ClientKeyShare;
use super::netschedule::{derive_ecdhe_share_net, KeyScheduleNet};
use super::record::Direction;
use super::schedule::{hkdf_expand_label, hmac_sha256, KeySchedule};
use super::verify::ServerCertVerifier;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const HS_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HS_CERTIFICATE: u8 = 0x0b;
const HS_CERTIFICATE_VERIFY: u8 = 0x0f;
const HS_FINISHED: u8 = 0x14;
const HS_KEY_UPDATE: u8 = 0x18;

const REC_CHANGE_CIPHER_SPEC: u8 = 20;
const REC_ALERT: u8 = 21;
const REC_HANDSHAKE: u8 = 22;
const REC_APPLICATION_DATA: u8 = 23;

// A remote server controls every byte after the ClientHello, so every server-driven read
// loop is bounded to deny liveness/memory DoS (endless CCS spam, a flight with no
// Finished, endless ticket records): a benign flight is a handful of records and well
// under a few hundred KiB.
const MAX_CCS_RECORDS: usize = 2; // RFC 8446 allows one middlebox-compat CCS; tolerate 2
const MAX_FLIGHT_BYTES: usize = 256 * 1024;
const MAX_SERVER_RECORDS: usize = 512; // per server-driven read loop

const GROUP_SECP256R1: u16 = 0x0017;
const CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;

/// A live application-data session after a completed handshake: the client-write and
/// server-read record directions (each keyed to an application-traffic secret, seq 0), plus
/// the key schedule + engine needed to advance them on a **KeyUpdate** (RFC 8446 §7.2).
pub struct AppSession {
    pub client_write: Direction,
    pub server_read: Direction,
    schedule: KeySchedule,
    engine: EngineKind,
}

impl AppSession {
    /// Send a TLS 1.3 **KeyUpdate** and rekey the client write path (RFC 8446 §7.2): the
    /// KeyUpdate handshake message is sealed under the *current* client key, then the client
    /// application-traffic secret is advanced and `client_write` reset to the new key (seq 0).
    /// `request_update` asks the server to KeyUpdate its write path in return.
    pub fn send_key_update(&mut self, ch: &mut dyn Channel, request_update: bool) -> Result<()> {
        let msg = handshake_message(HS_KEY_UPDATE, &[request_update as u8]);
        let zeros = vec![0u8; msg.len()];
        let rec = self.client_write.seal(REC_HANDSHAKE, &msg, &zeros)?;
        ch.send(&rec)?;
        let new_keys = self.schedule.update_client_application()?;
        self.client_write = Direction::with_engine(self.engine, &new_keys);
        Ok(())
    }

    /// Advance the server read path one KeyUpdate generation (called when an inbound
    /// KeyUpdate is received): rekey `server_read` to the next server application secret.
    fn apply_server_key_update(&mut self) -> Result<()> {
        let new_keys = self.schedule.update_server_application()?;
        self.server_read = Direction::with_engine(self.engine, &new_keys);
        Ok(())
    }
}

// ---- little-endian-free wire writers -----------------------------------------

fn u16b(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}
fn u24b(n: usize) -> [u8; 3] {
    let b = (n as u32).to_be_bytes();
    [b[1], b[2], b[3]]
}

/// `extension_type(2) ‖ length(2) ‖ data`.
fn extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + data.len());
    v.extend_from_slice(&u16b(ext_type));
    v.extend_from_slice(&u16b(data.len() as u16));
    v.extend_from_slice(data);
    v
}

/// Wrap a handshake body in its 4-byte header `msg_type ‖ uint24 length`.
fn handshake_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.push(msg_type);
    v.extend_from_slice(&u24b(body.len()));
    v.extend_from_slice(body);
    v
}

/// Build the ClientHello handshake message (with its 4-byte header), offering only
/// `TLS_CHACHA20_POLY1305_SHA256` + `secp256r1`, with the split-scalar `key_share`.
fn build_client_hello(
    key_share: &[u8; 65],
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    server_name: &str,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(client_random);
    body.push(32); // legacy_session_id length
    body.extend_from_slice(session_id);
    body.extend_from_slice(&u16b(2)); // cipher_suites length
    body.extend_from_slice(&u16b(CIPHER_CHACHA20_POLY1305_SHA256));
    body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods

    // Extensions.
    let mut exts = Vec::new();
    // supported_versions: list_len(1) ‖ TLS1.3.
    exts.extend_from_slice(&extension(0x002b, &[0x02, 0x03, 0x04]));
    // supported_groups: list_len(2) ‖ secp256r1.
    let mut sg = Vec::new();
    sg.extend_from_slice(&u16b(2));
    sg.extend_from_slice(&u16b(GROUP_SECP256R1));
    exts.extend_from_slice(&extension(0x000a, &sg));
    // signature_algorithms: list_len(2) ‖ ecdsa_secp256r1_sha256.
    let mut sa = Vec::new();
    sa.extend_from_slice(&u16b(2));
    sa.extend_from_slice(&u16b(SIG_ECDSA_SECP256R1_SHA256));
    exts.extend_from_slice(&extension(0x000d, &sa));
    // key_share: client_shares_len(2) ‖ [group ‖ ke_len ‖ point].
    let mut ks = Vec::new();
    let mut entry = Vec::new();
    entry.extend_from_slice(&u16b(GROUP_SECP256R1));
    entry.extend_from_slice(&u16b(65));
    entry.extend_from_slice(key_share);
    ks.extend_from_slice(&u16b(entry.len() as u16));
    ks.extend_from_slice(&entry);
    exts.extend_from_slice(&extension(0x0033, &ks));
    // server_name (SNI): list_len(2) ‖ [name_type(1)=0 ‖ host_len(2) ‖ host].
    if !server_name.is_empty() {
        let host = server_name.as_bytes();
        let mut sni = Vec::new();
        let mut entry = vec![0x00];
        entry.extend_from_slice(&u16b(host.len() as u16));
        entry.extend_from_slice(host);
        sni.extend_from_slice(&u16b(entry.len() as u16));
        sni.extend_from_slice(&entry);
        exts.extend_from_slice(&extension(0x0000, &sni));
    }

    body.extend_from_slice(&u16b(exts.len() as u16));
    body.extend_from_slice(&exts);
    handshake_message(HS_CLIENT_HELLO, &body)
}

/// A byte cursor over a message body.
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.p + n > self.b.len() {
            return Err(Error::Crypto("tls parse: truncated message".into()));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
}

struct ServerHello {
    cipher_suite: u16,
    selected_version: u16,
    server_key_share: Vec<u8>,
}

/// Parse a ServerHello body (after the 4-byte handshake header): confirm TLS 1.3 + the
/// ChaCha20 suite, and extract the server's `secp256r1` `key_share`.
fn parse_server_hello(body: &[u8]) -> Result<ServerHello> {
    let mut r = Reader::new(body);
    r.take(2)?; // legacy_version
    r.take(32)?; // random
    let sid_len = r.u8()? as usize;
    r.take(sid_len)?; // legacy_session_id_echo
    let cipher_suite = r.u16()?;
    r.u8()?; // legacy_compression_method
    let ext_total = r.u16()? as usize;
    let ext_bytes = r.take(ext_total)?;

    let mut selected_version = 0x0303;
    let mut server_key_share = Vec::new();
    let mut er = Reader::new(ext_bytes);
    while er.p < ext_bytes.len() {
        let etype = er.u16()?;
        let elen = er.u16()? as usize;
        let edata = er.take(elen)?;
        match etype {
            0x002b => {
                // supported_versions (server): a single selected 2-byte version.
                if edata.len() >= 2 {
                    selected_version = u16::from_be_bytes([edata[0], edata[1]]);
                }
            }
            0x0033 => {
                // key_share (server): a single KeyShareEntry, no outer list length.
                let mut kr = Reader::new(edata);
                let _group = kr.u16()?;
                let ke_len = kr.u16()? as usize;
                server_key_share = kr.take(ke_len)?.to_vec();
            }
            _ => {}
        }
    }
    Ok(ServerHello {
        cipher_suite,
        selected_version,
        server_key_share,
    })
}

/// A minimal DER TLV cursor: each [`next`](Der::next) yields `(tag, value)` and advances.
struct Der<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Der<'a> {
    fn new(b: &'a [u8]) -> Self {
        Der { b, p: 0 }
    }
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.b.get(self.p)?;
        self.p += 1;
        let l0 = *self.b.get(self.p)?;
        self.p += 1;
        let len = if l0 < 0x80 {
            l0 as usize
        } else {
            // Long form: low 7 bits = number of length octets (reject absurd widths).
            let n = (l0 & 0x7f) as usize;
            if n == 0 || n > 4 {
                return None;
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | *self.b.get(self.p)? as usize;
                self.p += 1;
            }
            l
        };
        let end = self.p.checked_add(len)?; // no overflow even for a 4-octet length on 32-bit
        let val = self.b.get(self.p..end)?;
        self.p = end;
        Some((tag, val))
    }
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7

/// Extract the leaf certificate's P-256 public point by a **positional** DER walk
/// (RFC 5280): `Certificate → tbsCertificate`, then the `subjectPublicKeyInfo` at its
/// *structural position* — the field immediately after `subject`
/// (`[0]version? · serialNumber · signature · issuer · validity · subject · SPKI · …`) —
/// **not** the first SPKI-shaped SEQUENCE (which a hostile cert could smuggle into
/// `subject`/`issuer`/an extension: a parser differential vs. a real validator). The SPKI
/// algorithm must be `{id-ecPublicKey, prime256v1}` and its `subjectPublicKey` the BIT
/// STRING `0x00 ‖ 0x04 ‖ X ‖ Y`. Full **chain-building to a trust anchor** (issuer
/// signatures, validity, hostname) is a caller-supplied verifier — see the boundary.
fn leaf_p256_point(cert_der: &[u8]) -> Option<[u8; 65]> {
    let (_, cert_body) = Der::new(cert_der).next()?; // Certificate SEQUENCE
    let (_, tbs) = Der::new(cert_body).next()?; // tbsCertificate SEQUENCE (first element)
    let mut fields = Der::new(tbs);
    let mut fld = fields.next()?;
    if fld.0 == 0xA0 {
        fld = fields.next()?; // skip optional [0] EXPLICIT version
    }
    // `fld` is now serialNumber; skip it + signature + issuer + validity + subject (5),
    // leaving `fld` = subjectPublicKeyInfo at its exact structural position.
    for _ in 0..5 {
        fld = fields.next()?;
    }
    let (tag, spki) = fld;
    if tag != 0x30 {
        return None; // SubjectPublicKeyInfo is a SEQUENCE
    }
    let mut inner = Der::new(spki);
    let (0x30, alg) = inner.next()? else {
        return None;
    };
    let mut a = Der::new(alg);
    let is_ec_p256 = matches!(a.next(), Some((0x06, oid)) if oid == OID_EC_PUBLIC_KEY)
        && matches!(a.next(), Some((0x06, curve)) if curve == OID_PRIME256V1);
    if !is_ec_p256 {
        return None;
    }
    // subjectPublicKey BIT STRING: 0x00 unused-bits ‖ 0x04 ‖ X ‖ Y (65-byte point).
    match inner.next()? {
        (0x03, bits) if bits.len() == 66 && bits[0] == 0x00 && bits[1] == 0x04 => {
            bits[1..66].try_into().ok()
        }
        _ => None,
    }
}

/// The built-in leaf verification: verify the server's `CertificateVerify`
/// (`ecdsa_secp256r1_sha256` only) over the transcript against the leaf certificate's
/// P-256 key. `signed` is the RFC 8446 §4.4.3 signed content, `sig_der` the DER signature.
/// Used by [`verify::LeafKeyVerifier`](super::verify::LeafKeyVerifier); does **not** build
/// a chain to a trust anchor (that is [`verify::WebpkiVerifier`](super::verify)).
pub(super) fn verify_leaf_signature_p256(
    leaf: &[u8],
    scheme: u16,
    signed: &[u8],
    sig_der: &[u8],
) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    if scheme != SIG_ECDSA_SECP256R1_SHA256 {
        return Err(Error::Crypto(format!(
            "certverify: built-in verifier supports only ecdsa_secp256r1_sha256, got 0x{scheme:04x}"
        )));
    }
    let point = leaf_p256_point(leaf)
        .ok_or_else(|| Error::Crypto("certverify: no P-256 key in leaf cert".into()))?;
    let vk = VerifyingKey::from_sec1_bytes(&point)
        .map_err(|_| Error::Crypto("certverify: bad P-256 key".into()))?;
    let sig = Signature::from_der(sig_der)
        .map_err(|_| Error::Crypto("certverify: malformed ECDSA signature".into()))?;
    vk.verify(signed, &sig)
        .map_err(|_| Error::Crypto("certverify: signature verification failed — abort".into()))
}

/// The RFC 8446 §4.4.3 signed content for the server's CertificateVerify.
fn certificate_verify_signed(transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = vec![0x20u8; 64];
    m.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    m.push(0x00);
    m.extend_from_slice(transcript_hash);
    m
}

fn send_plaintext_handshake(ch: &mut dyn Channel, msg: &[u8]) -> Result<()> {
    let mut rec = vec![REC_HANDSHAKE, 0x03, 0x03];
    rec.extend_from_slice(&u16b(msg.len() as u16));
    rec.extend_from_slice(msg);
    ch.send(&rec)
}

/// Try to split one complete handshake message off the front of `buf`; returns the full
/// message bytes (incl. header) and how many bytes it consumed.
fn try_take_handshake(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
    let total = 4 + len;
    if buf.len() < total {
        return None;
    }
    Some((buf[..total].to_vec(), total))
}

/// Read the server's encrypted flight (EncryptedExtensions … server Finished) under the
/// server handshake key `rx`, returning the full handshake messages in order (dropping
/// CCS records). Stops at the server Finished.
fn read_server_flight(ch: &mut dyn Channel, rx: &mut Direction) -> Result<Vec<Vec<u8>>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut msgs: Vec<Vec<u8>> = Vec::new();
    let mut ccs = 0usize;
    for _ in 0..MAX_SERVER_RECORDS {
        let (ctype, rec) = read_tls_record(ch)?;
        match ctype {
            REC_CHANGE_CIPHER_SPEC => {
                ccs += 1;
                if ccs > MAX_CCS_RECORDS {
                    return Err(Error::Crypto(
                        "tls: too many change_cipher_spec records".into(),
                    ));
                }
                continue; // middlebox CCS: drop, no seq/transcript
            }
            REC_ALERT => {
                return Err(Error::Crypto(format!(
                    "tls: server sent a plaintext alert {rec:?}"
                )))
            }
            REC_APPLICATION_DATA => {
                let (inner_ct, pt) = rx.open(&rec)?;
                if inner_ct != REC_HANDSHAKE {
                    return Err(Error::Crypto(format!(
                        "tls: expected handshake in server flight, got content type {inner_ct}"
                    )));
                }
                buf.extend_from_slice(&pt);
                if buf.len() + msgs.iter().map(Vec::len).sum::<usize>() > MAX_FLIGHT_BYTES {
                    return Err(Error::Crypto(
                        "tls: server flight exceeds size bound".into(),
                    ));
                }
            }
            other => {
                return Err(Error::Crypto(format!(
                    "tls: unexpected record type {other}"
                )))
            }
        }
        while let Some((msg, consumed)) = try_take_handshake(&buf) {
            let is_finished = msg[0] == HS_FINISHED;
            msgs.push(msg);
            buf.drain(0..consumed);
            if is_finished {
                return Ok(msgs);
            }
        }
    }
    Err(Error::Crypto(
        "tls: server flight did not complete within the record bound (no Finished)".into(),
    ))
}

/// Drive the full TLS 1.3 client handshake over `ch` against the server named
/// `server_name`, **semi-honest**, with the built-in leaf verifier. On success returns an
/// [`AppSession`] for application data. Every key is derived under 2PC; the server is
/// authenticated by its Finished + CertificateVerify. Use [`client_handshake_with_engine`]
/// for the malicious online, or [`client_handshake_verified`] to plug in a full X.509
/// chain-building verifier.
pub fn client_handshake(ch: &mut dyn Channel, server_name: &str) -> Result<AppSession> {
    client_handshake_with_engine(ch, server_name, EngineKind::Semihonest)
}

/// [`client_handshake`] under a chosen 2PC [`EngineKind`] (built-in leaf verifier).
pub fn client_handshake_with_engine(
    ch: &mut dyn Channel,
    server_name: &str,
    engine: EngineKind,
) -> Result<AppSession> {
    client_handshake_verified(ch, server_name, engine, &super::verify::LeafKeyVerifier)
}

/// [`client_handshake_with_engine`] with a caller-supplied
/// [`ServerCertVerifier`](super::verify::ServerCertVerifier) — e.g.
/// [`verify::WebpkiVerifier`](super::verify) (feature `live-tls-webpki`) for full X.509
/// chain-building to trust anchors.
pub fn client_handshake_verified(
    ch: &mut dyn Channel,
    server_name: &str,
    engine: EngineKind,
    verifier: &dyn super::verify::ServerCertVerifier,
) -> Result<AppSession> {
    // 1. Split-scalar key_share + fresh randoms; emit ClientHello (plaintext).
    let cks = ClientKeyShare::generate()?;
    let mut client_random = [0u8; 32];
    let mut session_id = [0u8; 32];
    getrandom::getrandom(&mut client_random).map_err(|e| Error::Rng(e.to_string()))?;
    getrandom::getrandom(&mut session_id).map_err(|e| Error::Rng(e.to_string()))?;
    let ch_msg = build_client_hello(&cks.key_share, &client_random, &session_id, server_name);
    send_plaintext_handshake(ch, &ch_msg)?;

    let mut transcript = ch_msg.clone();

    // 2. Read ServerHello (plaintext; skip a bounded number of leading CCS records).
    let mut sh_body = None;
    let mut ccs = 0usize;
    for _ in 0..MAX_CCS_RECORDS + 1 {
        let (ctype, rec) = read_tls_record(ch)?;
        match ctype {
            REC_CHANGE_CIPHER_SPEC => {
                ccs += 1;
                if ccs > MAX_CCS_RECORDS {
                    return Err(Error::Crypto(
                        "tls: too many change_cipher_spec records".into(),
                    ));
                }
                continue;
            }
            REC_HANDSHAKE => {
                if rec.first() != Some(&HS_SERVER_HELLO) {
                    return Err(Error::Crypto("tls: expected ServerHello".into()));
                }
                let (msg, _) = try_take_handshake(&rec)
                    .ok_or_else(|| Error::Crypto("tls: truncated ServerHello".into()))?;
                transcript.extend_from_slice(&msg);
                sh_body = Some(msg[4..].to_vec());
                break;
            }
            REC_ALERT => return Err(Error::Crypto("tls: server alert before ServerHello".into())),
            other => return Err(Error::Crypto(format!("tls: unexpected record {other}"))),
        }
    }
    let sh_body = sh_body
        .ok_or_else(|| Error::Crypto("tls: no ServerHello after change_cipher_spec".into()))?;
    let sh = parse_server_hello(&sh_body)?;
    if sh.selected_version != 0x0304 {
        return Err(Error::Crypto("tls: server did not select TLS 1.3".into()));
    }
    if sh.cipher_suite != CIPHER_CHACHA20_POLY1305_SHA256 {
        return Err(Error::Crypto(
            "tls: server did not select ChaCha20-Poly1305".into(),
        ));
    }

    // 3. ECDHE shared secret (2PC) + Handshake Secret + handshake traffic keys.
    let shared = cks.derive_shared(&sh.server_key_share)?;
    let mut ks =
        KeySchedule::derive_handshake(engine, &shared.secret_a, &shared.secret_b, &transcript)?;
    let mut rx_hs = Direction::with_engine(engine, &ks.server_handshake_keys()?);

    // 4. Server flight: EncryptedExtensions, Certificate, CertificateVerify, Finished.
    let flight = read_server_flight(ch, &mut rx_hs)?;
    let mut chain: Option<Vec<Vec<u8>>> = None;
    let mut transcript_before_certverify: Option<[u8; 32]> = None;
    let mut transcript_before_serverfin: Option<[u8; 32]> = None;
    for msg in &flight {
        match msg[0] {
            HS_ENCRYPTED_EXTENSIONS => transcript.extend_from_slice(msg),
            HS_CERTIFICATE => {
                chain = Some(parse_cert_chain(&msg[4..])?);
                transcript.extend_from_slice(msg);
            }
            HS_CERTIFICATE_VERIFY => {
                // Signed content is over Hash(CH..Certificate) — the transcript so far.
                transcript_before_certverify = Some(sha256(&transcript));
                transcript.extend_from_slice(msg);
            }
            HS_FINISHED => {
                // Server Finished verify_data is over Hash(CH..CertificateVerify).
                transcript_before_serverfin = Some(sha256(&transcript));
                transcript.extend_from_slice(msg);
            }
            other => {
                return Err(Error::Crypto(format!(
                    "tls: unexpected flight message {other}"
                )))
            }
        }
    }

    // 5. Verify CertificateVerify (server authentication) + server Finished (binds ECDHE).
    verify_server_certificate_verify(
        &flight,
        chain.as_deref(),
        transcript_before_certverify,
        server_name,
        verifier,
    )?;
    let sfin_hash = transcript_before_serverfin
        .ok_or_else(|| Error::Crypto("tls: no server Finished in flight".into()))?;
    let server_fin = flight
        .iter()
        .find(|m| m[0] == HS_FINISHED)
        .ok_or_else(|| Error::Crypto("tls: missing server Finished".into()))?;
    let expected = ks.server_finished(&sfin_hash)?;
    if server_fin[4..] != expected[..] {
        return Err(Error::Crypto(
            "tls: server Finished MAC mismatch — handshake not authenticated (abort)".into(),
        ));
    }

    // 6. Client Finished over Hash(CH..server Finished), computed under 2PC, then sent
    //    encrypted under the client handshake key.
    let cfin_hash = sha256(&transcript);
    let client_verify_data = ks.client_finished(&cfin_hash)?;
    let client_fin_msg = handshake_message(HS_FINISHED, &client_verify_data);
    let mut tx_hs = Direction::with_engine(engine, &ks.client_handshake_keys()?);
    let zeros = vec![0u8; client_fin_msg.len()];
    let rec = tx_hs.seal(REC_HANDSHAKE, &client_fin_msg, &zeros)?;
    ch.send(&rec)?;
    transcript.extend_from_slice(&client_fin_msg);

    // 7. Application epoch: derive c/s application traffic secrets over CH..server
    //    Finished; rekey both directions (fresh seq 0).
    let app_transcript_hash_input = &transcript[..transcript.len() - client_fin_msg.len()];
    ks.derive_application(app_transcript_hash_input)?;
    let client_write = Direction::with_engine(engine, &ks.client_application_keys()?);
    let server_read = Direction::with_engine(engine, &ks.server_application_keys()?);
    Ok(AppSession {
        client_write,
        server_read,
        schedule: ks,
        engine,
    })
}

/// Parse the Certificate message body → the certificate chain (DER, **leaf first**).
fn parse_cert_chain(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut r = Reader::new(body);
    let ctx_len = r.u8()? as usize;
    r.take(ctx_len)?; // certificate_request_context
    let list_len = ((r.u8()? as usize) << 16) | ((r.u8()? as usize) << 8) | (r.u8()? as usize);
    let list = r.take(list_len)?;
    let mut lr = Reader::new(list);
    let mut chain = Vec::new();
    while lr.p < list.len() {
        let clen = ((lr.u8()? as usize) << 16) | ((lr.u8()? as usize) << 8) | (lr.u8()? as usize);
        chain.push(lr.take(clen)?.to_vec());
        let ext_len = r_u16(&mut lr)?; // per-entry extensions
        lr.take(ext_len)?;
    }
    if chain.is_empty() {
        return Err(Error::Crypto("tls: empty certificate chain".into()));
    }
    Ok(chain)
}

fn r_u16(r: &mut Reader) -> Result<usize> {
    Ok(((r.u8()? as usize) << 8) | r.u8()? as usize)
}

/// Verify the CertificateVerify message from the flight: recover `(scheme, signature)`,
/// build the RFC 8446 §4.4.3 signed content, and delegate the chain + signature check to
/// the caller's [`ServerCertVerifier`](super::verify::ServerCertVerifier).
fn verify_server_certificate_verify(
    flight: &[Vec<u8>],
    chain: Option<&[Vec<u8>]>,
    transcript_before_cv: Option<[u8; 32]>,
    server_name: &str,
    verifier: &dyn super::verify::ServerCertVerifier,
) -> Result<()> {
    // This client always performs a full (non-PSK) ECDHE handshake, so the server MUST
    // authenticate via CertificateVerify — a flight without it is unauthenticated and aborts.
    let cv = flight
        .iter()
        .find(|m| m[0] == HS_CERTIFICATE_VERIFY)
        .ok_or_else(|| {
            Error::Crypto("tls: server flight missing CertificateVerify — abort".into())
        })?;
    let chain =
        chain.ok_or_else(|| Error::Crypto("tls: CertificateVerify without Certificate".into()))?;
    let th = transcript_before_cv
        .ok_or_else(|| Error::Crypto("tls: missing pre-CertificateVerify transcript".into()))?;

    let mut r = Reader::new(&cv[4..]);
    let scheme = r.u16()?;
    let sig_len = r.u16()? as usize;
    let sig = r.take(sig_len)?;
    let signed = certificate_verify_signed(&th);
    verifier.verify(chain, server_name, scheme, &signed, sig)
}

/// Send one application-data record (shared plaintext `data`) to the server.
pub fn send_application(ch: &mut dyn Channel, sess: &mut AppSession, data: &[u8]) -> Result<()> {
    let zeros = vec![0u8; data.len()];
    let rec = sess.client_write.seal(REC_APPLICATION_DATA, data, &zeros)?;
    ch.send(&rec)
}

/// Read the next application-data record from the server (skipping post-handshake
/// NewSessionTicket handshake records), returning the opened plaintext. Bounded so a
/// server cannot keep the client reading forever without delivering application data.
pub fn recv_application(ch: &mut dyn Channel, sess: &mut AppSession) -> Result<Vec<u8>> {
    for _ in 0..MAX_SERVER_RECORDS {
        let (ctype, rec) = read_tls_record(ch)?;
        match ctype {
            REC_CHANGE_CIPHER_SPEC => continue,
            REC_APPLICATION_DATA => {
                let (inner_ct, pt) = sess.server_read.open(&rec)?;
                match inner_ct {
                    REC_HANDSHAKE => {
                        // Post-handshake messages, possibly coalesced in one record (RFC 8446
                        // §5.1). Handle each: a KeyUpdate (§7.2) rekeys the read path (the record
                        // was decrypted under the old key) and, if update_requested, KeyUpdates
                        // our write path back; NewSessionTicket etc. are skipped.
                        let mut buf = pt.as_slice();
                        while let Some((msg, consumed)) = try_take_handshake(buf) {
                            if msg[0] == HS_KEY_UPDATE {
                                // KeyUpdate ::= enum { not_requested(0), requested(1) }: exactly
                                // one body byte, value 0 or 1 (RFC 8446 §4.6.3) — else abort.
                                if msg.len() != 5 || msg[4] > 1 {
                                    return Err(Error::Crypto(
                                        "tls: malformed KeyUpdate (illegal_parameter)".into(),
                                    ));
                                }
                                sess.apply_server_key_update()?;
                                if msg[4] == 1 {
                                    sess.send_key_update(ch, false)?;
                                }
                            }
                            buf = &buf[consumed..];
                        }
                        continue;
                    }
                    REC_APPLICATION_DATA => return Ok(pt),
                    REC_ALERT => return Err(Error::Crypto(format!("tls: server alert {pt:?}"))),
                    other => {
                        return Err(Error::Crypto(format!("tls: unexpected inner type {other}")))
                    }
                }
            }
            other => {
                return Err(Error::Crypto(format!(
                    "tls: unexpected record type {other}"
                )))
            }
        }
    }
    Err(Error::Crypto(
        "tls: server sent too many non-application records without delivering app data".into(),
    ))
}

// ===================================================================================
// Committee 2PC-TLS handshake driver (networked, two exit-committee members)
// ===================================================================================
//
// The two committee members jointly play one TLS 1.3 client against a real server, each
// holding only its own ECDHE scalar share + a share of every traffic secret — so no single
// member ever holds the session key or sees the plaintext. Party A (the lead) holds the
// server connection and relays the *public* wire bytes to party B over the member↔member
// `party` channel; both run every 2PC gadget (ECDHE, key schedule, record layer) over it.
// The client stays a normal onion client and reconstructs plaintext from the members' shares.
// Semi-honest; interop-verified against a stock rustls server (see the tests).

/// A completed committee 2PC-TLS session: this member's shares of the application-traffic
/// keys, the opened public IVs, and per-direction record sequence numbers.
pub struct CommitteeSession {
    role: Party,
    cw_key: [u8; 32], // client_write app-traffic key share
    cw_iv: [u8; 12],
    cw_seq: u64,
    sr_key: [u8; 32], // server_read app-traffic key share
    sr_iv: [u8; 12],
    sr_seq: u64,
}

/// Lead→follower relay of a public blob over the party channel (u32 length prefix).
fn relay_send(party: &mut dyn Channel, bytes: &[u8]) -> Result<()> {
    let mut m = (bytes.len() as u32).to_be_bytes().to_vec();
    m.extend_from_slice(bytes);
    party.send(&m)
}
fn relay_recv(party: &mut dyn Channel) -> Result<Vec<u8>> {
    let len = u32::from_be_bytes(party.recv_exact(4)?.try_into().expect("4 bytes")) as usize;
    if len > MAX_FLIGHT_BYTES {
        return Err(Error::Crypto("committee: oversized relay".into()));
    }
    // A relayed message always carries at least a 1-byte handshake-type tag; every caller
    // indexes `m[0]`. Reject a zero-length frame here so a dishonest lead can't crash the
    // follower's 2PC thread by relaying a `len == 0` frame (the message is attacker-chosen).
    if len == 0 {
        return Err(Error::Crypto("committee: empty relay frame".into()));
    }
    party.recv_exact(len)
}

/// Open a value both members hold as XOR-shares (a public handshake value): send mine, recv
/// the peer's, XOR. Symmetric — both members call it.
fn combine_public(party: &mut dyn Channel, mine: &[u8]) -> Result<Vec<u8>> {
    party.send(mine)?;
    let peer = party.recv_exact(mine.len())?;
    Ok(mine.iter().zip(&peer).map(|(a, b)| a ^ b).collect())
}

/// Open the 12-byte record IV from the two members' 32-byte IV shares (public — an IV is a
/// PRF output, safe with the key still shared).
fn open_iv(party: &mut dyn Channel, iv_share: &[u8; 32]) -> Result<[u8; 12]> {
    let iv = combine_public(party, &iv_share[..12])?;
    Ok(iv.try_into().expect("12-byte iv"))
}

// ---- cleartext handshake crypto (HS-open fast path) --------------------------------------
//
// Once the handshake-traffic secrets are opened (KeyScheduleNet::open_handshake_secrets), the
// server flight (all PUBLIC/authenticated) is decrypted, the Finished MACs computed, and the
// client Finished sealed **in the clear** with the vetted stock ChaCha20-Poly1305 + HKDF —
// removing the certificate-flight 2PC (the dominant cost). Only the application epoch stays
// 2PC. The application keys are never opened, so no member ever holds application plaintext.

/// The TLS 1.3 per-record nonce: `static_iv XOR seq` (RFC 8446 §5.3).
fn tls13_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    for (b, s) in n[4..].iter_mut().zip(seq.to_be_bytes()) {
        *b ^= s;
    }
    n
}

/// Cleartext `(key, iv)` from a handshake-traffic secret (RFC 8446 §7.3).
fn cleartext_traffic_keys(secret: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let key: [u8; 32] = hkdf_expand_label(secret, b"key", b"", 32)
        .try_into()
        .expect("32");
    let iv: [u8; 12] = hkdf_expand_label(secret, b"iv", b"", 12)
        .try_into()
        .expect("12");
    (key, iv)
}

/// Cleartext Finished MAC = `HMAC(HKDF-Expand-Label(secret,"finished","",32), transcript_hash)`.
fn cleartext_finished(secret: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let fk: [u8; 32] = hkdf_expand_label(secret, b"finished", b"", 32)
        .try_into()
        .expect("32");
    hmac_sha256(&fk, transcript_hash)
}

/// Cleartext TLS 1.3 record open (stock AEAD): decrypt `record_body` (ciphertext ‖ tag),
/// strip padding + the trailing content type. Returns `(content_type, plaintext)`.
fn cleartext_open_record(
    key: &[u8; 32],
    iv: &[u8; 12],
    seq: u64,
    record_body: &[u8],
) -> Result<(u8, Vec<u8>)> {
    let length = (record_body.len()) as u16;
    let header = [0x17, 0x03, 0x03, (length >> 8) as u8, length as u8];
    let nonce = tls13_nonce(iv, seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut inner = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: record_body,
                aad: &header,
            },
        )
        .map_err(|_| Error::Crypto("tls: server record failed to decrypt/authenticate".into()))?;
    while inner.last() == Some(&0) {
        inner.pop();
    }
    let ct = inner
        .pop()
        .ok_or_else(|| Error::Crypto("tls: empty TLSInnerPlaintext".into()))?;
    Ok((ct, inner))
}

/// Cleartext TLS 1.3 record seal (stock AEAD): returns the wire record
/// `0x17 ‖ 0x0303 ‖ length ‖ ciphertext ‖ tag`.
fn cleartext_seal_record(
    key: &[u8; 32],
    iv: &[u8; 12],
    seq: u64,
    content_type: u8,
    content: &[u8],
) -> Result<Vec<u8>> {
    let mut inner = content.to_vec();
    inner.push(content_type);
    let length = (inner.len() + 16) as u16;
    let header = [0x17, 0x03, 0x03, (length >> 8) as u8, length as u8];
    let nonce = tls13_nonce(iv, seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &header,
            },
        )
        .map_err(|_| Error::Crypto("tls: client record seal failed".into()))?;
    let mut record = header.to_vec();
    record.extend_from_slice(&sealed);
    Ok(record)
}

/// SEC1 uncompressed encoding of a P-256 point (65 bytes).
fn point_sec1(p: &ProjectivePoint) -> [u8; 65] {
    <[u8; 65]>::try_from(p.to_affine().to_encoded_point(false).as_bytes()).expect("65-byte SEC1")
}

/// Read the plaintext ServerHello from the server (skipping bounded leading CCS records).
fn read_plaintext_server_hello(server: &mut dyn Channel) -> Result<Vec<u8>> {
    let mut ccs = 0usize;
    for _ in 0..MAX_CCS_RECORDS + 1 {
        let (ctype, rec) = read_tls_record(server)?;
        match ctype {
            REC_CHANGE_CIPHER_SPEC => {
                ccs += 1;
                if ccs > MAX_CCS_RECORDS {
                    return Err(Error::Crypto("tls: too many change_cipher_spec".into()));
                }
            }
            REC_HANDSHAKE => {
                let (msg, _) = try_take_handshake(&rec)
                    .ok_or_else(|| Error::Crypto("tls: truncated ServerHello".into()))?;
                return Ok(msg);
            }
            REC_ALERT => return Err(Error::Crypto("tls: alert before ServerHello".into())),
            other => return Err(Error::Crypto(format!("tls: unexpected record {other}"))),
        }
    }
    Err(Error::Crypto("tls: no ServerHello after CCS".into()))
}

/// **The committee 2PC-TLS handshake driver.** See the module section header. `server` is
/// `Some` for the lead (party A) and `None` for the follower (party B). `scalar` is this
/// member's ephemeral ECDHE scalar share.
pub fn committee_handshake_net(
    party: &mut dyn Channel,
    role: Party,
    mut server: Option<&mut dyn Channel>,
    server_name: &str,
    scalar: &Scalar,
    verifier: &dyn ServerCertVerifier,
) -> Result<CommitteeSession> {
    let lead = role == Party::A;
    if lead != server.is_some() {
        return Err(Error::Crypto(
            "committee: party A must hold the server connection; B must not".into(),
        ));
    }

    // 1. Public client_random + session_id — A draws, relays to B.
    let (client_random, session_id): ([u8; 32], [u8; 32]) = if lead {
        let mut cr = [0u8; 32];
        let mut sid = [0u8; 32];
        getrandom::getrandom(&mut cr).map_err(|e| Error::Rng(e.to_string()))?;
        getrandom::getrandom(&mut sid).map_err(|e| Error::Rng(e.to_string()))?;
        let mut m = cr.to_vec();
        m.extend_from_slice(&sid);
        relay_send(party, &m)?;
        (cr, sid)
    } else {
        let m = relay_recv(party)?;
        if m.len() != 64 {
            return Err(Error::Crypto("committee: bad random relay".into()));
        }
        (m[..32].try_into().unwrap(), m[32..].try_into().unwrap())
    };

    // 2. Joint key share X = (x_A + x_B)·G — exchange per-member points.
    let my_point = ProjectivePoint::GENERATOR * *scalar;
    party.send(&point_sec1(&my_point))?;
    let peer_bytes = party.recv_exact(65)?;
    let peer_point = PublicKey::from_sec1_bytes(&peer_bytes)
        .map_err(|_| Error::Crypto("committee: bad peer key-share point".into()))?
        .to_projective();
    let x_share = point_sec1(&(my_point + peer_point));

    // 3. ClientHello (both build the identical message; A sends it).
    let ch_msg = build_client_hello(&x_share, &client_random, &session_id, server_name);
    if let Some(s) = server.as_deref_mut() {
        send_plaintext_handshake(s, &ch_msg)?;
    }
    let mut transcript = ch_msg.clone();

    // 4. ServerHello: A reads (skips CCS) + relays; both parse.
    let sh_msg = if lead {
        let msg = read_plaintext_server_hello(server.as_deref_mut().expect("lead has server"))?;
        relay_send(party, &msg)?;
        msg
    } else {
        relay_recv(party)?
    };
    if sh_msg.first() != Some(&HS_SERVER_HELLO) {
        return Err(Error::Crypto("committee: expected ServerHello".into()));
    }
    transcript.extend_from_slice(&sh_msg);
    let sh = parse_server_hello(&sh_msg[4..])?;
    if sh.selected_version != 0x0304 || sh.cipher_suite != CIPHER_CHACHA20_POLY1305_SHA256 {
        return Err(Error::Crypto(
            "committee: server did not select TLS 1.3 + ChaCha20-Poly1305".into(),
        ));
    }

    // 5. ECDHE (2PC) + Handshake Secret + the two HS-traffic secrets (2PC), then **OPEN** them
    //    to cleartext. `handshake_secret` stays SHARED — its application-branch children
    //    (master → app keys) are derived under 2PC in step 10; only its *public* siblings
    //    client_hs/server_hs are revealed, so the flight decrypt + Finished can run in the
    //    clear (removing the certificate-flight 2PC) while no member ever sees application data.
    let ecdhe = derive_ecdhe_share_net(party, role, scalar, &sh.server_key_share)?;
    let mut ks = KeyScheduleNet::derive_handshake(party, role, &ecdhe, &transcript)?;
    let (client_hs, server_hs) = ks.open_handshake_secrets(party)?;
    let (shk, shiv) = cleartext_traffic_keys(&server_hs);

    // 6. Server flight: A reads encrypted records + relays; both open (2PC) + reassemble.
    let mut flight: Vec<Vec<u8>> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut ccs = 0usize;
    let mut seq = 0u64;
    'flight: for _ in 0..MAX_SERVER_RECORDS {
        // Relay one raw record (content_type ‖ body) lead→follower.
        let (ctype, body) = if lead {
            let (ct, b) = read_tls_record(server.as_deref_mut().expect("lead has server"))?;
            let mut m = vec![ct];
            m.extend_from_slice(&b);
            relay_send(party, &m)?;
            (ct, b)
        } else {
            let m = relay_recv(party)?;
            (m[0], m[1..].to_vec())
        };
        match ctype {
            REC_CHANGE_CIPHER_SPEC => {
                ccs += 1;
                if ccs > MAX_CCS_RECORDS {
                    return Err(Error::Crypto("tls: too many change_cipher_spec".into()));
                }
                continue;
            }
            REC_APPLICATION_DATA => {
                // The server flight is public/authenticated — decrypt it IN THE CLEAR with the
                // opened server-HS key (stock ChaCha20-Poly1305). No 2PC.
                let (inner_ct, inner) = cleartext_open_record(&shk, &shiv, seq, &body)?;
                seq += 1;
                if inner_ct != REC_HANDSHAKE {
                    return Err(Error::Crypto("tls: expected handshake in flight".into()));
                }
                buf.extend_from_slice(&inner);
                if buf.len() + flight.iter().map(Vec::len).sum::<usize>() > MAX_FLIGHT_BYTES {
                    return Err(Error::Crypto("tls: server flight too large".into()));
                }
            }
            REC_ALERT => return Err(Error::Crypto("tls: alert in server flight".into())),
            other => return Err(Error::Crypto(format!("tls: unexpected record {other}"))),
        }
        while let Some((msg, consumed)) = try_take_handshake(&buf) {
            let is_finished = msg[0] == HS_FINISHED;
            flight.push(msg);
            buf.drain(0..consumed);
            if is_finished {
                break 'flight;
            }
        }
    }
    if flight.last().map(|m| m[0]) != Some(HS_FINISHED) {
        return Err(Error::Crypto("tls: server flight never completed".into()));
    }

    // 7. Process flight messages, capturing transcript-hash checkpoints.
    let mut chain: Option<Vec<Vec<u8>>> = None;
    let mut tbcv: Option<[u8; 32]> = None;
    let mut tbsf: Option<[u8; 32]> = None;
    for msg in &flight {
        match msg[0] {
            HS_ENCRYPTED_EXTENSIONS => transcript.extend_from_slice(msg),
            HS_CERTIFICATE => {
                chain = Some(parse_cert_chain(&msg[4..])?);
                transcript.extend_from_slice(msg);
            }
            HS_CERTIFICATE_VERIFY => {
                tbcv = Some(sha256(&transcript));
                transcript.extend_from_slice(msg);
            }
            HS_FINISHED => {
                tbsf = Some(sha256(&transcript));
                transcript.extend_from_slice(msg);
            }
            other => {
                return Err(Error::Crypto(format!(
                    "committee: unexpected flight msg {other}"
                )))
            }
        }
    }

    // 8. Authenticate: CertificateVerify + server Finished — both members verify locally
    //    (cleartext) against the opened server-HS secret. No 2PC.
    verify_server_certificate_verify(&flight, chain.as_deref(), tbcv, server_name, verifier)?;
    let sfin_hash = tbsf.ok_or_else(|| Error::Crypto("committee: no server Finished".into()))?;
    let server_fin = flight
        .iter()
        .find(|m| m[0] == HS_FINISHED)
        .ok_or_else(|| Error::Crypto("committee: missing server Finished".into()))?;
    let expected = cleartext_finished(&server_hs, &sfin_hash);
    if server_fin[4..] != expected[..] {
        return Err(Error::Crypto(
            "committee: server Finished MAC mismatch — handshake not authenticated (abort)".into(),
        ));
    }

    // 9. Client Finished — computed + sealed in the clear under the opened client-HS secret.
    let cfin_hash = sha256(&transcript);
    let cfin = cleartext_finished(&client_hs, &cfin_hash);
    let cfin_msg = handshake_message(HS_FINISHED, &cfin);
    let (chk, chiv) = cleartext_traffic_keys(&client_hs);
    let fin_record = cleartext_seal_record(&chk, &chiv, 0, REC_HANDSHAKE, &cfin_msg)?;
    if let Some(s) = server {
        s.send(&fin_record)?;
    }

    // 10. Application epoch over CH..server Finished (transcript before client Finished).
    ks.derive_application(party, &transcript)?;
    let (cw_key, cw_iv_share) = ks.client_application_keys_share(party)?;
    let (sr_key, sr_iv_share) = ks.server_application_keys_share(party)?;
    let cw_iv = open_iv(party, &cw_iv_share)?;
    let sr_iv = open_iv(party, &sr_iv_share)?;

    Ok(CommitteeSession {
        role,
        cw_key,
        cw_iv,
        cw_seq: 0,
        sr_key,
        sr_iv,
        sr_seq: 0,
    })
}

/// Send application data through the committee session. `pt_share` is this member's share of
/// the plaintext (for a public request, the lead carries the bytes and the follower zeros).
/// The lead writes the sealed record to `server`.
pub fn committee_send_app(
    party: &mut dyn Channel,
    session: &mut CommitteeSession,
    server: Option<&mut dyn Channel>,
    pt_share: &[u8],
) -> Result<()> {
    let record = seal_tls13_record_net(
        party,
        session.role,
        &session.cw_key,
        &session.cw_iv,
        session.cw_seq,
        REC_APPLICATION_DATA,
        pt_share,
    )?;
    session.cw_seq += 1;
    if let Some(s) = server {
        s.send(&record)?;
    }
    Ok(())
}

/// Receive one application record. The lead reads it from `server` and relays it; both open
/// under 2PC. Returns this member's XOR-share of the plaintext (skipping any leading CCS).
pub fn committee_recv_app(
    party: &mut dyn Channel,
    session: &mut CommitteeSession,
    mut server: Option<&mut dyn Channel>,
) -> Result<Vec<u8>> {
    let lead = session.role == Party::A;
    for _ in 0..MAX_SERVER_RECORDS {
        let (ctype, body) = if lead {
            let (ct, b) = read_tls_record(server.as_deref_mut().expect("lead has server"))?;
            let mut m = vec![ct];
            m.extend_from_slice(&b);
            relay_send(party, &m)?;
            (ct, b)
        } else {
            let m = relay_recv(party)?;
            (m[0], m[1..].to_vec())
        };
        match ctype {
            REC_CHANGE_CIPHER_SPEC => continue,
            REC_APPLICATION_DATA => {
                let mut record = vec![0x17, 0x03, 0x03, (body.len() >> 8) as u8, body.len() as u8];
                record.extend_from_slice(&body);
                let (inner_share, ok) = open_tls13_record_net(
                    party,
                    session.role,
                    &session.sr_key,
                    &session.sr_iv,
                    session.sr_seq,
                    &record,
                )?;
                if !ok {
                    return Err(Error::Crypto(
                        "committee: app record tag verify failed".into(),
                    ));
                }
                session.sr_seq += 1;
                // Return this member's full inner-plaintext share (content ‖ content_type ‖
                // padding). The committee must NOT combine it — the client XORs the two
                // members' shares and strips the trailing content_type itself.
                return Ok(inner_share);
            }
            REC_ALERT => return Err(Error::Crypto("committee: server alert".into())),
            other => {
                return Err(Error::Crypto(format!(
                    "committee: unexpected record {other}"
                )))
            }
        }
    }
    Err(Error::Crypto("committee: no application record".into()))
}

#[cfg(test)]
mod tests {
    use super::super::channel::{Loopback, TcpChannel};
    use super::super::schedule::TrafficKeys;
    use super::*;

    /// DER TLV: `tag ‖ length ‖ value`.
    fn der(tag: u8, val: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = val.len();
        if n < 128 {
            v.push(n as u8);
        } else if n < 256 {
            v.extend_from_slice(&[0x81, n as u8]);
        } else {
            v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend_from_slice(val);
        v
    }

    /// A SubjectPublicKeyInfo SEQUENCE for a given P-256 uncompressed point.
    fn spki(point: &[u8; 65]) -> Vec<u8> {
        let alg = der(
            0x30,
            &[der(0x06, OID_EC_PUBLIC_KEY), der(0x06, OID_PRIME256V1)].concat(),
        );
        let mut bitstr = vec![0x00];
        bitstr.extend_from_slice(point);
        der(0x30, &[alg, der(0x03, &bitstr)].concat())
    }

    #[test]
    fn leaf_p256_point_binds_to_the_spki_position_not_first_match() {
        // Parser-differential guard: a hostile cert places a decoy SPKI-shaped SEQUENCE in
        // the `subject` field (an earlier position). The positional parser must return the
        // GENUINE key at the subjectPublicKeyInfo slot, never the smuggled one.
        let real: [u8; 65] = core::array::from_fn(|i| if i == 0 { 0x04 } else { i as u8 });
        let decoy: [u8; 65] = core::array::from_fn(|i| if i == 0 { 0x04 } else { 0xff ^ i as u8 });

        let version = der(0xA0, &der(0x02, &[0x02])); // [0] EXPLICIT INTEGER 2 (v3)
        let serial = der(0x02, &[0x2a]);
        let signature = der(0x30, &[]);
        let issuer = der(0x30, &[]);
        let validity = der(0x30, &[]);
        let subject = spki(&decoy); // smuggled: `subject` shaped like an SPKI
        let real_spki = spki(&real);
        let tbs = der(
            0x30,
            &[
                version, serial, signature, issuer, validity, subject, real_spki,
            ]
            .concat(),
        );
        let cert = der(0x30, &tbs); // Certificate ::= SEQUENCE { tbsCertificate, ... }

        assert_eq!(
            leaf_p256_point(&cert),
            Some(real),
            "must extract the genuine SPKI key, not the decoy smuggled into `subject`"
        );
        assert_ne!(leaf_p256_point(&cert), Some(decoy), "decoy must never win");
        // Truncated / malformed DER must not panic — just fail to parse.
        assert_eq!(leaf_p256_point(&cert[..cert.len() / 2]), None);
        assert_eq!(leaf_p256_point(&[0x30, 0x82, 0xff, 0xff]), None);
    }
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn read_server_flight_aborts_on_ccs_spam() {
        // A malicious server streaming endless change_cipher_spec records must abort the
        // bounded flight reader, not spin forever.
        let (mut client, mut server) = Loopback::pair();
        for _ in 0..MAX_CCS_RECORDS + 5 {
            server.send(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).unwrap(); // a CCS record
        }
        let keys = TrafficKeys {
            key_a: [0u8; 32],
            key_b: [0u8; 32],
            iv: [0u8; 12],
        };
        let mut rx = Direction::new(&keys);
        assert!(
            read_server_flight(&mut client, &mut rx).is_err(),
            "CCS spam must be rejected by the record/CCS bound"
        );
    }

    /// A loopback rustls TLS 1.3 server restricted to `TLS_CHACHA20_POLY1305_SHA256` +
    /// `secp256r1`, with a self-signed ECDSA-P256 cert. It echoes the first app record.
    /// Returns the bound address; the server runs on a detached thread.
    fn spawn_rustls_echo_server() -> std::net::SocketAddr {
        spawn_rustls_echo_server_cert().0
    }

    /// As [`spawn_rustls_echo_server`], also returning the server's self-signed cert DER
    /// (usable as a trust anchor for the webpki verifier test).
    fn spawn_rustls_echo_server_cert() -> (std::net::SocketAddr, Vec<u8>) {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256];
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];

        // rcgen 0.13 defaults to a P-256 ECDSA key — exactly what the client verifies.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let anchor_der = cert_der.to_vec();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        config.send_tls13_tickets = 0; // keep the exchange minimal + deterministic
        let config = Arc::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(config).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            let mut buf = [0u8; 256];
            // First read drives the whole handshake, then yields the client's app data.
            let n = tls.read(&mut buf).unwrap();
            tls.write_all(&buf[..n]).unwrap();
            tls.flush().ok();
            // Confirm the negotiated parameters server-side.
            assert_eq!(
                tls.conn.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                tls.conn.negotiated_cipher_suite().map(|c| c.suite()),
                Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            );
        });
        (addr, anchor_der)
    }

    #[test]
    #[cfg(feature = "live-tls-webpki")]
    #[ignore] // ~15s release: full handshake + webpki chain-building
    fn live_handshake_with_webpki_chain_verification() {
        // The 2PC handshake with FULL X.509 chain-building: the webpki verifier validates
        // the server chain to a trust anchor (here the self-signed cert itself), checks the
        // "localhost" subject name, and verifies the CertificateVerify signature — all via
        // vetted rustls-webpki, replacing the built-in leaf-only check.
        use super::super::verify::WebpkiVerifier;
        let (addr, root) = spawn_rustls_echo_server_cert();
        let verifier = WebpkiVerifier::with_roots(&[root]).expect("build webpki verifier");
        let mut ch = TcpChannel::connect(addr).unwrap();
        let mut session =
            client_handshake_verified(&mut ch, "localhost", EngineKind::Semihonest, &verifier)
                .expect("2PC TLS 1.3 handshake with webpki chain validation");
        let payload = b"webpki-verified ping";
        send_application(&mut ch, &mut session, payload).unwrap();
        assert_eq!(recv_application(&mut ch, &mut session).unwrap(), payload);
    }

    #[test]
    #[cfg(feature = "live-tls-webpki")]
    #[ignore] // ~15s release: full handshake + webpki chain-building via pre-parsed anchors
    fn live_handshake_with_webpki_trust_anchors() {
        // As above but through `with_trust_anchors` — the constructor a relay uses to pass the
        // `webpki-roots` Mozilla bundle: parse the self-signed cert into an owned trust anchor
        // and trust it directly (rather than as a DER via `with_roots`).
        use super::super::verify::WebpkiVerifier;
        use rustls::pki_types::CertificateDer;
        let (addr, root) = spawn_rustls_echo_server_cert();
        let der = CertificateDer::from(root.as_slice());
        let anchor = webpki::anchor_from_trusted_cert(&der).unwrap().to_owned();
        let verifier = WebpkiVerifier::with_trust_anchors(vec![anchor]);
        let mut ch = TcpChannel::connect(addr).unwrap();
        let mut session =
            client_handshake_verified(&mut ch, "localhost", EngineKind::Semihonest, &verifier)
                .expect("2PC TLS 1.3 handshake with webpki trust-anchor validation");
        let payload = b"webpki-anchor ping";
        send_application(&mut ch, &mut session, payload).unwrap();
        assert_eq!(recv_application(&mut ch, &mut session).unwrap(), payload);
    }

    #[test]
    #[cfg(feature = "live-tls-webpki")]
    #[ignore] // ~15s release: full handshake up to the (rejected) cert check
    fn webpki_rejects_cert_not_chaining_to_the_trusted_root() {
        // Enforcement proof: trust a *different* self-signed cert as the only anchor; the server
        // presents its own, which does not chain to that anchor, so webpki must REJECT it —
        // where the leaf-only `LeafKeyVerifier` (no chain-building) would have accepted it.
        use super::super::verify::WebpkiVerifier;
        let (addr, _server_cert) = spawn_rustls_echo_server_cert();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let verifier =
            WebpkiVerifier::with_roots(&[other.cert.der().to_vec()]).expect("build verifier");
        let mut ch = TcpChannel::connect(addr).unwrap();
        let err = match client_handshake_verified(
            &mut ch,
            "localhost",
            EngineKind::Semihonest,
            &verifier,
        ) {
            Ok(_) => panic!("a cert that does not chain to the trusted anchor must be rejected"),
            Err(e) => e,
        };
        let msg = format!("{err}").to_lowercase();
        assert!(
            msg.contains("cert") || msg.contains("chain"),
            "expected a certificate-validation failure, got: {err}"
        );
    }

    #[test]
    fn committee_handshake_against_rustls_and_echo() {
        // The committee-model end-to-end proof: TWO exit-committee members, each holding only
        // its own ECDHE scalar share, jointly complete a real TLS 1.3 handshake against a
        // stock rustls server over a member↔member socket, then send + receive an application
        // record — neither member ever holding the session key or the plaintext. rustls
        // accepting the joint ClientHello, its flight decrypting under the 2PC server key, its
        // Finished verifying against the 2PC MAC, and its decrypting the 2PC client Finished +
        // app record (then echoing) is the independent oracle. The "client" reconstructs the
        // echo by XOR-ing the two members' plaintext shares.
        use super::super::verify::LeafKeyVerifier;
        use p256::Scalar;
        use std::net::TcpStream;

        let server_addr = spawn_rustls_echo_server();
        let plistener = TcpListener::bind("127.0.0.1:0").unwrap();
        let paddr = plistener.local_addr().unwrap();
        let payload = b"committee 2pc-tls ping".to_vec();

        // Party B (follower): no server connection; carries zeros for the public request.
        let pl = payload.len();
        let b = thread::spawn(move || {
            let mut party = TcpChannel::from_stream(TcpStream::connect(paddr).unwrap());
            let x2 = Scalar::from(0x0f0f_a5a5_1234_5678u64);
            let mut sess = committee_handshake_net(
                &mut party,
                Party::B,
                None,
                "localhost",
                &x2,
                &LeafKeyVerifier,
            )
            .expect("party B handshake");
            committee_send_app(&mut party, &mut sess, None, &vec![0u8; pl]).unwrap();
            committee_recv_app(&mut party, &mut sess, None).unwrap()
        });

        // Party A (lead): holds the connection to rustls.
        let (psock, _) = plistener.accept().unwrap();
        let mut party = TcpChannel::from_stream(psock);
        let mut server = TcpChannel::from_stream(TcpStream::connect(server_addr).unwrap());
        let x1 = Scalar::from(0x1234_5678_9abc_def0u64);
        let mut sess = committee_handshake_net(
            &mut party,
            Party::A,
            Some(&mut server),
            "localhost",
            &x1,
            &LeafKeyVerifier,
        )
        .expect("party A handshake");
        committee_send_app(&mut party, &mut sess, Some(&mut server), &payload).unwrap();
        let share_a = committee_recv_app(&mut party, &mut sess, Some(&mut server)).unwrap();
        let share_b = b.join().unwrap();

        // "Client" reconstruction: XOR the members' inner-plaintext shares, strip padding +
        // the trailing content_type.
        let mut inner: Vec<u8> = share_a.iter().zip(&share_b).map(|(a, b)| a ^ b).collect();
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let ct = inner.pop();
        assert_eq!(ct, Some(REC_APPLICATION_DATA), "inner content_type");
        assert_eq!(
            inner, payload,
            "rustls echoed the committee 2PC-TLS application record"
        );
    }

    #[test]
    fn committee_handshake_amortized_base_ots_still_interops() {
        // Identical to `committee_handshake_against_rustls_and_echo`, but each member wraps its
        // member↔member socket in `AmortizingChannel`, so the whole session's garbled gadgets
        // (key schedule + the app record) share ONE KOS base-OT setup per role — 128 base OTs
        // once, not per gadget. rustls accepting the result is the oracle that the amortized
        // COT path yields byte-identical correct 2PC output: amortization changes cost, not the
        // protocol. Also exercises the per-batch PRG separation + global H tweak over a real
        // multi-gadget session (not just the isolated `kos` batch tests).
        use super::super::channel::AmortizingChannel;
        use super::super::verify::LeafKeyVerifier;
        use p256::Scalar;
        use std::net::TcpStream;

        let server_addr = spawn_rustls_echo_server();
        let plistener = TcpListener::bind("127.0.0.1:0").unwrap();
        let paddr = plistener.local_addr().unwrap();
        let payload = b"amortized committee 2pc-tls ping".to_vec();
        let pl = payload.len();

        let b = thread::spawn(move || {
            let mut raw = TcpChannel::from_stream(TcpStream::connect(paddr).unwrap());
            let mut party = AmortizingChannel::new(&mut raw);
            let x2 = Scalar::from(0x0f0f_a5a5_1234_5678u64);
            let mut sess = committee_handshake_net(
                &mut party,
                Party::B,
                None,
                "localhost",
                &x2,
                &LeafKeyVerifier,
            )
            .expect("party B handshake");
            committee_send_app(&mut party, &mut sess, None, &vec![0u8; pl]).unwrap();
            committee_recv_app(&mut party, &mut sess, None).unwrap()
        });

        let (psock, _) = plistener.accept().unwrap();
        let mut raw = TcpChannel::from_stream(psock);
        let mut party = AmortizingChannel::new(&mut raw);
        let mut server = TcpChannel::from_stream(TcpStream::connect(server_addr).unwrap());
        let x1 = Scalar::from(0x1234_5678_9abc_def0u64);
        let mut sess = committee_handshake_net(
            &mut party,
            Party::A,
            Some(&mut server),
            "localhost",
            &x1,
            &LeafKeyVerifier,
        )
        .expect("party A handshake");
        committee_send_app(&mut party, &mut sess, Some(&mut server), &payload).unwrap();
        let share_a = committee_recv_app(&mut party, &mut sess, Some(&mut server)).unwrap();
        let share_b = b.join().unwrap();

        let mut inner: Vec<u8> = share_a.iter().zip(&share_b).map(|(a, b)| a ^ b).collect();
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let ct = inner.pop();
        assert_eq!(ct, Some(REC_APPLICATION_DATA), "inner content_type");
        assert_eq!(inner, payload, "amortized committee 2PC-TLS echo matches");
    }

    #[test]
    fn live_handshake_against_rustls_server_and_echo() {
        // The end-to-end M45 proof: two 2PC client parties jointly complete a real
        // TLS 1.3 handshake against a stock rustls server and exchange application data.
        // rustls accepting our ClientHello, its flight decrypting under the 2PC-derived
        // server key, its Finished verifying against our 2PC MAC, and its decrypting our
        // 2PC-protected Finished + app data (then echoing) is the independent oracle.
        let addr = spawn_rustls_echo_server();
        let mut ch = TcpChannel::connect(addr).unwrap();

        let mut session = client_handshake(&mut ch, "localhost").expect("2PC TLS 1.3 handshake");

        let payload = b"neo-2pc-tls ping";
        send_application(&mut ch, &mut session, payload).expect("send app data");
        let echo = recv_application(&mut ch, &mut session).expect("recv echo");
        assert_eq!(
            echo, payload,
            "rustls echoed the 2PC-encrypted application record"
        );
    }

    #[test]
    #[ignore] // ~5 min (semi-honest garbling of the handshake + a KeyUpdate); run explicitly
    fn live_handshake_with_key_update_against_rustls() {
        // After a real handshake, the 2PC client performs a TLS 1.3 KeyUpdate (RFC 8446
        // §7.2): it rekeys its write path under 2PC and keeps sending — rustls must process
        // the KeyUpdate, rekey its read path, and still decrypt + echo the post-update
        // application record. Interop proof that the 2PC KeyUpdate is wire-correct.
        let addr = spawn_rustls_echo_server();
        let mut ch = TcpChannel::connect(addr).unwrap();
        let mut session = client_handshake(&mut ch, "localhost").expect("handshake");

        session
            .send_key_update(&mut ch, false)
            .expect("send KeyUpdate + rekey write");

        let payload = b"post-keyupdate ping";
        send_application(&mut ch, &mut session, payload).expect("send under updated key");
        let echo = recv_application(&mut ch, &mut session).expect("recv echo");
        assert_eq!(echo, payload, "rustls decrypted the post-KeyUpdate record");
    }

    #[test]
    #[ignore] // ~15-20 min: the entire live session under authenticated garbling
    fn live_handshake_under_malicious_engine() {
        // Malicious-live end-to-end: the whole TLS 1.3 session — key schedule + every
        // record — runs under the WRK17/KRRW18 authenticated-garbling online, against the
        // same stock rustls server. Far slower than the semi-honest path, so ignored by
        // default; run with `--ignored --release`.
        let addr = spawn_rustls_echo_server();
        let mut ch = TcpChannel::connect(addr).unwrap();

        let mut session = client_handshake_with_engine(&mut ch, "localhost", EngineKind::Malicious)
            .expect("malicious 2PC TLS 1.3 handshake");

        let payload = b"neo-malicious ping";
        send_application(&mut ch, &mut session, payload).expect("send app data");
        let echo = recv_application(&mut ch, &mut session).expect("recv echo");
        assert_eq!(echo, payload, "malicious-engine session echoed the record");
    }
}
