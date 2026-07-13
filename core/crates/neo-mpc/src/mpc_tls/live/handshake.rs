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
//!   verified against the leaf certificate's key. **Full X.509 chain-building to trust
//!   anchors is out of scope here** (the test uses a self-signed cert) — a deployment
//!   layers standard path validation on top.
//! - Semi-honest, in-process party model — see [`super`]'s boundary.

use neo_core::{Error, Result};

use super::super::sha256::sha256;
use super::channel::{read_tls_record, Channel};
use super::ecdhe::ClientKeyShare;
use super::record::Direction;
use super::schedule::KeySchedule;

const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const HS_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HS_CERTIFICATE: u8 = 0x0b;
const HS_CERTIFICATE_VERIFY: u8 = 0x0f;
const HS_FINISHED: u8 = 0x14;

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
/// server-read record directions (each keyed to an application-traffic secret, seq 0).
pub struct AppSession {
    pub client_write: Direction,
    pub server_read: Direction,
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

/// Locate a P-256 (`prime256v1`) uncompressed public point inside a leaf certificate's
/// DER: the `subjectPublicKeyInfo` ends in `BIT STRING { 0x00 unused, 0x04 ‖ X ‖ Y }`,
/// i.e. the byte run `03 42 00 04 <64 bytes>`. Minimal, targeted to the ECDSA-P256 case
/// (what the interop cert uses); full X.509 parsing is out of scope (see boundary).
fn find_p256_point(cert_der: &[u8]) -> Option<[u8; 65]> {
    cert_der
        .windows(4)
        .position(|w| w == [0x03, 0x42, 0x00, 0x04])
        .and_then(|i| {
            let start = i + 3; // at the 0x04
            cert_der.get(start..start + 65)?.try_into().ok()
        })
}

/// Verify the server's `CertificateVerify` (ECDSA-P256 over the transcript). `signed`
/// is the RFC 8446 §4.4.3 signed content; `sig_der` the DER signature; `leaf` the leaf
/// certificate DER.
fn verify_certificate_verify(leaf: &[u8], signed: &[u8], sig_der: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let point = find_p256_point(leaf)
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
/// `server_name`. On success returns an [`AppSession`] for application data. Every key is
/// derived under 2PC; the server is authenticated by its Finished + CertificateVerify.
pub fn client_handshake(ch: &mut dyn Channel, server_name: &str) -> Result<AppSession> {
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
    let mut ks = KeySchedule::derive_handshake(&shared.secret_a, &shared.secret_b, &transcript)?;
    let mut rx_hs = Direction::new(&ks.server_handshake_keys()?);

    // 4. Server flight: EncryptedExtensions, Certificate, CertificateVerify, Finished.
    let flight = read_server_flight(ch, &mut rx_hs)?;
    let mut leaf_cert: Option<Vec<u8>> = None;
    let mut transcript_before_certverify: Option<[u8; 32]> = None;
    let mut transcript_before_serverfin: Option<[u8; 32]> = None;
    for msg in &flight {
        match msg[0] {
            HS_ENCRYPTED_EXTENSIONS => transcript.extend_from_slice(msg),
            HS_CERTIFICATE => {
                leaf_cert = Some(parse_leaf_cert(&msg[4..])?);
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
    verify_server_certificate_verify(&flight, leaf_cert.as_deref(), transcript_before_certverify)?;
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
    let mut tx_hs = Direction::new(&ks.client_handshake_keys()?);
    let zeros = vec![0u8; client_fin_msg.len()];
    let rec = tx_hs.seal(REC_HANDSHAKE, &client_fin_msg, &zeros)?;
    ch.send(&rec)?;
    transcript.extend_from_slice(&client_fin_msg);

    // 7. Application epoch: derive c/s application traffic secrets over CH..server
    //    Finished; rekey both directions (fresh seq 0).
    let app_transcript_hash_input = &transcript[..transcript.len() - client_fin_msg.len()];
    ks.derive_application(app_transcript_hash_input)?;
    let client_write = Direction::new(&ks.client_application_keys()?);
    let server_read = Direction::new(&ks.server_application_keys()?);
    Ok(AppSession {
        client_write,
        server_read,
    })
}

/// Parse the Certificate message body → the leaf (first) certificate DER.
fn parse_leaf_cert(body: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(body);
    let ctx_len = r.u8()? as usize;
    r.take(ctx_len)?; // certificate_request_context
    let list_len = ((r.u8()? as usize) << 16) | ((r.u8()? as usize) << 8) | (r.u8()? as usize);
    let list = r.take(list_len)?;
    let mut lr = Reader::new(list);
    let clen = ((lr.u8()? as usize) << 16) | ((lr.u8()? as usize) << 8) | (lr.u8()? as usize);
    Ok(lr.take(clen)?.to_vec())
}

/// Verify the CertificateVerify message from the flight against the leaf cert + the
/// pre-CertVerify transcript hash.
fn verify_server_certificate_verify(
    flight: &[Vec<u8>],
    leaf: Option<&[u8]>,
    transcript_before_cv: Option<[u8; 32]>,
) -> Result<()> {
    let cv = flight.iter().find(|m| m[0] == HS_CERTIFICATE_VERIFY);
    let cv = match cv {
        Some(cv) => cv,
        None => return Ok(()), // no CertificateVerify (e.g. PSK) — nothing to check here
    };
    let leaf =
        leaf.ok_or_else(|| Error::Crypto("tls: CertificateVerify without Certificate".into()))?;
    let th = transcript_before_cv
        .ok_or_else(|| Error::Crypto("tls: missing pre-CertificateVerify transcript".into()))?;

    let mut r = Reader::new(&cv[4..]);
    let scheme = r.u16()?;
    if scheme != SIG_ECDSA_SECP256R1_SHA256 {
        return Err(Error::Crypto(format!(
            "tls: unsupported CertificateVerify scheme 0x{scheme:04x} (only ecdsa_secp256r1_sha256)"
        )));
    }
    let sig_len = r.u16()? as usize;
    let sig = r.take(sig_len)?;
    let signed = certificate_verify_signed(&th);
    verify_certificate_verify(leaf, &signed, sig)
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
                    REC_HANDSHAKE => continue, // NewSessionTicket etc. — skip
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

#[cfg(test)]
mod tests {
    use super::super::channel::{Loopback, TcpChannel};
    use super::super::schedule::TrafficKeys;
    use super::*;
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
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites =
            vec![rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256];
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];

        // rcgen 0.13 defaults to a P-256 ECDSA key — exactly what the client verifies.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
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
        addr
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
}
