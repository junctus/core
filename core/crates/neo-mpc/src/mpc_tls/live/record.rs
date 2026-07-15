//! The TLS 1.3 record layer under 2PC: **seal** (send) reuses
//! [`seal_tls13_record_shared`](super::super::session::seal_tls13_record_shared); this
//! module adds the matching **open** (receive) — ChaCha20-Poly1305 decrypt-and-verify
//! under 2PC — plus the per-direction sequence-number state a live session needs.
//!
//! Opening a record: the ciphertext + tag arrive **public** on the wire, so the Poly1305
//! MAC is computed over public data with the *shared* one-time key (a bad tag aborts),
//! and decryption XORs the public ciphertext with the shared ChaCha20 keystream. The
//! handshake flight is then **opened** (server-authenticated public data both parties
//! validate); application data can instead be kept in shares (see [`Direction::open_shared`]).

use neo_core::{Error, Result};

use super::super::engine::EngineKind;
use super::super::poly1305::tag_shared_multi_engine;
use super::super::session::{seal_tls13_record_shared_engine, share_keystream_engine};
use super::schedule::TrafficKeys;

/// The TLS 1.3 per-record nonce (RFC 8446 §5.3): `static_iv XOR seq` (seq big-endian in
/// the low 8 bytes).
fn tls13_nonce(static_iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *static_iv;
    for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *n ^= s;
    }
    nonce
}

/// The public Poly1305 message for the AEAD: `AAD ‖ pad16 ‖ CT ‖ pad16 ‖ len(AAD)_LE ‖
/// len(CT)_LE`, as 16-byte blocks (RFC 8439 §2.8).
fn poly_blocks(aad: &[u8], ct: &[u8]) -> Vec<[u8; 16]> {
    let mut data = Vec::new();
    data.extend_from_slice(aad);
    while data.len() % 16 != 0 {
        data.push(0);
    }
    data.extend_from_slice(ct);
    while data.len() % 16 != 0 {
        data.push(0);
    }
    data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    data.chunks(16)
        .map(|c| {
            let mut b = [0u8; 16];
            b[..c.len()].copy_from_slice(c);
            b
        })
        .collect()
}

/// Constant-time 16-byte equality (tag comparison must not leak via timing).
fn ct_eq16(a: &[u8], b: &[u8; 16]) -> bool {
    if a.len() != 16 {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Decrypt-and-verify one TLS 1.3 `application_data` record under 2PC, returning the
/// **opened** `(inner_content_type, plaintext)`. `record_body` is the record after the
/// 5-byte header (`ciphertext ‖ 16-byte tag`); `static_iv`/`seq` are public. A bad tag
/// aborts (the record is inauthentic).
pub fn open_tls13_record_shared(
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    static_iv: &[u8; 12],
    seq: u64,
    record_body: &[u8],
) -> Result<(u8, Vec<u8>)> {
    open_tls13_record_shared_engine(
        EngineKind::Semihonest,
        key_a,
        key_b,
        static_iv,
        seq,
        record_body,
    )
}

/// [`open_tls13_record_shared`] under a chosen 2PC [`EngineKind`].
pub fn open_tls13_record_shared_engine(
    engine: EngineKind,
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    static_iv: &[u8; 12],
    seq: u64,
    record_body: &[u8],
) -> Result<(u8, Vec<u8>)> {
    let (ct_a, ct_b, tag) = open_shares(engine, key_a, key_b, static_iv, seq, record_body)?;
    // Open: plaintext = ct_a ⊕ ct_b (ct_a already folds in the public ciphertext).
    let _ = tag;
    let mut pt: Vec<u8> = ct_a.iter().zip(&ct_b).map(|(a, b)| a ^ b).collect();
    // Strip TLSInnerPlaintext: drop zero padding, then the trailing real content_type.
    while pt.last() == Some(&0) {
        pt.pop();
    }
    let content_type = pt
        .pop()
        .ok_or_else(|| Error::Crypto("record: empty TLSInnerPlaintext".into()))?;
    Ok((content_type, pt))
}

/// The shares-preserving core of [`open_tls13_record_shared`]: verifies the tag (abort on
/// failure) and returns XOR-shares `(pt_a, pt_b)` of the *inner* plaintext (still
/// including the trailing content-type byte) plus the verified tag. `pt_a` folds in the
/// public ciphertext, so `pt_a ⊕ pt_b` is the plaintext but neither share alone reveals it.
fn open_shares(
    engine: EngineKind,
    key_a: &[u8; 32],
    key_b: &[u8; 32],
    static_iv: &[u8; 12],
    seq: u64,
    record_body: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, [u8; 16])> {
    if record_body.len() < 16 {
        return Err(Error::Crypto("record: shorter than the AEAD tag".into()));
    }
    let (ct, tag) = record_body.split_at(record_body.len() - 16);
    let nonce = tls13_nonce(static_iv, seq);

    // AAD = the 5-byte TLS 1.3 record header carrying the true (ciphertext+tag) length.
    let length = record_body.len() as u16;
    let header = [0x17, 0x03, 0x03, (length >> 8) as u8, length as u8];

    // 1. Verify the tag: Poly1305 over public (AAD‖CT) with the shared one-time key
    //    (= keystream block 0). Combine the tag shares only to compare — abort on mismatch.
    let ks0 = share_keystream_engine(engine, key_a, key_b, 0, &nonce)?;
    let poly_a: [u8; 32] = ks0.share_a[..32].try_into().expect("32");
    let poly_b: [u8; 32] = ks0.share_b[..32].try_into().expect("32");
    let (ta, tb) = tag_shared_multi_engine(engine, &poly_a, &poly_b, &poly_blocks(&header, ct))?;
    let got: [u8; 16] = core::array::from_fn(|i| ta[i] ^ tb[i]);
    if !ct_eq16(tag, &got) {
        return Err(Error::Crypto(
            "record: AEAD tag verification failed (inauthentic record — abort)".into(),
        ));
    }

    // 2. Decrypt into shares: pt_a = CT ⊕ ks.share_a (folds in the public CT), pt_b = ks.share_b.
    let mut pt_a = vec![0u8; ct.len()];
    let mut pt_b = vec![0u8; ct.len()];
    for j in 0..ct.len().div_ceil(64) {
        let ks = share_keystream_engine(engine, key_a, key_b, 1 + j as u32, &nonce)?;
        let off = j * 64;
        let end = (off + 64).min(ct.len());
        for i in off..end {
            pt_a[i] = ct[i] ^ ks.share_a[i - off];
            pt_b[i] = ks.share_b[i - off];
        }
    }
    Ok((pt_a, pt_b, got))
}

/// One direction of a live record channel: a traffic key/IV (key shared, IV public), an
/// independent record sequence counter (RFC 8446 §5.3 — resets to 0 on each key epoch),
/// and the 2PC [`EngineKind`] its seal/open circuits run under.
pub struct Direction {
    engine: EngineKind,
    key_a: [u8; 32],
    key_b: [u8; 32],
    iv: [u8; 12],
    seq: u64,
}

impl Direction {
    /// A semi-honest direction (the live default).
    pub fn new(keys: &TrafficKeys) -> Self {
        Self::with_engine(EngineKind::Semihonest, keys)
    }

    /// A direction whose seal/open circuits run under `engine`.
    pub fn with_engine(engine: EngineKind, keys: &TrafficKeys) -> Self {
        Direction {
            engine,
            key_a: keys.key_a,
            key_b: keys.key_b,
            iv: keys.iv,
            seq: 0,
        }
    }

    /// Seal one record of shared `content` under this direction's key, advancing the
    /// sequence number. Returns the exact wire bytes (`header ‖ ciphertext ‖ tag`).
    pub fn seal(&mut self, content_type: u8, pt_a: &[u8], pt_b: &[u8]) -> Result<Vec<u8>> {
        let rec = seal_tls13_record_shared_engine(
            self.engine,
            &self.key_a,
            &self.key_b,
            &self.iv,
            self.seq,
            content_type,
            pt_a,
            pt_b,
        )?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("tls: record sequence number space exhausted".into()))?;
        Ok(rec)
    }

    /// Open one record body (post-header), advancing the sequence number; returns the
    /// opened `(inner_content_type, plaintext)`.
    pub fn open(&mut self, record_body: &[u8]) -> Result<(u8, Vec<u8>)> {
        let out = open_tls13_record_shared_engine(
            self.engine,
            &self.key_a,
            &self.key_b,
            &self.iv,
            self.seq,
            record_body,
        )?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("tls: record sequence number space exhausted".into()))?;
        Ok(out)
    }

    /// Open one record body but keep the *body* plaintext in XOR-shares (for application
    /// data that must not be assembled at either party). Returns `(content_type, pt_a,
    /// pt_b)` where `pt_a ⊕ pt_b` is the content and neither share alone reveals it.
    ///
    /// Only the TLSInnerPlaintext *boundary* is opened: the trailing zero-padding run and
    /// the single content-type byte (structure/length information TLS already exposes via
    /// record framing) are located by scanning the tail — each tail byte's
    /// `pt_a[i] ⊕ pt_b[i]` is combined one at a time, stopping at the first non-zero. The
    /// interior body bytes `[0..end-1]` are **never** XOR-combined, so the content stays
    /// shared. (In a real garbler/evaluator split this is a per-byte equality-open on the
    /// tail, not a full-record reveal.)
    pub fn open_shared(&mut self, record_body: &[u8]) -> Result<(u8, Vec<u8>, Vec<u8>)> {
        let (mut pt_a, mut pt_b, _tag) = open_shares(
            self.engine,
            &self.key_a,
            &self.key_b,
            &self.iv,
            self.seq,
            record_body,
        )?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("tls: record sequence number space exhausted".into()))?;
        // Tail-only scan: combine one byte at a time from the end, never the interior body.
        let mut end = pt_a.len();
        while end > 0 && (pt_a[end - 1] ^ pt_b[end - 1]) == 0 {
            end -= 1;
        }
        if end == 0 {
            return Err(Error::Crypto("record: empty TLSInnerPlaintext".into()));
        }
        let content_type = pt_a[end - 1] ^ pt_b[end - 1]; // the one opened content-type byte
        pt_a.truncate(end - 1);
        pt_b.truncate(end - 1);
        Ok((content_type, pt_a, pt_b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(pt: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let a: Vec<u8> = pt
            .iter()
            .enumerate()
            .map(|(i, _)| (i as u8).wrapping_mul(31))
            .collect();
        let b: Vec<u8> = pt.iter().zip(&a).map(|(p, x)| p ^ x).collect();
        (a, b)
    }

    #[test]
    #[ignore] // ~40s in release (authenticated garbling); run with `--ignored --release`
    fn malicious_engine_record_round_trips() {
        // Malicious-live record layer: a record sealed + opened under the authenticated-
        // garbling online recovers the same plaintext (the ChaCha20 keystream + Poly1305
        // tag circuits run under `EngineKind::Malicious`). Small payload to bound time.
        let keys = TrafficKeys {
            key_a: [0x11; 32],
            key_b: core::array::from_fn(|i| (i as u8) ^ 0x77),
            iv: [0x24; 12],
        };
        let mut tx = Direction::with_engine(EngineKind::Malicious, &keys);
        let mut rx = Direction::with_engine(EngineKind::Malicious, &keys);
        let msg = b"hi";
        let (pa, pb) = split(msg);
        let record = tx.seal(0x17, &pa, &pb).unwrap();
        let (ctype, pt) = rx.open(&record[5..]).unwrap();
        assert_eq!(ctype, 0x17, "malicious open recovers content type");
        assert_eq!(pt, msg, "malicious seal/open round-trips");
    }

    #[test]
    fn seal_then_open_round_trips_under_2pc() {
        // Independent key shares + IV; a record sealed under 2PC must open under 2PC to
        // the same plaintext + content type, and a bit-flip must abort.
        let keys = TrafficKeys {
            key_a: [0x11; 32],
            key_b: core::array::from_fn(|i| (i as u8) ^ 0x77),
            iv: [0x24; 12],
        };
        let mut tx = Direction::new(&keys);
        let mut rx = Direction::new(&keys);

        let msg = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let (pa, pb) = split(msg);
        let record = tx.seal(0x17, &pa, &pb).unwrap();

        // Body is the record minus the 5-byte header.
        let (ctype, pt) = rx.open(&record[5..]).unwrap();
        assert_eq!(ctype, 0x17, "application_data content type recovered");
        assert_eq!(pt, msg, "2PC open recovers the sealed plaintext");

        // Tamper one ciphertext byte → tag verify aborts.
        let mut bad = record.clone();
        bad[7] ^= 1;
        let mut rx2 = Direction::new(&keys);
        assert!(rx2.open(&bad[5..]).is_err(), "a tampered record must abort");
    }

    #[test]
    fn open_matches_stock_chacha20poly1305() {
        // Seal with the STOCK chacha20poly1305 crate (key = key_a ⊕ key_b, nonce =
        // iv ⊕ seq, AAD = the TLS header) and confirm the 2PC open decrypts + verifies it
        // — proving open() interoperates with a real AEAD, not just our own seal().
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        let key_a = [0x09u8; 32];
        let key_b: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(3));
        let iv = [0x31u8; 12];
        let key_combined: [u8; 32] = core::array::from_fn(|i| key_a[i] ^ key_b[i]);

        let seq = 0u64;
        let nonce = tls13_nonce(&iv, seq);
        let inner = b"hello world\x17".to_vec(); // content ‖ content_type(0x17)
        let length = (inner.len() + 16) as u16;
        let header = [0x17, 0x03, 0x03, (length >> 8) as u8, length as u8];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_combined));
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &inner,
                    aad: &header,
                },
            )
            .unwrap();

        let mut rx = Direction::new(&TrafficKeys { key_a, key_b, iv });
        let (ctype, pt) = rx.open(&sealed).unwrap();
        assert_eq!(ctype, 0x17);
        assert_eq!(pt, b"hello world");
    }
}
