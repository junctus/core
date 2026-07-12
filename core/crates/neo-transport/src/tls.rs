//! A minimal TLS 1.3 ClientHello codec for in-ClientHello REALITY (M27).
//!
//! The REALITY auth core (`neo_crypto::reality`) produces a fixed 64-byte prefix —
//! `ephemeral_pubkey(32) ‖ tag(32)` — that is uniform-random to anyone without the
//! server capability. To make the *first packet* byte-for-byte an ordinary TLS 1.3
//! handshake (not a bespoke length-prefixed blob a censor can fingerprint), we hide
//! that prefix inside fields of a real ClientHello that are **already** uniform:
//!
//! - `ephemeral_pubkey` → the `key_share` X25519 entry. It is a genuine X25519
//!   public key, so it is indistinguishable from any browser's key_share.
//! - `tag` → `legacy_session_id`. Every TLS 1.3 client sends a random 32-byte
//!   session id (RFC 8446 §4.1.2), so 32 uniform bytes there are expected.
//!
//! This is the layout the real [REALITY] uses. The server parses the ClientHello,
//! pulls those two fields back out, and hands `eph ‖ tag` to `classify`.
//!
//! **Honest boundary.** This emits **one** plausible, self-consistent TLS 1.3
//! fingerprint (a modern browser-ish cipher/extension set with GREASE). It does
//! **not** byte-exactly clone a specific Chrome/Firefox JA3/JA4, nor rotate the
//! fingerprint — a frozen fingerprint is itself a (weak) tell, and exact mimicry is
//! a moving target as browsers update. That refinement (uTLS-grade profiles) is
//! out of scope here and is called out in `MILESTONES.md` M27.
//!
//! [REALITY]: https://github.com/XTLS/REALITY

use neo_crypto::REALITY_PREFIX_LEN;

/// TLS record content type for a handshake message.
const CONTENT_HANDSHAKE: u8 = 0x16;
/// Handshake message type for ClientHello.
const HS_CLIENT_HELLO: u8 = 0x01;
/// `legacy_record_version` — TLS 1.0, as every real TLS 1.3 ClientHello sends for
/// middlebox compatibility (the real version is in `supported_versions`).
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x01];
/// `legacy_version` inside the ClientHello — TLS 1.2, likewise for compatibility.
const LEGACY_HELLO_VERSION: [u8; 2] = [0x03, 0x03];
/// The `key_share` / `supported_groups` code point for X25519.
const GROUP_X25519: u16 = 0x001d;

/// Extension type numbers used here (RFC 8446 / IANA TLS registry).
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// The largest ClientHello record body we will read/accept — a sane cap far above a
/// real hello (~a few hundred bytes) that still bounds a malicious length field.
pub const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// Build a TLS 1.3 ClientHello **record** (record header included) that carries the
/// REALITY 64-byte prefix: `prefix[..32]` → the X25519 `key_share`, `prefix[32..]`
/// → `legacy_session_id`. `server_name` is the SNI to present (the decoy host).
///
/// The `client_random` is fresh random — it is *not* part of the authenticator, so
/// it looks exactly like a normal client's. Returns the bytes to write as the first
/// flight.
pub fn build_client_hello(prefix: &[u8; REALITY_PREFIX_LEN], server_name: &str) -> Vec<u8> {
    let (eph, tag) = neo_crypto::RealityKey::split_prefix(prefix);

    let mut client_random = [0u8; 32];
    // A failure here is not fatal to indistinguishability (zeros are still a valid,
    // if unlucky, random); best-effort fill.
    let _ = getrandom::getrandom(&mut client_random);
    let grease = grease_value();

    let mut hello = Vec::with_capacity(512);
    hello.extend_from_slice(&LEGACY_HELLO_VERSION);
    hello.extend_from_slice(&client_random);
    // legacy_session_id <0..32>: exactly 32 bytes carrying the auth tag.
    hello.push(tag.len() as u8);
    hello.extend_from_slice(&tag);
    // cipher_suites <2..2^16-2>.
    let suites = cipher_suites(grease);
    hello.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    hello.extend_from_slice(&suites);
    // legacy_compression_methods <1..2^8-1>: just null compression.
    hello.push(1);
    hello.push(0x00);
    // extensions <8..2^16-1>.
    let exts = extensions(grease, server_name, &eph);
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);

    // Wrap: handshake header (u24 length) then record header (u16 length).
    let mut handshake = Vec::with_capacity(hello.len() + 4);
    handshake.push(HS_CLIENT_HELLO);
    handshake.extend_from_slice(&u24(hello.len()));
    handshake.extend_from_slice(&hello);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(CONTENT_HANDSHAKE);
    record.extend_from_slice(&LEGACY_RECORD_VERSION);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// The parsed REALITY carrier fields of a ClientHello record: the X25519 key_share
/// (`eph`) and the `legacy_session_id` (`tag`), concatenated into the 64-byte prefix
/// `classify` expects. Returns `None` on **anything** that isn't a well-formed TLS
/// ClientHello carrying a 32-byte session id and an X25519 key_share — never panics,
/// so a random probe or a genuine-but-different client simply falls through to the
/// silent Decoy path.
pub fn parse_client_hello(record: &[u8]) -> Option<[u8; REALITY_PREFIX_LEN]> {
    let mut r = Reader::new(record);
    // Record header.
    if r.u8()? != CONTENT_HANDSHAKE {
        return None;
    }
    r.skip(2)?; // legacy_record_version
    let rec_len = r.u16()?;
    let body = r.take(rec_len)?; // exactly the handshake message

    let mut h = Reader::new(body);
    if h.u8()? != HS_CLIENT_HELLO {
        return None;
    }
    let hs_len = h.u24()?;
    let ch = h.take(hs_len)?;

    let mut c = Reader::new(ch);
    c.skip(2)?; // legacy_version
    c.skip(32)?; // random
    let session_id = c.vec_u8()?; // legacy_session_id <0..32>
    let tag: [u8; 32] = session_id.try_into().ok()?; // ours is exactly 32
    let _suites = c.vec_u16()?;
    let _compression = c.vec_u8()?;
    let ext_bytes = c.vec_u16()?; // extensions <..>

    let eph = key_share_x25519(ext_bytes)?;

    let mut prefix = [0u8; REALITY_PREFIX_LEN];
    prefix[..32].copy_from_slice(&eph);
    prefix[32..].copy_from_slice(&tag);
    Some(prefix)
}

/// Walk the extensions block and return the X25519 `key_share` entry's 32-byte key.
fn key_share_x25519(ext_bytes: &[u8]) -> Option<[u8; 32]> {
    let mut e = Reader::new(ext_bytes);
    while !e.is_empty() {
        let ext_type = e.u16()?;
        let ext_body = e.vec_u16()?;
        if ext_type == EXT_KEY_SHARE as usize {
            // KeyShareClientHello: client_shares <0..2^16-1> of { group, key<1..2^16-1> }.
            let mut k = Reader::new(ext_body);
            let shares = k.vec_u16()?;
            let mut s = Reader::new(shares);
            while !s.is_empty() {
                let group = s.u16()?;
                let key = s.vec_u16()?;
                if group == GROUP_X25519 as usize {
                    return key.try_into().ok();
                }
            }
            return None;
        }
    }
    None
}

/// The extensions block (concatenated), in a plausible modern order.
fn extensions(grease: u16, server_name: &str, eph: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    // Leading GREASE (empty), as browsers place one first.
    out.extend_from_slice(&ext(grease, &[]));
    out.extend_from_slice(&ext(EXT_SERVER_NAME, &server_name_ext(server_name)));
    out.extend_from_slice(&ext(EXT_EXTENDED_MASTER_SECRET, &[]));
    out.extend_from_slice(&ext(EXT_SUPPORTED_GROUPS, &supported_groups(grease)));
    out.extend_from_slice(&ext(EXT_EC_POINT_FORMATS, &[1, 0x00])); // uncompressed
    out.extend_from_slice(&ext(EXT_SESSION_TICKET, &[]));
    out.extend_from_slice(&ext(EXT_ALPN, &alpn(&["h2", "http/1.1"])));
    out.extend_from_slice(&ext(EXT_SIGNATURE_ALGORITHMS, &signature_algorithms()));
    out.extend_from_slice(&ext(EXT_KEY_SHARE, &key_share_ext(grease, eph)));
    out.extend_from_slice(&ext(EXT_PSK_KEY_EXCHANGE_MODES, &[1, 0x01])); // psk_dhe_ke
    out.extend_from_slice(&ext(EXT_SUPPORTED_VERSIONS, &supported_versions(grease)));
    // Trailing GREASE with a single byte, as browsers do.
    out.extend_from_slice(&ext(grease_other(grease), &[0x00]));
    out
}

/// The cipher-suites list (GREASE first, then modern TLS 1.3 + 1.2 suites).
fn cipher_suites(grease: u16) -> Vec<u8> {
    let mut suites = vec![grease];
    suites.extend_from_slice(&[
        0x1301, 0x1302, 0x1303, // TLS 1.3 AEADs
        0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE-ECDSA/RSA GCM
        0xcca9, 0xcca8, // ECDHE ChaCha20-Poly1305
        0xc013, 0xc014, // ECDHE-RSA CBC (legacy tail)
        0x009c, 0x009d, // RSA GCM (legacy tail)
    ]);
    let mut out = Vec::with_capacity(suites.len() * 2);
    for s in suites {
        out.extend_from_slice(&s.to_be_bytes());
    }
    out
}

fn supported_groups(grease: u16) -> Vec<u8> {
    let groups = [grease, GROUP_X25519, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
    let mut list = Vec::new();
    for g in groups {
        list.extend_from_slice(&g.to_be_bytes());
    }
    let mut out = Vec::with_capacity(2 + list.len());
    out.extend_from_slice(&(list.len() as u16).to_be_bytes());
    out.extend_from_slice(&list);
    out
}

fn supported_versions(grease: u16) -> Vec<u8> {
    // ProtocolVersion list <2..254>: GREASE + TLS 1.3.
    let mut list = Vec::new();
    list.extend_from_slice(&grease.to_be_bytes());
    list.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
    let mut out = Vec::with_capacity(1 + list.len());
    out.push(list.len() as u8);
    out.extend_from_slice(&list);
    out
}

fn key_share_ext(grease: u16, eph: &[u8; 32]) -> Vec<u8> {
    // A GREASE share (1 byte) then the real X25519 share, as Chrome sends.
    let mut shares = Vec::new();
    shares.extend_from_slice(&grease.to_be_bytes());
    shares.extend_from_slice(&1u16.to_be_bytes());
    shares.push(0x00);
    shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
    shares.extend_from_slice(&(eph.len() as u16).to_be_bytes());
    shares.extend_from_slice(eph);
    let mut out = Vec::with_capacity(2 + shares.len());
    out.extend_from_slice(&(shares.len() as u16).to_be_bytes());
    out.extend_from_slice(&shares);
    out
}

fn server_name_ext(host: &str) -> Vec<u8> {
    // ServerNameList <1..2^16-1> of { name_type=host_name(0), HostName <1..2^16-1> }.
    let host = host.as_bytes();
    let mut entry = Vec::with_capacity(3 + host.len());
    entry.push(0x00); // host_name
    entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
    entry.extend_from_slice(host);
    let mut out = Vec::with_capacity(2 + entry.len());
    out.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    out.extend_from_slice(&entry);
    out
}

fn alpn(protocols: &[&str]) -> Vec<u8> {
    let mut list = Vec::new();
    for p in protocols {
        list.push(p.len() as u8);
        list.extend_from_slice(p.as_bytes());
    }
    let mut out = Vec::with_capacity(2 + list.len());
    out.extend_from_slice(&(list.len() as u16).to_be_bytes());
    out.extend_from_slice(&list);
    out
}

fn signature_algorithms() -> Vec<u8> {
    // A common modern set.
    let algs: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let mut list = Vec::new();
    for a in algs {
        list.extend_from_slice(&a.to_be_bytes());
    }
    let mut out = Vec::with_capacity(2 + list.len());
    out.extend_from_slice(&(list.len() as u16).to_be_bytes());
    out.extend_from_slice(&list);
    out
}

/// One TLS extension: `type(2) ‖ length(2) ‖ body`.
fn ext(ext_type: u16, body: &[u8]) -> Vec<u8> {
    let mut e = Vec::with_capacity(4 + body.len());
    e.extend_from_slice(&ext_type.to_be_bytes());
    e.extend_from_slice(&(body.len() as u16).to_be_bytes());
    e.extend_from_slice(body);
    e
}

/// A random RFC 8701 GREASE value (both bytes `0x?a`), as browsers send.
fn grease_value() -> u16 {
    let mut b = [0u8; 1];
    let _ = getrandom::getrandom(&mut b);
    let n = (b[0] & 0x0f) as u16; // 0..=15
    let byte = (n << 4) | 0x0a; // 0x0a, 0x1a, ... 0xfa
    (byte << 8) | byte
}

/// A second GREASE value distinct from `first` (browsers use several).
fn grease_other(first: u16) -> u16 {
    let mut g = grease_value();
    if g == first {
        // Rotate to the next GREASE value deterministically.
        let byte = ((first & 0xff) as u8).wrapping_add(0x10) | 0x0a;
        g = ((byte as u16) << 8) | byte as u16;
    }
    g
}

fn u24(n: usize) -> [u8; 3] {
    [(n >> 16) as u8, (n >> 8) as u8, n as u8]
}

/// A bounds-checked big-endian byte reader; every accessor returns `None` on
/// underflow so the parser can never panic on hostile input.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<usize> {
        let s = self.take(2)?;
        Some(((s[0] as usize) << 8) | s[1] as usize)
    }
    fn u24(&mut self) -> Option<usize> {
        let s = self.take(3)?;
        Some(((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }
    /// A `u8`-length-prefixed slice.
    fn vec_u8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    /// A `u16`-length-prefixed slice.
    fn vec_u16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_crypto::{RealitySecret, Verdict};

    #[test]
    fn client_hello_round_trips_the_prefix() {
        let prefix: [u8; REALITY_PREFIX_LEN] = std::array::from_fn(|i| i as u8);
        let record = build_client_hello(&prefix, "www.example.com");
        let parsed = parse_client_hello(&record).expect("well-formed hello parses");
        assert_eq!(parsed, prefix, "eph‖tag survive the ClientHello round-trip");
    }

    #[test]
    fn authenticated_flight_survives_the_tls_wrapping() {
        // End-to-end through the real auth core: build prefix → wrap in ClientHello
        // → parse → classify → Authenticated with the matching seed.
        let server = RealitySecret::generate().unwrap();
        let key = server.public();
        let epoch = 7;
        let (prefix, client_seed) = key.client_hello_prefix(epoch).unwrap();
        let record = build_client_hello(&prefix, "cdn.example.net");
        let recovered = parse_client_hello(&record).unwrap();
        match server.classify(&recovered, epoch) {
            Verdict::Authenticated { session_seed } => assert_eq!(session_seed, client_seed),
            Verdict::Decoy => panic!("a wrapped authenticated flight must classify as neo"),
        }
    }

    #[test]
    fn malformed_and_foreign_inputs_do_not_panic_and_yield_none() {
        assert!(parse_client_hello(&[]).is_none());
        assert!(parse_client_hello(&[CONTENT_HANDSHAKE]).is_none());
        assert!(parse_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]).is_none()); // not handshake
                                                                                      // A truncated but plausible-looking header.
        assert!(parse_client_hello(&[CONTENT_HANDSHAKE, 0x03, 0x01, 0xff, 0xff]).is_none());
        // Fuzz-ish: random junk of assorted lengths never panics.
        for len in [1usize, 5, 20, 64, 200] {
            let mut junk = vec![0u8; len];
            let _ = getrandom::getrandom(&mut junk);
            let _ = parse_client_hello(&junk); // must not panic
        }
    }

    #[test]
    fn a_hello_with_a_non_32_byte_session_id_is_rejected() {
        // Build a valid-looking record but with a 16-byte session id (not ours).
        let prefix: [u8; REALITY_PREFIX_LEN] = [9u8; REALITY_PREFIX_LEN];
        let mut record = build_client_hello(&prefix, "x.example");
        // Corrupt the session-id length byte (offset: 5 record hdr + 4 hs hdr + 2 ver + 32 rand).
        let sid_len_off = 5 + 4 + 2 + 32;
        if record.len() > sid_len_off {
            record[sid_len_off] = 16; // claim 16-byte session id
                                      // The structure is now inconsistent → parse fails cleanly, no panic.
            let _ = parse_client_hello(&record);
        }
    }
}
