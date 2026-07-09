//! PQ-hybrid, mutually-authenticated key exchange with key confirmation.
//!
//! A three-message handshake in the spirit of TLS 1.3's hybrid key exchange:
//! session keys are derived from **both** an ephemeral X25519 Diffie–Hellman and
//! an ephemeral **ML-KEM-768** encapsulation, so the session stays secure if
//! *either* primitive holds (defense against "harvest-now, decrypt-later").
//! Each party's **full self-certifying `NodeId`** (all three long-term keys) is
//! bound into the signed transcript, giving mutual authentication with no
//! unknown-key-share, and forward secrecy from the ephemerals.
//!
//! ```text
//! initiator I                          responder R
//! ----------                           -----------
//! m1: eph X25519 pk, eph ML-KEM ek,  --->  verify sig_I, bind NodeId_I
//!     id_I(sign,kex,kem), sig_I
//!                              <---  m2: eph X25519 pk, ML-KEM ct(ek),
//!                                        id_R(sign,kex,kem), sig_R
//! verify sig_R, bind NodeId_R
//! shared = HKDF( x25519_dh || mlkem_ss , transcript )
//! m3: MAC_kconfirm(transcript)       --->  verify → session established
//! ```
//!
//! The **key-confirmation (m3)** flight means the responder never treats the
//! session as live — or emits application data — until it has proof the
//! initiator derived the same key and is live, so a replayed or forged m1 can
//! never establish a confirmed session.
//!
//! Not a formally analyzed Noise pattern — it is a straightforward signed hybrid
//! KEX and must be reviewed/audited before real use (see `docs/CRYPTO.md`).

use blake3::Hasher;
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};
use neo_core::{Error, NodeId, NodeIdentity, Result};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::session::Session;

const DOMAIN: &[u8] = b"neo-handshake-v1";
const COOKIE_DOMAIN: &[u8] = b"neo-handshake-cookie-v1";

/// A responder's ephemeral secret for stateless anti-DoS cookies.
///
/// Generated fresh **per accepted connection**, so it needs no rotation and no
/// cross-connection state — it only has to survive the single cookie
/// round-trip. The cookie is a cheap MAC the responder issues *before* doing any
/// ML-KEM work; the initiator must echo it in a re-sent m1. A replayed or
/// connect-and-abandon m1 therefore costs only a MAC, never a KEM encapsulation.
pub struct CookieKey([u8; 32]);

impl CookieKey {
    /// Generate a fresh cookie key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self(random_32()?))
    }

    /// The cookie bound to an initiator's ephemeral X25519 key.
    fn cookie(&self, eph_x_pub_i: &[u8]) -> [u8; 32] {
        let mut h = Hasher::new_keyed(&self.0);
        h.update(COOKIE_DOMAIN);
        h.update(eph_x_pub_i);
        *h.finalize().as_bytes()
    }
}

/// Wrap a raw m1 with a (possibly empty) anti-DoS cookie prefix. The raw m1 that
/// follows is byte-identical across the first send and the cookied re-send, so
/// the signature and transcript are unaffected by the cookie.
fn wrap_init(cookie: &[u8], m1: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + cookie.len() + m1.len());
    put(&mut v, cookie);
    v.extend_from_slice(m1);
    v
}

/// Split an init message into its cookie prefix and the raw m1 that follows.
fn unwrap_init(init_msg: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut cur = init_msg;
    let cookie = get(&mut cur)?;
    Ok((cookie, cur))
}

/// Cheap first responder step: derive the anti-DoS cookie challenge for an init
/// message **without** any expensive asymmetric work. The responder returns
/// this and awaits a re-sent init message carrying the cookie; only then does
/// [`responder_process`] perform the ML-KEM encapsulation.
pub fn responder_cookie(cookie_key: &CookieKey, init_msg: &[u8]) -> Result<Vec<u8>> {
    let (_cookie, m1) = unwrap_init(init_msg)?;
    let mut cur = m1;
    let eph_x_pub_i = get(&mut cur)?; // the first m1 field
    Ok(cookie_key.cookie(eph_x_pub_i).to_vec())
}

type KemEncapKey = <MlKem768 as KemCore>::EncapsulationKey;
type KemDecapKey = <MlKem768 as KemCore>::DecapsulationKey;

/// Outcome of a completed handshake: the live session and the peer's identity.
pub struct HandshakeResult {
    /// The encrypted, authenticated data channel.
    pub session: Session,
    /// The peer's long-term Ed25519 verifying key (their authenticated identity).
    pub peer: VerifyingKey,
    /// The peer's full self-certifying [`NodeId`], recomputed from all three
    /// long-term keys proven **in-band**. Authorize on this — not on a key from
    /// an out-of-band record — so a handshake cannot be attributed to the wrong
    /// node identity (unknown-key-share).
    pub peer_id: NodeId,
}

/// Initiator state carried between the two handshake messages.
pub struct Initiator {
    eph_x: StaticSecret,
    eph_kem_dk: KemDecapKey,
    msg1: Vec<u8>,
}

impl Initiator {
    /// Re-send m1 carrying the responder's anti-DoS cookie challenge. The raw m1
    /// is unchanged (so its signature and the transcript still hold); only the
    /// cookie prefix differs.
    pub fn with_cookie(&self, cookie: &[u8]) -> Vec<u8> {
        wrap_init(cookie, &self.msg1)
    }
}

/// Responder state between sending m2 and receiving the initiator's key
/// confirmation (m3). The session is **not** live until [`responder_confirm`]
/// verifies m3, so a replayed/forged m1 never yields a usable session.
pub struct PendingResponder {
    session: Session,
    peer: VerifyingKey,
    peer_id: NodeId,
    k_confirm: [u8; 32],
    th: [u8; 32],
}

/// Build the first handshake message (initiator → responder).
pub fn initiator_message1(identity: &NodeIdentity) -> Result<(Initiator, Vec<u8>)> {
    let eph_x = StaticSecret::from(random_32()?);
    let eph_x_pub = PublicKey::from(&eph_x);

    let (eph_kem_dk, eph_kem_ek) = MlKem768::generate(&mut rand_core::OsRng);
    let ek_bytes = eph_kem_ek.as_bytes();

    let nonce = random_32()?;
    let public = identity.public();
    let id_pub = public.signing;
    let kex = *public.kex.as_bytes();
    let kem = public.kem_bytes();

    let signed = bind_m1(
        eph_x_pub.as_bytes(),
        ek_bytes.as_ref(),
        id_pub.as_bytes(),
        &kex,
        &kem,
        &nonce,
    );
    let sig = identity.sign(&signed);

    let mut msg1 = Vec::new();
    put(&mut msg1, eph_x_pub.as_bytes());
    put(&mut msg1, ek_bytes.as_ref());
    put(&mut msg1, id_pub.as_bytes());
    put(&mut msg1, &kex);
    put(&mut msg1, &kem);
    put(&mut msg1, &nonce);
    put(&mut msg1, &sig.to_bytes());

    // The wire message wraps the raw m1 with an (initially empty) cookie prefix.
    let wire = wrap_init(&[], &msg1);
    Ok((
        Initiator {
            eph_x,
            eph_kem_dk,
            msg1,
        },
        wire,
    ))
}

/// Process a cookied init message (m1) and produce message 2 plus a **pending**
/// responder state. Verifies the anti-DoS cookie (issued by [`responder_cookie`]
/// under the same `cookie_key`) **before** any ML-KEM work, so only a
/// round-tripped initiator ever triggers the expensive path. The session becomes
/// live only after [`responder_confirm`] verifies the key confirmation (m3).
pub fn responder_process(
    identity: &NodeIdentity,
    init_msg: &[u8],
    cookie_key: &CookieKey,
) -> Result<(Vec<u8>, PendingResponder)> {
    let (cookie, msg1) = unwrap_init(init_msg)?;
    // Cheap gate first: reject anything without a valid cookie before the KEM.
    let mut peek = msg1;
    let eph_x_pub_i_peek = get(&mut peek)?;
    if !ct_eq(cookie, &cookie_key.cookie(eph_x_pub_i_peek)) {
        return Err(Error::Crypto("missing or invalid handshake cookie".into()));
    }

    let mut cur = msg1;
    let eph_x_pub_i = get(&mut cur)?;
    let ek_i = get(&mut cur)?;
    let id_pub_i = get(&mut cur)?;
    let kex_i = get(&mut cur)?;
    let kem_i = get(&mut cur)?;
    let nonce_i = get(&mut cur)?;
    let sig_i = get(&mut cur)?;
    // Reject trailing bytes: they are not covered by `sig_i` (which signs the
    // parsed fields) but *are* hashed into the transcript, so an on-path
    // attacker appending one byte would desync the two sides' keys — a silent
    // DoS. Refuse the message instead.
    if !cur.is_empty() {
        return Err(Error::Decode(
            "trailing bytes after handshake message 1".into(),
        ));
    }

    let peer = verifying_key(id_pub_i)?;
    let signed = bind_m1(eph_x_pub_i, ek_i, id_pub_i, kex_i, kem_i, nonce_i);
    peer.verify_strict(&signed, &signature(sig_i)?)
        .map_err(|_| Error::Crypto("initiator signature invalid".into()))?;
    let peer_id = node_id_from(id_pub_i, kex_i, kem_i)?;

    // Responder ephemeral X25519 and DH with the initiator's ephemeral.
    let eph_x = StaticSecret::from(random_32()?);
    let eph_x_pub = PublicKey::from(&eph_x);
    let dh = eph_x.diffie_hellman(&public_key(eph_x_pub_i)?).to_bytes();

    // Encapsulate to the initiator's ephemeral ML-KEM key.
    let ek = KemEncapKey::from_bytes(&encoded_ek(ek_i)?);
    let (ct, ss) = ek
        .encapsulate(&mut rand_core::OsRng)
        .map_err(|_| Error::Crypto("ML-KEM encapsulation failed".into()))?;
    let ct_bytes = &ct[..];

    let nonce_r = random_32()?;
    let public_r = identity.public();
    let id_pub_r = public_r.signing;
    let kex_r = *public_r.kex.as_bytes();
    let kem_r = public_r.kem_bytes();
    let th = transcript(
        msg1,
        eph_x_pub.as_bytes(),
        ct_bytes,
        id_pub_r.as_bytes(),
        &kex_r,
        &kem_r,
        &nonce_r,
    );

    let signed_r = bind_m2(
        &th,
        eph_x_pub.as_bytes(),
        ct_bytes,
        id_pub_r.as_bytes(),
        &kex_r,
        &kem_r,
        &nonce_r,
    );
    let sig_r = identity.sign(&signed_r);

    let (k_i2r, k_r2i, k_confirm) = derive_keys(&dh, &shared_to_array(&ss[..])?, &th);

    let mut msg2 = Vec::new();
    put(&mut msg2, eph_x_pub.as_bytes());
    put(&mut msg2, ct_bytes);
    put(&mut msg2, id_pub_r.as_bytes());
    put(&mut msg2, &kex_r);
    put(&mut msg2, &kem_r);
    put(&mut msg2, &nonce_r);
    put(&mut msg2, &sig_r.to_bytes());

    Ok((
        msg2,
        PendingResponder {
            session: Session::new(k_r2i, k_i2r),
            peer,
            peer_id,
            k_confirm,
            th,
        },
    ))
}

/// Complete the responder side: verify the initiator's key confirmation (m3)
/// and return the now-established session. Rejects a bad/absent confirmation, so
/// no application data is ever sent to a party that didn't derive the key.
pub fn responder_confirm(pending: PendingResponder, msg3: &[u8]) -> Result<HandshakeResult> {
    let mut cur = msg3;
    let tag = get(&mut cur)?;
    if !cur.is_empty() {
        return Err(Error::Decode(
            "trailing bytes after key confirmation".into(),
        ));
    }
    let expected = confirm_tag(&pending.k_confirm, &pending.th);
    if !ct_eq(tag, &expected) {
        return Err(Error::Crypto("key confirmation failed".into()));
    }
    Ok(HandshakeResult {
        session: pending.session,
        peer: pending.peer,
        peer_id: pending.peer_id,
    })
}

/// Complete the handshake on the initiator from message 2, returning the key
/// confirmation (m3) to send to the responder plus the established result.
pub fn initiator_finish(state: Initiator, msg2: &[u8]) -> Result<(Vec<u8>, HandshakeResult)> {
    let mut cur = msg2;
    let eph_x_pub_r = get(&mut cur)?;
    let ct_bytes = get(&mut cur)?;
    let id_pub_r = get(&mut cur)?;
    let kex_r = get(&mut cur)?;
    let kem_r = get(&mut cur)?;
    let nonce_r = get(&mut cur)?;
    let sig_r = get(&mut cur)?;
    if !cur.is_empty() {
        return Err(Error::Decode(
            "trailing bytes after handshake message 2".into(),
        ));
    }

    let peer = verifying_key(id_pub_r)?;
    let th = transcript(
        &state.msg1,
        eph_x_pub_r,
        ct_bytes,
        id_pub_r,
        kex_r,
        kem_r,
        nonce_r,
    );
    let signed_r = bind_m2(&th, eph_x_pub_r, ct_bytes, id_pub_r, kex_r, kem_r, nonce_r);
    peer.verify_strict(&signed_r, &signature(sig_r)?)
        .map_err(|_| Error::Crypto("responder signature invalid".into()))?;
    let peer_id = node_id_from(id_pub_r, kex_r, kem_r)?;

    let dh = state
        .eph_x
        .diffie_hellman(&public_key(eph_x_pub_r)?)
        .to_bytes();
    let ct = Ciphertext::<MlKem768>::try_from(ct_bytes)
        .map_err(|_| Error::Decode("bad ML-KEM ciphertext length".into()))?;
    let ss = state
        .eph_kem_dk
        .decapsulate(&ct)
        .map_err(|_| Error::Crypto("ML-KEM decapsulation failed".into()))?;

    let (k_i2r, k_r2i, k_confirm) = derive_keys(&dh, &shared_to_array(&ss[..])?, &th);

    // Produce the key-confirmation message (m3) the responder must verify.
    let mut msg3 = Vec::new();
    put(&mut msg3, &confirm_tag(&k_confirm, &th));

    Ok((
        msg3,
        HandshakeResult {
            session: Session::new(k_i2r, k_r2i),
            peer,
            peer_id,
        },
    ))
}

// ---- helpers ---------------------------------------------------------------

fn derive_keys(
    dh: &[u8; 32],
    ss: &[u8; 32],
    transcript: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh);
    ikm[32..].copy_from_slice(ss);
    let hk = Hkdf::<Sha256>::new(Some(transcript), &ikm);
    let mut k_i2r = [0u8; 32];
    let mut k_r2i = [0u8; 32];
    let mut k_confirm = [0u8; 32];
    hk.expand(b"neo i2r", &mut k_i2r).expect("hkdf i2r");
    hk.expand(b"neo r2i", &mut k_r2i).expect("hkdf r2i");
    hk.expand(b"neo confirm", &mut k_confirm)
        .expect("hkdf confirm");
    (k_i2r, k_r2i, k_confirm)
}

/// The initiator's key-confirmation tag over the transcript, under the derived
/// confirmation key. The responder must see a valid tag before it treats the
/// session as established — proving the initiator is live and derived the same
/// key, so a replayed or forged m1 can never establish a confirmed session.
fn confirm_tag(k_confirm: &[u8; 32], th: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new_keyed(k_confirm);
    h.update(DOMAIN);
    h.update(b"|confirm|");
    h.update(th);
    *h.finalize().as_bytes()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[allow(clippy::too_many_arguments)]
fn transcript(
    msg1: &[u8],
    eph_x_r: &[u8],
    ct: &[u8],
    id_r: &[u8],
    kex_r: &[u8],
    kem_r: &[u8],
    nonce_r: &[u8],
) -> [u8; 32] {
    let mut h = Hasher::new();
    for part in [DOMAIN, msg1, eph_x_r, ct, id_r, kex_r, kem_r, nonce_r] {
        h.update(part);
    }
    *h.finalize().as_bytes()
}

fn bind_m1(eph_x: &[u8], ek: &[u8], id: &[u8], kex: &[u8], kem: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    for part in [DOMAIN, b"|m1|".as_ref(), eph_x, ek, id, kex, kem, nonce] {
        v.extend_from_slice(part);
    }
    v
}

#[allow(clippy::too_many_arguments)]
fn bind_m2(
    th: &[u8],
    eph_x: &[u8],
    ct: &[u8],
    id: &[u8],
    kex: &[u8],
    kem: &[u8],
    nonce: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    for part in [DOMAIN, b"|m2|".as_ref(), th, eph_x, ct, id, kex, kem, nonce] {
        v.extend_from_slice(part);
    }
    v
}

/// Recompute a peer's self-certifying [`NodeId`] from the long-term keys it
/// proved in-band — so the caller authorizes on the identity actually
/// authenticated, not one taken from an out-of-band record.
fn node_id_from(signing: &[u8], kex: &[u8], kem: &[u8]) -> Result<NodeId> {
    let s: [u8; 32] = signing
        .try_into()
        .map_err(|_| Error::Decode("bad signing key length".into()))?;
    let k: [u8; 32] = kex
        .try_into()
        .map_err(|_| Error::Decode("bad kex key length".into()))?;
    NodeId::from_keys(&s, &k, kem)
}

fn random_32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(b)
}

fn put(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

fn get<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    if buf.len() < 4 {
        return Err(Error::Decode("truncated handshake message".into()));
    }
    let len = u32::from_be_bytes(buf[..4].try_into().expect("checked")) as usize;
    *buf = &buf[4..];
    if buf.len() < len {
        return Err(Error::Decode("truncated handshake field".into()));
    }
    let (field, rest) = buf.split_at(len);
    *buf = rest;
    Ok(field)
}

fn verifying_key(bytes: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Decode("bad verifying key length".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| Error::Crypto("invalid verifying key".into()))
}

fn signature(bytes: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| Error::Decode("bad signature length".into()))?;
    Ok(Signature::from_bytes(&arr))
}

fn public_key(bytes: &[u8]) -> Result<PublicKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Decode("bad X25519 key length".into()))?;
    Ok(PublicKey::from(arr))
}

fn encoded_ek(bytes: &[u8]) -> Result<Encoded<KemEncapKey>> {
    Encoded::<KemEncapKey>::try_from(bytes)
        .map_err(|_| Error::Decode("bad ML-KEM encapsulation key length".into()))
}

fn shared_to_array(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| Error::Crypto("unexpected ML-KEM shared secret length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the full handshake (cookie round-trip + key confirmation), returning
    /// both sides' results.
    fn full_handshake(
        alice: &NodeIdentity,
        bob: &NodeIdentity,
    ) -> (HandshakeResult, HandshakeResult) {
        let (state, init1) = initiator_message1(alice).unwrap();
        let cookie_key = CookieKey::generate().unwrap();
        let challenge = responder_cookie(&cookie_key, &init1).unwrap();
        let init2 = state.with_cookie(&challenge);
        let (m2, pending) = responder_process(bob, &init2, &cookie_key).unwrap();
        let (m3, alice_res) = initiator_finish(state, &m2).unwrap();
        let bob_res = responder_confirm(pending, &m3).unwrap();
        (alice_res, bob_res)
    }

    #[test]
    fn handshake_agrees_and_communicates() {
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (alice_res, bob_res) = full_handshake(&alice, &bob);

        // Each side authenticated the other's real identity.
        assert_eq!(bob_res.peer.as_bytes(), alice.public().signing.as_bytes());
        assert_eq!(alice_res.peer.as_bytes(), bob.public().signing.as_bytes());

        // The derived sessions interoperate in both directions.
        let mut a = alice_res.session;
        let mut b = bob_res.session;
        let frame = a.seal(b"hello bob").unwrap();
        assert_eq!(b.open(&frame).unwrap(), b"hello bob");
        let frame = b.seal(b"hi alice").unwrap();
        assert_eq!(a.open(&frame).unwrap(), b"hi alice");
    }

    #[test]
    fn responder_rejects_a_bad_key_confirmation() {
        // Without a valid m3, the responder never establishes the session — so a
        // replayed/forged m1 (which can't produce m3) cannot be confirmed.
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (state, init1) = initiator_message1(&alice).unwrap();
        let cookie_key = CookieKey::generate().unwrap();
        let challenge = responder_cookie(&cookie_key, &init1).unwrap();
        let init2 = state.with_cookie(&challenge);
        let (_m2, pending) = responder_process(&bob, &init2, &cookie_key).unwrap();

        // A garbage confirmation tag is rejected.
        let mut bad_m3 = Vec::new();
        put(&mut bad_m3, &[0u8; 32]);
        assert!(responder_confirm(pending, &bad_m3).is_err());
    }

    #[test]
    fn tampered_message1_is_rejected() {
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (state, init1) = initiator_message1(&alice).unwrap();
        let cookie_key = CookieKey::generate().unwrap();
        let challenge = responder_cookie(&cookie_key, &init1).unwrap();
        let mut init2 = state.with_cookie(&challenge);
        let n = init2.len();
        init2[n - 10] ^= 0xff; // flip a byte inside m1's signature
        assert!(responder_process(&bob, &init2, &cookie_key).is_err());
    }

    #[test]
    fn responder_does_no_kem_without_a_valid_cookie() {
        // An init message with no (or a wrong) cookie is rejected by
        // `responder_process` before any ML-KEM work.
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (_state, init1) = initiator_message1(&alice).unwrap();
        let cookie_key = CookieKey::generate().unwrap();
        // init1 carries an *empty* cookie → must be refused.
        assert!(responder_process(&bob, &init1, &cookie_key).is_err());
        // A cookie from a *different* key is refused too.
        let other = CookieKey::generate().unwrap();
        let wrong = responder_cookie(&other, &init1).unwrap();
        let init_wrong = _state.with_cookie(&wrong);
        assert!(responder_process(&bob, &init_wrong, &cookie_key).is_err());
    }

    #[test]
    fn handshake_binds_and_returns_the_full_node_id() {
        // Both sides authenticate the peer's *full* self-certifying NodeId, not
        // just its Ed25519 key — computed from keys proven in-band.
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (alice_res, bob_res) = full_handshake(&alice, &bob);
        assert_eq!(bob_res.peer_id, alice.id());
        assert_eq!(alice_res.peer_id, bob.id());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        // A single appended byte must be refused (else it silently desyncs keys).
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (state, init1) = initiator_message1(&alice).unwrap();
        let cookie_key = CookieKey::generate().unwrap();
        let challenge = responder_cookie(&cookie_key, &init1).unwrap();
        let mut init2 = state.with_cookie(&challenge);
        init2.push(0x00); // trailing byte after m1
        assert!(responder_process(&bob, &init2, &cookie_key).is_err());
    }

    #[test]
    fn replayed_frame_is_rejected() {
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (alice_res, bob_res) = full_handshake(&alice, &bob);

        let mut a = alice_res.session;
        let mut b = bob_res.session;
        let frame = a.seal(b"once").unwrap();
        assert_eq!(b.open(&frame).unwrap(), b"once");
        assert!(b.open(&frame).is_err(), "replay must be rejected");
    }
}
