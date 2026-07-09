//! PQ-hybrid, mutually-authenticated key exchange.
//!
//! A two-message handshake in the spirit of TLS 1.3's hybrid key exchange:
//! session keys are derived from **both** an ephemeral X25519 Diffie–Hellman and
//! an ephemeral **ML-KEM-768** encapsulation, so the session stays secure if
//! *either* primitive holds (defense against "harvest-now, decrypt-later").
//! Both ephemeral keys are bound to the parties' long-term Ed25519 identities by
//! signatures over the transcript, giving mutual authentication and forward
//! secrecy.
//!
//! ```text
//! initiator I                          responder R
//! ----------                           -----------
//! eph X25519 pk, eph ML-KEM ek,  --->  verify sig_I
//! id_I, sig_I                          eph X25519 pk, ML-KEM ct(ek),
//!                              <---     id_R, sig_R
//! verify sig_R
//! shared = HKDF( x25519_dh || mlkem_ss , transcript )
//! ```
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

    Ok((
        Initiator {
            eph_x,
            eph_kem_dk,
            msg1: msg1.clone(),
        },
        msg1,
    ))
}

/// Process message 1 and produce message 2 plus the responder's session.
pub fn responder_process(
    identity: &NodeIdentity,
    msg1: &[u8],
) -> Result<(Vec<u8>, HandshakeResult)> {
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

    let (k_i2r, k_r2i) = derive_keys(&dh, &shared_to_array(&ss[..])?, &th);

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
        HandshakeResult {
            session: Session::new(k_r2i, k_i2r),
            peer,
            peer_id,
        },
    ))
}

/// Complete the handshake on the initiator from message 2.
pub fn initiator_finish(state: Initiator, msg2: &[u8]) -> Result<HandshakeResult> {
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

    let (k_i2r, k_r2i) = derive_keys(&dh, &shared_to_array(&ss[..])?, &th);
    Ok(HandshakeResult {
        session: Session::new(k_i2r, k_r2i),
        peer,
        peer_id,
    })
}

// ---- helpers ---------------------------------------------------------------

fn derive_keys(dh: &[u8; 32], ss: &[u8; 32], transcript: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh);
    ikm[32..].copy_from_slice(ss);
    let hk = Hkdf::<Sha256>::new(Some(transcript), &ikm);
    let mut k_i2r = [0u8; 32];
    let mut k_r2i = [0u8; 32];
    hk.expand(b"neo i2r", &mut k_i2r).expect("hkdf i2r");
    hk.expand(b"neo r2i", &mut k_r2i).expect("hkdf r2i");
    (k_i2r, k_r2i)
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

    #[test]
    fn handshake_agrees_and_communicates() {
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();

        let (state, m1) = initiator_message1(&alice).unwrap();
        let (m2, bob_res) = responder_process(&bob, &m1).unwrap();
        let alice_res = initiator_finish(state, &m2).unwrap();

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
    fn tampered_message1_is_rejected() {
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (_state, mut m1) = initiator_message1(&alice).unwrap();
        m1[8] ^= 0xff; // flip a byte inside the signed ephemeral key
        assert!(responder_process(&bob, &m1).is_err());
    }

    #[test]
    fn handshake_binds_and_returns_the_full_node_id() {
        // Both sides authenticate the peer's *full* self-certifying NodeId, not
        // just its Ed25519 key — computed from keys proven in-band.
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (state, m1) = initiator_message1(&alice).unwrap();
        let (m2, bob_res) = responder_process(&bob, &m1).unwrap();
        let alice_res = initiator_finish(state, &m2).unwrap();
        assert_eq!(bob_res.peer_id, alice.id());
        assert_eq!(alice_res.peer_id, bob.id());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        // A single appended byte must be refused (else it silently desyncs keys).
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (_state, mut m1) = initiator_message1(&alice).unwrap();
        m1.push(0x00);
        assert!(responder_process(&bob, &m1).is_err());
    }

    #[test]
    fn replayed_frame_is_rejected() {
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (state, m1) = initiator_message1(&alice).unwrap();
        let (m2, bob_res) = responder_process(&bob, &m1).unwrap();
        let alice_res = initiator_finish(state, &m2).unwrap();

        let mut a = alice_res.session;
        let mut b = bob_res.session;
        let frame = a.seal(b"once").unwrap();
        assert_eq!(b.open(&frame).unwrap(), b"once");
        assert!(b.open(&frame).is_err(), "replay must be rejected");
    }
}
