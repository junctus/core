//! Per-hop onion layering for multi-hop circuits (M2).
//!
//! A payload is wrapped in one encryption layer per hop. Each hop peels exactly
//! one layer with its own X25519 static key, learning only *the next hop* and the
//! still-encrypted remainder — never the full path or the payload (unless it is
//! the exit). Per layer the sender uses a fresh ephemeral X25519 key, so each
//! layer key is unique and a constant AEAD nonce is safe.
//!
//! This is a working onion, not full Sphinx: it does not yet have fixed-size
//! padding, bitwise unlinkability, or replay tags. Those (and a PQ per-hop KEM)
//! are refinements tracked for later. Post-quantum protection of the *end-to-end*
//! session already comes from the M1 handshake.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use neo_core::{Error, NodeIdentity, Result};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const LAYER_NONCE: [u8; 12] = [0u8; 12];
const TAG_RELAY: u8 = 0;
const TAG_FINAL: u8 = 1;

/// A hop in an onion path: its X25519 public key and its routing address/label.
#[derive(Clone)]
pub struct OnionHop {
    /// The hop's X25519 public key (from its node identity).
    pub key: PublicKey,
    /// The hop's routing address, embedded in the *previous* layer as "next".
    pub addr: Vec<u8>,
}

impl OnionHop {
    /// Build a hop from a raw X25519 public key and its routing address.
    pub fn new(kex: [u8; 32], addr: Vec<u8>) -> Self {
        Self {
            key: PublicKey::from(kex),
            addr,
        }
    }
}

/// The result of peeling one onion layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peeled {
    /// Forward `onion` to `next`.
    Relay {
        /// Address of the next hop.
        next: Vec<u8>,
        /// The remaining (still-layered) onion.
        onion: Vec<u8>,
    },
    /// This node is the exit; here is the payload.
    Final {
        /// The delivered payload.
        payload: Vec<u8>,
    },
}

/// Wrap `payload` for the given path (first element = first hop).
pub fn wrap(hops: &[OnionHop], payload: &[u8]) -> Result<Vec<u8>> {
    let last = hops
        .len()
        .checked_sub(1)
        .ok_or_else(|| Error::Config("onion needs at least one hop".into()))?;

    let mut wire = seal_layer(&hops[last].key, &encode_final(payload))?;
    for j in (0..last).rev() {
        let plaintext = encode_relay(&hops[j + 1].addr, &wire);
        wire = seal_layer(&hops[j].key, &plaintext)?;
    }
    Ok(wire)
}

/// Peel one layer with this node's identity.
pub fn peel(identity: &NodeIdentity, wire: &[u8]) -> Result<Peeled> {
    if wire.len() < 32 {
        return Err(Error::Decode("onion layer too short".into()));
    }
    let eph_pub = public_key(&wire[..32])?;
    let shared = identity.diffie_hellman(&eph_pub);
    let key = layer_key(&shared);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&LAYER_NONCE), &wire[32..])
        .map_err(|_| Error::Crypto("onion peel failed (not this hop, or corrupt)".into()))?;

    decode(&plaintext)
}

fn seal_layer(hop_pub: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let eph = StaticSecret::from(random_32()?);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(hop_pub).to_bytes();
    let key = layer_key(&shared);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&LAYER_NONCE), plaintext)
        .map_err(|_| Error::Crypto("onion seal failed".into()))?;

    let mut out = Vec::with_capacity(32 + ciphertext.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn layer_key(shared: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"neo-onion-v1"), shared);
    let mut key = [0u8; 32];
    hk.expand(b"layer", &mut key).expect("hkdf onion layer");
    key
}

fn encode_final(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![TAG_FINAL];
    put(&mut v, payload);
    v
}

fn encode_relay(next: &[u8], onion: &[u8]) -> Vec<u8> {
    let mut v = vec![TAG_RELAY];
    put(&mut v, next);
    put(&mut v, onion);
    v
}

fn decode(plaintext: &[u8]) -> Result<Peeled> {
    let (&tag, mut cur) = plaintext
        .split_first()
        .ok_or_else(|| Error::Decode("empty onion layer".into()))?;
    match tag {
        TAG_RELAY => {
            let next = get(&mut cur)?.to_vec();
            let onion = get(&mut cur)?.to_vec();
            Ok(Peeled::Relay { next, onion })
        }
        TAG_FINAL => {
            let payload = get(&mut cur)?.to_vec();
            Ok(Peeled::Final { payload })
        }
        _ => Err(Error::Decode("unknown onion tag".into())),
    }
}

fn public_key(bytes: &[u8]) -> Result<PublicKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Decode("bad X25519 key length".into()))?;
    Ok(PublicKey::from(arr))
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
        return Err(Error::Decode("truncated onion field".into()));
    }
    let len = u32::from_be_bytes(buf[..4].try_into().expect("checked")) as usize;
    *buf = &buf[4..];
    if buf.len() < len {
        return Err(Error::Decode("truncated onion payload".into()));
    }
    let (field, rest) = buf.split_at(len);
    *buf = rest;
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(id: &NodeIdentity) -> OnionHop {
        OnionHop {
            key: id.public().kex,
            addr: id.id().as_bytes().to_vec(),
        }
    }

    #[test]
    fn three_hop_onion_peels_to_payload() {
        let h1 = NodeIdentity::generate().unwrap();
        let h2 = NodeIdentity::generate().unwrap();
        let h3 = NodeIdentity::generate().unwrap();
        let hops = vec![hop(&h1), hop(&h2), hop(&h3)];

        let wire = wrap(&hops, b"top secret payload").unwrap();

        let onion = match peel(&h1, &wire).unwrap() {
            Peeled::Relay { next, onion } => {
                assert_eq!(next, h2.id().as_bytes().to_vec());
                onion
            }
            other => panic!("hop 1 should relay, got {other:?}"),
        };
        let onion = match peel(&h2, &onion).unwrap() {
            Peeled::Relay { next, onion } => {
                assert_eq!(next, h3.id().as_bytes().to_vec());
                onion
            }
            other => panic!("hop 2 should relay, got {other:?}"),
        };
        match peel(&h3, &onion).unwrap() {
            Peeled::Final { payload } => assert_eq!(payload, b"top secret payload"),
            other => panic!("hop 3 should be final, got {other:?}"),
        }
    }

    #[test]
    fn wrong_hop_cannot_peel() {
        let h1 = NodeIdentity::generate().unwrap();
        let h2 = NodeIdentity::generate().unwrap();
        let wrong = NodeIdentity::generate().unwrap();
        let wire = wrap(&[hop(&h1), hop(&h2)], b"x").unwrap();
        assert!(peel(&wrong, &wire).is_err());
    }
}
