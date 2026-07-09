//! Node cryptographic identity.
//!
//! Each node holds a long-term, **PQ-hybrid** identity made of:
//! - an **Ed25519** signing key (authentication / signatures),
//! - an **X25519** key-exchange key (classical KEX), and
//! - an **ML-KEM-768** key-encapsulation key (post-quantum KEX).
//!
//! A **Ristretto** routing key for Sphinx (`neo-crypto`) is derived
//! deterministically from the signing seed, so it needs no extra storage and is
//! bound to the identity. The X25519 and ML-KEM keys together give a hybrid key
//! exchange secure if *either* holds — the defense against "harvest-now,
//! decrypt-later" quantum attacks.
//!
//! Secret buffers are scrubbed with `zeroize`; the dalek key types also zeroize
//! their own material on drop.

use crate::error::{Error, Result};
use core::fmt;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use x25519_dalek::{PublicKey as KexPublic, StaticSecret as KexSecret};
use zeroize::Zeroize;

/// ML-KEM secret (decapsulation) key type for the chosen parameter set.
type KemDecapKey = <MlKem768 as KemCore>::DecapsulationKey;
/// ML-KEM public (encapsulation) key type for the chosen parameter set.
type KemEncapKey = <MlKem768 as KemCore>::EncapsulationKey;

/// Length of the two classical seeds at the start of a serialized identity.
const CLASSICAL_SEED_LEN: usize = 64;

/// Serialized length of an ML-KEM-768 encapsulation (public) key.
pub const KEM_PUBLIC_LEN: usize = 1184;

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// A stable, self-certifying node identifier: BLAKE3 over the public keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// The raw 32-byte identifier.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstruct an identifier from raw bytes (e.g. a discovery record).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NodeId(bytes)
    }

    /// Full lowercase-hex encoding of the identifier.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Re-derive the identifier from raw public-key bytes.
    ///
    /// This is what makes discovery records **self-certifying**: a verifier
    /// recomputes the id from the keys a record carries and rejects the record
    /// if it does not match, so nobody can publish keys under another node's id.
    pub fn from_keys(signing: &[u8; 32], kex: &[u8; 32], kem: &[u8]) -> Result<Self> {
        if kem.len() != KEM_PUBLIC_LEN {
            return Err(Error::Decode(format!(
                "ML-KEM public key must be {KEM_PUBLIC_LEN} bytes, got {}",
                kem.len()
            )));
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"neo-node-id-v1");
        hasher.update(signing);
        hasher.update(kex);
        hasher.update(kem);
        Ok(NodeId(*hasher.finalize().as_bytes()))
    }

    fn derive(signing: &VerifyingKey, kex: &KexPublic, kem: &KemEncapKey) -> Self {
        Self::from_keys(signing.as_bytes(), kex.as_bytes(), kem.as_bytes().as_ref())
            .expect("typed keys always have valid lengths")
    }
}

/// Verify an Ed25519 signature made with a node's long-term signing key.
///
/// Uses `verify_strict`, which additionally rejects small-order / non-canonical
/// keys and signatures — the right default for records consumed from the
/// network.
pub fn verify_signature(
    signing: &[u8; 32],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(signing)
        .map_err(|_| Error::Crypto("invalid Ed25519 verifying key".into()))?;
    let sig = Signature::from_bytes(signature);
    key.verify_strict(message, &sig)
        .map_err(|_| Error::Crypto("signature verification failed".into()))
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short, greppable form: `neo:` + first 8 bytes of hex.
        write!(f, "neo:{}", hex::encode(&self.0[..8]))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.to_hex())
    }
}

/// The public half of a node identity — safe to share.
#[derive(Clone)]
pub struct NodePublic {
    /// Ed25519 verifying key.
    pub signing: VerifyingKey,
    /// X25519 public key (classical KEX).
    pub kex: KexPublic,
    /// ML-KEM-768 encapsulation key (post-quantum KEX).
    pub kem: KemEncapKey,
    /// Compressed Ristretto routing public key (for Sphinx).
    pub sphinx: [u8; 32],
    /// Stable identifier derived from the public keys.
    pub id: NodeId,
}

impl NodePublic {
    /// The ML-KEM-768 encapsulation key as raw bytes (for discovery records).
    pub fn kem_bytes(&self) -> Vec<u8> {
        let encoded = self.kem.as_bytes();
        let bytes: &[u8] = encoded.as_ref();
        bytes.to_vec()
    }
}

/// A node's long-term secret identity. Keep this out of logs and off the wire.
pub struct NodeIdentity {
    signing: SigningKey,
    kex: KexSecret,
    kem: KemDecapKey,
}

impl NodeIdentity {
    /// Generate a fresh identity from the operating-system CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut signing_seed = [0u8; 32];
        getrandom::getrandom(&mut signing_seed).map_err(|e| Error::Rng(e.to_string()))?;
        let signing = SigningKey::from_bytes(&signing_seed);
        signing_seed.zeroize();

        let mut kex_seed = [0u8; 32];
        getrandom::getrandom(&mut kex_seed).map_err(|e| Error::Rng(e.to_string()))?;
        let kex = KexSecret::from(kex_seed);
        kex_seed.zeroize();

        // ML-KEM keygen draws directly from the OS CSPRNG.
        let (kem, _kem_public) = MlKem768::generate(&mut rand_core::OsRng);

        Ok(Self { signing, kex, kem })
    }

    /// The shareable public identity.
    pub fn public(&self) -> NodePublic {
        let signing = self.signing.verifying_key();
        let kex = KexPublic::from(&self.kex);
        let kem = self.kem.encapsulation_key().clone();
        let id = NodeId::derive(&signing, &kex, &kem);
        NodePublic {
            signing,
            kex,
            kem,
            sphinx: self.sphinx_public(),
            id,
        }
    }

    /// The node's stable identifier.
    pub fn id(&self) -> NodeId {
        self.public().id
    }

    /// Sign a message with the node's long-term Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Static X25519 Diffie–Hellman with a peer's KEX public key.
    ///
    /// Returns the raw shared secret; callers must run it through a KDF before
    /// use. This backs classical key agreement in `neo-crypto`.
    pub fn diffie_hellman(&self, peer: &KexPublic) -> [u8; 32] {
        self.kex.diffie_hellman(peer).to_bytes()
    }

    /// Compressed Ristretto routing public key used by Sphinx (`neo-crypto`).
    pub fn sphinx_public(&self) -> [u8; 32] {
        (RISTRETTO_BASEPOINT_POINT * self.route_scalar())
            .compress()
            .to_bytes()
    }

    /// Sphinx shared secret `route_scalar · alpha` (compressed). Errors if
    /// `alpha` is not a valid Ristretto point **or is the identity element**.
    ///
    /// Rejecting the identity is essential: `identity · route_scalar` is the
    /// identity for *every* node's key, so an `alpha` of the identity would yield
    /// a node-independent, publicly-known shared secret — letting anyone derive a
    /// victim's per-hop keys and forge a packet it accepts, with no key at all.
    pub fn sphinx_shared(&self, alpha: [u8; 32]) -> Result<[u8; 32]> {
        let point = CompressedRistretto::from_slice(&alpha)
            .map_err(|_| Error::Decode("bad Ristretto point length".into()))?
            .decompress()
            .ok_or_else(|| Error::Crypto("alpha is not a valid Ristretto point".into()))?;
        if point.is_identity() {
            return Err(Error::Crypto("alpha is the identity point".into()));
        }
        Ok((point * self.route_scalar()).compress().to_bytes())
    }

    /// Derive the Sphinx routing scalar from the signing seed (never stored).
    fn route_scalar(&self) -> Scalar {
        let mut seed = self.signing.to_bytes();
        let mut wide = [0u8; 64];
        let mut xof = blake3::Hasher::new_derive_key("neo-sphinx-routing-key-v1");
        xof.update(&seed);
        xof.finalize_xof().fill(&mut wide);
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        seed.zeroize();
        wide.zeroize();
        scalar
    }

    /// Serialize the secret identity for on-disk persistence.
    ///
    /// Layout: `[0..32]` Ed25519 seed, `[32..64]` X25519 secret scalar, then the
    /// ML-KEM-768 decapsulation key (fixed length for the parameter set). The
    /// Ristretto routing key is re-derived, not stored.
    pub fn to_bytes(&self) -> Vec<u8> {
        let kem_bytes = self.kem.as_bytes();
        let mut out = Vec::with_capacity(CLASSICAL_SEED_LEN + kem_bytes.len());
        out.extend_from_slice(&self.signing.to_bytes());
        out.extend_from_slice(&self.kex.to_bytes());
        out.extend_from_slice(kem_bytes.as_ref());
        out
    }

    /// Reconstruct a secret identity from [`to_bytes`](Self::to_bytes) output.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= CLASSICAL_SEED_LEN {
            return Err(Error::Decode(format!(
                "identity too short: {} bytes",
                bytes.len()
            )));
        }
        let mut signing_seed = [0u8; 32];
        signing_seed.copy_from_slice(&bytes[..32]);
        let mut kex_seed = [0u8; 32];
        kex_seed.copy_from_slice(&bytes[32..CLASSICAL_SEED_LEN]);

        let kem_bytes = &bytes[CLASSICAL_SEED_LEN..];
        let encoded = Encoded::<KemDecapKey>::try_from(kem_bytes)
            .map_err(|_| Error::Decode("invalid ML-KEM decapsulation key length".to_string()))?;
        let kem = KemDecapKey::from_bytes(&encoded);

        let identity = Self {
            signing: SigningKey::from_bytes(&signing_seed),
            kex: KexSecret::from(kex_seed),
            kem,
        };
        signing_seed.zeroize();
        kex_seed.zeroize();
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrips_through_bytes() {
        let id = NodeIdentity::generate().unwrap();
        let restored = NodeIdentity::from_bytes(&id.to_bytes()).expect("from_bytes");
        assert_eq!(id.public().id, restored.public().id);
        assert_eq!(id.to_bytes(), restored.to_bytes());
        // The derived Ristretto routing key survives a round-trip too.
        assert_eq!(id.sphinx_public(), restored.sphinx_public());
    }

    #[test]
    fn node_id_is_stable() {
        let id = NodeIdentity::generate().unwrap();
        assert_eq!(id.id(), id.public().id);
    }

    #[test]
    fn distinct_identities_have_distinct_ids() {
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn serialized_identity_includes_pq_key() {
        let id = NodeIdentity::generate().unwrap();
        assert!(id.to_bytes().len() > CLASSICAL_SEED_LEN + 1000);
    }

    #[test]
    fn sphinx_shared_is_symmetric() {
        // route_a · (route_b · G) == route_b · (route_a · G)
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        let ab = a.sphinx_shared(b.sphinx_public()).unwrap();
        let ba = b.sphinx_shared(a.sphinx_public()).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn from_bytes_rejects_truncated_input() {
        assert!(NodeIdentity::from_bytes(&[0u8; 10]).is_err());
        assert!(NodeIdentity::from_bytes(&[0u8; CLASSICAL_SEED_LEN]).is_err());
    }

    #[test]
    fn node_id_recomputes_from_raw_key_bytes() {
        let p = NodeIdentity::generate().unwrap().public();
        let recomputed =
            NodeId::from_keys(&p.signing.to_bytes(), p.kex.as_bytes(), &p.kem_bytes()).unwrap();
        assert_eq!(recomputed, p.id);
    }

    #[test]
    fn kem_public_len_matches_real_keys() {
        let p = NodeIdentity::generate().unwrap().public();
        assert_eq!(p.kem_bytes().len(), KEM_PUBLIC_LEN);
        // Wrong length must be rejected, not silently hashed.
        assert!(NodeId::from_keys(&[0u8; 32], &[0u8; 32], &[0u8; 10]).is_err());
    }

    #[test]
    fn signatures_verify_and_tampering_is_caught() {
        let identity = NodeIdentity::generate().unwrap();
        let key = identity.public().signing.to_bytes();
        let sig = identity.sign(b"hello neo").to_bytes();

        assert!(verify_signature(&key, b"hello neo", &sig).is_ok());
        assert!(verify_signature(&key, b"hello neo!", &sig).is_err());
        let other = NodeIdentity::generate()
            .unwrap()
            .public()
            .signing
            .to_bytes();
        assert!(verify_signature(&other, b"hello neo", &sig).is_err());
    }
}
