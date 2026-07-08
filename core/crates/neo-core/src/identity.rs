//! Node cryptographic identity.
//!
//! Each node holds a long-term, **PQ-hybrid** identity made of:
//! - an **Ed25519** signing key (authentication / signatures),
//! - an **X25519** key-exchange key (classical KEX), and
//! - an **ML-KEM-768** key-encapsulation key (post-quantum KEX).
//!
//! The X25519 and ML-KEM keys together give a hybrid key exchange that stays
//! secure if *either* component holds — the defense against "harvest-now,
//! decrypt-later" quantum attacks. `neo-crypto` folds both into the handshake
//! (plan M0/M2); this module owns the long-term keys and the stable [`NodeId`]
//! derived from all three public keys.
//!
//! TODO(security): wrap secret key material in `zeroize` types so it is scrubbed
//! on drop. The current handling is not sufficient for a release.

use crate::error::{Error, Result};
use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use x25519_dalek::{PublicKey as KexPublic, StaticSecret as KexSecret};

/// ML-KEM secret (decapsulation) key type for the chosen parameter set.
type KemDecapKey = <MlKem768 as KemCore>::DecapsulationKey;
/// ML-KEM public (encapsulation) key type for the chosen parameter set.
type KemEncapKey = <MlKem768 as KemCore>::EncapsulationKey;

/// Length of the two classical seeds at the start of a serialized identity.
const CLASSICAL_SEED_LEN: usize = 64;

/// A stable, self-certifying node identifier: BLAKE3 over all public keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// The raw 32-byte identifier.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Full lowercase-hex encoding of the identifier.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn derive(signing: &VerifyingKey, kex: &KexPublic, kem: &KemEncapKey) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"neo-node-id-v1");
        hasher.update(signing.as_bytes());
        hasher.update(kex.as_bytes());
        hasher.update(kem.as_bytes().as_ref());
        NodeId(*hasher.finalize().as_bytes())
    }
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
    /// Stable identifier derived from the public keys.
    pub id: NodeId,
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

        let mut kex_seed = [0u8; 32];
        getrandom::getrandom(&mut kex_seed).map_err(|e| Error::Rng(e.to_string()))?;
        let kex = KexSecret::from(kex_seed);

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
            id,
        }
    }

    /// The node's stable identifier.
    pub fn id(&self) -> NodeId {
        self.public().id
    }

    /// Serialize the secret identity for on-disk persistence.
    ///
    /// Layout: `[0..32]` Ed25519 seed, `[32..64]` X25519 secret scalar, then the
    /// ML-KEM-768 decapsulation key (fixed length for the parameter set).
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

        Ok(Self {
            signing: SigningKey::from_bytes(&signing_seed),
            kex: KexSecret::from(kex_seed),
            kem,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrips_through_bytes() {
        let id = NodeIdentity::generate().expect("generate");
        let restored = NodeIdentity::from_bytes(&id.to_bytes()).expect("from_bytes");
        assert_eq!(id.public().id, restored.public().id);
        assert_eq!(id.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn node_id_is_stable() {
        let id = NodeIdentity::generate().expect("generate");
        assert_eq!(id.id(), id.public().id);
    }

    #[test]
    fn distinct_identities_have_distinct_ids() {
        let a = NodeIdentity::generate().expect("generate");
        let b = NodeIdentity::generate().expect("generate");
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn serialized_identity_includes_pq_key() {
        // Classical seeds are 64 bytes; a PQ-hybrid identity is much larger.
        let id = NodeIdentity::generate().expect("generate");
        assert!(
            id.to_bytes().len() > CLASSICAL_SEED_LEN + 1000,
            "expected ML-KEM key to dominate the serialized size"
        );
    }

    #[test]
    fn from_bytes_rejects_truncated_input() {
        assert!(NodeIdentity::from_bytes(&[0u8; 10]).is_err());
        assert!(NodeIdentity::from_bytes(&[0u8; CLASSICAL_SEED_LEN]).is_err());
    }
}
