//! VRF-based unbiasable selection (M11).
//!
//! A Verifiable Random Function lets a node derive a random output from a seed
//! (e.g. a request id) that anyone can *verify* was computed correctly from the
//! seed and the node's key — but that the node could not have biased. neo uses it
//! so per-request path/exit selection is verifiably fair: a client cannot grind
//! seeds to herd traffic onto attacker-controlled relays.
//!
//! Built on `schnorrkel`'s Ristretto VRF.

use schnorrkel::vrf::{VRFPreOut, VRFProof};
use schnorrkel::{signing_context, Keypair, PublicKey};

const CONTEXT: &[u8] = b"neo-vrf-v1";
const OUTPUT_LABEL: &[u8] = b"neo-vrf-output";

/// A VRF keypair.
pub struct VrfKeypair(Keypair);

/// A VRF proof plus the pre-output needed to verify it.
#[derive(Clone)]
pub struct VrfProof {
    preout: [u8; 32],
    proof: [u8; 64],
}

impl VrfKeypair {
    /// Generate a fresh VRF keypair.
    pub fn generate() -> Self {
        VrfKeypair(Keypair::generate_with(rand_core::OsRng))
    }

    /// The public key bytes, for verifiers.
    pub fn public(&self) -> [u8; 32] {
        self.0.public.to_bytes()
    }

    /// Produce the VRF output for `seed` and a proof of correctness.
    pub fn prove(&self, seed: &[u8]) -> (VrfProof, [u8; 32]) {
        let (inout, proof, _) = self.0.vrf_sign(signing_context(CONTEXT).bytes(seed));
        let output = inout.make_bytes::<[u8; 32]>(OUTPUT_LABEL);
        (
            VrfProof {
                preout: inout.to_preout().to_bytes(),
                proof: proof.to_bytes(),
            },
            output,
        )
    }
}

/// Verify a VRF proof. Returns the (unbiasable) output on success.
pub fn verify(public: &[u8; 32], seed: &[u8], proof: &VrfProof) -> Option<[u8; 32]> {
    let public = PublicKey::from_bytes(public).ok()?;
    let preout = VRFPreOut::from_bytes(&proof.preout).ok()?;
    let vrf_proof = VRFProof::from_bytes(&proof.proof).ok()?;
    let (inout, _) = public
        .vrf_verify(signing_context(CONTEXT).bytes(seed), &preout, &vrf_proof)
        .ok()?;
    Some(inout.make_bytes::<[u8; 32]>(OUTPUT_LABEL))
}

/// Map a VRF output to an index in `0..n` (for choosing a relay/exit).
pub fn selection_index(output: &[u8; 32], n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut head = [0u8; 8];
    head.copy_from_slice(&output[..8]);
    (u64::from_le_bytes(head) % n as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_then_verify_roundtrips() {
        let kp = VrfKeypair::generate();
        let public = kp.public();
        let (proof, output) = kp.prove(b"request-42");
        assert_eq!(verify(&public, b"request-42", &proof), Some(output));
    }

    #[test]
    fn output_is_deterministic_for_a_seed() {
        let kp = VrfKeypair::generate();
        let (_, a) = kp.prove(b"seed");
        let (_, b) = kp.prove(b"seed");
        assert_eq!(
            a, b,
            "a VRF output must be unbiasable / deterministic per seed"
        );
    }

    #[test]
    fn rejects_wrong_seed_or_tampered_proof() {
        let kp = VrfKeypair::generate();
        let public = kp.public();
        let (proof, _) = kp.prove(b"seed-a");
        assert!(verify(&public, b"seed-b", &proof).is_none());

        let mut tampered = proof.clone();
        tampered.proof[0] ^= 0xff;
        assert!(verify(&public, b"seed-a", &tampered).is_none());
    }

    #[test]
    fn selection_index_is_in_range() {
        let kp = VrfKeypair::generate();
        let (_, output) = kp.prove(b"x");
        assert!(selection_index(&output, 7) < 7);
        assert_eq!(selection_index(&output, 0), 0);
    }
}
