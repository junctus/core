//! Unbiasable, verifiable path-seed derivation (M11).
//!
//! [`vrf`](crate::vrf) gives a per-node output nobody can bias *for a fixed
//! input*. But path selection has two parties who might each want to cheat: the
//! **client** (grinding request ids until it lands on relays it likes) and the
//! **beacon** relay that produces the VRF (choosing an input that steers the
//! client onto attacker paths). This module combines them so neither can bias
//! the result **for a fixed commitment**, and anyone can verify it.
//!
//! Construction (commit-then-VRF):
//! 1. The client commits to a value it cannot vary per attempt — derive it from a
//!    **beacon-independent epoch and a monotonic counter** via [`epoch_commitment`]
//!    — and publishes only the **commitment** `H(input)`, bound before it can see
//!    any VRF output.
//! 2. The beacon computes a VRF over that commitment. Because a VRF is a
//!    *function* of its input, the beacon has exactly one possible output for
//!    the client's commitment — it cannot try alternatives.
//! 3. The final path seed is `H(domain ‖ commitment ‖ vrf_output)`. The client
//!    couldn't grind it (the VRF output was unknown at commit time); the beacon
//!    couldn't grind it (its output was fixed by the commitment).
//!
//! **Residual — beacon abort-grinding (mitigated, not eliminated).** A beacon that
//! computes the seed *before* replying could selectively **abort** to force a
//! fresh draw. Deriving the commitment from `(epoch, counter)` defeats this:
//! retrying the same `(epoch, counter)` reproduces the *identical* commitment,
//! VRF output, and seed, so an abort yields no new sample. A beacon that then
//! *persistently* aborts is a detectable liveness fault — log it, rotate the
//! beacon, or use a threshold of beacons (roadmap). It is no longer a silent bias.
//!
//! Feed the seed to `neo_routing::Router::select_path_seeded` for a verifiable,
//! abort-resistant path.

use crate::vrf::{self, VrfKeypair, VrfProof};

const COMMIT_DOMAIN: &[u8] = b"neo-selection-commit-v1";
const SEED_DOMAIN: &[u8] = b"neo-selection-seed-v1";
const EPOCH_DOMAIN: &[u8] = b"neo-selection-epoch-v1";

/// A client's commitment to its selection nonce: `blake3(domain ‖ nonce)`.
///
/// Publish this to the beacon *before* receiving any VRF output. Reveal the
/// nonce afterwards only if the exchange needs to be audited by a third party.
pub fn commitment(nonce: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

/// The recommended commitment for path selection: bound to a **beacon-independent
/// epoch** and a **monotonic counter** rather than a fresh random nonce, so a
/// beacon that aborts to force a re-draw gets the *identical* commitment (and thus
/// the identical seed) on retry — defeating abort-grinding. Advance `counter` only
/// to intentionally request a new draw, never merely because a beacon aborted.
pub fn epoch_commitment(epoch: u64, counter: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EPOCH_DOMAIN);
    hasher.update(&epoch.to_be_bytes());
    hasher.update(&counter.to_be_bytes());
    commitment(hasher.finalize().as_bytes())
}

/// Beacon side: produce the VRF over the client's commitment plus the path seed.
/// Returns the proof (sent to the client) and the seed to route with.
pub fn beacon_respond(beacon: &VrfKeypair, commitment: &[u8; 32]) -> (VrfProof, [u8; 32]) {
    let (proof, output) = beacon.prove(commitment);
    (proof.clone(), derive_seed(commitment, &output))
}

/// Client side: verify the beacon's VRF proof over the commitment it sent, and
/// on success return the same unbiasable path seed the beacon derived. Returns
/// `None` if the proof does not verify (wrong key, tampered proof, or a
/// commitment the beacon didn't actually sign).
pub fn verify_seed(
    beacon_public: &[u8; 32],
    commitment: &[u8; 32],
    proof: &VrfProof,
) -> Option<[u8; 32]> {
    let output = vrf::verify(beacon_public, commitment, proof)?;
    Some(derive_seed(commitment, &output))
}

/// `blake3(domain ‖ commitment ‖ vrf_output)` — the shared path seed.
fn derive_seed(commitment: &[u8; 32], vrf_output: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEED_DOMAIN);
    hasher.update(commitment);
    hasher.update(vrf_output);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_beacon_agree_on_a_verifiable_seed() {
        let beacon = VrfKeypair::generate();
        let public = beacon.public();

        let nonce = b"client-random-nonce";
        let commit = commitment(nonce);

        let (proof, beacon_seed) = beacon_respond(&beacon, &commit);
        let client_seed = verify_seed(&public, &commit, &proof).expect("proof verifies");

        assert_eq!(
            beacon_seed, client_seed,
            "both sides derive the same unbiasable seed"
        );
    }

    #[test]
    fn a_proof_bound_to_another_commitment_is_rejected() {
        // A beacon can't take its VRF proof for commitment A and pass it off as
        // the response to commitment B: the proof is bound to its input.
        let beacon = VrfKeypair::generate();
        let public = beacon.public();
        let (proof_a, _) = beacon_respond(&beacon, &commitment(b"commit-a"));
        assert!(verify_seed(&public, &commitment(b"commit-b"), &proof_a).is_none());
    }

    #[test]
    fn the_beacon_cannot_grind_for_a_fixed_commitment() {
        // For one commitment the VRF output is a function of the beacon key, so
        // the beacon has exactly one seed available — it cannot search.
        let beacon = VrfKeypair::generate();
        let commit = commitment(b"fixed");
        let (_, seed_a) = beacon_respond(&beacon, &commit);
        let (_, seed_b) = beacon_respond(&beacon, &commit);
        assert_eq!(seed_a, seed_b, "one commitment ⇒ one possible seed");
    }

    #[test]
    fn a_different_commitment_yields_a_different_seed() {
        let beacon = VrfKeypair::generate();
        let (_, seed_a) = beacon_respond(&beacon, &commitment(b"nonce-a"));
        let (_, seed_b) = beacon_respond(&beacon, &commitment(b"nonce-b"));
        assert_ne!(seed_a, seed_b);
    }

    #[test]
    fn epoch_commitment_is_deterministic_so_aborts_dont_re_draw() {
        // Same (epoch, counter) ⇒ same commitment ⇒ same seed on retry, so a
        // beacon abort gains no fresh sample. Advancing the counter re-draws.
        let beacon = VrfKeypair::generate();
        let (_, seed1) = beacon_respond(&beacon, &epoch_commitment(7, 0));
        let (_, seed2) = beacon_respond(&beacon, &epoch_commitment(7, 0));
        assert_eq!(
            seed1, seed2,
            "a retried (epoch, counter) reproduces the seed"
        );
        let (_, seed3) = beacon_respond(&beacon, &epoch_commitment(7, 1));
        assert_ne!(seed1, seed3, "advancing the counter is a fresh draw");
    }

    #[test]
    fn a_wrong_beacon_key_is_rejected() {
        let beacon = VrfKeypair::generate();
        let impostor = VrfKeypair::generate();
        let commit = commitment(b"nonce");
        let (proof, _) = beacon_respond(&beacon, &commit);
        assert!(verify_seed(&impostor.public(), &commit, &proof).is_none());
    }
}
