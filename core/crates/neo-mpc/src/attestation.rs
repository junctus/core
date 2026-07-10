//! Verifiable non-custody — an operator's proof that a committee member is
//! *cryptographically incapable* of unilaterally reading traffic (M28).
//!
//! The M28 trust story is: "even the exit committee cannot read your response,
//! and here is the proof." A [`NonCustodyProof`] is that publishable artifact. A
//! member computes `D = y_i·R` for a **fresh challenge** `R` (unrelated to any
//! real session) with a Chaum–Pedersen DLEQ, and anyone holding the committee's
//! public [`KeyCommitments`] can [`verify`](NonCustodyProof::verify) that:
//!
//! - the member holds a secret `y_i` matching its **committed public share**
//!   `Y_i` (the DLEQ binds `D` to `Y_i = Σ_l C_l·i^l`), and
//! - its cryptographic role is confined to producing `y_i·R` — it demonstrably
//!   computes a *partial*, never the key or a plaintext.
//!
//! Combined with the public fact that the committee is **threshold-`k`** (its
//! commitment vector has `k` entries, so decryption needs `k` cooperating
//! members), the artifact shows this operator is one of `n` share-holders that
//! **cannot decrypt alone**. So a subpoena served on it (or on any minority
//! below `k`) yields only a share, which reveals neither the key nor any
//! plaintext.
//!
//! **Honest boundary.** The proof uses a *fresh* challenge, not a live session's
//! ciphertext, so publishing it — even by every member — never forms a quorum
//! over real traffic and leaks nothing. It is therefore a proof of *structural
//! non-custody* ("I hold only a threshold share; my behavior is DLEQ-constrained
//! to partial decryption"), **not** a claim about any specific message's
//! plaintext (the protocol keeps live-session partials to the client). It also
//! does not speak to the *egress* member that sees plaintext at send — that gap
//! is M33, documented at the call site.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use neo_core::{Error, Result};

use crate::threshold::{partial_decrypt, verify_partial, Ciphertext, Partial};
use crate::vss::{KeyCommitments, KeyShare};

/// A publishable proof that committee member `member` holds only a threshold
/// share and computes only DLEQ-bound partials — see the module docs.
#[derive(Clone, Debug)]
pub struct NonCustodyProof {
    /// The 1-based committee member this proof is about.
    pub member: u8,
    /// A fresh challenge point `R = r·G`, unrelated to any real session.
    challenge: CompressedRistretto,
    /// The member's `D = y_i·R` and its Chaum–Pedersen DLEQ.
    partial: Partial,
}

impl NonCustodyProof {
    /// Produce a non-custody proof from a committee member's share. Uses a fresh
    /// random challenge, so the artifact is safe to publish and never contributes
    /// to decrypting live traffic.
    pub fn prove(share: &KeyShare) -> Result<Self> {
        let mut wide = [0u8; 64];
        getrandom::getrandom(&mut wide).map_err(|e| Error::Rng(e.to_string()))?;
        let r = Scalar::from_bytes_mod_order_wide(&wide);
        let challenge = (RISTRETTO_BASEPOINT_POINT * r).compress();
        // c is unused by verify_partial (it only checks R and the DLEQ), so the
        // challenge "ciphertext" carries an empty body.
        let ct = Ciphertext {
            r_point: challenge,
            c: Vec::new(),
        };
        let partial = partial_decrypt(share, &ct)?;
        Ok(Self {
            member: share.member,
            challenge,
            partial,
        })
    }

    /// Verify the proof against the committee's public commitments: the DLEQ must
    /// bind `D` to the member's committed public share `Y_i`, confirming the
    /// operator holds a valid threshold share and only ever computed a partial.
    pub fn verify(&self, commitments: &KeyCommitments) -> bool {
        if self.member == 0 || self.partial.member() != self.member {
            return false;
        }
        let ct = Ciphertext {
            r_point: self.challenge,
            c: Vec::new(),
        };
        verify_partial(commitments, &ct, &self.partial)
    }

    /// Serialize as `member (1) || challenge (32) || partial (97)` = 130 bytes.
    pub fn to_bytes(&self) -> [u8; 130] {
        let mut out = [0u8; 130];
        out[0] = self.member;
        out[1..33].copy_from_slice(self.challenge.as_bytes());
        out[33..130].copy_from_slice(&self.partial.to_bytes());
        out
    }

    /// Parse [`to_bytes`](Self::to_bytes). Bounds-checked; never panics.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 130 {
            return Err(Error::Decode("non-custody proof must be 130 bytes".into()));
        }
        let member = bytes[0];
        if member == 0 {
            return Err(Error::Decode(
                "non-custody proof member 0 is invalid".into(),
            ));
        }
        let challenge = CompressedRistretto(bytes[1..33].try_into().expect("32 bytes"));
        let partial = Partial::from_bytes(&bytes[33..130])?;
        if partial.member() != member {
            return Err(Error::Decode(
                "non-custody proof member disagrees with its partial".into(),
            ));
        }
        Ok(Self {
            member,
            challenge,
            partial,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg;
    use crate::CommitteeConfig;

    fn committee(members: usize, threshold: usize) -> (KeyCommitments, Vec<KeyShare>) {
        // Build a real committee key via DKG (no party holds s), then attest.
        let cfg = CommitteeConfig { members, threshold };
        let contributions: Vec<dkg::Contribution> = (1..=members as u8)
            .map(|m| dkg::Contribution::generate(m, &cfg).unwrap())
            .collect();
        let mut shares = Vec::new();
        for recipient in 1..=members as u8 {
            let dealt: Vec<KeyShare> = contributions
                .iter()
                .map(|d| d.share_for(recipient).unwrap())
                .collect();
            shares.push(dkg::aggregate_share(recipient, &dealt).unwrap());
        }
        let commitments = dkg::joint_commitments(
            &contributions
                .iter()
                .map(|c| c.commitment().clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        (commitments, shares)
    }

    #[test]
    fn a_members_proof_verifies_against_the_committee_key() {
        let (commitments, shares) = committee(5, 3);
        for share in &shares {
            let proof = NonCustodyProof::prove(share).unwrap();
            assert!(
                proof.verify(&commitments),
                "an honest member's proof verifies"
            );
        }
    }

    #[test]
    fn a_proof_for_the_wrong_committee_fails() {
        let (_commitments_a, shares_a) = committee(5, 3);
        let (commitments_b, _shares_b) = committee(5, 3);
        // A proof from committee A's member does not verify against B's key.
        let proof = NonCustodyProof::prove(&shares_a[0]).unwrap();
        assert!(!proof.verify(&commitments_b));
    }

    #[test]
    fn a_forged_member_index_is_rejected() {
        let (commitments, shares) = committee(5, 3);
        let mut proof = NonCustodyProof::prove(&shares[0]).unwrap();
        proof.member = proof.member.wrapping_add(1); // claim to be a different member
        assert!(!proof.verify(&commitments));
    }

    #[test]
    fn proof_roundtrips_on_the_wire() {
        let (commitments, shares) = committee(4, 3);
        let proof = NonCustodyProof::prove(&shares[1]).unwrap();
        let parsed = NonCustodyProof::from_bytes(&proof.to_bytes()).unwrap();
        assert_eq!(parsed.member, proof.member);
        assert!(parsed.verify(&commitments));
        // A truncated buffer and a member/partial mismatch are rejected.
        assert!(NonCustodyProof::from_bytes(&proof.to_bytes()[..100]).is_err());
        let mut bad = proof.to_bytes();
        bad[0] = bad[0].wrapping_add(1);
        assert!(NonCustodyProof::from_bytes(&bad).is_err());
    }
}
