//! Distributed key generation (DKG) — a committee joint key **no party holds**.
//!
//! [`vss`](crate::vss) and the base dealer use a *trusted dealer*: one party
//! picks the secret `s`, shares it, and therefore knows it. That is fine when the
//! dealer is the client decrypting its own request, but the M28 committee exit
//! wants a joint key where **no single party — not even the client — ever holds
//! `s`**, so a subpoena of any one party (or any minority below the threshold)
//! yields nothing.
//!
//! This is **Joint-Feldman DKG** over Ristretto. Each of the `n` members deals a
//! fresh Feldman sharing of its *own* random contribution `s_j`; the joint secret
//! is `s = Σ_j s_j` and the joint public key is `Y = Σ_j s_j·G = commitments[0]`.
//! A member's final share is `y_i = Σ_j f_j(i)`, the sum of the shares dealt to
//! it. No member ever sees another's `s_j`, and recovering `s` needs a threshold
//! of members — so no party holds it. The output — the aggregate
//! [`KeyCommitments`] and a per-member [`KeyShare`] — plugs directly into
//! [`threshold`](crate::threshold) (`encrypt` / `partial_decrypt` / `combine`),
//! because the aggregate share verifies against the aggregate commitments exactly
//! as a dealt share does: `y_i·G = Σ_j f_j(i)·G = Σ_l (Σ_j C_j[l])·i^l`.
//!
//! **Honest boundary.** This is Joint-Feldman DKG. A *rushing* adversary who sees
//! others' contributions before committing its own can bias the *distribution* of
//! the joint key `Y` (Gennaro–Jarecki–Krawczyk–Rabin, 1999). That bias reveals
//! **neither `s` nor any plaintext**, so it does not weaken M28's non-custody
//! property — but it means `Y` is not guaranteed uniformly random. The
//! Pedersen-commitment "New-DKG" that removes the bias is a documented refinement,
//! not implemented here. Fault handling is **abort-on-invalid-share**: a member
//! whose dealt share fails its own Feldman commitment is identified (via
//! [`KeyShare::verify`]) and the run aborts; a complaint/disqualification round
//! for liveness under active faults is likewise deferred.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::{Identity, IsIdentity};
use curve25519_dalek::Scalar;
use neo_core::{Error, Result};

use crate::vss::{KeyCommitments, KeyShare};
use crate::CommitteeConfig;

/// One member's DKG contribution: its secret sharing polynomial (kept private)
/// and the public Feldman commitment it broadcasts. The member deals one share
/// per participant with [`share_for`](Self::share_for).
pub struct Contribution {
    member: u8,
    members: usize,
    /// Secret polynomial `a_0..a_{k-1}` with `a_0 = s_j`, this member's
    /// contribution to the joint secret. Never leaves the member.
    poly: Vec<Scalar>,
    /// Public Feldman commitment `[a_l·G]`, broadcast to every member.
    commitment: KeyCommitments,
}

impl Contribution {
    /// Generate this member's contribution: a fresh random degree-(k-1)
    /// polynomial and its Feldman commitment. `member` is the 1-based index.
    pub fn generate(member: u8, cfg: &CommitteeConfig) -> Result<Self> {
        cfg.validate()?;
        if member == 0 || member as usize > cfg.members {
            return Err(Error::Config("DKG member index out of range".into()));
        }
        let mut poly = Vec::with_capacity(cfg.threshold);
        for _ in 0..cfg.threshold {
            poly.push(random_scalar()?);
        }
        let commitment = KeyCommitments(
            poly.iter()
                .map(|a| (RISTRETTO_BASEPOINT_POINT * a).compress())
                .collect(),
        );
        Ok(Self {
            member,
            members: cfg.members,
            poly,
            commitment,
        })
    }

    /// This member's 1-based index.
    pub fn member(&self) -> u8 {
        self.member
    }

    /// This member's public Feldman commitment, broadcast to all members.
    pub fn commitment(&self) -> &KeyCommitments {
        &self.commitment
    }

    /// The share this member deals to `recipient` (1..=n), delivered over a
    /// private channel. The recipient MUST verify it against
    /// [`commitment`](Self::commitment) with [`KeyShare::verify`] before
    /// aggregating.
    pub fn share_for(&self, recipient: u8) -> Result<KeyShare> {
        if recipient == 0 || recipient as usize > self.members {
            return Err(Error::Config("DKG recipient index out of range".into()));
        }
        let x = Scalar::from(recipient as u64);
        // Horner evaluation of the secret polynomial at x.
        let mut value = Scalar::ZERO;
        for coeff in self.poly.iter().rev() {
            value = value * x + coeff;
        }
        Ok(KeyShare {
            member: recipient,
            value,
        })
    }
}

/// Sum the members' broadcast Feldman commitments into the **joint** commitments
/// (component-wise point addition). `commitments[0]` of the result is the joint
/// public key `Y = Σ_j s_j·G`. All contributions must share the same degree
/// (threshold), and the joint key must not be the identity (a degenerate key
/// whose KEM secret would be public — rejected here and again in
/// [`threshold::encrypt`](crate::threshold::encrypt)).
pub fn joint_commitments(contributions: &[KeyCommitments]) -> Result<KeyCommitments> {
    let first = contributions
        .first()
        .ok_or_else(|| Error::Crypto("no DKG contributions".into()))?;
    let k = first.0.len();
    if k == 0 {
        return Err(Error::Crypto("empty DKG commitment".into()));
    }
    let mut acc = vec![RistrettoPoint::identity(); k];
    for c in contributions {
        if c.0.len() != k {
            return Err(Error::Crypto(
                "DKG contributions disagree on the threshold".into(),
            ));
        }
        for (slot, point) in acc.iter_mut().zip(&c.0) {
            let p = point
                .decompress()
                .ok_or_else(|| Error::Crypto("DKG commitment is not a valid point".into()))?;
            *slot += p;
        }
    }
    if acc[0].is_identity() {
        return Err(Error::Crypto(
            "DKG joint public key is the identity point".into(),
        ));
    }
    Ok(KeyCommitments(acc.iter().map(|p| p.compress()).collect()))
}

/// A member's **aggregate** share `y_i = Σ_j f_j(i)` — the sum of the shares
/// dealt to it by every member. Each dealt share MUST already have been verified
/// against its dealer's commitment ([`KeyShare::verify`]); this only sums. All
/// inputs must address the same recipient `member`. The result verifies against
/// [`joint_commitments`] of the same run.
pub fn aggregate_share(member: u8, dealt: &[KeyShare]) -> Result<KeyShare> {
    if member == 0 {
        return Err(Error::Config(
            "aggregate share for member 0 is invalid".into(),
        ));
    }
    if dealt.is_empty() {
        return Err(Error::Crypto("no dealt shares to aggregate".into()));
    }
    let mut value = Scalar::ZERO;
    for s in dealt {
        if s.member != member {
            return Err(Error::Crypto(
                "a dealt share is addressed to a different member".into(),
            ));
        }
        value += s.value;
    }
    Ok(KeyShare { member, value })
}

fn random_scalar() -> Result<Scalar> {
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold;
    use curve25519_dalek::ristretto::CompressedRistretto;

    /// Simulate a full DKG run for `cfg` in one process (test-only: a real run
    /// exchanges `Contribution`s over the network, and no single host ever holds
    /// every polynomial). Returns the joint commitments and each member's
    /// aggregate share, having verified every dealt share against its dealer.
    fn simulate(cfg: &CommitteeConfig) -> (KeyCommitments, Vec<KeyShare>) {
        let contributions: Vec<Contribution> = (1..=cfg.members as u8)
            .map(|m| Contribution::generate(m, cfg).unwrap())
            .collect();

        // Every member verifies each dealer's share to it, then aggregates.
        let mut shares = Vec::with_capacity(cfg.members);
        for recipient in 1..=cfg.members as u8 {
            let dealt: Vec<KeyShare> = contributions
                .iter()
                .map(|dealer| {
                    let s = dealer.share_for(recipient).unwrap();
                    assert!(
                        s.verify(dealer.commitment()),
                        "dealt share must verify against the dealer's commitment"
                    );
                    s
                })
                .collect();
            shares.push(aggregate_share(recipient, &dealt).unwrap());
        }

        let commitments: Vec<KeyCommitments> = contributions
            .iter()
            .map(|c| c.commitment().clone())
            .collect();
        (joint_commitments(&commitments).unwrap(), shares)
    }

    fn cfg(members: usize, threshold: usize) -> CommitteeConfig {
        CommitteeConfig { members, threshold }
    }

    #[test]
    fn aggregate_shares_verify_against_the_joint_commitments() {
        let (commitments, shares) = simulate(&cfg(5, 3));
        assert_eq!(commitments.0.len(), 3, "k commitments for a degree-2 poly");
        for share in &shares {
            assert!(
                share.verify(&commitments),
                "each member's aggregate share must verify against the joint key"
            );
        }
    }

    #[test]
    fn dkg_output_drives_threshold_decryption_no_party_holding_s() {
        // The M28 property, keyed by DKG: the egress encrypts a response to the
        // joint key; a quorum of members emit partials (never forming s or the
        // plaintext); only the client combines them to recover the response.
        let (commitments, shares) = simulate(&cfg(5, 3));
        let response = b"HTTP/1.1 200 OK\r\n\r\nsecret body no committee member may read";

        let ct = threshold::encrypt(&commitments, response).unwrap();

        // A single member (e.g. the egress) cannot decrypt its own ciphertext.
        let lone = vec![threshold::partial_decrypt(&shares[0], &ct).unwrap()];
        assert!(threshold::combine(&commitments, 3, &ct, &lone).is_err());

        // A threshold quorum's partials, combined by the client, recover it.
        let partials: Vec<_> = [0, 2, 4]
            .iter()
            .map(|&i| threshold::partial_decrypt(&shares[i], &ct).unwrap())
            .collect();
        assert_eq!(
            threshold::combine(&commitments, 3, &ct, &partials).unwrap(),
            response
        );
    }

    #[test]
    fn a_dealt_share_that_fails_its_commitment_is_caught() {
        let c = cfg(4, 3);
        let dealer = Contribution::generate(1, &c).unwrap();
        let mut share = dealer.share_for(2).unwrap();
        share.value += Scalar::ONE; // tamper the dealt share
        assert!(
            !share.verify(dealer.commitment()),
            "a member dealing a bad share is caught before aggregation"
        );
    }

    #[test]
    fn contributions_disagreeing_on_threshold_are_rejected() {
        let a = Contribution::generate(1, &cfg(3, 2)).unwrap();
        let b = Contribution::generate(1, &cfg(3, 3)).unwrap();
        assert!(joint_commitments(&[a.commitment().clone(), b.commitment().clone()]).is_err());
    }

    #[test]
    fn an_identity_joint_key_is_rejected() {
        // Two contributions whose constant terms cancel would yield Y = 0·G.
        let p = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
        let c1 = KeyCommitments(vec![p.compress(), CompressedRistretto::identity()]);
        let c2 = KeyCommitments(vec![(-p).compress(), CompressedRistretto::identity()]);
        assert!(joint_commitments(&[c1, c2]).is_err());
    }

    #[test]
    fn aggregate_share_rejects_mismatched_recipient() {
        let c = cfg(3, 2);
        let d1 = Contribution::generate(1, &c).unwrap();
        let d2 = Contribution::generate(2, &c).unwrap();
        // Shares addressed to different recipients must not be summed together.
        let mixed = vec![d1.share_for(1).unwrap(), d2.share_for(2).unwrap()];
        assert!(aggregate_share(1, &mixed).is_err());
    }
}
