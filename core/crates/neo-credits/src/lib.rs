//! `neo-credits` — anonymous bandwidth credits (frontier, M10).
//!
//! Unlinkable, token-free credits built on a **VOPRF** (the Privacy Pass
//! primitive, *verifiable* mode). A node **earns** a credit by relaying: it
//! blinds a random serial, the issuer blind-evaluates it (without seeing the
//! serial) and returns a **DLEQ proof** that it used its one committed key, and
//! the node finalizes a token — rejecting the result if the proof fails. It
//! **spends** the credit by presenting `(serial, token)`; the issuer recomputes
//! the OPRF and checks it. Because the issuer only ever saw a *blinded* serial at
//! issuance, it cannot link issuance to spending — the credits are unlinkable. A
//! spend log rejects double-spends.
//!
//! Verifiability matters for anonymity, not just correctness: with a *base* OPRF
//! a malicious issuer could blind-evaluate different earners under different keys
//! and later tell, at redeem time, which key a spend verifies under — partitioning
//! the anonymity set. The VOPRF proof forces one published key for everyone, so a
//! spend cannot be traced back to an earner by key-tagging.
//!
//! Earning a credit costs real relayed bandwidth, so forging N identities costs N
//! identities' worth of bandwidth — one mechanism against both Sybil attacks and
//! free-riding, with **no blockchain token**.

#![forbid(unsafe_code)]

pub mod earn;

use std::collections::HashSet;

use earn::{EarnLedger, RelayReceipt};
use neo_core::{Error, NodeId, Result};
use voprf::{
    BlindedElement, EvaluationElement, Group, Proof, Ristretto255, VoprfClient, VoprfServer,
};

const SERIAL_LEN: usize = 32;

/// The credit issuer (holds the VOPRF key and the earn ledger that gates issuance).
///
/// The double-spend set is **key-epoch-scoped**: rotating the key ([`rotate_key`])
/// retires the old key for one grace epoch (so outstanding credits still redeem)
/// and drops the epoch before it, bounding the spent set to ~2 epochs of serials
/// rather than growing forever. Operators rotate on a schedule (e.g. daily).
///
/// **Boundary:** the spent set is in-memory; persisting it across restarts (so a
/// redeploy cannot re-enable replay of the current epoch's serials) is M32.
pub struct Issuer {
    current: VoprfServer<Ristretto255>,
    /// Retained one epoch for a redeem grace window after rotation.
    previous: Option<VoprfServer<Ristretto255>>,
    spent_current: HashSet<Vec<u8>>,
    spent_previous: HashSet<Vec<u8>>,
    ledger: EarnLedger,
}

impl Issuer {
    /// Generate a fresh issuer key.
    pub fn new() -> Result<Self> {
        let current = VoprfServer::<Ristretto255>::new(&mut rand::rngs::OsRng)
            .map_err(|e| Error::Crypto(format!("credit keygen: {e}")))?;
        Ok(Self {
            current,
            previous: None,
            spent_current: HashSet::new(),
            spent_previous: HashSet::new(),
            ledger: EarnLedger::new(),
        })
    }

    /// The issuer's current public key. Clients need it to verify that a blind
    /// evaluation was performed under the issuer's committed key (the DLEQ proof
    /// binds to it), so it should be published/pinned out of band.
    pub fn public_key(&self) -> IssuerPublicKey {
        IssuerPublicKey(Ristretto255::serialize_elem(self.current.get_public_key()).to_vec())
    }

    /// Rotate the issuer key. The old key is kept for **one** grace epoch so
    /// already-issued credits still redeem; the epoch before it is dropped, which
    /// retires (and frees) its spent set. Publish the new [`public_key`] to clients.
    pub fn rotate_key(&mut self) -> Result<()> {
        let fresh = VoprfServer::<Ristretto255>::new(&mut rand::rngs::OsRng)
            .map_err(|e| Error::Crypto(format!("credit keygen: {e}")))?;
        self.previous = Some(std::mem::replace(&mut self.current, fresh));
        self.spent_previous = std::mem::take(&mut self.spent_current);
        Ok(())
    }

    /// Record a proof-of-relay receipt (as of time `now`) against the issuer's
    /// ledger, crediting the earning relay. Returns the number of whole new credits
    /// earned. This is the **only** way a relay accrues the earned balance
    /// [`issue`](Issuer::issue) requires.
    pub fn record_receipt(&mut self, now: u64, receipt: &RelayReceipt) -> Result<u64> {
        self.ledger.record(now, receipt)
    }

    /// Whole earned credits `relay` has not yet redeemed for a token.
    pub fn earned_balance(&self, relay: &NodeId) -> u64 {
        self.ledger.earned_balance(relay)
    }

    /// Blind-evaluate a client's blinded credit for the identified earning `relay`.
    /// **Gated on earning:** it consumes one of the relay's earned credits (from
    /// receipts recorded via [`record_receipt`](Issuer::record_receipt)) and fails
    /// if the relay has none — so tokens cannot be minted without proven work.
    ///
    /// Issuance is *identified* (the issuer sees `relay` and can rate-limit it) but
    /// the serial stays blinded, so spend remains unlinkable to the earning relay.
    pub fn issue(&mut self, relay: &NodeId, blinded: &BlindCredit) -> Result<IssuedCredit> {
        // Validate the blinded element *before* consuming an earned credit, so a
        // malformed request is rejected without burning the relay's balance.
        let element = BlindedElement::<Ristretto255>::deserialize(&blinded.0)
            .map_err(|e| Error::Decode(format!("blinded element: {e}")))?;
        if !self.ledger.redeem_earned(relay) {
            return Err(Error::Crypto(
                "relay has no earned credit to issue against".into(),
            ));
        }
        let evaluated = self
            .current
            .blind_evaluate(&mut rand::rngs::OsRng, &element);
        Ok(IssuedCredit {
            element: evaluated.message.serialize().to_vec(),
            proof: evaluated.proof.serialize().to_vec(),
        })
    }

    /// Redeem a credit: recompute the OPRF over its serial under the current key
    /// (or the previous key during the post-rotation grace window), check the
    /// token, and reject double-spends within that key's epoch.
    ///
    /// This uses the issuer's own (non-verifiable) `evaluate`, so it is sound only
    /// when the issuer *is* the verifier (as here). It is not a third-party-
    /// verifiable spend proof — that would require the VOPRF verification path with
    /// a DLEQ proof, as issuance already uses.
    pub fn redeem(&mut self, credit: &Credit) -> Result<()> {
        // Current key.
        if token_matches(&self.current, credit) {
            return if self.spent_current.insert(credit.serial.clone()) {
                Ok(())
            } else {
                Err(Error::Crypto("credit already spent".into()))
            };
        }
        // Previous key (grace window after a rotation).
        if let Some(prev) = &self.previous {
            if token_matches(prev, credit) {
                return if self.spent_previous.insert(credit.serial.clone()) {
                    Ok(())
                } else {
                    Err(Error::Crypto("credit already spent".into()))
                };
            }
        }
        Err(Error::Crypto("invalid credit".into()))
    }
}

/// Whether `credit`'s token is the OPRF of its serial under `server`'s key.
fn token_matches(server: &VoprfServer<Ristretto255>, credit: &Credit) -> bool {
    server
        .evaluate(&credit.serial)
        .map(|expected| expected.as_slice() == credit.token.as_slice())
        .unwrap_or(false)
}

/// The issuer's committed public key, needed to verify blind evaluations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerPublicKey(Vec<u8>);

/// A blinded credit request, sent to the issuer (reveals nothing about the serial).
pub struct BlindCredit(Vec<u8>);

/// Client-held state to finalize a signed credit. Keep private.
pub struct CreditSecret {
    client: VoprfClient<Ristretto255>,
    serial: Vec<u8>,
}

/// The issuer's blind evaluation of a blinded credit, with its DLEQ proof.
pub struct IssuedCredit {
    element: Vec<u8>,
    proof: Vec<u8>,
}

/// A finalized, spendable, unlinkable credit.
pub struct Credit {
    serial: Vec<u8>,
    token: Vec<u8>,
}

/// Create a blinded request for a fresh random-serial credit (client-side).
pub fn request() -> Result<(BlindCredit, CreditSecret)> {
    let mut serial = vec![0u8; SERIAL_LEN];
    getrandom::getrandom(&mut serial).map_err(|e| Error::Rng(e.to_string()))?;
    let blind = VoprfClient::<Ristretto255>::blind(&serial, &mut rand::rngs::OsRng)
        .map_err(|e| Error::Crypto(format!("blind: {e}")))?;
    Ok((
        BlindCredit(blind.message.serialize().to_vec()),
        CreditSecret {
            client: blind.state,
            serial,
        },
    ))
}

/// Finalize a blind-evaluated credit into a spendable token (client-side).
///
/// Fails if the issuer's DLEQ proof does not verify against `issuer_pk` — i.e. if
/// the issuer tried to evaluate under a key other than its committed one.
pub fn finalize(
    secret: CreditSecret,
    issued: IssuedCredit,
    issuer_pk: &IssuerPublicKey,
) -> Result<Credit> {
    let evaluated = EvaluationElement::<Ristretto255>::deserialize(&issued.element)
        .map_err(|e| Error::Decode(format!("evaluation element: {e}")))?;
    let proof = Proof::<Ristretto255>::deserialize(&issued.proof)
        .map_err(|e| Error::Decode(format!("proof: {e}")))?;
    let pk = Ristretto255::deserialize_elem(&issuer_pk.0)
        .map_err(|e| Error::Decode(format!("issuer public key: {e}")))?;
    let token = secret
        .client
        .finalize(&secret.serial, &evaluated, &proof, pk)
        .map_err(|e| Error::Crypto(format!("finalize: {e}")))?;
    Ok(Credit {
        serial: secret.serial,
        token: token.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::earn::{RelayReceipt, BYTES_PER_CREDIT};

    /// Earn one credit for a fresh relay on `issuer`, returning the relay id.
    fn earn_credit(issuer: &mut Issuer, nonce: u8) -> NodeId {
        let client = neo_core::NodeIdentity::generate().unwrap();
        let relay = neo_core::NodeIdentity::generate().unwrap().id();
        let now = 1_000_000;
        let receipt =
            RelayReceipt::issue(&client, relay, BYTES_PER_CREDIT, [nonce; 32], now + 3600);
        assert_eq!(issuer.record_receipt(now, &receipt).unwrap(), 1);
        relay
    }

    #[test]
    fn credit_is_unlinkable_verifiable_and_single_use() {
        let mut issuer = Issuer::new().unwrap();
        let pk = issuer.public_key();
        let relay = earn_credit(&mut issuer, 1);

        // Client blinds a random serial; issuer blind-evaluates the earned credit.
        let (blinded, secret) = request().unwrap();
        let issued = issuer.issue(&relay, &blinded).unwrap();
        let credit = finalize(secret, issued, &pk).unwrap();

        // Spend it once; a second spend is rejected.
        assert!(issuer.redeem(&credit).is_ok());
        assert!(
            issuer.redeem(&credit).is_err(),
            "double-spend must be rejected"
        );
    }

    #[test]
    fn issuance_requires_a_proven_earned_credit() {
        // The anti-Sybil premise: issue() mints nothing without proven earning.
        let mut issuer = Issuer::new().unwrap();
        let relay = neo_core::NodeIdentity::generate().unwrap().id();
        let (blinded, _secret) = request().unwrap();
        assert!(
            issuer.issue(&relay, &blinded).is_err(),
            "issuance without an earned credit must be refused"
        );

        // After earning exactly one credit, issue() works once and only once.
        let relay = earn_credit(&mut issuer, 9);
        let (b1, _) = request().unwrap();
        assert!(issuer.issue(&relay, &b1).is_ok());
        let (b2, _) = request().unwrap();
        assert!(
            issuer.issue(&relay, &b2).is_err(),
            "a single earned credit issues a single token"
        );
    }

    #[test]
    fn key_rotation_keeps_a_grace_window_then_retires_old_credits() {
        let mut issuer = Issuer::new().unwrap();
        let pk = issuer.public_key();
        let relay = earn_credit(&mut issuer, 20);
        let (blinded, secret) = request().unwrap();
        let credit = finalize(secret, issuer.issue(&relay, &blinded).unwrap(), &pk).unwrap();

        // One rotation: the credit still redeems via the previous-key grace window.
        issuer.rotate_key().unwrap();
        assert!(
            issuer.redeem(&credit).is_ok(),
            "grace window redeems an outstanding credit"
        );

        // A credit issued under the now-current key, two rotations later, is retired.
        let relay2 = earn_credit(&mut issuer, 21);
        let pk2 = issuer.public_key();
        let (b2, s2) = request().unwrap();
        let old = finalize(s2, issuer.issue(&relay2, &b2).unwrap(), &pk2).unwrap();
        issuer.rotate_key().unwrap();
        issuer.rotate_key().unwrap();
        assert!(
            issuer.redeem(&old).is_err(),
            "a credit two rotations old no longer redeems"
        );
    }

    #[test]
    fn tampered_credit_is_rejected() {
        let mut issuer = Issuer::new().unwrap();
        let pk = issuer.public_key();
        let relay = earn_credit(&mut issuer, 2);
        let (blinded, secret) = request().unwrap();
        let issued = issuer.issue(&relay, &blinded).unwrap();
        let mut credit = finalize(secret, issued, &pk).unwrap();

        credit.token[0] ^= 0xff; // token no longer matches OPRF(serial)
        assert!(issuer.redeem(&credit).is_err());
    }

    #[test]
    fn evaluation_under_the_wrong_key_is_caught_by_the_proof() {
        // A malicious issuer blind-evaluates under a key other than the one it
        // published. The DLEQ proof fails, so the client rejects at finalize —
        // this is what stops key-tagging deanonymization.
        let honest = Issuer::new().unwrap();
        let mut rogue = Issuer::new().unwrap();
        let honest_pk = honest.public_key();
        let relay = earn_credit(&mut rogue, 3);

        let (blinded, secret) = request().unwrap();
        let issued = rogue.issue(&relay, &blinded).unwrap();
        assert!(
            finalize(secret, issued, &honest_pk).is_err(),
            "a proof under the wrong key must not finalize"
        );
    }
}
