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

use neo_core::{Error, Result};
use voprf::{
    BlindedElement, EvaluationElement, Group, Proof, Ristretto255, VoprfClient, VoprfServer,
};

const SERIAL_LEN: usize = 32;

/// The credit issuer (holds the VOPRF key).
pub struct Issuer {
    server: VoprfServer<Ristretto255>,
    spent: HashSet<Vec<u8>>,
}

impl Issuer {
    /// Generate a fresh issuer key.
    pub fn new() -> Result<Self> {
        let server = VoprfServer::<Ristretto255>::new(&mut rand::rngs::OsRng)
            .map_err(|e| Error::Crypto(format!("credit keygen: {e}")))?;
        Ok(Self {
            server,
            spent: HashSet::new(),
        })
    }

    /// The issuer's public key. Clients need it to verify that a blind evaluation
    /// was performed under the issuer's committed key (the DLEQ proof binds to it),
    /// so it should be published/pinned out of band, not fetched per-issuance.
    pub fn public_key(&self) -> IssuerPublicKey {
        IssuerPublicKey(Ristretto255::serialize_elem(self.server.get_public_key()).to_vec())
    }

    /// Blind-evaluate a client's blinded credit — done once the node has earned
    /// it. The issuer never sees the serial, and returns a DLEQ proof that the
    /// evaluation used its committed key.
    pub fn issue(&self, blinded: &BlindCredit) -> Result<IssuedCredit> {
        let element = BlindedElement::<Ristretto255>::deserialize(&blinded.0)
            .map_err(|e| Error::Decode(format!("blinded element: {e}")))?;
        let evaluated = self.server.blind_evaluate(&mut rand::rngs::OsRng, &element);
        Ok(IssuedCredit {
            element: evaluated.message.serialize().to_vec(),
            proof: evaluated.proof.serialize().to_vec(),
        })
    }

    /// Redeem a credit: recompute the OPRF over its serial, check the token, and
    /// reject double-spends.
    pub fn redeem(&mut self, credit: &Credit) -> Result<()> {
        let expected = self
            .server
            .evaluate(&credit.serial)
            .map_err(|e| Error::Crypto(format!("evaluate: {e}")))?;
        if expected.as_slice() != credit.token.as_slice() {
            return Err(Error::Crypto("invalid credit".into()));
        }
        if !self.spent.insert(credit.serial.clone()) {
            return Err(Error::Crypto("credit already spent".into()));
        }
        Ok(())
    }
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

    #[test]
    fn credit_is_unlinkable_verifiable_and_single_use() {
        let mut issuer = Issuer::new().unwrap();
        let pk = issuer.public_key();

        // Client blinds a random serial; issuer blind-evaluates it (earned by relaying).
        let (blinded, secret) = request().unwrap();
        let issued = issuer.issue(&blinded).unwrap();
        let credit = finalize(secret, issued, &pk).unwrap();

        // Spend it once; a second spend is rejected.
        assert!(issuer.redeem(&credit).is_ok());
        assert!(
            issuer.redeem(&credit).is_err(),
            "double-spend must be rejected"
        );
    }

    #[test]
    fn tampered_credit_is_rejected() {
        let mut issuer = Issuer::new().unwrap();
        let pk = issuer.public_key();
        let (blinded, secret) = request().unwrap();
        let issued = issuer.issue(&blinded).unwrap();
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
        let rogue = Issuer::new().unwrap();
        let honest_pk = honest.public_key();

        let (blinded, secret) = request().unwrap();
        let issued = rogue.issue(&blinded).unwrap();
        assert!(
            finalize(secret, issued, &honest_pk).is_err(),
            "a proof under the wrong key must not finalize"
        );
    }
}
