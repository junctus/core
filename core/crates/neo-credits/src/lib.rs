//! `neo-credits` — anonymous bandwidth credits (frontier, M10).
//!
//! Unlinkable, token-free credits built on a **VOPRF** (the Privacy Pass
//! primitive). A node **earns** a credit by relaying: it blinds a random serial,
//! the issuer blind-evaluates it (without seeing the serial), and the node
//! finalizes a token. It **spends** the credit by presenting `(serial, token)`;
//! the issuer recomputes the OPRF and checks it. Because the issuer only ever saw
//! a *blinded* serial at issuance, it cannot link issuance to spending — the
//! credits are unlinkable. A spend log rejects double-spends.
//!
//! Earning a credit costs real relayed bandwidth, so forging N identities costs N
//! identities' worth of bandwidth — one mechanism against both Sybil attacks and
//! free-riding, with **no blockchain token**.

#![forbid(unsafe_code)]

use std::collections::HashSet;

use neo_core::{Error, Result};
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer, Ristretto255};

const SERIAL_LEN: usize = 32;

/// The credit issuer (holds the OPRF key).
pub struct Issuer {
    server: OprfServer<Ristretto255>,
    spent: HashSet<Vec<u8>>,
}

impl Issuer {
    /// Generate a fresh issuer key.
    pub fn new() -> Result<Self> {
        let server = OprfServer::<Ristretto255>::new(&mut rand::rngs::OsRng)
            .map_err(|e| Error::Crypto(format!("credit keygen: {e}")))?;
        Ok(Self {
            server,
            spent: HashSet::new(),
        })
    }

    /// Blind-evaluate a client's blinded credit — done once the node has earned
    /// it. The issuer never sees the serial.
    pub fn issue(&self, blinded: &BlindCredit) -> Result<IssuedCredit> {
        let element = BlindedElement::<Ristretto255>::deserialize(&blinded.0)
            .map_err(|e| Error::Decode(format!("blinded element: {e}")))?;
        let evaluated = self.server.blind_evaluate(&element);
        Ok(IssuedCredit(evaluated.serialize().to_vec()))
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

/// A blinded credit request, sent to the issuer (reveals nothing about the serial).
pub struct BlindCredit(Vec<u8>);

/// Client-held state to finalize a signed credit. Keep private.
pub struct CreditSecret {
    client: OprfClient<Ristretto255>,
    serial: Vec<u8>,
}

/// The issuer's blind evaluation of a blinded credit.
pub struct IssuedCredit(Vec<u8>);

/// A finalized, spendable, unlinkable credit.
pub struct Credit {
    serial: Vec<u8>,
    token: Vec<u8>,
}

/// Create a blinded request for a fresh random-serial credit (client-side).
pub fn request() -> Result<(BlindCredit, CreditSecret)> {
    let mut serial = vec![0u8; SERIAL_LEN];
    getrandom::getrandom(&mut serial).map_err(|e| Error::Rng(e.to_string()))?;
    let blind = OprfClient::<Ristretto255>::blind(&serial, &mut rand::rngs::OsRng)
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
pub fn finalize(secret: CreditSecret, issued: IssuedCredit) -> Result<Credit> {
    let evaluated = EvaluationElement::<Ristretto255>::deserialize(&issued.0)
        .map_err(|e| Error::Decode(format!("evaluation element: {e}")))?;
    let token = secret
        .client
        .finalize(&secret.serial, &evaluated)
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

        // Client blinds a random serial; issuer blind-evaluates it (earned by relaying).
        let (blinded, secret) = request().unwrap();
        let issued = issuer.issue(&blinded).unwrap();
        let credit = finalize(secret, issued).unwrap();

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
        let (blinded, secret) = request().unwrap();
        let issued = issuer.issue(&blinded).unwrap();
        let mut credit = finalize(secret, issued).unwrap();

        credit.token[0] ^= 0xff; // token no longer matches OPRF(serial)
        assert!(issuer.redeem(&credit).is_err());
    }
}
