//! Earn-side accounting: bind credit issuance to *proven relayed bandwidth*.
//!
//! The VOPRF credits in the crate root are unlinkable at spend time, but nothing
//! yet gates who may *earn* one. This module supplies the proof-of-relay: a
//! client that a relay served signs a [`RelayReceipt`] attesting how many bytes
//! the relay forwarded for a given circuit. A relay accumulates receipts in an
//! [`EarnLedger`]; once its proven bytes cross [`BYTES_PER_CREDIT`], it is owed a
//! credit and may run the (blinded, identified) issuance flow.
//!
//! Earning is **identified** — the relay proves it did work — while spending
//! stays **anonymous** via the VOPRF blinding, so the issuer still cannot link
//! earn ↔ spend. Honest limit: the proof is a *client-attested* receipt, not a
//! trustless bandwidth measurement (an open problem even Tor does not solve).
//! Colluding client+relay can still mint receipts for unperformed work; receipts
//! bound Sybil/free-riding to the cost of running clients, not to zero. A future
//! refinement is bilateral receipts (both adjacent hops co-sign).

use std::collections::{HashMap, HashSet};

use neo_core::{verify_signature, Error, NodeId, NodeIdentity, Result, SIGNATURE_LEN};

/// Bytes a relay must prove it forwarded to earn one credit.
pub const BYTES_PER_CREDIT: u64 = 1_000_000;

/// Domain separator for receipt signatures.
const RECEIPT_DOMAIN: &[u8] = b"neo-relay-receipt-v1";

/// A client's signed attestation that `relay` forwarded `bytes` for a circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayReceipt {
    /// The relay being credited.
    pub relay: NodeId,
    /// Bytes the client attests the relay forwarded.
    pub bytes: u64,
    /// Per-circuit nonce, unique per receipt — prevents double-claiming.
    pub nonce: [u8; 32],
    /// The attesting client's Ed25519 verifying key.
    pub client: [u8; 32],
    /// The client's signature over the receipt body.
    pub sig: [u8; SIGNATURE_LEN],
}

impl RelayReceipt {
    /// A client issues a receipt crediting `relay` for `bytes` on circuit `nonce`.
    pub fn issue(client: &NodeIdentity, relay: NodeId, bytes: u64, nonce: [u8; 32]) -> Self {
        let mut receipt = RelayReceipt {
            relay,
            bytes,
            nonce,
            client: client.public().signing.to_bytes(),
            sig: [0u8; SIGNATURE_LEN],
        };
        receipt.sig = client.sign(&receipt.signable()).to_bytes();
        receipt
    }

    /// Verify the client's signature over the receipt.
    pub fn verify(&self) -> Result<()> {
        verify_signature(&self.client, &self.signable(), &self.sig)
    }

    fn signable(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECEIPT_DOMAIN.len() + 72);
        out.extend_from_slice(RECEIPT_DOMAIN);
        out.extend_from_slice(self.relay.as_bytes());
        out.extend_from_slice(&self.bytes.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.client);
        out
    }
}

/// Tracks proven relayed bytes per relay and converts them into earned credits.
#[derive(Default)]
pub struct EarnLedger {
    /// Proven bytes not yet converted to credits, per relay.
    residual_bytes: HashMap<NodeId, u64>,
    /// `(relay, client, nonce)` triples already counted — replay/double-claim guard.
    claimed: HashSet<(NodeId, [u8; 32], [u8; 32])>,
}

impl EarnLedger {
    /// A new, empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and record a receipt. Returns the number of *whole new credits* the
    /// relay has earned as a result (0 if it hasn't crossed the next threshold),
    /// deducting the corresponding bytes. Rejects forged or already-claimed
    /// receipts.
    pub fn record(&mut self, receipt: &RelayReceipt) -> Result<u64> {
        receipt.verify()?;
        let key = (receipt.relay, receipt.client, receipt.nonce);
        if !self.claimed.insert(key) {
            return Err(Error::Crypto("relay receipt already claimed".into()));
        }
        let bucket = self.residual_bytes.entry(receipt.relay).or_insert(0);
        *bucket = bucket.saturating_add(receipt.bytes);
        let earned = *bucket / BYTES_PER_CREDIT;
        *bucket -= earned * BYTES_PER_CREDIT;
        Ok(earned)
    }

    /// Proven bytes credited to `relay` that haven't yet become a whole credit.
    pub fn residual(&self, relay: &NodeId) -> u64 {
        self.residual_bytes.get(relay).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{finalize, request, Issuer};

    fn nonce(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn receipts_verify_and_accumulate_into_credits() {
        let client = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap().id();
        let mut ledger = EarnLedger::new();

        // Two half-credit receipts add up to exactly one credit.
        let half = BYTES_PER_CREDIT / 2;
        let r1 = RelayReceipt::issue(&client, relay, half, nonce(1));
        let r2 = RelayReceipt::issue(&client, relay, half, nonce(2));
        assert_eq!(ledger.record(&r1).unwrap(), 0);
        assert_eq!(ledger.record(&r2).unwrap(), 1, "two halves make one credit");
        assert_eq!(ledger.residual(&relay), 0);
    }

    #[test]
    fn forged_and_replayed_receipts_are_rejected() {
        let client = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap().id();
        let mut ledger = EarnLedger::new();

        // Tampered byte count invalidates the signature.
        let mut forged = RelayReceipt::issue(&client, relay, 10, nonce(1));
        forged.bytes = BYTES_PER_CREDIT * 1000;
        assert!(forged.verify().is_err());
        assert!(ledger.record(&forged).is_err());

        // Replaying the same receipt is rejected.
        let honest = RelayReceipt::issue(&client, relay, 10, nonce(2));
        assert_eq!(ledger.record(&honest).unwrap(), 0);
        assert!(
            ledger.record(&honest).is_err(),
            "the same receipt cannot be claimed twice"
        );
    }

    #[test]
    fn earning_gates_an_unlinkable_credit_issuance() {
        // Full lifecycle: prove relay work → earn a credit → get an unlinkable
        // spendable token via the VOPRF issuer.
        let client = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap().id();
        let mut ledger = EarnLedger::new();
        let mut issuer = Issuer::new().unwrap();

        // Prove a full credit's worth of relaying.
        let receipt = RelayReceipt::issue(&client, relay, BYTES_PER_CREDIT, nonce(7));
        let earned = ledger.record(&receipt).unwrap();
        assert_eq!(earned, 1, "one credit earned");

        // Gate issuance on the earned credit, then run the anonymous flow.
        assert!(earned >= 1);
        let (blinded, secret) = request().unwrap();
        let issued = issuer.issue(&blinded).unwrap();
        let credit = finalize(secret, issued).unwrap();
        assert!(
            issuer.redeem(&credit).is_ok(),
            "the earned credit spends once"
        );
        assert!(issuer.redeem(&credit).is_err(), "and only once");
    }
}
