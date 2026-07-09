//! 1-out-of-2 **oblivious transfer** — Chou–Orlandi ("the simplest OT"), the
//! primitive that lets a garbled-circuit evaluator fetch the input labels for its
//! own bits without the garbler learning those bits, and without the evaluator
//! learning the labels it did not choose.
//!
//! Semi-honest: this is the standard model for classic garbled-circuit 2PC. A
//! maliciously-secure variant (consistency checks / correlation-robust OT
//! extension) is the hardening path, noted in the parent module.
//!
//! The parties are modelled as message-passing functions (the transport is the
//! caller's): `sender_setup → receiver_choose → sender_send → receiver_finish`.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as B;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::Scalar;
use neo_core::{Error, Result};

/// The width of a transferred message (a garbled-circuit wire label).
pub const MSG_LEN: usize = 16;

/// The sender's per-transfer setup: a secret `y` and the public `S = y·B`.
pub struct SenderSetup {
    y: Scalar,
    /// The public point `S = y·B`, sent to the receiver.
    pub s: RistrettoPoint,
}

/// The receiver's per-transfer state: a secret `x`, the public `R`, and the
/// (hidden) choice bit.
pub struct ReceiverChoice {
    x: Scalar,
    /// The public point `R`, sent to the sender.
    pub r: RistrettoPoint,
    choice: bool,
}

/// Sender step 1: publish `S = y·B`.
pub fn sender_setup() -> Result<SenderSetup> {
    let y = random_scalar()?;
    Ok(SenderSetup { y, s: B * y })
}

/// Receiver step 1: given the sender's `S` and a choice bit, publish `R`.
/// `R = x·B` for choice 0, `R = S + x·B` for choice 1.
pub fn receiver_choose(s: &RistrettoPoint, choice: bool) -> Result<ReceiverChoice> {
    let x = random_scalar()?;
    let r = if choice { s + B * x } else { B * x };
    Ok(ReceiverChoice { x, r, choice })
}

/// Sender step 2: encrypt both messages to the receiver's `R`. The receiver can
/// only recover the one matching its choice bit.
pub fn sender_send(
    setup: &SenderSetup,
    r: &RistrettoPoint,
    m0: &[u8; MSG_LEN],
    m1: &[u8; MSG_LEN],
) -> ([u8; MSG_LEN], [u8; MSG_LEN]) {
    let yr = r * setup.y; // y·R  → equals x·S when choice = 0
    let t = setup.s * setup.y; // T = y·S = y²·B
    let k0 = pad(&setup.s, r, &yr);
    let k1 = pad(&setup.s, r, &(yr - t)); // y·R − T → equals x·S when choice = 1
    (xor(m0, &k0), xor(m1, &k1))
}

/// Receiver step 2: recover `m_choice` (and nothing about the other message).
pub fn receiver_finish(
    choice: &ReceiverChoice,
    s: &RistrettoPoint,
    e0: &[u8; MSG_LEN],
    e1: &[u8; MSG_LEN],
) -> [u8; MSG_LEN] {
    let xs = s * choice.x; // x·S
    let k = pad(s, &choice.r, &xs);
    xor(if choice.choice { e1 } else { e0 }, &k)
}

fn pad(s: &RistrettoPoint, r: &RistrettoPoint, key: &RistrettoPoint) -> [u8; MSG_LEN] {
    let mut h = blake3::Hasher::new_derive_key("neo-mpc-ot-v1");
    h.update(s.compress().as_bytes());
    h.update(r.compress().as_bytes());
    h.update(key.compress().as_bytes());
    let mut out = [0u8; MSG_LEN];
    out.copy_from_slice(&h.finalize().as_bytes()[..MSG_LEN]);
    out
}

fn xor(a: &[u8; MSG_LEN], b: &[u8; MSG_LEN]) -> [u8; MSG_LEN] {
    let mut out = [0u8; MSG_LEN];
    for i in 0..MSG_LEN {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn random_scalar() -> Result<Scalar> {
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_ot(choice: bool, m0: [u8; 16], m1: [u8; 16]) -> [u8; 16] {
        let setup = sender_setup().unwrap();
        let rc = receiver_choose(&setup.s, choice).unwrap();
        let (e0, e1) = sender_send(&setup, &rc.r, &m0, &m1);
        receiver_finish(&rc, &setup.s, &e0, &e1)
    }

    #[test]
    fn receiver_gets_exactly_the_chosen_message() {
        let m0 = [0x11u8; 16];
        let m1 = [0x22u8; 16];
        assert_eq!(run_ot(false, m0, m1), m0, "choice 0 → m0");
        assert_eq!(run_ot(true, m0, m1), m1, "choice 1 → m1");
    }

    #[test]
    fn the_unchosen_message_is_not_revealed() {
        // Recovering with the wrong ciphertext under the receiver's key yields
        // garbage, not the other message — the receiver learns only m_choice.
        let m0 = [0xaau8; 16];
        let m1 = [0x55u8; 16];
        let setup = sender_setup().unwrap();
        let rc = receiver_choose(&setup.s, false).unwrap(); // choice 0
        let (_e0, e1) = sender_send(&setup, &rc.r, &m0, &m1);
        // The receiver's key only opens e0; applying it to e1 must not give m1.
        let wrong = receiver_finish(&rc, &setup.s, &e1, &e1);
        assert_ne!(wrong, m1, "the unchosen message stays hidden");
    }

    #[test]
    fn distinct_transfers_are_independent() {
        let m0 = [1u8; 16];
        let m1 = [2u8; 16];
        // Two independent OT instances both succeed with fresh randomness.
        assert_eq!(run_ot(true, m0, m1), m1);
        assert_eq!(run_ot(false, m0, m1), m0);
    }
}
