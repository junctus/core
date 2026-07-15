//! **Networked masked-circuit eval** — the two-party, over-the-wire counterpart to the
//! in-process [`engine::eval_circuit`](super::engine::eval_circuit) masking seam.
//!
//! Every secret-dependent 2PC gadget in the live layer — the arithmetic→boolean share
//! conversion ([`a2b_shared`](super::convert::a2b_shared)) and the whole HKDF/HMAC key
//! schedule ([`hkdf`](super::hkdf)) — is one **768-wire** boolean circuit with the fixed
//! input layout `[shareA(256) ‖ shareB(256) ‖ maskA(256)]` whose 256-bit output is
//! `result ⊕ maskA`. In-process, `eval_circuit` assembles *both* parties' shares and the
//! mask and reads back the masked output; the gadget then hands `maskA` to party A and
//! `result ⊕ maskA` to party B as their XOR-shares (see [`hkdf`]'s convention).
//!
//! [`masked_eval`] runs that same circuit as **two separate parties over a
//! [`Channel`](super::live::channel::Channel)**, on the constant-round garbled online
//! ([`garble_net`](super::garble_net)):
//! - **Party A garbles.** It feeds its share on wires `0..256` and a fresh random mask on
//!   `512..768`; its output share **is** that mask (it learns nothing of the result).
//! - **Party B evaluates.** It feeds its share on wires `256..512` and receives
//!   `result ⊕ maskA` — its output share.
//!
//! Combined bitwise (`maskA ⊕ (result ⊕ maskA) = result`) the two shares reconstruct the
//! circuit output — under *any* consistent bit-unpacking, since XOR commutes with the
//! fixed bit permutation each gadget uses to (de)serialize its 32-byte values. This is the
//! single seam every networked key-schedule gadget routes through, so the whole handshake
//! key agreement runs in a constant number of flights per gadget over a real link.
//!
//! # Honest boundary
//! Semi-honest, exactly as [`garble_net`] (a malicious garbler is the authenticated-garbling
//! online; networking *that* constant-round is a further step). Validated: the two-party
//! networked schedule reproduces the stock RFC 8446 key schedule byte-for-byte over TCP
//! (see [`live::netschedule`](super::live::netschedule)).

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::Circuit;
use super::garble_net::{evaluator_run, garbler_run};
use super::live::channel::Channel;

/// Which side of the two-party masked eval this process plays. **A garbles** (owns
/// `shareA` + the output mask); **B evaluates** (owns `shareB`, receives the masked output).
/// The assignment is fixed for a whole session so every sub-protocol (ECtF, A2B, the key
/// schedule) uses the same role split on the one channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    A,
    B,
}

/// Evaluate one 768-wire `[shareA ‖ shareB ‖ maskA]` gadget circuit over `ch`, returning
/// **this party's XOR-share** of the 256-bit output. `my_share` is this party's 256 input
/// bits (placed on `0..256` for A, `256..512` for B). Party A returns the random mask it
/// injected; party B returns `result ⊕ maskA`. See the module docs for why the two combine
/// to the circuit output under any consistent unpacking.
pub fn masked_eval(
    ch: &mut dyn Channel,
    party: Party,
    circuit: &Circuit,
    my_share: &[bool],
) -> Result<Vec<bool>> {
    if circuit.input_bits != 768 || my_share.len() != 256 {
        return Err(Error::Crypto(
            "netengine: expected a 768-wire [shareA|shareB|maskA] gadget with a 256-bit share"
                .into(),
        ));
    }
    let ev: HashSet<usize> = (256..512).collect(); // shareB is the evaluator's
    match party {
        Party::A => {
            let mut mask = vec![false; 256];
            let mut raw = [0u8; 32];
            getrandom::getrandom(&mut raw).map_err(|e| Error::Rng(e.to_string()))?;
            for (i, m) in mask.iter_mut().enumerate() {
                *m = (raw[i / 8] >> (i % 8)) & 1 == 1;
            }
            let mut g_in = vec![false; 768];
            g_in[0..256].copy_from_slice(my_share);
            g_in[512..768].copy_from_slice(&mask);
            garbler_run(ch, circuit, &ev, &g_in)?;
            Ok(mask) // A's share = the mask it injected
        }
        Party::B => {
            let mut e_in = vec![false; 768];
            e_in[256..512].copy_from_slice(my_share);
            evaluator_run(ch, circuit, &ev, &e_in) // B's share = result ⊕ maskA
        }
    }
}
