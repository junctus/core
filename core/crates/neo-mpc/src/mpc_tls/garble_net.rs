//! **Networked constant-round garbled-circuit online** — the two-party form of
//! [`garble::eval_2pc`](super::garble), run over a [`Channel`](super::live::channel::Channel).
//!
//! The whole point is **round complexity independent of the circuit**: unlike the
//! interactive authenticated online ([`netprep::eval_authenticated`](super::netprep), one
//! Beaver round-trip *per AND gate* — days for a TLS circuit over a WAN), a garbled circuit
//! is evaluated in a **fixed 3 flights** no matter how deep the circuit:
//!
//! 1. **G → E**: the garbled AND tables + output decoding + the garbler's own input labels
//!    + the OT sender setups (one point per evaluator input wire).
//! 2. **E → G**: the OT receiver responses (one point per evaluator input wire).
//! 3. **G → E**: the OT ciphertexts.
//!
//! Then the evaluator evaluates **locally** and decodes. Bandwidth is `O(circuit)` (the
//! garbled tables), but round-trips are `O(1)` — the difference between *seconds* and
//! *days* over a real link. This is what makes a networked-party live 2PC-TLS session
//! feasible; the higher-level gadgets run their masked circuit through [`garbler_run`] /
//! [`evaluator_run`] (see the networked-HMAC test in [`hkdf`](super::hkdf)).
//!
//! # Honest boundary
//! - **Semi-honest**, exactly as [`garble`](super::garble): the garbler is trusted to
//!   garble honestly (a malicious garbler is [`authgarble`](super::authgarble)'s
//!   authenticated garbling — networking *that* is the malicious constant-round online, a
//!   further step). The base OT is [`ot`](super::ot) (Chou–Orlandi); for many evaluator
//!   input wires a deployment swaps it for KOS OT-extension (bandwidth, not rounds).
//! - Validated: the networked evaluation reproduces the in-process
//!   [`eval_2pc`](super::garble::eval_2pc) / the plaintext circuit over real TCP (tests),
//!   including the actual SHA-256 key-schedule circuit in a fixed 3 flights.

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::Circuit;
use super::garble::{decode, evaluate, AndTable, Garbler, Label};
use super::kos;
use super::live::channel::Channel;

/// AND tables streamed per `ch.send`/`recv` on flight 1 — 32 KiB of scratch, so neither
/// party ever buffers the whole (message-sized) table set. The wire bytes are identical to
/// one big send (the channel is an unframed byte stream).
const TABLES_PER_CHUNK: usize = 1024;

fn label16(buf: &[u8]) -> Label {
    buf.try_into().expect("16-byte label")
}

/// The evaluator's input wires in ascending order (both parties derive the same order).
fn ev_sorted(ev_wires: &HashSet<usize>) -> Vec<usize> {
    let mut v: Vec<usize> = ev_wires.iter().copied().collect();
    v.sort_unstable();
    v
}

/// **Garbler role.** Garble `circuit`, send the tables + decoding + the garbler's input
/// labels (for wires *not* in `ev_wires`) + the OT setups, then serve the OT for the
/// evaluator's input wires — a fixed 3 flights. `inputs` supplies the bit for every input
/// wire, but **only the garbler's own wires are read** (evaluator wires are ignored). The
/// garbler learns no output; its output share is whatever it fed on its own wires (e.g. the
/// mask, in the gadget convention).
pub fn garbler_run(
    ch: &mut dyn Channel,
    circuit: &Circuit,
    ev_wires: &HashSet<usize>,
    inputs: &[bool],
) -> Result<()> {
    if inputs.len() != circuit.input_bits {
        return Err(Error::Crypto("garble-net: wrong input width".into()));
    }
    let g = Garbler::garble(circuit)?;
    let decoding = g.decoding(circuit);
    let evs = ev_sorted(ev_wires);

    // Flight 1 = tables ‖ decoding ‖ garbler-labels ‖ OT setups. The bytes on the wire are
    // unchanged (send is `write_all`, no framing), but the tables are **streamed** in fixed
    // chunks rather than materialised into one buffer — so the garbler never holds a second
    // full copy of the (message-sized) tables. See [`garbled`](super::garble::Garbler) is
    // no longer cloned.
    let mut buf = Vec::with_capacity(TABLES_PER_CHUNK * 32);
    for chunk in g.tables().chunks(TABLES_PER_CHUNK) {
        buf.clear();
        for (tg, te) in chunk {
            buf.extend_from_slice(tg);
            buf.extend_from_slice(te);
        }
        ch.send(&buf)?;
    }
    // Tail (decoding ‖ garbler-labels ‖ OT setups), one send — built in the same order.
    let mut tail = Vec::new();
    let mut dec = vec![0u8; decoding.len().div_ceil(8)];
    for (i, &b) in decoding.iter().enumerate() {
        if b {
            dec[i / 8] |= 1 << (i % 8);
        }
    }
    tail.extend_from_slice(&dec);
    for (w, &bit) in inputs.iter().enumerate() {
        if !ev_wires.contains(&w) {
            tail.extend_from_slice(&g.input_label(w, bit));
        }
    }
    ch.send(&tail)?; // [flight 1: tables ‖ decoding ‖ garbler-labels]

    // Transfer the evaluator's input labels via ONE **KOS OT-extension** (a constant ~128
    // base OTs + cheap symmetric extension for all wires) instead of a Chou–Orlandi base OT
    // per wire — the dominant cost once garbling is fast. `ot_pair(w) = (W₀, W₀⊕Δ)` are the
    // wire's two labels; the evaluator learns only the one for its bit.
    let messages: Vec<(Label, Label)> = evs.iter().map(|&w| g.ot_pair(w)).collect();
    // `cot_sender` reuses the session's persistent base OTs when `ch` is an
    // `AmortizingChannel` (paying the 128 base OTs once for the whole handshake — shared with
    // ectf's MtAs), else runs a one-shot COT.
    kos::cot_sender(ch, &messages)?;
    Ok(())
}

/// **Evaluator role.** Receive the garbled circuit, fetch its own input labels by OT, then
/// evaluate **locally** and decode — a fixed 3 flights. `inputs` supplies the bit for every
/// input wire, but **only the evaluator's own wires are read**. Returns the decoded output
/// bits (the evaluator's share, in the gadget convention).
pub fn evaluator_run(
    ch: &mut dyn Channel,
    circuit: &Circuit,
    ev_wires: &HashSet<usize>,
    inputs: &[bool],
) -> Result<Vec<bool>> {
    if inputs.len() != circuit.input_bits {
        return Err(Error::Crypto("garble-net: wrong input width".into()));
    }
    let evs = ev_sorted(ev_wires);
    let n_and = circuit.and_gates();
    let n_out = circuit.outputs.len();
    let n_g = circuit.input_bits - evs.len();

    // Flight 1 (recv): sizes are all derivable from the (public) circuit + ev_wires. Tables
    // arrive streamed in ≤32 KiB chunks straight into the pre-sized `Vec<AndTable>` (no
    // whole-flight buffer), then a single tail recv for decoding ‖ labels ‖ OT points.
    let dec_bytes = n_out.div_ceil(8);
    let lbl = n_g * 16;

    let mut tables: Vec<AndTable> = Vec::with_capacity(n_and);
    let mut remaining = n_and;
    while remaining > 0 {
        let take = remaining.min(TABLES_PER_CHUNK);
        let chunk = ch.recv_exact(take * 32)?;
        for i in 0..take {
            let b = i * 32;
            tables.push((label16(&chunk[b..b + 16]), label16(&chunk[b + 16..b + 32])));
        }
        remaining -= take;
    }

    let tail = ch.recv_exact(dec_bytes + lbl)?;
    let mut off = 0;

    let decoding: Vec<bool> = (0..n_out)
        .map(|i| (tail[off + i / 8] >> (i % 8)) & 1 == 1)
        .collect();
    off += dec_bytes;

    let mut labels = vec![[0u8; 16]; circuit.input_bits];
    let mut gi = 0;
    for (w, label) in labels.iter_mut().enumerate() {
        if !ev_wires.contains(&w) {
            *label = label16(&tail[off + gi * 16..off + gi * 16 + 16]);
            gi += 1;
        }
    }

    // Fetch the evaluator's own input labels via KOS OT-extension (constant base OTs +
    // symmetric extension), replacing a base OT per wire.
    let evchoices: Vec<bool> = evs.iter().map(|&w| inputs[w]).collect();
    let ev_labels = kos::cot_receiver(ch, &evchoices)?;
    for (&w, label) in evs.iter().zip(ev_labels) {
        labels[w] = label;
    }

    // Local, non-interactive evaluation + decode.
    Ok(decode(&evaluate(circuit, &tables, &labels), &decoding))
}

#[cfg(test)]
mod tests {
    use super::super::circuit::Builder;
    use super::super::live::channel::TcpChannel;
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /// Run garbler_run (party G, its own thread) + evaluator_run (party E, this thread)
    /// over a loopback TCP pair; return the evaluator's decoded output.
    fn run_net(circuit: &Circuit, ev_wires: HashSet<usize>, inputs: Vec<bool>) -> Vec<bool> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (c_g, ev_g, in_g) = (circuit.clone(), ev_wires.clone(), inputs.clone());
        let g = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            garbler_run(&mut ch, &c_g, &ev_g, &in_g).unwrap();
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let out = evaluator_run(&mut ch, circuit, &ev_wires, &inputs).unwrap();
        g.join().unwrap();
        out
    }

    #[test]
    fn networked_garbling_matches_plaintext() {
        // A small circuit with split input ownership, evaluated over TCP in a fixed 3
        // flights; the decoded output must equal the plaintext circuit.
        let mut b = Builder::new(4);
        let a01 = b.and(0, 1);
        let o0 = b.xor(a01, 2);
        let o1 = b.and(0, 3);
        let circuit = b.build(4, vec![o0, o1]);
        let ev: HashSet<usize> = [1usize, 3].into_iter().collect(); // evaluator owns i1, i3

        for bits in [
            [false, false, false, false],
            [true, true, false, true],
            [true, false, true, true],
            [true, true, true, false],
        ] {
            let out = run_net(&circuit, ev.clone(), bits.to_vec());
            assert_eq!(out, circuit.eval(&bits), "networked garbling for {bits:?}");
        }
    }

    #[test]
    fn networked_garbling_evaluates_real_tls_circuit_in_constant_rounds() {
        // The actual SHA-256 key-schedule compression (67k ANDs) garbled + evaluated over
        // TCP in a FIXED 3 flights — the whole point vs. the per-AND interactive online.
        use super::super::sha256::sha256_compress_circuit;
        let circuit = sha256_compress_circuit();
        // Split the inputs: evaluator owns the second half of the wires.
        let ev: HashSet<usize> = (circuit.input_bits / 2..circuit.input_bits).collect();
        let bits: Vec<bool> = (0..circuit.input_bits)
            .map(|i| i.wrapping_mul(2_654_435_761) & 1 == 1)
            .collect();
        let t = std::time::Instant::now();
        let out = run_net(&circuit, ev, bits.clone());
        eprintln!(
            "networked garbled SHA-256 ({} ANDs) over TCP: {:?}",
            circuit.and_gates(),
            t.elapsed()
        );
        assert_eq!(
            out,
            circuit.eval(&bits),
            "networked garbled SHA-256 == plaintext"
        );
    }
}
