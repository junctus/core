//! **Dual-execution** — a step from semi-honest toward malicious security. A
//! semi-honest garbler can silently corrupt the circuit and make the evaluator
//! accept a wrong output. Dual-execution runs the garbling **both ways** (each
//! party garbles once and evaluates once) and then runs an **equality check** on
//! the two executions' output labels: if either party cheated in garbling, the
//! check fails and the protocol aborts.
//!
//! Guarantee (Mohassel–Franklin / Huang–Katz–Evans): a cheating garbler is caught
//! except with the standard **≤ 1-bit leakage** of the equality test. This is a
//! real, well-known malicious-security amplification — not the whole of it: full
//! malicious security (authenticated garbling, WRK17) additionally removes even
//! that 1-bit selective-failure channel and is the remaining step.
//!
//! Modelled in-process; the equality test here compares hashes of the parties'
//! check values, revealing only the equal/not-equal bit.

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::Circuit;
use super::garble::{self, Garbler, Label};
use super::ot;

/// One execution's result: the decoded output bits, the evaluated output labels
/// (the evaluator's view), and the garbler's `(zero, one)` output label pairs.
pub struct Execution {
    /// Decoded output bits.
    pub bits: Vec<bool>,
    /// Output labels the evaluator obtained.
    pub eval_labels: Vec<Label>,
    /// The garbler's output label pairs.
    pub garbler_pairs: Vec<(Label, Label)>,
}

/// Run `circuit` once: the wires in `garbler_wires` are the garbler's inputs; the
/// rest are the evaluator's (fetched by real OT).
pub fn execute(
    circuit: &Circuit,
    garbler_wires: &HashSet<usize>,
    inputs: &[bool],
) -> Result<Execution> {
    let garbler = Garbler::garble(circuit)?;
    let gc = garbler.garbled(circuit);

    let mut labels = vec![[0u8; 16]; circuit.input_bits];
    for (wire, label) in labels.iter_mut().enumerate() {
        if garbler_wires.contains(&wire) {
            *label = garbler.input_label(wire, inputs[wire]);
        } else {
            let (m0, m1) = garbler.ot_pair(wire);
            let setup = ot::sender_setup()?;
            let rc = ot::receiver_choose(&setup.s, inputs[wire])?;
            let (e0, e1) = ot::sender_send(&setup, &rc.r, &m0, &m1);
            *label = ot::receiver_finish(&rc, &setup.s, &e0, &e1);
        }
    }
    let eval_labels = garble::evaluate(circuit, &gc.tables, &labels);
    Ok(Execution {
        bits: garble::decode(&eval_labels, &gc.decoding),
        eval_labels,
        garbler_pairs: garbler.output_labels(circuit),
    })
}

/// Full dual-execution of `circuit`, with `a_wires` party A's input wires (the
/// rest are B's). Returns the agreed output, or an error if the equality check
/// detects a cheating garbler / the two executions disagree.
pub fn dual_execute(
    circuit: &Circuit,
    a_wires: &HashSet<usize>,
    inputs: &[bool],
) -> Result<Vec<bool>> {
    let b_wires: HashSet<usize> = (0..circuit.input_bits)
        .filter(|w| !a_wires.contains(w))
        .collect();

    // Execution 1: A garbles, B evaluates. Execution 2: B garbles, A evaluates.
    let ex1 = execute(circuit, a_wires, inputs)?;
    let ex2 = execute(circuit, &b_wires, inputs)?;

    if !check_pass(&ex1, &ex2) {
        return Err(Error::Crypto(
            "dual-execution equality check failed — a garbler cheated".into(),
        ));
    }
    Ok(ex1.bits)
}

/// The equality check. Party A (garbled ex1, evaluated ex2) forms, per output `i`,
/// the pair `(A's ex1 label for A's evaluated bit, ex2 eval label)`. Party B
/// (garbled ex2, evaluated ex1) forms `(ex1 eval label, B's ex2 label for B's
/// evaluated bit)`. Honest, matching executions make these identical, so their
/// hashes match; any garbling fault makes them differ.
pub fn check_pass(ex1: &Execution, ex2: &Execution) -> bool {
    if ex1.bits.len() != ex2.bits.len() || ex1.bits != ex2.bits {
        return false; // outputs disagree ⇒ a garbler cheated
    }
    let va = hash_pairs(
        ex1.bits
            .iter()
            .enumerate()
            .map(|(i, &b)| (label_for(&ex1.garbler_pairs[i], b), ex2.eval_labels[i])),
    );
    let vb = hash_pairs(
        ex2.bits
            .iter()
            .enumerate()
            .map(|(i, &b)| (ex1.eval_labels[i], label_for(&ex2.garbler_pairs[i], b))),
    );
    va == vb
}

fn label_for(pair: &(Label, Label), bit: bool) -> Label {
    if bit {
        pair.1
    } else {
        pair.0
    }
}

fn hash_pairs(pairs: impl Iterator<Item = (Label, Label)>) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("neo-dualex-check-v1");
    for (a, b) in pairs {
        h.update(&a);
        h.update(&b);
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::super::circuit::Builder;
    use super::*;

    fn and_chain() -> Circuit {
        // out0 = a0 & b0, out1 = a1 ^ b1 — two inputs each party.
        let mut b = Builder::new(4);
        let o0 = b.and(0, 2);
        let o1 = b.xor(1, 3);
        b.build(4, vec![o0, o1])
    }

    #[test]
    fn dual_execution_agrees_on_the_honest_output() {
        let circuit = and_chain();
        let a_wires: HashSet<usize> = [0, 1].into_iter().collect(); // A owns wires 0,1
        for inputs in [
            vec![true, false, true, true],
            vec![false, true, true, false],
            vec![true, true, false, true],
        ] {
            let got = dual_execute(&circuit, &a_wires, &inputs).unwrap();
            assert_eq!(got, circuit.eval(&inputs), "dual-exec matches plaintext");
        }
    }

    #[test]
    fn a_cheating_garbler_is_detected() {
        let circuit = and_chain();
        let a_wires: HashSet<usize> = [0, 1].into_iter().collect();
        let inputs = vec![true, false, true, true];

        // Honest ex1, but a tampered ex2 whose garbler flipped an output label so
        // the evaluated label no longer matches its own pair — a cheating garbler.
        let ex1 = execute(&circuit, &a_wires, &inputs).unwrap();
        let mut ex2 = execute(&circuit, &[2, 3].into_iter().collect(), &inputs).unwrap();
        ex2.eval_labels[0][0] ^= 0xff; // corrupt the label B handed A

        assert!(
            !check_pass(&ex1, &ex2),
            "the equality check must catch a garbling fault"
        );
    }
}
