//! Garbled circuits: **free-XOR** + **point-and-permute** + the **ZRE15 half-gate**
//! AND. This is general semi-honest 2PC of any boolean [`Circuit`]: the garbler
//! encrypts the circuit and its own input labels; the evaluator fetches labels for
//! its own inputs via [`ot`](super::ot) and evaluates to output bits, learning
//! nothing else.
//!
//! Free-XOR: a global secret offset `Δ` (with `lsb(Δ)=1`) ties each wire's two
//! labels as `W₁ = W₀ ⊕ Δ`, so XOR and NOT gates need no ciphertext. Only AND
//! gates cost two ciphertexts (`TG`, `TE`). The hash is BLAKE3 keyed by a
//! per-gate tweak (a correlation-robust hash in the random-oracle model).

use std::collections::HashSet;

use neo_core::{Error, Result};

use super::circuit::{Circuit, Gate};
use super::ot;

/// A wire label (128-bit).
pub type Label = [u8; 16];

/// Two garbled ciphertexts for one AND gate (generator + evaluator half-gates).
pub type AndTable = (Label, Label);

fn color(l: &Label) -> bool {
    l[0] & 1 == 1
}

fn xor(a: &Label, b: &Label) -> Label {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// `base ⊕ x` if `cond`, else `base` (branch-free in intent; the value is public
/// point-and-permute colour, so a data-dependent branch here leaks nothing).
fn cond_xor(base: &Label, cond: bool, x: &Label) -> Label {
    if cond {
        xor(base, x)
    } else {
        *base
    }
}

/// Correlation-robust hash `H(label, tweak)` → 128 bits.
fn h(label: &Label, tweak: u64) -> Label {
    let mut hh = blake3::Hasher::new_derive_key("neo-mpc-garble-v1");
    hh.update(&tweak.to_le_bytes());
    hh.update(label);
    let mut o = [0u8; 16];
    o.copy_from_slice(&hh.finalize().as_bytes()[..16]);
    o
}

fn rand_label() -> Result<Label> {
    let mut l = [0u8; 16];
    getrandom::getrandom(&mut l).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(l)
}

/// The garbler: the global offset, every wire's zero-label, and the AND tables.
pub struct Garbler {
    delta: Label,
    zero: Vec<Label>,
    tables: Vec<AndTable>,
}

/// A garbled circuit as sent to the evaluator: the AND tables and the output
/// decoding (colour of each output zero-label). Input labels travel separately
/// (garbler's directly, evaluator's via OT).
#[derive(Clone)]
pub struct GarbledCircuit {
    /// Per-AND-gate ciphertext pairs, in gate order.
    pub tables: Vec<AndTable>,
    /// Colour bit of each output wire's zero-label, to decode output labels.
    pub decoding: Vec<bool>,
}

impl Garbler {
    /// Garble `circuit`: pick `Δ`, random input zero-labels, and propagate,
    /// emitting a half-gate table per AND.
    pub fn garble(circuit: &Circuit) -> Result<Self> {
        let mut delta = rand_label()?;
        delta[0] |= 1; // lsb(Δ) = 1 for point-and-permute

        let mut zero = vec![[0u8; 16]; circuit.num_wires];
        for z in zero.iter_mut().take(circuit.input_bits) {
            *z = rand_label()?;
        }

        let mut tables = Vec::with_capacity(circuit.and_gates());
        let mut gid = 0u64;
        for gate in &circuit.gates {
            match *gate {
                Gate::Xor(a, b, o) => zero[o] = xor(&zero[a], &zero[b]),
                Gate::Inv(a, o) => zero[o] = xor(&zero[a], &delta), // fold flip into the zero-label
                Gate::And(a, b, o) => {
                    let (wc0, table) = garble_and(&zero[a], &zero[b], &delta, gid);
                    zero[o] = wc0;
                    tables.push(table);
                    gid += 1;
                }
            }
        }
        Ok(Self {
            delta,
            zero,
            tables,
        })
    }

    /// The label carrying `bit` on an input `wire` the garbler drives directly.
    pub fn input_label(&self, wire: usize, bit: bool) -> Label {
        cond_xor(&self.zero[wire], bit, &self.delta)
    }

    /// The `(zero, one)` label pair for an evaluator-owned input `wire`, to be
    /// transferred by OT (the evaluator picks by its bit, learning only that one).
    pub fn ot_pair(&self, wire: usize) -> (Label, Label) {
        (self.zero[wire], xor(&self.zero[wire], &self.delta))
    }

    /// The `(zero, one)` label pair for each output wire — the garbler's own view
    /// of the outputs, used by dual-execution's equality check.
    pub fn output_labels(&self, circuit: &Circuit) -> Vec<(Label, Label)> {
        circuit
            .outputs
            .iter()
            .map(|&o| (self.zero[o], xor(&self.zero[o], &self.delta)))
            .collect()
    }

    /// The garbled circuit to hand the evaluator.
    pub fn garbled(&self, circuit: &Circuit) -> GarbledCircuit {
        GarbledCircuit {
            tables: self.tables.clone(),
            decoding: circuit
                .outputs
                .iter()
                .map(|&o| color(&self.zero[o]))
                .collect(),
        }
    }
}

fn garble_and(wa0: &Label, wb0: &Label, delta: &Label, gid: u64) -> (Label, AndTable) {
    let pa = color(wa0);
    let pb = color(wb0);
    let wa1 = xor(wa0, delta);
    let wb1 = xor(wb0, delta);
    let jg = 2 * gid;
    let je = 2 * gid + 1;

    // Generator half-gate.
    let tg = xor(
        &xor(&h(wa0, jg), &h(&wa1, jg)),
        &if pb { *delta } else { [0u8; 16] },
    );
    let wg0 = cond_xor(&h(wa0, jg), pa, &tg);
    // Evaluator half-gate.
    let te = xor(&xor(&h(wb0, je), &h(&wb1, je)), wa0);
    let we0 = cond_xor(&h(wb0, je), pb, &xor(&te, wa0));

    (xor(&wg0, &we0), (tg, te))
}

/// Evaluate a garbled `circuit` given its `tables` and the input labels (one per
/// input wire). Returns the output **labels**; decode with [`decode`].
pub fn evaluate(circuit: &Circuit, tables: &[AndTable], input_labels: &[Label]) -> Vec<Label> {
    let mut w = vec![[0u8; 16]; circuit.num_wires];
    w[..circuit.input_bits].copy_from_slice(input_labels);
    let mut gid = 0usize;
    for gate in &circuit.gates {
        match *gate {
            Gate::Xor(a, b, o) => w[o] = xor(&w[a], &w[b]),
            Gate::Inv(a, o) => w[o] = w[a], // flip is absorbed by the decoding colour
            Gate::And(a, b, o) => {
                let (tg, te) = tables[gid];
                w[o] = eval_and(&w[a], &w[b], &tg, &te, gid as u64);
                gid += 1;
            }
        }
    }
    circuit.outputs.iter().map(|&o| w[o]).collect()
}

fn eval_and(wa: &Label, wb: &Label, tg: &Label, te: &Label, gid: u64) -> Label {
    let sa = color(wa);
    let sb = color(wb);
    let jg = 2 * gid;
    let je = 2 * gid + 1;
    let wg = cond_xor(&h(wa, jg), sa, tg);
    let we = cond_xor(&h(wb, je), sb, &xor(te, wa));
    xor(&wg, &we)
}

/// Decode output labels to bits using the garbler's output decoding colours.
pub fn decode(output_labels: &[Label], decoding: &[bool]) -> Vec<bool> {
    output_labels
        .iter()
        .zip(decoding)
        .map(|(l, d)| color(l) ^ d)
        .collect()
}

/// Run one semi-honest 2PC of `circuit`: the wires in `evaluator_wires` are the
/// evaluator's inputs (fetched by real [`ot`](super::ot)); all other input wires
/// are the garbler's (driven directly). `inputs` gives the bit for every input
/// wire. Returns the decoded output bits. This is the executor the higher-level
/// gadgets (keystream, key schedule, MAC) all run on.
pub fn eval_2pc(
    circuit: &Circuit,
    evaluator_wires: &HashSet<usize>,
    inputs: &[bool],
) -> Result<Vec<bool>> {
    let garbler = Garbler::garble(circuit)?;
    let gc = garbler.garbled(circuit);

    let mut labels = vec![[0u8; 16]; circuit.input_bits];
    for (wire, label) in labels.iter_mut().enumerate() {
        if evaluator_wires.contains(&wire) {
            let (m0, m1) = garbler.ot_pair(wire);
            let setup = ot::sender_setup()?;
            let rc = ot::receiver_choose(&setup.s, inputs[wire])?;
            let (e0, e1) = ot::sender_send(&setup, &rc.r, &m0, &m1);
            *label = ot::receiver_finish(&rc, &setup.s, &e0, &e1);
        } else {
            *label = garbler.input_label(wire, inputs[wire]);
        }
    }
    Ok(decode(
        &evaluate(circuit, &gc.tables, &labels),
        &gc.decoding,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::circuit::Builder;
    use super::super::ot;
    use super::*;

    /// Run a full semi-honest 2PC: garbler owns input wires in `g_bits` (by index),
    /// evaluator owns the rest (via real OT). Returns decoded outputs.
    fn run_2pc(circuit: &Circuit, g_wires: &[usize], all_bits: &[bool]) -> Vec<bool> {
        let garbler = Garbler::garble(circuit).unwrap();
        let gc = garbler.garbled(circuit);

        let mut labels = vec![[0u8; 16]; circuit.input_bits];
        for wire in 0..circuit.input_bits {
            if g_wires.contains(&wire) {
                labels[wire] = garbler.input_label(wire, all_bits[wire]);
            } else {
                // Evaluator fetches its label by OT, learning only its bit's label.
                let (m0, m1) = garbler.ot_pair(wire);
                let setup = ot::sender_setup().unwrap();
                let rc = ot::receiver_choose(&setup.s, all_bits[wire]).unwrap();
                let (e0, e1) = ot::sender_send(&setup, &rc.r, &m0, &m1);
                labels[wire] = ot::receiver_finish(&rc, &setup.s, &e0, &e1);
            }
        }
        decode(&evaluate(circuit, &gc.tables, &labels), &gc.decoding)
    }

    fn gate_circuit(kind: u8) -> Circuit {
        let mut b = Builder::new(2);
        let o = match kind {
            0 => b.and(0, 1),
            1 => b.xor(0, 1),
            _ => b.inv(0),
        };
        b.build(2, vec![o])
    }

    #[test]
    fn every_gate_garbles_correctly_over_all_inputs() {
        for (kind, name) in [(0u8, "and"), (1, "xor"), (2, "inv")] {
            let circuit = gate_circuit(kind);
            for a in [false, true] {
                for bbit in [false, true] {
                    let expect = match kind {
                        0 => a & bbit,
                        1 => a ^ bbit,
                        _ => !a,
                    };
                    // Garbler drives both inputs directly (isolates the gate crypto).
                    let out = run_2pc(&circuit, &[0, 1], &[a, bbit]);
                    assert_eq!(out[0], expect, "{name}({a},{bbit})");
                }
            }
        }
    }

    #[test]
    fn garbled_adder_matches_plaintext_with_split_inputs() {
        // Garbler owns x (wires 0..32), evaluator owns y (wires 32..64, via OT).
        let mut b = Builder::new(64);
        let a: Vec<usize> = (0..32).collect();
        let bw: Vec<usize> = (32..64).collect();
        let sum = b.add_mod(&a, &bw);
        let circuit = b.build(64, sum);
        let g_wires: Vec<usize> = (0..32).collect();

        for (x, y) in [
            (0u32, 0u32),
            (123456, 987654),
            (0xffff_ffff, 7),
            (0x0f0f_0f0f, 0xf0f0_f0f0),
        ] {
            let mut bits = vec![false; 64];
            for i in 0..32 {
                bits[i] = (x >> i) & 1 == 1;
                bits[32 + i] = (y >> i) & 1 == 1;
            }
            let out = run_2pc(&circuit, &g_wires, &bits);
            let got = out
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, &b)| acc | ((b as u32) << i));
            assert_eq!(got, x.wrapping_add(y), "2PC add {x:#x}+{y:#x}");
        }
    }
}
