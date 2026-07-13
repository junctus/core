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
use std::sync::OnceLock;

use neo_core::{Error, Result};
use rayon::prelude::*;

use super::circuit::{Circuit, Gate};
use super::ot;

/// A topological **leveling** of a circuit for data-parallel garbling/evaluation. Gates at
/// the same depth read only strictly-earlier wires (inputs have smaller indices than any
/// gate output, and each wire is written once), so a whole level is independent and can be
/// processed in parallel. `and_gid[gi]` is the AND-gate ordinal (its garbled-table index and
/// blake3 tweak seed) precomputed in gate order — so the tweak/table order is identical to
/// the sequential version regardless of parallel completion order.
struct Plan {
    levels: Vec<Vec<usize>>,
    and_gid: Vec<u64>,
    n_and: usize,
}

fn plan(circuit: &Circuit) -> Plan {
    let mut wire_level = vec![0u32; circuit.num_wires]; // inputs = level 0
    let mut gate_level = vec![0u32; circuit.gates.len()];
    let mut and_gid = vec![0u64; circuit.gates.len()];
    let mut gid = 0u64;
    let mut maxl = 0u32;
    for (gi, gate) in circuit.gates.iter().enumerate() {
        let (o, lvl) = match *gate {
            Gate::Xor(a, b, o) => (o, 1 + wire_level[a].max(wire_level[b])),
            Gate::Inv(a, o) => (o, 1 + wire_level[a]),
            Gate::And(a, b, o) => {
                and_gid[gi] = gid;
                gid += 1;
                (o, 1 + wire_level[a].max(wire_level[b]))
            }
        };
        debug_assert!(o >= circuit.input_bits, "gate must not write an input wire");
        wire_level[o] = lvl;
        gate_level[gi] = lvl;
        maxl = maxl.max(lvl);
    }
    let mut levels = vec![Vec::new(); maxl as usize + 1];
    for (gi, &l) in gate_level.iter().enumerate() {
        levels[l as usize].push(gi);
    }
    Plan {
        levels,
        and_gid,
        n_and: gid as usize,
    }
}

/// Minimum gates per rayon task — batches tiny levels so per-task overhead can't dominate
/// the many shallow levels of deep-but-narrow circuits (carry chains).
const PAR_MIN_LEN: usize = 256;

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

/// The BLAKE3 hasher pre-keyed with the garble context. `new_derive_key` re-runs the
/// context KDF on every call, so we derive it once and clone the (cheap) keyed state per
/// hash — byte-identical output, but millions of KDF re-derivations saved per handshake.
fn keyed_hasher() -> &'static blake3::Hasher {
    static K: OnceLock<blake3::Hasher> = OnceLock::new();
    K.get_or_init(|| blake3::Hasher::new_derive_key("neo-mpc-garble-v1"))
}

/// Correlation-robust hash `H(label, tweak)` → 128 bits.
fn h(label: &Label, tweak: u64) -> Label {
    let mut hh = keyed_hasher().clone();
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

        // Garble level-by-level: gates within a level read only earlier-level (final) wire
        // labels, so the (blake3-heavy) per-gate work runs in parallel; a trivial sequential
        // scatter then writes each unique output wire and `tables[gid]`. Byte-identical to a
        // sequential garble — the RNG prologue above is untouched, the gate body is pure, and
        // `and_gid` fixes the table/tweak order.
        let p = plan(circuit);
        let mut tables = vec![([0u8; 16], [0u8; 16]); p.n_and];
        let mut scratch: Vec<(usize, Label, Option<(u64, AndTable)>)> = Vec::new();
        for level in &p.levels {
            level
                .par_iter()
                .with_min_len(PAR_MIN_LEN)
                .map(|&gi| match circuit.gates[gi] {
                    Gate::Xor(a, b, o) => (o, xor(&zero[a], &zero[b]), None),
                    Gate::Inv(a, o) => (o, xor(&zero[a], &delta), None),
                    Gate::And(a, b, o) => {
                        let gid = p.and_gid[gi];
                        let (wc0, table) = garble_and(&zero[a], &zero[b], &delta, gid);
                        (o, wc0, Some((gid, table)))
                    }
                })
                .collect_into_vec(&mut scratch); // reuses the allocation across levels
            for (o, label, and) in scratch.drain(..) {
                zero[o] = label;
                if let Some((gid, table)) = and {
                    tables[gid as usize] = table;
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
            decoding: self.decoding(circuit),
        }
    }

    /// Borrow the AND tables in gid order (avoids the [`garbled`](Self::garbled) clone —
    /// the networked garbler streams these directly).
    pub fn tables(&self) -> &[AndTable] {
        &self.tables
    }

    /// The output decoding (colour of each output wire's zero-label).
    pub fn decoding(&self, circuit: &Circuit) -> Vec<bool> {
        circuit.outputs.iter().map(|&o| color(&self.zero[o])).collect()
    }
}

fn garble_and(wa0: &Label, wb0: &Label, delta: &Label, gid: u64) -> (Label, AndTable) {
    let pa = color(wa0);
    let pb = color(wb0);
    let wa1 = xor(wa0, delta);
    let wb1 = xor(wb0, delta);
    let jg = 2 * gid;
    let je = 2 * gid + 1;

    // Hash each input zero-label once (reused by the table + the output label).
    let hwa0 = h(wa0, jg);
    let hwb0 = h(wb0, je);
    // Generator half-gate.
    let tg = xor(
        &xor(&hwa0, &h(&wa1, jg)),
        &if pb { *delta } else { [0u8; 16] },
    );
    let wg0 = cond_xor(&hwa0, pa, &tg);
    // Evaluator half-gate.
    let te = xor(&xor(&hwb0, &h(&wb1, je)), wa0);
    let we0 = cond_xor(&hwb0, pb, &xor(&te, wa0));

    (xor(&wg0, &we0), (tg, te))
}

/// Evaluate a garbled `circuit` given its `tables` and the input labels (one per
/// input wire). Returns the output **labels**; decode with [`decode`].
pub fn evaluate(circuit: &Circuit, tables: &[AndTable], input_labels: &[Label]) -> Vec<Label> {
    let mut w = vec![[0u8; 16]; circuit.num_wires];
    w[..circuit.input_bits].copy_from_slice(input_labels);
    // Level-parallel, mirroring `garble`: each level's gates read only earlier-level wires.
    let p = plan(circuit);
    let mut scratch: Vec<(usize, Label)> = Vec::new();
    for level in &p.levels {
        level
            .par_iter()
            .with_min_len(PAR_MIN_LEN)
            .map(|&gi| match circuit.gates[gi] {
                Gate::Xor(a, b, o) => (o, xor(&w[a], &w[b])),
                Gate::Inv(a, o) => (o, w[a]), // flip absorbed by the decoding colour
                Gate::And(a, b, o) => {
                    let gid = p.and_gid[gi];
                    let (tg, te) = tables[gid as usize];
                    (o, eval_and(&w[a], &w[b], &tg, &te, gid))
                }
            })
            .collect_into_vec(&mut scratch);
        for (o, label) in scratch.drain(..) {
            w[o] = label;
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
