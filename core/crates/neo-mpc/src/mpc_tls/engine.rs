//! The **2PC engine seam**: evaluate a boolean circuit under either the semi-honest
//! garbler ([`garble::eval_2pc`](super::garble)) or the malicious authenticated-garbling
//! online ([`authgarble::eval_garbled`](super::authgarble)), selected by [`EngineKind`].
//!
//! Every high-level 2PC gadget (`share_keystream`, the `hkdf_*` schedule steps, the AEAD
//! seal/open) evaluates a masked boolean circuit and reads back XOR-shares of the result.
//! Because the mask is an *input wire* of the circuit, **both engines return the same
//! masked output** — so a gadget can run under either engine just by routing its one
//! `eval` call through [`eval_circuit`]. The malicious engine additionally **aborts on a
//! tampered wire** (authenticated shares), giving the live session a malicious-secure
//! online.
//!
//! # Honest boundary
//!
//! - [`EngineKind::Semihonest`] is the default (dual-execution ≤ 1-bit leak).
//! - [`EngineKind::Malicious`] runs the real WRK17/KRRW18 authenticated online over
//!   **bucketed `F_pre` AND-triples** ([`authgarble::bucketed_and_triples`], the malicious
//!   leaky-AND + bucketing preprocessing). What it still models **in-process** (the
//!   crate's standing boundary) is the *networked* generation of the underlying aBits —
//!   a deployment runs the KOS-OT aBit preprocessing between the two separate parties.
//!   So `Malicious` gives a malicious-secure *online + preprocessing construction* whose
//!   abort mechanism is tested, not the formal end-to-end theorem (that is the audit).

use neo_core::Result;

use super::authgarble::{bucketed_and_triples, eval_garbled, AShare, Deltas};
use super::circuit::Circuit;
use super::garble;

/// Which 2PC engine a live session evaluates its circuits under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineKind {
    /// Free-XOR / half-gate garbling ([`garble::eval_2pc`](super::garble)); ≤ 1-bit leak
    /// with dual-execution. The live path's default.
    Semihonest,
    /// WRK17/KRRW18 authenticated garbling ([`authgarble::eval_garbled`](super::authgarble))
    /// over bucketed `F_pre` triples — aborts on a cheating party.
    Malicious,
}

/// Bucket size for the malicious `F_pre` (KRRW18 leaky-AND → AND-triple). A real
/// deployment picks this from the statistical-security parameter.
const MALICIOUS_BUCKET: usize = 3;

/// Evaluate `circuit` on `inputs` under the chosen 2PC `engine`, returning the circuit
/// output bits. `evaluator_wires` marks the evaluator-owned input wires (used by the
/// semi-honest OT path; the malicious path authenticates every wire and ignores it).
///
/// Both engines return the same result on the same circuit/inputs — the malicious one
/// additionally aborts if a wire's authentication is violated.
pub fn eval_circuit(
    engine: EngineKind,
    circuit: &Circuit,
    evaluator_wires: &std::collections::HashSet<usize>,
    inputs: &[bool],
) -> Result<Vec<bool>> {
    match engine {
        EngineKind::Semihonest => garble::eval_2pc(circuit, evaluator_wires, inputs),
        EngineKind::Malicious => {
            let d = Deltas::random()?;
            let shares: Vec<AShare> = inputs
                .iter()
                .map(|&b| AShare::deal(b, &d))
                .collect::<Result<_>>()?;
            let triples = bucketed_and_triples(circuit.and_gates(), MALICIOUS_BUCKET, &d)?;
            eval_garbled(circuit, &shares, &triples, &d)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::circuit::Builder;
    use super::*;
    use std::collections::HashSet;

    /// A small circuit exercising XOR + AND + a constant: out0 = (i0∧i1)⊕i2, out1 = i0∧i3.
    fn tiny_circuit() -> Circuit {
        let mut b = Builder::new(4);
        let a = b.and(0, 1);
        let o0 = b.xor(a, 2);
        let o1 = b.and(0, 3);
        b.build(4, vec![o0, o1])
    }

    #[test]
    fn both_engines_agree_on_the_same_circuit() {
        // The seam's core guarantee: a circuit dispatched through eval_circuit produces
        // the same output under the semi-honest and the malicious engine (and both match
        // the plaintext oracle). The malicious engine's abort-on-tamper behaviour is
        // covered by `authgarble`'s own tamper tests (and the real SHA-256 circuit test).
        let circuit = tiny_circuit();
        let ew: HashSet<usize> = [1usize, 3].into_iter().collect(); // evaluator owns i1,i3

        for bits in [
            [false, false, false, false],
            [true, true, false, true],
            [true, false, true, true],
            [true, true, true, false],
            [false, true, true, true],
        ] {
            let inputs = bits.to_vec();
            let plain = circuit.eval(&inputs);
            let sh = eval_circuit(EngineKind::Semihonest, &circuit, &ew, &inputs).unwrap();
            let mal = eval_circuit(EngineKind::Malicious, &circuit, &ew, &inputs).unwrap();
            assert_eq!(
                sh, plain,
                "semi-honest engine matches plaintext for {inputs:?}"
            );
            assert_eq!(
                mal, plain,
                "malicious engine matches plaintext for {inputs:?}"
            );
        }
    }

    #[test]
    #[ignore] // perf probe: ~3-4s in release; run with `--ignored --release`
    fn bench_malicious_sha256() {
        use super::super::sha256::sha256_compress_circuit;
        let c = sha256_compress_circuit();
        let ew: HashSet<usize> = HashSet::new();
        let bits: Vec<bool> = (0..c.input_bits).map(|i| i % 3 == 0).collect();
        let t = std::time::Instant::now();
        let out = eval_circuit(EngineKind::Malicious, c, &ew, &bits).unwrap();
        eprintln!(
            "MALICIOUS sha256 ({} ANDs): {:?}",
            c.and_gates(),
            t.elapsed()
        );
        assert_eq!(out, c.eval(&bits));
    }
}
