//! The live-session **2PC engine seam**: evaluate a boolean circuit under either the
//! semi-honest garbler ([`garble::eval_2pc`](super::super::garble)) or the malicious
//! authenticated-garbling online ([`authgarble::eval_garbled`](super::super::authgarble)),
//! selected by [`EngineKind`](super::EngineKind).
//!
//! Today the live handshake/record gadgets call `eval_2pc` directly (semi-honest). This
//! module is the single point where that choice becomes explicit and swappable: both
//! engines compute the *same* circuit output, and the malicious one **aborts on a
//! tampered wire**. It is what a future "malicious-live" mode routes every circuit
//! through.
//!
//! # Honest boundary
//!
//! - [`EngineKind::Semihonest`] is the production live path (dual-execution ≤ 1-bit leak).
//! - [`EngineKind::Malicious`] runs the real WRK17/KRRW18 authenticated online, but its
//!   `F_pre` **AND-triples are dealt from a bucketed-but-honest source here** — the
//!   remaining gap to malicious-live is generating those triples maliciously end to end
//!   (MASCOT aBits + sacrifice; the M38/M45 residual). Wiring `Malicious` into the
//!   *high-level gadgets* (`share_keystream`, `hkdf_*`) additionally requires re-plumbing
//!   them to deal `AShare` inputs, since `eval_garbled` is not drop-in for `eval_2pc`.
//!   This seam proves the circuits run under both engines; it does not yet claim the live
//!   session is malicious-secure.

use neo_core::Result;

use super::super::authgarble::{bucketed_and_triples, eval_garbled, AShare, Deltas};
use super::super::circuit::Circuit;
use super::super::garble;
use super::EngineKind;

/// Bucket size for the malicious `F_pre` (KRRW18 leaky-AND → AND-triple). A real
/// deployment picks this from the statistical-security parameter; the seam uses a small
/// value so the engine test stays fast.
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
    use super::super::super::circuit::Builder;
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
        // the plaintext oracle). The malicious engine's *abort*-on-tamper behaviour is
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
}
