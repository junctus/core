//! ZK proof-of-mixing (M13) — scaffold + partial accountability check.
//!
//! **Goal (deferred):** a mix node proves its outputs are a permutation of its
//! (decrypted) inputs *without revealing the permutation* — a zero-knowledge
//! verifiable shuffle (e.g. Bayer–Groth, typically over Bulletproofs/arkworks).
//! That is a large construction and is not implemented here.
//!
//! **Implemented (weaker):** a non-ZK **conservation check** — given the input
//! and output tags, confirm they are the same multiset, i.e. the mix neither
//! dropped nor injected packets. It does *not* hide the permutation from the
//! verifier, so it is for audit/simulation rather than live privacy — a stepping
//! stone toward the full ZK proof.

/// True iff `outputs` is a permutation of `inputs` (no packet dropped or injected).
pub fn conserves(inputs: &[[u8; 32]], outputs: &[[u8; 32]]) -> bool {
    if inputs.len() != outputs.len() {
        return false;
    }
    let mut a = inputs.to_vec();
    let mut b = outputs.to_vec();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_permutations_rejects_drops_and_injects() {
        let inputs = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let permuted = [[3u8; 32], [1u8; 32], [2u8; 32]];
        assert!(conserves(&inputs, &permuted));

        let dropped = [[1u8; 32], [2u8; 32]];
        assert!(!conserves(&inputs, &dropped));

        let injected = [[1u8; 32], [2u8; 32], [3u8; 32], [9u8; 32]];
        assert!(!conserves(&inputs, &injected));
    }
}
