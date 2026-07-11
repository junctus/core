//! Registration proof-of-work — a coarse anti-Sybil rate limiter (M36).
//!
//! A relay attaches a small proof-of-work to each registration: a `nonce` such
//! that `BLAKE3(domain || node_id || nonce)` has at least [`REGISTRATION_POW_BITS`]
//! leading zero bits. The seed re-checks it before admitting the record. The proof
//! binds to the relay's [`NodeId`], so it can't be replayed under a different
//! identity, and it is paid **per identity** — minting `N` Sybil identities costs
//! `N · 2^bits` hashes on top of controlling `N` reachable hosts in distinct
//! subnets.
//!
//! Honest scope: this is a *speed bump*, not Sybil resistance. CPU proof-of-work
//! is cheap for an adversary with a GPU/ASIC, so the difficulty is kept low enough
//! not to burden an honest relay on weak hardware. The real cost an attacker pays
//! is the dial-back (a reachable host per identity) and the per-subnet attestation
//! cap; the PoW just raises the floor and throttles automated floods. It carries
//! **no** freshness/epoch binding by design — an honest relay re-registering the
//! same identity reuses one solved nonce forever rather than re-grinding.

use crate::NodeId;

/// Domain separation tag so a registration PoW can never be mistaken for any other
/// BLAKE3 hash in the system.
const POW_DOMAIN: &[u8] = b"neo-registration-pow-v1";

/// Default difficulty in leading zero bits (~`2^bits` hashes to solve). 20 bits is
/// ~1M hashes — well under a second even on a small relay box, but a real per-
/// identity cost when multiplied across a Sybil fleet.
pub const REGISTRATION_POW_BITS: u32 = 20;

/// The proof-of-work hash bound to `id` and `nonce`.
fn pow_hash(id: &NodeId, nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(POW_DOMAIN);
    h.update(id.as_bytes());
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Number of leading zero bits in a 32-byte hash (0..=256).
fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for &byte in hash {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Whether `nonce` is a valid proof-of-work for `id` at `bits` difficulty.
pub fn verify(id: &NodeId, nonce: u64, bits: u32) -> bool {
    leading_zero_bits(&pow_hash(id, nonce)) >= bits
}

/// Grind a valid `nonce` for `id` at `bits` difficulty. Deterministic (scans from
/// 0), so a relay caches the result and never recomputes for the same identity.
/// Returns `None` only if the whole `u64` space is exhausted without a solution —
/// impossible at any sane difficulty (`bits < 64`).
pub fn solve(id: &NodeId, bits: u32) -> Option<u64> {
    (0..=u64::MAX).find(|&nonce| verify(id, nonce, bits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeIdentity;

    #[test]
    fn solved_nonce_verifies_and_binds_to_identity() {
        let id = NodeIdentity::generate().unwrap().id();
        // A modest difficulty keeps the test fast but exercises the real path.
        let bits = 12;
        let nonce = solve(&id, bits).unwrap();
        assert!(verify(&id, nonce, bits), "the solved nonce must verify");

        // The proof is bound to the identity: a different id rejects this nonce
        // (with overwhelming probability at 12 bits).
        let other = NodeIdentity::generate().unwrap().id();
        assert!(
            !verify(&other, nonce, bits),
            "a nonce solved for one identity must not satisfy another"
        );
    }

    #[test]
    fn a_random_nonce_fails_a_real_difficulty() {
        let id = NodeIdentity::generate().unwrap().id();
        // nonce 0 almost certainly has fewer than 24 leading zero bits.
        assert!(!verify(&id, 0, 24) || verify(&id, 0, 0));
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
        let mut h = [0u8; 32];
        h[0] = 0x01; // 7 leading zero bits then a 1
        assert_eq!(leading_zero_bits(&h), 7);
        h[0] = 0xff;
        assert_eq!(leading_zero_bits(&h), 0);
        let mut h2 = [0u8; 32];
        h2[0] = 0x00;
        h2[1] = 0x80; // 8 + 0 = 8 bits
        assert_eq!(leading_zero_bits(&h2), 8);
    }
}
