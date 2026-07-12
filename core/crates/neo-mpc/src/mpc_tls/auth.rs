//! Information-theoretic MACs on bits (IT-MACs / "authenticated bits") — the
//! **foundational primitive** of WRK17 authenticated garbling, the step that would
//! remove dual-execution's ≤1-bit leak and give the 2PC session **malicious**
//! security.
//!
//! An authenticated bit lets one party (the *holder*) commit to a bit `x` such that
//! the other party (the *verifier*) can later check the revealed value but the
//! holder **cannot flip it** without being caught. Concretely, the verifier holds a
//! secret global key `Δ` (fixed across all bits) and, per bit, a local key `K`; the
//! holder holds `x` and a MAC `M` with the relation
//!
//! ```text
//!     M = K ⊕ (x · Δ)          (M = K if x = 0,  M = K ⊕ Δ if x = 1)
//! ```
//!
//! To reveal a *different* bit `x' ≠ x` with a valid MAC the holder would need
//! `M' = K ⊕ (x'·Δ) = M ⊕ Δ`, i.e. it would have to guess `Δ` — a `2^-κ` chance.
//! Authenticated bits are **XOR-homomorphic for free** (`x₁⊕x₂` has MAC `M₁⊕M₂` and
//! key `K₁⊕K₂`), which is what makes the free-XOR garbling scheme authenticable.
//!
//! ## Honest boundary — this is the primitive, **not** the protocol
//!
//! This module implements and tests the IT-MAC *algebra* (authenticate, verify,
//! XOR-homomorphism, forgery-resistance). It is the foundation WRK17 builds on, but
//! it is **not** malicious-secure 2PC: the full protocol — generating authenticated
//! bits from correlated OT, authenticated AND triples (`aAND`), the distributed
//! authenticated garbling, and the online evaluation — is the bulk of WRK17 and is
//! **not** implemented. The session path is still semi-honest with dual-execution's
//! ≤1-bit leak; this module does not change that. It is a first, verified brick.

use neo_core::{Error, Result};

/// MAC / global-key length in bytes (`κ = 128` bits).
pub const KAPPA: usize = 16;

fn xor(a: [u8; KAPPA], b: [u8; KAPPA]) -> [u8; KAPPA] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

fn ct_eq(a: &[u8; KAPPA], b: &[u8; KAPPA]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The verifier's secret global MAC key `Δ`, fixed across all authenticated bits it
/// holds keys for. Learning `Δ` would let a holder forge, so it never leaves the
/// verifier.
pub struct GlobalKey([u8; KAPPA]);

/// The holder's share of an authenticated bit: the bit `x` and its MAC `M`.
#[derive(Clone, Copy, Debug)]
pub struct AuthBit {
    x: bool,
    mac: [u8; KAPPA],
}

/// The verifier's local key `K` for one authenticated bit, with `M = K ⊕ (x·Δ)`.
#[derive(Clone, Copy, Debug)]
pub struct BitKey([u8; KAPPA]);

impl GlobalKey {
    /// A fresh random global key.
    pub fn random() -> Result<Self> {
        let mut d = [0u8; KAPPA];
        getrandom::getrandom(&mut d).map_err(|e| Error::Rng(e.to_string()))?;
        Ok(GlobalKey(d))
    }

    /// Authenticate a bit `x` the holder owns: draw a random verifier key `K` and
    /// set the MAC `M = K ⊕ (x·Δ)`. Returns the holder's [`AuthBit`] and the
    /// verifier's [`BitKey`]. (In the real protocol `K`/`M` come from correlated OT;
    /// this constructs the same relation for the algebra + tests.)
    pub fn authenticate(&self, x: bool) -> Result<(AuthBit, BitKey)> {
        let mut k = [0u8; KAPPA];
        getrandom::getrandom(&mut k).map_err(|e| Error::Rng(e.to_string()))?;
        let mac = if x { xor(k, self.0) } else { k };
        Ok((AuthBit { x, mac }, BitKey(k)))
    }

    /// Verify the holder's revealed `(x, M)` against the verifier's key `K`:
    /// `M == K ⊕ (x·Δ)`.
    pub fn verify(&self, bit: &AuthBit, key: &BitKey) -> bool {
        let expect = if bit.x { xor(key.0, self.0) } else { key.0 };
        ct_eq(&bit.mac, &expect)
    }
}

impl AuthBit {
    /// The bit value the holder committed to.
    pub fn value(&self) -> bool {
        self.x
    }

    /// XOR two authenticated bits — **local, no interaction**: `x₁⊕x₂` with MAC
    /// `M₁⊕M₂`. The verifier XORs the matching [`BitKey`]s.
    pub fn xor(&self, other: &AuthBit) -> AuthBit {
        AuthBit {
            x: self.x ^ other.x,
            mac: xor(self.mac, other.mac),
        }
    }
}

impl BitKey {
    /// XOR two bit keys, matching [`AuthBit::xor`] on the holder side.
    pub fn xor(&self, other: &BitKey) -> BitKey {
        BitKey(xor(self.0, other.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_bit_verifies_for_both_values() {
        let delta = GlobalKey::random().unwrap();
        for x in [false, true] {
            let (bit, key) = delta.authenticate(x).unwrap();
            assert_eq!(bit.value(), x);
            assert!(delta.verify(&bit, &key), "an honest ({x}) authenticated bit verifies");
        }
    }

    #[test]
    fn a_flipped_bit_cannot_keep_a_valid_mac() {
        // The whole point: the holder cannot reveal the opposite bit with the same
        // MAC — verify recomputes K ⊕ (x'·Δ) = M ⊕ Δ ≠ M.
        let delta = GlobalKey::random().unwrap();
        let (bit, key) = delta.authenticate(true).unwrap();
        let forged = AuthBit {
            x: false, // flip the bit …
            mac: bit.mac, // … keep the MAC
        };
        assert!(!delta.verify(&forged, &key), "flipping the bit must fail verification");
    }

    #[test]
    fn forging_a_mac_requires_guessing_delta() {
        // Without Δ, a holder trying to flip the bit must produce M' = M ⊕ Δ. A
        // random guess at that offset fails with overwhelming probability; here we
        // confirm any offset other than the true Δ is rejected.
        let delta = GlobalKey::random().unwrap();
        let (bit, key) = delta.authenticate(false).unwrap();
        for byte in 0..KAPPA {
            for bitpos in 0..8u8 {
                let mut guess = [0u8; KAPPA];
                guess[byte] = 1 << bitpos; // a wrong, nonzero offset (≠ Δ w.h.p.)
                let forged = AuthBit {
                    x: true,
                    mac: xor(bit.mac, guess),
                };
                assert!(!delta.verify(&forged, &key), "a wrong Δ-guess is rejected");
            }
        }
    }

    #[test]
    fn xor_is_homomorphic_and_stays_authenticated() {
        // Authenticated bits XOR locally: the combined bit + MAC still verify under
        // the combined key. This is what lets free-XOR garbling be authenticated.
        let delta = GlobalKey::random().unwrap();
        for (x1, x2) in [(false, false), (false, true), (true, false), (true, true)] {
            let (b1, k1) = delta.authenticate(x1).unwrap();
            let (b2, k2) = delta.authenticate(x2).unwrap();
            let bx = b1.xor(&b2);
            let kx = k1.xor(&k2);
            assert_eq!(bx.value(), x1 ^ x2);
            assert!(delta.verify(&bx, &kx), "XORed authenticated bit still verifies");
        }
    }
}
