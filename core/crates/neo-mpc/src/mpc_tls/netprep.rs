//! **Networked authenticated-bit (aBit) preprocessing** — the two parties run the WRK17
//! `F_pre` foundation as a *real two-party protocol over a [`Channel`]*, each holding only
//! its own secrets, instead of the in-process dealer that [`wrk17`](super::wrk17) and
//! [`authgarble`](super::authgarble) model.
//!
//! An authenticated bit is one **correlated OT** (COT): the *key-holder* (verifier) is the
//! OT sender with the pair `(Kᵢ, Kᵢ⊕Δ)` and keeps the key `Kᵢ`; the *bit-holder* (prover)
//! is the OT receiver with choice `bitᵢ` and learns the IT-MAC `Mᵢ = Kᵢ ⊕ bitᵢ·Δ`. The
//! COT runs over the network via the **malicious** [`kos`](super::kos) OT extension
//! ([`kos::cot_sender`]/[`kos::cot_receiver`]) — so a cheating party is caught by the
//! GF(2^128) correlation check on the wire, not just in-process.
//!
//! The result is *distributed*: the prover holds [`ProverBits`] `{(bitᵢ, Mᵢ)}`, the
//! verifier holds [`VerifierBits`] `{Δ, Kᵢ}`, and neither function ever sees the other's
//! share. Opening an aBit (prover reveals `(bit, M)`, verifier checks `M == K ⊕ bit·Δ`)
//! **aborts on a forgery** — the prover cannot open a bit to the wrong value without Δ.
//!
//! # Honest boundary
//!
//! - This is the **foundational aBit layer** run over a genuine two-party channel (tested
//!   over real TCP sockets): the OT extension is [`kos`](super::kos)'s maliciously-secure
//!   one, so the *networked* generation catches a cheating receiver.
//! - Composing this up into the full networked `F_pre` — authenticated bits in **both**
//!   directions → WRK17 `leaky_and` → bucketing → the distributed `AShare` the online
//!   consumes — is the **next layer** (the in-process [`authgarble::bucketed_and_triples`]
//!   remains the reference for that stage).
//! - The KOS **Roy22** caveat ([`kos`](super::kos)) applies, and nothing here is audited.

use neo_core::{Error, Result};

use super::kos;
use super::live::channel::Channel;

fn rand16() -> Result<[u8; 16]> {
    let mut k = [0u8; 16];
    getrandom::getrandom(&mut k).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(k)
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

/// Constant-time 16-byte equality (MAC comparison must not leak via timing).
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// The **verifier**'s view of a batch of authenticated bits: its global key `Δ` and the
/// per-bit keys `Kᵢ`. It can *check* an opened `(bit, MAC)` but never learns the bit until
/// the prover opens it.
pub struct VerifierBits {
    delta: [u8; 16],
    keys: Vec<[u8; 16]>,
}

/// The **prover**'s view: its bits and their IT-MACs `Mᵢ = Kᵢ ⊕ bitᵢ·Δ` under the
/// verifier's (unknown) `Δ`.
pub struct ProverBits {
    bits: Vec<bool>,
    macs: Vec<[u8; 16]>,
}

/// Verifier side of networked aBit generation: authenticate the prover's `n` bits under
/// `delta`, over `ch`. Draws fresh per-bit keys `Kᵢ`, runs the COT **sender** role
/// (`messages[i] = (Kᵢ, Kᵢ⊕Δ)`), and keeps the keys. Aborts if the OT check fails.
pub fn authenticate_verifier(
    ch: &mut dyn Channel,
    delta: &[u8; 16],
    n: usize,
) -> Result<VerifierBits> {
    let mut keys = Vec::with_capacity(n);
    let mut messages = Vec::with_capacity(n);
    for _ in 0..n {
        let k = rand16()?;
        messages.push((k, xor16(&k, delta)));
        keys.push(k);
    }
    kos::cot_sender(ch, &messages)?;
    Ok(VerifierBits {
        delta: *delta,
        keys,
    })
}

/// Prover side of networked aBit generation: obtain IT-MACs on `bits` under the
/// verifier's (unknown) `Δ`, over `ch`. Runs the COT **receiver** role; the returned MACs
/// satisfy `Mᵢ = Kᵢ ⊕ bitᵢ·Δ`.
pub fn authenticate_prover(ch: &mut dyn Channel, bits: &[bool]) -> Result<ProverBits> {
    let macs = kos::cot_receiver(ch, bits)?;
    Ok(ProverBits {
        bits: bits.to_vec(),
        macs,
    })
}

impl ProverBits {
    pub fn len(&self) -> usize {
        self.bits.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }
    /// The `i`-th bit (the prover's private value).
    pub fn bit(&self, i: usize) -> bool {
        self.bits[i]
    }
    /// Open aBit `i`: the value + its MAC, to hand to the verifier.
    pub fn reveal(&self, i: usize) -> (bool, [u8; 16]) {
        (self.bits[i], self.macs[i])
    }
}

impl VerifierBits {
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    /// Check a revealed `(bit, mac)` for aBit `i`: `Mᵢ == Kᵢ ⊕ bitᵢ·Δ`. Returns the bit on
    /// success; **aborts** on a MAC mismatch (a forged opening).
    pub fn check(&self, i: usize, bit: bool, mac: &[u8; 16]) -> Result<bool> {
        let expect = if bit {
            xor16(&self.keys[i], &self.delta)
        } else {
            self.keys[i]
        };
        if !ct_eq(&expect, mac) {
            return Err(Error::Crypto(
                "aBit: IT-MAC check failed on open (forged bit — abort)".into(),
            ));
        }
        Ok(bit)
    }
}

#[cfg(test)]
mod tests {
    use super::super::live::channel::TcpChannel;
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /// Generate `bits.len()` networked aBits over a loopback TCP pair; return both views.
    fn gen_over_tcp(delta: [u8; 16], bits: Vec<bool>) -> (VerifierBits, ProverBits) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let n = bits.len();
        let verifier = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            authenticate_verifier(&mut ch, &delta, n).unwrap()
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let prover = authenticate_prover(&mut ch, &bits).unwrap();
        (verifier.join().unwrap(), prover)
    }

    #[test]
    fn networked_abits_open_and_reject_forgery() {
        // Two parties, each on its own socket, generate authenticated bits via the
        // networked malicious KOS-COT. Every honest open verifies; a bit opened to the
        // wrong value (which needs Δ to forge the MAC) is rejected.
        let delta: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x5a);
        let bits: Vec<bool> = (0..48).map(|i| (i * 5 + 1) % 3 == 0).collect();
        let (vbits, prover) = gen_over_tcp(delta, bits.clone());
        assert_eq!(vbits.len(), prover.len());

        for (i, &want) in bits.iter().enumerate() {
            let (b, mac) = prover.reveal(i);
            assert_eq!(b, want, "prover holds the right bit");
            assert_eq!(
                vbits.check(i, b, &mac).unwrap(),
                want,
                "honest open verifies"
            );
            // Opening the flipped value with the honest MAC must fail (no Δ to forge).
            assert!(
                vbits.check(i, !b, &mac).is_err(),
                "a forged (flipped-bit) open must abort"
            );
        }
    }
}
