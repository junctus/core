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
//! On top of the aBits, this module composes the **full networked TinyOT `F_pre`** the
//! WRK17 online consumes: distributed authenticated shares [`Share`] (both-direction
//! aBits, [`rand_shares`]) with a symmetric MAC-checked [`open`]; authenticated AND
//! triples [`Triple`] ([`rand_triples`]: the two cross-term bit-OTs `aa·bb`, `ab·ba` over
//! the networked COT, then `c = a∧b` authenticated both ways); the [`sacrifice`] check
//! that catches a corrupted triple; and [`combine`]/[`bucketed_triples`] for leakage
//! removal — all as genuine two-party protocols where neither party sees the other's
//! share.
//!
//! # Honest boundary
//!
//! - Run over a **genuine two-party channel** (tested over real TCP sockets): the OT is
//!   [`kos`](super::kos)'s maliciously-secure extension (so the networked generation
//!   catches a cheating receiver), honest triples satisfy `c = a∧b`, and the sacrifice
//!   aborts on a corrupted triple. This is the **distributed form** of
//!   [`wrk17`](super::wrk17)'s in-process `Share`/`Triple`/bucketing, which remains the
//!   reference.
//! - What remains is feeding these distributed triples into a **networked online**: the
//!   in-process [`wrk17::eval_authenticated`](super::wrk17) (interactive) and
//!   [`authgarble`](super::authgarble) (constant-round) consume *bundled* shares, so a
//!   fully networked evaluation would split those too — that is the next layer.
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

/// The verifier's per-bit keys `Kᵢ` for `n` aBits under `delta` (the raw COT-sender role):
/// draws fresh keys, runs the COT **sender** with `(Kᵢ, Kᵢ⊕Δ)`, and keeps the keys.
fn verifier_keys(ch: &mut dyn Channel, delta: &[u8; 16], n: usize) -> Result<Vec<[u8; 16]>> {
    let mut keys = Vec::with_capacity(n);
    let mut messages = Vec::with_capacity(n);
    for _ in 0..n {
        let k = rand16()?;
        messages.push((k, xor16(&k, delta)));
        keys.push(k);
    }
    kos::cot_sender(ch, &messages)?;
    Ok(keys)
}

/// The prover's IT-MACs `Mᵢ = Kᵢ ⊕ bitᵢ·Δ` on `bits` (the raw COT-receiver role).
fn prover_macs(ch: &mut dyn Channel, bits: &[bool]) -> Result<Vec<[u8; 16]>> {
    kos::cot_receiver(ch, bits)
}

/// Verifier side of networked aBit generation: authenticate the prover's `n` bits under
/// `delta`, over `ch`. Aborts if the OT check fails.
pub fn authenticate_verifier(
    ch: &mut dyn Channel,
    delta: &[u8; 16],
    n: usize,
) -> Result<VerifierBits> {
    Ok(VerifierBits {
        delta: *delta,
        keys: verifier_keys(ch, delta, n)?,
    })
}

/// Prover side of networked aBit generation: obtain IT-MACs on `bits` under the
/// verifier's (unknown) `Δ`, over `ch`. The returned MACs satisfy `Mᵢ = Kᵢ ⊕ bitᵢ·Δ`.
pub fn authenticate_prover(ch: &mut dyn Channel, bits: &[bool]) -> Result<ProverBits> {
    Ok(ProverBits {
        bits: bits.to_vec(),
        macs: prover_macs(ch, bits)?,
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

// ── Distributed authenticated shares ⟨x⟩ + AND-triples over the wire ─────────────
//
// Composing the aBits up into the WRK17/TinyOT `F_pre` the malicious online consumes.
// A shared bit `x = xa ⊕ xb` is authenticated in BOTH directions (aBits both ways). Each
// party holds one [`Share`]: its own bit, the MAC on its own bit under the *peer's* Δ, and
// its key on the *peer's* bit under its *own* Δ. Neither party ever sees the other's Share
// — this is the distributed form of [`wrk17::Share`](super::wrk17::Share).

/// Which of the two parties this state belongs to. The parties run mirror-image code, so
/// the OT roles line up on the wire (one provers-first, the other verifies-first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    A,
    B,
}

/// One party's share of `⟨x⟩`: `x` = this party's bit-share; `mac` = the IT-MAC on `x`
/// under the **peer's** Δ (`mac = peer_key ⊕ x·Δ_peer`); `key` = this party's key on the
/// **peer's** bit under **its own** Δ.
#[derive(Clone, Copy, Debug)]
pub struct Share {
    x: bool,
    mac: [u8; 16],
    key: [u8; 16],
}

impl Share {
    /// A valid share of the public constant `0` (`0 = 0 ⊕ 0·Δ`).
    fn zero() -> Share {
        Share {
            x: false,
            mac: [0u8; 16],
            key: [0u8; 16],
        }
    }

    /// `⟨x⟩ ⊕ ⟨y⟩`, fully local (XOR every component).
    pub fn xor(&self, o: &Share) -> Share {
        Share {
            x: self.x ^ o.x,
            mac: xor16(&self.mac, &o.mac),
            key: xor16(&self.key, &o.key),
        }
    }

    /// `⟨x⟩ · c` for a public bit `c`: identity if `c`, else the zero share (local).
    fn scale(&self, c: bool) -> Share {
        if c {
            *self
        } else {
            Share::zero()
        }
    }

    /// `⟨x⟩ ⊕ c` for a public bit `c` (local, no communication): by convention party **A**
    /// flips its bit-share and party **B** adjusts its key on A's bit by `c·Δ_B`, so the
    /// value flips while `mac = key ⊕ x·Δ` stays consistent.
    fn xor_const(&self, c: bool, party: Party, delta: &[u8; 16]) -> Share {
        let mut s = *self;
        if c {
            match party {
                Party::A => s.x = !s.x,
                Party::B => s.key = xor16(&s.key, delta),
            }
        }
        s
    }
}

/// Fisher–Yates over `n` items using bytes drawn on party A and sent to B, so both parties
/// apply the **same public permutation** (bucketing assignment is public).
fn shared_permutation(ch: &mut dyn Channel, party: Party, n: usize) -> Result<Vec<usize>> {
    let mut perm: Vec<usize> = (0..n).collect();
    match party {
        Party::A => {
            let mut bytes = Vec::with_capacity(n * 8);
            for i in (1..n).rev() {
                let mut b = [0u8; 8];
                getrandom::getrandom(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
                let j = (u64::from_le_bytes(b) % (i as u64 + 1)) as usize;
                perm.swap(i, j);
                bytes.extend_from_slice(&(j as u64).to_le_bytes());
            }
            ch.send(&bytes)?;
        }
        Party::B => {
            if n > 1 {
                let bytes = ch.recv_exact((n - 1) * 8)?;
                let mut k = 0;
                for i in (1..n).rev() {
                    let j = u64::from_le_bytes(bytes[k..k + 8].try_into().expect("8")) as usize;
                    perm.swap(i, j);
                    k += 8;
                }
            }
        }
    }
    Ok(perm)
}

fn rand_bits(n: usize) -> Result<Vec<bool>> {
    let mut bytes = vec![0u8; n.div_ceil(8)];
    getrandom::getrandom(&mut bytes).map_err(|e| Error::Rng(e.to_string()))?;
    Ok((0..n).map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1).collect())
}

fn bit_msg(b: bool) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = b as u8;
    m
}

/// **Open** `⟨x⟩` over `ch`, MAC-checked — symmetric for both parties, the abort gate.
/// Each side sends `(x, mac)` and checks the peer's against its own key + Δ: a party that
/// lies about its bit or MAC (which needs the peer's Δ to forge) is caught. Returns `x`.
pub fn open(ch: &mut dyn Channel, my_delta: &[u8; 16], share: &Share) -> Result<bool> {
    let mut msg = Vec::with_capacity(17);
    msg.push(share.x as u8);
    msg.extend_from_slice(&share.mac);
    ch.send(&msg)?;
    let peer = ch.recv_exact(17)?;
    let px = peer[0] & 1 == 1;
    let pmac: [u8; 16] = peer[1..17].try_into().expect("16");
    let expect = if px {
        xor16(&share.key, my_delta)
    } else {
        share.key
    };
    if !ct_eq(&expect, &pmac) {
        return Err(Error::Crypto(
            "netprep: IT-MAC check failed on open (tampered share — abort)".into(),
        ));
    }
    Ok(share.x ^ px)
}

/// `n` random authenticated shares `⟨rᵢ⟩` (each `rᵢ` unknown to both) — networked
/// [`wrk17::rand_shares`](super::wrk17). Runs aBits in both directions: this party's random
/// bits authenticated under the peer's Δ (prover), and the peer's bits under this party's Δ
/// (verifier). `party` fixes the OT ordering so both sides pair up on the wire.
pub fn rand_shares(
    ch: &mut dyn Channel,
    party: Party,
    delta: &[u8; 16],
    n: usize,
) -> Result<Vec<Share>> {
    let bits = rand_bits(n)?;
    let (macs, keys) = match party {
        Party::A => {
            let macs = prover_macs(ch, &bits)?; // A's bits authenticated to B
            let keys = verifier_keys(ch, delta, n)?; // B's bits authenticated to A
            (macs, keys)
        }
        Party::B => {
            let keys = verifier_keys(ch, delta, n)?; // A's bits authenticated to B
            let macs = prover_macs(ch, &bits)?; // B's bits authenticated to A
            (macs, keys)
        }
    };
    Ok((0..n)
        .map(|i| Share {
            x: bits[i],
            mac: macs[i],
            key: keys[i],
        })
        .collect())
}

/// An authenticated AND triple `⟨a⟩,⟨b⟩,⟨c⟩` with `c = a∧b`, one party's shares.
#[derive(Clone, Copy, Debug)]
pub struct Triple(pub Share, pub Share, pub Share);

/// A single bit-OT over the networked COT: receiver role (returns the low bits).
fn bit_ot_recv(ch: &mut dyn Channel, choices: &[bool]) -> Result<Vec<bool>> {
    Ok(kos::cot_receiver(ch, choices)?
        .into_iter()
        .map(|m| m[0] & 1 == 1)
        .collect())
}

/// A single bit-OT over the networked COT: sender role with `(m0ᵢ, m1ᵢ)` bits.
fn bit_ot_send(ch: &mut dyn Channel, m0: &[bool], m1: &[bool]) -> Result<()> {
    let msgs: Vec<([u8; 16], [u8; 16])> = (0..m0.len())
        .map(|i| (bit_msg(m0[i]), bit_msg(m1[i])))
        .collect();
    kos::cot_sender(ch, &msgs)
}

/// `n` **raw** authenticated AND triples over the wire — networked
/// [`wrk17::rand_triples`](super::wrk17). Random `⟨a⟩,⟨b⟩`, then `c = a∧b` via the two
/// cross-term bit-OTs (`aa·bb`, `ab·ba`) plus local products, then `c` authenticated both
/// ways. "Raw" = possibly-leaky; [`sacrifice`] checks correctness, and combining (bucketing)
/// removes leakage.
pub fn rand_triples(
    ch: &mut dyn Channel,
    party: Party,
    delta: &[u8; 16],
    n: usize,
) -> Result<Vec<Triple>> {
    let a = rand_shares(ch, party, delta, n)?;
    let b = rand_shares(ch, party, delta, n)?;
    let my_a: Vec<bool> = a.iter().map(|s| s.x).collect(); // aa (A) or ab (B)
    let my_b: Vec<bool> = b.iter().map(|s| s.x).collect(); // ba (A) or bb (B)

    // Cross terms. cross1 = aa·bb: A is receiver (choice aa), B is sender (r1, r1⊕bb).
    // cross2 = ab·ba: B is receiver (choice ab), A is sender (r2, r2⊕ba). Each party ends
    // with an XOR-share of the cross product.
    let (cross1, cross2): (Vec<bool>, Vec<bool>) = match party {
        Party::A => {
            let cross1 = bit_ot_recv(ch, &my_a)?; // aa·bb ⊕ r1
            let r2 = rand_bits(n)?;
            let m1: Vec<bool> = (0..n).map(|i| r2[i] ^ my_b[i]).collect(); // r2 ⊕ ba
            bit_ot_send(ch, &r2, &m1)?; // cross2 share = r2
            (cross1, r2)
        }
        Party::B => {
            let r1 = rand_bits(n)?;
            let m1: Vec<bool> = (0..n).map(|i| r1[i] ^ my_b[i]).collect(); // r1 ⊕ bb
            bit_ot_send(ch, &r1, &m1)?; // cross1 share = r1
            let cross2 = bit_ot_recv(ch, &my_a)?; // ab·ba ⊕ r2
            (r1, cross2)
        }
    };

    // c = a∧b as an XOR-share: local aa·ba (A) / ab·bb (B), plus the two cross shares.
    let c_bits: Vec<bool> = (0..n)
        .map(|i| (my_a[i] & my_b[i]) ^ cross1[i] ^ cross2[i])
        .collect();

    // Authenticate c in both directions (this party's c-bits under the peer's Δ, and the
    // peer's c-bits under this party's Δ), mirroring rand_shares' ordering.
    let (c_macs, c_keys) = match party {
        Party::A => {
            let macs = prover_macs(ch, &c_bits)?;
            let keys = verifier_keys(ch, delta, n)?;
            (macs, keys)
        }
        Party::B => {
            let keys = verifier_keys(ch, delta, n)?;
            let macs = prover_macs(ch, &c_bits)?;
            (macs, keys)
        }
    };

    Ok((0..n)
        .map(|i| {
            let c = Share {
                x: c_bits[i],
                mac: c_macs[i],
                key: c_keys[i],
            };
            Triple(a[i], b[i], c)
        })
        .collect())
}

/// **Sacrifice check** (networked [`wrk17::verify_triple`](super::wrk17)): validate `t`
/// against an independent triple `aux` by MAC-checked-opening `d = a⊕â`, `e = b⊕b̂`, then
/// `⟨c⟩ ⊕ (â∧b̂ ⊕ d·b̂ ⊕ e·â ⊕ d·e)` to **0**. A maliciously-biased `c` in `t` is caught —
/// the protocol aborts. Both parties call this; `party`/`delta` drive the local const-adds.
pub fn sacrifice(
    ch: &mut dyn Channel,
    party: Party,
    delta: &[u8; 16],
    t: &Triple,
    aux: &Triple,
) -> Result<()> {
    let d = open(ch, delta, &t.0.xor(&aux.0))?; // a ⊕ â
    let e = open(ch, delta, &t.1.xor(&aux.1))?; // b ⊕ b̂
                                                // ⟨â∧b̂⟩ reconstructed from aux via Beaver: aux.c ⊕ d·⟨b̂⟩ ⊕ e·⟨â⟩ ⊕ d·e.
    let mut cp = aux.2.xor(&aux.1.scale(d)).xor(&aux.0.scale(e));
    if d & e {
        cp = cp.xor_const(true, party, delta);
    }
    if open(ch, delta, &t.2.xor(&cp))? {
        return Err(Error::Crypto(
            "netprep: triple failed the sacrifice check (corrupted triple — abort)".into(),
        ));
    }
    Ok(())
}

/// Bucket **combine** of two AND triples into one (networked
/// [`wrk17::combine`](super::wrk17)) — the leakage-removal step. Opens `d = y1⊕y2` and
/// outputs `(⟨x1⊕x2⟩, ⟨y1⟩, ⟨z1⊕z2⊕d·x2⟩)`, correct and non-leaky if *either* input was.
pub fn combine(ch: &mut dyn Channel, delta: &[u8; 16], t1: &Triple, t2: &Triple) -> Result<Triple> {
    let d = open(ch, delta, &t1.1.xor(&t2.1))?; // d = y1 ⊕ y2
    let x = t1.0.xor(&t2.0);
    let y = t1.1;
    let mut z = t1.2.xor(&t2.2);
    if d {
        z = z.xor(&t2.0); // ⊕ d·x2
    }
    Ok(Triple(x, y, z))
}

/// `n` **bucketed** AND triples over the wire (networked
/// [`wrk17::bucketed_triples`](super::wrk17)): `n·bucket` raw triples, a shared random
/// bucket assignment, each bucket folded with [`combine`]. Leakage is removed if ≥ 1 raw
/// triple per bucket was non-leaky; correctness is the raw triples' [`sacrifice`] job.
pub fn bucketed_triples(
    ch: &mut dyn Channel,
    party: Party,
    delta: &[u8; 16],
    n: usize,
    bucket: usize,
) -> Result<Vec<Triple>> {
    assert!(bucket >= 1, "bucket size must be ≥ 1");
    let raw = rand_triples(ch, party, delta, n * bucket)?;
    let perm = shared_permutation(ch, party, raw.len())?;
    let shuffled: Vec<Triple> = perm.iter().map(|&i| raw[i]).collect();
    let mut out = Vec::with_capacity(n);
    for chunk in shuffled.chunks(bucket) {
        let mut acc = chunk[0];
        for t in &chunk[1..] {
            acc = combine(ch, delta, &acc, t)?;
        }
        out.push(acc);
    }
    Ok(out)
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

    /// Run party A's closure on this thread and party B's on a spawned thread, connected
    /// by a loopback TCP pair; return both results.
    fn two_party<TA, TB>(
        a_fn: impl FnOnce(&mut TcpChannel) -> TA,
        b_fn: impl FnOnce(&mut TcpChannel) -> TB + Send + 'static,
    ) -> (TA, TB)
    where
        TB: Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hb = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            b_fn(&mut ch)
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let ra = a_fn(&mut ch);
        let rb = hb.join().unwrap();
        (ra, rb)
    }

    /// The mirror-image body both parties run for the triple test: generate triples, open
    /// the first `n` and assert `c == a∧b`, do an honest sacrifice (must pass) and a
    /// tampered one (must abort). Both parties execute the identical sequence so every
    /// interactive open/sacrifice pairs up on the wire.
    fn triple_party_body(
        ch: &mut TcpChannel,
        party: Party,
        delta: &[u8; 16],
        n: usize,
    ) -> Result<()> {
        let triples = rand_triples(ch, party, delta, n + 4)?;
        for (k, t) in triples.iter().enumerate().take(n) {
            let a = open(ch, delta, &t.0)?;
            let b = open(ch, delta, &t.1)?;
            let c = open(ch, delta, &t.2)?;
            assert_eq!(c, a & b, "triple {k}: c must equal a∧b");
        }
        // Honest sacrifice of a correct triple against an independent one — must pass.
        sacrifice(ch, party, delta, &triples[n], &triples[n + 1])?;
        // A wrong-but-MAC-valid triple (c flipped via a public const-add on both parties)
        // must be caught by the sacrifice's value check.
        let mut bad = triples[n + 2];
        bad.2 = bad.2.xor_const(true, party, delta);
        let res = sacrifice(ch, party, delta, &bad, &triples[n + 3]);
        assert!(res.is_err(), "sacrifice must abort on a corrupted triple");
        Ok(())
    }

    #[test]
    fn networked_triples_are_correct_and_sacrifice_aborts() {
        // Two networked parties build authenticated AND triples over TCP via the TinyOT
        // F_pre (both-direction aBits + cross-term OTs). Every honest triple satisfies
        // c = a∧b, an honest sacrifice passes, and a corrupted triple is caught.
        let da = [0x11u8; 16];
        let db = [0x22u8; 16];
        let n = 2usize;
        let (ra, rb) = two_party(
            move |ch| triple_party_body(ch, Party::A, &da, n),
            move |ch| triple_party_body(ch, Party::B, &db, n),
        );
        ra.expect("party A completes");
        rb.expect("party B completes");
    }

    #[test]
    fn networked_bucketed_triples_are_correct() {
        // Bucketing (leakage removal via combine) still yields correct triples.
        let da = [0x3cu8; 16];
        let db = [0x5au8; 16];
        let (ra, rb) = two_party(
            move |ch| -> Result<()> {
                let ts = bucketed_triples(ch, Party::A, &da, 2, 2)?;
                for t in &ts {
                    let a = open(ch, &da, &t.0)?;
                    let b = open(ch, &da, &t.1)?;
                    let c = open(ch, &da, &t.2)?;
                    assert_eq!(c, a & b, "bucketed triple: c == a∧b");
                }
                Ok(())
            },
            move |ch| -> Result<()> {
                let ts = bucketed_triples(ch, Party::B, &db, 2, 2)?;
                for t in &ts {
                    let a = open(ch, &db, &t.0)?;
                    let b = open(ch, &db, &t.1)?;
                    let c = open(ch, &db, &t.2)?;
                    assert_eq!(c, a & b);
                }
                Ok(())
            },
        );
        ra.expect("party A completes");
        rb.expect("party B completes");
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
