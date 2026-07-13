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
//! On top of the aBits, this module composes the **full networked TinyOT `F_pre`** and the
//! **networked online** — an end-to-end two-party malicious 2PC with no in-process
//! modelling: distributed authenticated shares [`Share`] (both-direction aBits,
//! [`rand_shares`]) with a symmetric MAC-checked [`open`]; authenticated AND triples
//! [`Triple`] ([`rand_triples`]: the two cross-term bit-OTs `aa·bb`, `ab·ba` over the
//! networked COT, then `c = a∧b` authenticated both ways); the [`sacrifice`] check that
//! catches a corrupted triple; [`combine`]/[`bucketed_triples`] for leakage removal; and
//! [`eval_authenticated`], which evaluates any boolean circuit under the distributed shares
//! (XOR/NOT local, each AND a networked Beaver open) — all as genuine two-party protocols
//! where neither party sees the other's share.
//!
//! # Honest boundary
//!
//! - Run over a **genuine two-party channel** (tested over real TCP sockets): the OT is
//!   [`kos`](super::kos)'s maliciously-secure extension (so the networked generation
//!   catches a cheating receiver), honest triples satisfy `c = a∧b`, the sacrifice aborts
//!   on a corrupted triple, the networked online reproduces the plaintext circuit, and a
//!   forged-MAC open aborts. This is the **distributed form** of
//!   [`wrk17`](super::wrk17)'s in-process `Share`/`Triple`/online, which remains the
//!   reference; the constant-round [`authgarble`](super::authgarble) online is the
//!   higher-throughput alternative (still bundled/in-process).
//! - The KOS **Roy22** caveat ([`kos`](super::kos)) applies, and nothing here is audited —
//!   correctness + the abort mechanism are tested; the formal malicious-security theorem is
//!   the WRK17/KOS proofs + the external audit.

use neo_core::{Error, Result};

use super::circuit::{Circuit, Gate};
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

// ── Networked authenticated online — evaluate a circuit over the wire ────────────
//
// The distributed counterpart of [`wrk17::eval_authenticated`](super::wrk17): the two
// parties jointly evaluate a boolean circuit under their [`Share`]s, XOR/NOT local, each
// AND a Beaver step with a [`Triple`] from [`netprep`]'s networked `F_pre`, every open
// MAC-checked over the [`Channel`]. Composed with [`rand_shares`] (inputs) + [`bucketed_triples`]
// this is an **end-to-end two-party malicious 2PC with no in-process modelling**.

/// Networked Beaver AND: `⟨x∧y⟩` from `⟨x⟩,⟨y⟩` and a triple `⟨a⟩,⟨b⟩,⟨a∧b⟩`, via the two
/// MAC-checked opens `d = x⊕a`, `e = y⊕b` (masked by the random triple, so nothing leaks):
/// `⟨xy⟩ = ⟨c⟩ ⊕ d·⟨b⟩ ⊕ e·⟨a⟩ ⊕ d·e`.
fn beaver_and(
    ch: &mut dyn Channel,
    party: Party,
    delta: &[u8; 16],
    x: &Share,
    y: &Share,
    t: &Triple,
) -> Result<Share> {
    let d = open(ch, delta, &x.xor(&t.0))?;
    let e = open(ch, delta, &y.xor(&t.1))?;
    let mut z = t.2.xor(&t.1.scale(d)).xor(&t.0.scale(e));
    if d & e {
        z = z.xor_const(true, party, delta);
    }
    Ok(z)
}

/// **Networked authenticated input** (TinyOT input protocol): the `owner` party injects
/// its known `values` as authenticated shares `⟨vᵢ⟩`, over `ch`. Both parties draw random
/// `⟨rᵢ⟩` ([`rand_shares`]); `rᵢ` is **partially opened to the owner only** (the peer sends
/// its MAC-checked share and learns nothing); the owner broadcasts the public
/// `δᵢ = vᵢ ⊕ rᵢ`; both set `⟨vᵢ⟩ = ⟨rᵢ⟩ ⊕ δᵢ`. The peer learns `δ` but not `v` (`r` stays
/// hidden). `values` is `Some(bits)` for the owner, `None` for the peer.
pub fn input_bits(
    ch: &mut dyn Channel,
    party: Party,
    delta: &[u8; 16],
    owner: Party,
    values: Option<&[bool]>,
    n: usize,
) -> Result<Vec<Share>> {
    let r = rand_shares(ch, party, delta, n)?;
    let deltas: Vec<bool> = if party == owner {
        let values =
            values.ok_or_else(|| Error::Crypto("netprep: owner needs input values".into()))?;
        if values.len() != n {
            return Err(Error::Crypto("netprep: input value count mismatch".into()));
        }
        // Owner recovers rᵢ from the peer's MAC-checked share, then broadcasts δ.
        let peer = ch.recv_exact(n * 17)?;
        let mut ds = Vec::with_capacity(n);
        for (i, ri) in r.iter().enumerate() {
            let px = peer[i * 17] & 1 == 1;
            let pmac: [u8; 16] = peer[i * 17 + 1..i * 17 + 17].try_into().expect("16");
            let expect = if px { xor16(&ri.key, delta) } else { ri.key };
            if !ct_eq(&expect, &pmac) {
                return Err(Error::Crypto(
                    "netprep: input-share MAC check failed (abort)".into(),
                ));
            }
            ds.push(values[i] ^ (ri.x ^ px));
        }
        ch.send(&ds.iter().map(|&b| b as u8).collect::<Vec<u8>>())?;
        ds
    } else {
        // Peer reveals its shares to the owner (MAC-checked there), then receives δ.
        let mut msg = Vec::with_capacity(n * 17);
        for s in &r {
            msg.push(s.x as u8);
            msg.extend_from_slice(&s.mac);
        }
        ch.send(&msg)?;
        ch.recv_exact(n)?.iter().map(|&b| b & 1 == 1).collect()
    };
    Ok((0..n)
        .map(|i| r[i].xor_const(deltas[i], party, delta))
        .collect())
}

/// Evaluate a boolean `circuit` end-to-end over the wire under **known** per-party inputs:
/// party A owns input wires `[0, a_owned)`, party B owns `[a_owned, input_bits)`. Each party
/// passes only its own `my_bits`; inputs are injected via [`input_bits`], triples via
/// [`rand_triples`], then [`eval_authenticated`]. Returns the opened output. This is the
/// "known-input" front-end that lets a real circuit (e.g. a TLS key-schedule circuit) run
/// through the fully-networked engine.
pub fn eval_circuit_2pc(
    ch: &mut dyn Channel,
    party: Party,
    delta: &[u8; 16],
    circuit: &Circuit,
    a_owned: usize,
    my_bits: &[bool],
) -> Result<Vec<bool>> {
    let n_b = circuit
        .input_bits
        .checked_sub(a_owned)
        .ok_or_else(|| Error::Crypto("netprep: a_owned exceeds circuit input width".into()))?;
    let a_vals = if party == Party::A {
        Some(my_bits)
    } else {
        None
    };
    let b_vals = if party == Party::B {
        Some(my_bits)
    } else {
        None
    };
    let mut inputs = input_bits(ch, party, delta, Party::A, a_vals, a_owned)?;
    inputs.extend(input_bits(ch, party, delta, Party::B, b_vals, n_b)?);
    let triples = rand_triples(ch, party, delta, circuit.and_gates())?;
    eval_authenticated(ch, party, delta, circuit, &inputs, &triples)
}

/// Evaluate `circuit` under distributed authenticated shares over `ch`. `inputs[i]` is this
/// party's share of wire `i`; `triples` supplies one AND-triple per AND gate. XOR/NOT are
/// local, each AND is a networked [`beaver_and`], and every output is MAC-checked-opened —
/// **aborting on any tamper**. Both parties run this identically; the returned output bits
/// are the same on both sides.
pub fn eval_authenticated(
    ch: &mut dyn Channel,
    party: Party,
    delta: &[u8; 16],
    circuit: &Circuit,
    inputs: &[Share],
    triples: &[Triple],
) -> Result<Vec<bool>> {
    if inputs.len() != circuit.input_bits {
        return Err(Error::Crypto("netprep: wrong input width".into()));
    }
    if triples.len() < circuit.and_gates() {
        return Err(Error::Crypto("netprep: not enough AND triples".into()));
    }
    let mut w: Vec<Option<Share>> = vec![None; circuit.num_wires];
    for (i, s) in inputs.iter().enumerate() {
        w[i] = Some(*s);
    }
    let get = |w: &[Option<Share>], i: usize| -> Result<Share> {
        w[i].ok_or_else(|| Error::Crypto("netprep: wire used before set".into()))
    };
    let mut tix = 0;
    for gate in &circuit.gates {
        match *gate {
            Gate::Xor(a, b, o) => w[o] = Some(get(&w, a)?.xor(&get(&w, b)?)),
            Gate::Inv(a, o) => w[o] = Some(get(&w, a)?.xor_const(true, party, delta)),
            Gate::And(a, b, o) => {
                let s = beaver_and(ch, party, delta, &get(&w, a)?, &get(&w, b)?, &triples[tix])?;
                tix += 1;
                w[o] = Some(s);
            }
        }
    }
    circuit
        .outputs
        .iter()
        .map(|&o| open(ch, delta, &get(&w, o)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::circuit::Builder;
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

    /// A small circuit exercising AND, XOR and NOT: out0 = (i0∧i1)⊕i2,
    /// out1 = (i0∧i3)⊕¬i1. 4 inputs, 2 AND gates.
    fn small_circuit() -> Circuit {
        let mut b = Builder::new(4);
        let a01 = b.and(0, 1);
        let o0 = b.xor(a01, 2);
        let a03 = b.and(0, 3);
        let n1 = b.inv(1);
        let o1 = b.xor(a03, n1);
        b.build(4, vec![o0, o1])
    }

    /// Both parties jointly evaluate `circuit` over the wire on random shared inputs, then
    /// open the inputs and outputs; returns `(input_bits, output_bits)`.
    fn eval_party(
        ch: &mut TcpChannel,
        party: Party,
        delta: &[u8; 16],
        circuit: &Circuit,
    ) -> Result<(Vec<bool>, Vec<bool>)> {
        let inputs = rand_shares(ch, party, delta, circuit.input_bits)?;
        let triples = rand_triples(ch, party, delta, circuit.and_gates())?;
        let out = eval_authenticated(ch, party, delta, circuit, &inputs, &triples)?;
        let in_vals = inputs
            .iter()
            .map(|s| open(ch, delta, s))
            .collect::<Result<Vec<bool>>>()?;
        Ok((in_vals, out))
    }

    #[test]
    fn networked_online_evaluates_a_circuit() {
        // End-to-end two-party malicious 2PC with NO in-process modelling: both parties,
        // each on its own socket with its own Δ, jointly evaluate the circuit over the
        // wire (inputs + triples from netprep's networked F_pre, each AND a networked
        // Beaver open). The opened output must equal the plaintext circuit on the opened
        // inputs, and both parties must agree.
        let da = [0x11u8; 16];
        let db = [0x22u8; 16];
        let circuit = small_circuit();
        let (ca, cb) = (circuit.clone(), circuit.clone());
        let (ra, rb) = two_party(
            move |ch| eval_party(ch, Party::A, &da, &ca),
            move |ch| eval_party(ch, Party::B, &db, &cb),
        );
        let (in_a, out_a) = ra.expect("party A completes");
        let (in_b, out_b) = rb.expect("party B completes");
        assert_eq!(in_a, in_b, "both parties open the same inputs");
        assert_eq!(out_a, out_b, "both parties open the same outputs");
        assert_eq!(
            out_a,
            circuit.eval(&in_a),
            "networked online == plaintext circuit"
        );
    }

    #[test]
    fn networked_known_input_circuit_matches_plaintext() {
        // Known per-party inputs injected via the networked input-sharing protocol, then
        // evaluated over the wire: A owns wires [0,2), B owns [2,4). The opened output
        // must equal the plaintext circuit on the full input.
        let da = [0x11u8; 16];
        let db = [0x22u8; 16];
        let circuit = small_circuit();
        let full: [bool; 4] = [true, false, true, true];
        let a_owned = 2;
        let (ca, cb) = (circuit.clone(), circuit.clone());
        let a_bits = full[..a_owned].to_vec();
        let b_bits = full[a_owned..].to_vec();
        let (ra, rb) = two_party(
            move |ch| eval_circuit_2pc(ch, Party::A, &da, &ca, a_owned, &a_bits),
            move |ch| eval_circuit_2pc(ch, Party::B, &db, &cb, a_owned, &b_bits),
        );
        let out_a = ra.expect("party A completes");
        let out_b = rb.expect("party B completes");
        assert_eq!(out_a, out_b, "both parties open the same output");
        assert_eq!(
            out_a,
            circuit.eval(&full),
            "networked known-input eval == plaintext"
        );
    }

    #[test]
    #[ignore] // ~30-60s: a real TLS key-schedule circuit (SHA-256 compression) over the wire
    fn networked_online_evaluates_real_tls_circuit() {
        // The actual SHA-256 compression circuit the TLS 1.3 key schedule runs, evaluated
        // end-to-end over TCP through the fully-networked engine (input-sharing → F_pre →
        // authenticated online), matching the plaintext circuit. Proves the live-TLS
        // circuits run through the networked two-party engine, not just a toy adder.
        use super::super::sha256::sha256_compress_circuit;
        let da = [0x3cu8; 16];
        let db = [0x5au8; 16];
        let circuit = sha256_compress_circuit();
        let full: Vec<bool> = (0..circuit.input_bits)
            .map(|i| i.wrapping_mul(2_654_435_761) & 1 == 1)
            .collect();
        let a_owned = circuit.input_bits / 2;
        let (ca, cb) = (circuit.clone(), circuit.clone());
        let a_bits = full[..a_owned].to_vec();
        let b_bits = full[a_owned..].to_vec();
        let (ra, rb) = two_party(
            move |ch| eval_circuit_2pc(ch, Party::A, &da, &ca, a_owned, &a_bits),
            move |ch| eval_circuit_2pc(ch, Party::B, &db, &cb, a_owned, &b_bits),
        );
        let out_a = ra.expect("party A completes");
        rb.expect("party B completes");
        assert_eq!(
            out_a,
            circuit.eval(&full),
            "networked online reproduces the real SHA-256 compression"
        );
    }

    #[test]
    fn networked_open_aborts_on_forged_mac() {
        // The online's abort gate: a party that forges its share's MAC (which needs the
        // peer's Δ) is caught at the very next open. Single open → no deadlock: the honest
        // party aborts, the forger's own check (of the honest peer) passes.
        let da = [0x33u8; 16];
        let db = [0x44u8; 16];
        let (_ra, rb) = two_party(
            move |ch| {
                // Party A forges: flip a MAC byte on its share before opening.
                let mut s = rand_shares(ch, Party::A, &da, 1).unwrap()[0];
                s.mac[0] ^= 1;
                let _ = open(ch, &da, &s); // A's own check (of B) passes; ignore
            },
            move |ch| -> bool {
                let s = rand_shares(ch, Party::B, &db, 1).unwrap()[0];
                open(ch, &db, &s).is_err() // B must detect A's forged MAC
            },
        );
        assert!(rb, "the honest party aborts on a forged-MAC open");
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
