//! **WRK17 authenticated 2PC** — the malicious-security machinery for the MPC-TLS
//! session: TinyOT-style **authenticated shares**, OT-generated **authenticated AND
//! triples** (`aAND`), and an **authenticated online evaluation** of any boolean
//! circuit whose every opening is **MAC-checked**, so a party that tampers with a
//! wire is **caught and the protocol aborts**. This is the step past [`dualex`]'s
//! ≤1-bit leak.
//!
//! # Authenticated shares `⟨x⟩`
//!
//! Both parties hold a global key ([`Keys`]): P_A holds `Δ_A`, P_B holds `Δ_B`
//! (κ = 128 bits). A shared bit `x = xa ⊕ xb` is *authenticated in both directions*
//! (this is the WRK17/TinyOT `⟨·⟩`): each party's share carries an information-
//! theoretic MAC the *other* party can check but cannot forge:
//!
//! ```text
//!     ma = ka ⊕ (xa · Δ_B)      (A owns xa, holds MAC ma;  B holds key ka)
//!     mb = kb ⊕ (xb · Δ_A)      (B owns xb, holds MAC mb;  A holds key kb)
//! ```
//!
//! - **XOR** ([`Share::xor`]) is fully local — MACs and keys are XOR-linear.
//! - **XOR-with-public-constant** ([`Share::xor_const`]) flips A's bit and B's key.
//! - **Open** ([`Share::open`]) reveals `x` *and re-checks both MACs*: a flipped share
//!   would need `ma ⊕ Δ_B`, i.e. a `2⁻κ` guess at `Δ_B`. **This is the abort gate.**
//!
//! # Preprocessing (`F_pre`) — authenticated randoms and `aAND` triples
//!
//! - [`rand_shares`] draws random `⟨r⟩` from **correlated, maliciously-secure OT**
//!   ([`kos`]): each party's random bit is the OT choice against the other's
//!   `(K, K⊕Δ)` pair, so it receives exactly `K ⊕ bit·Δ` — the MAC — under one fixed
//!   `Δ`. Running the aBit generation over KOS is what **closes the selective-failure
//!   channel on `Δ`** (the aBit consistency check).
//! - [`rand_triples`] produces `⟨a⟩,⟨b⟩,⟨c⟩` with `c = a∧b`: the two cross terms of
//!   `(aa⊕ab)(ba⊕bb)` are each a 1-bit OT (XOR-shares of a bit product), the diagonal
//!   terms are local, and the resulting `c` is then authenticated. Correct triples,
//!   from the crate's real OT.
//! - [`verify_triple`] is the **sacrifice check**: a triple is validated by
//!   Beaver-multiplying `a·b` with a second (sacrificed) triple and MAC-checked-opening
//!   the difference to 0 — a maliciously corrupted `c` is caught.
//! - [`combine_shared_y`] is WRK17's **bucket combine** of two triples sharing `⟨b⟩`.
//!
//! # Online — authenticated circuit evaluation
//!
//! [`eval_authenticated`] evaluates any [`Circuit`](super::circuit::Circuit) on
//! `⟨·⟩`-shared inputs: XOR/NOT local, each AND consuming one triple via Beaver's
//! trick with **MAC-checked opens**, outputs MAC-checked-opened. Correct on honest
//! input; **any tampered share aborts**.
//!
//! # Honest boundary — what this is, and what it is *not*
//!
//! This is a real, tested implementation of WRK17's authenticated-share machinery and
//! its malicious-**detection** mechanism (MAC-checked opens + the sacrifice check).
//! It is **not**, and is not claimed to be, an audited malicious-secure protocol:
//!
//! 1. **The OT layer is now KOS** ([`kos`]) — maliciously-secure, so the aBit and
//!    triple-cross-term OTs abort on a cheating receiver (the aBit consistency check).
//!    What still stands between this and *end-to-end* malicious security: WRK17's
//!    malicious **triple generation** (leaky-AND + bucketing — [`verify_triple`] and
//!    [`combine_shared_y`] are the pieces, not yet the full generator) and KOS's own
//!    honest-base-OT assumption.
//! 2. **Round complexity**: WRK17's headline is a *constant-round garbled* online.
//!    Realized here is the equivalent **interactive** authenticated-share online (same
//!    `F_pre`, same MAC-check security machinery, one round per AND-depth layer). The
//!    garbled online is the remaining form, not the security core.
//! 3. Both parties are modelled **in-process** (as the rest of this crate is); a
//!    deployment splits [`Share`] state across the wire.
//! 4. **Correctness and the abort mechanism are what the tests establish** — the
//!    *formal* malicious-security theorem is WRK17's proof and requires the external
//!    audit. It is **not** established by these correctness tests.

use neo_core::{Error, Result};

use super::circuit::{Circuit, Gate};
use super::kos;

/// MAC / global-key length in bytes (κ = 128 bits).
pub const KAPPA: usize = 16;

type Mac = [u8; KAPPA];

fn xor16(a: Mac, b: Mac) -> Mac {
    core::array::from_fn(|i| a[i] ^ b[i])
}

fn ct_eq(a: &Mac, b: &Mac) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn rand16() -> Result<Mac> {
    let mut k = [0u8; KAPPA];
    getrandom::getrandom(&mut k).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(k)
}

fn rand_bits(n: usize) -> Result<Vec<bool>> {
    let mut bytes = vec![0u8; n.div_ceil(8)];
    getrandom::getrandom(&mut bytes).map_err(|e| Error::Rng(e.to_string()))?;
    Ok((0..n).map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1).collect())
}

/// The two parties' global MAC keys: `Δ_A` (held by A), `Δ_B` (held by B). Fixed for
/// the lifetime of a share set; learning the other's `Δ` would allow forgery.
#[derive(Clone)]
pub struct Keys {
    da: Mac,
    db: Mac,
}

impl Keys {
    /// Fresh random global keys for both parties.
    pub fn random() -> Result<Self> {
        Ok(Keys {
            da: rand16()?,
            db: rand16()?,
        })
    }
}

/// A both-directions-authenticated shared bit `⟨x⟩`, `x = xa ⊕ xb`. Bundles both
/// parties' state for in-process modelling (a deployment splits it across the wire).
#[derive(Clone, Copy, Debug)]
pub struct Share {
    xa: bool,
    ma: Mac,
    ka: Mac,
    xb: bool,
    mb: Mac,
    kb: Mac,
}

impl Share {
    /// The all-zero share of the constant 0 (valid: `0 = 0 ⊕ 0·Δ`).
    fn zero() -> Share {
        Share {
            xa: false,
            ma: [0u8; KAPPA],
            ka: [0u8; KAPPA],
            xb: false,
            mb: [0u8; KAPPA],
            kb: [0u8; KAPPA],
        }
    }

    /// Deal a fresh, valid authenticated share of a **known** value `v` (dealer model;
    /// used to inject circuit inputs and in tests). A real input-sharing derives these
    /// from [`rand_shares`] and a masked open.
    pub fn deal(v: bool, keys: &Keys) -> Result<Share> {
        let xa = rand_bits(1)?[0];
        let xb = v ^ xa;
        let ka = rand16()?;
        let kb = rand16()?;
        Ok(Share {
            xa,
            ma: if xa { xor16(ka, keys.db) } else { ka },
            ka,
            xb,
            mb: if xb { xor16(kb, keys.da) } else { kb },
            kb,
        })
    }

    /// The cleartext value `xa ⊕ xb`. Not a per-party operation — for tests/asserts.
    pub fn value(&self) -> bool {
        self.xa ^ self.xb
    }

    /// `⟨x⟩ ⊕ ⟨y⟩`, fully local: XOR every component.
    pub fn xor(&self, o: &Share) -> Share {
        Share {
            xa: self.xa ^ o.xa,
            ma: xor16(self.ma, o.ma),
            ka: xor16(self.ka, o.ka),
            xb: self.xb ^ o.xb,
            mb: xor16(self.mb, o.mb),
            kb: xor16(self.kb, o.kb),
        }
    }

    /// `⟨x⟩ ⊕ c` for a **public** bit `c`: A flips its bit, B flips A's key by `c·Δ_B`
    /// (both preserving `ma = ka ⊕ xa·Δ_B`). Realises NOT (`c = 1`).
    pub fn xor_const(&self, c: bool, keys: &Keys) -> Share {
        let mut s = *self;
        if c {
            s.xa = !s.xa;
            s.ka = xor16(s.ka, keys.db);
        }
        s
    }

    /// `⟨x⟩ · c` for a **public** bit `c`: identity if `c = 1`, else the zero share.
    fn scale(&self, c: bool) -> Share {
        if c {
            *self
        } else {
            Share::zero()
        }
    }

    /// Open `⟨x⟩`, **re-checking both MACs** — the abort gate. Returns `x`, or an error
    /// if either party's revealed share fails its IT-MAC (a tamper attempt).
    pub fn open(&self, keys: &Keys) -> Result<bool> {
        let expect_ma = if self.xa {
            xor16(self.ka, keys.db)
        } else {
            self.ka
        };
        if !ct_eq(&self.ma, &expect_ma) {
            return Err(Error::Crypto(
                "WRK17: MAC check failed on A's share (abort)".into(),
            ));
        }
        let expect_mb = if self.xb {
            xor16(self.kb, keys.da)
        } else {
            self.kb
        };
        if !ct_eq(&self.mb, &expect_mb) {
            return Err(Error::Crypto(
                "WRK17: MAC check failed on B's share (abort)".into(),
            ));
        }
        Ok(self.xa ^ self.xb)
    }
}

/// An authenticated AND triple `⟨a⟩, ⟨b⟩, ⟨c⟩` with `c = a ∧ b`.
#[derive(Clone, Copy, Debug)]
pub struct Triple(pub Share, pub Share, pub Share);

/// Correlated-OT authentication: given a holder's `bits` and the verifier's global
/// key `delta`, run IKNP OT on `(Kᵢ, Kᵢ⊕Δ)` so the holder receives `Mᵢ = Kᵢ ⊕ bitᵢ·Δ`.
/// Returns `(macs, keys)` — holder's MACs and verifier's per-bit keys.
fn cot(bits: &[bool], delta: &Mac) -> Result<(Vec<Mac>, Vec<Mac>)> {
    let mut keys = Vec::with_capacity(bits.len());
    let mut pairs = Vec::with_capacity(bits.len());
    for _ in bits {
        let k = rand16()?;
        keys.push(k);
        pairs.push((k, xor16(k, *delta)));
    }
    let macs = kos::extend(bits, &pairs)?;
    Ok((macs, keys))
}

/// `n` random authenticated shares `⟨rᵢ⟩` (each `rᵢ` uniform, unknown to both), from
/// correlated OT in both directions.
pub fn rand_shares(n: usize, keys: &Keys) -> Result<Vec<Share>> {
    let xa = rand_bits(n)?;
    let xb = rand_bits(n)?;
    let (ma, ka) = cot(&xa, &keys.db)?; // A's bits authenticated to B
    let (mb, kb) = cot(&xb, &keys.da)?; // B's bits authenticated to A
    Ok((0..n)
        .map(|i| Share {
            xa: xa[i],
            ma: ma[i],
            ka: ka[i],
            xb: xb[i],
            mb: mb[i],
            kb: kb[i],
        })
        .collect())
}

fn bit_msg(b: bool) -> Mac {
    let mut m = [0u8; KAPPA];
    m[0] = b as u8;
    m
}

/// `n` authenticated AND triples `⟨a⟩,⟨b⟩,⟨c⟩` with `c = a∧b`, from real OT.
pub fn rand_triples(n: usize, keys: &Keys) -> Result<Vec<Triple>> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let shares = rand_shares(2 * n, keys)?;
    let (a, b) = shares.split_at(n);

    // Per-party bit parts: a = aa⊕ab, b = ba⊕bb.
    let aa: Vec<bool> = a.iter().map(|s| s.xa).collect();
    let ab: Vec<bool> = a.iter().map(|s| s.xb).collect();
    let ba: Vec<bool> = b.iter().map(|s| s.xa).collect();
    let bb: Vec<bool> = b.iter().map(|s| s.xb).collect();

    // cross1 = aa·bb via OT: A chooses with aa, B sends (r1, r1⊕bb). A learns r1⊕aa·bb.
    let r1 = rand_bits(n)?;
    let msg1: Vec<(Mac, Mac)> = (0..n)
        .map(|i| (bit_msg(r1[i]), bit_msg(r1[i] ^ bb[i])))
        .collect();
    let recv1 = kos::extend(&aa, &msg1)?;
    let cross1_a: Vec<bool> = recv1.iter().map(|m| m[0] & 1 == 1).collect();
    let cross1_b = &r1;

    // cross2 = ab·ba via OT: B chooses with ab, A sends (r2, r2⊕ba). B learns r2⊕ab·ba.
    let r2 = rand_bits(n)?;
    let msg2: Vec<(Mac, Mac)> = (0..n)
        .map(|i| (bit_msg(r2[i]), bit_msg(r2[i] ^ ba[i])))
        .collect();
    let recv2 = kos::extend(&ab, &msg2)?;
    let cross2_b: Vec<bool> = recv2.iter().map(|m| m[0] & 1 == 1).collect();
    let cross2_a = &r2;

    // c = a∧b as XOR-shares: cA = aa·ba ⊕ cross1_A ⊕ cross2_A ; cB = ab·bb ⊕ cross1_B ⊕ cross2_B.
    let ca: Vec<bool> = (0..n)
        .map(|i| (aa[i] & ba[i]) ^ cross1_a[i] ^ cross2_a[i])
        .collect();
    let cb: Vec<bool> = (0..n)
        .map(|i| (ab[i] & bb[i]) ^ cross1_b[i] ^ cross2_b[i])
        .collect();

    // Authenticate c in both directions.
    let (mca, kca) = cot(&ca, &keys.db)?;
    let (mcb, kcb) = cot(&cb, &keys.da)?;

    Ok((0..n)
        .map(|i| {
            let c = Share {
                xa: ca[i],
                ma: mca[i],
                ka: kca[i],
                xb: cb[i],
                mb: mcb[i],
                kb: kcb[i],
            };
            Triple(a[i], b[i], c)
        })
        .collect())
}

/// Beaver AND of two authenticated shares using one triple: `⟨x∧y⟩ = ⟨c⟩ ⊕ d·⟨b⟩ ⊕
/// e·⟨a⟩ ⊕ d·e`, where `d = open(x⊕a)`, `e = open(y⊕b)` are **MAC-checked**.
fn beaver_and(x: &Share, y: &Share, t: &Triple, keys: &Keys) -> Result<Share> {
    let d = x.xor(&t.0).open(keys)?;
    let e = y.xor(&t.1).open(keys)?;
    let mut z = t.2.xor(&t.1.scale(d)).xor(&t.0.scale(e));
    if d & e {
        z = z.xor_const(true, keys);
    }
    Ok(z)
}

/// **Sacrifice check**: validate triple `t` by Beaver-multiplying `a·b` with the
/// sacrificed triple `aux` and MAC-checked-opening `⟨c⟩ ⊕ ⟨a∧b⟩` to 0. A maliciously
/// corrupted `c` in `t` is caught. (`aux` must be an independent honest triple; the
/// residual selective-failure that motivates WRK17's bucketing is a security property,
/// not a correctness one — see the module boundary.)
pub fn verify_triple(t: &Triple, aux: &Triple, keys: &Keys) -> Result<()> {
    let d = t.0.xor(&aux.0).open(keys)?; // a ⊕ â
    let e = t.1.xor(&aux.1).open(keys)?; // b ⊕ b̂
    let mut cp = aux.2.xor(&aux.1.scale(d)).xor(&aux.0.scale(e)); // ⟨a∧b⟩
    if d & e {
        cp = cp.xor_const(true, keys);
    }
    if t.2.xor(&cp).open(keys)? {
        return Err(Error::Crypto(
            "WRK17: triple failed the sacrifice check (abort)".into(),
        ));
    }
    Ok(())
}

/// WRK17 **bucket combine** of two triples that share `⟨b⟩`: returns
/// `(⟨a1⊕a2⟩, ⟨b⟩, ⟨c1⊕c2⟩)`, itself a correct triple since `(a1⊕a2)·b = c1⊕c2`. In
/// full WRK17 this is the leakage-removal step (combine a bucket of leaky triples);
/// its *security* role is not something a correctness test can show.
pub fn combine_shared_y(t1: &Triple, t2: &Triple) -> Triple {
    Triple(t1.0.xor(&t2.0), t1.1, t1.2.xor(&t2.2))
}

/// Evaluate `circuit` under authenticated shares: `inputs[i]` is `⟨wireᵢ⟩`, `triples`
/// supplies one aAND per AND gate. XOR/NOT are local; each AND uses [`beaver_and`]
/// with MAC-checked opens; outputs are MAC-checked-opened. Aborts on any tamper.
pub fn eval_authenticated(
    circuit: &Circuit,
    inputs: &[Share],
    triples: &[Triple],
    keys: &Keys,
) -> Result<Vec<bool>> {
    if inputs.len() != circuit.input_bits {
        return Err(Error::Crypto("WRK17: wrong input width".into()));
    }
    if triples.len() < circuit.and_gates() {
        return Err(Error::Crypto("WRK17: not enough AND triples".into()));
    }
    let mut w: Vec<Option<Share>> = vec![None; circuit.num_wires];
    for (i, s) in inputs.iter().enumerate() {
        w[i] = Some(*s);
    }
    let get = |w: &Vec<Option<Share>>, i: usize| -> Result<Share> {
        w[i].ok_or_else(|| Error::Crypto("WRK17: wire used before set".into()))
    };

    let mut tix = 0;
    for gate in &circuit.gates {
        match *gate {
            Gate::Xor(a, b, o) => {
                let s = get(&w, a)?.xor(&get(&w, b)?);
                w[o] = Some(s);
            }
            Gate::Inv(a, o) => {
                let s = get(&w, a)?.xor_const(true, keys);
                w[o] = Some(s);
            }
            Gate::And(a, b, o) => {
                let s = beaver_and(&get(&w, a)?, &get(&w, b)?, &triples[tix], keys)?;
                tix += 1;
                w[o] = Some(s);
            }
        }
    }
    circuit
        .outputs
        .iter()
        .map(|&o| get(&w, o)?.open(keys))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc_tls::circuit::Builder;

    // A 4-bit ripple-carry adder: inputs x[0..4] ‖ y[4..8], outputs sum[0..4] ‖ carry.
    fn adder4() -> Circuit {
        let mut b = Builder::new(8);
        let x: Vec<usize> = (0..4).collect();
        let y: Vec<usize> = (4..8).collect();
        let mut carry = b.zero();
        let mut out = Vec::new();
        for i in 0..4 {
            let (sum, c) = b.full_adder(x[i], y[i], carry);
            out.push(sum);
            carry = c;
        }
        out.push(carry);
        b.build(8, out)
    }

    fn input_shares(vals: &[bool], keys: &Keys) -> Vec<Share> {
        vals.iter()
            .map(|&v| Share::deal(v, keys).unwrap())
            .collect()
    }

    #[test]
    fn xor_and_const_preserve_the_mac() {
        let keys = Keys::random().unwrap();
        for (x, y) in [(false, false), (false, true), (true, false), (true, true)] {
            let sx = Share::deal(x, &keys).unwrap();
            let sy = Share::deal(y, &keys).unwrap();
            assert_eq!(
                sx.xor(&sy).open(&keys).unwrap(),
                x ^ y,
                "XOR opens correctly"
            );
            assert_eq!(
                sx.xor_const(true, &keys).open(&keys).unwrap(),
                !x,
                "NOT opens correctly"
            );
        }
    }

    #[test]
    fn a_tampered_share_aborts_on_open() {
        let keys = Keys::random().unwrap();
        let mut s = Share::deal(false, &keys).unwrap();
        // Flip A's bit but keep its MAC — the classic forgery the IT-MAC must catch.
        s.xa = !s.xa;
        assert!(
            s.open(&keys).is_err(),
            "flipping xa without fixing ma must abort"
        );
        // Flip B's MAC directly.
        let mut s2 = Share::deal(true, &keys).unwrap();
        s2.mb[0] ^= 1;
        assert!(s2.open(&keys).is_err(), "corrupting mb must abort");
    }

    #[test]
    fn ot_generated_triples_are_correct_ands() {
        let keys = Keys::random().unwrap();
        let triples = rand_triples(16, &keys).unwrap();
        for t in &triples {
            // Each share opens (MACs valid) and c = a∧b.
            let a = t.0.open(&keys).unwrap();
            let b = t.1.open(&keys).unwrap();
            let c = t.2.open(&keys).unwrap();
            assert_eq!(c, a & b, "OT triple must satisfy c = a ∧ b");
        }
    }

    #[test]
    fn sacrifice_check_passes_honest_and_catches_corruption() {
        let keys = Keys::random().unwrap();
        let mut triples = rand_triples(4, &keys).unwrap();
        // Honest triple validated against an honest sacrifice passes.
        verify_triple(&triples[0], &triples[1], &keys).unwrap();
        // Corrupt c of triple[2] (flip its value while keeping a valid MAC under Δ).
        triples[2].2 = triples[2].2.xor_const(true, &keys);
        assert!(
            verify_triple(&triples[2], &triples[3], &keys).is_err(),
            "a corrupted triple must fail the sacrifice check"
        );
    }

    #[test]
    fn bucket_combine_yields_a_correct_triple() {
        let keys = Keys::random().unwrap();
        // Two triples sharing the same ⟨b⟩, dealt honestly.
        let shared_b = Share::deal(true, &keys).unwrap();
        let mk = |av: bool| -> Triple {
            let a = Share::deal(av, &keys).unwrap();
            let c = Share::deal(av & shared_b.value(), &keys).unwrap();
            Triple(a, shared_b, c)
        };
        let t1 = mk(true);
        let t2 = mk(false);
        let combined = combine_shared_y(&t1, &t2);
        let a = combined.0.open(&keys).unwrap();
        let b = combined.1.open(&keys).unwrap();
        let c = combined.2.open(&keys).unwrap();
        assert_eq!(c, a & b, "combined triple stays a correct AND");
    }

    #[test]
    fn evaluate_adder_under_authenticated_shares() {
        let keys = Keys::random().unwrap();
        let circuit = adder4();
        for (x, y) in [(0u8, 0u8), (7, 9), (5, 5), (15, 15), (10, 6)] {
            let bits: Vec<bool> = (0..4)
                .map(|i| (x >> i) & 1 == 1)
                .chain((0..4).map(|i| (y >> i) & 1 == 1))
                .collect();
            let inputs = input_shares(&bits, &keys);
            let triples = rand_triples(circuit.and_gates(), &keys).unwrap();

            let out = eval_authenticated(&circuit, &inputs, &triples, &keys).unwrap();
            // Cross-check against the plaintext circuit and against integer addition.
            assert_eq!(
                out,
                circuit.eval(&bits),
                "authenticated eval matches plaintext circuit"
            );
            let got: u8 = (0..5).filter(|&i| out[i]).map(|i| 1u8 << i).sum();
            assert_eq!(got, x + y, "4-bit adder: {x} + {y}");
        }
    }

    #[test]
    fn a_tampered_wire_aborts_the_evaluation() {
        let keys = Keys::random().unwrap();
        let circuit = adder4();
        let bits = vec![true, false, true, false, true, true, false, false];
        let mut inputs = input_shares(&bits, &keys);
        let triples = rand_triples(circuit.and_gates(), &keys).unwrap();
        // Corrupt an input share's MAC: the first MAC-checked open must abort.
        inputs[0].ma[0] ^= 1;
        assert!(
            eval_authenticated(&circuit, &inputs, &triples, &keys).is_err(),
            "a tampered input share must abort the authenticated evaluation"
        );
    }
}
