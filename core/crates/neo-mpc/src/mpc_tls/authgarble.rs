//! **WRK17 / KRRW18 authenticated garbling** — the *constant-round* maliciously-secure
//! 2PC online, implemented from the published construction (Wang–Ranellucci–Katz 2017,
//! optimised by Katz–Ranellucci–Rosulek–Wang 2018; see the module boundary for the
//! reference this follows). This is the piece past [`wrk17`](super::wrk17)'s interactive
//! authenticated online: instead of a round per AND-depth layer, the garbler sends one
//! garbled row per AND gate and the evaluator finishes locally.
//!
//! # The authenticated share `{x}`
//!
//! A wire holds `{x} = [x·(Δ_G, Δ_E, 1)]` — an XOR secret share (garbler `g`, evaluator
//! `e`) of the `(2λ+1)`-bit vector `x·(Δ_G, Δ_E, 1)`, where `Δ_G` is the garbler's global
//! key and `Δ_E` the evaluator's ([`V`] is one party's `(2λ+1)`-bit share). Concretely
//! `g ⊕ e = x·(Δ_G, Δ_E, 1)`, so the last bit shares `x`, the first `λ` bits share
//! `x·Δ_G` (a MAC the garbler can check), and the middle `λ` bits share `x·Δ_E` (a MAC
//! the evaluator can check). **Open** re-checks *both* MACs — the abort gate.
//!
//! # Gates
//!
//! - **XOR** is local: `{x}⊕{y} = {x⊕y}` (the `(Δ_G,Δ_E,1)` correlation is the free-XOR
//!   offset).
//! - **Authenticated half gate** `{x},{y} ↦ {xy}` where the evaluator *knows* `x`
//!   ([`garble_half`]/[`eval_half`]): with label `X = {x}.g.dg` (so `X⊕Δ_G` is E's when
//!   `x=1`) and `H : {0,1}^λ → {0,1}^{2λ+1}`, the garbler sets `Z_G = H(X)` and sends
//!   `r = H(X⊕Δ_G) ⊕ H(X) ⊕ Y`; the evaluator computes
//!   `Z_E = H(X_E) ⊕ (x ? (Y_E ⊕ r) : 0)`. Then `Z_G ⊕ Z_E = xy·(Δ_G,Δ_E,1) = {xy}`. A
//!   garbler who corrupts `r` makes E's output share **unauthenticated** ⇒ a later open
//!   aborts.
//! - **AND** `{x},{y} ↦ {xy}` ([`and_gate`]) via `xy = (x⊕α)y ⊕ (y⊕β)α ⊕ αβ` and a
//!   preprocessing triple `{α},{β},{αβ}`: open `u=x⊕α`, `v=y⊕β` (MAC-checked; masked by
//!   the random `α,β` so nothing leaks), two half gates `{u},{y}↦{uy}` and
//!   `{v},{α}↦{vα}`, then `{xy} = {uy} ⊕ {vα} ⊕ {αβ}` locally. A selective abort by the
//!   garbler is now on the *random* `u`/`v`, hence simulatable — not an attack.
//!
//! # Honest boundary
//!
//! - **Follows the published construction** (David Heath's CS507 exposition of
//!   WRK17/KRRW18). **Correctness and the abort mechanism are what the tests establish**
//!   (evaluates circuits correctly; a corrupted garbled row aborts). The *formal*
//!   malicious-security theorem is the papers' proof and requires the **external audit**
//!   — it is **not** established by these correctness tests.
//! - The preprocessing triples come from [`wrk17`](super::wrk17)'s malicious `F_pre`
//!   (aBits over KOS + bucketing); here they are dealt honestly for the online tests.
//! - Both parties are modelled **in-process** (as the rest of the crate); a deployment
//!   sends the garbled rows `r` and the opens over the wire.

use neo_core::{Error, Result};

use super::circuit::{Circuit, Gate};

/// Security parameter / key length in bytes (λ = 128 bits).
pub const LAMBDA: usize = 16;

fn x16(a: [u8; LAMBDA], b: [u8; LAMBDA]) -> [u8; LAMBDA] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

fn rand16() -> Result<[u8; LAMBDA]> {
    let mut k = [0u8; LAMBDA];
    getrandom::getrandom(&mut k).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(k)
}

fn rand_bit() -> Result<bool> {
    Ok(rand16()?[0] & 1 == 1)
}

/// The random oracle `H : {0,1}^λ → {0,1}^{2λ+1}`, returned as a `(2λ+1)`-bit [`V`].
fn h(x: &[u8; LAMBDA]) -> V {
    let mut hh = blake3::Hasher::new_derive_key("neo-authgarble-H-v1");
    hh.update(x);
    let mut b = [0u8; 2 * LAMBDA + 1]; // 2λ+1 bytes via the XOF (finalize() is only 32)
    hh.finalize_xof().fill(&mut b);
    V {
        dg: core::array::from_fn(|i| b[i]),
        de: core::array::from_fn(|i| b[LAMBDA + i]),
        b: b[2 * LAMBDA] & 1 == 1,
    }
}

/// One party's share of the `(2λ+1)`-bit vector `x·(Δ_G, Δ_E, 1)`: the `Δ_G`-part
/// (`dg`), the `Δ_E`-part (`de`), and the value bit (`b`).
#[derive(Clone, Copy, Default, Debug)]
pub struct V {
    dg: [u8; LAMBDA],
    de: [u8; LAMBDA],
    b: bool,
}

impl V {
    fn xor(self, o: V) -> V {
        V {
            dg: x16(self.dg, o.dg),
            de: x16(self.de, o.de),
            b: self.b ^ o.b,
        }
    }
}

/// The two parties' global keys: `Δ_G` (garbler), `Δ_E` (evaluator).
#[derive(Clone, Copy)]
pub struct Deltas {
    g: [u8; LAMBDA],
    e: [u8; LAMBDA],
}

impl Deltas {
    pub fn random() -> Result<Self> {
        Ok(Deltas {
            g: rand16()?,
            e: rand16()?,
        })
    }
}

/// A doubly-authenticated shared bit `{x} = [x·(Δ_G, Δ_E, 1)]` (garbler share `g`,
/// evaluator share `e`), bundled in-process.
#[derive(Clone, Copy, Debug)]
pub struct AShare {
    g: V,
    e: V,
}

impl AShare {
    /// The cleartext value `x` (for tests/asserts, not a per-party op).
    pub fn value(&self) -> bool {
        self.g.b ^ self.e.b
    }

    /// `{x} ⊕ {y}`, fully local.
    pub fn xor(&self, o: &AShare) -> AShare {
        AShare {
            g: self.g.xor(o.g),
            e: self.e.xor(o.e),
        }
    }

    /// Deal a fresh valid `{x}` for a known `x` (dealer model — circuit inputs / tests;
    /// a real input-sharing opens a random `{α}` to the input party).
    pub fn deal(x: bool, d: &Deltas) -> Result<AShare> {
        let g = V {
            dg: rand16()?,
            de: rand16()?,
            b: rand_bit()?,
        };
        let e = V {
            dg: if x { x16(g.dg, d.g) } else { g.dg },
            de: if x { x16(g.de, d.e) } else { g.de },
            b: g.b ^ x,
        };
        Ok(AShare { g, e })
    }

    /// Open `{x}`, re-checking **both** MACs — the abort gate. The evaluator checks the
    /// garbler's `Δ_E`-MAC; the garbler checks the evaluator's `Δ_G`-MAC. Either failing
    /// (a corrupted / unauthenticated share) aborts.
    pub fn open(&self, d: &Deltas) -> Result<bool> {
        let x = self.g.b ^ self.e.b;
        let e_ok = self.g.de == if x { x16(self.e.de, d.e) } else { self.e.de };
        let g_ok = self.e.dg == if x { x16(self.g.dg, d.g) } else { self.g.dg };
        if !e_ok || !g_ok {
            return Err(Error::Crypto(
                "authgarble: MAC check failed on open (unauthenticated wire — abort)".into(),
            ));
        }
        Ok(x)
    }
}

/// An authenticated AND triple `{α},{β},{αβ}` with `αβ = α∧β`, from `F_pre`.
#[derive(Clone, Copy, Debug)]
pub struct Triple(pub AShare, pub AShare, pub AShare);

/// Garbler's side of the half gate `{x},{y} ↦ {xy}`: returns `(Z_G, r)`.
fn garble_half(x_share: &AShare, y_share: &AShare, d: &Deltas) -> (V, V) {
    let x_label = x_share.g.dg; // X
    let z_g = h(&x_label); // Z_G = H(X)
    let r = h(&x16(x_label, d.g)).xor(z_g).xor(y_share.g); // H(X⊕Δ_G) ⊕ H(X) ⊕ Y
    (z_g, r)
}

/// Evaluator's side of the half gate, given the garbled row `r` and the *known* `x`:
/// `Z_E = H(X_E) ⊕ (x ? (Y_E ⊕ r) : 0)`.
fn eval_half(x_share: &AShare, y_share: &AShare, x_known: bool, r: V) -> V {
    let z_e = h(&x_share.e.dg); // H(X_E)  (= H(X) when x=0)
    if x_known {
        z_e.xor(y_share.e).xor(r)
    } else {
        z_e
    }
}

/// AND gate `{x},{y} ↦ {xy}` using triple `t = {α},{β},{αβ}`. `corrupt` is a test hook
/// that may tamper a garbled row before the evaluator uses it (honest run: identity).
fn and_gate(
    x: &AShare,
    y: &AShare,
    t: &Triple,
    d: &Deltas,
    corrupt: &mut dyn FnMut(usize, V) -> V,
    gate_id: usize,
) -> Result<AShare> {
    let (alpha, beta, alpha_beta) = (&t.0, &t.1, &t.2);
    let u_share = x.xor(alpha); // {x⊕α}
    let v_share = y.xor(beta); // {y⊕β}
    let u = u_share.open(d)?; // E learns u = x⊕α (masked by α), MAC-checked
    let v = v_share.open(d)?;

    // Half gate 1: {u},{y} ↦ {uy}.
    let (uy_g, r1) = garble_half(&u_share, y, d);
    let r1 = corrupt(2 * gate_id, r1);
    let uy = AShare {
        g: uy_g,
        e: eval_half(&u_share, y, u, r1),
    };
    // Half gate 2: {v},{α} ↦ {vα}.
    let (va_g, r2) = garble_half(&v_share, alpha, d);
    let r2 = corrupt(2 * gate_id + 1, r2);
    let va = AShare {
        g: va_g,
        e: eval_half(&v_share, alpha, v, r2),
    };
    // {xy} = {uy} ⊕ {vα} ⊕ {αβ}.
    Ok(uy.xor(&va).xor(alpha_beta))
}

/// Evaluate `circuit` under authenticated garbling: `inputs[i]` is `{wireᵢ}`, `triples`
/// supplies one `{α},{β},{αβ}` per AND gate. XOR/NOT are local; each AND is one
/// [`and_gate`]; outputs are MAC-checked-opened. Aborts on any tamper.
pub fn eval_garbled(
    circuit: &Circuit,
    inputs: &[AShare],
    triples: &[Triple],
    d: &Deltas,
) -> Result<Vec<bool>> {
    eval_garbled_inner(circuit, inputs, triples, d, &mut |_, r| r)
}

fn eval_garbled_inner(
    circuit: &Circuit,
    inputs: &[AShare],
    triples: &[Triple],
    d: &Deltas,
    corrupt: &mut dyn FnMut(usize, V) -> V,
) -> Result<Vec<bool>> {
    if inputs.len() != circuit.input_bits {
        return Err(Error::Crypto("authgarble: wrong input width".into()));
    }
    if triples.len() < circuit.and_gates() {
        return Err(Error::Crypto("authgarble: not enough triples".into()));
    }
    // A public constant `{c}` (both shares zero ⇒ value 0); NOT flips it via ⊕ Δ on one
    // party. We realise NOT as {x}⊕{1}; build {1} = deal-free constant.
    let one = const_share(true, d);
    let mut w: Vec<Option<AShare>> = vec![None; circuit.num_wires];
    for (i, s) in inputs.iter().enumerate() {
        w[i] = Some(*s);
    }
    let get = |w: &Vec<Option<AShare>>, i: usize| -> Result<AShare> {
        w[i].ok_or_else(|| Error::Crypto("authgarble: wire used before set".into()))
    };
    let mut tix = 0;
    for gate in &circuit.gates {
        match *gate {
            Gate::Xor(a, b, o) => w[o] = Some(get(&w, a)?.xor(&get(&w, b)?)),
            Gate::Inv(a, o) => w[o] = Some(get(&w, a)?.xor(&one)),
            Gate::And(a, b, o) => {
                let s = and_gate(&get(&w, a)?, &get(&w, b)?, &triples[tix], d, corrupt, tix)?;
                tix += 1;
                w[o] = Some(s);
            }
        }
    }
    circuit
        .outputs
        .iter()
        .map(|&o| get(&w, o)?.open(d))
        .collect()
}

/// A public constant `{c}` with a valid authentication (`g ⊕ e = c·(Δ_G,Δ_E,1)`), used
/// for NOT and constants. Deterministic (no secrecy needed): garbler share zero,
/// evaluator share `c·(Δ_G,Δ_E,1)`.
fn const_share(c: bool, d: &Deltas) -> AShare {
    let g = V::default();
    let e = V {
        dg: if c { d.g } else { [0u8; LAMBDA] },
        de: if c { d.e } else { [0u8; LAMBDA] },
        b: c,
    };
    AShare { g, e }
}

fn rand_v() -> Result<V> {
    Ok(V {
        dg: rand16()?,
        de: rand16()?,
        b: rand_bit()?,
    })
}

/// WRK17/KRRW18 **leaky AND triple** — the malicious `F_pre` step. From random
/// authenticated bits `{α_A}` (A's half), `{α_B}` (B's half), and `{β}`, produce a
/// triple `{α}, {β}, {αβ}` with `α = α_A ⊕ α_B`, using `{αβ} = {α_A·β} ⊕ {α_B·β}`.
/// Each half is a garbled-row trick: for `{α_B·β}`, A (holding the label `X = {α_B}`'s
/// `Δ_A`-share) picks random `Z` and sends `r0 = H(X)⊕Z`, `r1 = H(X⊕Δ_A)⊕Y⊕Z`
/// (`Y = {β}`'s A-share); B, knowing `α_B`, opens the row for its key and gets
/// `Z ⊕ α_B·β·(Δ_A,Δ_B,1)`. `{α_A·β}` is symmetric (B garbles over `Δ_B`).
///
/// The triple is **correct**; its residual leakage (a garbler corrupting a row learns
/// `α` with prob ≤ ½, else the honest party aborts) is removed by
/// [`bucketed_and_triples`]. `β` never leaks.
pub fn leaky_and(alpha_a: &AShare, alpha_b: &AShare, beta: &AShare, d: &Deltas) -> Result<Triple> {
    // {α_B·β}: A garbles with the Δ_A-key of {α_B}; B evaluates knowing α_B.
    let x = alpha_b.g.dg; // label X (A's Δ_A-share of α_B)
    let z = rand_v()?; // A's random output share
    let r0 = h(&x).xor(z);
    let r1 = h(&x16(x, d.g)).xor(beta.g).xor(z); // H(X⊕Δ_A) ⊕ Y ⊕ Z
    let b_key = alpha_b.e.dg; // B's key = X ⊕ α_B·Δ_A
    let ab_beta = AShare {
        g: z,
        e: if alpha_b.value() {
            r1.xor(h(&b_key)).xor(beta.e)
        } else {
            r0.xor(h(&b_key))
        },
    };

    // {α_A·β}: B garbles with the Δ_B-key of {α_A}; A evaluates knowing α_A.
    let xp = alpha_a.e.de; // label X' (B's Δ_B-share of α_A)
    let zp = rand_v()?; // B's random output share
    let r0p = h(&xp).xor(zp);
    let r1p = h(&x16(xp, d.e)).xor(beta.e).xor(zp); // H(X'⊕Δ_B) ⊕ Y' ⊕ Z'
    let a_key = alpha_a.g.de; // A's key = X' ⊕ α_A·Δ_B
    let aa_beta = AShare {
        g: if alpha_a.value() {
            r1p.xor(h(&a_key)).xor(beta.g)
        } else {
            r0p.xor(h(&a_key))
        },
        e: zp,
    };

    Ok(Triple(
        alpha_a.xor(alpha_b),  // {α}
        *beta,                 // {β}
        ab_beta.xor(&aa_beta), // {αβ}
    ))
}

/// WRK17 bucket **combine** of two triples `t0={α⁰,β⁰,α⁰β⁰}`, `t1={α¹,β¹,α¹β¹}` into
/// `{α⁰⊕α¹, β⁰, (α⁰⊕α¹)β⁰}` — halving the corruption probability. Opens `β = β⁰⊕β¹`
/// (MAC-checked; hidden by the random `β¹` one-time pad), then a local combination.
pub fn combine(t0: &Triple, t1: &Triple, d: &Deltas) -> Result<Triple> {
    let beta = t0.1.xor(&t1.1).open(d)?; // β = β⁰ ⊕ β¹
    let mut z = t0.2.xor(&t1.2); // α⁰β⁰ ⊕ α¹β¹
    if beta {
        z = z.xor(&t1.0); // ⊕ β·{α¹}
    }
    Ok(Triple(t0.0.xor(&t1.0), t0.1, z)) // {α}, {β⁰}, {αβ⁰}
}

/// A fresh dealer-model leaky-AND triple over random authenticated bits.
fn fresh_triple(d: &Deltas) -> Result<Triple> {
    let alpha_a = AShare::deal(rand_bit()?, d)?;
    let alpha_b = AShare::deal(rand_bit()?, d)?;
    let beta = AShare::deal(rand_bit()?, d)?;
    leaky_and(&alpha_a, &alpha_b, &beta, d)
}

/// **Sacrifice check** (WRK17): validate that triple `t` satisfies `αβ = α∧β` by
/// Beaver-multiplying with an independent honest triple `aux` and MAC-checked-opening
/// `⟨c⟩ ⊕ ⟨a∧b⟩` to 0. A maliciously biased product share `c` — one that stayed
/// MAC-consistent, so a plain `open` wouldn't flag it — is caught here and aborts.
/// `aux` is consumed (sacrificed); its `â, b̂` one-time-pad the opened `d, e`, so the
/// check reveals nothing about `t`. Mirrors [`wrk17::verify_triple`](super::wrk17) for
/// this module's share type (the conditional XORs realise `⟨x⟩ · public_bit`).
pub fn verify_triple(t: &Triple, aux: &Triple, d: &Deltas) -> Result<()> {
    let dd = t.0.xor(&aux.0).open(d)?; // a ⊕ â
    let ee = t.1.xor(&aux.1).open(d)?; // b ⊕ b̂
    let mut cp = aux.2; // ⟨â∧b̂⟩
    if dd {
        cp = cp.xor(&aux.1); // ⊕ d·⟨b̂⟩
    }
    if ee {
        cp = cp.xor(&aux.0); // ⊕ e·⟨â⟩
    }
    if dd & ee {
        cp = cp.xor(&const_share(true, d)); // ⊕ d·e (public constant)
    }
    if t.2.xor(&cp).open(d)? {
        return Err(Error::Crypto(
            "authgarble: triple failed the sacrifice check (abort)".into(),
        ));
    }
    Ok(())
}

/// Generate `n` malicious-secure AND triples: `n·bucket` [`leaky_and`] triples over
/// fresh random authenticated bits, a public random shuffle, fold each bucket of
/// `bucket` with [`combine`] (corruption prob ≤ `2^{-bucket}`), then **sacrifice-check**
/// each folded triple with [`verify_triple`] against a fresh independent triple.
/// Bucketing removes *leakage*; the sacrifice removes *incorrectness* (a biased raw row
/// whose `c` stayed MAC-consistent, which would otherwise silently flip a gate) — the two
/// together give malicious correctness *and* security, not just leakage removal. The
/// random bits are dealt here (dealer model); a deployment draws them from the aBit
/// generation over [`kos`](super::kos) and the networked sacrifice in
/// [`netprep`](super::netprep).
pub fn bucketed_and_triples(n: usize, bucket: usize, d: &Deltas) -> Result<Vec<Triple>> {
    assert!(bucket >= 1, "bucket size must be ≥ 1");
    let mut leaky = Vec::with_capacity(n * bucket);
    for _ in 0..n * bucket {
        leaky.push(fresh_triple(d)?);
    }
    shuffle(&mut leaky)?;
    let mut out = Vec::with_capacity(n);
    for chunk in leaky.chunks(bucket) {
        let mut acc = chunk[0];
        for t in &chunk[1..] {
            acc = combine(&acc, t, d)?;
        }
        // Remove residual incorrectness: a corrupted raw row yields αβ ≠ α∧β that is
        // MAC-consistent (so `open` wouldn't flag it) yet silently flips a gate. The
        // sacrifice against a fresh independent triple catches it and aborts.
        let aux = fresh_triple(d)?;
        verify_triple(&acc, &aux, d)?;
        out.push(acc);
    }
    Ok(out)
}

fn shuffle<T>(items: &mut [T]) -> Result<()> {
    for i in (1..items.len()).rev() {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).map_err(|e| Error::Rng(e.to_string()))?;
        let j = (u64::from_le_bytes(buf) % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc_tls::circuit::Builder;
    use crate::mpc_tls::sha256::sha256_compress_circuit;

    fn deal_triple(a: bool, b: bool, d: &Deltas) -> Triple {
        Triple(
            AShare::deal(a, d).unwrap(),
            AShare::deal(b, d).unwrap(),
            AShare::deal(a & b, d).unwrap(),
        )
    }

    #[test]
    fn sacrifice_catches_a_corrupted_product_share() {
        let d = Deltas::random().unwrap();
        // An honest triple passes the sacrifice check.
        let good = fresh_triple(&d).unwrap();
        assert!(
            verify_triple(&good, &fresh_triple(&d).unwrap(), &d).is_ok(),
            "an honest triple passes"
        );
        // Bias the product share's value while keeping it authenticated (⊕ the public
        // constant {1}). `open` alone can't see this, but the sacrifice must.
        let bad = Triple(good.0, good.1, good.2.xor(&const_share(true, &d)));
        assert!(
            verify_triple(&bad, &fresh_triple(&d).unwrap(), &d).is_err(),
            "a biased product share must fail the sacrifice check (abort)"
        );
        // The generator now sacrifices every output, so it still yields correct triples.
        assert_eq!(bucketed_and_triples(4, 3, &d).unwrap().len(), 4);
    }

    fn adder4() -> Circuit {
        let mut bld = Builder::new(8);
        let mut carry = bld.zero();
        let mut out = Vec::new();
        for i in 0..4 {
            let (sum, c) = bld.full_adder(i, 4 + i, carry);
            out.push(sum);
            carry = c;
        }
        out.push(carry);
        bld.build(8, out)
    }

    #[test]
    fn ashare_algebra_and_open() {
        let d = Deltas::random().unwrap();
        for (x, y) in [(false, false), (false, true), (true, false), (true, true)] {
            let sx = AShare::deal(x, &d).unwrap();
            let sy = AShare::deal(y, &d).unwrap();
            assert_eq!(sx.open(&d).unwrap(), x, "open recovers x");
            assert_eq!(sx.xor(&sy).open(&d).unwrap(), x ^ y, "XOR is correct");
        }
        // A tampered evaluator share must abort on open.
        let mut s = AShare::deal(true, &d).unwrap();
        s.e.de[0] ^= 1;
        assert!(s.open(&d).is_err(), "corrupting a MAC aborts");
    }

    #[test]
    fn authenticated_and_gate_is_correct_for_all_inputs() {
        let d = Deltas::random().unwrap();
        for x in [false, true] {
            for y in [false, true] {
                // Random triple values (cover both u,v branches).
                for (a, b) in [(false, false), (true, false), (false, true), (true, true)] {
                    let t = deal_triple(a, b, &d);
                    let sx = AShare::deal(x, &d).unwrap();
                    let sy = AShare::deal(y, &d).unwrap();
                    let z = and_gate(&sx, &sy, &t, &d, &mut |_, r| r, 0).unwrap();
                    assert_eq!(z.open(&d).unwrap(), x & y, "AND({x},{y}) with α={a},β={b}");
                }
            }
        }
    }

    #[test]
    fn evaluate_adder_under_authenticated_garbling() {
        let d = Deltas::random().unwrap();
        let circuit = adder4();
        for (x, y) in [(0u8, 0u8), (7, 9), (5, 5), (15, 15), (10, 6)] {
            let bits: Vec<bool> = (0..4)
                .map(|i| (x >> i) & 1 == 1)
                .chain((0..4).map(|i| (y >> i) & 1 == 1))
                .collect();
            let inputs: Vec<AShare> = bits.iter().map(|&v| AShare::deal(v, &d).unwrap()).collect();
            let triples: Vec<Triple> = (0..circuit.and_gates())
                .map(|_| deal_triple(rand_bit().unwrap(), rand_bit().unwrap(), &d))
                .collect();
            let out = eval_garbled(&circuit, &inputs, &triples, &d).unwrap();
            assert_eq!(
                out,
                circuit.eval(&bits),
                "authenticated garbling matches plaintext circuit"
            );
            let got: u8 = (0..5).filter(|&i| out[i]).map(|i| 1u8 << i).sum();
            assert_eq!(got, x + y, "4-bit adder {x}+{y}");
        }
    }

    #[test]
    fn a_corrupted_garbled_row_aborts() {
        // Single AND gate with x=y=1 and triple α=β=0 ⇒ u=v=1, so both half-gate rows
        // are actually used by the evaluator. Corrupting r1 makes E's output share
        // unauthenticated ⇒ the output open aborts. (With α random the garbler cannot
        // target u=1; here we fix it to exercise detection deterministically.)
        let d = Deltas::random().unwrap();
        let mut bld = Builder::new(2);
        let o = bld.and(0, 1);
        let circuit = bld.build(2, vec![o]);
        let inputs = vec![
            AShare::deal(true, &d).unwrap(),
            AShare::deal(true, &d).unwrap(),
        ];
        let triples = vec![deal_triple(false, false, &d)];
        // Honest run first: correct.
        assert_eq!(
            eval_garbled(&circuit, &inputs, &triples, &d).unwrap(),
            vec![true],
            "honest AND(1,1) = 1"
        );
        // Corrupt the first half-gate row (index 0): flip a bit of r1.
        let res = eval_garbled_inner(&circuit, &inputs, &triples, &d, &mut |idx, mut r| {
            if idx == 0 {
                r.dg[0] ^= 1;
            }
            r
        });
        assert!(
            res.is_err(),
            "a corrupted garbled row must abort the evaluation"
        );
    }

    #[test]
    fn leaky_and_produces_correct_triples() {
        // The malicious F_pre leaky-AND: for random α_A, α_B, β, the triple satisfies
        // α = α_A⊕α_B, and αβ = α∧β, and every share opens (MACs valid).
        let d = Deltas::random().unwrap();
        for aa in [false, true] {
            for ab in [false, true] {
                for bv in [false, true] {
                    let alpha_a = AShare::deal(aa, &d).unwrap();
                    let alpha_b = AShare::deal(ab, &d).unwrap();
                    let beta = AShare::deal(bv, &d).unwrap();
                    let t = leaky_and(&alpha_a, &alpha_b, &beta, &d).unwrap();
                    let (a, b, c) = (
                        t.0.open(&d).unwrap(),
                        t.1.open(&d).unwrap(),
                        t.2.open(&d).unwrap(),
                    );
                    assert_eq!(a, aa ^ ab, "α = α_A ⊕ α_B");
                    assert_eq!(b, bv, "β preserved");
                    assert_eq!(c, a & b, "leaky-AND triple is a correct AND");
                }
            }
        }
    }

    #[test]
    fn combine_yields_a_correct_triple() {
        let d = Deltas::random().unwrap();
        for a0 in [false, true] {
            for b0 in [false, true] {
                for a1 in [false, true] {
                    for b1 in [false, true] {
                        let t = combine(&deal_triple(a0, b0, &d), &deal_triple(a1, b1, &d), &d)
                            .unwrap();
                        let (a, b, c) = (
                            t.0.open(&d).unwrap(),
                            t.1.open(&d).unwrap(),
                            t.2.open(&d).unwrap(),
                        );
                        assert_eq!(a, a0 ^ a1, "combined α = α⁰⊕α¹");
                        assert_eq!(b, b0, "combined β = β⁰");
                        assert_eq!(c, a & b, "combined triple is a correct AND");
                    }
                }
            }
        }
    }

    #[test]
    fn bucketing_yields_correct_triples() {
        let d = Deltas::random().unwrap();
        for bucket in [1usize, 2, 3] {
            for t in bucketed_and_triples(4, bucket, &d).unwrap() {
                let (a, b, c) = (
                    t.0.open(&d).unwrap(),
                    t.1.open(&d).unwrap(),
                    t.2.open(&d).unwrap(),
                );
                assert_eq!(
                    c,
                    a & b,
                    "bucketed triple (bucket={bucket}) is a correct AND"
                );
            }
        }
    }

    #[test]
    fn malicious_fpre_feeds_authenticated_garbling_end_to_end() {
        // The complete malicious 2PC online: triples produced by the leaky-AND + bucketing
        // malicious F_pre drive the authenticated-garbling evaluation of a real circuit.
        let d = Deltas::random().unwrap();
        let circuit = adder4();
        for (x, y) in [(0u8, 0u8), (9, 6), (15, 15), (11, 4)] {
            let bits: Vec<bool> = (0..4)
                .map(|i| (x >> i) & 1 == 1)
                .chain((0..4).map(|i| (y >> i) & 1 == 1))
                .collect();
            let inputs: Vec<AShare> = bits.iter().map(|&v| AShare::deal(v, &d).unwrap()).collect();
            let triples = bucketed_and_triples(circuit.and_gates(), 2, &d).unwrap();
            let out = eval_garbled(&circuit, &inputs, &triples, &d).unwrap();
            let got: u8 = (0..5).filter(|&i| out[i]).map(|i| 1u8 << i).sum();
            assert_eq!(
                got,
                x + y,
                "F_pre (leaky-AND+bucketing) → authenticated garbling: {x}+{y}"
            );
        }
    }

    #[test]
    fn real_tls_key_schedule_circuit_under_authenticated_garbling() {
        // The malicious online on a REAL TLS key-schedule circuit — the full SHA-256
        // compression function (tens of thousands of AND gates), not a toy adder:
        // authenticated garbling evaluates it correctly against the plaintext oracle,
        // and a tampered wire aborts. This is the malicious 2PC online applied to the
        // actual circuit the key schedule runs, closing the "authgarble only tested on
        // an adder" gap.
        let d = Deltas::random().unwrap();
        let circuit = sha256_compress_circuit();
        let n = circuit.and_gates();
        assert!(
            n > 10_000,
            "sanity: SHA-256 compression is a large circuit ({n} ANDs)"
        );

        // A fixed pseudo-random input over all input wires (h_in ‖ block); only that the
        // garbled result equals the plaintext circuit matters.
        let bits: Vec<bool> = (0..circuit.input_bits)
            .map(|i| i.wrapping_mul(2_654_435_761) & 1 == 1)
            .collect();
        let inputs: Vec<AShare> = bits.iter().map(|&v| AShare::deal(v, &d).unwrap()).collect();
        let triples: Vec<Triple> = (0..n)
            .map(|_| deal_triple(rand_bit().unwrap(), rand_bit().unwrap(), &d))
            .collect();

        let out = eval_garbled(&circuit, &inputs, &triples, &d).unwrap();
        assert_eq!(
            out,
            circuit.eval(&bits),
            "authenticated garbling matches the plaintext SHA-256 compression ({n} ANDs)"
        );

        // A single tampered input-share MAC aborts a MAC-checked open during evaluation.
        let mut bad = inputs.clone();
        bad[0].e.dg[0] ^= 1;
        assert!(
            eval_garbled(&circuit, &bad, &triples, &d).is_err(),
            "a tampered wire must abort the real-circuit evaluation"
        );
    }
}
