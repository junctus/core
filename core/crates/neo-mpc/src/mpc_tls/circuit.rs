//! Boolean circuits for 2PC: a tiny representation, a builder, a plaintext
//! evaluator (the correctness oracle), and the gadgets TLS needs — a ripple-carry
//! **32-bit adder** (the only non-linear part of ChaCha) and, in
//! [`chacha20_block`], the full **ChaCha20** block function as a circuit.
//!
//! Wires are indices. Inputs occupy `[0, input_bits)`; every gate allocates one
//! fresh output wire, so gate order is already topological. XOR and NOT are
//! "free" under free-XOR garbling; AND is the only gate that costs ciphertexts,
//! which is why the adder (its carry chain) is the thing we count.

use std::sync::OnceLock;

/// A boolean gate over wire indices.
#[derive(Clone, Copy, Debug)]
pub enum Gate {
    /// `out = a ⊕ b`
    Xor(usize, usize, usize),
    /// `out = a ∧ b`
    And(usize, usize, usize),
    /// `out = ¬a`
    Inv(usize, usize),
}

/// A boolean circuit: inputs, topologically-ordered gates, and output wires.
#[derive(Clone, Debug)]
pub struct Circuit {
    /// Total wires (inputs + one per gate).
    pub num_wires: usize,
    /// Input wires are `[0, input_bits)`.
    pub input_bits: usize,
    /// Gates in evaluation order.
    pub gates: Vec<Gate>,
    /// Output wire indices, in output-bit order.
    pub outputs: Vec<usize>,
}

impl Circuit {
    /// Count of AND gates (the only ones that garble to ciphertext).
    pub fn and_gates(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| matches!(g, Gate::And(..)))
            .count()
    }

    /// Plaintext evaluation — the correctness oracle the garbled version is
    /// checked against. `inputs` are the `input_bits` input wire values.
    pub fn eval(&self, inputs: &[bool]) -> Vec<bool> {
        assert_eq!(inputs.len(), self.input_bits, "wrong input width");
        let mut w = vec![false; self.num_wires];
        w[..self.input_bits].copy_from_slice(inputs);
        for gate in &self.gates {
            match *gate {
                Gate::Xor(a, b, o) => w[o] = w[a] ^ w[b],
                Gate::And(a, b, o) => w[o] = w[a] & w[b],
                Gate::Inv(a, o) => w[o] = !w[a],
            }
        }
        self.outputs.iter().map(|&o| w[o]).collect()
    }
}

/// Incrementally builds a circuit, allocating a fresh wire per gate.
pub struct Builder {
    gates: Vec<Gate>,
    num_wires: usize,
    zero: Option<usize>,
    one: Option<usize>,
}

impl Builder {
    /// Start a builder with `inputs` input wires (`[0, inputs)`).
    pub fn new(inputs: usize) -> Self {
        Self {
            gates: Vec::new(),
            num_wires: inputs,
            zero: None,
            one: None,
        }
    }

    fn fresh(&mut self) -> usize {
        let w = self.num_wires;
        self.num_wires += 1;
        w
    }

    /// `a ⊕ b`
    pub fn xor(&mut self, a: usize, b: usize) -> usize {
        let o = self.fresh();
        self.gates.push(Gate::Xor(a, b, o));
        o
    }

    /// `a ∧ b`
    pub fn and(&mut self, a: usize, b: usize) -> usize {
        let o = self.fresh();
        self.gates.push(Gate::And(a, b, o));
        o
    }

    /// `¬a`
    pub fn inv(&mut self, a: usize) -> usize {
        let o = self.fresh();
        self.gates.push(Gate::Inv(a, o));
        o
    }

    /// `a ∨ b = ¬(¬a ∧ ¬b)`
    pub fn or(&mut self, a: usize, b: usize) -> usize {
        let na = self.inv(a);
        let nb = self.inv(b);
        let nor = self.and(na, nb);
        self.inv(nor)
    }

    /// A constant-false wire (built once as `w ⊕ w` on input 0).
    pub fn zero(&mut self) -> usize {
        if let Some(z) = self.zero {
            return z;
        }
        let z = self.xor(0, 0);
        self.zero = Some(z);
        z
    }

    /// A constant-true wire (`¬0`).
    pub fn one(&mut self) -> usize {
        if let Some(o) = self.one {
            return o;
        }
        let z = self.zero();
        let o = self.inv(z);
        self.one = Some(o);
        o
    }

    /// A 32-bit constant as a little-endian wire vector (each bit a shared 0/1 wire).
    pub fn word_const(&mut self, val: u32) -> Vec<usize> {
        let z = self.zero();
        let o = self.one();
        (0..32)
            .map(|i| if (val >> i) & 1 == 1 { o } else { z })
            .collect()
    }

    /// Finalize into a [`Circuit`] with the given input width and output wires.
    pub fn build(self, inputs: usize, outputs: Vec<usize>) -> Circuit {
        Circuit {
            num_wires: self.num_wires,
            input_bits: inputs,
            gates: self.gates,
            outputs,
        }
    }

    /// One full adder: returns `(sum, carry_out)` for `a + b + cin`, using the
    /// **AND-optimal 1-gate carry** — the dominant cost in a garbled circuit is AND gates
    /// (XOR is free), so this halves-and-thirds the SHA-256/ChaCha adder cost vs the naive
    /// 3-AND `(a∧b) ∨ (cin ∧ (a⊕b))` form.
    /// `sum = a ⊕ b ⊕ cin`; `cout = a ⊕ ((a⊕b) ∧ (a⊕cin))` = majority(a,b,cin)
    /// (a=0 ⇒ b∧cin; a=1 ⇒ b∨cin) — **one AND gate**.
    pub fn full_adder(&mut self, a: usize, b: usize, cin: usize) -> (usize, usize) {
        let axb = self.xor(a, b);
        let sum = self.xor(axb, cin);
        let axc = self.xor(a, cin);
        let t = self.and(axb, axc);
        let cout = self.xor(a, t);
        (sum, cout)
    }

    /// Ripple-carry add of two little-endian `n`-bit numbers (wires
    /// least-significant-first). Returns `n` sum wires (carry out discarded, i.e.
    /// addition mod `2^n` — exactly ChaCha's 32-bit wrapping add).
    pub fn add_mod(&mut self, a: &[usize], b: &[usize]) -> Vec<usize> {
        assert_eq!(a.len(), b.len());
        let mut carry = self.zero();
        let mut out = Vec::with_capacity(a.len());
        for i in 0..a.len() {
            let (s, c) = self.full_adder(a[i], b[i], carry);
            out.push(s);
            carry = c;
        }
        out
    }
}

/// The ChaCha20 constants ("expand 32-byte k").
const CHACHA_CONST: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The **ChaCha20 block function** as a boolean circuit (RFC 8439 §2.3).
///
/// Input wires (`384`), little-endian bits: `key[256] ‖ counter[32] ‖ nonce[96]`,
/// each 32-bit word LSB-first. Output wires (`512`): the 16 keystream words,
/// word 0 first, each LSB-first — serialize each word little-endian for the
/// 64-byte keystream block. The only non-linear gates are the adders' carry
/// chains; everything else is XOR (free) and rotation (wiring).
pub fn chacha20_block() -> Circuit {
    let mut b = Builder::new(384);
    let key: Vec<usize> = (0..256).collect();
    let counter: Vec<usize> = (256..288).collect();
    let nonce: Vec<usize> = (288..384).collect();
    let outputs = chacha_core(&mut b, &key, &counter, &nonce);
    b.build(384, outputs)
}

/// The **2PC variant** of [`chacha20_block`]. Inputs (`1152`): `keyA[256] ‖
/// keyB[256] ‖ counter[32] ‖ nonce[96] ‖ maskA[512]`. The circuit forms the key
/// as `keyA ⊕ keyB` (so neither party inputs the whole key) and outputs the
/// keystream **XOR-masked** by `maskA` (so the party that decodes learns only
/// `KS ⊕ maskA`, and the party holding `maskA` learns only `maskA` — neither
/// learns the keystream). Output wires (`512`): `KS ⊕ maskA`.
pub fn chacha20_block_2pc() -> &'static Circuit {
    static CIRCUIT: OnceLock<Circuit> = OnceLock::new();
    CIRCUIT.get_or_init(build_chacha20_block_2pc)
}

fn build_chacha20_block_2pc() -> Circuit {
    let mut b = Builder::new(1152);
    // key = keyA ⊕ keyB
    let key: Vec<usize> = (0..256).map(|i| b.xor(i, 256 + i)).collect();
    let counter: Vec<usize> = (512..544).collect();
    let nonce: Vec<usize> = (544..640).collect();
    let raw = chacha_core(&mut b, &key, &counter, &nonce);
    // output = KS ⊕ maskA
    let outputs: Vec<usize> = (0..512).map(|j| b.xor(raw[j], 640 + j)).collect();
    b.build(1152, outputs)
}

/// The ChaCha20 block over caller-supplied wire vectors (256-bit key, 32-bit
/// counter, 96-bit nonce), returning the 512 raw keystream wires.
fn chacha_core(b: &mut Builder, key: &[usize], counter: &[usize], nonce: &[usize]) -> Vec<usize> {
    let mut state: Vec<Vec<usize>> = Vec::with_capacity(16);
    for &c in &CHACHA_CONST {
        state.push(b.word_const(c)); // words 0..3
    }
    for k in 0..8 {
        state.push(key[k * 32..k * 32 + 32].to_vec()); // key words 4..11
    }
    state.push(counter.to_vec()); // word 12
    for k in 0..3 {
        state.push(nonce[k * 32..k * 32 + 32].to_vec()); // nonce words 13..15
    }

    let mut w = state.clone();
    for _ in 0..10 {
        quarter(b, &mut w, 0, 4, 8, 12);
        quarter(b, &mut w, 1, 5, 9, 13);
        quarter(b, &mut w, 2, 6, 10, 14);
        quarter(b, &mut w, 3, 7, 11, 15);
        quarter(b, &mut w, 0, 5, 10, 15);
        quarter(b, &mut w, 1, 6, 11, 12);
        quarter(b, &mut w, 2, 7, 8, 13);
        quarter(b, &mut w, 3, 4, 9, 14);
    }

    let mut outputs = Vec::with_capacity(512);
    for i in 0..16 {
        outputs.extend(b.add_mod(&w[i], &state[i])); // working + original state
    }
    outputs
}

fn xor_word(b: &mut Builder, x: &[usize], y: &[usize]) -> Vec<usize> {
    (0..32).map(|i| b.xor(x[i], y[i])).collect()
}

/// Rotate a 32-bit little-endian wire vector left by `n` (pure wiring).
fn rotl(w: &[usize], n: usize) -> Vec<usize> {
    (0..32).map(|j| w[(j + 32 - n) % 32]).collect()
}

fn quarter(b: &mut Builder, s: &mut [Vec<usize>], ia: usize, ib: usize, ic: usize, id: usize) {
    s[ia] = b.add_mod(&s[ia], &s[ib]);
    s[id] = xor_word(b, &s[id], &s[ia]);
    s[id] = rotl(&s[id], 16);
    s[ic] = b.add_mod(&s[ic], &s[id]);
    s[ib] = xor_word(b, &s[ib], &s[ic]);
    s[ib] = rotl(&s[ib], 12);
    s[ia] = b.add_mod(&s[ia], &s[ib]);
    s[id] = xor_word(b, &s[id], &s[ia]);
    s[id] = rotl(&s[id], 8);
    s[ic] = b.add_mod(&s[ic], &s[id]);
    s[ib] = xor_word(b, &s[ib], &s[ic]);
    s[ib] = rotl(&s[ib], 7);
}

/// Build the 384 input bits for [`chacha20_block`] from a key/counter/nonce.
pub fn chacha20_inputs(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(384);
    for k in 0..8 {
        let word = u32::from_le_bytes(key[k * 4..k * 4 + 4].try_into().expect("4 bytes"));
        push_word(&mut bits, word);
    }
    push_word(&mut bits, counter);
    for k in 0..3 {
        let word = u32::from_le_bytes(nonce[k * 4..k * 4 + 4].try_into().expect("4 bytes"));
        push_word(&mut bits, word);
    }
    bits
}

/// Serialize [`chacha20_block`]'s 512 output bits into the 64-byte keystream.
pub fn chacha20_output_bytes(bits: &[bool]) -> [u8; 64] {
    assert_eq!(bits.len(), 512);
    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = bits[i * 32..i * 32 + 32]
            .iter()
            .enumerate()
            .fold(0u32, |acc, (j, &b)| acc | ((b as u32) << j));
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn push_word(bits: &mut Vec<bool>, word: u32) {
    for j in 0..32 {
        bits.push((word >> j) & 1 == 1);
    }
}

/// Plaintext ChaCha20 block — the oracle the circuit is checked against.
pub fn chacha20_block_ref(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&CHACHA_CONST);
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    let mut w = state;
    for _ in 0..10 {
        qr(&mut w, 0, 4, 8, 12);
        qr(&mut w, 1, 5, 9, 13);
        qr(&mut w, 2, 6, 10, 14);
        qr(&mut w, 3, 7, 11, 15);
        qr(&mut w, 0, 5, 10, 15);
        qr(&mut w, 1, 6, 11, 12);
        qr(&mut w, 2, 7, 8, 13);
        qr(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&w[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits_le(mut v: u32, n: usize) -> Vec<bool> {
        (0..n)
            .map(|_| {
                let b = v & 1 == 1;
                v >>= 1;
                b
            })
            .collect()
    }

    fn from_bits_le(bits: &[bool]) -> u32 {
        bits.iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | ((b as u32) << i))
    }

    #[test]
    fn add_mod_matches_wrapping_u32() {
        // 32-bit adder: build once, check against native wrapping add on samples.
        let mut b = Builder::new(64);
        let a_wires: Vec<usize> = (0..32).collect();
        let b_wires: Vec<usize> = (32..64).collect();
        let sum = b.add_mod(&a_wires, &b_wires);
        let circuit = b.build(64, sum);

        for (x, y) in [
            (0u32, 0u32),
            (1, 1),
            (0xffff_ffff, 1),
            (0x1234_5678, 0x8765_4321),
            (0xdead_beef, 0xfeed_face),
        ] {
            let mut inputs = bits_le(x, 32);
            inputs.extend(bits_le(y, 32));
            let out = from_bits_le(&circuit.eval(&inputs));
            assert_eq!(out, x.wrapping_add(y), "add {x:#x}+{y:#x}");
        }
    }

    #[test]
    fn constants_and_or_are_correct() {
        let mut b = Builder::new(2);
        let z = b.zero();
        let o = b.one();
        let orv = b.or(0, 1);
        let circuit = b.build(2, vec![z, o, orv]);
        for (x, y) in [(false, false), (false, true), (true, false), (true, true)] {
            let out = circuit.eval(&[x, y]);
            assert!(!out[0], "zero");
            assert!(out[1], "one");
            assert_eq!(out[2], x | y, "or");
        }
    }

    #[test]
    fn chacha_reference_matches_rfc8439_kat() {
        // RFC 8439 §2.3.2 known-answer test — anchors the plaintext oracle.
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        // byte 24 is 0x04 (RFC gutter renders it non-printable, not 'B'=0x42).
        assert_eq!(chacha20_block_ref(&key, 1, &nonce), expected);
    }

    #[test]
    fn chacha_circuit_matches_reference() {
        let circuit = chacha20_block();
        assert_eq!(circuit.input_bits, 384);
        assert_eq!(circuit.outputs.len(), 512);
        let cases: [([u8; 32], u32, [u8; 12]); 2] = [
            (
                core::array::from_fn(|i| i as u8),
                1,
                [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0],
            ),
            (
                core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3)),
                0xdead_beef,
                core::array::from_fn(|i| (i as u8) ^ 0xa5),
            ),
        ];
        for (key, ctr, nonce) in cases {
            let inputs = chacha20_inputs(&key, ctr, &nonce);
            let out = chacha20_output_bytes(&circuit.eval(&inputs));
            assert_eq!(
                out,
                chacha20_block_ref(&key, ctr, &nonce),
                "circuit == reference"
            );
        }
    }
}
