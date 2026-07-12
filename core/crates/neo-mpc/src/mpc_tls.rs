//! **Full two-party MPC-TLS core** (M24) — computing a TLS session under 2PC so
//! the session key and record plaintext are **never assembled at a single party**.
//!
//! [`threshold`](crate::threshold) removed the single point of assembly for a
//! *committee decrypt*. This module goes to the real thing: the classic 2PC-TLS
//! construction (DECO / TLSNotary / `mpz` lineage) where the **client role of a
//! TLS session is split across two parties**, P1 and P2, such that — in the
//! **semi-honest** model (see the boundary below) — neither alone holds the
//! traffic key or can read/forge a record, yet together they speak to a real TLS
//! server.
//!
//! It is built bottom-up from real primitives, each verified before the next:
//! 1. [`ot`] — 1-of-2 **oblivious transfer** (Chou–Orlandi), so the evaluator can
//!    fetch labels for its own input bits blindly; [`ot_ext`] — **IKNP OT
//!    extension** turning `k` base OTs into arbitrarily many cheap ones; [`kos`] —
//!    **KOS maliciously-secure OT extension** (IKNP + a `GF(2^κ)` correlation check
//!    that aborts on a cheating receiver). The malicious-security path ([`wrk17`],
//!    [`ectf`]) runs its OT over [`kos`].
//! 2. [`garble`] — a **garbled-circuit** engine (free-XOR, point-and-permute,
//!    ZRE15 half-gate AND): general 2PC of any boolean circuit.
//! 3. [`circuit`] — boolean circuits for the pieces TLS needs: a 32-bit adder, the
//!    full **ChaCha20** block, **SHA-256** ([`sha256`], the key schedule's core),
//!    and **Poly1305** ([`poly1305`], `GF(2¹³⁰−5)` arithmetic), each verified
//!    against its RFC/NIST KAT and, garbled, against the plaintext oracle.
//! 4. The **session** (this module): a DECO-style **additively-shared ECDHE**
//!    handshake (neither party learns the pre-master); the ChaCha20 keystream and
//!    the Poly1305 tag computed **under 2PC into XOR-shares**; the SHA-256 key
//!    schedule under 2PC ([`sha256::digest_shared`]); and an end-to-end
//!    **ChaCha20-Poly1305 record sealed under 2PC** ([`session::seal_record_shared`])
//!    where neither party ever holds the key, keystream, or plaintext.
//! 5. [`dualex`] — **dual-execution**, a step past semi-honest: a cheating garbler
//!    is caught by an output-equality check (≤ 1-bit leakage).
//!
//! ## Honest boundary
//!
//! This is a **real 2PC core** with the full ChaCha20-Poly1305 AEAD and SHA-256
//! key schedule running inside the garbled circuit. Two of the sub-protocols that a
//! production deployment needs are now built and tested (still semi-honest / awaiting
//! audit), and what remains is well-scoped, not a redesign:
//! - **EC share conversion** — *built*: [`ectf`] is DECO's ECtF, converting the
//!   additive *point* share from [`session::shared_ecdhe`] into an additive
//!   x-coordinate share under 2PC (Gilboa MtA over `F_p` on the real OT, masked
//!   inversion). Its test validates against **P-256 point addition from the vetted
//!   `p256` crate**. What remains is A2B ([`convert`]) on the real curve prime and
//!   feeding the key-schedule circuit; and a constant-time field for production.
//! - **Malicious-security machinery** — *built*: [`wrk17`] is the WRK17
//!   authenticated-share core — TinyOT-style IT-MAC shares, OT-generated `aAND`
//!   triples, an authenticated circuit evaluation whose every open is **MAC-checked**
//!   (tamper ⇒ abort), and the sacrifice check. It is malicious-**detecting** and
//!   tested as such; it is **not** end-to-end malicious-secure — that needs a
//!   maliciously-secure (KOS) OT under it and the formal WRK17 proof (see the module).
//!   Until then the live session path still uses [`dualex`]'s ≤ 1-bit leak.
//! - **Live wiring**: a real TLS socket on the server's actual curve
//!   (X25519/P-256 x-only) rather than Ristretto, and HKDF/AEAD framing (AAD,
//!   length blocks) iterated through the same circuits.
//! - The **external audit** gate, as everywhere in neo.

pub mod auth;
pub mod circuit;
pub mod convert;
pub mod dualex;
pub mod ectf;
pub mod garble;
pub mod kos;
pub mod mta;
pub mod ot;
pub mod ot_ext;
pub mod poly1305;
pub mod sha256;
pub mod wrk17;

pub use convert::{a2b_shared, premaster_hash_from_point_shares};
pub use ectf::ectf;
pub use garble::{decode, evaluate, GarbledCircuit, Garbler};
pub use wrk17::{
    bucketed_triples, combine, eval_authenticated, rand_shares, rand_triples, verify_triple, Keys,
    Share, Triple,
};

mod session;
pub use session::{
    combine_ciphertext, local_cipher_share, seal_aead_shared, seal_record_shared,
    seal_tls13_record_shared, share_keystream, shared_ecdhe, KeystreamShares, PreMasterShares,
};
