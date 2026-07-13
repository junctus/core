//! **Live 2PC-TLS (M45)** — driving the built MPC-TLS crypto through a *real* TLS 1.3
//! handshake and record layer against an actual server, instead of the in-process
//! simulation in [`session`](super::session).
//!
//! The crypto is all built and audit-gated elsewhere in [`mpc_tls`](super); this module
//! is the **systems integration**: the TLS 1.3 state machine, the record framing, and
//! the two-party driver that ties them together. It is organised as:
//!
//! - [`channel`] — the transport to the server (a [`Channel`] trait with a loopback pair
//!   for tests and a real `TcpStream` impl), plus a length-prefixed 2PC message frame.
//! - [`ecdhe`] — a split-scalar **P-256 ECDHE** against a real server key share, where
//!   neither client party holds the ephemeral secret; ends in shares of the shared
//!   secret via [`ectf`](super::ectf) → [`a2b_shared`](super::convert::a2b_shared).
//! - [`schedule`] — the **TLS 1.3 key schedule under 2PC** (RFC 8446 §7.1), validated
//!   against the vetted `hkdf`/`hmac`/`sha2` crates.
//! - [`record`] — the record layer: seal (reuses
//!   [`seal_tls13_record_shared`](super::session::seal_tls13_record_shared)) and the
//!   matching **open/decrypt under 2PC**, with sequence-number state.
//! - [`handshake`] — the client state machine: build ClientHello, parse the server
//!   flight, drive the schedule from the real transcript hash, verify the server
//!   Finished, emit the client Finished, rekey to the application epoch. Interop-tested
//!   against a live **rustls** TLS 1.3 server.
//!
//! # Honest boundary
//!
//! - **Client ↔ server is a real TLS 1.3 session** (interop-tested against stock rustls),
//!   and **every crypto step is validated against an independent oracle** (stock
//!   `hkdf`/`hmac`/`sha2`/`chacha20poly1305`/`p256`, and rustls' `KeyLog`).
//! - **Party ↔ party 2PC is still modelled in-process** (as everywhere in
//!   [`mpc_tls`](super) — the high-level gadgets compute both sides): the [`Channel`]
//!   here transports the client↔server TLS bytes; a deployment additionally runs the
//!   garbler/evaluator/OT sub-protocol over a party↔party wire. This is the crate's
//!   standing modelling boundary, not new to M45.
//! - **Semi-honest**, on [`garble::eval_2pc`](super::garble); the malicious online
//!   ([`authgarble`](super::authgarble)) is the same schedule/records under a different
//!   engine and additionally needs malicious triple generation (M38/M45 residual). The
//!   engine seam is [`EngineKind`].
//! - **Nothing here is audited.** Live interop proves *correctness*, not the malicious-
//!   security theorem — that is the external audit gate, as everywhere in neo.

pub mod channel;
pub mod ecdhe;
pub mod engine;
pub mod handshake;
pub mod record;
pub mod schedule;

/// Which 2PC engine the live session evaluates its circuits under. The record/schedule
/// gadgets run on [`Semihonest`](EngineKind::Semihonest) today; [`Malicious`](EngineKind::Malicious)
/// is reserved for the [`authgarble`](super::authgarble) online once malicious triple
/// generation is wired end to end (see the module boundary).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineKind {
    /// Free-XOR / half-gate garbling ([`garble::eval_2pc`](super::garble)); ≤1-bit leak
    /// with dual-execution. What the live path uses today.
    Semihonest,
    /// WRK17/KRRW18 authenticated garbling ([`authgarble`](super::authgarble)) — aborts on
    /// a cheating party. Gated on malicious triple generation; not yet the live default.
    Malicious,
}

pub use channel::{Channel, Loopback, TcpChannel};
pub use ecdhe::{ClientKeyShare, SharedSecret};
pub use engine::eval_circuit;
pub use handshake::{client_handshake, recv_application, send_application, AppSession};
pub use record::Direction;
pub use schedule::{KeySchedule, Secret2, TrafficKeys};
