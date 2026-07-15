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
//! - **Engine-selectable** via [`EngineKind`]: the default is semi-honest
//!   ([`garble::eval_2pc`](super::garble)), but the **entire session — key schedule and
//!   every record — runs under the malicious WRK17/KRRW18 authenticated-garbling online**
//!   ([`authgarble`](super::authgarble)) with [`client_handshake_with_engine`]. The
//!   malicious key schedule is tested to match the stock RFC 8446 schedule and a malicious
//!   record round-trips (aborting on a cheating party); the full malicious handshake is an
//!   `#[ignore]`d interop test (~15-20 min under garbling). What "malicious" still models
//!   in-process is the *networked* aBit preprocessing (the KOS-OT `F_pre` between the two
//!   separate parties) — the crate's standing boundary — so this is a malicious-secure
//!   *construction* whose abort mechanism is tested, not the formal end-to-end theorem.
//! - **Nothing here is audited.** Live interop proves *correctness*, not the malicious-
//!   security theorem — that is the external audit gate, as everywhere in neo.

pub mod channel;
pub mod ecdhe;
pub mod handshake;
pub mod netschedule;
pub mod record;
pub mod schedule;
pub mod verify;

pub use super::engine::{eval_circuit, EngineKind};
pub use channel::{Channel, Loopback, TcpChannel};
pub use ecdhe::{ClientKeyShare, SharedSecret};
pub use handshake::{
    client_handshake, client_handshake_verified, client_handshake_with_engine, recv_application,
    send_application, AppSession,
};
pub use record::Direction;
pub use schedule::{KeySchedule, Secret2, TrafficKeys};
pub use verify::{LeafKeyVerifier, ServerCertVerifier};
