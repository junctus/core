//! `neo-crypto` — cryptographic core.
//!
//! - [`handshake`] — PQ-hybrid, mutually-authenticated key exchange (M1).
//! - [`session`] — the authenticated, ordered data channel it establishes (M1).
//! - [`onion`] — per-hop layered encryption for multi-hop circuits (M2).
//!
//! Thin wrappers over vetted primitives (X25519, ML-KEM-768, Ed25519,
//! ChaCha20-Poly1305, BLAKE3, HKDF). **Not audited** — see `docs/CRYPTO.md`.

#![forbid(unsafe_code)]

pub mod handshake;
pub mod onion;
pub mod session;

pub use handshake::{
    initiator_finish, initiator_message1, responder_process, HandshakeResult, Initiator,
};
pub use onion::{peel, wrap, OnionHop, Peeled};
pub use session::Session;
