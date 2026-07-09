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
pub mod session;
pub mod sphinx;

pub use handshake::{
    initiator_finish, initiator_message1, responder_confirm, responder_cookie, responder_process,
    CookieKey, HandshakeResult, Initiator, PendingResponder,
};
pub use session::{Opener, Sealer, Session};
pub use sphinx::{
    create_packet, create_packet_keyed, process, Processed, ReplayCache, SphinxHop, SphinxPacket,
};
