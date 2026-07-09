//! `neo-seed` — a witnessed discovery seed.
//!
//! A seed is the network's *first contact* and nothing more. It never relays
//! user traffic; it holds only public, signed relay records in memory. Its job:
//!
//! 1. **Accept** signed [`PeerRecord`](neo_discovery::PeerRecord)s from relays
//!    (`POST /register`), verifying each one is self-certifying and node-signed.
//! 2. **Verify reachability** by dialing each relay back and completing the neo
//!    handshake — proving the operator controls both the address and the key.
//! 3. **Attest** to the healthy set by signing a [`SignedSnapshot`] as a
//!    *witness*, served from `GET /snapshot`.
//!
//! Because the snapshot is witness-signed, it is safe to serve from any
//! untrusted mirror or CDN: a host that tampers with it can't forge the
//! signature, and a colluding witness can at worst omit relays, never
//! impersonate them. Run several independent seeds and have clients require a
//! k-of-n threshold to erode any single operator's trust.
//!
//! [`SignedSnapshot`]: neo_discovery::snapshot::SignedSnapshot

#![forbid(unsafe_code)]

pub mod health;
pub mod registry;
pub mod service;

pub use registry::Registry;
pub use service::{Seed, SeedConfig};
