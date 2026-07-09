//! `neo-verify` — verifiable, not trusted, privacy (frontier).
//!
//! - [`vrf`] — VRF for unbiasable per-request path selection (M11).
//! - [`selection`] — commit-then-VRF path-seed derivation neither party can bias (M11).
//! - [`pir`] — 2-server private information retrieval for oblivious lookups (M13).
//! - [`oblivious`] — keyword oblivious lookup over PIR for discovery (M13).
//! - [`proof_of_mixing`] — design notes for ZK proof-of-mixing (M13, scaffold).

#![forbid(unsafe_code)]

pub mod oblivious;
pub mod pir;
pub mod proof_of_mixing;
pub mod selection;
pub mod vrf;
