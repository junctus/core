//! `neo-verify` — verifiable, not trusted, privacy (frontier).
//!
//! Shared primitives that let clients *verify* the network behaved instead of
//! trusting it:
//! - **VRF** for unbiasable per-request path selection (used by `neo-routing`).
//! - **PIR** for oblivious peer discovery (used by `neo-discovery`).
//! - **ZK proof-of-mixing** so a mix node proves it shuffled correctly without
//!   revealing the permutation (used by `neo-mix`).
//!
//! Status: stub — grows across M11 (VRF) and M13 (PIR, ZK).
