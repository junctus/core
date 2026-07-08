//! `neo-routing` — path selection and circuit construction.
//!
//! Chooses node-disjoint multipaths and a fresh exit **per request**, so no two
//! requests share a route. Later hardened with **VRF-based** selection so the
//! randomness is verifiable and an adversary cannot herd a client onto
//! attacker-controlled paths.
//!
//! Status: stub — grows across M2 (circuits), M7 (per-request exits), M11 (VRF).
