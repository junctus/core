//! `neo-crypto` — cryptographic core.
//!
//! Responsibilities:
//! - **PQ-hybrid Noise handshake** (X25519 + ML-KEM-768) for per-hop links.
//! - **Onion layering** and **Sphinx-format packets** for multi-hop circuits.
//! - Thin, reviewed wrappers over primitives (ChaCha20-Poly1305, BLAKE3, HKDF).
//!
//! Status: stub — grows across M0 (PQ-hybrid keys) and M2 (onion / Sphinx).
//! See `docs/CRYPTO.md`.
