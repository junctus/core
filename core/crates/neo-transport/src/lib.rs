//! `neo-transport` — pluggable, DPI-resistant transport.
//!
//! Defines a `Transport` trait and an obfuscation ladder that makes neo traffic
//! indistinguishable from mainstream internet traffic: QUIC baseline →
//! MASQUE/HTTP-3 → Snowflake-style WebRTC → (REALITY later). All `libp2p`
//! traffic runs *behind* this layer, never raw, because libp2p's own wire
//! protocol is DPI-fingerprintable.
//!
//! Status: stub — implemented in milestone M6.
