//! `neo-ffi` — mobile bindings.
//!
//! Exposes a small, batched API over the neo core to Swift and Kotlin via
//! **UniFFI**, so iOS (NEPacketTunnelProvider) and Android (VpnService) can run
//! the same engine. The API is intentionally coarse — packets are batched across
//! the FFI boundary rather than crossing it per-packet.
//!
//! Status: stub — implemented in milestone M8 (UniFFI wiring added there).
