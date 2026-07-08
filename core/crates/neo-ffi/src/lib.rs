//! `neo-ffi` — the mobile binding surface.
//!
//! A small, coarse-grained API over the neo core that the iOS
//! (NEPacketTunnelProvider) and Android (VpnService) shells call. It is written
//! as plain safe Rust so it always builds and is unit-tested; the `uniffi`
//! feature layers **UniFFI** scaffolding on top to generate Swift and Kotlin
//! bindings (`uniffi-bindgen`), and the crate builds as a `cdylib`/`staticlib`
//! for `cargo-ndk` (Android) and `xcframework` (iOS).
//!
//! The API is intentionally coarse — packets are batched across the FFI boundary
//! rather than crossing per-packet. Building the actual iOS/Android apps needs
//! Xcode / Gradle / the NDK (see `platforms/ios` and `platforms/android`).

use neo_core::NodeIdentity;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// Generate a fresh PQ-hybrid identity, returned as its secret bytes.
///
/// Returns an empty vector only if the OS RNG is unavailable (catastrophic).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_identity() -> Vec<u8> {
    NodeIdentity::generate()
        .map(|identity| identity.to_bytes())
        .unwrap_or_default()
}

/// The short node id (`neo:…`) for a stored identity's secret bytes, or `None`
/// if the bytes are not a valid identity.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn identity_node_id(secret: Vec<u8>) -> Option<String> {
    NodeIdentity::from_bytes(&secret)
        .ok()
        .map(|identity| identity.id().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_derive_node_id() {
        let secret = generate_identity();
        assert!(!secret.is_empty());
        let id = identity_node_id(secret).expect("valid identity");
        assert!(id.starts_with("neo:"));
    }

    #[test]
    fn invalid_secret_yields_none() {
        assert!(identity_node_id(vec![0u8; 5]).is_none());
    }
}
