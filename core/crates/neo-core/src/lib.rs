//! `neo-core` — shared types for the neo overlay engine.
//!
//! This crate holds the pieces every other `neo-*` crate depends on: error
//! types, node configuration (including the adaptive [`PrivacyLevel`] dial), and
//! the long-term [`NodeIdentity`]. It has no async runtime and no networking, so
//! it stays cheap to depend on and easy to reason about.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod identity;
pub mod net;
pub mod pow;

pub use config::{NodeConfig, PrivacyLevel};
pub use error::{Error, Result};
pub use identity::{
    verify_signature, NodeId, NodeIdentity, NodePublic, KEM_PUBLIC_LEN, SIGNATURE_LEN,
};

/// The neo engine version (from the crate version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
