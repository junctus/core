//! Error and result types shared across the neo engine.

/// The crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors surfaced by the neo core.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A cryptographic operation failed or key material was invalid.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Serialized data could not be parsed (wrong length, bad encoding, etc.).
    #[error("decode error: {0}")]
    Decode(String),

    /// Configuration was invalid or could not be loaded.
    #[error("config error: {0}")]
    Config(String),

    /// The operating-system RNG failed to produce randomness.
    #[error("rng failure: {0}")]
    Rng(String),

    /// An underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
