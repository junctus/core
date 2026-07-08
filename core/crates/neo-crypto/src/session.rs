//! Authenticated, ordered data channel established by the handshake.
//!
//! Each direction has its own ChaCha20-Poly1305 key. A frame carries an explicit
//! 64-bit counter used as the AEAD nonce, and the receiver enforces strict
//! monotonicity for replay/reorder protection (fine over a reliable transport).
//!
//! A [`Session`] can be [`split`](Session::split) into an independent [`Sealer`]
//! and [`Opener`] so the two directions of a tunnel run concurrently. Session
//! keys are zeroized on drop.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use neo_core::{Error, Result};
use zeroize::Zeroize;

/// The send half of a session: seals outbound frames.
pub struct Sealer {
    key: [u8; 32],
    counter: u64,
}

impl Sealer {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }

    /// Encrypt `plaintext` into a self-describing frame (`counter || ciphertext`).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("session nonce space exhausted".into()))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_from(counter)), plaintext)
            .map_err(|_| Error::Crypto("session seal failed".into()))?;

        let mut frame = Vec::with_capacity(8 + ciphertext.len());
        frame.extend_from_slice(&counter.to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }
}

impl Drop for Sealer {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// The receive half of a session: opens inbound frames, rejecting replays.
pub struct Opener {
    key: [u8; 32],
    last: Option<u64>,
}

impl Opener {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self { key, last: None }
    }

    /// Decrypt a frame produced by [`Sealer::seal`], rejecting replays/reorders.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 8 {
            return Err(Error::Decode("session frame too short".into()));
        }
        let counter = u64::from_be_bytes(frame[..8].try_into().expect("checked length"));
        if let Some(last) = self.last {
            if counter <= last {
                return Err(Error::Crypto("replayed or reordered frame".into()));
            }
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_from(counter)), &frame[8..])
            .map_err(|_| Error::Crypto("session open failed".into()))?;

        self.last = Some(counter);
        Ok(plaintext)
    }
}

impl Drop for Opener {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// A live, encrypted session between two neo nodes.
pub struct Session {
    sealer: Sealer,
    opener: Opener,
}

impl Session {
    pub(crate) fn new(key_send: [u8; 32], key_recv: [u8; 32]) -> Self {
        Self {
            sealer: Sealer::new(key_send),
            opener: Opener::new(key_recv),
        }
    }

    /// Encrypt `plaintext` into a frame.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.sealer.seal(plaintext)
    }

    /// Decrypt a frame.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        self.opener.open(frame)
    }

    /// Split into independent send/receive halves for a concurrent tunnel.
    pub fn split(self) -> (Sealer, Opener) {
        (self.sealer, self.opener)
    }
}

fn nonce_from(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealer_and_opener_roundtrip() {
        let key = [3u8; 32];
        let mut sealer = Sealer::new(key);
        let mut opener = Opener::new(key);
        let frame = sealer.seal(b"hello").unwrap();
        assert_eq!(opener.open(&frame).unwrap(), b"hello");
        assert!(opener.open(&frame).is_err(), "replay is rejected");
    }
}
