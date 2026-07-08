//! Authenticated, ordered data channel established by the handshake.
//!
//! Each direction has its own ChaCha20-Poly1305 key. A frame carries an explicit
//! 64-bit counter used as the AEAD nonce, and the receiver enforces strict
//! monotonicity for replay/reorder protection (fine over a reliable transport).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use neo_core::{Error, Result};

/// A live, encrypted session between two neo nodes.
pub struct Session {
    key_send: [u8; 32],
    key_recv: [u8; 32],
    counter_send: u64,
    last_recv: Option<u64>,
}

impl Session {
    pub(crate) fn new(key_send: [u8; 32], key_recv: [u8; 32]) -> Self {
        Self {
            key_send,
            key_recv,
            counter_send: 0,
            last_recv: None,
        }
    }

    /// Encrypt `plaintext` into a self-describing frame (`counter || ciphertext`).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.counter_send;
        self.counter_send = self
            .counter_send
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("session nonce space exhausted".into()))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key_send));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_from(counter)), plaintext)
            .map_err(|_| Error::Crypto("session seal failed".into()))?;

        let mut frame = Vec::with_capacity(8 + ciphertext.len());
        frame.extend_from_slice(&counter.to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Decrypt a frame produced by [`seal`](Self::seal), rejecting replays/reorders.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 8 {
            return Err(Error::Decode("session frame too short".into()));
        }
        let counter = u64::from_be_bytes(frame[..8].try_into().expect("checked length"));
        if let Some(last) = self.last_recv {
            if counter <= last {
                return Err(Error::Crypto("replayed or reordered frame".into()));
            }
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key_recv));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_from(counter)), &frame[8..])
            .map_err(|_| Error::Crypto("session open failed".into()))?;

        self.last_recv = Some(counter);
        Ok(plaintext)
    }
}

fn nonce_from(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}
