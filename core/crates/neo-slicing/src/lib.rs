//! `neo-slicing` — information slicing (the novel core, part 1).
//!
//! A flow is **encrypted first, then sliced** into `n` shares (`data + parity`)
//! with a Reed-Solomon code, so that:
//! - any `data` (= `k`) of the `n` shares reconstruct the flow, and
//! - fewer than `k` shares — or all `n` without the key — reveal nothing, because
//!   every share is a fragment of AEAD ciphertext that is pseudorandom without
//!   the key.
//!
//! Shares are meant to travel node-disjoint paths (see `neo-routing`), so no
//! single relay ever holds a complete, meaningful flow. The AEAD key is carried
//! end-to-end, never inside a share.
//!
//! This is the algorithmic core; wire framing and key distribution live in
//! `neo-node`. See `docs/PROTOCOL.md`.

#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use neo_core::{Error, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Length of the symmetric key used to encrypt a flow before slicing.
pub const KEY_LEN: usize = 32;
/// AEAD nonce length (ChaCha20-Poly1305, 96-bit).
const NONCE_LEN: usize = 12;

/// One share of a sliced flow. Individually meaningless without `k` peers and the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// Position of this share within the code (`0..data+parity`).
    pub index: u8,
    /// Number of data shares (`k`) — the reconstruction threshold.
    pub data_shares: u8,
    /// Number of parity shares (`n - k`).
    pub parity_shares: u8,
    /// Length of the original ciphertext, so padding can be trimmed on reassembly.
    pub cipher_len: u32,
    /// AEAD nonce (public).
    pub nonce: [u8; NONCE_LEN],
    /// The Reed-Solomon shard bytes.
    pub shard: Vec<u8>,
}

impl Share {
    /// Serialize this share for transport: a fixed 19-byte header + the shard.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(19 + self.shard.len());
        v.push(self.index);
        v.push(self.data_shares);
        v.push(self.parity_shares);
        v.extend_from_slice(&self.cipher_len.to_be_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.shard);
        v
    }

    /// Parse a share from [`to_bytes`](Self::to_bytes) output.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 19 {
            return Err(Error::Decode("share too short".into()));
        }
        let cipher_len = u32::from_be_bytes(bytes[3..7].try_into().expect("checked length"));
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[7..19]);
        Ok(Share {
            index: bytes[0],
            data_shares: bytes[1],
            parity_shares: bytes[2],
            cipher_len,
            nonce,
            shard: bytes[19..].to_vec(),
        })
    }
}

/// Encrypt `plaintext` under `key`, then slice it into `data_shares + parity_shares` shares.
///
/// Any `data_shares` of the returned shares reconstruct the flow.
pub fn encrypt_and_slice(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    data_shares: usize,
    parity_shares: usize,
) -> Result<Vec<Share>> {
    if data_shares == 0 || parity_shares == 0 {
        return Err(Error::Config("data and parity shares must be > 0".into()));
    }
    if data_shares + parity_shares > 255 {
        return Err(Error::Config("data + parity shares must be <= 255".into()));
    }

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| Error::Rng(e.to_string()))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Crypto("AEAD encrypt failed".into()))?;

    let shard_len = ciphertext.len().div_ceil(data_shares).max(1);
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(data_shares + parity_shares);
    for i in 0..data_shares {
        let start = (i * shard_len).min(ciphertext.len());
        let end = (start + shard_len).min(ciphertext.len());
        let mut shard = vec![0u8; shard_len];
        shard[..end - start].copy_from_slice(&ciphertext[start..end]);
        shards.push(shard);
    }
    for _ in 0..parity_shares {
        shards.push(vec![0u8; shard_len]);
    }

    let rs = ReedSolomon::new(data_shares, parity_shares)
        .map_err(|e| Error::Crypto(format!("reed-solomon init: {e}")))?;
    rs.encode(&mut shards)
        .map_err(|e| Error::Crypto(format!("reed-solomon encode: {e}")))?;

    Ok(shards
        .into_iter()
        .enumerate()
        .map(|(i, shard)| Share {
            index: i as u8,
            data_shares: data_shares as u8,
            parity_shares: parity_shares as u8,
            cipher_len: ciphertext.len() as u32,
            nonce,
            shard,
        })
        .collect())
}

/// Reassemble and decrypt a flow from a subset of its shares (at least `k`).
pub fn reassemble_and_decrypt(key: &[u8; KEY_LEN], shares: &[Share]) -> Result<Vec<u8>> {
    let first = shares
        .first()
        .ok_or_else(|| Error::Decode("no shares provided".into()))?;
    let k = first.data_shares as usize;
    let m = first.parity_shares as usize;
    let n = k + m;
    let cipher_len = first.cipher_len as usize;
    let nonce = first.nonce;

    let mut slots: Vec<Option<Vec<u8>>> = vec![None; n];
    for s in shares {
        if s.data_shares as usize != k
            || s.parity_shares as usize != m
            || s.cipher_len as usize != cipher_len
            || s.nonce != nonce
        {
            return Err(Error::Decode(
                "shares are from different sliced flows".into(),
            ));
        }
        if (s.index as usize) < n {
            slots[s.index as usize] = Some(s.shard.clone());
        }
    }

    let present = slots.iter().filter(|s| s.is_some()).count();
    if present < k {
        return Err(Error::Decode(format!(
            "need {k} shares to reconstruct, have {present}"
        )));
    }

    let rs =
        ReedSolomon::new(k, m).map_err(|e| Error::Crypto(format!("reed-solomon init: {e}")))?;
    rs.reconstruct(&mut slots)
        .map_err(|e| Error::Crypto(format!("reed-solomon reconstruct: {e}")))?;

    let mut ciphertext = Vec::with_capacity(k * first.shard.len());
    for slot in slots.iter().take(k) {
        let shard = slot
            .as_ref()
            .ok_or_else(|| Error::Crypto("missing data shard after reconstruct".into()))?;
        ciphertext.extend_from_slice(shard);
    }
    ciphertext.truncate(cipher_len);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| Error::Crypto("AEAD decrypt failed (wrong key or corrupt shares)".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];

    #[test]
    fn roundtrip_with_all_shares() {
        let msg = b"the quick brown fox jumps over the lazy dog";
        let shares = encrypt_and_slice(&KEY, msg, 3, 2).unwrap();
        assert_eq!(shares.len(), 5);
        let out = reassemble_and_decrypt(&KEY, &shares).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn recovers_from_any_k_shares() {
        let msg = b"lose any two of five and still recover";
        let shares = encrypt_and_slice(&KEY, msg, 3, 2).unwrap();
        // Keep only shares 1, 3, 4 (drop two, including a data shard).
        let subset: Vec<Share> = shares
            .into_iter()
            .filter(|s| [1u8, 3, 4].contains(&s.index))
            .collect();
        assert_eq!(subset.len(), 3);
        let out = reassemble_and_decrypt(&KEY, &subset).unwrap();
        assert_eq!(out, msg);
    }

    #[test]
    fn fewer_than_k_shares_reveal_nothing() {
        let msg = b"insufficient shares must fail";
        let shares = encrypt_and_slice(&KEY, msg, 3, 2).unwrap();
        let too_few: Vec<Share> = shares.into_iter().take(2).collect();
        assert!(reassemble_and_decrypt(&KEY, &too_few).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let msg = b"authenticated encryption catches the wrong key";
        let shares = encrypt_and_slice(&KEY, msg, 3, 2).unwrap();
        let wrong = [9u8; KEY_LEN];
        assert!(reassemble_and_decrypt(&wrong, &shares).is_err());
    }

    #[test]
    fn tampered_shard_is_rejected() {
        let msg = b"integrity is enforced by the AEAD tag";
        let mut shares = encrypt_and_slice(&KEY, msg, 3, 2).unwrap();
        shares[0].shard[0] ^= 0xff;
        assert!(reassemble_and_decrypt(&KEY, &shares).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let shares = encrypt_and_slice(&KEY, b"", 2, 1).unwrap();
        assert_eq!(reassemble_and_decrypt(&KEY, &shares).unwrap(), b"");
    }

    #[test]
    fn share_from_bytes_roundtrips_and_survives_garbage() {
        let shares = encrypt_and_slice(&KEY, b"hi", 2, 1).unwrap();
        assert_eq!(Share::from_bytes(&shares[0].to_bytes()).unwrap(), shares[0]);

        let mut seed = 0xabcd_ef01u64;
        for _ in 0..3000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (seed >> 40) as usize % 96;
            let bytes: Vec<u8> = (0..len).map(|i| (seed >> (i % 8 * 8)) as u8).collect();
            let _ = Share::from_bytes(&bytes);
        }
    }
}
