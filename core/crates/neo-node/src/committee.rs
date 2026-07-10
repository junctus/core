//! Committee-exit circuits (M28): the subpoena-proof exit over a live circuit.
//!
//! The circuit's hops **are** a threshold committee holding DKG shares
//! ([`neo_mpc::dkg`]) of a joint key `Y` — no party holds the secret `s`. The
//! exit encrypts the destination's response to `Y`
//! ([`neo_mpc::threshold::encrypt`]) and each hop, on the return path,
//! contributes its partial decryption `D_i = y_i·R`. Only the client — holding
//! every hop's Sphinx-derived return secret — recovers the partials and combines
//! them, so **no committee member sees the response plaintext** (the egress that
//! terminates the destination's TLS is the honest exception, since it produced
//! the response before sealing it — that gap is the 2PC-TLS send path, M33).
//!
//! ## Why each partial is sealed to the client
//!
//! Partials accumulate as the response flows back toward the client. A naive
//! plaintext append would let the hop *nearest the client* observe every other
//! hop's partial — a full quorum — and decrypt the response itself, defeating the
//! whole property. To prevent that, each member `i` **seals** its partial under a
//! key derived from its own return secret `s_i` (which only the client re-derives,
//! from [`create_packet_keyed`](neo_crypto::create_packet_keyed)). A downstream
//! member relays the sealed blobs but cannot open them, so it never assembles a
//! quorum; only the client opens all of them.
//!
//! This module is the return-path crypto core (sealing + client recovery). Wiring
//! it onto the live persistent circuit (the M26 serving loop) and the
//! `neo run --committee` role build on top of it.

use std::collections::HashSet;

use neo_core::{Error, Result};
use neo_mpc::threshold::{self, Ciphertext, Partial};
use neo_mpc::vss::{KeyCommitments, KeyShare};

/// A serialized [`Partial`] is 97 bytes; sealing adds a keyed MAC.
const PARTIAL_LEN: usize = 97;
/// Integrity tag length on a sealed partial.
const SEAL_MAC_LEN: usize = 16;
/// Total sealed-partial length on the wire.
pub const SEALED_PARTIAL_LEN: usize = PARTIAL_LEN + SEAL_MAC_LEN;
/// Bound on sealed partials in one response (one per committee member).
const MAX_SEALED_PARTIALS: usize = neo_mpc::MAX_MEMBERS;

fn seal_key(return_secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("neo-committee-partial-seal-v1", return_secret)
}

/// XOR `data` with a keystream derived from `key` (one sealed partial, one key).
fn xor_mask(data: &mut [u8], key: &[u8; 32]) {
    let mut ks = vec![0u8; data.len()];
    blake3::Hasher::new_keyed(key).finalize_xof().fill(&mut ks);
    for (b, k) in data.iter_mut().zip(&ks) {
        *b ^= k;
    }
}

fn seal_mac(key: &[u8; 32], body: &[u8]) -> [u8; SEAL_MAC_LEN] {
    let mac_key = blake3::derive_key("neo-committee-partial-mac-v1", key);
    let full = blake3::keyed_hash(&mac_key, body);
    let mut out = [0u8; SEAL_MAC_LEN];
    out.copy_from_slice(&full.as_bytes()[..SEAL_MAC_LEN]);
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A committee member computes and **seals** its partial decryption of `ct` for
/// the client. `return_secret` is the member's Sphinx-derived stream secret for
/// this circuit — only the client re-derives it, so a downstream hop relaying the
/// blob cannot open it (and thus cannot reach a decryption quorum).
pub fn seal_partial(
    return_secret: &[u8; 32],
    share: &KeyShare,
    ct: &Ciphertext,
) -> Result<Vec<u8>> {
    let partial = threshold::partial_decrypt(share, ct)?;
    let key = seal_key(return_secret);
    let mut body = partial.to_bytes().to_vec();
    xor_mask(&mut body, &key);
    let mac = seal_mac(&key, &body);
    body.extend_from_slice(&mac);
    Ok(body)
}

/// The client opens one sealed partial with a member's return secret. Fails if
/// the MAC does not match (wrong key / tampered), so a member can never open a
/// blob sealed to a different member.
pub fn open_partial(return_secret: &[u8; 32], sealed: &[u8]) -> Result<Partial> {
    if sealed.len() != SEALED_PARTIAL_LEN {
        return Err(Error::Decode("sealed partial has the wrong length".into()));
    }
    let key = seal_key(return_secret);
    let (body, mac) = sealed.split_at(PARTIAL_LEN);
    if !ct_eq(mac, &seal_mac(&key, body)) {
        return Err(Error::Crypto(
            "sealed partial failed its integrity check".into(),
        ));
    }
    let mut plain = body.to_vec();
    xor_mask(&mut plain, &key);
    Partial::from_bytes(&plain)
}

/// The response a committee circuit returns to the client: the exit's threshold
/// [`Ciphertext`] plus one sealed partial per committee member on the path.
#[derive(Clone, Debug)]
pub struct CommitteeResponse {
    /// The response encrypted to the committee's joint key (only a quorum decrypts).
    pub ciphertext: Ciphertext,
    /// Each member's partial, sealed to the client.
    pub sealed_partials: Vec<Vec<u8>>,
}

impl CommitteeResponse {
    /// Serialize as `ct_len (u32) || ct || count (u16) || count × sealed partials`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct = self.ciphertext.to_bytes();
        let mut out =
            Vec::with_capacity(6 + ct.len() + self.sealed_partials.len() * SEALED_PARTIAL_LEN);
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
        out.extend_from_slice(&(self.sealed_partials.len() as u16).to_be_bytes());
        for sealed in &self.sealed_partials {
            out.extend_from_slice(sealed);
        }
        out
    }

    /// Parse [`to_bytes`](Self::to_bytes). Bounds-checked; never panics.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = bytes;
        let ct_len = u32::from_be_bytes(take(&mut cur, 4)?.try_into().expect("4 bytes")) as usize;
        let ct = Ciphertext::from_bytes(take(&mut cur, ct_len)?)?;
        let count = u16::from_be_bytes(take(&mut cur, 2)?.try_into().expect("2 bytes")) as usize;
        if count > MAX_SEALED_PARTIALS {
            return Err(Error::Decode("too many sealed partials".into()));
        }
        let mut sealed_partials = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            sealed_partials.push(take(&mut cur, SEALED_PARTIAL_LEN)?.to_vec());
        }
        if !cur.is_empty() {
            return Err(Error::Decode(
                "trailing bytes after committee response".into(),
            ));
        }
        Ok(Self {
            ciphertext: ct,
            sealed_partials,
        })
    }
}

/// The client recovers the response plaintext: open each sealed partial with a
/// matching return secret (the MAC identifies the right one), de-duplicate by
/// member, and combine a threshold quorum. Returns an error — never garbage — if
/// fewer than `threshold_k` partials open and verify.
pub fn open_response(
    commitments: &KeyCommitments,
    threshold_k: usize,
    response: &CommitteeResponse,
    return_secrets: &[[u8; 32]],
) -> Result<Vec<u8>> {
    let mut partials = Vec::new();
    let mut seen = HashSet::new();
    for sealed in &response.sealed_partials {
        for secret in return_secrets {
            if let Ok(p) = open_partial(secret, sealed) {
                if seen.insert(p.member()) {
                    partials.push(p);
                }
                break;
            }
        }
    }
    threshold::combine(commitments, threshold_k, &response.ciphertext, &partials)
}

/// Split `n` bytes off the front of `cur`, erroring (not panicking) if short.
fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if cur.len() < n {
        return Err(Error::Decode("truncated committee response".into()));
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_mpc::dkg;
    use neo_mpc::CommitteeConfig;

    /// A DKG committee (no party holds `s`) plus a fresh return secret per hop.
    fn committee(members: usize, threshold: usize) -> (KeyCommitments, Vec<KeyShare>) {
        let cfg = CommitteeConfig { members, threshold };
        let contributions: Vec<dkg::Contribution> = (1..=members as u8)
            .map(|m| dkg::Contribution::generate(m, &cfg).unwrap())
            .collect();
        let mut shares = Vec::new();
        for recipient in 1..=members as u8 {
            let dealt: Vec<KeyShare> = contributions
                .iter()
                .map(|d| d.share_for(recipient).unwrap())
                .collect();
            shares.push(dkg::aggregate_share(recipient, &dealt).unwrap());
        }
        let commitments = dkg::joint_commitments(
            &contributions
                .iter()
                .map(|c| c.commitment().clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        (commitments, shares)
    }

    fn secret(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn only_the_client_recovers_the_response_never_a_relaying_member() {
        // A 3-hop committee circuit (threshold 3) over a 3-member committee.
        let (commitments, shares) = committee(3, 3);
        let secrets = [secret(11), secret(22), secret(33)];
        let response_plaintext = b"HTTP/1.1 200 OK\r\n\r\ntop secret body";

        // Exit encrypts the response to the joint key.
        let ct = threshold::encrypt(&commitments, response_plaintext).unwrap();
        // Each hop seals its partial under its own return secret.
        let sealed: Vec<Vec<u8>> = (0..3)
            .map(|i| seal_partial(&secrets[i], &shares[i], &ct).unwrap())
            .collect();
        let response = CommitteeResponse {
            ciphertext: ct,
            sealed_partials: sealed,
        };

        // The client, holding every return secret, recovers the plaintext.
        assert_eq!(
            open_response(&commitments, 3, &response, &secrets).unwrap(),
            response_plaintext
        );

        // A relaying member — it forwards all three sealed blobs but knows only
        // its OWN return secret — opens just one partial, below threshold, so it
        // cannot decrypt. This is the property that makes on-circuit fan-in safe.
        let just_mine = [secrets[0]];
        assert!(
            open_response(&commitments, 3, &response, &just_mine).is_err(),
            "a hop relaying every sealed partial must still be unable to decrypt"
        );
    }

    #[test]
    fn a_sealed_partial_opens_only_with_its_own_secret() {
        let (_c, shares) = committee(3, 3);
        let ct = threshold::encrypt(&_c, b"x").unwrap();
        let sealed = seal_partial(&secret(7), &shares[0], &ct).unwrap();
        assert_eq!(sealed.len(), SEALED_PARTIAL_LEN);
        assert!(open_partial(&secret(7), &sealed).is_ok());
        assert!(
            open_partial(&secret(8), &sealed).is_err(),
            "the wrong return secret must fail the MAC, not yield a forged partial"
        );
    }

    #[test]
    fn committee_response_roundtrips_on_the_wire() {
        let (commitments, shares) = committee(4, 3);
        let ct = threshold::encrypt(&commitments, b"a response").unwrap();
        let secrets: Vec<[u8; 32]> = (0..4).map(|i| secret(i as u8 + 1)).collect();
        let sealed: Vec<Vec<u8>> = (0..4)
            .map(|i| seal_partial(&secrets[i], &shares[i], &ct).unwrap())
            .collect();
        let response = CommitteeResponse {
            ciphertext: ct,
            sealed_partials: sealed,
        };
        let parsed = CommitteeResponse::from_bytes(&response.to_bytes()).unwrap();
        assert_eq!(
            open_response(&commitments, 3, &parsed, &secrets).unwrap(),
            b"a response"
        );
        // A truncated buffer is rejected, not panicked.
        assert!(CommitteeResponse::from_bytes(&response.to_bytes()[..5]).is_err());
    }
}
