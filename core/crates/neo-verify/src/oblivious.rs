//! Keyword oblivious discovery over PIR (M13).
//!
//! [`pir`](crate::pir) hides *which index* a client fetches, but discovery is
//! keyed by `NodeId`, not by a public index. This layer bridges the two: records
//! are placed into a fixed number of buckets by a **public** hash of their key
//! (`bucket = H(salt ‖ key) mod B`), so a client that wants key `k` computes the
//! same bucket everyone would — then fetches it with 2-server PIR, revealing the
//! bucket to *neither* server. The result: a client looks up a relay by id while
//! each discovery server learns nothing about which relay.
//!
//! The salt is searched at build time so no two keys collide (a small perfect-
//! hashing step); the directory grows and re-salts if needed. Records are framed
//! with a length prefix and padded to a fixed size, as PIR requires. The two
//! servers hold identical replicas and must not collude — the standard 2-server
//! PIR assumption.

use neo_core::{Error, Result};

use crate::pir::{make_query, PirDatabase, PirQuery};

/// Attempts to find a collision-free salt before growing the table.
const SALT_TRIES: u32 = 256;

/// A PIR-servable directory keyed by arbitrary byte keys (e.g. `NodeId` bytes).
pub struct ObliviousDirectory {
    records: Vec<Vec<u8>>,
    salt: u32,
    n_buckets: usize,
}

impl ObliviousDirectory {
    /// Build a directory from `(key, record)` entries. Chooses a bucket count and
    /// a salt so every key lands in its own bucket. Records may vary in length
    /// (they are length-framed and padded to the largest).
    pub fn build(entries: &[(Vec<u8>, Vec<u8>)]) -> Result<Self> {
        // A zero-length record would encode as an all-zero length prefix — the same
        // sentinel try_place() uses for an *empty* bucket — so a second entry could
        // silently collide into it, breaking the perfect-hashing invariant. Refuse.
        if entries.iter().any(|(_, r)| r.is_empty()) {
            return Err(Error::Config(
                "oblivious directory records must be non-empty".into(),
            ));
        }
        let max_record = entries.iter().map(|(_, r)| r.len()).max().unwrap_or(0);
        if max_record > u16::MAX as usize {
            return Err(Error::Config("oblivious record too large".into()));
        }
        let record_len = max_record + 2; // 2-byte length prefix

        // Grow buckets (power of two, ≥ 2× entries) until a salt places all keys
        // without collision.
        let mut n_buckets = (entries.len().max(1) * 2).next_power_of_two();
        loop {
            if let Some((salt, records)) = try_place(entries, n_buckets, record_len) {
                return Ok(Self {
                    records,
                    salt,
                    n_buckets,
                });
            }
            n_buckets = n_buckets
                .checked_mul(2)
                .ok_or_else(|| Error::Config("oblivious directory too large".into()))?;
        }
    }

    /// The public bucket for `key` under this directory's salt. Both the client
    /// and the servers agree on this without interaction.
    pub fn bucket_of(&self, key: &[u8]) -> usize {
        bucket_of(self.salt, self.n_buckets, key)
    }

    /// Number of buckets (the PIR database size).
    pub fn n_buckets(&self) -> usize {
        self.n_buckets
    }

    /// The salt clients need to compute buckets (public).
    pub fn salt(&self) -> u32 {
        self.salt
    }

    /// The two identical PIR replicas to hand to the two non-colluding servers.
    pub fn replicas(&self) -> Result<(PirDatabase, PirDatabase)> {
        Ok((
            PirDatabase::new(self.records.clone())?,
            PirDatabase::new(self.records.clone())?,
        ))
    }
}

/// Client parameters needed to query a directory (published, non-secret).
#[derive(Clone, Copy, Debug)]
pub struct DirectoryParams {
    /// Bucket count.
    pub n_buckets: usize,
    /// Placement salt.
    pub salt: u32,
}

impl DirectoryParams {
    /// The pair of PIR queries to obliviously fetch `key`. Send `.0` to server
    /// one and `.1` to server two; neither learns the bucket.
    pub fn query(&self, key: &[u8]) -> Result<(PirQuery, PirQuery)> {
        make_query(self.n_buckets, bucket_of(self.salt, self.n_buckets, key))
    }
}

/// Decode a combined PIR answer back into a record, or `None` if the bucket was
/// empty (the key isn't in the directory).
pub fn decode(combined: &[u8]) -> Option<Vec<u8>> {
    if combined.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([combined[0], combined[1]]) as usize;
    if len == 0 || 2 + len > combined.len() {
        return None;
    }
    Some(combined[2..2 + len].to_vec())
}

fn bucket_of(salt: u32, n_buckets: usize, key: &[u8]) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"neo-oblivious-bucket-v1");
    hasher.update(&salt.to_be_bytes());
    hasher.update(key);
    let digest = hasher.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest.as_bytes()[..8]);
    (u64::from_be_bytes(head) % n_buckets as u64) as usize
}

/// Try to place every entry in its own bucket for some salt. Returns the salt
/// and the packed bucket records on success.
fn try_place(
    entries: &[(Vec<u8>, Vec<u8>)],
    n_buckets: usize,
    record_len: usize,
) -> Option<(u32, Vec<Vec<u8>>)> {
    for salt in 0..SALT_TRIES {
        let mut records = vec![vec![0u8; record_len]; n_buckets];
        let mut ok = true;
        for (key, value) in entries {
            let bucket = bucket_of(salt, n_buckets, key);
            // Occupied? (non-zero length prefix) ⇒ collision, try next salt.
            if records[bucket][0] != 0 || records[bucket][1] != 0 {
                ok = false;
                break;
            }
            records[bucket][..2].copy_from_slice(&(value.len() as u16).to_be_bytes());
            records[bucket][2..2 + value.len()].copy_from_slice(value);
        }
        if ok {
            return Some((salt, records));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pir::combine;

    fn entries() -> Vec<(Vec<u8>, Vec<u8>)> {
        (0u8..12)
            .map(|i| {
                // Distinct 32-byte "NodeId" keys and variable-length records.
                let key = vec![i; 32];
                let record = format!("relay-{i}@10.0.0.{i}:9000").into_bytes();
                (key, record)
            })
            .collect()
    }

    #[test]
    fn empty_records_are_rejected_to_preserve_perfect_hashing() {
        // A zero-length record aliases the empty-bucket sentinel, so it must be
        // refused rather than allowed to cause a silent collision.
        let bad = vec![(vec![1u8; 32], Vec::new()), (vec![2u8; 32], vec![9])];
        assert!(ObliviousDirectory::build(&bad).is_err());
    }

    #[test]
    fn oblivious_fetch_returns_the_right_record() {
        let dir = ObliviousDirectory::build(&entries()).unwrap();
        let params = DirectoryParams {
            n_buckets: dir.n_buckets(),
            salt: dir.salt(),
        };
        let (server_one, server_two) = dir.replicas().unwrap();

        for (key, expected) in entries() {
            // Client makes two queries; each server answers its own.
            let (q1, q2) = params.query(&key).unwrap();
            let a1 = server_one.answer(&q1).unwrap();
            let a2 = server_two.answer(&q2).unwrap();
            let record = decode(&combine(&a1, &a2)).expect("record present");
            assert_eq!(record, expected);
        }
    }

    #[test]
    fn absent_key_decodes_to_a_miss() {
        let dir = ObliviousDirectory::build(&entries()).unwrap();
        let params = DirectoryParams {
            n_buckets: dir.n_buckets(),
            salt: dir.salt(),
        };
        let (s1, s2) = dir.replicas().unwrap();

        // A key not in the directory lands in some (probably empty) bucket.
        // If it happens to collide with a real bucket the decode still returns a
        // record, so pick a key we know maps to an empty bucket.
        let mut miss_key = None;
        for probe in 100u8..255 {
            let key = vec![probe; 32];
            let bucket = dir.bucket_of(&key);
            let occupied = entries().iter().any(|(k, _)| dir.bucket_of(k) == bucket);
            if !occupied {
                miss_key = Some(key);
                break;
            }
        }
        let key = miss_key.expect("an empty bucket exists");
        let (q1, q2) = params.query(&key).unwrap();
        let a1 = s1.answer(&q1).unwrap();
        let a2 = s2.answer(&q2).unwrap();
        assert!(decode(&combine(&a1, &a2)).is_none());
    }

    #[test]
    fn bucket_mapping_is_deterministic_and_public() {
        let dir = ObliviousDirectory::build(&entries()).unwrap();
        let key = vec![3u8; 32];
        // The same (salt, n_buckets) always yields the same bucket, so a client
        // reproduces the server-side placement without any interaction.
        let from_params = bucket_of(dir.salt(), dir.n_buckets(), &key);
        assert_eq!(dir.bucket_of(&key), from_params);
        assert_eq!(dir.bucket_of(&key), dir.bucket_of(&key));
    }

    #[test]
    fn all_keys_get_distinct_buckets() {
        let dir = ObliviousDirectory::build(&entries()).unwrap();
        let mut seen = std::collections::HashSet::new();
        for (key, _) in entries() {
            assert!(seen.insert(dir.bucket_of(&key)), "collision-free placement");
        }
    }
}
