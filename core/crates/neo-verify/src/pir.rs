//! Two-server information-theoretic PIR for oblivious lookups (M13).
//!
//! Private Information Retrieval lets a client fetch record `i` from a replicated
//! database **without either server learning `i`** — closing the leak that plain
//! DHT lookups have (the query reveals *what* you're looking for).
//!
//! This is the classic two-server XOR scheme: the client sends each server a
//! uniformly-random query vector; the two vectors differ in exactly one bit (at
//! `i`). Each server XORs the records its vector selects; XORing the two answers
//! yields record `i`. Neither server, alone, learns anything about `i` (its
//! query is uniformly random). Requires the two servers not to collude.

use neo_core::{Error, Result};

/// A replicated database of equal-length records (each server holds a copy).
pub struct PirDatabase {
    records: Vec<Vec<u8>>,
    record_len: usize,
}

impl PirDatabase {
    /// Build a database; all records must be the same length.
    pub fn new(records: Vec<Vec<u8>>) -> Result<Self> {
        let record_len = records.first().map(|r| r.len()).unwrap_or(0);
        if records.iter().any(|r| r.len() != record_len) {
            return Err(Error::Config("all PIR records must be equal length".into()));
        }
        Ok(Self {
            records,
            record_len,
        })
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// A server's answer: the XOR of every record its query vector selects.
    pub fn answer(&self, query: &PirQuery) -> Result<Vec<u8>> {
        if query.n != self.records.len() {
            return Err(Error::Decode(
                "PIR query size does not match database".into(),
            ));
        }
        let mut acc = vec![0u8; self.record_len];
        for (j, record) in self.records.iter().enumerate() {
            if query.get(j) {
                for (a, b) in acc.iter_mut().zip(record) {
                    *a ^= b;
                }
            }
        }
        Ok(acc)
    }
}

/// One server's query vector (a bitset over the record indices).
pub struct PirQuery {
    n: usize,
    bits: Vec<u8>,
}

impl PirQuery {
    fn get(&self, j: usize) -> bool {
        (self.bits[j / 8] >> (j % 8)) & 1 == 1
    }

    fn flip(&mut self, j: usize) {
        self.bits[j / 8] ^= 1 << (j % 8);
    }
}

/// Build the pair of queries for retrieving `index` from an `n`-record database.
/// Send `.0` to server one and `.1` to server two.
pub fn make_query(n: usize, index: usize) -> Result<(PirQuery, PirQuery)> {
    if index >= n {
        return Err(Error::Config("PIR index out of range".into()));
    }
    let byte_len = n.div_ceil(8).max(1);
    let mut bits = vec![0u8; byte_len];
    getrandom::getrandom(&mut bits).map_err(|e| Error::Rng(e.to_string()))?;
    // Clear padding bits past `n` so both servers see well-formed vectors.
    for j in n..byte_len * 8 {
        bits[j / 8] &= !(1 << (j % 8));
    }

    let first = PirQuery {
        n,
        bits: bits.clone(),
    };
    let mut second = PirQuery { n, bits };
    second.flip(index);
    Ok((first, second))
}

/// Combine the two servers' answers into the requested record.
pub fn combine(answer_one: &[u8], answer_two: &[u8]) -> Vec<u8> {
    answer_one
        .iter()
        .zip(answer_two)
        .map(|(a, b)| a ^ b)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieves_the_right_record_without_the_index() {
        let records: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 16]).collect();
        let server_one = PirDatabase::new(records.clone()).unwrap();
        let server_two = PirDatabase::new(records).unwrap();

        for index in 0..8 {
            let (q1, q2) = make_query(8, index).unwrap();
            let a1 = server_one.answer(&q1).unwrap();
            let a2 = server_two.answer(&q2).unwrap();
            assert_eq!(combine(&a1, &a2), vec![index as u8; 16]);
        }
    }

    #[test]
    fn rejects_out_of_range_index() {
        assert!(make_query(4, 4).is_err());
    }
}
