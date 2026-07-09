//! `neo-mpc` — committee / MPC-TLS exit (frontier flagship, M12).
//!
//! A k-of-n committee jointly stands in for the exit so that **no coalition
//! smaller than the threshold can reconstruct the destination + plaintext** of a
//! clearnet request. This turns "no responsible exit" from a *statistical*
//! property (M7's rotating exits) into a *cryptographic* one.
//!
//! ## What is implemented (real, information-theoretic)
//!
//! The clearnet request is **threshold secret-shared** (Shamir over GF(256)) into
//! one share per committee member. Any `k-1` members — even colluding — learn
//! *nothing* about the destination or payload (this is Shamir's information-
//! theoretic guarantee, not a computational assumption). Any `k` members
//! reconstruct it. A hash bound into the secret makes a corrupted or swapped
//! share detectable at reconstruction.
//!
//! ## What is deferred (honest boundary)
//!
//! Full **MPC-TLS** — where the committee computes the TLS session itself under
//! multi-party computation, so the plaintext is *never* assembled at any single
//! point, including the moment it is sent to the real server — is a large 2PC/MPC
//! construction (TLSNotary/`mpz` lineage) and is **not** implemented here. This
//! crate provides the trust-splitting core (no minority reconstructs) and the
//! committee model that a future MPC reconstruct-and-send step slots into. The
//! honest gap: reconstruction here produces the assembled request in one place;
//! MPC-TLS removes even that.

#![forbid(unsafe_code)]

pub mod vss;

use neo_core::{Error, Result};
use sharks::{Share, Sharks};

/// Domain tag bound into every shared secret (versioning + separation).
const SECRET_DOMAIN: &[u8] = b"neo-committee-request-v1";
/// Maximum committee size (Shamir x-coordinates are non-zero bytes: 1..=255).
pub const MAX_MEMBERS: usize = 255;

/// A clearnet request the committee will perform on the client's behalf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearnetRequest {
    /// The destination, e.g. `example.com:443`.
    pub destination: String,
    /// The opaque request payload (e.g. an encrypted TLS record stream).
    pub payload: Vec<u8>,
}

impl ClearnetRequest {
    /// Serialize `[domain][2-byte dest len][dest][payload]` — the plaintext body
    /// that gets secret-shared (after a hash is prepended; see [`deal`]).
    pub(crate) fn body(&self) -> Result<Vec<u8>> {
        if self.destination.len() > u16::MAX as usize {
            return Err(Error::Config("destination too long".into()));
        }
        let mut out = Vec::with_capacity(2 + self.destination.len() + self.payload.len());
        out.extend_from_slice(&(self.destination.len() as u16).to_be_bytes());
        out.extend_from_slice(self.destination.as_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub(crate) fn from_body(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(Error::Decode("committee request too short".into()));
        }
        let dlen = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let rest = &bytes[2..];
        if rest.len() < dlen {
            return Err(Error::Decode(
                "committee request destination truncated".into(),
            ));
        }
        let destination = std::str::from_utf8(&rest[..dlen])
            .map_err(|_| Error::Decode("destination is not valid UTF-8".into()))?
            .to_string();
        Ok(Self {
            destination,
            payload: rest[dlen..].to_vec(),
        })
    }
}

/// A committee's size and reconstruction threshold.
#[derive(Clone, Copy, Debug)]
pub struct CommitteeConfig {
    /// Total committee members `n`.
    pub members: usize,
    /// Shares required to reconstruct `k` (`2 <= k <= n`).
    pub threshold: usize,
}

impl CommitteeConfig {
    /// Validate `2 <= threshold <= members <= MAX_MEMBERS`. A threshold of 1 is
    /// rejected: it would let a single member reconstruct, defeating the point.
    pub fn validate(&self) -> Result<()> {
        if self.threshold < 2 {
            return Err(Error::Config(
                "committee threshold must be >= 2 (else one member reconstructs)".into(),
            ));
        }
        if self.members < self.threshold {
            return Err(Error::Config("committee needs members >= threshold".into()));
        }
        if self.members > MAX_MEMBERS {
            return Err(Error::Config(format!(
                "committee supports at most {MAX_MEMBERS} members"
            )));
        }
        Ok(())
    }
}

/// One committee member's Shamir share of a request. Opaque; distribute one to
/// each member. The member index is the share's x-coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberShare(Vec<u8>);

impl MemberShare {
    /// The member index (Shamir x-coordinate, 1..=255).
    pub fn member(&self) -> u8 {
        // `Vec::from(&Share)` puts the x-coordinate first; empty is impossible
        // for a well-formed share but guard anyway.
        self.0.first().copied().unwrap_or(0)
    }

    /// Raw bytes for the wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Wrap wire bytes (validated at reconstruction time).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        MemberShare(bytes)
    }
}

/// Secret-share `request` across a committee. Returns one [`MemberShare`] per
/// member; hand exactly one to each. Any `threshold-1` of them reveal nothing.
pub fn deal(request: &ClearnetRequest, cfg: CommitteeConfig) -> Result<Vec<MemberShare>> {
    cfg.validate()?;

    // secret = domain || blake3(domain || body) || body, so a reconstruction can
    // verify integrity and reject corrupted/swapped shares.
    let body = request.body()?;
    let mut secret = Vec::with_capacity(SECRET_DOMAIN.len() + 32 + body.len());
    let mut hasher = blake3::Hasher::new();
    hasher.update(SECRET_DOMAIN);
    hasher.update(&body);
    secret.extend_from_slice(SECRET_DOMAIN);
    secret.extend_from_slice(hasher.finalize().as_bytes());
    secret.extend_from_slice(&body);

    let sharks = Sharks(cfg.threshold as u8);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<MemberShare> = dealer
        .take(cfg.members)
        .map(|s| MemberShare(Vec::from(&s)))
        .collect();
    if shares.len() != cfg.members {
        return Err(Error::Crypto("dealer produced too few shares".into()));
    }
    Ok(shares)
}

/// Reconstruct the request from at least `threshold` shares. Fails if fewer than
/// the threshold are present or if the shares don't agree (corruption detected
/// via the embedded hash).
pub fn reconstruct(shares: &[MemberShare], cfg: CommitteeConfig) -> Result<ClearnetRequest> {
    cfg.validate()?;
    if shares.len() < cfg.threshold {
        return Err(Error::Crypto(format!(
            "need {} shares to reconstruct, have {}",
            cfg.threshold,
            shares.len()
        )));
    }

    let parsed: Vec<Share> = shares
        .iter()
        .map(|s| Share::try_from(s.0.as_slice()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Decode(format!("bad committee share: {e}")))?;

    let sharks = Sharks(cfg.threshold as u8);
    let secret = sharks
        .recover(parsed.iter())
        .map_err(|e| Error::Crypto(format!("committee recover: {e}")))?;

    // Undo the domain || hash || body framing and verify integrity.
    let after_domain = secret
        .strip_prefix(SECRET_DOMAIN)
        .ok_or_else(|| Error::Crypto("reconstructed secret has wrong domain".into()))?;
    if after_domain.len() < 32 {
        return Err(Error::Crypto("reconstructed secret truncated".into()));
    }
    let (claimed_hash, body) = after_domain.split_at(32);
    let mut hasher = blake3::Hasher::new();
    hasher.update(SECRET_DOMAIN);
    hasher.update(body);
    if hasher.finalize().as_bytes() != claimed_hash {
        return Err(Error::Crypto(
            "committee reconstruction failed integrity check (corrupt/insufficient shares)".into(),
        ));
    }
    ClearnetRequest::from_body(body)
}

/// A committee that holds one share per member and reconstructs on a threshold.
///
/// This models the custody split: shares are distributed to members, and the
/// request can only be reassembled when at least `threshold` of them cooperate.
pub struct Committee {
    cfg: CommitteeConfig,
    shares: Vec<MemberShare>,
}

impl Committee {
    /// Split `request` and take custody of the shares.
    pub fn deal(request: &ClearnetRequest, cfg: CommitteeConfig) -> Result<Self> {
        Ok(Self {
            cfg,
            shares: deal(request, cfg)?,
        })
    }

    /// The committee configuration.
    pub fn config(&self) -> CommitteeConfig {
        self.cfg
    }

    /// The share held by member index `i` (0-based position in the committee).
    pub fn share_of(&self, i: usize) -> Option<&MemberShare> {
        self.shares.get(i)
    }

    /// Attempt reconstruction from the members at the given positions. Succeeds
    /// only if at least `threshold` distinct members contribute.
    pub fn reconstruct_from(&self, members: &[usize]) -> Result<ClearnetRequest> {
        let mut collected = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for &i in members {
            if let Some(share) = self.shares.get(i) {
                if seen.insert(i) {
                    collected.push(share.clone());
                }
            }
        }
        reconstruct(&collected, self.cfg)
    }

    /// Honest overhead: total shared bytes divided by the original request size.
    /// Shamir replicates the secret per member, so expansion ≈ `members`.
    pub fn expansion_factor(&self, request: &ClearnetRequest) -> f64 {
        let original = request.body().map(|b| b.len()).unwrap_or(0).max(1);
        let total: usize = self.shares.iter().map(|s| s.0.len()).sum();
        total as f64 / original as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ClearnetRequest {
        ClearnetRequest {
            destination: "example.com:443".into(),
            payload: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        }
    }

    #[test]
    fn threshold_reconstructs_and_below_threshold_fails() {
        let cfg = CommitteeConfig {
            members: 5,
            threshold: 3,
        };
        let req = request();
        let committee = Committee::deal(&req, cfg).unwrap();

        // Any 3 members reconstruct exactly.
        assert_eq!(committee.reconstruct_from(&[0, 2, 4]).unwrap(), req);
        assert_eq!(committee.reconstruct_from(&[1, 3, 4]).unwrap(), req);

        // Any 2 members cannot.
        assert!(committee.reconstruct_from(&[0, 1]).is_err());
    }

    #[test]
    fn no_single_share_reveals_the_destination() {
        let cfg = CommitteeConfig {
            members: 5,
            threshold: 3,
        };
        let req = request();
        let shares = deal(&req, cfg).unwrap();
        // The destination string must not appear in any individual share.
        for share in &shares {
            let bytes = share.to_bytes();
            assert!(
                !contains_subslice(&bytes, req.destination.as_bytes()),
                "a single share leaked the destination"
            );
        }
    }

    #[test]
    fn duplicate_members_do_not_satisfy_the_threshold() {
        let cfg = CommitteeConfig {
            members: 4,
            threshold: 3,
        };
        let committee = Committee::deal(&request(), cfg).unwrap();
        // The same member offered three times is still one contribution.
        assert!(committee.reconstruct_from(&[2, 2, 2]).is_err());
    }

    #[test]
    fn a_corrupted_share_is_detected() {
        let cfg = CommitteeConfig {
            members: 5,
            threshold: 3,
        };
        let req = request();
        let mut shares = deal(&req, cfg).unwrap();
        // Corrupt a payload byte of one share (past the x-coordinate).
        let last = shares[2].0.len() - 1;
        shares[2].0[last] ^= 0xff;
        let err = reconstruct(&shares[..3], cfg).unwrap_err();
        assert!(format!("{err}").contains("integrity") || format!("{err}").contains("recover"));
    }

    #[test]
    fn wire_roundtrip_and_member_index() {
        let cfg = CommitteeConfig {
            members: 3,
            threshold: 2,
        };
        let shares = deal(&request(), cfg).unwrap();
        for share in &shares {
            let wire = share.to_bytes();
            let back = MemberShare::from_bytes(wire.clone());
            assert_eq!(back, *share);
            assert_ne!(share.member(), 0, "member index (x-coord) is 1..=255");
        }
        // Reconstruct from deserialized wire shares.
        let wire: Vec<MemberShare> = shares
            .iter()
            .map(|s| MemberShare::from_bytes(s.to_bytes()))
            .collect();
        assert_eq!(reconstruct(&wire[..2], cfg).unwrap(), request());
    }

    #[test]
    fn rejects_degenerate_configs() {
        assert!(CommitteeConfig {
            members: 3,
            threshold: 1
        }
        .validate()
        .is_err());
        assert!(CommitteeConfig {
            members: 2,
            threshold: 3
        }
        .validate()
        .is_err());
    }

    #[test]
    fn empty_payload_is_supported() {
        let cfg = CommitteeConfig {
            members: 3,
            threshold: 2,
        };
        let req = ClearnetRequest {
            destination: "a.example:443".into(),
            payload: vec![],
        };
        let committee = Committee::deal(&req, cfg).unwrap();
        assert_eq!(committee.reconstruct_from(&[0, 1]).unwrap(), req);
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
