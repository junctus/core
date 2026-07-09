//! Baked-in discovery defaults and config resolution.
//!
//! This is the *entire* configuration a user needs for `neo run` to find the
//! network: a list of seed mirrors to fetch a relay snapshot from, and the
//! witness public keys that snapshot must be signed by. Everything else is
//! discovered.
//!
//! ## Operator setup (discovery.junctus.org)
//!
//! After you generate the seed's witness identity on the server
//! (`neo identity generate --output witness.key` → prints its node id; the
//! service also exposes the key at `GET /witness`), paste the hex key into
//! [`BAKED_WITNESSES`] and ship the rebuilt client. Until then, users can point
//! at your seed with `--mirror`/`--witness` or the `NEO_MIRRORS`/`NEO_WITNESSES`
//! environment variables. Trust is explicit by design: a client will not accept
//! a snapshot from a witness it hasn't been told to trust.

use std::time::Duration;

use anyhow::{bail, Context, Result};

/// Seed mirrors the client fetches `/snapshot` from, in order, until one
/// returns a snapshot that verifies. These are *untrusted* for integrity — the
/// witness signatures are what a client checks — so adding CDN mirrors here is
/// safe and only improves availability/censorship-resistance.
pub const BAKED_MIRRORS: &[&str] = &["https://discovery.junctus.org"];

/// Ed25519 witness public keys (hex) whose signatures a snapshot must carry.
/// A client will not accept a snapshot signed only by witnesses absent here.
pub const BAKED_WITNESSES: &[&str] = &[
    // discovery.junctus.org — the seed at BAKED_MIRRORS[0].
    "acb813898892f6f11292ddf79d291927fc1f19e77fec1acbaece86c92814972b",
];

/// Default minimum number of distinct trusted witnesses that must sign a
/// snapshot. Capped to the number of known witnesses at resolution time.
pub const DEFAULT_THRESHOLD: usize = 1;

/// How long a cached snapshot is trusted offline before a refetch is forced,
/// independent of the snapshot's own expiry (belt and suspenders).
pub const CACHE_MAX_AGE: Duration = Duration::from_secs(6 * 3600);

/// Resolved client discovery configuration (flags > env > baked).
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Seed mirror base URLs (no trailing slash).
    pub mirrors: Vec<String>,
    /// Trusted witness public keys (32 bytes each).
    pub witnesses: Vec<[u8; 32]>,
    /// Required distinct valid witness signatures.
    pub threshold: usize,
}

impl DiscoveryConfig {
    /// Resolve config from CLI overrides, environment, then baked defaults.
    ///
    /// `mirror_flags` / `witness_flags` come from repeatable CLI options; empty
    /// means "not overridden", so we fall back to `NEO_MIRRORS` / `NEO_WITNESSES`
    /// (comma-separated) and finally the baked constants.
    pub fn resolve(
        mirror_flags: &[String],
        witness_flags: &[String],
        threshold_flag: Option<usize>,
    ) -> Result<Self> {
        let mirrors = pick_list(mirror_flags, "NEO_MIRRORS", BAKED_MIRRORS)
            .into_iter()
            .map(|m| m.trim_end_matches('/').to_string())
            .collect::<Vec<_>>();
        if mirrors.is_empty() {
            bail!("no discovery mirrors configured (set --mirror or NEO_MIRRORS)");
        }

        let witness_hexes = pick_list(witness_flags, "NEO_WITNESSES", BAKED_WITNESSES);
        if witness_hexes.is_empty() {
            bail!(
                "no trusted witnesses configured. A client will not trust a snapshot from an \
                 unknown witness. Set --witness <hex> (or NEO_WITNESSES), or bake your seed's \
                 witness key into BAKED_WITNESSES. Get the key from `GET /witness` on your seed."
            );
        }
        let mut witnesses = Vec::with_capacity(witness_hexes.len());
        for hexkey in &witness_hexes {
            let mut key = [0u8; 32];
            hex::decode_to_slice(hexkey.trim(), &mut key)
                .with_context(|| format!("invalid witness key hex: {hexkey}"))?;
            witnesses.push(key);
        }

        let threshold = threshold_flag.unwrap_or(DEFAULT_THRESHOLD).max(1);
        if threshold > witnesses.len() {
            bail!(
                "witness threshold {threshold} exceeds the {} trusted witness(es) configured",
                witnesses.len()
            );
        }

        Ok(Self {
            mirrors,
            witnesses,
            threshold,
        })
    }
}

/// Flags win if non-empty; else a comma-separated env var; else the baked list.
fn pick_list(flags: &[String], env: &str, baked: &[&str]) -> Vec<String> {
    if !flags.is_empty() {
        return flags.to_vec();
    }
    if let Ok(value) = std::env::var(env) {
        let items: Vec<String> = value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !items.is_empty() {
            return items;
        }
    }
    baked.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_override_env_and_baked() {
        let cfg = DiscoveryConfig::resolve(
            &["https://example.org/".to_string()],
            &["ab".repeat(32)], // 64 hex chars
            None,
        )
        .unwrap();
        assert_eq!(cfg.mirrors, vec!["https://example.org"]); // trailing slash trimmed
        assert_eq!(cfg.witnesses.len(), 1);
        assert_eq!(cfg.threshold, 1);
    }

    #[test]
    fn baked_witnesses_are_valid_hex_keys() {
        // Clients must ship trusting at least one witness, and every baked entry
        // must decode to a 32-byte Ed25519 key (a typo here would brick discovery
        // for every distributed client, so guard it at build time).
        assert!(
            !BAKED_WITNESSES.is_empty(),
            "clients must ship with a trusted witness"
        );
        for hexkey in BAKED_WITNESSES {
            let mut key = [0u8; 32];
            hex::decode_to_slice(hexkey.trim(), &mut key)
                .unwrap_or_else(|_| panic!("baked witness is not 32-byte hex: {hexkey}"));
        }
    }

    #[test]
    fn threshold_cannot_exceed_witnesses() {
        let err = DiscoveryConfig::resolve(&["https://m".to_string()], &["cd".repeat(32)], Some(2))
            .unwrap_err();
        assert!(err.to_string().contains("threshold"));
    }
}
