//! Client-side discovery: obtain a verified relay snapshot, and (for relays)
//! register with seeds.
//!
//! A client's integrity check is the witness signatures on the snapshot, so the
//! transport it arrives over is untrusted — any mirror, CDN, or on-disk cache
//! is acceptable. The order of preference is: fetch fresh from the configured
//! mirrors; if none are reachable, fall back to a still-valid cached snapshot
//! so a client that has run before can bootstrap fully offline of the seeds.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use neo_discovery::now_unix;
use neo_discovery::snapshot::SignedSnapshot;
use neo_discovery::PeerRecord;

use crate::defaults::{DiscoveryConfig, CACHE_MAX_AGE};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// `~/.neo`, created if absent — holds the snapshot cache and node identity.
pub fn neo_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    let dir = PathBuf::from(home).join(".neo");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Path of the cached snapshot.
pub fn cache_path() -> Result<PathBuf> {
    Ok(neo_dir()?.join("snapshot.bin"))
}

/// Path of the anti-rollback high-water mark (highest accepted `created_at`).
fn hwm_path() -> Result<PathBuf> {
    Ok(neo_dir()?.join("snapshot.hwm"))
}

/// The highest snapshot `created_at` this client has ever accepted (0 if none).
fn read_hwm() -> u64 {
    hwm_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Record a newly-accepted snapshot's `created_at` as the new high-water mark.
fn bump_hwm(created_at: u64) {
    if read_hwm() < created_at {
        if let Ok(p) = hwm_path() {
            let _ = std::fs::write(p, created_at.to_string());
        }
    }
}

/// Anti-rollback decision: a snapshot is acceptable only if it is at least as
/// new as the newest one previously accepted — so an untrusted mirror cannot
/// freeze the client on a stale-but-validly-signed snapshot (e.g. to keep it
/// routing through an already-evicted relay). Pure for testability.
fn accepts_created_at(created_at: u64, hwm: u64) -> bool {
    created_at >= hwm
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(concat!("neo/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HTTP client")
}

/// Obtain a verified snapshot: try each mirror, else a valid cached copy.
pub async fn obtain_snapshot(cfg: &DiscoveryConfig) -> Result<SignedSnapshot> {
    match fetch_verified(cfg).await {
        Ok(snapshot) => {
            if let Err(e) = write_cache(&snapshot) {
                tracing::warn!("could not cache snapshot: {e}");
            }
            Ok(snapshot)
        }
        Err(fetch_err) => match load_cached(cfg) {
            Some(snapshot) => {
                tracing::warn!("all mirrors failed ({fetch_err}); using cached snapshot");
                Ok(snapshot)
            }
            None => Err(fetch_err).context("no mirror reachable and no valid cached snapshot"),
        },
    }
}

/// Fetch `/snapshot` from each mirror in turn; return the first that verifies.
pub async fn fetch_verified(cfg: &DiscoveryConfig) -> Result<SignedSnapshot> {
    let client = http_client()?;
    let now = now_unix();
    let mut last_err = anyhow!("no mirrors configured");

    for mirror in &cfg.mirrors {
        let url = format!("{mirror}/snapshot");
        match fetch_one(&client, &url).await {
            Ok(bytes) => match SignedSnapshot::from_bytes(&bytes) {
                Ok(snapshot) => match snapshot.verify(&cfg.witnesses, cfg.threshold, now) {
                    Ok(()) if !accepts_created_at(snapshot.snapshot.created_at, read_hwm()) => {
                        last_err = anyhow!(
                            "{mirror}: snapshot rolled back (created_at {} < last accepted {})",
                            snapshot.snapshot.created_at,
                            read_hwm()
                        );
                    }
                    Ok(()) => {
                        bump_hwm(snapshot.snapshot.created_at);
                        tracing::info!(
                            mirror = %mirror,
                            relays = snapshot.relays(now).len(),
                            "fetched verified snapshot"
                        );
                        return Ok(snapshot);
                    }
                    Err(e) => last_err = anyhow!("{mirror}: snapshot failed verification: {e}"),
                },
                Err(e) => last_err = anyhow!("{mirror}: malformed snapshot: {e}"),
            },
            Err(e) => last_err = anyhow!("{mirror}: {e}"),
        }
    }
    Err(last_err)
}

async fn fetch_one(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await.context("request failed")?;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }
    Ok(resp.bytes().await.context("reading body")?.to_vec())
}

/// Load and re-verify the cached snapshot, honoring both its own expiry and the
/// local [`CACHE_MAX_AGE`] freshness bound.
pub fn load_cached(cfg: &DiscoveryConfig) -> Option<SignedSnapshot> {
    let path = cache_path().ok()?;
    let bytes = std::fs::read(&path).ok()?;
    let snapshot = SignedSnapshot::from_bytes(&bytes).ok()?;
    let now = now_unix();
    snapshot.verify(&cfg.witnesses, cfg.threshold, now).ok()?;
    // Reject a snapshot that's technically valid but older than we're willing
    // to run on without a refetch, or that would roll back the relay set.
    if now.saturating_sub(snapshot.snapshot.created_at) > CACHE_MAX_AGE.as_secs() {
        return None;
    }
    if !accepts_created_at(snapshot.snapshot.created_at, read_hwm()) {
        return None;
    }
    Some(snapshot)
}

fn write_cache(snapshot: &SignedSnapshot) -> Result<()> {
    let path = cache_path()?;
    std::fs::write(&path, snapshot.to_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Register a relay's signed record with every configured seed mirror.
/// Returns how many accepted it. Failures are logged, not fatal — a relay that
/// reaches even one seed becomes discoverable.
pub async fn register_with_seeds(cfg: &DiscoveryConfig, record: &PeerRecord) -> Result<usize> {
    let client = http_client()?;
    let body = record.to_bytes();
    let mut accepted = 0;
    for mirror in &cfg.mirrors {
        let url = format!("{mirror}/register");
        match client.post(&url).body(body.clone()).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(mirror = %mirror, status = %resp.status(), "registered with seed");
                accepted += 1;
            }
            Ok(resp) => {
                tracing::warn!(mirror = %mirror, status = %resp.status(), "seed rejected registration")
            }
            Err(e) => tracing::warn!(mirror = %mirror, "could not reach seed: {e}"),
        }
    }
    Ok(accepted)
}

/// Choose one relay uniformly at random from a verified list.
pub fn pick_relay(relays: &[&PeerRecord]) -> Option<PeerRecord> {
    if relays.is_empty() {
        return None;
    }
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).ok()?;
    let idx = (u64::from_le_bytes(b) % relays.len() as u64) as usize;
    Some(relays[idx].clone())
}

#[cfg(test)]
mod tests {
    use super::accepts_created_at;

    #[test]
    fn anti_rollback_accepts_newer_or_equal_rejects_older() {
        // First ever snapshot (hwm = 0) is accepted.
        assert!(accepts_created_at(1000, 0));
        // A newer or equal snapshot is accepted.
        assert!(accepts_created_at(2000, 1000));
        assert!(accepts_created_at(1000, 1000));
        // An older (rolled-back) snapshot is rejected.
        assert!(!accepts_created_at(999, 1000));
    }
}
