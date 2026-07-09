//! Client-side discovery: obtain a verified relay snapshot, and (for relays)
//! register with seeds.
//!
//! A client's integrity check is the witness signatures on the snapshot, so the
//! transport it arrives over is untrusted — any mirror, CDN, or on-disk cache
//! is acceptable. The order of preference is: fetch fresh from the configured
//! mirrors; if none are reachable, fall back to a still-valid cached snapshot
//! so a client that has run before can bootstrap fully offline of the seeds.
//!
//! When a client already holds a cached snapshot it first asks for a **delta**
//! (`GET /snapshot/diff`) instead of the whole set: it sends its set's
//! fingerprint, applies whatever changed, and re-verifies the reconstructed
//! snapshot against the witnesses. The delta is a pure optimization — any
//! failure (an unreachable endpoint, a plain CDN mirror, a malformed or
//! non-verifying result) falls back to a full fetch, which is verified the same
//! way — so anti-rollback can't be downgraded by forcing the fallback.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use neo_discovery::now_unix;
use neo_discovery::snapshot::{manifest_digest, SignedSnapshot, SnapshotDelta};
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

/// Fetch a verified snapshot from each mirror in turn; return the first that
/// verifies. If a cached snapshot exists it is used as a delta base, so most
/// refreshes transfer only what changed.
pub async fn fetch_verified(cfg: &DiscoveryConfig) -> Result<SignedSnapshot> {
    let client = http_client()?;
    let now = now_unix();
    let hwm = read_hwm();
    let base = cached_base();
    let mut last_err = anyhow!("no mirrors configured");

    for mirror in &cfg.mirrors {
        match fetch_from_mirror(&client, mirror, cfg, base.as_ref(), now, hwm).await {
            Ok(snapshot) => {
                tracing::info!(
                    mirror = %mirror,
                    relays = snapshot.relays(now).len(),
                    "fetched verified snapshot"
                );
                return Ok(snapshot);
            }
            Err(e) => last_err = anyhow!("{mirror}: {e}"),
        }
    }
    Err(last_err)
}

/// Fetch and verify a snapshot from one mirror: try a delta first (if we have a
/// base), then a full `/snapshot`. Both paths verify identically.
async fn fetch_from_mirror(
    client: &reqwest::Client,
    mirror: &str,
    cfg: &DiscoveryConfig,
    base: Option<&SignedSnapshot>,
    now: u64,
    hwm: u64,
) -> Result<SignedSnapshot> {
    if let Some(base) = base {
        if let Some(snapshot) = try_delta(client, mirror, cfg, base, now, hwm).await {
            return Ok(snapshot);
        }
    }
    let body = fetch_one(client, &format!("{mirror}/snapshot")).await?;
    let snapshot = SignedSnapshot::from_bytes(&body).context("malformed snapshot")?;
    accept_snapshot(snapshot, cfg, now, hwm)
}

/// Best-effort delta fetch: request `/snapshot/diff` with our base fingerprint,
/// apply the returned delta (or accept a full snapshot the seed sent instead),
/// and verify the result. Returns `None` on **any** failure so the caller falls
/// back to a full fetch — a delta is only ever an optimization, and the result
/// is verified against the witnesses exactly like a full snapshot.
async fn try_delta(
    client: &reqwest::Client,
    mirror: &str,
    cfg: &DiscoveryConfig,
    base: &SignedSnapshot,
    now: u64,
    hwm: u64,
) -> Option<SignedSnapshot> {
    let digest = manifest_digest(&base.snapshot.relays);
    let url = format!("{mirror}/snapshot/diff?base={}", hex::encode(digest));
    let (body, is_delta) = fetch_with_kind(client, &url).await.ok()?;
    let snapshot = if is_delta {
        SnapshotDelta::from_bytes(&body)
            .ok()?
            .apply(&base.snapshot.relays)
    } else {
        // The seed didn't recognize our base and sent a full snapshot instead.
        SignedSnapshot::from_bytes(&body).ok()?
    };
    accept_snapshot(snapshot, cfg, now, hwm).ok()
}

/// Verify a snapshot (signatures + freshness/anti-rollback) and advance the
/// high-water mark. Shared by the delta and full paths so anti-rollback is
/// enforced identically and cannot be downgraded by forcing a full fallback.
fn accept_snapshot(
    snapshot: SignedSnapshot,
    cfg: &DiscoveryConfig,
    now: u64,
    hwm: u64,
) -> Result<SignedSnapshot> {
    snapshot
        .verify_fresh(&cfg.witnesses, cfg.threshold, now, hwm)
        .context("snapshot failed verification or was rolled back")?;
    bump_hwm(snapshot.snapshot.created_at);
    Ok(snapshot)
}

async fn fetch_one(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await.context("request failed")?;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }
    Ok(resp.bytes().await.context("reading body")?.to_vec())
}

/// Fetch a body and whether the seed marked it a delta (`X-Neo-Diff: delta`)
/// rather than a full snapshot.
async fn fetch_with_kind(client: &reqwest::Client, url: &str) -> Result<(Vec<u8>, bool)> {
    let resp = client.get(url).send().await.context("request failed")?;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }
    let is_delta = resp
        .headers()
        .get("x-neo-diff")
        .map(|v| v.as_bytes() == b"delta")
        .unwrap_or(false);
    Ok((
        resp.bytes().await.context("reading body")?.to_vec(),
        is_delta,
    ))
}

/// The cached snapshot's relay set, to use as a delta base. Parsed only — the
/// reconstructed result is fully verified, so a stale or even corrupt base at
/// worst forces a full-snapshot fallback, never an unverified acceptance.
fn cached_base() -> Option<SignedSnapshot> {
    let bytes = std::fs::read(cache_path().ok()?).ok()?;
    SignedSnapshot::from_bytes(&bytes).ok()
}

/// Load and re-verify the cached snapshot, honoring both its own expiry and the
/// local [`CACHE_MAX_AGE`] freshness bound.
pub fn load_cached(cfg: &DiscoveryConfig) -> Option<SignedSnapshot> {
    let path = cache_path().ok()?;
    let bytes = std::fs::read(&path).ok()?;
    let snapshot = SignedSnapshot::from_bytes(&bytes).ok()?;
    let now = now_unix();
    // Verify signatures + anti-rollback (same check the online paths use).
    snapshot
        .verify_fresh(&cfg.witnesses, cfg.threshold, now, read_hwm())
        .ok()?;
    // Reject a snapshot that's technically valid but older than we're willing
    // to run on without a refetch.
    if now.saturating_sub(snapshot.snapshot.created_at) > CACHE_MAX_AGE.as_secs() {
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
    use super::*;
    use neo_core::NodeIdentity;
    use neo_discovery::snapshot::Snapshot;

    fn witnessed(
        witness: &NodeIdentity,
        relays: Vec<PeerRecord>,
        created_at: u64,
    ) -> SignedSnapshot {
        let snapshot = Snapshot {
            created_at,
            expires_at: created_at + 3600,
            relays,
        };
        let signatures = vec![snapshot.sign(witness)];
        SignedSnapshot {
            snapshot,
            signatures,
        }
    }

    fn cfg_for(witness: &NodeIdentity) -> DiscoveryConfig {
        DiscoveryConfig {
            mirrors: vec!["https://example.invalid".into()],
            witnesses: vec![witness.public().signing.to_bytes()],
            threshold: 1,
        }
    }

    #[test]
    fn delta_applied_to_a_base_verifies_like_a_full_snapshot() {
        // End-to-end of the client delta path without HTTP: a base set, a delta
        // that adds a relay, applied and verified exactly as fetch would.
        let w = NodeIdentity::generate().unwrap();
        let cfg = cfg_for(&w);
        let now = now_unix();

        let a = NodeIdentity::generate().unwrap();
        let base_rec =
            PeerRecord::build_signed(&a, vec!["1.1.1.1:1".into()], true, false, now + 3600, 1)
                .unwrap();
        let base = witnessed(&w, vec![base_rec.clone()], now);

        let b = NodeIdentity::generate().unwrap();
        let added =
            PeerRecord::build_signed(&b, vec!["2.2.2.2:2".into()], true, false, now + 3600, 1)
                .unwrap();
        let mut new_set = vec![base_rec, added.clone()];
        new_set.sort_by(|x, y| x.id.as_bytes().cmp(y.id.as_bytes()));
        let new_snapshot = Snapshot {
            created_at: now + 1,
            expires_at: now + 3601,
            relays: new_set,
        };
        let delta = SnapshotDelta {
            created_at: new_snapshot.created_at,
            expires_at: new_snapshot.expires_at,
            upserts: vec![added],
            removed: vec![],
            signatures: vec![new_snapshot.sign(&w)],
        };

        let reconstructed = delta.apply(&base.snapshot.relays);
        // The client's accept step (verify + anti-rollback) succeeds.
        let accepted = accept_snapshot(reconstructed, &cfg, now, 0).unwrap();
        assert_eq!(accepted.snapshot.relays.len(), 2);
    }

    #[test]
    fn accept_snapshot_enforces_anti_rollback() {
        let w = NodeIdentity::generate().unwrap();
        let cfg = cfg_for(&w);
        let now = now_unix();
        let snap = witnessed(&w, vec![], now);
        // A snapshot older than the high-water mark is refused on both paths.
        assert!(accept_snapshot(snap, &cfg, now, now + 1).is_err());
    }
}
