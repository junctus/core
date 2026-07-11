//! The seed's HTTP discovery service.
//!
//! Three endpoints, all cheap, none serving user traffic:
//! - `GET /snapshot` — the current witness-signed [`SignedSnapshot`] (binary).
//!   Cached and re-signed on a timer, so it's a constant-cost static response.
//! - `GET /healthz` — liveness plus the attested relay count.
//! - `GET /witness` — this seed's witness public key (hex), for baking into
//!   clients as a trusted witness.
//! - `POST /register` — a relay submits its signed [`PeerRecord`]; the seed
//!   verifies it, then a background dial-back decides whether to attest it.
//! - `GET|POST /committee` — a bulletin board for M28 committee descriptors
//!   (opaque bytes): members publish, clients fetch and verify. Not a trust root.
//!
//! The service is designed to sit behind a TLS-terminating reverse proxy
//! (Caddy at `discovery.junctus.org`), so it binds plain HTTP on localhost and
//! reads the client IP from `X-Forwarded-For` for per-IP registration
//! cooldowns.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use neo_core::net::AsnDb;
use neo_core::{NodeId, NodeIdentity};
use neo_discovery::snapshot::{manifest_digest, SignedSnapshot, Snapshot, SnapshotDelta};
use neo_discovery::PeerRecord;

use crate::health::dial_back;
use crate::registry::Registry;

/// Maximum accepted `POST /register` body (a record is ~1.4 KB).
const MAX_REGISTER_BODY: usize = 8 * 1024;
/// Maximum accepted `POST /committee` descriptor body.
const MAX_COMMITTEE_BODY: usize = 64 * 1024;
/// Maximum published committee descriptors the seed retains (flood bound).
const MAX_COMMITTEES: usize = 1024;
/// How many recent **distinct** relay sets the seed remembers so it can answer
/// `GET /snapshot/diff` with a delta. A client whose base set is older than this
/// (or otherwise unrecognized) is served a full snapshot instead.
const MAX_DIFF_HISTORY: usize = 64;

/// A remembered relay set for diffing: its [`manifest_digest`] and the `(id, seq)`
/// pairs it contained.
type RelaySetManifest = ([u8; 32], Vec<(NodeId, u64)>);

/// The seed's cached published snapshot plus the state needed to serve diffs.
struct SnapshotCache {
    /// The current signed snapshot (relays are full records from the registry).
    signed: SignedSnapshot,
    /// The current snapshot pre-serialized (compact) for cheap `GET /snapshot`.
    bytes: Vec<u8>,
    /// [`manifest_digest`] of the current relay set — a client sends this back
    /// as its base when it already holds the current set.
    digest: [u8; 32],
    /// Recent distinct relay sets (their `(id, seq)` manifests), newest last, so
    /// a diff can be computed against a client's older base. Bounded by
    /// [`MAX_DIFF_HISTORY`]; unknown bases fall back to a full snapshot.
    history: VecDeque<RelaySetManifest>,
}

impl SnapshotCache {
    /// A placeholder replaced immediately by the first `resign_snapshot`.
    fn empty() -> Self {
        SnapshotCache {
            signed: SignedSnapshot {
                snapshot: Snapshot {
                    created_at: 0,
                    expires_at: 0,
                    relays: vec![],
                },
                signatures: vec![],
            },
            bytes: Vec::new(),
            digest: [0u8; 32],
            history: VecDeque::new(),
        }
    }
}

/// Whether a `/snapshot/diff` response is an incremental delta or a full snapshot.
enum DiffKind {
    Delta,
    Full,
}

/// Tunables for the seed service.
#[derive(Clone, Debug)]
pub struct SeedConfig {
    /// Address to bind the plain-HTTP listener (put TLS in front of it).
    pub bind: SocketAddr,
    /// How often to dial-back every known relay.
    pub health_interval: Duration,
    /// How often to prune, re-sign, and republish the snapshot.
    pub snapshot_interval: Duration,
    /// Minimum gap between registrations from one IP.
    pub register_cooldown: Duration,
    /// Peers whose `X-Forwarded-For` header is trusted (the fronting proxy).
    /// **Only** these sources may set the client IP the cooldown keys on;
    /// everyone else is keyed by their real socket address, so a client cannot
    /// spoof `X-Forwarded-For` to mint unlimited distinct cooldown keys.
    pub trusted_proxies: Vec<IpAddr>,
    /// Permit dial-back to loopback targets (local dev/test only). Production
    /// leaves this `false` so an attacker cannot make the seed dial its own
    /// localhost services (SSRF).
    pub allow_loopback: bool,
    /// Require a registration proof-of-work (M36) in the `X-Neo-Pow` header. A
    /// coarse anti-flood measure; see [`neo_core::pow`]. When enabling this on a
    /// live seed, roll out PoW-capable relays **first** — an older relay binary
    /// sends no proof and would be refused.
    pub require_registration_pow: bool,
    /// Difficulty (leading zero bits) for the registration PoW when required.
    pub registration_pow_bits: u32,
    /// Optional IP→ASN table for the per-ASN attestation cap (M36). `None` (the
    /// default) leaves subnet-only capping; supply an `ip2asn` dataset to also cap
    /// per autonomous system.
    pub asn_db: Option<Arc<AsnDb>>,
    /// Seconds a relay must stay continuously healthy before it is attested (M36
    /// maturation gate). `0` (the default) disables it. A non-zero value raises the
    /// Sybil *time* cost but, because the seed's state is in-memory, blanks the
    /// snapshot for this window after a seed restart — enable it once multiple
    /// independent seeds exist so no single restart empties the network.
    pub min_attestation_maturity: u64,
}

impl Default for SeedConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8899".parse().expect("valid default addr"),
            health_interval: Duration::from_secs(60),
            snapshot_interval: Duration::from_secs(60),
            register_cooldown: Duration::from_secs(30),
            // The seed sits behind a loopback reverse proxy (Caddy) by default.
            trusted_proxies: vec![
                "127.0.0.1".parse().expect("v4 loopback"),
                "::1".parse().expect("v6 loopback"),
            ],
            allow_loopback: false,
            require_registration_pow: true,
            registration_pow_bits: neo_core::pow::REGISTRATION_POW_BITS,
            asn_db: None,
            min_attestation_maturity: 0,
        }
    }
}

/// Shared service state.
struct AppState {
    registry: Mutex<Registry>,
    /// Signs snapshots; its public key is the witness clients trust.
    witness: NodeIdentity,
    /// Dials relays back to prove reachability + key possession.
    prober: NodeIdentity,
    /// The latest signed snapshot plus diff state.
    snapshot: RwLock<SnapshotCache>,
    /// Last registration time per source IP (rate limiting).
    cooldowns: Mutex<HashMap<IpAddr, Instant>>,
    /// Last registration time per relay **key** — bounds a single identity's
    /// registration rate even across many source IPs (the per-IP limit alone is
    /// bypassable with IP diversity).
    key_cooldowns: Mutex<HashMap<NodeId, Instant>>,
    cooldown: Duration,
    /// Proxies whose `X-Forwarded-For` we trust.
    trusted_proxies: Vec<IpAddr>,
    /// Whether dial-back may target loopback (dev/test).
    allow_loopback: bool,
    /// Whether registration requires a valid `X-Neo-Pow` proof (M36).
    require_registration_pow: bool,
    /// Difficulty (leading zero bits) for the registration PoW.
    registration_pow_bits: u32,
    /// Published committee descriptors (M28), stored as opaque bytes — the seed
    /// is a bulletin board here, not a trust root: a client parses and verifies
    /// each (its members are witness-attested relays; a bogus committee just
    /// fails to decrypt). Bounded in count and size against flooding.
    committees: RwLock<Vec<Vec<u8>>>,
}

impl AppState {
    fn resign_snapshot(&self) {
        let signed = self
            .registry
            .lock()
            .expect("registry")
            .sign_snapshot(&self.witness);
        let bytes = signed.to_bytes();
        let digest = manifest_digest(&signed.snapshot.relays);
        let manifest: Vec<(NodeId, u64)> = signed
            .snapshot
            .relays
            .iter()
            .map(|r| (r.id, r.seq))
            .collect();

        let mut cache = self.snapshot.write().expect("snapshot");
        // Record this set in history for diffs, deduping consecutive identical
        // sets (a re-sign with no churn just refreshes timestamps) and capping
        // the ring so it can't grow without bound.
        if cache.history.back().map(|(d, _)| *d) != Some(digest) {
            cache.history.push_back((digest, manifest));
            while cache.history.len() > MAX_DIFF_HISTORY {
                cache.history.pop_front();
            }
        }
        cache.signed = signed;
        cache.bytes = bytes;
        cache.digest = digest;
    }

    /// Compute the `GET /snapshot/diff` response for a client whose base set has
    /// the given fingerprint. Returns the body and whether it is a delta or a
    /// full snapshot. A delta is emitted when the base is the current set (a
    /// tiny timestamp/signature refresh) or a remembered older set; otherwise a
    /// full snapshot is returned. The client verifies whatever it gets, so an
    /// unnecessary full response is never a correctness problem.
    fn snapshot_diff(&self, base: Option<[u8; 32]>) -> (Vec<u8>, DiffKind) {
        let cache = self.snapshot.read().expect("snapshot");
        let Some(base) = base else {
            return (cache.bytes.clone(), DiffKind::Full);
        };
        if base == cache.digest {
            // The client already holds the current set: send an empty-change
            // delta that just carries the fresh timestamps and signatures.
            let delta = SnapshotDelta {
                created_at: cache.signed.snapshot.created_at,
                expires_at: cache.signed.snapshot.expires_at,
                upserts: vec![],
                removed: vec![],
                signatures: cache.signed.signatures.clone(),
            };
            return (delta.to_bytes(), DiffKind::Delta);
        }
        if let Some((_, base_ids)) = cache.history.iter().find(|(d, _)| *d == base) {
            return (
                build_delta(&cache.signed, base_ids).to_bytes(),
                DiffKind::Delta,
            );
        }
        (cache.bytes.clone(), DiffKind::Full)
    }
}

/// Build a delta that turns the client's `base` relay set into `current`'s.
/// Upserts every current record that is new or has a higher seq than the base;
/// removes every base id no longer present. The client applies this and verifies
/// the reconstructed body against the witness signatures, so a wrong delta is
/// caught, not trusted.
fn build_delta(current: &SignedSnapshot, base_ids: &[(NodeId, u64)]) -> SnapshotDelta {
    let base_seq: HashMap<NodeId, u64> = base_ids.iter().copied().collect();
    let current_ids: HashSet<NodeId> = current.snapshot.relays.iter().map(|r| r.id).collect();
    let upserts = current
        .snapshot
        .relays
        .iter()
        .filter(|r| base_seq.get(&r.id).map(|&s| s < r.seq).unwrap_or(true))
        .cloned()
        .collect();
    let removed = base_ids
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| !current_ids.contains(id))
        .collect();
    SnapshotDelta {
        created_at: current.snapshot.created_at,
        expires_at: current.snapshot.expires_at,
        upserts,
        removed,
        signatures: current.signatures.clone(),
    }
}

/// A running seed service handle.
pub struct Seed {
    state: Arc<AppState>,
    config: SeedConfig,
}

impl Seed {
    /// Create a seed with a distinct witness identity and dial-back prober.
    pub fn new(witness: NodeIdentity, prober: NodeIdentity, config: SeedConfig) -> Self {
        let mut registry = Registry::new();
        registry.set_asn_db(config.asn_db.clone());
        registry.set_min_maturity(config.min_attestation_maturity);
        let state = Arc::new(AppState {
            registry: Mutex::new(registry),
            witness,
            prober,
            snapshot: RwLock::new(SnapshotCache::empty()),
            cooldowns: Mutex::new(HashMap::new()),
            key_cooldowns: Mutex::new(HashMap::new()),
            cooldown: config.register_cooldown,
            trusted_proxies: config.trusted_proxies.clone(),
            allow_loopback: config.allow_loopback,
            require_registration_pow: config.require_registration_pow,
            registration_pow_bits: config.registration_pow_bits,
            committees: RwLock::new(Vec::new()),
        });
        // Publish an initial (empty) signed snapshot immediately.
        state.resign_snapshot();
        Self { state, config }
    }

    /// This seed's witness public key, hex-encoded — bake it into clients.
    pub fn witness_hex(&self) -> String {
        hex::encode(self.state.witness.public().signing.to_bytes())
    }

    /// Bind, spawn the background loops, and serve until the process exits.
    pub async fn serve(self) -> neo_core::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.config.bind)
            .await
            .map_err(|e| neo_core::Error::Config(format!("bind {}: {e}", self.config.bind)))?;
        tracing::info!(addr = %self.config.bind, "seed listening");

        spawn_health_loop(self.state.clone(), self.config.health_interval);
        spawn_snapshot_loop(self.state.clone(), self.config.snapshot_interval);

        let app = router(self.state);
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| neo_core::Error::Config(format!("serve: {e}")))
    }
}

/// Build the router over a prepared state (shared by `serve` and tests).
fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/snapshot", get(get_snapshot))
        .route("/snapshot/diff", get(get_snapshot_diff))
        .route("/healthz", get(get_healthz))
        .route("/witness", get(get_witness))
        .route("/register", post(post_register))
        .route(
            "/committee",
            get(get_committees)
                .post(post_committee)
                .layer(DefaultBodyLimit::max(MAX_COMMITTEE_BODY)),
        )
        .layer(DefaultBodyLimit::max(MAX_REGISTER_BODY))
        .with_state(state)
}

async fn get_snapshot(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let bytes = state.snapshot.read().expect("snapshot").bytes.clone();
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes)
}

/// `GET /snapshot/diff?base=<hex32>` — a client that already holds a snapshot
/// sends the [`manifest_digest`] of its relay set as `base` and gets back either
/// a small [`SnapshotDelta`] (header `X-Neo-Diff: delta`) or, when the base is
/// unrecognized, a full [`SignedSnapshot`] (`X-Neo-Diff: full`). The body's own
/// framing is unambiguous, but the header lets the client route without sniffing.
async fn get_snapshot_diff(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
) -> Response {
    let base = query.as_deref().and_then(base_param).and_then(parse_hex32);
    let (bytes, kind) = state.snapshot_diff(base);
    let diff_header = match kind {
        DiffKind::Delta => "delta",
        DiffKind::Full => "full",
    };
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("x-neo-diff", diff_header)
        .body(Body::from(bytes))
        .expect("valid response")
}

/// Extract the `base=` value from a raw query string, if present.
fn base_param(query: &str) -> Option<&str> {
    query.split('&').find_map(|kv| kv.strip_prefix("base="))
}

/// Parse a 32-byte hex fingerprint; `None` on any malformation (→ full snapshot).
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut out).ok()?;
    Some(out)
}

async fn get_healthz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let relays = state.registry.lock().expect("registry").attestable().len();
    (StatusCode::OK, format!("ok relays={relays}\n"))
}

async fn get_witness(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        hex::encode(state.witness.public().signing.to_bytes()),
    )
}

/// `POST /committee` — publish an opaque committee descriptor (M28). The seed
/// stores it as a bulletin board entry; it does not parse or vouch for it (the
/// client does, and its members are witness-attested relays), so this is not a
/// trust root. De-duplicated, size- and count-bounded against flooding.
async fn post_committee(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if body.is_empty() || body.len() > MAX_COMMITTEE_BODY {
        return (StatusCode::BAD_REQUEST, "bad descriptor size\n");
    }
    let mut guard = state.committees.write().expect("committees");
    if guard.iter().any(|d| d.as_slice() == body.as_ref()) {
        return (StatusCode::OK, "already published\n");
    }
    if guard.len() >= MAX_COMMITTEES {
        return (StatusCode::TOO_MANY_REQUESTS, "committee list full\n");
    }
    guard.push(body.to_vec());
    (StatusCode::ACCEPTED, "committee published\n")
}

/// `GET /committee` — the published committee descriptors as
/// `count (u16) || [len (u32) || descriptor bytes]…`. Clients parse and verify.
async fn get_committees(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state.committees.read().expect("committees");
    let mut out = Vec::new();
    out.extend_from_slice(&(guard.len() as u16).to_be_bytes());
    for d in guard.iter() {
        out.extend_from_slice(&(d.len() as u32).to_be_bytes());
        out.extend_from_slice(d);
    }
    ([(header::CONTENT_TYPE, "application/octet-stream")], out)
}

async fn post_register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let ip = client_ip(&headers, peer.ip(), &state.trusted_proxies);
    if !state.check_and_stamp_cooldown(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down\n".to_string());
    }

    let record = match PeerRecord::from_bytes(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad record: {e}\n")),
    };

    // Registration proof-of-work (M36): a coarse anti-flood gate bound to the
    // record's identity. Checked before the (cheap) key cooldown and the (more
    // expensive) signature verification inside `admit`, so an unsolved flood is
    // rejected early.
    if state.require_registration_pow {
        match parse_pow_header(&headers) {
            Some(nonce)
                if neo_core::pow::verify(&record.id, nonce, state.registration_pow_bits) => {}
            Some(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid registration proof-of-work\n".to_string(),
                )
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "missing X-Neo-Pow registration proof-of-work\n".to_string(),
                )
            }
        }
    }

    // Per-key cooldown: bounds one identity's registration rate across IPs.
    if !state.check_and_stamp_key_cooldown(record.id) {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down\n".to_string());
    }

    match state.registry.lock().expect("registry").admit(record) {
        Ok(true) => (
            StatusCode::ACCEPTED,
            "registered — pending dial-back health check\n".to_string(),
        ),
        Ok(false) => (StatusCode::OK, "already current\n".to_string()),
        Err(e) => (StatusCode::BAD_REQUEST, format!("rejected: {e}\n")),
    }
}

impl AppState {
    /// Enforce the per-IP cooldown; records the timestamp when it passes.
    fn check_and_stamp_cooldown(&self, ip: IpAddr) -> bool {
        let mut guard = self.cooldowns.lock().expect("cooldowns");
        let now = Instant::now();
        if let Some(last) = guard.get(&ip) {
            if now.duration_since(*last) < self.cooldown {
                return false;
            }
        }
        guard.insert(ip, now);
        // Opportunistically drop stale entries so the map can't grow forever.
        let cooldown = self.cooldown;
        guard.retain(|_, last| now.duration_since(*last) < cooldown * 4);
        true
    }

    /// Enforce the per-key cooldown; records the timestamp when it passes.
    fn check_and_stamp_key_cooldown(&self, id: NodeId) -> bool {
        let mut guard = self.key_cooldowns.lock().expect("key cooldowns");
        let now = Instant::now();
        if let Some(last) = guard.get(&id) {
            if now.duration_since(*last) < self.cooldown {
                return false;
            }
        }
        guard.insert(id, now);
        let cooldown = self.cooldown;
        guard.retain(|_, last| now.duration_since(*last) < cooldown * 4);
        true
    }
}

/// Parse the `X-Neo-Pow` registration proof-of-work nonce (a decimal `u64`).
fn parse_pow_header(headers: &HeaderMap) -> Option<u64> {
    headers.get("x-neo-pow")?.to_str().ok()?.trim().parse().ok()
}

/// The client IP for rate-limiting. `X-Forwarded-For` is honored **only** when
/// the real socket peer is a trusted proxy; otherwise the socket peer is used,
/// so a direct client cannot spoof the header to dodge the per-IP cooldown.
fn client_ip(headers: &HeaderMap, peer: IpAddr, trusted_proxies: &[IpAddr]) -> IpAddr {
    if !trusted_proxies.contains(&peer) {
        return peer;
    }
    // Trusted proxy: take the right-most entry it appended (the last untrusted
    // hop it observed), not the left-most (which the client controls).
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.rsplit(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(peer)
}

/// Relays dial-backed per sweep, bounding sweep cost against a registration flood.
const MAX_DIAL_PER_SWEEP: usize = 2_000;
/// Concurrent dial-backs in flight (a slow/black-holing relay can't stall the rest).
const DIAL_CONCURRENCY: usize = 64;

fn spawn_health_loop(state: Arc<AppState>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // A slow sweep must not queue up bursts of catch-up ticks.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let mut due = state.registry.lock().expect("registry").due_for_check();
            due.truncate(MAX_DIAL_PER_SWEEP); // bound per-sweep work

            // Dial concurrently in bounded chunks so one black-holing relay can't
            // serialize/starve the health of every other relay.
            for chunk in due.chunks(DIAL_CONCURRENCY) {
                let mut inflight = Vec::with_capacity(chunk.len());
                for record in chunk {
                    let prober = NodeIdentity::from_bytes(&state.prober.to_bytes())
                        .expect("prober round-trips");
                    let record = record.clone();
                    let allow = state.allow_loopback;
                    inflight.push(tokio::spawn(async move {
                        (record.id, dial_back(&prober, &record, allow).await)
                    }));
                }
                for handle in inflight {
                    if let Ok((id, ok)) = handle.await {
                        state
                            .registry
                            .lock()
                            .expect("registry")
                            .record_health(&id, ok);
                    }
                }
            }
            // Re-sign immediately so a newly-healthy (or newly-evicted) relay
            // shows up in `/snapshot` this sweep, not a snapshot-interval later.
            // Keeps `/healthz` and `/snapshot` consistent.
            state.resign_snapshot();
        }
    });
}

fn spawn_snapshot_loop(state: Arc<AppState>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            state.registry.lock().expect("registry").prune_expired();
            state.resign_snapshot();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_discovery::now_unix;

    fn test_state() -> Arc<AppState> {
        test_state_with_pow(false, 0)
    }

    fn test_state_with_pow(
        require_registration_pow: bool,
        registration_pow_bits: u32,
    ) -> Arc<AppState> {
        let state = Arc::new(AppState {
            registry: Mutex::new(Registry::new()),
            witness: NodeIdentity::generate().unwrap(),
            prober: NodeIdentity::generate().unwrap(),
            snapshot: RwLock::new(SnapshotCache::empty()),
            cooldowns: Mutex::new(HashMap::new()),
            key_cooldowns: Mutex::new(HashMap::new()),
            cooldown: Duration::from_secs(30),
            trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
            allow_loopback: true,
            require_registration_pow,
            registration_pow_bits,
            committees: RwLock::new(Vec::new()),
        });
        state.resign_snapshot();
        state
    }

    #[test]
    fn xff_is_ignored_from_an_untrusted_peer() {
        let trusted = ["127.0.0.1".parse().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        // A direct (untrusted) client cannot spoof its rate-limit key.
        let direct: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(client_ip(&headers, direct, &trusted), direct);
        // Behind the trusted proxy, the forwarded IP is honored.
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            client_ip(&headers, proxy, &trusted),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn register_verifies_and_snapshot_serves() {
        let state = test_state();
        let app = router(state.clone());

        // Boot the router on an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // A valid relay record registers.
        let relay = NodeIdentity::generate().unwrap();
        let record = PeerRecord::build_signed(
            &relay,
            vec!["127.0.0.1:9000".into()],
            true,
            false,
            now_unix() + 3600,
            1,
        )
        .unwrap();
        let resp = client
            .post(format!("{base}/register"))
            .body(record.to_bytes())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202);

        // Garbage is rejected.
        let resp = client
            .post(format!("{base}/register"))
            .header("x-forwarded-for", "10.9.9.9")
            .body(vec![1u8, 2, 3])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);

        // The witness key is fetchable and the snapshot verifies against it.
        let witness_hex = client
            .get(format!("{base}/witness"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let mut witness = [0u8; 32];
        hex::decode_to_slice(witness_hex.trim(), &mut witness).unwrap();

        // Force a re-sign so the just-registered (not-yet-healthy) relay state
        // is captured, then fetch and verify the snapshot.
        state.resign_snapshot();
        let bytes = client
            .get(format!("{base}/snapshot"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let signed = SignedSnapshot::from_bytes(&bytes).unwrap();
        signed.verify(&[witness], 1, now_unix()).unwrap();
    }

    #[tokio::test]
    async fn registration_requires_valid_proof_of_work() {
        // A low difficulty keeps the test fast while exercising the real gate.
        let bits = 8;
        let state = test_state_with_pow(true, bits);
        let app = router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        let relay = NodeIdentity::generate().unwrap();
        let record = PeerRecord::build_signed(
            &relay,
            vec!["127.0.0.1:9000".into()],
            true,
            false,
            now_unix() + 3600,
            1,
        )
        .unwrap();

        // Each POST uses a distinct forwarded IP (127.0.0.1 is a trusted proxy) so
        // the per-IP cooldown doesn't mask the PoW gate under test.
        // No proof → refused.
        let resp = client
            .post(format!("{base}/register"))
            .header("x-forwarded-for", "10.0.0.1")
            .body(record.to_bytes())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "registration without PoW is refused");

        // A deterministically wrong nonce → refused.
        let bad = (0..)
            .find(|&n| !neo_core::pow::verify(&relay.id(), n, bits))
            .unwrap();
        let resp = client
            .post(format!("{base}/register"))
            .header("x-forwarded-for", "10.0.0.2")
            .header("x-neo-pow", bad.to_string())
            .body(record.to_bytes())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "an invalid PoW nonce is refused");

        // A valid proof → accepted.
        let nonce = neo_core::pow::solve(&relay.id(), bits).unwrap();
        let resp = client
            .post(format!("{base}/register"))
            .header("x-forwarded-for", "10.0.0.3")
            .header("x-neo-pow", nonce.to_string())
            .body(record.to_bytes())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202, "a valid PoW registers the relay");
    }

    #[test]
    fn snapshot_diff_serves_deltas_and_falls_back_to_full() {
        let state = test_state();
        let trusted = [state.witness.public().signing.to_bytes()];
        let now = now_unix();
        let mk = |id: &NodeIdentity, seq| {
            PeerRecord::build_signed(
                id,
                vec!["127.0.0.1:9000".into()],
                true,
                false,
                now + 3600,
                seq,
            )
            .unwrap()
        };

        // Publish a base snapshot of two healthy relays.
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        {
            let mut reg = state.registry.lock().unwrap();
            reg.admit(mk(&a, 1)).unwrap();
            reg.admit(mk(&b, 1)).unwrap();
            reg.record_health(&a.id(), Some("127.0.0.1:9000".into()));
            reg.record_health(&b.id(), Some("127.0.0.1:9000".into()));
        }
        state.resign_snapshot();

        // The client holds the parsed (compact) base set and its fingerprint.
        let base_bytes = state.snapshot.read().unwrap().bytes.clone();
        let base = SignedSnapshot::from_bytes(&base_bytes).unwrap();
        base.verify(&trusted, 1, now).unwrap();
        let base_relays = base.snapshot.relays.clone();
        let base_digest = manifest_digest(&base_relays);

        // base == current → an empty-change refresh delta that still verifies.
        let (bytes, kind) = state.snapshot_diff(Some(base_digest));
        assert!(matches!(kind, DiffKind::Delta));
        let delta = SnapshotDelta::from_bytes(&bytes).unwrap();
        assert!(delta.upserts.is_empty() && delta.removed.is_empty());
        delta.apply(&base_relays).verify(&trusted, 1, now).unwrap();

        // Churn: evict a, add c, republish.
        let c = NodeIdentity::generate().unwrap();
        {
            let mut reg = state.registry.lock().unwrap();
            reg.admit(mk(&c, 1)).unwrap();
            reg.record_health(&c.id(), Some("127.0.0.1:9000".into()));
            for _ in 0..crate::registry::MAX_STRIKES {
                reg.record_health(&a.id(), None);
            }
        }
        state.resign_snapshot();

        // A client on the OLD base gets a delta that reconstructs the NEW set,
        // and the reconstruction verifies against the witness.
        let (bytes, kind) = state.snapshot_diff(Some(base_digest));
        assert!(matches!(kind, DiffKind::Delta));
        let delta = SnapshotDelta::from_bytes(&bytes).unwrap();
        let reconstructed = delta.apply(&base_relays);
        reconstructed.verify(&trusted, 1, now).unwrap();
        let ids: HashSet<NodeId> = reconstructed.snapshot.relays.iter().map(|r| r.id).collect();
        assert!(ids.contains(&b.id()));
        assert!(ids.contains(&c.id()));
        assert!(!ids.contains(&a.id()));

        // An unrecognized base falls back to a full snapshot.
        let (bytes, kind) = state.snapshot_diff(Some([0x77; 32]));
        assert!(matches!(kind, DiffKind::Full));
        SignedSnapshot::from_bytes(&bytes).unwrap();
    }

    #[tokio::test]
    async fn per_ip_cooldown_blocks_rapid_registrations() {
        let state = test_state();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(state.check_and_stamp_cooldown(ip));
        assert!(!state.check_and_stamp_cooldown(ip));
        // A different IP is unaffected.
        assert!(state.check_and_stamp_cooldown("203.0.113.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn committee_descriptors_publish_and_list() {
        let state = test_state();
        let app = router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // Publish a descriptor; a duplicate is accepted idempotently.
        let resp = client
            .post(format!("{base}/committee"))
            .body(b"committee-descriptor-bytes".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202);
        let resp = client
            .post(format!("{base}/committee"))
            .body(b"committee-descriptor-bytes".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // List returns `count(u16) || [len(u32) || bytes]`.
        let bytes = client
            .get(format!("{base}/committee"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 1);
        let len = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
        assert_eq!(&bytes[6..6 + len], b"committee-descriptor-bytes");
    }
}
