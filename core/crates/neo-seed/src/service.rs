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
//!
//! The service is designed to sit behind a TLS-terminating reverse proxy
//! (Caddy at `discovery.junctus.org`), so it binds plain HTTP on localhost and
//! reads the client IP from `X-Forwarded-For` for per-IP registration
//! cooldowns.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use neo_core::NodeIdentity;
use neo_discovery::PeerRecord;

use crate::health::dial_back;
use crate::registry::Registry;

/// Maximum accepted `POST /register` body (a record is ~1.4 KB).
const MAX_REGISTER_BODY: usize = 8 * 1024;

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
    /// The latest signed snapshot, pre-serialized for cheap serving.
    snapshot_bytes: RwLock<Vec<u8>>,
    /// Last registration time per source IP (rate limiting).
    cooldowns: Mutex<HashMap<IpAddr, Instant>>,
    cooldown: Duration,
    /// Proxies whose `X-Forwarded-For` we trust.
    trusted_proxies: Vec<IpAddr>,
}

impl AppState {
    fn resign_snapshot(&self) {
        let signed = self
            .registry
            .lock()
            .expect("registry")
            .sign_snapshot(&self.witness);
        *self.snapshot_bytes.write().expect("snapshot") = signed.to_bytes();
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
        let state = Arc::new(AppState {
            registry: Mutex::new(Registry::new()),
            witness,
            prober,
            snapshot_bytes: RwLock::new(Vec::new()),
            cooldowns: Mutex::new(HashMap::new()),
            cooldown: config.register_cooldown,
            trusted_proxies: config.trusted_proxies.clone(),
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
        .route("/healthz", get(get_healthz))
        .route("/witness", get(get_witness))
        .route("/register", post(post_register))
        .layer(DefaultBodyLimit::max(MAX_REGISTER_BODY))
        .with_state(state)
}

async fn get_snapshot(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let bytes = state.snapshot_bytes.read().expect("snapshot").clone();
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes)
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

fn spawn_health_loop(state: Arc<AppState>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let due = state.registry.lock().expect("registry").due_for_check();
            for record in due {
                let ok = dial_back(&state.prober, &record).await;
                state
                    .registry
                    .lock()
                    .expect("registry")
                    .record_health(&record.id, ok);
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
    use neo_discovery::snapshot::SignedSnapshot;

    fn test_state() -> Arc<AppState> {
        let state = Arc::new(AppState {
            registry: Mutex::new(Registry::new()),
            witness: NodeIdentity::generate().unwrap(),
            prober: NodeIdentity::generate().unwrap(),
            snapshot_bytes: RwLock::new(Vec::new()),
            cooldowns: Mutex::new(HashMap::new()),
            cooldown: Duration::from_secs(30),
            trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
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
    async fn per_ip_cooldown_blocks_rapid_registrations() {
        let state = test_state();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(state.check_and_stamp_cooldown(ip));
        assert!(!state.check_and_stamp_cooldown(ip));
        // A different IP is unaffected.
        assert!(state.check_and_stamp_cooldown("203.0.113.8".parse().unwrap()));
    }
}
