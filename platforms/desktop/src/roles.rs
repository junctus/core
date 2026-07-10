//! The discovery-driven node roles: relay and client.
//!
//! - [`run_relay`] is a public node: it listens, publishes a signed record to
//!   the seeds, re-registers on a heartbeat, and **forwards onion traffic** to
//!   the next hop (or delivers it if it is the exit).
//! - [`run_client`] is the zero-configuration consumer: it obtains a verified
//!   relay snapshot, picks a relay, and completes an authenticated handshake —
//!   no peer address typed by hand.
//! - [`run_send`] routes a one-shot message through a discovered multi-hop
//!   onion circuit.
//!
//! These build on the M1 handshake (`neo_node::run`) and the onion data plane
//! (`neo_node::forward`); discovery decides *who* to talk to.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use neo_core::{NodeId, NodeIdentity};
use neo_crypto::ReplayCache;
use neo_discovery::{now_unix, PeerRecord};
use neo_node::circuit::ExitPolicy;
use neo_node::forward::{Hop, Outcome};
use neo_node::serve::{serve_connection, Served};

use crate::defaults::DiscoveryConfig;
use crate::discovery;

/// Seconds a relay's published record stays valid; it re-registers well inside
/// this so a healthy relay never lapses out of a snapshot.
const RELAY_RECORD_TTL: u64 = 1800;
/// Heartbeat gap between re-registrations.
const RELAY_HEARTBEAT: Duration = Duration::from_secs(600);

/// A relay's next-hop address book: `NodeId → dialable address`, refreshed from
/// the discovery snapshot so it can forward onions to any known relay.
type Resolver = Arc<RwLock<HashMap<NodeId, String>>>;

/// How often a relay refreshes its forwarding address book from the snapshot.
/// Overridable via `NEO_RESOLVER_REFRESH_SECS` (useful for fast local demos).
fn resolver_refresh() -> Duration {
    let secs = std::env::var("NEO_RESOLVER_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    Duration::from_secs(secs)
}

/// Run as a relay: listen, register with seeds, and forward onion traffic.
pub async fn run_relay(
    identity: NodeIdentity,
    bind: &str,
    announce_addr: Option<String>,
    exit: bool,
    cfg: DiscoveryConfig,
) -> Result<()> {
    let listener = neo_node::netif::listen_scoped(bind)
        .await
        .with_context(|| format!("binding relay listener on {bind}"))?;
    let local = listener.local_addr()?;
    println!("relay {} listening on {local}", identity.id());

    // What we tell the world to dial. Prefer an explicit public address; fall
    // back to the bound address (fine for localhost demos, wrong behind NAT —
    // which is why we warn).
    let advertised = announce_addr.unwrap_or_else(|| {
        tracing::warn!(
            "no --announce-addr given; advertising the bound address {local}. Behind NAT, \
             set --announce-addr to your reachable public host:port."
        );
        local.to_string()
    });

    // Publish the first record, then keep it fresh on a heartbeat.
    let seeds = cfg.clone();
    let heartbeat_identity = NodeIdentity::from_bytes(&identity.to_bytes())?;
    let advertised_hb = advertised.clone();
    tokio::spawn(async move {
        let mut seq = 1u64;
        let mut ticker = tokio::time::interval(RELAY_HEARTBEAT);
        // Consume the immediate first tick; the explicit registration below
        // already covers t=0, so the first heartbeat should be one period out.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match build_record(&heartbeat_identity, &advertised_hb, exit, seq) {
                Ok(record) => {
                    match discovery::register_with_seeds(&seeds, &record).await {
                        Ok(0) => tracing::warn!("no seed accepted this relay's registration"),
                        Ok(n) => tracing::info!("re-registered with {n} seed(s), seq={seq}"),
                        Err(e) => tracing::warn!("registration error: {e}"),
                    }
                    seq += 1;
                }
                Err(e) => tracing::error!("could not build relay record: {e}"),
            }
        }
    });

    // Immediate first registration so the relay is discoverable right away.
    let first = build_record(&identity, &advertised, exit, 0)?;
    match discovery::register_with_seeds(&cfg, &first).await {
        Ok(0) => println!("warning: no seed accepted the registration yet (will retry)"),
        Ok(n) => println!("registered with {n} seed(s) as {advertised}"),
        Err(e) => println!("warning: registration failed ({e}); will retry on heartbeat"),
    }

    // Keep an address book of known relays so we can forward onions to the next
    // hop. Refreshed from the (witness-verified) snapshot in the background.
    let resolver: Resolver = Arc::new(RwLock::new(HashMap::new()));
    spawn_resolver_refresh(cfg.clone(), resolver.clone());

    // One replay cache for the relay's whole lifetime, shared across every
    // connection — so a Sphinx packet replayed on a *new* connection is
    // rejected (a per-connection cache would make replay defense a no-op).
    let replay = Arc::new(std::sync::Mutex::new(ReplayCache::new()));

    // Serve onions forever. The accept loop only does the cheap `listener.accept()`;
    // the (slow) responder handshake and onion handling run in a spawned task, so a
    // slowloris client can't head-of-line-block new connections. A semaphore bounds
    // concurrent in-flight handshakes so a connection flood can't exhaust the host.
    let identity = Arc::new(identity);
    let handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HANDSHAKES));
    // Production exit policy: never splice to non-public targets, and only offer
    // clearnet exit at all when this relay was started with `--exit`.
    let policy = ExitPolicy {
        allow_loopback: false,
        offer_exit: exit,
    };
    println!(
        "serving onions and circuits{} (Ctrl-C to stop)",
        if exit {
            " — clearnet exit enabled"
        } else {
            ""
        }
    );
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                continue;
            }
        };
        // Over the concurrency cap: drop this connection rather than queue unbounded.
        let Ok(permit) = handshakes.clone().try_acquire_owned() else {
            tracing::warn!("handshake concurrency cap reached; dropping a connection");
            continue;
        };
        let identity = identity.clone();
        let resolver = resolver.clone();
        let replay = replay.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the connection finishes
            let (stream, result) = match neo_node::run::responder_handshake(stream, &identity).await
            {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("handshake failed: {e}");
                    return;
                }
            };
            // Snapshot the address book so the borrow doesn't cross await.
            let addrs = resolver.read().expect("resolver lock").clone();
            // A plain relay is not a committee member (no share), so it refuses
            // committee circuits — passes `None`. The `neo run --committee` role
            // supplies its share here.
            match serve_connection(
                &identity,
                stream,
                result.session,
                &addrs,
                &replay,
                policy,
                None,
            )
            .await
            {
                Ok(Served::Message(Outcome::Delivered { payload })) => {
                    println!(
                        "delivered {} bytes: {}",
                        payload.len(),
                        String::from_utf8_lossy(&payload)
                    );
                }
                Ok(Served::Message(Outcome::Forwarded { next })) => {
                    tracing::info!("forwarded onion to {next}");
                }
                Ok(Served::Circuit) => tracing::info!("circuit connection closed"),
                Ok(Served::Committee) => tracing::info!("committee circuit handled"),
                Err(e) => tracing::warn!("connection handling failed: {e}"),
            }
        });
    }
}

/// Concurrent responder handshakes a relay allows in flight, bounding memory/FD use.
const MAX_CONCURRENT_HANDSHAKES: usize = 512;

/// Background task: periodically rebuild the relay's `NodeId → addr` book from
/// the verified snapshot so it can forward to any healthy relay.
fn spawn_resolver_refresh(cfg: DiscoveryConfig, resolver: Resolver) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(resolver_refresh());
        loop {
            ticker.tick().await;
            match discovery::obtain_snapshot(&cfg).await {
                Ok(snapshot) => {
                    let now = now_unix();
                    let map: HashMap<NodeId, String> = snapshot
                        .relays(now)
                        .into_iter()
                        .filter_map(|r| r.addrs.first().map(|a| (r.id, a.clone())))
                        .collect();
                    let count = map.len();
                    *resolver.write().expect("resolver lock") = map;
                    tracing::debug!("forwarding table refreshed: {count} relay(s)");
                }
                Err(e) => tracing::warn!("could not refresh forwarding table: {e}"),
            }
        }
    });
}

fn build_record(
    identity: &NodeIdentity,
    advertised: &str,
    exit: bool,
    seq: u64,
) -> Result<PeerRecord> {
    PeerRecord::build_signed(
        identity,
        vec![advertised.to_string()],
        true,
        exit,
        now_unix() + RELAY_RECORD_TTL,
        seq,
    )
    .context("signing relay record")
}

/// Run as a zero-configuration client: discover a relay and handshake with it.
pub async fn run_client(identity: NodeIdentity, cfg: DiscoveryConfig) -> Result<()> {
    println!("this node : {} (client)", identity.id());
    println!("discovering relays via {} mirror(s)…", cfg.mirrors.len());

    let snapshot = discovery::obtain_snapshot(&cfg).await?;
    let now = now_unix();
    let relays = snapshot.relays(now);
    println!(
        "verified snapshot: {} relay(s), signed by {}/{} required witnesses",
        relays.len(),
        cfg.witnesses.len().min(snapshot.signatures.len()),
        cfg.threshold
    );

    let relay = discovery::pick_relay(&relays)
        .context("the verified snapshot contains no usable relay yet")?;
    let addr = relay
        .addrs
        .first()
        .cloned()
        .context("chosen relay advertises no address")?;

    println!("connecting to relay {} at {addr} …", relay.id);
    // connect_verified requires the relay to authenticate as exactly the identity
    // the snapshot vouched for: it checks the full NodeId, recomputed in-band from
    // all three of the relay's long-term keys (including the ML-KEM key a compact
    // record omits), against the witness-trusted `id`. That is what makes compact
    // records safe — the key commitment the snapshot could not carry is verified
    // here against live keys, with no extra round trip — and it subsumes a
    // signing-key check, since `id` is a BLAKE3 commitment to the signing key.
    let (_stream, _result) = neo_node::run::connect_verified(&addr, &identity, &relay.id).await?;
    println!("handshake ok — authenticated relay {}", relay.id.to_hex());
    println!("discovery works: found and connected to a relay with zero manual configuration.");
    Ok(())
}

/// Send a one-shot onion message through a discovered multi-hop circuit.
///
/// Discovers relays, builds a `hops`-relay Sphinx circuit (the last hop is the
/// exit that receives the message), and hands the onion to the first hop. Each
/// relay forwards a peeled layer to the next; only the exit sees the payload.
pub async fn run_send(
    identity: NodeIdentity,
    cfg: DiscoveryConfig,
    message: String,
    hops: usize,
) -> Result<()> {
    if hops == 0 {
        bail!("a circuit needs at least one hop");
    }
    println!("this node : {} (sender)", identity.id());
    let snapshot = discovery::obtain_snapshot(&cfg).await?;
    let now = now_unix();
    let relays = snapshot.relays(now);
    if relays.len() < hops {
        bail!(
            "need {hops} relays for the circuit, discovered only {}",
            relays.len()
        );
    }

    let circuit = pick_circuit(&relays, hops)?;
    println!("routing through a {}-hop circuit:", circuit.len());
    for (i, hop) in circuit.iter().enumerate() {
        let role = if i + 1 == circuit.len() {
            "exit"
        } else {
            "relay"
        };
        println!("  hop {} ({role}): {} @ {}", i + 1, hop.id, hop.addr);
    }

    neo_node::forward::send_onion(&identity, &circuit, message.as_bytes()).await?;
    println!(
        "onion handed to the first hop — each relay peels one layer and forwards; \
         the exit delivers the message. No relay on the path can read it."
    );
    Ok(())
}

/// Pick `hops` distinct relays at random and turn them into a circuit.
fn pick_circuit(relays: &[&PeerRecord], hops: usize) -> Result<Vec<Hop>> {
    // Fisher–Yates over indices, then take the first `hops`.
    let mut idx: Vec<usize> = (0..relays.len()).collect();
    for i in (1..idx.len()).rev() {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
        let j = (u64::from_le_bytes(b) % (i as u64 + 1)) as usize;
        idx.swap(i, j);
    }
    idx.into_iter()
        .take(hops)
        .map(|i| {
            let r = relays[i];
            let addr = r
                .addrs
                .first()
                .cloned()
                .context("a chosen relay advertises no address")?;
            Ok(Hop {
                id: r.id,
                sphinx: r.sphinx,
                addr,
            })
        })
        .collect()
}

/// Load an identity from `path`, generating and persisting one if absent.
/// Relays need a stable id, so unlike the ephemeral client default this writes
/// the key back to disk.
pub fn load_or_create_identity(path: &Path) -> Result<NodeIdentity> {
    if path.exists() {
        return Ok(NodeIdentity::from_bytes(&std::fs::read(path)?)?);
    }
    let identity = NodeIdentity::generate()?;
    std::fs::write(path, identity.to_bytes())
        .with_context(|| format!("writing identity to {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("generated a new relay identity at {}", path.display());
    Ok(identity)
}
