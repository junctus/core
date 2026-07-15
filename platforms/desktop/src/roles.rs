//! The discovery-driven node roles: relay and client.
//!
//! - [`run_relay`] is a public node: it listens, publishes a signed record to
//!   the seeds, re-registers on a heartbeat, and **forwards onion traffic** to
//!   the next hop (or delivers it if it is the exit).
//! - [`run_client`] obtains a quorum-verified relay snapshot, picks a relay, and
//!   completes an authenticated handshake — no peer address typed by hand.
//! - [`run_send`] routes a one-shot message through a discovered multi-hop
//!   onion circuit.
//!
//! These build on the M1 handshake (`neo_node::run`) and the onion data plane
//! (`neo_node::forward`); discovery decides *who* to talk to.

use std::collections::HashMap;
use std::io::{Read, Write};
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
/// Heartbeat gap between re-registrations. Kept short so that if a seed loses its
/// in-memory registry (a seed restart), relays re-announce — and are re-attested by
/// the next dial-back — within a couple of minutes instead of lapsing to `relays=0`
/// for a full re-announce cycle. Comfortably below the seed's per-IP register cooldown
/// multiple and far below `RELAY_RECORD_TTL`.
const RELAY_HEARTBEAT: Duration = Duration::from_secs(120);

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
                    println!("delivered {} bytes", payload.len());
                }
                Ok(Served::Message(Outcome::Forwarded { next })) => {
                    tracing::info!("forwarded onion to {next}");
                }
                Ok(Served::Circuit) => tracing::info!("circuit connection closed"),
                Ok(Served::Committee) => tracing::info!("committee circuit handled"),
                Ok(Served::CommitteeLink) => tracing::info!("committee-2pc member link handled"),
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

/// Run as a discovery-configured client: discover a relay and handshake with it.
pub async fn run_client(identity: NodeIdentity, cfg: DiscoveryConfig) -> Result<()> {
    println!("client identity loaded");
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

/// **Committee 2PC-TLS onion fetch** (experimental, audit-gated): fetch `dest` through a
/// self-formed 2-member exit committee, anonymized via a disjoint relay path. Discovers the
/// attested relay pool, picks a lead (an exit relay) + a follower + a disjoint path hop, and
/// runs the client side — the request is XOR-shared across the members and the response is
/// reconstructed from their two shares, so no committee member ever sees the client or the
/// plaintext.
pub async fn run_committee_2pc(
    identity: NodeIdentity,
    cfg: DiscoveryConfig,
    dest: String,
    request: Option<String>,
) -> Result<()> {
    let host = dest
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&dest)
        .to_string();
    let request = request.unwrap_or_else(|| {
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: neo-committee2pc\r\nConnection: close\r\n\r\n")
    });
    println!("this node : {} (committee-2pc client)", identity.id());
    let snapshot = discovery::obtain_snapshot(&cfg).await?;
    let relays = snapshot.relays(now_unix());
    if relays.len() < 4 {
        bail!(
            "committee-2pc needs ≥4 relays (2 committee members + a disjoint path hop for each); found {}",
            relays.len()
        );
    }
    // Shuffle, then pick: lead = an exit-capable relay (it egresses); a follower; and a
    // SEPARATE path hop for each member — all distinct, so the lead's and follower's onion
    // circuits are node-disjoint (no single relay sees the client using both committee
    // halves, which would let it correlate them).
    let mut idx: Vec<usize> = (0..relays.len()).collect();
    for i in (1..idx.len()).rev() {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
        idx.swap(i, (u64::from_le_bytes(b) % (i as u64 + 1)) as usize);
    }
    let lead_pos = idx
        .iter()
        .position(|&i| relays[i].exit)
        .context("no exit-capable relay to lead the committee")?;
    let lead_i = idx.remove(lead_pos);
    let follower_i = idx.remove(0);
    let lead_path_i = idx.remove(0);
    let follower_path_i = idx.remove(0);
    let hop_of = |r: &PeerRecord| -> Result<Hop> {
        Ok(Hop {
            id: r.id,
            sphinx: r.sphinx,
            addr: r.addrs.first().cloned().context("relay has no address")?,
        })
    };
    let lead = hop_of(relays[lead_i])?;
    let follower = hop_of(relays[follower_i])?;
    let lead_path = vec![hop_of(relays[lead_path_i])?];
    let follower_path = vec![hop_of(relays[follower_path_i])?];
    println!(
        "committee: lead {} @ {} (via {}) + follower {} @ {} (via {}) — node-disjoint paths",
        lead.id, lead.addr, lead_path[0].id, follower.id, follower.addr, follower_path[0].id
    );

    let response = neo_node::committee_2pc::committee_2pc_fetch(
        &identity,
        &lead_path,
        &follower_path,
        &lead,
        &follower,
        &dest,
        request.as_bytes(),
    )
    .await?;
    let text = String::from_utf8_lossy(&response);
    let status = text.lines().next().unwrap_or("(no status line)");
    println!("✓ committee 2PC-TLS fetch of {dest} — server responded: {status}");
    println!(
        "  reconstructed {} bytes from the two members' shares — neither member saw the client or the plaintext.",
        response.len()
    );
    Ok(())
}

/// Pick `hops` distinct relays at random and turn them into a circuit, preferring
/// hops in distinct subnets (M36) so one operator can't own the whole path.
fn pick_circuit(relays: &[&PeerRecord], hops: usize) -> Result<Vec<Hop>> {
    // Fisher–Yates over indices ...
    let mut idx: Vec<usize> = (0..relays.len()).collect();
    for i in (1..idx.len()).rev() {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
        let j = (u64::from_le_bytes(b) % (i as u64 + 1)) as usize;
        idx.swap(i, j);
    }
    // ... then front-load subnet-distinct hops so the first `hops` span as many
    // /24s as the relay set allows (best-effort; falls back to repeats otherwise).
    let idx = neo_core::net::prioritize_distinct_subnets(idx, |&i| relays[i].subnet_keys());
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

/// Parse a committee roster file: one member per line,
/// `index node_id_hex sphinx_hex addr` (blank lines and `#` comments ignored).
fn parse_roster(path: &Path) -> Result<Vec<neo_node::committee::CommitteeMemberInfo>> {
    use neo_node::committee::CommitteeMemberInfo;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading roster {}", path.display()))?;
    let mut members = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 4 {
            bail!("roster line must be `index node_id_hex sphinx_hex addr`: {line:?}");
        }
        let index: u8 = parts[0].parse().context("roster member index")?;
        let mut id = [0u8; 32];
        hex::decode_to_slice(parts[1], &mut id).context("roster node id hex")?;
        let mut sphinx = [0u8; 32];
        hex::decode_to_slice(parts[2], &mut sphinx).context("roster sphinx hex")?;
        members.push(CommitteeMemberInfo {
            index,
            id: NodeId::from_bytes(id),
            sphinx,
            addr: parts[3].to_string(),
        });
    }
    if members.is_empty() {
        bail!("committee roster is empty");
    }
    Ok(members)
}

/// `neo committee serve`: join a committee (run DKG so no party holds the key),
/// publish the descriptor, and serve committee-exit circuits — the M28 role.
#[allow(clippy::too_many_arguments)]
pub async fn run_committee_serve(
    identity: NodeIdentity,
    index: u8,
    listen: &str,
    roster_path: &Path,
    threshold: usize,
    out_descriptor: Option<std::path::PathBuf>,
    cfg: DiscoveryConfig,
) -> Result<()> {
    let roster = parse_roster(roster_path)?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    println!(
        "committee member {index}: running DKG with up to {} members …",
        roster.len()
    );
    let (share, descriptor) = neo_node::committee::run_dkg(
        &identity,
        index,
        &roster,
        &listener,
        threshold,
        std::time::Duration::from_secs(30),
    )
    .await?;
    println!(
        "DKG complete — joint key established over {} qualified members; no single party holds it.",
        descriptor.members.len()
    );
    if let Some(path) = out_descriptor {
        std::fs::write(&path, hex::encode(descriptor.to_bytes()))
            .with_context(|| format!("writing descriptor {}", path.display()))?;
        println!("wrote committee descriptor to {}", path.display());
    }
    // Publish the descriptor to the seeds so clients can discover this committee.
    match discovery::publish_committee(&cfg, &descriptor.to_bytes()).await {
        Ok(n) => println!("published committee descriptor to {n} seed(s)"),
        Err(e) => tracing::warn!("could not publish committee: {e}"),
    }

    // Resolve next-hop ids to addresses from the roster.
    let mut addrs: HashMap<NodeId, String> = HashMap::new();
    for m in &descriptor.members {
        addrs.insert(m.id, m.addr.clone());
    }

    println!("serving committee-exit circuits on {listen} — the committee cannot read responses.");
    let identity = Arc::new(identity);
    let share = Arc::new(share);
    let addrs = Arc::new(addrs);
    let replay = Arc::new(std::sync::Mutex::new(ReplayCache::new()));
    loop {
        let (stream, _peer) = listener.accept().await?;
        let identity = identity.clone();
        let share = share.clone();
        let addrs = addrs.clone();
        let replay = replay.clone();
        tokio::spawn(async move {
            let (stream, result) = match neo_node::run::responder_handshake(stream, &identity).await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("committee handshake failed: {e}");
                    return;
                }
            };
            let serving = neo_node::serve::CommitteeServing {
                share: share.as_ref(),
                // A production committee exit fetches the real clearnet
                // destination (SSRF-guarded; no loopback).
                exit: neo_node::committee::ExitBehavior::Clearnet {
                    allow_loopback: false,
                },
            };
            if let Err(e) = neo_node::serve::serve_connection(
                &identity,
                stream,
                result.session,
                addrs.as_ref(),
                &replay,
                ExitPolicy::default(),
                Some(serving),
            )
            .await
            {
                tracing::warn!("committee circuit failed: {e}");
            }
        });
    }
}

/// `neo committee send`: route a request through a committee (from its published
/// descriptor) and print the response the client recovers by combining partials.
pub async fn run_committee_send(
    descriptor_path: Option<std::path::PathBuf>,
    destination: &str,
    message: &str,
    cfg: DiscoveryConfig,
) -> Result<()> {
    let descriptor = match descriptor_path {
        Some(path) => {
            let hexs = std::fs::read_to_string(&path)
                .with_context(|| format!("reading descriptor {}", path.display()))?;
            let bytes = hex::decode(hexs.trim()).context("descriptor hex")?;
            neo_node::committee::CommitteeDescriptor::from_bytes(&bytes)?
        }
        None => {
            // Discover a committee from the seeds and use the first that parses.
            let list = discovery::fetch_committees(&cfg).await?;
            list.iter()
                .find_map(|b| neo_node::committee::CommitteeDescriptor::from_bytes(b).ok())
                .context("no committee available from the seeds (or pass --descriptor)")?
        }
    };
    let identity = NodeIdentity::generate()?;
    println!(
        "routing through a {}-member committee (threshold {}) …",
        descriptor.members.len(),
        descriptor.threshold()
    );
    // Liveness: try k-member subsets with a per-attempt timeout, so an offline
    // member is retried around (needs an over-provisioned n > k committee).
    let response = neo_node::committee::committee_request(
        &identity,
        &descriptor,
        destination,
        message.as_bytes(),
        std::time::Duration::from_secs(30),
        8,
    )
    .await?;
    println!(
        "response ({} bytes): {}",
        response.len(),
        String::from_utf8_lossy(&response)
    );
    println!(
        "recovered by combining the committee's threshold partials — no member could read it."
    );
    Ok(())
}

/// Load an identity from `path`, generating and persisting one if absent.
/// Relays need a stable id, so unlike the ephemeral client default this writes
/// the key back to disk.
pub fn load_or_create_identity(path: &Path) -> Result<NodeIdentity> {
    if path.exists() {
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            bail!(
                "refusing to load identity through symlink {}",
                path.display()
            );
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NOFOLLOW closes the metadata/open race; O_NONBLOCK avoids hanging
            // if an attacker swaps in a FIFO before the open.
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("opening identity {}", path.display()))?;
        if !file.metadata()?.is_file() {
            bail!("identity path is not a regular file: {}", path.display());
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        return Ok(NodeIdentity::from_bytes(&bytes)?);
    }
    let identity = NodeIdentity::generate()?;
    write_secret_file(path, &identity.to_bytes(), false)?;
    println!("generated a new relay identity at {}", path.display());
    Ok(identity)
}

/// Persist secret bytes without a world-readable creation window or symlink
/// following. New files use an atomic no-clobber hard link; replacement renames a
/// same-directory temporary file over the destination.
pub fn write_secret_file(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("secret path has no file name: {}", path.display()))?;
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).context("generating secret-file nonce")?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        hex::encode(nonce)
    ));

    let result = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        if replace {
            #[cfg(windows)]
            if std::fs::symlink_metadata(path).is_ok() {
                std::fs::remove_file(path)?;
            }
            std::fs::rename(&tmp, path)?;
        } else {
            // hard_link is an atomic create-if-absent operation and never follows
            // an existing destination symlink.
            std::fs::hard_link(&tmp, path)?;
            std::fs::remove_file(&tmp)?;
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing secret to {}", path.display()))
}

#[cfg(test)]
mod secret_file_tests {
    use super::*;

    fn path(name: &str) -> std::path::PathBuf {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        std::env::temp_dir().join(format!("neo-{name}-{}", hex::encode(random)))
    }

    #[test]
    fn secret_creation_is_no_clobber_and_owner_only() {
        let path = path("secret");
        write_secret_file(&path, b"first", false).unwrap();
        assert!(write_secret_file(&path, b"second", false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secret_replacement_replaces_a_symlink_instead_of_following_it() {
        use std::os::unix::fs::symlink;
        let target = path("target");
        let link = path("link");
        std::fs::write(&target, b"do not overwrite").unwrap();
        symlink(&target, &link).unwrap();
        write_secret_file(&link, b"new secret", true).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"do not overwrite");
        assert_eq!(std::fs::read(&link).unwrap(), b"new secret");
        std::fs::remove_file(target).unwrap();
        std::fs::remove_file(link).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn identity_loading_rejects_a_symlink() {
        use std::os::unix::fs::symlink;
        let target = path("identity-target");
        let link = path("identity-link");
        let identity = NodeIdentity::generate().unwrap();
        write_secret_file(&target, &identity.to_bytes(), false).unwrap();
        symlink(&target, &link).unwrap();
        assert!(load_or_create_identity(&link).is_err());
        std::fs::remove_file(target).unwrap();
        std::fs::remove_file(link).unwrap();
    }
}
