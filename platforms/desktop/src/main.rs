//! `neo` — desktop daemon and CLI for macOS and Linux.
//!
//! One cfg-gated binary serves both platforms. `neo run` establishes the
//! PQ-hybrid handshake with a peer over TCP; with `--tun` (and the `tun` feature,
//! run as root) it bridges a real TUN device through the encrypted, mixed tunnel.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use neo_core::NodeIdentity;
use tokio::net::TcpListener;

mod defaults;
mod discovery;
mod doh;
mod roles;

#[derive(Parser)]
#[command(
    name = "neo",
    version,
    about = "neo — a dispersed, post-quantum privacy overlay"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage this node's long-term identity.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Run a neo node.
    ///
    /// With no flags, runs as a **client**: discovers relays from the seed
    /// mirrors and connects — zero configuration. With `--relay`, runs as a
    /// public relay that registers with the seeds. `--listen`/`--connect` still
    /// drive the manual two-process M1 handshake for local testing.
    Run {
        /// Run as a public relay: register with seeds and serve handshakes.
        #[arg(long, conflicts_with = "connect")]
        relay: bool,
        /// Public `host:port` to advertise to clients (relay mode; defaults to
        /// the bound address with a warning — set this behind NAT).
        #[arg(long)]
        announce_addr: Option<String>,
        /// Offer clearnet exit (relay mode, opt-in, off by default).
        #[arg(long)]
        exit: bool,
        /// Listen address: the relay bind (relay mode) or manual M1 responder.
        #[arg(long, conflicts_with = "connect")]
        listen: Option<String>,
        /// Connect to a peer at this address (manual M1 initiator).
        #[arg(long, conflicts_with = "listen")]
        connect: Option<String>,
        /// Override discovery mirror base URLs (repeatable; else NEO_MIRRORS/baked).
        #[arg(long = "mirror")]
        mirrors: Vec<String>,
        /// Override trusted witness keys, hex (repeatable; else NEO_WITNESSES/baked).
        #[arg(long = "witness")]
        witnesses: Vec<String>,
        /// Required distinct witness signatures on a snapshot.
        #[arg(long)]
        threshold: Option<usize>,
        /// Path to this node's identity file.
        #[arg(long, default_value = "identity.key")]
        identity: PathBuf,
        /// Bridge a TUN device through the tunnel (needs `--features tun` and root).
        #[arg(long)]
        tun: bool,
    },
    /// Run a discovery seed: verify, health-check, and attest relays; serve
    /// signed snapshots over HTTP. Relays no user traffic. Put TLS in front.
    Seed {
        /// Plain-HTTP bind address (a reverse proxy terminates TLS).
        #[arg(long, default_value = "127.0.0.1:8899")]
        bind: String,
        /// Witness identity file (its public key is what clients trust).
        #[arg(long, default_value = "witness.key")]
        witness: PathBuf,
        /// Seconds between dial-back health checks of known relays.
        #[arg(long, default_value_t = 60)]
        health_interval: u64,
        /// Seconds between snapshot prune + re-sign + publish.
        #[arg(long, default_value_t = 60)]
        snapshot_interval: u64,
        /// Minimum seconds between registrations from one IP (0 disables;
        /// useful for local multi-relay demos where all relays share 127.0.0.1).
        #[arg(long, default_value_t = 30)]
        register_cooldown: u64,
        /// Permit dial-back to loopback relays (local dev/test only). Off by
        /// default so an attacker cannot make a public seed dial its own
        /// localhost services (SSRF).
        #[arg(long, default_value_t = false)]
        allow_loopback: bool,
    },
    /// Fetch, verify, and print the current relay snapshot (diagnostics).
    Snapshot {
        /// Override discovery mirror base URLs (repeatable).
        #[arg(long = "mirror")]
        mirrors: Vec<String>,
        /// Override trusted witness keys, hex (repeatable).
        #[arg(long = "witness")]
        witnesses: Vec<String>,
        /// Required distinct witness signatures.
        #[arg(long)]
        threshold: Option<usize>,
    },
    /// Send a one-shot message through a multi-hop onion circuit of discovered
    /// relays. Each relay peels one layer and forwards; only the exit reads it.
    Send {
        /// The message to deliver to the exit.
        #[arg(long)]
        message: String,
        /// Relays in the circuit (the last one is the exit).
        #[arg(long, default_value_t = 2)]
        hops: usize,
        /// Override discovery mirror base URLs (repeatable).
        #[arg(long = "mirror")]
        mirrors: Vec<String>,
        /// Override trusted witness keys, hex (repeatable).
        #[arg(long = "witness")]
        witnesses: Vec<String>,
        /// Required distinct witness signatures.
        #[arg(long)]
        threshold: Option<usize>,
    },
    /// Operator: sign a bootstrap record (current mirrors + witnesses) with a
    /// bootstrap key and print the DNS TXT value to publish for DoH rendezvous.
    BootstrapRecord {
        /// Bootstrap signing identity (long-lived; its public key is baked into clients).
        #[arg(long, default_value = "bootstrap.key")]
        identity: PathBuf,
        /// Current discovery mirror base URLs (repeatable).
        #[arg(long = "mirror", required = true)]
        mirrors: Vec<String>,
        /// Current trusted witness keys, hex (repeatable).
        #[arg(long = "witness", required = true)]
        witnesses: Vec<String>,
    },
    /// Fetch and verify current mirrors + witnesses over DNS-over-HTTPS.
    BootstrapResolve {
        /// DoH JSON resolver endpoint.
        #[arg(long, default_value = "https://cloudflare-dns.com/dns-query")]
        resolver: String,
        /// TXT record name to look up (e.g. `_neo-bootstrap.junctus.org`).
        #[arg(long)]
        name: String,
        /// Trusted bootstrap public key(s), hex (repeatable).
        #[arg(long = "key", required = true)]
        keys: Vec<String>,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a fresh PQ-hybrid node identity and write it to a file.
    Generate {
        /// Path to write the secret identity to.
        #[arg(long, default_value = "identity.key")]
        output: PathBuf,
        /// Overwrite the output file if it already exists.
        #[arg(long)]
        force: bool,
    },
    /// Show an identity's public info: node id and witness (signing) key.
    Show {
        /// Path to the identity file to read.
        #[arg(long, default_value = "identity.key")]
        identity: PathBuf,
        /// Print only the witness key hex (for scripting).
        #[arg(long)]
        witness_only: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Identity { action } => match action {
            IdentityAction::Generate { output, force } => generate_identity(&output, force)?,
            IdentityAction::Show {
                identity,
                witness_only,
            } => show_identity(&identity, witness_only)?,
        },
        Command::Run {
            relay,
            announce_addr,
            exit,
            listen,
            connect,
            mirrors,
            witnesses,
            threshold,
            identity,
            tun,
        } => {
            run_command(RunArgs {
                relay,
                announce_addr,
                exit,
                listen,
                connect,
                mirrors,
                witnesses,
                threshold,
                identity,
                tun,
            })
            .await?
        }
        Command::Seed {
            bind,
            witness,
            health_interval,
            snapshot_interval,
            register_cooldown,
            allow_loopback,
        } => {
            run_seed(
                &bind,
                &witness,
                health_interval,
                snapshot_interval,
                register_cooldown,
                allow_loopback,
            )
            .await?
        }
        Command::Snapshot {
            mirrors,
            witnesses,
            threshold,
        } => show_snapshot(&mirrors, &witnesses, threshold).await?,
        Command::Send {
            message,
            hops,
            mirrors,
            witnesses,
            threshold,
        } => {
            let cfg = defaults::DiscoveryConfig::resolve(&mirrors, &witnesses, threshold)?;
            let identity = NodeIdentity::generate()?;
            roles::run_send(identity, cfg, message, hops).await?
        }
        Command::BootstrapRecord {
            identity,
            mirrors,
            witnesses,
        } => bootstrap_record(&identity, mirrors, &witnesses)?,
        Command::BootstrapResolve {
            resolver,
            name,
            keys,
        } => bootstrap_resolve(&resolver, &name, &keys).await?,
    }
    Ok(())
}

/// Operator: sign a bootstrap record and print the TXT value to publish.
fn bootstrap_record(
    identity_path: &Path,
    mirrors: Vec<String>,
    witness_hexes: &[String],
) -> anyhow::Result<()> {
    use neo_discovery::bootstrap::BootstrapRecord;
    use neo_discovery::now_unix;

    let identity = roles::load_or_create_identity(identity_path)?;
    let witnesses = decode_keys(witness_hexes)?;
    let record = BootstrapRecord::sign(&identity, now_unix(), mirrors, witnesses)?;

    println!(
        "bootstrap key : {}",
        hex::encode(identity.public().signing.to_bytes())
    );
    println!("\nPublish this as a DNS TXT record (split into 255-char strings if needed),");
    println!("then clients resolve it over DoH. TXT value:\n");
    println!("{}", record.to_txt());
    Ok(())
}

/// Client/diagnostic: fetch + verify current mirrors and witnesses over DoH.
async fn bootstrap_resolve(resolver: &str, name: &str, key_hexes: &[String]) -> anyhow::Result<()> {
    let keys = decode_keys(key_hexes)?;
    let (mirrors, witnesses) = doh::resolve_via_doh(resolver, name, &keys, 0).await?;
    println!("verified bootstrap for {name}:");
    println!("  mirrors   : {mirrors:?}");
    println!("  witnesses : {}", witnesses.len());
    for w in &witnesses {
        println!("    {}", hex::encode(w));
    }
    Ok(())
}

/// Decode a list of 64-hex-char Ed25519 keys into 32-byte arrays.
fn decode_keys(hexes: &[String]) -> anyhow::Result<Vec<[u8; 32]>> {
    hexes
        .iter()
        .map(|h| {
            let mut key = [0u8; 32];
            hex::decode_to_slice(h.trim(), &mut key)
                .map_err(|e| anyhow::anyhow!("invalid key hex {h}: {e}"))?;
            Ok(key)
        })
        .collect()
}

/// Parsed arguments for `neo run`.
struct RunArgs {
    relay: bool,
    announce_addr: Option<String>,
    exit: bool,
    listen: Option<String>,
    connect: Option<String>,
    mirrors: Vec<String>,
    witnesses: Vec<String>,
    threshold: Option<usize>,
    identity: PathBuf,
    tun: bool,
}

/// Dispatch `neo run` to the right role: TUN tunnel, manual M1, relay, or the
/// zero-configuration client.
async fn run_command(args: RunArgs) -> anyhow::Result<()> {
    // Manual/TUN modes keep the original explicit-peer behavior.
    if args.tun || (!args.relay && (args.listen.is_some() || args.connect.is_some())) {
        let identity = load_or_generate_identity(&args.identity)?;
        println!("this node : {}", identity.id());
        if args.tun {
            return run_tunnel_mode(args.listen, args.connect, &identity).await;
        }
        return run(args.listen, args.connect, &identity).await;
    }

    let cfg = defaults::DiscoveryConfig::resolve(&args.mirrors, &args.witnesses, args.threshold);

    if args.relay {
        let identity = roles::load_or_create_identity(&args.identity)?;
        let bind = args.listen.as_deref().unwrap_or("0.0.0.0:9000");
        let cfg = cfg?;
        return roles::run_relay(identity, bind, args.announce_addr, args.exit, cfg).await;
    }

    // Client: an ephemeral identity keeps the client unlinkable across runs.
    let identity = NodeIdentity::generate()?;
    roles::run_client(identity, cfg?).await
}

async fn run_seed(
    bind: &str,
    witness_path: &Path,
    health_interval: u64,
    snapshot_interval: u64,
    register_cooldown: u64,
    allow_loopback: bool,
) -> anyhow::Result<()> {
    use std::time::Duration;

    use neo_seed::{Seed, SeedConfig};

    let witness = roles::load_or_create_identity(witness_path)?;
    // The dial-back prober is ephemeral: relays only care that *someone*
    // completed the handshake as them, not who probed.
    let prober = NodeIdentity::generate()?;
    let config = SeedConfig {
        bind: bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --bind {bind}: {e}"))?,
        health_interval: Duration::from_secs(health_interval.max(1)),
        snapshot_interval: Duration::from_secs(snapshot_interval.max(1)),
        register_cooldown: Duration::from_secs(register_cooldown),
        allow_loopback,
        ..SeedConfig::default()
    };
    let seed = Seed::new(witness, prober, config);
    println!("seed witness key : {}", seed.witness_hex());
    println!("bake this into BAKED_WITNESSES (or share via NEO_WITNESSES) so clients trust it");
    println!("serving discovery on {bind} (no user traffic; put TLS in front)");
    seed.serve().await.map_err(Into::into)
}

async fn show_snapshot(
    mirrors: &[String],
    witnesses: &[String],
    threshold: Option<usize>,
) -> anyhow::Result<()> {
    let cfg = defaults::DiscoveryConfig::resolve(mirrors, witnesses, threshold)?;
    let snapshot = discovery::fetch_verified(&cfg).await?;
    let now = neo_discovery::now_unix();
    let relays = snapshot.relays(now);
    println!(
        "verified snapshot — created {}s ago, expires in {}s",
        now.saturating_sub(snapshot.snapshot.created_at),
        snapshot.snapshot.expires_at.saturating_sub(now),
    );
    println!("witness signatures : {}", snapshot.signatures.len());
    println!("relays             : {}", relays.len());
    for relay in relays {
        println!(
            "  {} {}  exit={}  addrs={:?}",
            relay.id,
            hex::encode(&relay.signing[..8]),
            relay.exit,
            relay.addrs
        );
    }
    Ok(())
}

fn generate_identity(output: &Path, force: bool) -> anyhow::Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "{} already exists — use --force to overwrite",
            output.display()
        );
    }

    let identity = NodeIdentity::generate()?;
    let bytes = identity.to_bytes();
    std::fs::write(output, &bytes)?;

    // Restrict the secret to the owner on Unix; other platforms fall back to defaults.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o600))?;
    }

    println!("node id : {}", identity.id());
    println!(
        "written : {} ({} bytes, PQ-hybrid)",
        output.display(),
        bytes.len()
    );
    println!("keep this file secret — it is the node's long-term identity");
    Ok(())
}

/// Print an identity's public info. The **witness key** is the Ed25519 signing
/// public key clients trust (what `GET /witness` and `NEO_WITNESSES` use), so a
/// seed operator can read it straight from the key file without the service
/// running.
fn show_identity(path: &Path, witness_only: bool) -> anyhow::Result<()> {
    let identity = NodeIdentity::from_bytes(&std::fs::read(path)?)?;
    let witness = hex::encode(identity.public().signing.to_bytes());
    if witness_only {
        println!("{witness}");
    } else {
        println!("node id     : {}", identity.id());
        println!("witness key : {witness}");
    }
    Ok(())
}

/// The manual, explicit-peer M1 handshake (`--listen` / `--connect`).
async fn run(
    listen: Option<String>,
    connect: Option<String>,
    identity: &NodeIdentity,
) -> anyhow::Result<()> {
    match (listen, connect) {
        (Some(addr), None) => {
            let listener = TcpListener::bind(&addr).await?;
            println!("listening on {addr} — waiting for a peer …");
            let peer = neo_node::run::ping_server(&listener, identity).await?;
            println!(
                "handshake ok — authenticated peer key {}",
                hex::encode(peer)
            );
        }
        (None, Some(addr)) => {
            println!("connecting to {addr} …");
            let peer = neo_node::run::ping_client(&addr, identity).await?;
            println!(
                "handshake ok — authenticated peer key {}",
                hex::encode(peer)
            );
        }
        _ => anyhow::bail!("specify exactly one of --listen or --connect"),
    }
    Ok(())
}

#[cfg(feature = "tun")]
async fn run_tunnel_mode(
    listen: Option<String>,
    connect: Option<String>,
    identity: &NodeIdentity,
) -> anyhow::Result<()> {
    use neo_core::PrivacyLevel;
    use neo_mix::MixParams;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    // Establish the session with the peer.
    let (stream, handshake) = match (listen, connect) {
        (Some(addr), None) => {
            let listener = TcpListener::bind(&addr).await?;
            println!("listening (tun) on {addr} — waiting for a peer …");
            neo_node::run::accept(&listener, identity).await?
        }
        (None, Some(addr)) => {
            println!("connecting (tun) to {addr} …");
            neo_node::run::connect(&addr, identity).await?
        }
        _ => anyhow::bail!("specify exactly one of --listen or --connect"),
    };
    println!(
        "handshake ok — peer {}",
        hex::encode(handshake.peer.to_bytes())
    );

    // Open the TUN device (requires root).
    let device = neo_dataplane::TunDevice::open("utun9", Ipv4Addr::new(10, 9, 0, 2), 24, 1400)?;
    println!("tun up — bridging traffic through the tunnel (Ctrl-C to stop)");

    let (app_out_tx, app_out_rx) = mpsc::channel(256);
    let (app_in_tx, app_in_rx) = mpsc::channel(256);
    let (wire_out_tx, mut wire_out_rx) = mpsc::channel::<Vec<u8>>(256);
    let (wire_in_tx, wire_in_rx) = mpsc::channel::<Vec<u8>>(256);

    // Bridge the TCP transport to the tunnel's wire channels.
    let (mut reader, mut writer) = stream.into_split();
    tokio::spawn(async move {
        while let Ok(frame) = neo_node::run::read_frame(&mut reader).await {
            if wire_in_tx.send(frame).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(frame) = wire_out_rx.recv().await {
            if neo_node::run::write_frame(&mut writer, &frame)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Bridge the TUN device to the tunnel's packet channels.
    tokio::spawn(neo_node::tunnel::bridge_packet_io(
        device, app_out_tx, app_in_rx,
    ));

    let mix = MixParams::for_level(PrivacyLevel::Balanced);
    neo_node::tunnel::run_tunnel(
        handshake.session,
        mix,
        app_out_rx,
        wire_out_tx,
        wire_in_rx,
        app_in_tx,
    )
    .await?;
    Ok(())
}

#[cfg(not(feature = "tun"))]
async fn run_tunnel_mode(
    _listen: Option<String>,
    _connect: Option<String>,
    _identity: &NodeIdentity,
) -> anyhow::Result<()> {
    anyhow::bail!("--tun requires building with `--features tun` and running as root")
}

fn load_or_generate_identity(path: &Path) -> anyhow::Result<NodeIdentity> {
    if path.exists() {
        Ok(NodeIdentity::from_bytes(&std::fs::read(path)?)?)
    } else {
        tracing::warn!("{} not found — using an ephemeral identity", path.display());
        Ok(NodeIdentity::generate()?)
    }
}
