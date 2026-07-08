//! `neo` — desktop daemon and CLI for macOS and Linux.
//!
//! One cfg-gated binary serves both platforms. `neo run` establishes the
//! PQ-hybrid handshake with a peer over TCP; with `--tun` (and the `tun` feature,
//! run as root) it bridges a real TUN device through the encrypted, mixed tunnel.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use neo_core::NodeIdentity;
use tokio::net::TcpListener;

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
    /// Run a neo node: hand-shake with a peer over TCP (M1), optionally bridging a TUN.
    Run {
        /// Listen for an incoming peer, e.g. `127.0.0.1:9000`.
        #[arg(long, conflicts_with = "connect")]
        listen: Option<String>,
        /// Connect to a peer at this address.
        #[arg(long, conflicts_with = "listen")]
        connect: Option<String>,
        /// Path to this node's identity file (an ephemeral one is used if missing).
        #[arg(long, default_value = "identity.key")]
        identity: PathBuf,
        /// Bridge a TUN device through the tunnel (needs `--features tun` and root).
        #[arg(long)]
        tun: bool,
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
        },
        Command::Run {
            listen,
            connect,
            identity,
            tun,
        } => run(listen, connect, &identity, tun).await?,
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

async fn run(
    listen: Option<String>,
    connect: Option<String>,
    identity_path: &Path,
    tun: bool,
) -> anyhow::Result<()> {
    let identity = load_or_generate_identity(identity_path)?;
    println!("this node : {}", identity.id());

    if tun {
        return run_tunnel_mode(listen, connect, &identity).await;
    }

    match (listen, connect) {
        (Some(addr), None) => {
            let listener = TcpListener::bind(&addr).await?;
            println!("listening on {addr} — waiting for a peer …");
            let peer = neo_node::run::ping_server(&listener, &identity).await?;
            println!(
                "handshake ok — authenticated peer key {}",
                hex::encode(peer)
            );
        }
        (None, Some(addr)) => {
            println!("connecting to {addr} …");
            let peer = neo_node::run::ping_client(&addr, &identity).await?;
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
