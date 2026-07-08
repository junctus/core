//! `neo` — desktop daemon and CLI for macOS and Linux.
//!
//! One cfg-gated binary serves both platforms; the TUN data plane (in
//! `neo-dataplane`) is added to `run` as milestone M1 is finalized. Today `run`
//! establishes the PQ-hybrid handshake between two peers over TCP and exchanges
//! an encrypted ping/pong — the first version where a session actually flows
//! through neo.

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
    /// Run a neo node: hand-shake with a peer over TCP (M1).
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
        } => run(listen, connect, &identity).await?,
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
) -> anyhow::Result<()> {
    let identity = load_or_generate_identity(identity_path)?;
    println!("this node : {}", identity.id());

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

fn load_or_generate_identity(path: &Path) -> anyhow::Result<NodeIdentity> {
    if path.exists() {
        Ok(NodeIdentity::from_bytes(&std::fs::read(path)?)?)
    } else {
        tracing::warn!("{} not found — using an ephemeral identity", path.display());
        Ok(NodeIdentity::generate()?)
    }
}
