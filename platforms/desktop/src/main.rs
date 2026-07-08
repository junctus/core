//! `neo` — desktop daemon and CLI for macOS and Linux.
//!
//! One cfg-gated binary serves both platforms; only the TUN backend and service
//! integration differ (added in milestone M1). For now it manages node identity
//! and stubs out `run`.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use neo_core::{NodeIdentity, VERSION};

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
    /// Run the neo node (not implemented yet — arrives in milestone M1).
    Run,
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

fn main() -> anyhow::Result<()> {
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
        Command::Run => {
            tracing::info!("neo {VERSION}");
            anyhow::bail!("`neo run` is not implemented yet (arrives in milestone M1)");
        }
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
