//! Per-connection relay dispatch.
//!
//! A relay serves both one-shot onion messages and persistent TCP circuits on
//! the same listener. After the handshake, the peer's first sealed frame is a
//! single **mode byte** ([`crate::run::FRAME_MESSAGE`] / [`FRAME_CIRCUIT`]);
//! this reads it and hands the connection to the matching handler, leaving both
//! handlers' internals untouched.

use std::sync::Mutex;

use neo_core::{Error, NodeIdentity, Result};
use neo_crypto::{ReplayCache, Session};
use tokio::net::TcpStream;

use crate::circuit::{serve_circuit, ExitPolicy};
use crate::forward::{handle_onion_shared, NextHop, Outcome};
use crate::run::{read_frame, FRAME_CIRCUIT, FRAME_MESSAGE};

/// What a served connection turned out to be, for the caller to log.
#[derive(Debug)]
pub enum Served {
    /// A one-shot onion message; carries the forward/deliver outcome.
    Message(Outcome),
    /// A persistent circuit, now torn down (relayed or exit-spliced).
    Circuit,
}

/// Read the connection-mode byte and dispatch to the message or circuit handler.
/// `policy` governs exit behaviour and is only consulted on the circuit path.
pub async fn serve_connection<R: NextHop>(
    identity: &NodeIdentity,
    mut stream: TcpStream,
    mut session: Session,
    resolver: &R,
    replay: &Mutex<ReplayCache>,
    policy: ExitPolicy,
) -> Result<Served> {
    let mode = session.open(&read_frame(&mut stream).await?)?;
    match mode.as_slice() {
        [FRAME_MESSAGE] => {
            let outcome =
                handle_onion_shared(identity, &mut stream, &mut session, resolver, replay).await?;
            Ok(Served::Message(outcome))
        }
        [FRAME_CIRCUIT] => {
            serve_circuit(identity, stream, session, resolver, replay, policy).await?;
            Ok(Served::Circuit)
        }
        other => Err(Error::Decode(format!(
            "unknown connection mode {other:?} (expected a single mode byte)"
        ))),
    }
}
