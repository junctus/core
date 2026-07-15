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
use neo_mpc::vss::KeyShare;
use tokio::net::TcpStream;

use crate::circuit::{serve_circuit, ExitPolicy};
use crate::committee::{handle_committee_circuit, ExitBehavior};
use crate::forward::{handle_onion_shared, NextHop, Outcome};
use crate::run::{read_frame, FRAME_CIRCUIT, FRAME_COMMITTEE, FRAME_MESSAGE};

/// A node's committee membership, supplied to [`serve_connection`] when it should
/// also serve committee-exit circuits (M28): this node's DKG [`KeyShare`] of the
/// committee key and the handler an exit runs on the request. A plain relay
/// passes `None` and rejects committee circuits.
pub struct CommitteeServing<'a> {
    /// This node's share of the committee's joint key.
    pub share: &'a KeyShare,
    /// How an exit produces a response (fetch the real destination, or echo).
    pub exit: ExitBehavior,
}

/// What a served connection turned out to be, for the caller to log.
#[derive(Debug)]
pub enum Served {
    /// A one-shot onion message; carries the forward/deliver outcome.
    Message(Outcome),
    /// A persistent circuit, now torn down (relayed or exit-spliced).
    Circuit,
    /// A committee-exit circuit hop, now handled.
    Committee,
    /// A committee-2PC member↔member coordination link, now handed to the waiting lead.
    CommitteeLink,
}

/// Read the connection-mode byte and dispatch to the message, circuit, or
/// committee handler. `policy` governs exit behaviour on the circuit path;
/// `committee` must be `Some` for this node to serve committee circuits.
pub async fn serve_connection<R: NextHop>(
    identity: &NodeIdentity,
    mut stream: TcpStream,
    mut session: Session,
    resolver: &R,
    replay: &Mutex<ReplayCache>,
    policy: ExitPolicy,
    committee: Option<CommitteeServing<'_>>,
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
        [FRAME_COMMITTEE] => {
            let serving = committee.ok_or_else(|| {
                Error::Config(
                    "this node is not a committee member; refusing committee circuit".into(),
                )
            })?;
            handle_committee_circuit(
                identity,
                serving.share,
                &mut stream,
                &mut session,
                resolver,
                replay,
                serving.exit,
            )
            .await?;
            Ok(Served::Committee)
        }
        [crate::committee_2pc::LINK_FRAME] => {
            // A committee-2PC follower opening the authenticated member↔member 2PC link; hand
            // the (stream, session) to the lead's waiting endpoint via the rendezvous.
            crate::committee_2pc::handle_link(stream, session).await?;
            Ok(Served::CommitteeLink)
        }
        other => Err(Error::Decode(format!(
            "unknown connection mode {other:?} (expected a single mode byte)"
        ))),
    }
}
