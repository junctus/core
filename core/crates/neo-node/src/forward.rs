//! Onion forwarding over the network — the multi-hop data plane (M2 wired to run).
//!
//! The Sphinx machinery in `neo-crypto` (`create_packet` / `process`) was, until
//! now, only exercised in-process. This module carries it over real sockets:
//!
//! - a **sender** builds a Sphinx onion for a payload routed through a chosen
//!   circuit of relays and hands it to the first hop over an authenticated
//!   session ([`send_onion`]);
//! - a **relay** accepts a hop, opens the frame, peels exactly one layer with
//!   `process`, and either forwards the transformed packet to the next hop
//!   (dialing it and establishing a fresh session) or, if it is the terminal
//!   hop, delivers the payload ([`handle_onion_shared`]).
//!
//! Each hop-to-hop link is independently encrypted by the M1 session (link
//! authentication + forward secrecy, and a passive observer sees only fixed-size
//! ciphertext), *and* the packet is onion-encrypted by Sphinx, so no relay
//! learns more than its own next hop, and none sees the payload except the exit.
//!
//! What this does **not** do yet (honest scope): build a return path or tunnel a
//! bidirectional byte stream. It delivers a one-shot onion message end to end —
//! the primitive a request/response or stream layer is built on next.

use std::collections::HashMap;
use std::sync::Mutex;

use neo_core::{Error, NodeId, NodeIdentity, Result};
use neo_crypto::{
    create_packet, process, Processed, ReplayCache, Session, SphinxHop, SphinxPacket,
};
use tokio::io::AsyncRead;

use crate::run::{connect, read_frame, write_frame};

/// One hop in a circuit: who to route through and how to reach the first one.
#[derive(Clone, Debug)]
pub struct Hop {
    /// The hop's stable node id (its Sphinx routing address).
    pub id: NodeId,
    /// The hop's Ristretto routing key (`NodePublic::sphinx`).
    pub sphinx: [u8; 32],
    /// A dialable address for the hop (only the first hop's is used by a sender).
    pub addr: String,
}

impl Hop {
    fn sphinx_hop(&self) -> SphinxHop {
        SphinxHop {
            id: *self.id.as_bytes(),
            public: self.sphinx,
        }
    }
}

/// Resolves a next-hop node id to a dialable address. A relay builds this from
/// its discovery snapshot (which carries every relay's address).
pub trait NextHop {
    /// The address to dial for `id`, if known.
    fn addr_of(&self, id: &NodeId) -> Option<String>;
}

impl NextHop for HashMap<NodeId, String> {
    fn addr_of(&self, id: &NodeId) -> Option<String> {
        self.get(id).cloned()
    }
}

/// The result of a relay handling one onion hop.
#[derive(Debug)]
pub enum Outcome {
    /// The packet was forwarded to `next`.
    Forwarded {
        /// The next hop it was sent to.
        next: NodeId,
    },
    /// This relay was the terminal hop; here is the delivered payload.
    Delivered {
        /// The recovered payload (the exit would act on this).
        payload: Vec<u8>,
    },
}

/// Build the onion for `payload` routed through `circuit` (the last hop is the
/// exit that will receive the payload). Returns the wire packet bytes and the
/// first hop's dial address.
pub fn build_onion(circuit: &[Hop], payload: &[u8]) -> Result<(Vec<u8>, String)> {
    let first = circuit
        .first()
        .ok_or_else(|| Error::Config("an onion circuit needs at least one hop".into()))?;
    let hops: Vec<SphinxHop> = circuit.iter().map(Hop::sphinx_hop).collect();
    let packet = create_packet(&hops, payload)?;
    Ok((packet.to_bytes(), first.addr.clone()))
}

/// Sender: build the onion and hand it to the first hop over a fresh session.
///
/// Returns once the first hop has accepted the framed packet; end-to-end
/// delivery then proceeds hop-by-hop without further involvement from the sender
/// (this is a one-shot, no return path — see the module docs).
pub async fn send_onion(identity: &NodeIdentity, circuit: &[Hop], payload: &[u8]) -> Result<()> {
    let (packet_bytes, first_addr) = build_onion(circuit, payload)?;
    let (mut stream, mut result) = connect(&first_addr, identity).await?;
    // Declare the connection mode, then hand over the onion.
    write_frame(&mut stream, &result.session.seal(&[crate::run::FRAME_MESSAGE])?).await?;
    let frame = result.session.seal(&packet_bytes)?;
    write_frame(&mut stream, &frame).await?;
    Ok(())
}

/// Relay: having completed the handshake with the previous hop, read one onion
/// frame off `stream`, peel a layer, and forward or deliver it — under a
/// **caller-owned** replay cache so a long-lived relay rejects replays across
/// connections.
///
/// `session` is the established session with the previous hop; `resolver` maps a
/// next-hop id to an address. A relay serving many concurrent connections wants
/// [`handle_onion_shared`], which takes a `Mutex`-guarded cache shared across
/// tasks; this variant is for a single-threaded owner of the cache. There is
/// deliberately no fresh-cache-per-call helper: it would silently accept replays.
pub async fn handle_onion_with_cache<S, R>(
    identity: &NodeIdentity,
    stream: &mut S,
    session: &mut Session,
    resolver: &R,
    cache: &mut ReplayCache,
) -> Result<Outcome>
where
    S: AsyncRead + Unpin,
    R: NextHop,
{
    let frame = read_frame(stream).await?;
    let packet_bytes = session.open(&frame)?;
    let packet = SphinxPacket::from_bytes(&packet_bytes)?;

    match process(identity, cache, &packet)? {
        Processed::Deliver { payload } => Ok(Outcome::Delivered { payload }),
        Processed::Forward { next, packet } => {
            let next_id = NodeId::from_bytes(next);
            let addr = resolver
                .addr_of(&next_id)
                .ok_or_else(|| Error::Config(format!("no address known for next hop {next_id}")))?;
            forward_packet(identity, &addr, &packet).await?;
            Ok(Outcome::Forwarded { next: next_id })
        }
    }
}

/// Relay handler with a **shared, long-lived** replay cache — the correct
/// default for a real relay. Reads one onion frame, peels a layer under the
/// shared cache (so a packet replayed on a *new* connection is rejected), and
/// forwards or delivers. The cache lock is held only for the synchronous
/// `process` call, never across an await.
pub async fn handle_onion_shared<S, R>(
    identity: &NodeIdentity,
    stream: &mut S,
    session: &mut Session,
    resolver: &R,
    cache: &Mutex<ReplayCache>,
) -> Result<Outcome>
where
    S: AsyncRead + Unpin,
    R: NextHop,
{
    let frame = read_frame(stream).await?;
    let packet_bytes = session.open(&frame)?;
    let packet = SphinxPacket::from_bytes(&packet_bytes)?;

    let processed = {
        let mut guard = cache.lock().expect("replay cache poisoned");
        process(identity, &mut guard, &packet)?
    };
    match processed {
        Processed::Deliver { payload } => Ok(Outcome::Delivered { payload }),
        Processed::Forward { next, packet } => {
            let next_id = NodeId::from_bytes(next);
            let addr = resolver
                .addr_of(&next_id)
                .ok_or_else(|| Error::Config(format!("no address known for next hop {next_id}")))?;
            forward_packet(identity, &addr, &packet).await?;
            Ok(Outcome::Forwarded { next: next_id })
        }
    }
}

/// Dial the next hop, establish a session, and hand off the peeled packet.
async fn forward_packet(
    identity: &NodeIdentity,
    next_addr: &str,
    packet: &SphinxPacket,
) -> Result<()> {
    let (mut stream, mut result) = connect(next_addr, identity).await?;
    // Propagate the message mode to the next hop, then the peeled packet.
    write_frame(&mut stream, &result.session.seal(&[crate::run::FRAME_MESSAGE])?).await?;
    let frame = result.session.seal(&packet.to_bytes())?;
    write_frame(&mut stream, &frame).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::accept;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    fn hop_of(identity: &NodeIdentity, addr: &str) -> Hop {
        let p = identity.public();
        Hop {
            id: p.id,
            sphinx: p.sphinx,
            addr: addr.to_string(),
        }
    }

    /// Bind a relay that accepts exactly one onion connection and returns the
    /// outcome of handling it. Returns the bound address and a handle to await.
    async fn relay_once(
        identity_bytes: Vec<u8>,
        resolver: HashMap<NodeId, String>,
    ) -> (String, JoinHandle<Outcome>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&identity_bytes).unwrap();
            let (mut stream, mut result) = accept(&listener, &identity).await.unwrap();
            // Consume the connection-mode frame the peer sends first.
            let mode = result
                .session
                .open(&crate::run::read_frame(&mut stream).await.unwrap())
                .unwrap();
            assert_eq!(mode, [crate::run::FRAME_MESSAGE]);
            let mut cache = ReplayCache::new();
            handle_onion_with_cache(
                &identity,
                &mut stream,
                &mut result.session,
                &resolver,
                &mut cache,
            )
            .await
            .unwrap()
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn two_hop_onion_forwards_then_delivers() {
        // Circuit: sender → relay → exit. The relay must forward (never see the
        // payload); the exit must deliver exactly the payload.
        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let sender = NodeIdentity::generate().unwrap();

        let (exit_addr, exit_handle) = relay_once(exit.to_bytes(), HashMap::new()).await;

        let mut resolver = HashMap::new();
        resolver.insert(exit.id(), exit_addr.clone());
        let (relay_addr, relay_handle) = relay_once(relay.to_bytes(), resolver).await;

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];
        let message = b"no relay on this path can read me";
        send_onion(&sender, &circuit, message).await.unwrap();

        // The exit delivered exactly the payload...
        match exit_handle.await.unwrap() {
            Outcome::Delivered { payload } => assert_eq!(payload, message),
            other => panic!("exit should deliver, got {other:?}"),
        }
        // ...and the middle relay only forwarded — it never obtained the payload.
        match relay_handle.await.unwrap() {
            Outcome::Forwarded { next } => assert_eq!(next, exit.id()),
            other => panic!("relay should forward, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn single_hop_delivers_directly() {
        let exit = NodeIdentity::generate().unwrap();
        let sender = NodeIdentity::generate().unwrap();
        let (exit_addr, exit_handle) = relay_once(exit.to_bytes(), HashMap::new()).await;

        let circuit = vec![hop_of(&exit, &exit_addr)];
        send_onion(&sender, &circuit, b"direct").await.unwrap();

        match exit_handle.await.unwrap() {
            Outcome::Delivered { payload } => assert_eq!(payload, b"direct"),
            other => panic!("expected delivery, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_relay_without_the_next_address_errors() {
        // A relay that can't resolve its next hop fails cleanly (no panic).
        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let sender = NodeIdentity::generate().unwrap();

        // relay's resolver is empty, so it cannot forward to the exit.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap().to_string();
        let relay_bytes = relay.to_bytes();
        let relay_task: JoinHandle<Result<Outcome>> = tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&relay_bytes).unwrap();
            let (mut stream, mut result) = accept(&listener, &identity).await.unwrap();
            let _mode = result
                .session
                .open(&crate::run::read_frame(&mut stream).await.unwrap())
                .unwrap();
            let empty: HashMap<NodeId, String> = HashMap::new();
            let mut cache = ReplayCache::new();
            handle_onion_with_cache(
                &identity,
                &mut stream,
                &mut result.session,
                &empty,
                &mut cache,
            )
            .await
        });

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, "10.0.0.1:9000")];
        send_onion(&sender, &circuit, b"x").await.unwrap();
        assert!(
            relay_task.await.unwrap().is_err(),
            "unresolvable next hop must error, not panic"
        );
    }
}
