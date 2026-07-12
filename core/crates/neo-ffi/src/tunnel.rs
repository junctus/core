//! `NeoTunnelSession` — the packet pipe a platform VPN shell drives.
//!
//! A macOS/iOS `NEPacketTunnelProvider` (or Android `VpnService`) captures the
//! device's IP packets and must hand them to neo and get replies back. This type
//! is that boundary: it dials a **peer exit node**, runs the M1 PQ-hybrid
//! handshake, and then carries raw IP packets to that peer through neo's
//! encrypted, timing-mixed tunnel data plane ([`neo_node::tunnel::run_tunnel`]).
//! The peer is a neo node that NATs the packets to the clearnet and returns the
//! replies through the same tunnel.
//!
//! The API is deliberately coarse and **batched** — the shell submits a batch of
//! outbound packets and drains a batch of inbound ones, so packets never cross
//! the FFI boundary one at a time.
//!
//! Honest scope: this is the single-peer data plane (transport encryption +
//! [`neo_mix`] cover/timing defense). Splitting each flow across *disjoint
//! multi-hop sliced circuits* from inside a packet tunnel additionally needs a
//! userspace TCP/IP stack (packets → flows) that the core does not yet have;
//! that is a separate milestone and slots in behind this same submit/drain API.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use neo_core::{NodeIdentity, PrivacyLevel};
use neo_mix::MixParams;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How much cover traffic / timing mixing the tunnel applies. Mirrors
/// [`neo_core::PrivacyLevel`] across the FFI boundary.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeoPrivacy {
    /// No mixing or cover — fastest, weakest. Development only.
    Off,
    /// Moderate mixing and cover (the default).
    Balanced,
    /// Heavy cover and deep mixing.
    Paranoid,
}

impl From<NeoPrivacy> for PrivacyLevel {
    fn from(p: NeoPrivacy) -> Self {
        match p {
            NeoPrivacy::Off => PrivacyLevel::Off,
            NeoPrivacy::Balanced => PrivacyLevel::Balanced,
            NeoPrivacy::Paranoid => PrivacyLevel::Paranoid,
        }
    }
}

/// Why a tunnel operation failed. Coarse on purpose — the shell logs `detail`
/// and surfaces a connect failure to the OS. (The field is `detail`, not
/// `message`, because a UniFFI error field named `message` collides with
/// `Throwable.message` in the generated Kotlin.)
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[derive(Debug, thiserror::Error)]
pub enum NeoTunnelError {
    /// The identity secret bytes were not a valid neo identity.
    #[error("invalid identity secret")]
    Identity,
    /// Dialing the peer or completing the handshake failed.
    #[error("connect failed: {detail}")]
    Connect { detail: String },
    /// Fetching or verifying the relay snapshot from the mirrors failed.
    #[error("discovery failed: {detail}")]
    Discovery { detail: String },
    /// The session has been closed.
    #[error("tunnel session is closed")]
    Closed,
}

/// Bounded queues between the OS packet loop and the async tunnel. A full queue
/// drops packets rather than blocking the OS callback — correct for a VPN, where
/// IP is already best-effort and stalling the packet loop is worse than a drop.
const QUEUE_DEPTH: usize = 512;

/// One shared multi-thread runtime for all sessions. Created lazily so merely
/// linking the crate (e.g. the identity-only functions) spins up no threads.
pub(crate) fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to build neo tunnel runtime")
    })
}

/// A live tunnel to a peer exit node. Drive it from the OS packet loop with
/// [`submit_outbound`](Self::submit_outbound) and
/// [`drain_inbound`](Self::drain_inbound); [`close`](Self::close) tears it down.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct NeoTunnelSession {
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    closed: AtomicBool,
    peer_key: Vec<u8>,
}

impl NeoTunnelSession {
    /// Dial `peer_addr` (`host:port`), handshake with the identity in `secret`,
    /// and start the tunnel. Blocks until the handshake resolves so the caller
    /// (e.g. `startTunnel`) can fail fast.
    fn connect_inner(
        secret: Vec<u8>,
        peer_addr: String,
        privacy: NeoPrivacy,
    ) -> Result<NeoTunnelSession, NeoTunnelError> {
        let identity = NodeIdentity::from_bytes(&secret).map_err(|_| NeoTunnelError::Identity)?;
        let rt = runtime();

        let (stream, handshake) = rt
            .block_on(neo_node::run::connect(&peer_addr, &identity))
            .map_err(|e| NeoTunnelError::Connect {
                detail: e.to_string(),
            })?;
        let peer_key = handshake.peer.to_bytes().to_vec();

        // app_out: OS -> tunnel;  app_in: tunnel -> OS.
        let (app_out_tx, app_out_rx) = mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);
        let (app_in_tx, app_in_rx) = mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);
        // wire_*: sealed frames to/from the TCP transport.
        let (wire_out_tx, mut wire_out_rx) = mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);
        let (wire_in_tx, wire_in_rx) = mpsc::channel::<Vec<u8>>(QUEUE_DEPTH);

        let (mut reader, mut writer) = stream.into_split();
        let read_task = rt.spawn(async move {
            while let Ok(frame) = neo_node::run::read_frame(&mut reader).await {
                if wire_in_tx.send(frame).await.is_err() {
                    break;
                }
            }
        });
        let write_task = rt.spawn(async move {
            while let Some(frame) = wire_out_rx.recv().await {
                if neo_node::run::write_frame(&mut writer, &frame)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let mix = MixParams::for_level(privacy.into());
        let tunnel_task = rt.spawn(async move {
            let _ = neo_node::tunnel::run_tunnel(
                handshake.session,
                mix,
                app_out_rx,
                wire_out_tx,
                wire_in_rx,
                app_in_tx,
            )
            .await;
        });

        Ok(NeoTunnelSession {
            outbound: app_out_tx,
            inbound: Mutex::new(app_in_rx),
            tasks: Mutex::new(vec![read_task, write_task, tunnel_task]),
            closed: AtomicBool::new(false),
            peer_key,
        })
    }

    fn submit_inner(&self, packets: Vec<Vec<u8>>) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        for packet in packets {
            // Best-effort: a full queue drops rather than blocks the packet loop.
            if self.outbound.try_send(packet).is_err() {
                break;
            }
        }
    }

    fn drain_inbound_inner(&self, max_packets: u32, timeout_ms: u32) -> Vec<Vec<u8>> {
        if self.closed.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let max = max_packets.max(1) as usize;
        let mut out = Vec::new();
        let mut rx = self.inbound.lock().expect("inbound lock poisoned");
        runtime().block_on(async {
            // Block up to the timeout for the first packet, then greedily drain
            // whatever else is already queued (up to max) into the same batch.
            if let Ok(Some(first)) =
                tokio::time::timeout(Duration::from_millis(timeout_ms as u64), rx.recv()).await
            {
                out.push(first);
                while out.len() < max {
                    match rx.try_recv() {
                        Ok(packet) => out.push(packet),
                        Err(_) => break,
                    }
                }
            }
        });
        out
    }

    fn close_inner(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Ok(tasks) = self.tasks.lock() {
            for task in tasks.iter() {
                task.abort();
            }
        }
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl NeoTunnelSession {
    /// Submit a batch of outbound IP packets (from the OS TUN). Non-blocking;
    /// packets are dropped if the tunnel is saturated or closed.
    pub fn submit_outbound(&self, packets: Vec<Vec<u8>>) {
        self.submit_inner(packets)
    }

    /// Wait up to `timeout_ms` for inbound packets and return up to `max_packets`
    /// of them (to write back to the OS TUN). Returns empty on timeout/close.
    pub fn drain_inbound(&self, max_packets: u32, timeout_ms: u32) -> Vec<Vec<u8>> {
        self.drain_inbound_inner(max_packets, timeout_ms)
    }

    /// The authenticated Ed25519 key of the peer exit node (32 bytes).
    pub fn peer_key(&self) -> Vec<u8> {
        self.peer_key.clone()
    }

    /// Tear down the tunnel and stop its background tasks. Idempotent.
    /// Named `shutdown` (not `close`) to avoid colliding with the `close()` that
    /// UniFFI generates for `AutoCloseable` in the Kotlin bindings.
    pub fn shutdown(&self) {
        self.close_inner()
    }
}

/// Dial a peer exit node and start a tunnel session. See
/// [`NeoTunnelSession::connect_inner`].
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn tunnel_connect(
    secret: Vec<u8>,
    peer_addr: String,
    privacy: NeoPrivacy,
) -> Result<std::sync::Arc<NeoTunnelSession>, NeoTunnelError> {
    NeoTunnelSession::connect_inner(secret, peer_addr, privacy).map(std::sync::Arc::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand up a responder that echoes tunnelled packets back, then drive it end
    /// to end through a real `NeoTunnelSession`: submit a packet, get it back.
    /// Exercises the handshake, `run_tunnel`, and the submit/drain FFI surface.
    #[test]
    fn tunnels_a_packet_to_a_peer_and_back() {
        let server_id = NodeIdentity::generate().unwrap();
        let client_id = NodeIdentity::generate().unwrap();
        let client_secret = client_id.to_bytes().to_vec();

        let rt = runtime();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        // Peer (responder): handshake, then run a tunnel that echoes — every
        // packet recovered from the tunnel (app_in) is fed straight back into it
        // to send (app_out).
        rt.spawn(async move {
            let (stream, result) = neo_node::run::accept(&listener, &server_id).await.unwrap();

            // app_out: packets this peer sends back; app_in: packets it recovers.
            let (app_out_tx, app_out_rx) = mpsc::channel::<Vec<u8>>(16);
            let (app_in_tx, mut app_in_rx) = mpsc::channel::<Vec<u8>>(16);
            let (wire_out_tx, mut wire_out_rx) = mpsc::channel::<Vec<u8>>(16);
            let (wire_in_tx, wire_in_rx) = mpsc::channel::<Vec<u8>>(16);

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
            tokio::spawn(async move {
                while let Some(packet) = app_in_rx.recv().await {
                    if app_out_tx.send(packet).await.is_err() {
                        break;
                    }
                }
            });

            let mix = MixParams::for_level(PrivacyLevel::Off);
            let _ = neo_node::tunnel::run_tunnel(
                result.session,
                mix,
                app_out_rx,
                wire_out_tx,
                wire_in_rx,
                app_in_tx,
            )
            .await;
        });

        let session = tunnel_connect(client_secret, addr, NeoPrivacy::Off).expect("connect");
        session.submit_outbound(vec![b"ping-through-the-tunnel".to_vec()]);
        let got = session.drain_inbound(4, 5_000);
        session.shutdown();
        assert_eq!(got, vec![b"ping-through-the-tunnel".to_vec()]);
        assert_eq!(session.peer_key().len(), 32);
    }
}
