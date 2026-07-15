//! **Committee 2PC-TLS exit — relay-side member (self-forming, mandatory).**
//!
//! Every relay's service can be selected into a committee for a flow (no opt-out): two
//! members jointly complete a TLS 1.3 handshake to the destination and seal/open every
//! application record **under 2PC**, so neither holds the session key or plaintext. Roles are
//! assigned by circuit position — the exit member (dials the destination = egresses, so must
//! be exit-capable) is **Party A**; the prior member is **Party B**. The client XOR-shares its
//! request across the members and reconstructs the response from their two shares; a third,
//! non-committee relay anonymizes the client from the members (the onion hop).
//!
//! The 2PC engine ([`neo_mpc::mpc_tls::live`]) is **synchronous** (`std::net`), while the node
//! is async (tokio). [`run_member`] is the bridge: it converts the tokio member↔member link to
//! a blocking socket and drives the interactive 2PC on a [`spawn_blocking`](tokio::task::spawn_blocking)
//! thread. This module is the per-member primitive; the Sphinx transport that carries the
//! request-shares in and the response-shares out (the `FRAME_COMMITTEE_2PC` handler + client
//! selection) wraps it.

use std::net::TcpStream as StdTcpStream;
use std::sync::{Arc, Mutex};

use neo_core::{Error, Result};
use neo_crypto::Session;
use p256::elliptic_curve::rand_core::OsRng;
use p256::{NonZeroScalar, Scalar};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::run::{read_frame, write_frame};
use neo_mpc::mpc_tls::live::channel::{AmortizingChannel, Channel, TcpChannel};
use neo_mpc::mpc_tls::live::handshake::{
    committee_handshake_net, committee_recv_app, committee_send_app,
};
use neo_mpc::mpc_tls::live::verify::LeafKeyVerifier;
use neo_mpc::mpc_tls::netengine::Party;

/// The host portion of a `host:port` destination (TLS SNI).
fn host_of(dest: &str) -> &str {
    dest.rsplit_once(':').map(|(h, _)| h).unwrap_or(dest)
}

// ── Wire protocol ──
//
// A committee-2PC flow reuses the onion: the client builds ONE circuit to EACH member as its
// endpoint (path hops disjoint from the members), and the sphinx exit payload carries this
// member's [`Committee2pcPayload`]. The two members rendezvous by `token` and coordinate the
// 2PC over a direct member↔member link (the follower dials the lead's relay port with a
// [`LINK_FRAME`] handshake). Each member returns its response-share via its own circuit's
// return path (onion-encrypted to the client) — no bespoke crypto beyond the onion.

/// Magic leading byte marking a circuit exit payload as a committee-2PC instruction (rather
/// than a `host:port` / `mux` / `udp:` target). `0xC2` is an invalid UTF-8 leading byte, so it
/// never collides with a text target.
pub const COMMITTEE_2PC_MAGIC: u8 = 0xC2;

/// Connection-mode byte for the member↔member 2PC coordination link (the follower opening a
/// direct link to the lead). Distinct from the relay's circuit/committee frames.
pub const LINK_FRAME: u8 = 0x5;

/// The per-member committee-2PC instruction, delivered as the member's onion-circuit exit
/// payload. Both members of a flow share the same `token`; each holds only its own request
/// share.
#[derive(Clone, Debug)]
pub struct Committee2pcPayload {
    /// `A` = lead (holds the destination socket, egresses); `B` = follower.
    pub lead: bool,
    /// Rendezvous token — identical in both members' payloads, so the follower's link matches
    /// the lead's pending flow.
    pub token: [u8; 16],
    /// The **lead's** relay address `host:port` — the follower dials it (with [`LINK_FRAME`] +
    /// `token`) to establish the member↔member 2PC link. Empty in the lead's own payload.
    pub lead_addr: String,
    /// The clearnet destination `host:port` (both members need it; the lead dials it).
    pub dest: String,
    /// This member's XOR-share of the request.
    pub request_share: Vec<u8>,
}

impl Committee2pcPayload {
    /// `MAGIC ‖ lead(1) ‖ token(16) ‖ lead_addr_len(u16) ‖ lead_addr ‖ dest_len(u16) ‖ dest ‖
    /// request_share`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(22 + self.lead_addr.len() + self.dest.len() + self.request_share.len());
        out.push(COMMITTEE_2PC_MAGIC);
        out.push(self.lead as u8);
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&(self.lead_addr.len() as u16).to_be_bytes());
        out.extend_from_slice(self.lead_addr.as_bytes());
        out.extend_from_slice(&(self.dest.len() as u16).to_be_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        out.extend_from_slice(&self.request_share);
        out
    }

    /// Parse [`encode`](Self::encode); bounds-checked, never panics. Returns `Ok(None)` if the
    /// payload is not a committee-2PC instruction (wrong magic), so the caller can fall through
    /// to the normal exit-target dispatch.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>> {
        if bytes.first() != Some(&COMMITTEE_2PC_MAGIC) {
            return Ok(None);
        }
        let mut cur = &bytes[1..];
        let take = |cur: &mut &[u8], n: usize| -> Result<Vec<u8>> {
            if cur.len() < n {
                return Err(Error::Decode("committee2pc: truncated payload".into()));
            }
            let (h, t) = cur.split_at(n);
            *cur = t;
            Ok(h.to_vec())
        };
        let take_str = |cur: &mut &[u8]| -> Result<String> {
            let len = u16::from_be_bytes(take(cur, 2)?.try_into().expect("2")) as usize;
            String::from_utf8(take(cur, len)?)
                .map_err(|_| Error::Decode("committee2pc: non-utf8 field".into()))
        };
        let lead = take(&mut cur, 1)?[0] != 0;
        let token: [u8; 16] = take(&mut cur, 16)?.try_into().expect("16");
        let lead_addr = take_str(&mut cur)?;
        let dest = take_str(&mut cur)?;
        let request_share = cur.to_vec();
        Ok(Some(Self { lead, token, lead_addr, dest, request_share }))
    }
}

/// Run this member's **blocking** 2PC-TLS session over the member↔member link `party_std`.
/// `role == Party::A` is the lead: it dials `dest` (egress) and holds the server socket;
/// `Party::B` is the follower (no server socket). `request_share` is this member's XOR-share
/// of the request. Returns this member's XOR-share of the response plaintext (the record
/// inner — the caller strips TLS padding + content-type after XOR-combining both shares).
///
/// **Blocking** — invoked under `spawn_blocking` by [`run_member`].
fn member_2pc_blocking(
    role: Party,
    party_link: &mut dyn Channel,
    dest: &str,
    request_share: &[u8],
) -> Result<Vec<u8>> {
    // Wrap the (encrypted-session-bridged) member link so the whole session shares one KOS
    // base-OT setup.
    let mut party = AmortizingChannel::new(party_link);

    // The lead dials the destination; the follower has no server socket.
    let mut server = if role == Party::A {
        let sock = StdTcpStream::connect(dest)
            .map_err(|e| Error::Config(format!("committee2pc: dial destination {dest}: {e}")))?;
        Some(TcpChannel::from_stream(sock))
    } else {
        None
    };

    let scalar: Scalar = *NonZeroScalar::random(&mut OsRng);
    let mut sess = committee_handshake_net(
        &mut party,
        role,
        server.as_mut().map(|c| c as &mut dyn Channel),
        host_of(dest),
        &scalar,
        &LeafKeyVerifier,
    )
    .map_err(|e| Error::Crypto(format!("committee2pc handshake: {e}")))?;

    committee_send_app(
        &mut party,
        &mut sess,
        server.as_mut().map(|c| c as &mut dyn Channel),
        request_share,
    )
    .map_err(|e| Error::Crypto(format!("committee2pc send: {e}")))?;

    committee_recv_app(
        &mut party,
        &mut sess,
        server.as_mut().map(|c| c as &mut dyn Channel),
    )
    .map_err(|e| Error::Crypto(format!("committee2pc recv: {e}")))
}

/// A blocking neo-mpc [`Channel`] bridged over an authenticated neo [`Session`]: the sync 2PC
/// engine `send`/`recv`s here; the async pump tasks in [`run_member`] seal/open each message
/// and do the socket I/O. Crossing is via `tokio::sync::mpsc` (unbounded → no backpressure
/// deadlock; each handshake's traffic is finite). `blocking_send`/`blocking_recv` are safe from
/// the `spawn_blocking` thread.
struct SessionChannel {
    to_pump: mpsc::UnboundedSender<Vec<u8>>,
    from_pump: mpsc::UnboundedReceiver<Vec<u8>>,
    rx: Vec<u8>,
}

impl Channel for SessionChannel {
    fn send(&mut self, buf: &[u8]) -> Result<()> {
        self.to_pump
            .send(buf.to_vec())
            .map_err(|_| Error::Crypto("committee2pc: session pump closed (send)".into()))
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.rx.is_empty() {
            match self.from_pump.blocking_recv() {
                Some(bytes) => self.rx = bytes,
                None => return Ok(0), // pump closed (EOF)
            }
        }
        let n = buf.len().min(self.rx.len());
        buf[..n].copy_from_slice(&self.rx[..n]);
        self.rx.drain(..n);
        Ok(n)
    }
}

/// **Async/session bridge.** Run this member's 2PC-TLS session over the authenticated member↔
/// member neo [`Session`] on `stream`, returning this member's XOR-share of the response. Two
/// async pump tasks carry the 2PC over the encrypted session (read: `read_frame`→`open`→2PC;
/// write: 2PC→`seal`→`write_frame`), sharing the `Session` via a `Mutex` locked only for the
/// fast sync seal/open (I/O outside the lock → no cross-blocking). The sync 2PC engine runs on
/// a `spawn_blocking` thread over a [`SessionChannel`]. The 2PC stays confidential + integrity-
/// protected against the network (never raw on the wire).
pub async fn run_member(
    role: Party,
    stream: TcpStream,
    session: Session,
    dest: String,
    request_share: Vec<u8>,
) -> Result<Vec<u8>> {
    let (mut rd, mut wr) = stream.into_split();
    let session = Arc::new(Mutex::new(session));
    let (to_pump_tx, mut to_pump_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (from_pump_tx, from_pump_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Read: wire → open → 2PC.
    let sess_r = session.clone();
    let read_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut rd).await {
                Ok(frame) => {
                    let opened = sess_r.lock().expect("session poisoned").open(&frame);
                    match opened {
                        Ok(pt) => {
                            if from_pump_tx.send(pt).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Write: 2PC → seal → wire.
    let sess_w = session.clone();
    let write_task = tokio::spawn(async move {
        while let Some(pt) = to_pump_rx.recv().await {
            let sealed = sess_w.lock().expect("session poisoned").seal(&pt);
            match sealed {
                Ok(s) => {
                    if write_frame(&mut wr, &s).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let out = tokio::task::spawn_blocking(move || {
        let mut ch = SessionChannel { to_pump: to_pump_tx, from_pump: from_pump_rx, rx: Vec::new() };
        member_2pc_blocking(role, &mut ch, &dest, &request_share)
    })
    .await
    .map_err(|e| Error::Config(format!("committee2pc: blocking task join: {e}")))?;

    read_task.abort();
    write_task.abort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Validate the async→sync bridge mechanism in isolation: a tokio stream converted to a
    /// blocking `Channel` (as `run_member` does) round-trips bytes on a `spawn_blocking`
    /// thread while the async peer drives it. This is the load-bearing plumbing; the full 2PC
    /// over it is proven by the live inter-relay test.
    #[tokio::test]
    async fn tokio_stream_bridges_to_blocking_channel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server side: accept, convert to a blocking neo-mpc Channel under spawn_blocking,
        // recv 4 bytes, echo them back — exactly the bridge run_member performs.
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let std_sock = sock.into_std().unwrap();
            std_sock.set_nonblocking(false).unwrap();
            tokio::task::spawn_blocking(move || {
                let mut ch = TcpChannel::from_stream(std_sock);
                let got = ch.recv_exact(4).unwrap();
                ch.send(&got).unwrap();
            })
            .await
            .unwrap();
        });

        // Async client drives the blocking bridge on the other end.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping", "blocking Channel over a bridged tokio stream round-trips");
        server.await.unwrap();
    }

    #[test]
    fn payload_round_trips_and_magic_gates() {
        let p = Committee2pcPayload {
            lead: false,
            token: [7u8; 16],
            lead_addr: "10.0.0.1:443".into(),
            dest: "example.com:443".into(),
            request_share: b"a-random-request-share".to_vec(),
        };
        let enc = p.encode();
        let got = Committee2pcPayload::decode(&enc).unwrap().expect("is committee2pc");
        assert!(!got.lead);
        assert_eq!(got.token, p.token);
        assert_eq!(got.lead_addr, p.lead_addr);
        assert_eq!(got.dest, p.dest);
        assert_eq!(got.request_share, p.request_share);
        // A normal text exit target (e.g. "host:port" / "mux") is NOT a committee2pc payload.
        assert!(Committee2pcPayload::decode(b"example.com:443").unwrap().is_none());
        assert!(Committee2pcPayload::decode(b"mux").unwrap().is_none());
        // Truncated committee2pc payloads error, not panic.
        assert!(Committee2pcPayload::decode(&enc[..10]).is_err());
    }
}
