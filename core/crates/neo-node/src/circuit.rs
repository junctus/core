//! Persistent circuit tunnels — multi-cell byte streams and TCP tunneling (M21).
//!
//! [`stream`](crate::stream) does a single request → response round-trip over a
//! Sphinx circuit. This module keeps the circuit **open** and carries a
//! bidirectional **byte stream** across it: many cells in each direction, and at
//! the exit a spliced **TCP connection** to a target — i.e. real TCP-over-onion
//! tunneling, the shape a SOCKS proxy or a full VPN return path needs.
//!
//! ## How it works
//!
//! A single Sphinx packet **sets up** the circuit: it routes to the exit (each
//! relay learns only its next hop) and carries the target address in its
//! exit-only payload. Setting it up also fixes the per-hop shared secrets — the
//! client gets them from [`create_packet_keyed`], each relay derives its own from
//! the packet's `alpha` — exactly as the one-shot path does.
//!
//! After setup the connections stay open and the parties exchange **cells**. A
//! cell is `[seq: u64][onion-layered body]`. Unlike Sphinx (one packet per hop,
//! replay-once), cells are a lightweight **counter-keyed symmetric onion**: each
//! hop XORs one keystream layer `KS(dir_key_i, seq)`, and because `seq` is unique
//! per direction the keystream never repeats (no XOR reuse). The endpoint body is
//! `[mac][payload]` with a **per-cell end-to-end MAC** keyed by the exit's secret,
//! so any middle relay that mauls a cell is detected at the endpoint, never
//! delivered. Each endpoint also enforces a **strict per-direction sequence
//! number** (`seq` starts at 0 and must increase by exactly one), so a relay that
//! duplicates, reorders, or drops a cell — re-injecting captured bytes into the
//! target/return stream — is rejected rather than delivered. Together these give
//! the stream tamper-, replay-, and reorder-detection end to end.
//!
//! Forward (client → exit) layers are applied outermost-first so hop 0 peels
//! first; return (exit → client) layers are added hop-by-hop and the client peels
//! all. No relay can read or forge the stream; only the exit and client can.
//!
//! **Honest scope:** cells are variable-length here (length hiding is the
//! transport layer's job — `neo-transport` bucketing / the mixer). Multiplexing
//! many streams over one circuit now rides on top ([`crate::mux`], with per-stream
//! flow control); aggregate cross-stream congestion control is the remaining
//! refinement.

use std::sync::Mutex;

use neo_core::{Error, NodeId, NodeIdentity, Result};
use neo_crypto::{
    create_packet_keyed, process, Opener, Processed, ReplayCache, Sealer, Session, SphinxPacket,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::forward::{Hop, NextHop};
use crate::run::{connect_verified, read_frame, write_frame};

/// Per-cell end-to-end MAC length.
const CELL_MAC_LEN: usize = 16;
/// Cell header: an 8-byte big-endian sequence number.
const SEQ_LEN: usize = 8;
/// Bytes read from a spliced TCP target per return cell.
const TCP_CHUNK: usize = 8 * 1024;
/// Largest UDP payload we read from a spliced datagram socket into one return
/// cell (a whole IPv4 UDP datagram fits; DNS answers are far smaller).
const UDP_DATAGRAM_MAX: usize = 65_535;

fn fwd_key(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("neo-circuit-fwd-v1", secret)
}
fn ret_key(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("neo-circuit-ret-v1", secret)
}
fn fwd_mac_key(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("neo-circuit-fwd-mac-v1", secret)
}
fn ret_mac_key(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("neo-circuit-ret-mac-v1", secret)
}

/// XOR `data` in place with the keystream `KS(key, seq)`. `seq` makes every cell's
/// keystream distinct, so a fixed per-hop key is never reused across cells.
fn xor_cell(data: &mut [u8], key: &[u8; 32], seq: u64) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&seq.to_be_bytes());
    let mut reader = hasher.finalize_xof();
    let mut ks = vec![0u8; data.len()];
    reader.fill(&mut ks);
    for (b, k) in data.iter_mut().zip(&ks) {
        *b ^= k;
    }
}

/// Per-cell MAC over `seq ‖ payload`, keyed by a direction MAC key.
fn cell_mac(key: &[u8; 32], seq: u64, payload: &[u8]) -> [u8; CELL_MAC_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&seq.to_be_bytes());
    hasher.update(payload);
    let mut out = [0u8; CELL_MAC_LEN];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..CELL_MAC_LEN]);
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The write half of a client's circuit: sends cells to the exit.
pub struct CircuitSink {
    w: OwnedWriteHalf,
    sealer: Sealer,
    secrets: Vec<[u8; 32]>,
    seq: u64,
}

/// The read half of a client's circuit: receives cells from the exit.
pub struct CircuitStream {
    r: OwnedReadHalf,
    opener: Opener,
    secrets: Vec<[u8; 32]>,
    /// The next return-cell sequence number expected — enforces in-order,
    /// no-duplicate, no-drop delivery so a relay cannot replay/reorder the stream.
    next_seq: u64,
}

impl CircuitSink {
    /// Send one application cell to the exit through the circuit.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let seq = self.seq;
        // The (key, seq) pair drives a one-time XOR keystream, so seq must NEVER
        // repeat — refuse to wrap rather than silently reuse a keystream (which
        // would let an observer XOR two cells and recover plaintext). At u64 this is
        // unreachable in practice; the check makes the guarantee unconditional.
        self.seq = seq
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("circuit cell sequence exhausted".into()))?;
        let exit_secret = self.secrets.last().expect("non-empty circuit");
        // Endpoint body: [e2e MAC][payload], then onion-layer it, hop 0 outermost.
        let mut body = Vec::with_capacity(CELL_MAC_LEN + data.len());
        body.extend_from_slice(&cell_mac(&fwd_mac_key(exit_secret), seq, data));
        body.extend_from_slice(data);
        for secret in self.secrets.iter().rev() {
            xor_cell(&mut body, &fwd_key(secret), seq);
        }
        let mut cell = Vec::with_capacity(SEQ_LEN + body.len());
        cell.extend_from_slice(&seq.to_be_bytes());
        cell.extend_from_slice(&body);
        let framed = self.sealer.seal(&cell)?;
        write_frame(&mut self.w, &framed).await
    }

    /// Send a **cover** cell: a zero-length cell. It rides the wire like any other
    /// cell (so it fills timing gaps — the cover-traffic dial), but carries no
    /// application bytes, so the exit writes nothing to the target. Zero-length is
    /// what keeps cover **wire-compatible with every exit**: an exit that doesn't
    /// special-case cover just writes an empty payload (a no-op) and advances.
    pub async fn send_cover(&mut self) -> Result<()> {
        self.send(&[]).await
    }
}

impl CircuitStream {
    /// Receive one application cell back from the exit (layers peeled, integrity
    /// checked). Errors if a relay tampered with the returned cell.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let framed = read_frame(&mut self.r).await?;
        let cell = self.opener.open(&framed)?;
        if cell.len() < SEQ_LEN + CELL_MAC_LEN {
            return Err(Error::Decode("short circuit cell".into()));
        }
        let seq = u64::from_be_bytes(cell[..SEQ_LEN].try_into().expect("8 bytes"));
        // Enforce strict in-order delivery: a duplicated or reordered cell (a relay
        // re-injecting captured bytes) has the wrong seq and is rejected.
        if seq != self.next_seq {
            return Err(Error::Crypto("return cell out of sequence".into()));
        }
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("circuit cell sequence exhausted".into()))?;
        let mut body = cell[SEQ_LEN..].to_vec();
        for secret in &self.secrets {
            xor_cell(&mut body, &ret_key(secret), seq);
        }
        let (mac, payload) = body.split_at(CELL_MAC_LEN);
        let exit_secret = self.secrets.last().expect("non-empty circuit");
        if !ct_eq(mac, &cell_mac(&ret_mac_key(exit_secret), seq, payload)) {
            return Err(Error::Crypto("return cell failed integrity check".into()));
        }
        Ok(payload.to_vec())
    }
}

/// Client: open a persistent circuit through `circuit` to a `target` the exit
/// will splice a TCP connection to. Returns the send/receive halves.
/// Exit-side **read** half of a circuit's cell channel: reads forward cells, peels
/// the exit's single forward layer, checks strict sequencing, and verifies the
/// end-to-end MAC, returning the endpoint payload. It is exactly `exit_splice`'s
/// forward loop exposed as a [`FrameSource`](crate::mux::FrameSource), so the exit
/// can run stream multiplexing ([`crate::mux::serve_mux`]) over the same cells.
pub struct ExitFrameSource {
    r: OwnedReadHalf,
    opener: Opener,
    secret: [u8; 32],
    next_seq: u64,
}

impl ExitFrameSource {
    /// Wrap the exit's inbound half and per-circuit secret.
    pub fn new(r: OwnedReadHalf, opener: Opener, secret: [u8; 32]) -> Self {
        Self {
            r,
            opener,
            secret,
            next_seq: 0,
        }
    }

    async fn recv_payload(&mut self) -> Result<Vec<u8>> {
        let framed = read_frame(&mut self.r).await?;
        let cell = self.opener.open(&framed)?;
        if cell.len() < SEQ_LEN + CELL_MAC_LEN {
            return Err(Error::Decode("short forward cell".into()));
        }
        let seq = u64::from_be_bytes(cell[..SEQ_LEN].try_into().expect("8 bytes"));
        if seq != self.next_seq {
            return Err(Error::Crypto("forward cell out of sequence".into()));
        }
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("splice cell sequence exhausted".into()))?;
        let mut body = cell[SEQ_LEN..].to_vec();
        xor_cell(&mut body, &fwd_key(&self.secret), seq);
        let (mac, payload) = body.split_at(CELL_MAC_LEN);
        if !ct_eq(mac, &cell_mac(&fwd_mac_key(&self.secret), seq, payload)) {
            return Err(Error::Crypto("forward cell failed integrity check".into()));
        }
        Ok(payload.to_vec())
    }
}

impl crate::mux::FrameSource for ExitFrameSource {
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        self.recv_payload().await
    }
}

/// Exit-side **write** half: wraps an endpoint payload into a return cell (e2e MAC,
/// the exit's single return layer, strict sequence). `exit_splice`'s return loop
/// exposed as a [`FrameSink`](crate::mux::FrameSink).
pub struct ExitFrameSink {
    w: OwnedWriteHalf,
    sealer: Sealer,
    secret: [u8; 32],
    seq: u64,
}

impl ExitFrameSink {
    /// Wrap the exit's outbound half and per-circuit secret.
    pub fn new(w: OwnedWriteHalf, sealer: Sealer, secret: [u8; 32]) -> Self {
        Self {
            w,
            sealer,
            secret,
            seq: 0,
        }
    }

    async fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        let seq = self.seq;
        self.seq = seq
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("splice cell sequence exhausted".into()))?;
        let mut body = Vec::with_capacity(CELL_MAC_LEN + payload.len());
        body.extend_from_slice(&cell_mac(&ret_mac_key(&self.secret), seq, payload));
        body.extend_from_slice(payload);
        xor_cell(&mut body, &ret_key(&self.secret), seq);
        let mut cell = Vec::with_capacity(SEQ_LEN + body.len());
        cell.extend_from_slice(&seq.to_be_bytes());
        cell.extend_from_slice(&body);
        let out = self.sealer.seal(&cell)?;
        write_frame(&mut self.w, &out).await
    }
}

impl crate::mux::FrameSink for ExitFrameSink {
    async fn send_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        self.send_payload(&frame).await
    }
}

pub async fn open_circuit(
    identity: &NodeIdentity,
    circuit: &[Hop],
    target: &str,
) -> Result<(CircuitSink, CircuitStream)> {
    if circuit.is_empty() {
        return Err(Error::Config("a circuit needs at least one hop".into()));
    }
    let hops: Vec<neo_crypto::SphinxHop> = circuit
        .iter()
        .map(|h| neo_crypto::SphinxHop {
            id: *h.id.as_bytes(),
            public: h.sphinx,
        })
        .collect();
    // The setup packet routes to the exit and carries the target in its exit-only
    // payload; create_packet_keyed hands us the per-hop secrets.
    let (packet, secrets) = create_packet_keyed(&hops, target.as_bytes())?;

    let (stream, result) = connect_verified(&circuit[0].addr, identity, &circuit[0].id).await?;
    let (mut sealer, opener) = result.session.split();
    let (r, mut w) = stream.into_split();
    // Declare the circuit mode, then send the setup packet.
    write_frame(&mut w, &sealer.seal(&[crate::run::FRAME_CIRCUIT])?).await?;
    let setup = sealer.seal(&packet.to_bytes())?;
    write_frame(&mut w, &setup).await?;

    Ok((
        CircuitSink {
            w,
            sealer,
            secrets: secrets.clone(),
            seq: 0,
        },
        CircuitStream {
            r,
            opener,
            secrets,
            next_seq: 0,
        },
    ))
}

/// Relay/exit: having handshaked with the previous hop, read the circuit's setup
/// packet and then either **relay** cells to the next hop (adding/removing one
/// layer per direction) or, at the exit, **splice** a TCP connection to the
/// target and pump bytes both ways. Runs until either end of the circuit closes.
pub async fn serve_circuit<R: NextHop>(
    identity: &NodeIdentity,
    prev_stream: TcpStream,
    prev_session: Session,
    resolver: &R,
    replay: &Mutex<ReplayCache>,
    policy: ExitPolicy,
) -> Result<()> {
    let (mut pr, pw) = prev_stream.into_split();
    let (pw_sealer, pr_opener) = {
        let (s, o) = prev_session.split();
        (s, o)
    };

    let setup_frame = read_frame(&mut pr).await?;
    let mut pr_opener = pr_opener;
    let packet_bytes = pr_opener.open(&setup_frame)?;
    let packet = SphinxPacket::from_bytes(&packet_bytes)?;
    let secret = identity.sphinx_shared(packet.alpha())?;

    let processed = {
        let mut cache = replay.lock().expect("replay cache poisoned");
        process(identity, &mut cache, &packet)?
    };

    match processed {
        Processed::Forward { next, packet } => {
            let next_id = NodeId::from_bytes(next);
            let addr = resolver
                .addr_of(&next_id)
                .ok_or_else(|| Error::Config(format!("no address for next hop {next_id}")))?;
            let (next_stream, next_result) = connect_verified(&addr, identity, &next_id).await?;
            let (mut ns_sealer, ns_opener) = next_result.session.split();
            let (nr, mut nw) = next_stream.into_split();
            // Propagate the circuit mode, then forward the setup packet on.
            write_frame(&mut nw, &ns_sealer.seal(&[crate::run::FRAME_CIRCUIT])?).await?;
            let fwd_setup = ns_sealer.seal(&packet.to_bytes())?;
            write_frame(&mut nw, &fwd_setup).await?;
            relay_pump(
                secret, pr, pr_opener, pw, pw_sealer, nr, ns_opener, nw, ns_sealer,
            )
            .await
        }
        Processed::Deliver { payload } => {
            // Committee-2PC endpoint: this node was selected into a self-forming exit committee
            // for this flow. Run the joint 2PC over an authenticated link to the partner member
            // (the lead egresses to the destination; the follower never sees plaintext) and
            // return this member's XOR-share of the response via the circuit return path.
            if let Some(cp) = crate::committee_2pc::Committee2pcPayload::decode(&payload)? {
                if cp.lead && !policy.offer_exit {
                    return Err(Error::Config(
                        "committee2pc: lead node does not offer clearnet exit".into(),
                    ));
                }
                let share = crate::committee_2pc::run_member_flow(cp, identity).await?;
                let mut sink = ExitFrameSink::new(pw, pw_sealer, secret);
                return sink.send_payload(&share).await;
            }
            // Only a node that opted into exit may splice to the clearnet; a plain
            // relay that finds itself the terminal hop refuses rather than proxy.
            if !policy.offer_exit {
                return Err(Error::Config(
                    "this node is the circuit exit but does not offer clearnet exit".into(),
                ));
            }
            let target = String::from_utf8(payload)
                .map_err(|_| Error::Decode("circuit target not valid utf-8".into()))?;
            // Target dispatch:
            //  - "mux"          → run stream multiplexing (many streams to many
            //                     targets over this one circuit).
            //  - "udp:host:port"→ carry datagrams over a UDP socket (one cell = one
            //                     datagram).
            //  - "host:port"    → splice a single TCP connection (the original mode).
            if target == "mux" {
                let sink = ExitFrameSink::new(pw, pw_sealer, secret);
                let source = ExitFrameSource::new(pr, pr_opener, secret);
                crate::mux::serve_mux(sink, source, policy).await
            } else if let Some(udp_target) = target.strip_prefix("udp:") {
                exit_splice_udp(secret, udp_target, pr, pr_opener, pw, pw_sealer, policy).await
            } else {
                exit_splice(secret, &target, pr, pr_opener, pw, pw_sealer, policy).await
            }
        }
    }
}

/// Ports an exit refuses to splice to by default — the reduced-harm baseline. These
/// are the destinations that generate the abuse complaints (and law-enforcement
/// attention) that deter people from running exits at all: mail (spam), remote
/// login / admin (brute-force scanning), and file sharing. Blocking them turns an
/// exit from an open proxy into a low-risk web egress.
///
/// **DNS (53) is intentionally *allowed*** — it is essential for browsing (a VPN
/// client resolves all names through the tunnel to avoid a DNS leak, so blocking 53
/// breaks every page load), and an exit resolving on behalf of a client *through the
/// circuit* is not a DNS-amplification vector: the response returns down the circuit
/// to that client, never reflected to a spoofed victim (unlike an open UDP resolver).
/// Tor blocks SMTP for the same abuse reason but likewise resolves DNS.
///
/// (A configurable allow/deny list — HTTPS-only, operator-curated — is the rest of M31.)
const DENIED_EXIT_PORTS: &[u16] = &[
    22,  // SSH
    23,  // Telnet
    25,  // SMTP (spam — Tor blocks this too)
    135, // MS RPC
    137, 138, 139, // NetBIOS
    445, // SMB
    465, 587,  // SMTP submission
    3389, // RDP
    6667, // IRC (botnet C2)
];

/// Policy governing what an exit may splice a connection to. The default **denies**
/// every non-public destination (loopback, RFC1918, link-local / metadata, ULA,
/// CGNAT, hostnames) — an SSRF / open-proxy guard — **and** the abuse-prone ports in
/// [`DENIED_EXIT_PORTS`]. `allow_loopback` opens localhost for local dev/test only;
/// production leaves it `false`. A full configurable exit policy (allowlists,
/// HTTPS-only) is M31.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExitPolicy {
    /// Permit loopback splice targets (local dev/test only).
    pub allow_loopback: bool,
    /// Whether this node offers clearnet exit at all. When false, the node
    /// refuses to splice even if a circuit terminates at it (defence in depth:
    /// only exit-flagged relays should be picked as an exit in the first place).
    pub offer_exit: bool,
}

impl ExitPolicy {
    /// Whether this exit will egress to `port`. Refuses the reduced-harm
    /// [`DENIED_EXIT_PORTS`] set so an exit can't be turned into an open proxy for
    /// spam / scanning / amplification.
    pub fn permits_port(&self, port: u16) -> bool {
        !DENIED_EXIT_PORTS.contains(&port)
    }
}

/// Reject a splice target whose port is on the reduced-harm denylist, after the
/// SSRF check has confirmed it parses as a public `host:port` literal.
fn check_exit_port(target: &str, policy: &ExitPolicy) -> Result<()> {
    let port = target
        .parse::<std::net::SocketAddr>()
        .map(|sa| sa.port())
        .map_err(|_| Error::Config("exit target has no parseable port".into()))?;
    if !policy.permits_port(port) {
        return Err(Error::Config(format!(
            "exit refuses port {port} (reduced-harm policy)"
        )));
    }
    Ok(())
}

/// A middle relay: strip one forward layer toward the exit, add one return layer
/// back toward the client. The two directions own disjoint halves, so they run
/// concurrently; the circuit tears down when either side closes.
#[allow(clippy::too_many_arguments)]
async fn relay_pump(
    secret: [u8; 32],
    mut pr: OwnedReadHalf,
    mut pr_opener: Opener,
    mut pw: OwnedWriteHalf,
    mut pw_sealer: Sealer,
    mut nr: OwnedReadHalf,
    mut ns_opener: Opener,
    mut nw: OwnedWriteHalf,
    mut ns_sealer: Sealer,
) -> Result<()> {
    let fk = fwd_key(&secret);
    let rk = ret_key(&secret);

    let forward = async {
        loop {
            let Ok(framed) = read_frame(&mut pr).await else {
                break;
            };
            let cell = pr_opener.open(&framed)?;
            let relayed = relay_layer(&cell, &fk)?;
            let out = ns_sealer.seal(&relayed)?;
            if write_frame(&mut nw, &out).await.is_err() {
                break;
            }
        }
        Ok::<(), Error>(())
    };

    let ret = async {
        loop {
            let Ok(framed) = read_frame(&mut nr).await else {
                break;
            };
            let cell = ns_opener.open(&framed)?;
            let relayed = relay_layer(&cell, &rk)?;
            let out = pw_sealer.seal(&relayed)?;
            if write_frame(&mut pw, &out).await.is_err() {
                break;
            }
        }
        Ok::<(), Error>(())
    };

    tokio::select! {
        r = forward => r,
        r = ret => r,
    }
}

/// XOR one layer (`key`, keyed by the cell's own `seq`) onto a `[seq][body]` cell.
fn relay_layer(cell: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if cell.len() < SEQ_LEN {
        return Err(Error::Decode("short circuit cell".into()));
    }
    let seq = u64::from_be_bytes(cell[..SEQ_LEN].try_into().expect("8 bytes"));
    let mut out = cell.to_vec();
    xor_cell(&mut out[SEQ_LEN..], key, seq);
    Ok(out)
}

/// The exit: splice a TCP connection to `target`, decrypt forward cells into the
/// socket, and wrap bytes read back from the socket into return cells.
async fn exit_splice(
    secret: [u8; 32],
    target: &str,
    mut pr: OwnedReadHalf,
    mut pr_opener: Opener,
    mut pw: OwnedWriteHalf,
    mut pw_sealer: Sealer,
    policy: ExitPolicy,
) -> Result<()> {
    // SSRF / open-proxy guard: refuse to splice to any non-public destination.
    if !neo_core::net::is_safe_dial_target(target, policy.allow_loopback) {
        return Err(Error::Config(format!(
            "exit refuses to splice to non-public target {target}"
        )));
    }
    // Reduced-harm port policy: refuse abuse-prone ports (spam/scan/amplification).
    check_exit_port(target, &policy)?;
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::netif::connect_scoped(target),
    )
    .await
    .map_err(|_| Error::Config("exit target connect timed out".into()))??;
    let (mut tr, mut tw) = tcp.into_split();
    let fk = fwd_key(&secret);
    let fmk = fwd_mac_key(&secret);
    let rk = ret_key(&secret);
    let rmk = ret_mac_key(&secret);

    // client → target: peel the exit's forward layer, verify the e2e MAC, write.
    let to_target = async {
        let mut next_seq = 0u64;
        loop {
            let Ok(framed) = read_frame(&mut pr).await else {
                break;
            };
            let cell = pr_opener.open(&framed)?;
            if cell.len() < SEQ_LEN + CELL_MAC_LEN {
                return Err(Error::Decode("short forward cell".into()));
            }
            let seq = u64::from_be_bytes(cell[..SEQ_LEN].try_into().expect("8 bytes"));
            // Strict in-order delivery: a relay that duplicates/reorders a forward
            // cell (re-injecting captured bytes into the target stream) is rejected.
            if seq != next_seq {
                return Err(Error::Crypto("forward cell out of sequence".into()));
            }
            next_seq = next_seq
                .checked_add(1)
                .ok_or_else(|| Error::Crypto("splice cell sequence exhausted".into()))?;
            let mut body = cell[SEQ_LEN..].to_vec();
            xor_cell(&mut body, &fk, seq);
            let (mac, payload) = body.split_at(CELL_MAC_LEN);
            if !ct_eq(mac, &cell_mac(&fmk, seq, payload)) {
                return Err(Error::Crypto("forward cell failed integrity check".into()));
            }
            // A zero-length payload is a cover cell: authenticated, writes nothing.
            if tw.write_all(payload).await.is_err() {
                break;
            }
        }
        Ok::<(), Error>(())
    };

    // target → client: chunk the socket, MAC + layer each chunk into a return cell.
    let to_client = async {
        let mut seq = 0u64;
        let mut buf = vec![0u8; TCP_CHUNK];
        loop {
            let n = match tr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let payload = &buf[..n];
            let mut body = Vec::with_capacity(CELL_MAC_LEN + n);
            body.extend_from_slice(&cell_mac(&rmk, seq, payload));
            body.extend_from_slice(payload);
            xor_cell(&mut body, &rk, seq);
            let mut cell = Vec::with_capacity(SEQ_LEN + body.len());
            cell.extend_from_slice(&seq.to_be_bytes());
            cell.extend_from_slice(&body);
            let out = pw_sealer.seal(&cell)?;
            if write_frame(&mut pw, &out).await.is_err() {
                break;
            }
            seq = seq
                .checked_add(1)
                .ok_or_else(|| Error::Crypto("splice cell sequence exhausted".into()))?;
        }
        Ok::<(), Error>(())
    };

    tokio::select! {
        r = to_target => r,
        r = to_client => r,
    }
}

/// UDP variant of [`exit_splice`]: each forward cell carries one whole datagram,
/// sent on a connected UDP socket, and each datagram received back becomes one
/// return cell. The cell crypto (sequence, per-cell MAC, onion XOR) is identical
/// to the TCP splice — only the transport differs (datagram boundaries instead of
/// a byte stream), so one cell maps to exactly one datagram in each direction.
async fn exit_splice_udp(
    secret: [u8; 32],
    target: &str,
    mut pr: OwnedReadHalf,
    mut pr_opener: Opener,
    mut pw: OwnedWriteHalf,
    mut pw_sealer: Sealer,
    policy: ExitPolicy,
) -> Result<()> {
    // Same SSRF / open-proxy guard as the TCP exit.
    if !neo_core::net::is_safe_dial_target(target, policy.allow_loopback) {
        return Err(Error::Config(format!(
            "exit refuses to splice UDP to non-public target {target}"
        )));
    }
    // Reduced-harm port policy (blocks the abuse-prone ports; DNS:53 is allowed).
    check_exit_port(target, &policy)?;
    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| Error::Config(format!("exit UDP bind failed: {e}")))?;
    udp.connect(target)
        .await
        .map_err(|e| Error::Config(format!("exit UDP connect to {target} failed: {e}")))?;
    let udp = std::sync::Arc::new(udp);

    let fk = fwd_key(&secret);
    let fmk = fwd_mac_key(&secret);
    let rk = ret_key(&secret);
    let rmk = ret_mac_key(&secret);

    // client → target: peel the exit's forward layer, verify the e2e MAC, send the
    // datagram. One forward cell == one datagram.
    let send_udp = udp.clone();
    let to_target = async move {
        let mut next_seq = 0u64;
        loop {
            let Ok(framed) = read_frame(&mut pr).await else {
                break;
            };
            let cell = pr_opener.open(&framed)?;
            if cell.len() < SEQ_LEN + CELL_MAC_LEN {
                return Err(Error::Decode("short forward cell".into()));
            }
            let seq = u64::from_be_bytes(cell[..SEQ_LEN].try_into().expect("8 bytes"));
            if seq != next_seq {
                return Err(Error::Crypto("forward cell out of sequence".into()));
            }
            next_seq = next_seq
                .checked_add(1)
                .ok_or_else(|| Error::Crypto("splice cell sequence exhausted".into()))?;
            let mut body = cell[SEQ_LEN..].to_vec();
            xor_cell(&mut body, &fk, seq);
            let (mac, payload) = body.split_at(CELL_MAC_LEN);
            if !ct_eq(mac, &cell_mac(&fmk, seq, payload)) {
                return Err(Error::Crypto("forward cell failed integrity check".into()));
            }
            // A zero-length payload is a cover cell — don't relay an empty datagram.
            if payload.is_empty() {
                continue;
            }
            if send_udp.send(payload).await.is_err() {
                break;
            }
        }
        Ok::<(), Error>(())
    };

    // target → client: each received datagram becomes one MAC'd, layered return cell.
    let to_client = async move {
        let mut seq = 0u64;
        let mut buf = vec![0u8; UDP_DATAGRAM_MAX];
        loop {
            let n = match udp.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };
            let payload = &buf[..n];
            let mut body = Vec::with_capacity(CELL_MAC_LEN + n);
            body.extend_from_slice(&cell_mac(&rmk, seq, payload));
            body.extend_from_slice(payload);
            xor_cell(&mut body, &rk, seq);
            let mut cell = Vec::with_capacity(SEQ_LEN + body.len());
            cell.extend_from_slice(&seq.to_be_bytes());
            cell.extend_from_slice(&body);
            let out = pw_sealer.seal(&cell)?;
            if write_frame(&mut pw, &out).await.is_err() {
                break;
            }
            seq = seq
                .checked_add(1)
                .ok_or_else(|| Error::Crypto("splice cell sequence exhausted".into()))?;
        }
        Ok::<(), Error>(())
    };

    tokio::select! {
        r = to_target => r,
        r = to_client => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::{accept, connect};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn exit_port_policy_blocks_abuse_ports() {
        let policy = ExitPolicy::default();
        // Web egress is fine — and DNS (53) is intentionally allowed, so a VPN client
        // can resolve names through the tunnel (blocking it breaks every page load).
        assert!(policy.permits_port(443));
        assert!(policy.permits_port(80));
        assert!(policy.permits_port(8080));
        assert!(
            policy.permits_port(53),
            "DNS must be allowed for name resolution"
        );
        // Abuse-prone ports are refused (reduced-harm default).
        for p in [22u16, 23, 25, 445, 465, 587, 3389, 6667] {
            assert!(!policy.permits_port(p), "port {p} must be denied");
        }
        // The splice-level guard rejects a denied port and accepts a web port.
        assert!(
            check_exit_port("1.1.1.1:25", &policy).is_err(),
            "SMTP refused"
        );
        assert!(
            check_exit_port("1.1.1.1:443", &policy).is_ok(),
            "HTTPS allowed"
        );
    }
    use tokio::task::JoinHandle;

    fn hop_of(identity: &NodeIdentity, addr: &str) -> Hop {
        let p = identity.public();
        Hop {
            id: p.id,
            sphinx: p.sphinx,
            addr: addr.to_string(),
        }
    }

    async fn spawn_serve(
        id_bytes: impl AsRef<[u8]> + Send + 'static,
        resolver: HashMap<NodeId, String>,
    ) -> (String, JoinHandle<Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(id_bytes.as_ref()).unwrap();
            let (stream, result) = accept(&listener, &identity).await.unwrap();
            let replay = Mutex::new(ReplayCache::new());
            // Go through the real relay dispatch so the mode frame is consumed.
            crate::serve::serve_connection(
                &identity,
                stream,
                result.session,
                &resolver,
                &replay,
                ExitPolicy {
                    allow_loopback: true,
                    offer_exit: true,
                },
                None,
            )
            .await
            .map(|_| ())
        });
        (addr, handle)
    }

    /// Bind a localhost TCP echo server; returns its address.
    async fn spawn_echo() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let (mut r, mut w) = sock.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });
        addr
    }

    #[test]
    fn cells_onion_layer_and_authenticate_end_to_end() {
        // Pure-crypto check of the cell onion + per-cell MAC, without sockets.
        let s0 = [1u8; 32]; // relay secret
        let s1 = [2u8; 32]; // exit secret
        let secrets = [s0, s1];
        let seq = 7u64;
        let payload = b"top secret cell payload";

        // Client builds the forward cell body: [mac][payload], layered hop0-outermost.
        let mut body = Vec::new();
        body.extend_from_slice(&cell_mac(&fwd_mac_key(&s1), seq, payload));
        body.extend_from_slice(payload);
        for s in secrets.iter().rev() {
            xor_cell(&mut body, &fwd_key(s), seq);
        }

        // The middle relay strips its layer only; the plaintext stays hidden.
        let mut at_relay = body.clone();
        xor_cell(&mut at_relay, &fwd_key(&s0), seq);
        assert!(
            !at_relay.windows(payload.len()).any(|w| w == payload),
            "a middle relay never sees the plaintext cell"
        );

        // The exit strips its layer, recovers [mac][payload], and the MAC verifies.
        let mut at_exit = at_relay.clone();
        xor_cell(&mut at_exit, &fwd_key(&s1), seq);
        let (mac, recovered) = at_exit.split_at(CELL_MAC_LEN);
        assert!(ct_eq(mac, &cell_mac(&fwd_mac_key(&s1), seq, recovered)));
        assert_eq!(recovered, payload);

        // Maul a byte on the wire: after both layers strip, the MAC fails.
        let mut mauled = body.clone();
        let i = mauled.len() / 2;
        mauled[i] ^= 0xff;
        xor_cell(&mut mauled, &fwd_key(&s0), seq);
        xor_cell(&mut mauled, &fwd_key(&s1), seq);
        let (mac2, rec2) = mauled.split_at(CELL_MAC_LEN);
        assert!(
            !ct_eq(mac2, &cell_mac(&fwd_mac_key(&s1), seq, rec2)),
            "a mauled cell must fail the end-to-end MAC"
        );
    }

    #[tokio::test]
    async fn circuit_carries_a_tcp_byte_stream_both_ways() {
        let echo_addr = spawn_echo().await;

        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();

        let (exit_addr, _exit) = spawn_serve(exit.to_bytes(), HashMap::new()).await;
        let mut resolver = HashMap::new();
        resolver.insert(exit.id(), exit_addr.clone());
        let (relay_addr, _relay) = spawn_serve(relay.to_bytes(), resolver).await;

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];
        let (mut sink, mut stream) = open_circuit(&client, &circuit, &echo_addr).await.unwrap();

        // Send several cells; the exit writes them into the echo socket in order.
        let parts: [&[u8]; 3] = [b"hello ", b"brave ", b"tunnel"];
        for p in parts {
            sink.send(p).await.unwrap();
        }
        let expected: Vec<u8> = parts.concat();

        // TCP is a byte stream: cell boundaries need not match send boundaries, so
        // collect returned bytes until we have the whole echo.
        let mut got = Vec::new();
        while got.len() < expected.len() {
            let chunk = tokio::time::timeout(Duration::from_secs(5), stream.recv())
                .await
                .expect("recv in time")
                .expect("a return cell arrived");
            got.extend_from_slice(&chunk);
        }
        assert_eq!(
            got, expected,
            "the byte stream round-trips through the circuit"
        );
    }

    /// A loopback echo server that accepts *many* connections (mux opens one per
    /// stream).
    async fn spawn_multi_echo() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.into_split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn circuit_multiplexes_streams_in_mux_mode() {
        // The same 2-hop circuit, opened in "mux" mode, carries two independent
        // streams to their own connections over one onion — exercising the exit's
        // ExitFrameSource/Sink codec + serve_mux dispatch over real cells.
        let echo_addr = spawn_multi_echo().await;
        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();
        let (exit_addr, _exit) = spawn_serve(exit.to_bytes(), HashMap::new()).await;
        let mut resolver = HashMap::new();
        resolver.insert(exit.id(), exit_addr.clone());
        let (relay_addr, _relay) = spawn_serve(relay.to_bytes(), resolver).await;
        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];

        let (sink, stream) = open_circuit(&client, &circuit, "mux").await.unwrap();
        let mux = crate::mux::MuxClient::start(sink, stream);

        let mut a = tokio::time::timeout(Duration::from_secs(5), mux.open(&echo_addr))
            .await
            .expect("open a")
            .expect("stream a");
        let mut b = tokio::time::timeout(Duration::from_secs(5), mux.open(&echo_addr))
            .await
            .expect("open b")
            .expect("stream b");
        assert_ne!(a.id(), b.id());

        a.send(b"stream-a").await.unwrap();
        b.send(b"stream-b").await.unwrap();
        let ga = tokio::time::timeout(Duration::from_secs(5), a.recv())
            .await
            .unwrap()
            .unwrap();
        let gb = tokio::time::timeout(Duration::from_secs(5), b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ga.as_deref(), Some(&b"stream-a"[..]));
        assert_eq!(gb.as_deref(), Some(&b"stream-b"[..]));
    }

    #[tokio::test]
    async fn cover_cells_are_dropped_at_the_exit() {
        let echo_addr = spawn_echo().await;
        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();
        let (exit_addr, _exit) = spawn_serve(exit.to_bytes(), HashMap::new()).await;
        let mut resolver = HashMap::new();
        resolver.insert(exit.id(), exit_addr.clone());
        let (relay_addr, _relay) = spawn_serve(relay.to_bytes(), resolver).await;

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];
        let (mut sink, mut stream) = open_circuit(&client, &circuit, &echo_addr).await.unwrap();

        // Interleave cover cells with real data. Cover cells are zero-length, so
        // the exit authenticates every cell (seq is strict) and writes an empty
        // payload for the cover ones — the echo returns only the real bytes, in
        // order, and the cover cells are wire-compatible with any exit.
        sink.send(b"hello ").await.unwrap();
        sink.send_cover().await.unwrap();
        sink.send(b"brave ").await.unwrap();
        sink.send_cover().await.unwrap();
        sink.send(b"tunnel").await.unwrap();
        let expected = b"hello brave tunnel".to_vec();

        let mut got = Vec::new();
        while got.len() < expected.len() {
            let chunk = tokio::time::timeout(Duration::from_secs(5), stream.recv())
                .await
                .expect("recv in time")
                .expect("a return cell arrived");
            got.extend_from_slice(&chunk);
        }
        assert_eq!(
            got, expected,
            "cover cells are authenticated then dropped; only real bytes reach the target"
        );
    }

    /// Bind a localhost UDP echo server; returns its address.
    async fn spawn_udp_echo() -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                if sock.send_to(&buf[..n], from).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    /// A "udp:host:port" circuit carries whole datagrams both ways, with
    /// boundaries preserved (one send == one datagram == one recv).
    #[tokio::test]
    async fn circuit_carries_udp_datagrams_both_ways() {
        let echo_addr = spawn_udp_echo().await;

        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();

        let (exit_addr, _exit) = spawn_serve(exit.to_bytes(), HashMap::new()).await;
        let mut resolver = HashMap::new();
        resolver.insert(exit.id(), exit_addr.clone());
        let (relay_addr, _relay) = spawn_serve(relay.to_bytes(), resolver).await;

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];
        // The "udp:" prefix routes the exit to the datagram splice.
        let target = format!("udp:{echo_addr}");
        let (mut sink, mut stream) = open_circuit(&client, &circuit, &target).await.unwrap();

        let datagrams: [&[u8]; 3] = [b"one", b"two-two", b"three-three-three"];
        for dg in datagrams {
            sink.send(dg).await.unwrap();
            let got = tokio::time::timeout(Duration::from_secs(5), stream.recv())
                .await
                .expect("recv in time")
                .expect("a return datagram arrived");
            assert_eq!(
                got, dg,
                "the datagram round-trips whole through the circuit"
            );
        }
    }

    #[tokio::test]
    async fn a_middle_relay_mauling_a_return_cell_is_caught() {
        let echo_addr = spawn_echo().await;

        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();

        let (exit_addr, _exit) = spawn_serve(exit.to_bytes(), HashMap::new()).await;

        // A malicious middle relay: honest on the forward path, but it flips a byte
        // of the first return cell before passing it back to the client.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap().to_string();
        let relay_bytes = relay.to_bytes();
        let exit_id = exit.id();
        let exit_dst = exit_addr.clone();
        tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&relay_bytes).unwrap();
            let (prev, prev_res) = accept(&listener, &identity).await.unwrap();
            let (mut pr, mut pw) = prev.into_split();
            let (mut pw_sealer, mut pr_opener) = prev_res.session.split();

            let _mode = pr_opener.open(&read_frame(&mut pr).await.unwrap()).unwrap();
            let setup = read_frame(&mut pr).await.unwrap();
            let packet = SphinxPacket::from_bytes(&pr_opener.open(&setup).unwrap()).unwrap();
            let secret = identity.sphinx_shared(packet.alpha()).unwrap();
            let mut cache = ReplayCache::new();
            let Processed::Forward { packet, .. } =
                process(&identity, &mut cache, &packet).unwrap()
            else {
                panic!("relay should forward");
            };
            let _ = exit_id;
            let (next, next_res) = connect(&exit_dst, &identity).await.unwrap();
            let (mut ns_sealer, mut ns_opener) = next_res.session.split();
            let (mut nr, mut nw) = next.into_split();
            write_frame(
                &mut nw,
                &ns_sealer.seal(&[crate::run::FRAME_CIRCUIT]).unwrap(),
            )
            .await
            .unwrap();
            write_frame(&mut nw, &ns_sealer.seal(&packet.to_bytes()).unwrap())
                .await
                .unwrap();

            let fk = fwd_key(&secret);
            let rk = ret_key(&secret);
            let forward = async move {
                while let Ok(f) = read_frame(&mut pr).await {
                    let c = pr_opener.open(&f).unwrap();
                    let out = ns_sealer.seal(&relay_layer(&c, &fk).unwrap()).unwrap();
                    if write_frame(&mut nw, &out).await.is_err() {
                        break;
                    }
                }
            };
            let ret = async move {
                let mut first = true;
                while let Ok(f) = read_frame(&mut nr).await {
                    let c = ns_opener.open(&f).unwrap();
                    let mut r = relay_layer(&c, &rk).unwrap();
                    if first {
                        let i = r.len() - 1; // a body byte
                        r[i] ^= 0xff;
                        first = false;
                    }
                    let out = pw_sealer.seal(&r).unwrap();
                    if write_frame(&mut pw, &out).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(forward, ret);
        });

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];
        let (mut sink, mut stream) = open_circuit(&client, &circuit, &echo_addr).await.unwrap();
        sink.send(b"please echo this").await.unwrap();

        let res = tokio::time::timeout(Duration::from_secs(5), stream.recv())
            .await
            .expect("recv in time");
        assert!(res.is_err(), "client must reject a mauled return cell");
    }

    #[tokio::test]
    async fn a_replayed_return_cell_is_rejected() {
        let echo_addr = spawn_echo().await;
        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();
        let (exit_addr, _exit) = spawn_serve(exit.to_bytes(), HashMap::new()).await;

        // A malicious middle relay that honestly forwards, but re-injects the first
        // return cell a second time under a fresh link counter.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap().to_string();
        let relay_bytes = relay.to_bytes();
        let exit_dst = exit_addr.clone();
        tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&relay_bytes).unwrap();
            let (prev, prev_res) = accept(&listener, &identity).await.unwrap();
            let (mut pr, mut pw) = prev.into_split();
            let (mut pw_sealer, mut pr_opener) = prev_res.session.split();
            let _mode = pr_opener.open(&read_frame(&mut pr).await.unwrap()).unwrap();
            let setup = read_frame(&mut pr).await.unwrap();
            let packet = SphinxPacket::from_bytes(&pr_opener.open(&setup).unwrap()).unwrap();
            let secret = identity.sphinx_shared(packet.alpha()).unwrap();
            let mut cache = ReplayCache::new();
            let Processed::Forward { packet, .. } =
                process(&identity, &mut cache, &packet).unwrap()
            else {
                panic!("relay should forward");
            };
            let (next, next_res) = connect(&exit_dst, &identity).await.unwrap();
            let (mut ns_sealer, mut ns_opener) = next_res.session.split();
            let (mut nr, mut nw) = next.into_split();
            write_frame(
                &mut nw,
                &ns_sealer.seal(&[crate::run::FRAME_CIRCUIT]).unwrap(),
            )
            .await
            .unwrap();
            write_frame(&mut nw, &ns_sealer.seal(&packet.to_bytes()).unwrap())
                .await
                .unwrap();
            let fk = fwd_key(&secret);
            let rk = ret_key(&secret);
            let forward = async move {
                while let Ok(f) = read_frame(&mut pr).await {
                    let c = pr_opener.open(&f).unwrap();
                    let out = ns_sealer.seal(&relay_layer(&c, &fk).unwrap()).unwrap();
                    if write_frame(&mut nw, &out).await.is_err() {
                        break;
                    }
                }
            };
            let ret = async move {
                let mut first = true;
                while let Ok(f) = read_frame(&mut nr).await {
                    let c = ns_opener.open(&f).unwrap();
                    let r = relay_layer(&c, &rk).unwrap();
                    if write_frame(&mut pw, &pw_sealer.seal(&r).unwrap())
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if first {
                        first = false; // replay the very first return cell
                        if write_frame(&mut pw, &pw_sealer.seal(&r).unwrap())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            };
            tokio::join!(forward, ret);
        });

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];
        let (mut sink, mut stream) = open_circuit(&client, &circuit, &echo_addr).await.unwrap();
        sink.send(b"echo me once").await.unwrap();

        // The genuine first cell (seq 0) is delivered; the duplicate is rejected.
        assert!(tokio::time::timeout(Duration::from_secs(5), stream.recv())
            .await
            .expect("recv in time")
            .is_ok());
        assert!(
            tokio::time::timeout(Duration::from_secs(5), stream.recv())
                .await
                .expect("recv in time")
                .is_err(),
            "a replayed return cell must be rejected (out of sequence)"
        );
    }

    #[tokio::test]
    async fn a_relay_without_exit_enabled_refuses_to_splice() {
        // A node that is the circuit's terminal hop but was not started with exit
        // enabled must refuse to splice to the target, tearing the circuit down.
        let echo_addr = spawn_echo().await;
        let exit = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = listener.local_addr().unwrap().to_string();
        let exit_bytes = exit.to_bytes();
        tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&exit_bytes).unwrap();
            let (stream, result) = accept(&listener, &identity).await.unwrap();
            let replay = Mutex::new(ReplayCache::new());
            let _ = crate::serve::serve_connection(
                &identity,
                stream,
                result.session,
                &HashMap::<NodeId, String>::new(),
                &replay,
                ExitPolicy {
                    allow_loopback: true,
                    offer_exit: false, // exit NOT offered
                },
                None,
            )
            .await;
        });

        let circuit = vec![hop_of(&exit, &exit_addr)];
        let (mut sink, mut stream) = open_circuit(&client, &circuit, &echo_addr).await.unwrap();
        let _ = sink.send(b"should never reach the target").await;
        // No splice happens, so no return bytes ever arrive — the circuit is dead.
        let res = tokio::time::timeout(Duration::from_secs(5), stream.recv())
            .await
            .expect("recv resolves in time");
        assert!(res.is_err(), "a non-exit relay must refuse to splice");
    }
}
