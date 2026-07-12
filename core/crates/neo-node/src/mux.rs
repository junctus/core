//! Stream multiplexing over a single circuit (M-next).
//!
//! Today a circuit carries **one** byte stream (the exit splices one TCP target
//! fixed at setup). This layer runs **many independent logical streams** over that
//! one circuit, each opened on demand to its own target — the shape a SOCKS proxy
//! or a full VPN return path needs — with **per-stream flow control** so one busy
//! stream can't starve another or make a peer buffer without bound.
//!
//! ## Where it sits
//!
//! The circuit ([`crate::circuit`]) already gives a **reliable, in-order,
//! integrity-checked, replay-resistant** bidirectional channel (per-cell
//! end-to-end MAC + strict sequencing). The mux is a small framing protocol *over*
//! that channel, so it inherits all of those guarantees and adds none of its own
//! crypto: a middle relay still cannot read, forge, reorder, or replay a cell, and
//! therefore cannot do so to a mux frame either.
//!
//! It is defined over the [`FrameSink`] / [`FrameSource`] traits (one reliable
//! frame each way), implemented by `CircuitSink`/`CircuitStream` in production and
//! by an in-memory duplex in tests, so the whole protocol is testable with no
//! sockets.
//!
//! ## Frames
//!
//! One frame per circuit cell: `type(1) ‖ stream_id(4) ‖ body`.
//! - `OPEN`   — `target_len(2) ‖ target`: open `stream_id` to a clearnet target.
//! - `DATA`   — `bytes`: application bytes for `stream_id`.
//! - `CLOSE`  — end-of-stream from this side (half-close).
//! - `WINDOW` — `credit(4)`: grant `credit` more send-bytes for `stream_id`.
//! - `RESET`  — abort `stream_id` (open refused by policy, dial failed, or error).
//!
//! ## Flow control
//!
//! Each stream has a **receive window** (bytes the peer may send before blocking).
//! It is modeled as a byte [`Semaphore`]: a sender acquires `n` permits to send `n`
//! bytes; the receiver returns `n` permits (a `WINDOW` frame) as the application
//! *consumes* those bytes. In-flight unacked data per stream is thus bounded by the
//! window, which bounds total memory to `window × open_streams`. Aggregate
//! congestion control (matching the circuit's capacity across streams) is a further
//! refinement; per-stream windows are the correctness-critical part and are here.

use std::collections::HashMap;
use std::sync::Arc;

use neo_core::{Error, Result};
use tokio::sync::{mpsc, Semaphore};

use crate::circuit::{CircuitSink, CircuitStream, ExitPolicy};

/// A reliable, ordered, integrity-checked frame **sink** — the write half of a
/// circuit. One `send` = one cell.
pub trait FrameSink: Send + 'static {
    fn send_frame(
        &mut self,
        frame: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// A reliable, ordered, integrity-checked frame **source** — the read half of a
/// circuit. One `recv` = one cell.
pub trait FrameSource: Send + 'static {
    fn recv_frame(&mut self) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

impl FrameSink for CircuitSink {
    async fn send_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        self.send(&frame).await
    }
}

impl FrameSource for CircuitStream {
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        self.recv().await
    }
}

const T_OPEN: u8 = 1;
const T_DATA: u8 = 2;
const T_CLOSE: u8 = 3;
const T_WINDOW: u8 = 4;
const T_RESET: u8 = 5;

/// Initial per-stream receive window (bytes the peer may send before it must wait
/// for the application to consume and return credit).
pub const DEFAULT_WINDOW: u32 = 256 * 1024;
/// Largest application chunk carried in one `DATA` frame (keeps a cell bounded and
/// lets flow control act at a fine grain).
pub const MAX_FRAME_DATA: usize = 16 * 1024;
/// Hard cap on concurrently open streams, so a peer can't exhaust memory by opening
/// unbounded streams.
pub const MAX_STREAMS: usize = 1024;

/// A parsed mux frame.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Frame {
    Open { id: u32, target: String },
    Data { id: u32, bytes: Vec<u8> },
    Close { id: u32 },
    Window { id: u32, credit: u32 },
    Reset { id: u32 },
}

impl Frame {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        match self {
            Frame::Open { id, target } => {
                out.push(T_OPEN);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&(target.len() as u16).to_be_bytes());
                out.extend_from_slice(target.as_bytes());
            }
            Frame::Data { id, bytes } => {
                out.push(T_DATA);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Frame::Close { id } => {
                out.push(T_CLOSE);
                out.extend_from_slice(&id.to_be_bytes());
            }
            Frame::Window { id, credit } => {
                out.push(T_WINDOW);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&credit.to_be_bytes());
            }
            Frame::Reset { id } => {
                out.push(T_RESET);
                out.extend_from_slice(&id.to_be_bytes());
            }
        }
        out
    }

    /// Parse a frame, or `None` on any malformed input (never panics on hostile
    /// bytes from a peer).
    fn decode(b: &[u8]) -> Option<Frame> {
        let (&ty, rest) = b.split_first()?;
        let id = u32::from_be_bytes(rest.get(0..4)?.try_into().ok()?);
        let body = &rest[4..];
        Some(match ty {
            T_OPEN => {
                let tlen = u16::from_be_bytes(body.get(0..2)?.try_into().ok()?) as usize;
                let target = std::str::from_utf8(body.get(2..2 + tlen)?)
                    .ok()?
                    .to_string();
                Frame::Open { id, target }
            }
            T_DATA => Frame::Data {
                id,
                bytes: body.to_vec(),
            },
            T_CLOSE => Frame::Close { id },
            T_WINDOW => Frame::Window {
                id,
                credit: u32::from_be_bytes(body.get(0..4)?.try_into().ok()?),
            },
            T_RESET => Frame::Reset { id },
            _ => return None,
        })
    }
}

/// Per-stream state the driver holds.
struct StreamState {
    /// Delivers inbound DATA to the stream's reader.
    inbound: mpsc::Sender<StreamEvent>,
    /// Send-window credit: a sender acquires permits to send; a peer `WINDOW`
    /// frame adds permits. Shared with the [`MuxStream`] handle.
    send_window: Arc<Semaphore>,
}

/// What a reader receives.
#[derive(Debug)]
enum StreamEvent {
    Data(Vec<u8>),
    Closed,
    Reset,
}

/// A command from a [`MuxStream`] handle (or the opener) to the driver.
enum Command {
    Open {
        target: String,
        reply: tokio::sync::oneshot::Sender<Result<MuxStream>>,
    },
    Send {
        frame: Frame,
    },
}

/// A single logical stream over the mux. Can be [`split`](MuxStream::split) into a
/// send half and a receive half so the two directions run concurrently.
pub struct MuxStream {
    tx: MuxStreamTx,
    rx: MuxStreamRx,
}

/// The send half of a [`MuxStream`].
pub struct MuxStreamTx {
    id: u32,
    commands: mpsc::Sender<Command>,
    send_window: Arc<Semaphore>,
}

/// The receive half of a [`MuxStream`].
pub struct MuxStreamRx {
    id: u32,
    commands: mpsc::Sender<Command>,
    inbound: mpsc::Receiver<StreamEvent>,
    /// Whether we've seen EOF/close/reset from the peer.
    peer_done: bool,
}

impl MuxStream {
    /// The stream's id (for diagnostics).
    pub fn id(&self) -> u32 {
        self.tx.id
    }

    /// Send application bytes (see [`MuxStreamTx::send`]).
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.tx.send(data).await
    }

    /// Receive the next inbound chunk (see [`MuxStreamRx::recv`]).
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        self.rx.recv().await
    }

    /// Half-close (see [`MuxStreamTx::close`]).
    pub async fn close(&mut self) -> Result<()> {
        self.tx.close().await
    }

    /// Split into independent send and receive halves so both directions can be
    /// driven concurrently (e.g. a proxy that pumps both ways).
    pub fn split(self) -> (MuxStreamTx, MuxStreamRx) {
        (self.tx, self.rx)
    }
}

impl MuxStreamTx {
    /// Send application bytes, respecting the peer's receive window (this awaits
    /// window credit rather than letting the peer buffer without bound). Splits
    /// into [`MAX_FRAME_DATA`] chunks.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(MAX_FRAME_DATA) {
            // Acquire `chunk.len()` bytes of send-window; the permits are returned
            // to us as WINDOW credit when the peer consumes them.
            let permit = self
                .send_window
                .acquire_many(chunk.len() as u32)
                .await
                .map_err(|_| Error::Config("mux stream closed".into()))?;
            permit.forget();
            self.commands
                .send(Command::Send {
                    frame: Frame::Data {
                        id: self.id,
                        bytes: chunk.to_vec(),
                    },
                })
                .await
                .map_err(|_| Error::Config("mux driver gone".into()))?;
        }
        Ok(())
    }

    /// Half-close: tell the peer no more data will follow from this side.
    pub async fn close(&mut self) -> Result<()> {
        self.commands
            .send(Command::Send {
                frame: Frame::Close { id: self.id },
            })
            .await
            .map_err(|_| Error::Config("mux driver gone".into()))
    }
}

impl MuxStreamRx {
    /// Receive the next chunk of inbound bytes, or `None` at end of stream. Returns
    /// credit to the peer (a `WINDOW` frame) as the bytes are consumed, replenishing
    /// its send window.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        if self.peer_done {
            return Ok(None);
        }
        match self.inbound.recv().await {
            Some(StreamEvent::Data(bytes)) => {
                // Grant the peer credit for the bytes we just consumed.
                let _ = self
                    .commands
                    .send(Command::Send {
                        frame: Frame::Window {
                            id: self.id,
                            credit: bytes.len() as u32,
                        },
                    })
                    .await;
                Ok(Some(bytes))
            }
            Some(StreamEvent::Closed) | None => {
                self.peer_done = true;
                Ok(None)
            }
            Some(StreamEvent::Reset) => {
                self.peer_done = true;
                Err(Error::Config("mux stream reset by peer".into()))
            }
        }
    }
}

/// The client end of a mux: opens streams to targets over one circuit.
pub struct MuxClient {
    commands: mpsc::Sender<Command>,
}

impl MuxClient {
    /// Start a client mux over a circuit's two halves, spawning the driver task.
    /// Generic over the frame channel so it works over `CircuitSink`/`CircuitStream`
    /// (production) or an in-memory duplex (tests).
    pub fn start<Si: FrameSink, So: FrameSource>(sink: Si, source: So) -> MuxClient {
        let (commands_tx, commands_rx) = mpsc::channel(256);
        let driver = Driver::new(commands_tx.clone(), None);
        tokio::spawn(driver.run(sink, source, commands_rx));
        MuxClient {
            commands: commands_tx,
        }
    }

    /// Open a new stream to `target` (`host:port`). The exit applies its SSRF +
    /// port policy; a refused target comes back as an error.
    pub async fn open(&self, target: &str) -> Result<MuxStream> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.commands
            .send(Command::Open {
                target: target.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Config("mux driver gone".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::Config("mux driver dropped the open".into()))?
    }
}

/// Run the exit end of a mux: accept `OPEN`s, dial the targets (SSRF + port policy),
/// and splice each to its stream. Returns when the circuit closes. Generic over the
/// frame channel (the exit uses its own single-layer cell codec).
pub async fn serve_mux<Si: FrameSink, So: FrameSource>(
    sink: Si,
    source: So,
    policy: ExitPolicy,
) -> Result<()> {
    let (commands_tx, commands_rx) = mpsc::channel(256);
    let driver = Driver::new(commands_tx.clone(), Some(policy));
    driver.run(sink, source, commands_rx).await
}

/// The single owner of the frame channel; demuxes inbound frames to streams and
/// serializes outbound frames from all streams.
struct Driver {
    commands_tx: mpsc::Sender<Command>,
    /// `Some` on the exit end (dials targets on OPEN); `None` on the client end.
    exit_policy: Option<ExitPolicy>,
    streams: HashMap<u32, StreamState>,
    next_id: u32,
}

impl Driver {
    fn new(commands_tx: mpsc::Sender<Command>, exit_policy: Option<ExitPolicy>) -> Self {
        Driver {
            commands_tx,
            exit_policy,
            streams: HashMap::new(),
            // Client streams are odd, exit-originated (none today) even — but the
            // client is the only opener, so a simple counter suffices.
            next_id: 1,
        }
    }

    async fn run<Si: FrameSink, So: FrameSource>(
        mut self,
        mut sink: Si,
        mut source: So,
        mut commands: mpsc::Receiver<Command>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                // Outbound: a stream (or opener) wants to send a frame.
                cmd = commands.recv() => {
                    match cmd {
                        Some(Command::Send { frame }) => {
                            if sink.send_frame(frame.encode()).await.is_err() {
                                break;
                            }
                        }
                        Some(Command::Open { target, reply }) => {
                            let stream = self.local_open(&target, &mut sink).await;
                            let _ = reply.send(stream);
                        }
                        None => break, // all handles dropped
                    }
                }
                // Inbound: a frame arrived from the peer.
                framed = source.recv_frame() => {
                    let Ok(bytes) = framed else { break };
                    let Some(frame) = Frame::decode(&bytes) else { continue };
                    if self.handle_inbound(frame, &mut sink).await.is_err() {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Client side: allocate an id, register the stream, and send `OPEN`.
    async fn local_open<Si: FrameSink>(
        &mut self,
        target: &str,
        sink: &mut Si,
    ) -> Result<MuxStream> {
        if self.streams.len() >= MAX_STREAMS {
            return Err(Error::Config("too many open mux streams".into()));
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(2).max(1);
        let (stream, state) = self.make_stream(id);
        self.streams.insert(id, state);
        sink.send_frame(
            Frame::Open {
                id,
                target: target.to_string(),
            }
            .encode(),
        )
        .await?;
        Ok(stream)
    }

    /// Build a [`MuxStream`] handle + the driver-side [`StreamState`] for `id`.
    fn make_stream(&self, id: u32) -> (MuxStream, StreamState) {
        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        let send_window = Arc::new(Semaphore::new(DEFAULT_WINDOW as usize));
        let stream = MuxStream {
            tx: MuxStreamTx {
                id,
                commands: self.commands_tx.clone(),
                send_window: send_window.clone(),
            },
            rx: MuxStreamRx {
                id,
                commands: self.commands_tx.clone(),
                inbound: inbound_rx,
                peer_done: false,
            },
        };
        let state = StreamState {
            inbound: inbound_tx,
            send_window,
        };
        (stream, state)
    }

    async fn handle_inbound<Si: FrameSink>(&mut self, frame: Frame, sink: &mut Si) -> Result<()> {
        match frame {
            Frame::Open { id, target } => self.handle_open(id, target, sink).await?,
            Frame::Data { id, bytes } => {
                if let Some(s) = self.streams.get(&id) {
                    // If the reader is gone, drop the data (the stream will be reset
                    // by its Close/Reset path); never block the whole mux on one
                    // slow reader beyond its window.
                    let _ = s.inbound.send(StreamEvent::Data(bytes)).await;
                }
            }
            Frame::Window { id, credit } => {
                if let Some(s) = self.streams.get(&id) {
                    // Grant our sender that many more bytes of window.
                    s.send_window.add_permits(credit as usize);
                }
            }
            Frame::Close { id } => {
                if let Some(s) = self.streams.get(&id) {
                    let _ = s.inbound.send(StreamEvent::Closed).await;
                }
            }
            Frame::Reset { id } => {
                if let Some(s) = self.streams.remove(&id) {
                    let _ = s.inbound.send(StreamEvent::Reset).await;
                }
            }
        }
        Ok(())
    }

    /// Exit side: an `OPEN` arrived — enforce policy, dial, and pump the target.
    async fn handle_open<Si: FrameSink>(
        &mut self,
        id: u32,
        target: String,
        sink: &mut Si,
    ) -> Result<()> {
        let Some(policy) = self.exit_policy else {
            // The client end never accepts inbound OPENs.
            let _ = sink.send_frame(Frame::Reset { id }.encode()).await;
            return Ok(());
        };
        if self.streams.len() >= MAX_STREAMS {
            let _ = sink.send_frame(Frame::Reset { id }.encode()).await;
            return Ok(());
        }
        // SSRF + reduced-harm port policy, exactly as the single-stream exit.
        if !neo_core::net::is_safe_dial_target(&target, policy.allow_loopback)
            || !target
                .parse::<std::net::SocketAddr>()
                .map(|sa| policy.permits_port(sa.port()))
                .unwrap_or(false)
        {
            let _ = sink.send_frame(Frame::Reset { id }.encode()).await;
            return Ok(());
        }
        let tcp = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            crate::netif::connect_scoped(&target),
        )
        .await
        {
            Ok(Ok(tcp)) => tcp,
            _ => {
                let _ = sink.send_frame(Frame::Reset { id }.encode()).await;
                return Ok(());
            }
        };
        // Register the stream and spawn a pump: target → DATA frames (respecting the
        // client's window), and inbound DATA → the target socket.
        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        let send_window = Arc::new(Semaphore::new(DEFAULT_WINDOW as usize));
        self.streams.insert(
            id,
            StreamState {
                inbound: inbound_tx,
                send_window: send_window.clone(),
            },
        );
        tokio::spawn(pump_target(
            id,
            tcp,
            inbound_rx,
            send_window,
            self.commands_tx.clone(),
        ));
        Ok(())
    }
}

/// The exit-side per-stream pump: copies the target socket → `DATA` frames (bounded
/// by the client's window) and inbound `DATA`/`CLOSE` → the target socket.
async fn pump_target(
    id: u32,
    tcp: tokio::net::TcpStream,
    mut inbound: mpsc::Receiver<StreamEvent>,
    send_window: Arc<Semaphore>,
    commands: mpsc::Sender<Command>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut tr, mut tw) = tcp.into_split();

    // target → client
    let up = {
        let commands = commands.clone();
        async move {
            let mut buf = vec![0u8; MAX_FRAME_DATA];
            loop {
                let n = match tr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                // Respect the client's receive window before emitting DATA.
                let Ok(permit) = send_window.acquire_many(n as u32).await else {
                    break;
                };
                permit.forget();
                if commands
                    .send(Command::Send {
                        frame: Frame::Data {
                            id,
                            bytes: buf[..n].to_vec(),
                        },
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = commands
                .send(Command::Send {
                    frame: Frame::Close { id },
                })
                .await;
        }
    };

    // client → target
    let down = async move {
        while let Some(ev) = inbound.recv().await {
            match ev {
                StreamEvent::Data(bytes) => {
                    // Return window credit to the client for what we accepted, then
                    // write it to the target.
                    let _ = commands
                        .send(Command::Send {
                            frame: Frame::Window {
                                id,
                                credit: bytes.len() as u32,
                            },
                        })
                        .await;
                    if tw.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                StreamEvent::Closed | StreamEvent::Reset => break,
            }
        }
        let _ = tw.shutdown().await;
    };

    tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
    use super::*;

    // An in-memory reliable frame duplex standing in for a circuit, so the whole
    // mux protocol is testable without sockets.
    struct MemSink(mpsc::Sender<Vec<u8>>);
    struct MemSource(mpsc::Receiver<Vec<u8>>);

    impl FrameSink for MemSink {
        async fn send_frame(&mut self, frame: Vec<u8>) -> Result<()> {
            self.0
                .send(frame)
                .await
                .map_err(|_| Error::Config("mem sink closed".into()))
        }
    }
    impl FrameSource for MemSource {
        async fn recv_frame(&mut self) -> Result<Vec<u8>> {
            self.0
                .recv()
                .await
                .ok_or_else(|| Error::Config("mem source closed".into()))
        }
    }

    /// Wire a client mux and an exit mux together over two in-memory frame
    /// channels and return the client handle. No sockets between the two ends — the
    /// circuit's reliability is assumed (that's the circuit's job, tested there).
    fn connected_mux() -> MuxClient {
        let (c2e_tx, c2e_rx) = mpsc::channel::<Vec<u8>>(256);
        let (e2c_tx, e2c_rx) = mpsc::channel::<Vec<u8>>(256);

        // Client driver (never accepts inbound OPENs).
        let (client_cmds_tx, client_cmds_rx) = mpsc::channel(256);
        let client_driver = Driver::new(client_cmds_tx.clone(), None);
        tokio::spawn(client_driver.run(MemSink(c2e_tx), MemSource(e2c_rx), client_cmds_rx));

        // Exit driver (dials loopback targets in the test).
        let policy = ExitPolicy {
            allow_loopback: true,
            offer_exit: true,
        };
        let (exit_cmds_tx, exit_cmds_rx) = mpsc::channel(256);
        let exit_driver = Driver::new(exit_cmds_tx.clone(), Some(policy));
        tokio::spawn(exit_driver.run(MemSink(e2c_tx), MemSource(c2e_rx), exit_cmds_rx));

        MuxClient {
            commands: client_cmds_tx,
        }
    }

    /// A loopback echo server; returns its address.
    async fn echo_server() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn two_streams_multiplex_independently_over_one_channel() {
        let echo = echo_server().await;
        let client = connected_mux();

        let mut a = client.open(&echo).await.unwrap();
        let mut b = client.open(&echo).await.unwrap();
        assert_ne!(a.id(), b.id(), "streams get distinct ids");

        // Interleave: each stream echoes only its own bytes.
        a.send(b"apple").await.unwrap();
        b.send(b"banana").await.unwrap();
        assert_eq!(a.recv().await.unwrap().as_deref(), Some(&b"apple"[..]));
        assert_eq!(b.recv().await.unwrap().as_deref(), Some(&b"banana"[..]));

        // Half-close A; B keeps working — proving independence.
        a.close().await.unwrap();
        b.send(b"cherry").await.unwrap();
        assert_eq!(b.recv().await.unwrap().as_deref(), Some(&b"cherry"[..]));
    }

    #[tokio::test]
    async fn flow_control_carries_more_than_one_window() {
        // Push well past DEFAULT_WINDOW so the send-window must be replenished by
        // WINDOW frames as the reader consumes — the whole payload must arrive. The
        // two directions run concurrently via split(), or the echo would back up and
        // deadlock against the window (which is exactly the property under test).
        let echo = echo_server().await;
        let client = connected_mux();
        let (mut tx, mut rx) = client.open(&echo).await.unwrap().split();

        let total = (DEFAULT_WINDOW as usize) * 3 + 12345;
        let payload: Vec<u8> = (0..total).map(|i| i as u8).collect();

        let p = payload.clone();
        let sender = tokio::spawn(async move {
            tx.send(&p).await.unwrap();
            tx.close().await.unwrap();
        });
        let mut got = Vec::with_capacity(total);
        while got.len() < total {
            match rx.recv().await.unwrap() {
                Some(chunk) => got.extend_from_slice(&chunk),
                None => break,
            }
        }
        sender.await.unwrap();
        assert_eq!(
            got.len(),
            total,
            "the full multi-window payload round-trips"
        );
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn a_policy_refused_target_resets_the_stream() {
        let client = connected_mux();
        // SMTP:25 is on the reduced-harm denylist → the exit resets the stream.
        let mut s = client.open("1.2.3.4:25").await.unwrap();
        let err = s.recv().await;
        assert!(err.is_err(), "a refused target must reset, not connect");
    }

    #[test]
    fn frame_round_trips_and_rejects_garbage() {
        let frames = [
            Frame::Open {
                id: 7,
                target: "1.2.3.4:443".into(),
            },
            Frame::Data {
                id: 7,
                bytes: vec![1, 2, 3, 4],
            },
            Frame::Window { id: 7, credit: 999 },
            Frame::Close { id: 7 },
            Frame::Reset { id: 7 },
        ];
        for f in frames {
            assert_eq!(Frame::decode(&f.encode()), Some(f));
        }
        // Hostile / short inputs never panic and decode to None.
        assert_eq!(Frame::decode(&[]), None);
        assert_eq!(Frame::decode(&[T_OPEN]), None);
        assert_eq!(Frame::decode(&[T_WINDOW, 0, 0, 0, 1]), None); // no credit
        assert_eq!(Frame::decode(&[T_OPEN, 0, 0, 0, 1, 0, 9]), None); // target len > body
        assert_eq!(Frame::decode(&[99, 0, 0, 0, 1]), None); // unknown type
    }
}
