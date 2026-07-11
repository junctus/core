//! The gateway: a smoltcp poll loop that intercepts TCP flows.
//!
//! smoltcp normally implements a *host* with its own address. Here it runs as a
//! **gateway** (`set_any_ip`): the OS routes every connection to our TUN, and for
//! each new TCP SYN — to *any* destination — we open a listening socket bound to
//! that destination, let smoltcp complete the handshake, and hand the caller a
//! [`Connection`] with the original destination and an async byte stream.
//!
//! The loop is synchronous (smoltcp is), so it runs on its own thread. Every
//! wakeup — an inbound packet, bytes to write back to a flow, a close — arrives on
//! one [`Cmd`] channel, whose `recv_timeout` also honours smoltcp's timers.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, TcpPacket,
    UdpPacket, UdpRepr,
};
use tokio::sync::mpsc;

/// Drop a UDP NAT entry after this long with no packet in either direction. UDP
/// is connectionless, so unlike TCP there's no FIN to reap on; DNS and most UDP
/// exchanges are brief, so a short idle window keeps the table small.
const UDP_IDLE: Duration = Duration::from_secs(30);

use crate::device::{ChannelDevice, MTU};

/// The gateway's own on-link address; the TUN's local address (`10.9.0.2`) sits
/// in the same /24 so locally-terminated replies route straight back to it.
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
/// Per-socket buffer capacity (bytes) in each direction.
const SOCK_BUF: usize = 64 * 1024;

/// One intercepted TCP flow. `dst` is the address the client tried to reach; the
/// caller pumps the byte stream through a neo circuit opened to that `dst`.
///
/// [`split`](Self::split) yields a [`ConnReader`] and a cloneable [`ConnWriter`]
/// so the two directions can be driven by independent tasks.
pub struct Connection {
    /// The original destination the client connected to.
    pub dst: SocketAddr,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    writer: ConnWriter,
}

impl Connection {
    /// Await the next chunk of client bytes, or `None` once the flow is closed.
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        self.incoming.recv().await
    }

    /// Queue `data` to be written back to the client. Non-blocking.
    pub fn write(&self, data: Vec<u8>) {
        self.writer.write(data);
    }

    /// Close the flow (sends a FIN once buffered writes drain).
    pub fn close(&self) {
        self.writer.close();
    }

    /// Split into the client-byte reader and a cloneable writer.
    pub fn split(self) -> (ConnReader, ConnWriter) {
        (
            ConnReader {
                dst: self.dst,
                incoming: self.incoming,
            },
            self.writer,
        )
    }
}

/// The read half of a [`Connection`]: bytes from the client, bound for the circuit.
pub struct ConnReader {
    pub dst: SocketAddr,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl ConnReader {
    /// Await the next chunk of client bytes, or `None` once the flow is closed.
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        self.incoming.recv().await
    }
}

/// The write half of a [`Connection`]: bytes from the circuit, bound for the
/// client. Cheap to clone; dropping the last one does not close the flow (call
/// [`close`](Self::close) for that).
#[derive(Clone)]
pub struct ConnWriter {
    cmd: std_mpsc::Sender<Cmd>,
    handle: SocketHandle,
}

impl ConnWriter {
    /// Queue `data` to be written back to the client. Non-blocking.
    pub fn write(&self, data: Vec<u8>) {
        if !data.is_empty() {
            let _ = self.cmd.send(Cmd::Write(self.handle, data));
        }
    }

    /// Close the flow (sends a FIN once buffered writes drain).
    pub fn close(&self) {
        let _ = self.cmd.send(Cmd::Close(self.handle));
    }
}

/// Commands into the poll loop — the single wakeup source.
enum Cmd {
    /// A raw IP packet arrived from the TUN.
    Inbound(Vec<u8>),
    /// Bytes to write back to a flow's client.
    Write(SocketHandle, Vec<u8>),
    /// Close a flow.
    Close(SocketHandle),
    /// A fully-built IP packet to emit to the TUN (a UDP reply we constructed
    /// outside the poll loop; smoltcp isn't involved for UDP).
    SendRaw(Vec<u8>),
}

/// One intercepted UDP flow: the datagrams a client sent to `dst`, plus a
/// [`UdpReply`] that wraps circuit responses back into UDP/IP packets to the
/// client. The caller pumps `incoming` through a `udp:`-tagged neo circuit.
pub struct UdpFlow {
    /// The original destination the client sent datagrams to.
    pub dst: SocketAddr,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    reply: UdpReply,
}

impl UdpFlow {
    /// Await the next datagram from the client, or `None` once the flow is reaped.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.incoming.recv().await
    }

    /// Send one datagram (a circuit response) back to the client.
    pub fn reply(&self, datagram: &[u8]) {
        self.reply.send(datagram);
    }

    /// Split into the datagram reader and a cloneable reply handle.
    pub fn split(self) -> (mpsc::UnboundedReceiver<Vec<u8>>, UdpReply) {
        (self.incoming, self.reply)
    }
}

/// Wraps a circuit's return datagrams into UDP/IP packets addressed back to the
/// client (from the original target), and queues them for the TUN. Cloneable.
#[derive(Clone)]
pub struct UdpReply {
    cmd: std_mpsc::Sender<Cmd>,
    /// The client's address (packet destination on the way back).
    client: SocketAddrV4,
    /// The target's address (packet source on the way back).
    target: SocketAddrV4,
}

impl UdpReply {
    /// Build a UDP/IP packet `target → client` carrying `datagram` and queue it
    /// for emission to the TUN. No-op if the client/target aren't IPv4.
    pub fn send(&self, datagram: &[u8]) {
        let packet = build_udp_v4(self.target, self.client, datagram);
        let _ = self.cmd.send(Cmd::SendRaw(packet));
    }
}

/// Per-flow UDP NAT state kept in the poll loop.
struct UdpNat {
    /// Datagrams from the client → the circuit.
    incoming_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Last time a packet moved in either direction (for idle reaping).
    last_seen: Instant,
}

/// The UDP state [`apply_cmd`] needs, bundled to keep its signature small. Holds
/// borrows of the poll loop's NAT table and the flow/command channels.
struct UdpCtx<'a> {
    nat: &'a mut HashMap<(SocketAddr, SocketAddr), UdpNat>,
    conn_tx: &'a mpsc::UnboundedSender<UdpFlow>,
    cmd_tx: &'a std_mpsc::Sender<Cmd>,
}

impl UdpCtx<'_> {
    /// A client datagram to `dst`: announce the flow on first sight, then forward
    /// the payload to its circuit. IPv4 only (the TUN carries IPv4).
    fn inbound(&mut self, src: SocketAddr, dst: SocketAddr, payload: Vec<u8>) {
        let (SocketAddr::V4(client), SocketAddr::V4(target)) = (src, dst) else {
            return;
        };
        // `self.cmd_tx`/`conn_tx` are shared refs (Copy); copy them out so the
        // or_insert_with closure doesn't borrow `self` while `nat` is borrowed.
        let cmd_tx = self.cmd_tx;
        let conn_tx = self.conn_tx;
        let entry = self.nat.entry((src, dst)).or_insert_with(|| {
            let (incoming_tx, incoming) = mpsc::unbounded_channel();
            let _ = conn_tx.send(UdpFlow {
                dst,
                incoming,
                reply: UdpReply {
                    cmd: cmd_tx.clone(),
                    client,
                    target,
                },
            });
            UdpNat {
                incoming_tx,
                last_seen: now(),
            }
        });
        entry.last_seen = now();
        let _ = entry.incoming_tx.send(payload);
    }
}

/// Parse an IPv4 UDP packet's `(client, dst, payload)`; `None` if not IPv4 UDP.
fn parse_udp(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
    if packet.first().map(|b| b >> 4) != Some(4) {
        return None; // the TUN is IPv4-only (NEIPv4Settings); ignore anything else
    }
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    let src = SocketAddr::new(IpAddr::V4(ip.src_addr()), udp.src_port());
    let dst = SocketAddr::new(IpAddr::V4(ip.dst_addr()), udp.dst_port());
    Some((src, dst, udp.payload().to_vec()))
}

/// Build an IPv4 UDP packet `from → to` carrying `payload`, with correct IP and
/// UDP checksums (via smoltcp's repr emit).
fn build_udp_v4(from: SocketAddrV4, to: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let udp_repr = UdpRepr {
        src_port: from.port(),
        dst_port: to.port(),
    };
    let ip_repr = Ipv4Repr {
        src_addr: *from.ip(),
        dst_addr: *to.ip(),
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + payload.len(),
        hop_limit: 64,
    };
    let caps = ChecksumCapabilities::default();
    let mut buf = vec![0u8; ip_repr.buffer_len() + ip_repr.payload_len];
    let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
    ip_repr.emit(&mut ip_pkt, &caps);
    let src_ip = IpAddress::from(IpAddr::V4(*from.ip()));
    let dst_ip = IpAddress::from(IpAddr::V4(*to.ip()));
    let mut udp_pkt = UdpPacket::new_unchecked(ip_pkt.payload_mut());
    udp_repr.emit(
        &mut udp_pkt,
        &src_ip,
        &dst_ip,
        payload.len(),
        |b| b.copy_from_slice(payload),
        &caps,
    );
    buf
}

/// Outbound IP packets the stack wants written back to the TUN.
pub type Outbound = mpsc::UnboundedReceiver<Vec<u8>>;
/// The stream of intercepted TCP flows.
pub type Connections = mpsc::UnboundedReceiver<Connection>;
/// The stream of intercepted UDP flows.
pub type UdpConnections = mpsc::UnboundedReceiver<UdpFlow>;

/// The control handle for a running stack: feed it TUN packets with
/// [`inject`](Self::inject). Dropping it stops the poll loop. The two output
/// streams — outbound packets and intercepted flows — are owned separately (see
/// [`new`](Self::new)) so a caller can await both concurrently.
pub struct NetStack {
    cmd: std_mpsc::Sender<Cmd>,
    stop: Arc<AtomicBool>,
}

impl NetStack {
    /// Build a stack, start its poll loop thread, and return the control handle
    /// plus the outbound-packet and intercepted-flow streams.
    pub fn new() -> (NetStack, Outbound, Connections, UdpConnections) {
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<Cmd>();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (conn_tx, conn_rx) = mpsc::unbounded_channel::<Connection>();
        let (udp_tx, udp_rx) = mpsc::unbounded_channel::<UdpFlow>();
        let stop = Arc::new(AtomicBool::new(false));

        let loop_cmd_tx = cmd_tx.clone();
        let loop_stop = stop.clone();
        std::thread::Builder::new()
            .name("neo-netstack".into())
            .spawn(move || {
                run_loop(cmd_rx, loop_cmd_tx, outbound_tx, conn_tx, udp_tx, loop_stop);
            })
            .expect("spawn netstack thread");

        (NetStack { cmd: cmd_tx, stop }, outbound_rx, conn_rx, udp_rx)
    }

    /// Feed one inbound IP packet (from the TUN) into the stack.
    pub fn inject(&self, packet: Vec<u8>) {
        let _ = self.cmd.send(Cmd::Inbound(packet));
    }
}

impl Drop for NetStack {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the loop's recv_timeout so it observes the stop flag promptly.
        let _ = self.cmd.send(Cmd::Close(SocketHandle::default()));
    }
}

/// Loop-side per-flow state.
struct Flow {
    dst: SocketAddr,
    incoming_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Client byte stream to announce (moved into the `Connection` on establish).
    to_announce: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    announced: bool,
    pending_write: Vec<u8>,
    closing: bool,
}

fn now() -> Instant {
    let since = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    Instant::from_micros(since.as_micros() as i64)
}

fn run_loop(
    cmd_rx: std_mpsc::Receiver<Cmd>,
    conn_cmd_tx: std_mpsc::Sender<Cmd>,
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    conn_tx: mpsc::UnboundedSender<Connection>,
    udp_conn_tx: mpsc::UnboundedSender<UdpFlow>,
    stop: Arc<AtomicBool>,
) {
    let mut device = ChannelDevice::new(MTU);
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9);
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = seed;
    let mut iface = Interface::new(config, &mut device, now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::from(GATEWAY_IP), 24));
    });

    let mut sockets = SocketSet::new(Vec::new());
    let mut flows: HashMap<SocketHandle, Flow> = HashMap::new();
    // 4-tuple (client, dst) → handle, so a retransmitted SYN doesn't open a dup.
    let mut by_tuple: HashMap<(SocketAddr, SocketAddr), SocketHandle> = HashMap::new();
    // UDP is connectionless: a NAT table keyed by (client, dst) instead of sockets.
    let mut udp_nat: HashMap<(SocketAddr, SocketAddr), UdpNat> = HashMap::new();

    let mut udp = UdpCtx {
        nat: &mut udp_nat,
        conn_tx: &udp_conn_tx,
        cmd_tx: &conn_cmd_tx,
    };

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        // Wait for a command or until smoltcp's next timer fires.
        let wait = poll_delay(&mut iface, &mut sockets);
        match cmd_rx.recv_timeout(wait) {
            Ok(cmd) => apply_cmd(
                cmd,
                &mut sockets,
                &mut flows,
                &mut by_tuple,
                &mut device,
                &mut udp,
            ),
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
        while let Ok(cmd) = cmd_rx.try_recv() {
            apply_cmd(
                cmd,
                &mut sockets,
                &mut flows,
                &mut by_tuple,
                &mut device,
                &mut udp,
            );
        }

        // Push buffered circuit→client bytes into socket send buffers.
        ferry_out(&mut sockets, &mut flows);
        iface.poll(now(), &mut device, &mut sockets);
        // Announce new flows, drain client→circuit bytes, honour closes.
        ferry_in(&mut sockets, &mut flows, &conn_tx, &conn_cmd_tx);
        // Flush any FINs / freshly-sent data produced by the ferry.
        iface.poll(now(), &mut device, &mut sockets);

        while let Some(packet) = device.tx.pop_front() {
            if outbound_tx.send(packet).is_err() {
                return; // caller gone
            }
        }

        reap(&mut sockets, &mut flows, &mut by_tuple);
        // Drop idle UDP flows (connectionless — there's no FIN to reap on).
        // Dropping the entry closes its incoming_tx, which ends the flow's
        // circuit handler in run_tunnel_stack.
        let cutoff = now();
        udp.nat
            .retain(|_, nat| (cutoff - nat.last_seen).total_millis() < UDP_IDLE.as_millis() as u64);
    }
}

/// The next wait bound: min of smoltcp's timer and a 1s heartbeat.
fn poll_delay(iface: &mut Interface, sockets: &mut SocketSet) -> Duration {
    match iface.poll_at(now(), sockets) {
        Some(at) => {
            let n = now();
            if at > n {
                Duration::from(at - n).min(Duration::from_secs(1))
            } else {
                Duration::from_millis(1)
            }
        }
        None => Duration::from_secs(1),
    }
}

fn apply_cmd(
    cmd: Cmd,
    sockets: &mut SocketSet,
    flows: &mut HashMap<SocketHandle, Flow>,
    by_tuple: &mut HashMap<(SocketAddr, SocketAddr), SocketHandle>,
    device: &mut ChannelDevice,
    udp: &mut UdpCtx,
) {
    match cmd {
        Cmd::Inbound(packet) => {
            // UDP is handled out of band — smoltcp here carries only TCP.
            if let Some((src, dst, payload)) = parse_udp(&packet) {
                udp.inbound(src, dst, payload);
                return;
            }
            if let Some((src, dst, syn)) = parse_tcp(&packet) {
                // A new flow's opening SYN: pre-create a listener bound to the
                // destination so smoltcp answers it (any_ip lets it accept any dst).
                if syn && !by_tuple.contains_key(&(src, dst)) {
                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
                        tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
                    );
                    let endpoint = smoltcp::wire::IpListenEndpoint {
                        addr: Some(IpAddress::from(dst.ip())),
                        port: dst.port(),
                    };
                    if socket.listen(endpoint).is_ok() {
                        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
                        let handle = sockets.add(socket);
                        by_tuple.insert((src, dst), handle);
                        flows.insert(
                            handle,
                            Flow {
                                dst,
                                incoming_tx,
                                to_announce: Some(incoming_rx),
                                announced: false,
                                pending_write: Vec::new(),
                                closing: false,
                            },
                        );
                    }
                }
            }
            device.rx.push_back(packet);
        }
        Cmd::Write(handle, data) => {
            if let Some(flow) = flows.get_mut(&handle) {
                flow.pending_write.extend_from_slice(&data);
            }
        }
        Cmd::Close(handle) => {
            if let Some(flow) = flows.get_mut(&handle) {
                flow.closing = true;
            }
        }
        Cmd::SendRaw(packet) => {
            // A UDP reply we built; queue it for the TUN (drained after the poll).
            device.tx.push_back(packet);
        }
    }
}

fn ferry_out(sockets: &mut SocketSet, flows: &mut HashMap<SocketHandle, Flow>) {
    for (handle, flow) in flows.iter_mut() {
        if flow.pending_write.is_empty() {
            continue;
        }
        let socket = sockets.get_mut::<tcp::Socket>(*handle);
        while !flow.pending_write.is_empty() && socket.can_send() {
            match socket.send_slice(&flow.pending_write) {
                Ok(0) => break,
                Ok(n) => {
                    flow.pending_write.drain(..n);
                }
                Err(_) => break,
            }
        }
    }
}

fn ferry_in(
    sockets: &mut SocketSet,
    flows: &mut HashMap<SocketHandle, Flow>,
    conn_tx: &mpsc::UnboundedSender<Connection>,
    conn_cmd_tx: &std_mpsc::Sender<Cmd>,
) {
    for (handle, flow) in flows.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(*handle);

        // Announce once the handshake completes and the socket is usable.
        if !flow.announced && socket.may_send() {
            flow.announced = true;
            if let Some(incoming) = flow.to_announce.take() {
                let conn = Connection {
                    dst: flow.dst,
                    incoming,
                    writer: ConnWriter {
                        cmd: conn_cmd_tx.clone(),
                        handle: *handle,
                    },
                };
                let _ = conn_tx.send(conn);
            }
        }

        // client → circuit: drain everything the socket has received.
        while socket.can_recv() {
            let mut chunk = Vec::new();
            let r = socket.recv(|buf| {
                chunk.extend_from_slice(buf);
                (buf.len(), ())
            });
            if r.is_err() || chunk.is_empty() {
                break;
            }
            if flow.incoming_tx.send(chunk).is_err() {
                // Caller dropped the Connection: tear the flow down.
                flow.closing = true;
                break;
            }
        }

        // Half-close once all buffered writes have been handed to smoltcp.
        if flow.closing && flow.pending_write.is_empty() && socket.may_send() {
            socket.close();
        }
    }
}

/// Remove flows whose sockets have fully closed, freeing their handles.
fn reap(
    sockets: &mut SocketSet,
    flows: &mut HashMap<SocketHandle, Flow>,
    by_tuple: &mut HashMap<(SocketAddr, SocketAddr), SocketHandle>,
) {
    let mut dead = Vec::new();
    for (handle, _flow) in flows.iter() {
        let socket = sockets.get::<tcp::Socket>(*handle);
        if socket.state() == tcp::State::Closed {
            dead.push(*handle);
        }
    }
    for handle in dead {
        if let Some(flow) = flows.remove(&handle) {
            drop(flow); // closes incoming_tx → the bridge's read() ends
        }
        sockets.remove(handle);
        by_tuple.retain(|_, h| *h != handle);
    }
}

/// Parse an IPv4/IPv6 TCP packet's `(client, dst, is_syn)`; `None` if not TCP.
fn parse_tcp(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, bool)> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src = SocketAddr::new(IpAddr::V4(ip.src_addr()), tcp.src_port());
            let dst = SocketAddr::new(IpAddr::V4(ip.dst_addr()), tcp.dst_port());
            Some((src, dst, tcp.syn() && !tcp.ack()))
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src = SocketAddr::new(IpAddr::V6(ip.src_addr()), tcp.src_port());
            let dst = SocketAddr::new(IpAddr::V6(ip.dst_addr()), tcp.dst_port());
            Some((src, dst, tcp.syn() && !tcp.ack()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::ChannelDevice;
    use std::time::Duration;

    /// A minimal smoltcp *client* used to drive the gateway in tests: it dials an
    /// arbitrary destination the way the OS would through a TUN.
    struct Client {
        iface: Interface,
        device: ChannelDevice,
        sockets: SocketSet<'static>,
        handle: SocketHandle,
    }

    impl Client {
        fn dial(dst: SocketAddr) -> Client {
            let mut device = ChannelDevice::new(MTU);
            let mut config = Config::new(HardwareAddress::Ip);
            config.random_seed = 0x1234_5678;
            let mut iface = Interface::new(config, &mut device, now());
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push(IpCidr::new(IpAddress::from(Ipv4Addr::new(10, 9, 0, 2)), 24));
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(GATEWAY_IP)
                .unwrap();

            let mut sockets = SocketSet::new(Vec::new());
            let socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
            );
            let handle = sockets.add(socket);
            sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(iface.context(), dst, (Ipv4Addr::new(10, 9, 0, 2), 49_000))
                .unwrap();

            Client {
                iface,
                device,
                sockets,
                handle,
            }
        }

        fn poll(&mut self) {
            self.iface.poll(now(), &mut self.device, &mut self.sockets);
        }

        fn socket(&mut self) -> &mut tcp::Socket<'static> {
            self.sockets.get_mut::<tcp::Socket>(self.handle)
        }
    }

    /// A real smoltcp client dials an arbitrary public address; assert the gateway
    /// intercepts the flow and streams bytes in both directions.
    #[tokio::test]
    async fn intercepts_a_tcp_flow_and_streams_both_ways() {
        let dst: SocketAddr = (Ipv4Addr::new(93, 184, 216, 34), 80).into();
        let (net, mut outbound, mut conns, _udp) = NetStack::new();
        let mut client = Client::dial(dst);

        // Pump packets between the two stacks until the gateway announces the flow.
        let conn = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                client.poll();
                while let Some(pkt) = client.device.tx.pop_front() {
                    net.inject(pkt);
                }
                tokio::select! {
                    out = outbound.recv() => {
                        if let Some(pkt) = out { client.device.rx.push_back(pkt); }
                    }
                    conn = conns.recv() => { if let Some(c) = conn { break c; } }
                    _ = tokio::time::sleep(Duration::from_millis(2)) => {}
                }
            }
        })
        .await
        .expect("gateway announced the flow");

        assert_eq!(conn.dst, dst, "the intercepted destination is preserved");
        let mut conn = conn;

        // client → circuit: the client sends bytes; they surface on conn.read().
        client
            .socket()
            .send_slice(b"hello from the client")
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                client.poll();
                while let Some(pkt) = client.device.tx.pop_front() {
                    net.inject(pkt);
                }
                tokio::select! {
                    out = outbound.recv() => {
                        if let Some(pkt) = out { client.device.rx.push_back(pkt); }
                    }
                    data = conn.read() => { if let Some(d) = data { break d; } }
                    _ = tokio::time::sleep(Duration::from_millis(2)) => {}
                }
            }
        })
        .await
        .expect("client bytes reached the gateway");
        assert_eq!(got, b"hello from the client");

        // circuit → client: bytes written to the flow arrive at the client socket.
        conn.write(b"hello from the exit".to_vec());
        let echoed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                client.poll();
                while let Some(pkt) = client.device.tx.pop_front() {
                    net.inject(pkt);
                }
                if client.socket().can_recv() {
                    let mut out = Vec::new();
                    let _ = client.socket().recv(|buf| {
                        out.extend_from_slice(buf);
                        (buf.len(), ())
                    });
                    if !out.is_empty() {
                        break out;
                    }
                }
                tokio::select! {
                    out = outbound.recv() => {
                        if let Some(pkt) = out { client.device.rx.push_back(pkt); }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(2)) => {}
                }
            }
        })
        .await
        .expect("gateway bytes reached the client");
        assert_eq!(echoed, b"hello from the exit");
    }

    /// A UDP datagram is intercepted as a flow, delivered whole, and a reply
    /// datagram comes back out as a correctly-addressed UDP/IP packet. Also
    /// exercises build_udp_v4 ↔ parse_udp round-tripping.
    #[tokio::test]
    async fn intercepts_a_udp_flow_and_replies() {
        let client: SocketAddrV4 = "10.9.0.2:5300".parse().unwrap();
        let target: SocketAddrV4 = "93.184.216.34:53".parse().unwrap();
        let (net, mut outbound, _conns, mut udp_conns) = NetStack::new();

        net.inject(build_udp_v4(client, target, b"dns-query"));

        let mut flow = tokio::time::timeout(Duration::from_secs(5), udp_conns.recv())
            .await
            .expect("flow announced in time")
            .expect("a udp flow arrived");
        assert_eq!(flow.dst, SocketAddr::V4(target), "destination preserved");

        let got = tokio::time::timeout(Duration::from_secs(5), flow.recv())
            .await
            .expect("datagram in time")
            .expect("a datagram arrived");
        assert_eq!(got, b"dns-query", "the client datagram is delivered whole");

        // A reply comes back out as a UDP/IP packet from target → client.
        flow.reply(b"dns-answer");
        let pkt = tokio::time::timeout(Duration::from_secs(5), outbound.recv())
            .await
            .expect("reply packet in time")
            .expect("a packet was emitted");
        let (psrc, pdst, payload) = parse_udp(&pkt).expect("emitted packet parses as UDP");
        assert_eq!(psrc, SocketAddr::V4(target), "reply source is the target");
        assert_eq!(
            pdst,
            SocketAddr::V4(client),
            "reply destination is the client"
        );
        assert_eq!(payload, b"dns-answer", "the reply datagram round-trips");
    }
}
