//! Bridge the userspace stack ([`neo_netstack`]) to onion circuits.
//!
//! [`neo_netstack::NetStack`] turns the TUN's raw IP packets into intercepted TCP
//! [`Connection`]s. This module drives that stack and, for **each** flow, opens a
//! fresh neo circuit to the flow's own destination (the exit splices a TCP
//! connection there — see [`crate::circuit`]) and pumps bytes both ways. That is
//! the full "route all traffic through the multi-hop network" data path: one
//! sliced, onion-routed circuit per connection, with a fresh route each time.

use std::sync::Arc;

use neo_core::NodeIdentity;
use neo_mix::{sample_exponential, MixParams};
use neo_netstack::{
    ConnReader, ConnWriter, Connection, Connections, NetStack, Outbound, UdpConnections, UdpFlow,
};
use tokio::sync::mpsc;

use crate::circuit::{open_circuit, CircuitSink, CircuitStream};
use crate::forward::Hop;

/// Chooses the relay circuit for a new flow. Called once per intercepted
/// connection so each gets a fresh route (neo's "fresh path per request").
pub trait CircuitPicker: Send + Sync {
    /// The ordered hops (last is the exit) to carry this flow.
    fn pick(&self) -> Vec<Hop>;
}

impl<F: Fn() -> Vec<Hop> + Send + Sync> CircuitPicker for F {
    fn pick(&self) -> Vec<Hop> {
        self()
    }
}

/// Run the full packet-tunnel data path until the TUN side closes.
///
/// - `identity`: this client's identity (each circuit handshakes with it).
/// - `net`/`outbound`/`conns`: the stack from [`NetStack::new`].
/// - `from_tun`: raw IP packets read from the OS TUN.
/// - `to_tun`: raw IP packets to write back to the OS TUN.
/// - `picker`: chooses a fresh circuit per intercepted flow.
/// - `mix`: the privacy dial — per-cell timing delay and cover-traffic interval
///   (`neo_mix::MixParams::for_level`) applied to each flow's outbound stream.
#[allow(clippy::too_many_arguments)] // a data-path entry point; all args are distinct wiring
pub async fn run_tunnel_stack(
    identity: Arc<NodeIdentity>,
    net: NetStack,
    mut outbound: Outbound,
    mut conns: Connections,
    mut udp_conns: UdpConnections,
    mut from_tun: mpsc::Receiver<Vec<u8>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    picker: Arc<dyn CircuitPicker>,
    mix: MixParams,
) {
    loop {
        tokio::select! {
            packet = from_tun.recv() => match packet {
                Some(packet) => net.inject(packet),
                None => break, // TUN closed
            },
            packet = outbound.recv() => match packet {
                Some(packet) => {
                    if to_tun.send(packet).await.is_err() {
                        break; // TUN writer gone
                    }
                }
                None => break,
            },
            conn = conns.recv() => match conn {
                Some(conn) => {
                    let identity = identity.clone();
                    let circuit = picker.pick();
                    tokio::spawn(async move {
                        handle_flow(identity, conn, circuit, mix).await;
                    });
                }
                None => break,
            },
            flow = udp_conns.recv() => match flow {
                Some(flow) => {
                    let identity = identity.clone();
                    let circuit = picker.pick();
                    tokio::spawn(async move {
                        handle_udp_flow(identity, flow, circuit, mix).await;
                    });
                }
                None => break,
            },
        }
    }
}

/// Open a `udp:`-tagged circuit to one UDP flow's destination and shuttle
/// datagrams both ways (one datagram == one circuit cell).
async fn handle_udp_flow(
    identity: Arc<NodeIdentity>,
    flow: UdpFlow,
    circuit: Vec<Hop>,
    mix: MixParams,
) {
    let target = format!("udp:{}", flow.dst);
    let (sink, stream) = match open_circuit(&identity, &circuit, &target).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::debug!(%target, error = %e, "udp circuit open failed; dropping flow");
            return;
        }
    };
    let (mut incoming, reply) = flow.split();
    // client → exit: each datagram becomes one forward cell, timing-mixed + covered.
    let to_exit = async move {
        let mut sink = sink;
        let mut cover = cover_ticker(&mix);
        loop {
            tokio::select! {
                datagram = incoming.recv() => match datagram {
                    Some(datagram) => {
                        delay(&mix).await;
                        if sink.send(&datagram).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = tick(&mut cover) => {
                    if sink.send_cover().await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    // exit → client: each return cell becomes one datagram back to the client.
    let to_client = async move {
        let mut stream = stream;
        while let Ok(datagram) = stream.recv().await {
            reply.send(&datagram);
        }
    };
    tokio::select! {
        _ = to_exit => {}
        _ = to_client => {}
    }
}

/// Open a circuit to one flow's destination and splice bytes both ways.
async fn handle_flow(
    identity: Arc<NodeIdentity>,
    conn: Connection,
    circuit: Vec<Hop>,
    mix: MixParams,
) {
    let target = conn.dst.to_string();
    let (sink, stream) = match open_circuit(&identity, &circuit, &target).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::debug!(%target, error = %e, "circuit open failed; dropping flow");
            conn.close();
            return;
        }
    };
    let (reader, writer) = conn.split();
    splice(reader, writer, sink, stream, mix).await;
}

/// Pump a flow's bytes to/from its circuit until either side ends.
///
/// The client→exit direction is **timing-mixed**: each cell waits an exponential
/// delay (`mix.mean_delay`) before it goes out, and — while the flow is idle —
/// **cover cells** are injected every `mix.cover_interval`, so an observer on the
/// client's link sees a padded, jittered stream rather than the raw send pattern.
/// The stream stays strictly ordered (a single task), since the exit re-emits the
/// bytes to a real TCP connection and must not receive them reordered.
async fn splice(
    mut reader: ConnReader,
    writer: ConnWriter,
    mut sink: CircuitSink,
    mut stream: CircuitStream,
    mix: MixParams,
) {
    // client → exit
    let to_exit = async move {
        let mut cover = cover_ticker(&mix);
        loop {
            tokio::select! {
                bytes = reader.read() => match bytes {
                    Some(bytes) => {
                        delay(&mix).await;
                        if sink.send(&bytes).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = tick(&mut cover) => {
                    if sink.send_cover().await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    // exit → client
    let to_client = async move {
        while let Ok(bytes) = stream.recv().await {
            writer.write(bytes);
        }
        writer.close();
    };

    tokio::select! {
        _ = to_exit => {}
        _ = to_client => {}
    }
}

/// The cover-traffic timer for a flow, or `None` when the level disables cover.
fn cover_ticker(mix: &MixParams) -> Option<tokio::time::Interval> {
    mix.cover_interval.map(|period| {
        // Start one period out (not immediately), and if the task is busy sending
        // real cells, skip missed cover ticks rather than bursting.
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval
    })
}

/// Await the next cover tick, or never (`pending`) when cover is disabled.
async fn tick(cover: &mut Option<tokio::time::Interval>) {
    match cover {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// Await this flow's per-cell timing delay (a no-op when `mean_delay` is zero).
async fn delay(mix: &MixParams) {
    if !mix.mean_delay.is_zero() {
        tokio::time::sleep(sample_exponential(mix.mean_delay)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::ExitPolicy;
    use crate::run::accept;
    use neo_core::NodeId;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Mutex;
    use std::time::Duration;

    use neo_crypto::ReplayCache;
    use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
    use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
    use smoltcp::socket::tcp;
    use smoltcp::time::Instant;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
    use std::collections::VecDeque;
    use tokio::net::TcpListener;

    // --- a minimal smoltcp client that dials through the netstack ---------------

    struct Dev {
        rx: VecDeque<Vec<u8>>,
        tx: VecDeque<Vec<u8>>,
    }
    struct Rx(Vec<u8>);
    impl RxToken for Rx {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(&self.0)
        }
    }
    struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
    impl TxToken for Tx<'_> {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut buf = vec![0u8; len];
            let r = f(&mut buf);
            self.0.push_back(buf);
            r
        }
    }
    impl Device for Dev {
        type RxToken<'a> = Rx;
        type TxToken<'a> = Tx<'a>;
        fn receive(&mut self, _t: Instant) -> Option<(Rx, Tx<'_>)> {
            self.rx.pop_front().map(|p| (Rx(p), Tx(&mut self.tx)))
        }
        fn transmit(&mut self, _t: Instant) -> Option<Tx<'_>> {
            Some(Tx(&mut self.tx))
        }
        fn capabilities(&self) -> DeviceCapabilities {
            let mut c = DeviceCapabilities::default();
            c.medium = Medium::Ip;
            c.max_transmission_unit = 1500;
            c
        }
    }

    fn instant() -> Instant {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        Instant::from_micros(d.as_micros() as i64)
    }

    struct Client {
        iface: Interface,
        device: Dev,
        sockets: SocketSet<'static>,
        handle: SocketHandle,
    }
    impl Client {
        fn dial(dst: SocketAddr) -> Client {
            let mut device = Dev {
                rx: VecDeque::new(),
                tx: VecDeque::new(),
            };
            let mut config = Config::new(HardwareAddress::Ip);
            config.random_seed = 42;
            let mut iface = Interface::new(config, &mut device, instant());
            iface.update_ip_addrs(|a| {
                let _ = a.push(IpCidr::new(IpAddress::from(Ipv4Addr::new(10, 9, 0, 2)), 24));
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Addr::new(10, 9, 0, 1))
                .unwrap();
            let mut sockets = SocketSet::new(Vec::new());
            let socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
            );
            let handle = sockets.add(socket);
            sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(iface.context(), dst, (Ipv4Addr::new(10, 9, 0, 2), 49_001))
                .unwrap();
            Client {
                iface,
                device,
                sockets,
                handle,
            }
        }
        fn poll(&mut self) {
            self.iface
                .poll(instant(), &mut self.device, &mut self.sockets);
        }
        fn socket(&mut self) -> &mut tcp::Socket<'static> {
            self.sockets.get_mut::<tcp::Socket>(self.handle)
        }
    }

    // --- circuit test scaffold (mirrors circuit.rs's helpers) -------------------

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
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(id_bytes.as_ref()).unwrap();
            let (stream, result) = accept(&listener, &identity).await.unwrap();
            let replay = Mutex::new(ReplayCache::new());
            let _ = crate::serve::serve_connection(
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
            .await;
        });
        addr
    }

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

    /// The whole path: a smoltcp client dials an echo server; its bytes are
    /// intercepted, carried through a real 2-hop onion circuit, spliced to the
    /// echo server at the exit, and the echo returns all the way back.
    #[tokio::test]
    async fn client_traffic_flows_through_a_circuit_to_the_target() {
        let echo = spawn_echo().await;
        let echo_dst: SocketAddr = echo.parse().unwrap();

        // Build a relay + exit and the circuit through them.
        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client_id = Arc::new(NodeIdentity::generate().unwrap());
        let exit_addr = spawn_serve(exit.to_bytes(), HashMap::new()).await;
        let mut resolver = HashMap::new();
        resolver.insert(exit.id(), exit_addr.clone());
        let relay_addr = spawn_serve(relay.to_bytes(), resolver).await;
        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];

        // Stand up the netstack + the tunnel-stack driver.
        let (net, outbound, conns, udp_conns) = NetStack::new();
        let (from_tun_tx, from_tun_rx) = mpsc::channel::<Vec<u8>>(256);
        let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Vec<u8>>(256);
        let picker: Arc<dyn CircuitPicker> = Arc::new(move || circuit.clone());
        tokio::spawn(run_tunnel_stack(
            client_id.clone(),
            net,
            outbound,
            conns,
            udp_conns,
            from_tun_rx,
            to_tun_tx,
            picker,
            // Exercise the mixing path: a small per-cell delay plus frequent cover
            // cells. The echo must still round-trip (cover is dropped at the exit,
            // real bytes stay ordered).
            MixParams {
                mean_delay: Duration::from_millis(5),
                cover_interval: Some(Duration::from_millis(20)),
                hops: 2,
                redundancy: (1, 1),
            },
        ));

        // Drive the smoltcp client dialing the echo server; shuttle its packets
        // to/from the driver and assert the echo comes back through the circuit.
        let mut client = Client::dial(echo_dst);
        let mut sent = false;

        let echoed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                client.poll();
                // Send the request once the handshake (through the circuit) completes.
                if !sent && client.socket().may_send() {
                    client
                        .socket()
                        .send_slice(b"ping through the circuit")
                        .unwrap();
                    sent = true;
                }
                while let Some(pkt) = client.device.tx.pop_front() {
                    let _ = from_tun_tx.send(pkt).await;
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
                    pkt = to_tun_rx.recv() => {
                        if let Some(pkt) = pkt { client.device.rx.push_back(pkt); }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(3)) => {}
                }
            }
        })
        .await
        .expect("echo returned through the circuit");

        assert_eq!(echoed, b"ping through the circuit");
    }
}
