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
use neo_netstack::{ConnReader, ConnWriter, Connection, Connections, NetStack, Outbound};
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
pub async fn run_tunnel_stack(
    identity: Arc<NodeIdentity>,
    net: NetStack,
    mut outbound: Outbound,
    mut conns: Connections,
    mut from_tun: mpsc::Receiver<Vec<u8>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    picker: Arc<dyn CircuitPicker>,
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
                        handle_flow(identity, conn, circuit).await;
                    });
                }
                None => break,
            },
        }
    }
}

/// Open a circuit to one flow's destination and splice bytes both ways.
async fn handle_flow(identity: Arc<NodeIdentity>, conn: Connection, circuit: Vec<Hop>) {
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
    splice(reader, writer, sink, stream).await;
}

/// Pump a flow's bytes to/from its circuit until either side ends.
async fn splice(
    mut reader: ConnReader,
    writer: ConnWriter,
    mut sink: CircuitSink,
    mut stream: CircuitStream,
) {
    // client → exit
    let to_exit = async move {
        while let Some(bytes) = reader.read().await {
            if sink.send(&bytes).await.is_err() {
                break;
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

    async fn spawn_serve(id_bytes: Vec<u8>, resolver: HashMap<NodeId, String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&id_bytes).unwrap();
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
        let (net, outbound, conns) = NetStack::new();
        let (from_tun_tx, from_tun_rx) = mpsc::channel::<Vec<u8>>(256);
        let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Vec<u8>>(256);
        let picker: Arc<dyn CircuitPicker> = Arc::new(move || circuit.clone());
        tokio::spawn(run_tunnel_stack(
            client_id.clone(),
            net,
            outbound,
            conns,
            from_tun_rx,
            to_tun_tx,
            picker,
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
