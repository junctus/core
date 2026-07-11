//! `NeoTunnelStackSession` — the **multi-hop** packet tunnel.
//!
//! Where [`crate::tunnel::NeoTunnelSession`] carries the device's packets to a
//! single peer, this session runs the full userspace stack: it discovers relays
//! (a witness-verified snapshot from the mirrors), and for **each** intercepted
//! TCP flow opens a fresh onion circuit — through `hops` relays picked at random
//! — to that flow's own destination, where the exit splices the real connection.
//!
//! The device-facing API is identical to the single-peer session
//! (`submit_outbound` / `drain_inbound`), so the platform packet-tunnel provider
//! drives it the same way; only `connect` differs (mirrors + witnesses instead
//! of a peer address).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use neo_core::NodeIdentity;
use neo_discovery::snapshot::SignedSnapshot;
use neo_discovery::{now_unix, PeerRecord};
use neo_netstack::NetStack;
use neo_node::forward::Hop;
use neo_node::tunnel_stack::{run_tunnel_stack, CircuitPicker};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::tunnel::{runtime, NeoTunnelError};

/// Bounded queue depth between the OS packet loop and the stack, matching the
/// single-peer session: a full queue drops rather than stalls the packet loop.
const QUEUE_DEPTH: usize = 512;
/// Snapshot fetch timeout per mirror.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Picks a fresh circuit of `hops` relays for each flow from a verified snapshot.
struct SnapshotPicker {
    relays: Vec<PeerRecord>,
    hops: usize,
}

impl CircuitPicker for SnapshotPicker {
    fn pick(&self) -> Vec<Hop> {
        pick_circuit(&self.relays, self.hops)
    }
}

/// Pick a fresh circuit whose **terminal hop is an exit** — the last hop splices
/// the real TCP connection, so it must be an exit-capable relay, and a non-exit
/// relay now refuses that role (`ExitPolicy::offer_exit`). The exit is chosen
/// uniformly among exit relays; the earlier hops are a random sample of the rest
/// (an exit may also serve as a middle hop), so path diversity grows with the
/// relay set rather than pinning to fixed nodes.
///
/// Returns empty (→ the flow is dropped) if there are too few relays, **no exit
/// relay**, the RNG fails, or a chosen relay lacks a dialable address.
fn pick_circuit(relays: &[PeerRecord], hops: usize) -> Vec<Hop> {
    pick_circuit_inner(relays, hops).unwrap_or_default()
}

fn pick_circuit_inner(relays: &[PeerRecord], hops: usize) -> Option<Vec<Hop>> {
    if hops == 0 || relays.len() < hops {
        return None;
    }
    // The terminal hop egresses to the clearnet, so it must be an exit.
    let exit_indices: Vec<usize> = (0..relays.len()).filter(|&i| relays[i].exit).collect();
    if exit_indices.is_empty() {
        return None;
    }
    let exit_idx = exit_indices[rand_index(exit_indices.len())?];

    // The earlier hops are any *other* relays, shuffled for diversity (an exit
    // relay is eligible as a middle hop — only the chosen exit is excluded).
    let mut rest: Vec<usize> = (0..relays.len()).filter(|&i| i != exit_idx).collect();
    for i in (1..rest.len()).rev() {
        let j = rand_index(i + 1)?;
        rest.swap(i, j);
    }
    // Prefer middle hops in subnets distinct from each other AND from the exit
    // (M36): put the exit first so its /24 is already "used", reorder to front-load
    // distinct subnets, then peel the exit back to the tail. Best-effort — a small
    // relay set still yields a full circuit.
    let subnet_of = |&i: &usize| -> Vec<neo_core::net::SubnetKey> {
        relays[i]
            .addrs
            .first()
            .and_then(|a| neo_core::net::SubnetKey::from_addr(a))
            .into_iter()
            .collect()
    };
    let mut with_exit = Vec::with_capacity(rest.len() + 1);
    with_exit.push(exit_idx);
    with_exit.extend(rest);
    let diverse = neo_core::net::prioritize_distinct_subnets(with_exit, subnet_of);
    // `diverse[0]` is the exit (it led the input and is always kept in front).
    let order = diverse
        .into_iter()
        .skip(1)
        .take(hops - 1)
        .chain(std::iter::once(exit_idx)); // exit last

    let circuit: Vec<Hop> = order
        .filter_map(|i| {
            relays[i].addrs.first().map(|addr| Hop {
                id: relays[i].id,
                sphinx: relays[i].sphinx,
                addr: addr.clone(),
            })
        })
        .collect();
    // A relay missing an address would shorten the circuit — drop the flow then.
    (circuit.len() == hops).then_some(circuit)
}

/// A uniform random index in `0..n` (requires `n > 0`), or `None` if the system
/// RNG fails. Modulo bias is negligible at relay-set sizes, matching the
/// long-standing Fisher–Yates shuffle this replaces.
fn rand_index(n: usize) -> Option<usize> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).ok()?;
    Some((u64::from_le_bytes(bytes) % n as u64) as usize)
}

/// Fetch `/snapshot` from each mirror in turn; return the relays from the first
/// snapshot that verifies against the trusted witnesses at the given threshold.
async fn fetch_relays(
    mirrors: &[String],
    witnesses: &[[u8; 32]],
    threshold: usize,
) -> Result<Vec<PeerRecord>, NeoTunnelError> {
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| NeoTunnelError::Discovery {
            message: e.to_string(),
        })?;
    let now = now_unix();
    let mut last = "no mirrors configured".to_string();

    for mirror in mirrors {
        let url = format!("{}/snapshot", mirror.trim_end_matches('/'));
        match client.get(&url).send().await {
            Ok(resp) => match resp.bytes().await {
                Ok(bytes) => match SignedSnapshot::from_bytes(&bytes) {
                    Ok(snapshot) => match snapshot.verify(witnesses, threshold, now) {
                        Ok(()) => {
                            let relays: Vec<PeerRecord> =
                                snapshot.relays(now).into_iter().cloned().collect();
                            if relays.is_empty() {
                                last = format!("{mirror}: snapshot has no usable relays");
                            } else {
                                return Ok(relays);
                            }
                        }
                        Err(e) => last = format!("{mirror}: snapshot failed verification: {e}"),
                    },
                    Err(e) => last = format!("{mirror}: malformed snapshot: {e}"),
                },
                Err(e) => last = format!("{mirror}: reading body: {e}"),
            },
            Err(e) => last = format!("{mirror}: {e}"),
        }
    }
    Err(NeoTunnelError::Discovery { message: last })
}

/// A live multi-hop tunnel. Drive it from the OS packet loop exactly like
/// [`crate::tunnel::NeoTunnelSession`].
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct NeoTunnelStackSession {
    to_stack: mpsc::Sender<Vec<u8>>,
    from_stack: Mutex<mpsc::Receiver<Vec<u8>>>,
    task: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
    relay_count: u32,
}

impl NeoTunnelStackSession {
    fn connect_inner(
        secret: Vec<u8>,
        mirrors: Vec<String>,
        witnesses_hex: Vec<String>,
        threshold: u32,
        hops: u32,
        net_interface_index: u32,
    ) -> Result<NeoTunnelStackSession, NeoTunnelError> {
        // Pin every circuit socket this stack opens to the physical interface, so
        // per-flow relay connections made *after* the OS points the default route
        // at our TUN bypass it instead of looping back in (which is why browsing
        // failed once the tunnel was up). Process-wide, exactly like the relay's
        // `--net-interface`. The one-time mirror fetch below runs before the TUN
        // is the default route, so it doesn't need this. Index 0 = unscoped.
        if net_interface_index != 0 {
            neo_node::netif::set_bound_interface(net_interface_index);
        }
        let identity = NodeIdentity::from_bytes(&secret).map_err(|_| NeoTunnelError::Identity)?;

        let mut witnesses = Vec::with_capacity(witnesses_hex.len());
        for hex_key in &witnesses_hex {
            let raw = hex::decode(hex_key.trim()).map_err(|_| NeoTunnelError::Discovery {
                message: format!("witness key is not valid hex: {hex_key}"),
            })?;
            let key: [u8; 32] = raw.try_into().map_err(|_| NeoTunnelError::Discovery {
                message: "witness key must be 32 bytes".to_string(),
            })?;
            witnesses.push(key);
        }

        let hops = hops.max(1) as usize;
        let rt = runtime();
        let relays = rt.block_on(fetch_relays(&mirrors, &witnesses, threshold as usize))?;
        let relay_count = relays.len() as u32;
        if relays.len() < hops {
            return Err(NeoTunnelError::Discovery {
                message: format!(
                    "need {hops} relays for a circuit, the snapshot has {relay_count}"
                ),
            });
        }

        let picker: Arc<dyn CircuitPicker> = Arc::new(SnapshotPicker { relays, hops });
        let (net, outbound, conns, udp_conns) = NetStack::new();
        let (to_stack_tx, to_stack_rx) = mpsc::channel(QUEUE_DEPTH);
        let (from_stack_tx, from_stack_rx) = mpsc::channel(QUEUE_DEPTH);
        let identity = Arc::new(identity);

        let task = rt.spawn(run_tunnel_stack(
            identity,
            net,
            outbound,
            conns,
            udp_conns,
            to_stack_rx,
            from_stack_tx,
            picker,
        ));

        Ok(NeoTunnelStackSession {
            to_stack: to_stack_tx,
            from_stack: Mutex::new(from_stack_rx),
            task: Mutex::new(Some(task)),
            closed: AtomicBool::new(false),
            relay_count,
        })
    }

    fn submit_inner(&self, packets: Vec<Vec<u8>>) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        for packet in packets {
            if self.to_stack.try_send(packet).is_err() {
                break; // saturated or gone: drop, like IP
            }
        }
    }

    fn drain_inner(&self, max_packets: u32, timeout_ms: u32) -> Vec<Vec<u8>> {
        if self.closed.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let max = max_packets.max(1) as usize;
        let mut out = Vec::new();
        let mut rx = self.from_stack.lock().expect("from_stack lock poisoned");
        runtime().block_on(async {
            let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
            if let Ok(Some(first)) = tokio::time::timeout_at(deadline.into(), rx.recv()).await {
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
        if let Some(task) = self.task.lock().expect("task lock poisoned").take() {
            task.abort();
        }
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl NeoTunnelStackSession {
    /// Submit a batch of outbound IP packets (from the OS TUN).
    pub fn submit_outbound(&self, packets: Vec<Vec<u8>>) {
        self.submit_inner(packets)
    }

    /// Wait up to `timeout_ms` for up to `max_packets` inbound packets.
    pub fn drain_inbound(&self, max_packets: u32, timeout_ms: u32) -> Vec<Vec<u8>> {
        self.drain_inner(max_packets, timeout_ms)
    }

    /// How many relays the verified snapshot offered (diagnostics).
    pub fn relay_count(&self) -> u32 {
        self.relay_count
    }

    /// Tear down the tunnel and its stack. Idempotent.
    pub fn close(&self) {
        self.close_inner()
    }
}

/// Discover relays and start a multi-hop tunnel. `witnesses` are hex-encoded
/// trusted witness keys; `threshold` is how many must sign the snapshot; `hops`
/// is the relays per circuit (last is the exit).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn tunnel_stack_connect(
    secret: Vec<u8>,
    mirrors: Vec<String>,
    witnesses: Vec<String>,
    threshold: u32,
    hops: u32,
    net_interface_index: u32,
) -> Result<std::sync::Arc<NeoTunnelStackSession>, NeoTunnelError> {
    NeoTunnelStackSession::connect_inner(
        secret,
        mirrors,
        witnesses,
        threshold,
        hops,
        net_interface_index,
    )
    .map(std::sync::Arc::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_relay_flagged(port: u16, exit: bool) -> PeerRecord {
        let id = NodeIdentity::generate().unwrap();
        PeerRecord::build_signed(
            &id,
            vec![format!("127.0.0.1:{port}")],
            true,
            exit,
            now_unix() + 3600,
            1,
        )
        .unwrap()
    }

    fn make_relay(port: u16) -> PeerRecord {
        make_relay_flagged(port, false)
    }

    fn make_relay_at(addr: &str, exit: bool) -> PeerRecord {
        let id = NodeIdentity::generate().unwrap();
        PeerRecord::build_signed(&id, vec![addr.into()], true, exit, now_unix() + 3600, 1).unwrap()
    }

    #[test]
    fn pick_circuit_prefers_distinct_subnets() {
        // Three relays in distinct /24s plus an exit in its own /24. Every 3-hop
        // pick should span three distinct subnets (M36), exit still last.
        let relays = vec![
            make_relay_at("1.1.1.1:9000", false),
            make_relay_at("2.2.2.1:9000", false),
            make_relay_at("3.3.3.1:9000", false),
            make_relay_at("4.4.4.1:9000", true),
        ];
        for _ in 0..40 {
            let circuit = pick_circuit(&relays, 3);
            assert_eq!(circuit.len(), 3);
            assert!(
                circuit.last().unwrap().addr.starts_with("4.4.4."),
                "exit last"
            );
            let subs: std::collections::HashSet<_> = circuit
                .iter()
                .filter_map(|h| neo_core::net::SubnetKey::from_addr(&h.addr))
                .collect();
            assert_eq!(subs.len(), 3, "hops span three distinct subnets");
        }
    }

    #[test]
    fn pick_circuit_puts_an_exit_last_and_keeps_hops_distinct() {
        // Plain relays plus two exits.
        let mut relays: Vec<PeerRecord> = (0..3).map(|i| make_relay(9000 + i)).collect();
        let exit_a = make_relay_flagged(9100, true);
        let exit_b = make_relay_flagged(9101, true);
        let exit_ids = [exit_a.id, exit_b.id];
        relays.push(exit_a);
        relays.push(exit_b);

        // Over many picks: the terminal hop is always an exit, hops are distinct.
        for _ in 0..40 {
            let circuit = pick_circuit(&relays, 3);
            assert_eq!(circuit.len(), 3, "a 3-hop pick yields three hops");
            assert!(
                exit_ids.contains(&circuit.last().unwrap().id),
                "the terminal hop must be an exit"
            );
            for a in 0..circuit.len() {
                for b in a + 1..circuit.len() {
                    assert_ne!(circuit[a].id, circuit[b].id, "hops must be distinct");
                }
            }
        }

        // The single-exit, two-relay case the app hits: exit is deterministically last.
        let two = vec![make_relay(9200), make_relay_flagged(9201, true)];
        let c = pick_circuit(&two, 2);
        assert_eq!(c.len(), 2);
        assert_eq!(c[1].id, two[1].id, "with one exit, it is the terminal hop");

        // No exit-capable relay → no flow can egress → dropped.
        let no_exit: Vec<PeerRecord> = (0..3).map(|i| make_relay(9300 + i)).collect();
        assert!(
            pick_circuit(&no_exit, 2).is_empty(),
            "no exit → flow dropped"
        );

        // Too many hops or zero → dropped.
        assert!(pick_circuit(&relays, 9).is_empty());
        assert!(pick_circuit(&relays, 0).is_empty());
    }

    /// Serve a witness-signed snapshot over HTTP and confirm `fetch_relays`
    /// fetches and verifies it — and rejects a snapshot signed by an untrusted
    /// witness. Exercises the security-critical discovery glue in the FFI.
    #[tokio::test]
    async fn fetch_relays_verifies_the_snapshot_and_rejects_untrusted_witnesses() {
        use neo_discovery::snapshot::{SignedSnapshot, Snapshot};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let witness = NodeIdentity::generate().unwrap();
        let now = now_unix();
        let snapshot = Snapshot {
            created_at: now,
            expires_at: now + 3600,
            relays: vec![make_relay(9101), make_relay(9102)],
        };
        let signed = SignedSnapshot {
            signatures: vec![snapshot.sign(&witness)],
            snapshot,
        };
        let body = signed.to_bytes();

        // A tiny HTTP/1.1 responder that returns the snapshot bytes at /snapshot.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = sock.read(&mut scratch).await; // consume the request line
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(header.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let mirror = format!("http://{addr}");
        let trusted = witness.public().signing.to_bytes();

        // Trusted witness at threshold 1 → the two relays come back.
        let relays = fetch_relays(std::slice::from_ref(&mirror), &[trusted], 1)
            .await
            .expect("verified snapshot yields relays");
        assert_eq!(relays.len(), 2);

        // A snapshot signed by an untrusted witness is rejected.
        let stranger = NodeIdentity::generate()
            .unwrap()
            .public()
            .signing
            .to_bytes();
        assert!(
            fetch_relays(&[mirror], &[stranger], 1).await.is_err(),
            "a snapshot with no trusted signature must be rejected"
        );
    }
}
