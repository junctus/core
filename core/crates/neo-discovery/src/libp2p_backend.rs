//! Real `rust-libp2p` backend: a Swarm with the **Kademlia DHT** and
//! **identify** over TCP + Noise + yamux (M4).
//!
//! [`Libp2pNode`] is the concrete decentralized network stack — trackerless peer
//! discovery, DHT put/get, and the connection substrate. It is behind the
//! `libp2p` feature because it pulls a large dependency tree. Wiring it to the
//! crate's [`Discovery`](crate::Discovery) trait (via a background swarm task and
//! a command channel) and adding DCUtR hole-punching + Circuit Relay v2 are the
//! remaining steps; the swarm, Kademlia, and identify here are the foundation and
//! are exercised by a local two-node test.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::futures::StreamExt;
use libp2p::kad::store::{MemoryStore, RecordStore};
use libp2p::kad::{GetRecordOk, InboundRequest, QueryId, QueryResult, Quorum, Record, RecordKey};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    autonat, dcutr, identify, kad, noise, relay, tcp, yamux, Multiaddr, PeerId, StreamProtocol,
    Swarm, SwarmBuilder,
};
use tokio::sync::{mpsc, oneshot};

use crate::{now_unix, Discovery, NodeRole, PeerRecord};
use neo_core::NodeId;
// Note: we deliberately do NOT bring `neo_core::Result` into scope — the
// `#[derive(NetworkBehaviour)]` macro generates code that uses the standard
// two-parameter `Result`, so our alias would shadow it. We qualify our own
// return types as `neo_core::Result` instead.
use neo_core::Error;

/// The neo network behaviour: Kademlia DHT + identify, plus the NAT-traversal
/// stack (M16) — AutoNAT (reachability detection), Circuit Relay v2 client
/// (reach/be-reached via a relay), and DCUtR (direct-connection upgrade /
/// hole-punching).
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    /// Trackerless peer/record discovery.
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Exchanges peer identity and observed addresses (feeds AutoNAT/DCUtR).
    pub identify: identify::Behaviour,
    /// Detects whether this node is publicly reachable or behind NAT.
    pub autonat: autonat::Behaviour,
    /// Circuit Relay v2 client: connect to / be reachable through a relay.
    pub relay_client: relay::client::Behaviour,
    /// Direct-connection upgrade (hole-punching) once a relayed path exists.
    pub dcutr: dcutr::Behaviour,
}

/// A libp2p node running the neo network behaviour.
pub struct Libp2pNode {
    swarm: Swarm<Behaviour>,
}

impl Libp2pNode {
    /// Build a node with a fresh identity over TCP + Noise + yamux.
    ///
    /// [`NodeRole::Client`] forces Kademlia **client mode**: the node issues
    /// queries but never answers or stores them, so it stays out of other
    /// nodes' routing tables — a client's participation is not enumerable via
    /// the DHT. [`NodeRole::Relay`] serves the DHT, with **inbound records
    /// filtered**: every incoming put is parsed and cryptographically verified
    /// before it is stored (see the event loops below).
    pub fn new(role: NodeRole) -> neo_core::Result<Self> {
        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| Error::Config(format!("libp2p tcp transport: {e}")))?
            // Circuit Relay v2 client: upgrades the transport so this node can be
            // reached (and reach others) through a relay when behind NAT.
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| Error::Config(format!("libp2p relay client: {e}")))?
            .with_behaviour(|key, relay_client| {
                let peer_id = key.public().to_peer_id();
                let mut cfg = kad::Config::new(StreamProtocol::new("/neo/kad/1.0.0"));
                // Query over independent paths so one adversarial routing-table
                // neighborhood can't eclipse a lookup (S/Kademlia-style).
                cfg.disjoint_query_paths(true);
                // Never auto-store inbound records: they surface as
                // `InboundRequest::PutRecord` events and are stored only after
                // signature + self-certification checks.
                cfg.set_record_filtering(kad::StoreInserts::FilterBoth);
                Behaviour {
                    kademlia: kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), cfg),
                    identify: identify::Behaviour::new(identify::Config::new(
                        "/neo/id/1.0.0".into(),
                        key.public(),
                    )),
                    autonat: autonat::Behaviour::new(peer_id, autonat::Config::default()),
                    relay_client,
                    dcutr: dcutr::Behaviour::new(peer_id),
                }
            })
            .map_err(|e| Error::Config(format!("libp2p behaviour: {e}")))?
            .with_swarm_config(|cfg| {
                // Keep connections alive between queries; the default closes idle
                // connections almost immediately, which churns the routing table.
                cfg.with_idle_connection_timeout(std::time::Duration::from_secs(60))
            })
            .build();
        let mode = match role {
            NodeRole::Client => kad::Mode::Client,
            NodeRole::Relay => kad::Mode::Server,
        };
        swarm.behaviour_mut().kademlia.set_mode(Some(mode));
        Ok(Self { swarm })
    }

    /// Verify an inbound DHT record and store it if it checks out: it must
    /// parse as a [`PeerRecord`], be stored under exactly its own node id,
    /// pass self-certification + signature + expiry, and not roll back a
    /// newer sequence number already in the store.
    fn store_verified_inbound(&mut self, record: Record) {
        let Ok(peer) = PeerRecord::from_bytes(&record.value) else {
            return;
        };
        if record.key.as_ref() != peer.id.as_bytes() || peer.verify(now_unix()).is_err() {
            return;
        }
        let store = self.swarm.behaviour_mut().kademlia.store_mut();
        if let Some(existing) = store.get(&record.key) {
            if let Ok(existing) = PeerRecord::from_bytes(&existing.value) {
                if existing.seq >= peer.seq {
                    return;
                }
            }
        }
        let _ = store.put(record);
    }

    /// This node's libp2p peer id.
    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// This node's current reachability as determined by AutoNAT (M16). Feeds
    /// [`connection_ladder_for`](crate::connection_ladder_for) so a public node
    /// skips hole-punching a peer it can dial directly.
    pub fn reachability(&self) -> crate::Reachability {
        match self.swarm.behaviour().autonat.nat_status() {
            autonat::NatStatus::Public(_) => crate::Reachability::Public,
            autonat::NatStatus::Private => crate::Reachability::Private,
            autonat::NatStatus::Unknown => crate::Reachability::Unknown,
        }
    }

    /// Start listening on a multiaddr (e.g. `/ip4/127.0.0.1/tcp/0`).
    pub fn listen(&mut self, addr: &str) -> neo_core::Result<()> {
        let addr: Multiaddr = addr
            .parse()
            .map_err(|e| Error::Config(format!("bad multiaddr: {e}")))?;
        self.swarm
            .listen_on(addr)
            .map_err(|e| Error::Config(format!("listen_on: {e}")))?;
        Ok(())
    }

    /// Teach Kademlia about a peer's address (a bootstrap/known relay).
    pub fn add_address(&mut self, peer: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kademlia.add_address(&peer, addr);
    }

    /// Dial a peer by multiaddr.
    pub fn dial(&mut self, addr: Multiaddr) -> neo_core::Result<()> {
        self.swarm
            .dial(addr)
            .map_err(|e| Error::Config(format!("dial: {e}")))?;
        Ok(())
    }

    /// Kick off a Kademlia bootstrap over known peers.
    pub fn bootstrap(&mut self) -> neo_core::Result<()> {
        self.swarm
            .behaviour_mut()
            .kademlia
            .bootstrap()
            .map_err(|e| Error::Config(format!("kad bootstrap: {e}")))?;
        Ok(())
    }

    /// Put a `(key, value)` record into the DHT, expiring at unix-seconds
    /// `expires_at` so the store drops it in step with the record's own expiry.
    pub fn put_record(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
        expires_at: u64,
    ) -> neo_core::Result<QueryId> {
        let ttl = expires_at.saturating_sub(now_unix());
        let record = Record {
            key: RecordKey::new(&key),
            value,
            publisher: None,
            expires: Some(Instant::now() + Duration::from_secs(ttl)),
        };
        self.swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, Quorum::One)
            .map_err(|e| Error::Config(format!("put_record: {e}")))
    }

    /// Start a DHT lookup for a key; the result arrives as a swarm event.
    pub fn get_record(&mut self, key: Vec<u8>) -> QueryId {
        self.swarm
            .behaviour_mut()
            .kademlia
            .get_record(RecordKey::new(&key))
    }

    /// Await the next swarm event (drives the node).
    pub async fn next_event(&mut self) -> SwarmEvent<BehaviourEvent> {
        self.swarm.select_next_some().await
    }
}

/// Commands sent to the background swarm task.
enum Command {
    Announce {
        record: PeerRecord,
        reply: oneshot::Sender<neo_core::Result<()>>,
    },
    Lookup {
        id: NodeId,
        reply: oneshot::Sender<neo_core::Result<Option<PeerRecord>>>,
    },
    SampleRelays {
        n: usize,
        reply: oneshot::Sender<Vec<PeerRecord>>,
    },
    Listen {
        addr: String,
        reply: oneshot::Sender<neo_core::Result<Multiaddr>>,
    },
    AddAndDial {
        peer: PeerId,
        addr: Multiaddr,
        reply: oneshot::Sender<neo_core::Result<()>>,
    },
}

/// A [`Discovery`](crate::Discovery) backend over the real libp2p Kademlia DHT.
///
/// The swarm runs in a background task; each method sends a command and awaits a
/// reply. `announce`/`lookup` map to Kademlia put/get (keyed by node id, valued
/// by a serialized [`PeerRecord`]); `sample_relays` draws from the locally-known
/// records.
pub struct Libp2pDiscovery {
    peer_id: PeerId,
    role: NodeRole,
    commands: mpsc::Sender<Command>,
}

impl Libp2pDiscovery {
    /// Spawn a libp2p node and its background event loop.
    pub fn spawn(role: NodeRole) -> neo_core::Result<Self> {
        let node = Libp2pNode::new(role)?;
        let peer_id = node.peer_id();
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(event_loop(node, rx));
        Ok(Self {
            peer_id,
            role,
            commands: tx,
        })
    }

    /// This node's libp2p peer id.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Listen on a multiaddr and return the bound address.
    pub async fn listen(&self, addr: &str) -> neo_core::Result<Multiaddr> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Listen {
            addr: addr.to_string(),
            reply: tx,
        })
        .await?;
        recv(rx).await?
    }

    /// Add a peer's address to Kademlia and dial it.
    pub async fn add_and_dial(&self, peer: PeerId, addr: Multiaddr) -> neo_core::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::AddAndDial {
            peer,
            addr,
            reply: tx,
        })
        .await?;
        recv(rx).await?
    }

    async fn send(&self, cmd: Command) -> neo_core::Result<()> {
        self.commands
            .send(cmd)
            .await
            .map_err(|_| Error::Config("discovery task stopped".into()))
    }
}

async fn recv<T>(rx: oneshot::Receiver<T>) -> neo_core::Result<T> {
    rx.await
        .map_err(|_| Error::Config("discovery task dropped a reply".into()))
}

impl Discovery for Libp2pDiscovery {
    async fn announce(&self, record: PeerRecord) -> neo_core::Result<()> {
        if self.role == NodeRole::Client {
            return Err(Error::Config(
                "clients never announce — announcing would make this node enumerable".into(),
            ));
        }
        record.verify(now_unix())?;
        let (tx, rx) = oneshot::channel();
        self.send(Command::Announce { record, reply: tx }).await?;
        recv(rx).await?
    }

    async fn lookup(&self, id: &NodeId) -> neo_core::Result<Option<PeerRecord>> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Lookup { id: *id, reply: tx }).await?;
        recv(rx).await?
    }

    async fn sample_relays(&self, n: usize) -> neo_core::Result<Vec<PeerRecord>> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::SampleRelays { n, reply: tx }).await?;
        recv(rx).await
    }

    async fn bootstrap(&self, seeds: &[PeerRecord]) -> neo_core::Result<()> {
        for seed in seeds {
            self.announce(seed.clone()).await?;
        }
        Ok(())
    }
}

/// Insert into the local cache unless a same-or-newer `seq` is already held.
fn cache_newest(cache: &mut HashMap<NodeId, PeerRecord>, record: PeerRecord) {
    match cache.get(&record.id) {
        Some(existing) if existing.seq >= record.seq => {}
        _ => {
            cache.insert(record.id, record);
        }
    }
}

/// The background task: owns the swarm, handles commands and DHT query results.
///
/// Everything that arrives from the network — lookup results and inbound store
/// requests alike — is parsed, checked against the key it claims, and
/// cryptographically verified before it is cached, stored, or handed to a
/// caller. Unverifiable data is dropped as if it never arrived.
async fn event_loop(mut node: Libp2pNode, mut commands: mpsc::Receiver<Command>) {
    let mut cache: HashMap<NodeId, PeerRecord> = HashMap::new();
    let mut pending_get: HashMap<QueryId, oneshot::Sender<neo_core::Result<Option<PeerRecord>>>> =
        HashMap::new();
    let mut pending_listen: Vec<oneshot::Sender<neo_core::Result<Multiaddr>>> = Vec::new();

    loop {
        tokio::select! {
            maybe_cmd = commands.recv() => {
                let Some(cmd) = maybe_cmd else { break };
                match cmd {
                    Command::Announce { record, reply } => {
                        cache_newest(&mut cache, record.clone());
                        let result = node
                            .put_record(
                                record.id.as_bytes().to_vec(),
                                record.to_bytes(),
                                record.expires_at,
                            )
                            .map(|_| ());
                        let _ = reply.send(result);
                    }
                    Command::Lookup { id, reply } => {
                        match cache.get(&id) {
                            Some(record) if !record.is_expired(now_unix()) => {
                                let _ = reply.send(Ok(Some(record.clone())));
                            }
                            _ => {
                                let query = node.get_record(id.as_bytes().to_vec());
                                pending_get.insert(query, reply);
                            }
                        }
                    }
                    Command::SampleRelays { n, reply } => {
                        let now = now_unix();
                        let mut relays: Vec<_> = cache
                            .values()
                            .filter(|r| r.relay && !r.is_expired(now))
                            .cloned()
                            .collect();
                        // Random partial Fisher-Yates so the sample isn't biased by
                        // HashMap iteration order (which a Sybil could exploit to
                        // over-represent its relays). Matches LocalRegistry's shuffle.
                        let take = n.min(relays.len());
                        for i in 0..take {
                            let mut b = [0u8; 8];
                            if getrandom::getrandom(&mut b).is_ok() {
                                let span = relays.len() - i;
                                let j = i + (u64::from_le_bytes(b) as usize) % span;
                                relays.swap(i, j);
                            }
                        }
                        relays.truncate(take);
                        let _ = reply.send(relays);
                    }
                    Command::Listen { addr, reply } => match node.listen(&addr) {
                        Ok(()) => pending_listen.push(reply),
                        Err(e) => {
                            let _ = reply.send(Err(e));
                        }
                    },
                    Command::AddAndDial { peer, addr, reply } => {
                        node.add_address(peer, addr.clone());
                        let _ = reply.send(node.dial(addr));
                    }
                }
            }
            event = node.next_event() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        if let Some(reply) = pending_listen.pop() {
                            let _ = reply.send(Ok(address));
                        }
                    }
                    // A peer asked us to store a record (server mode, with
                    // `StoreInserts::FilterBoth`): verify before storing.
                    SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                        kad::Event::InboundRequest {
                            request: InboundRequest::PutRecord { record: Some(record), .. },
                        },
                    )) => {
                        node.store_verified_inbound(record);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                        kad::Event::OutboundQueryProgressed { id, result, .. },
                    )) => match result {
                        QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(found))) => {
                            let verified = PeerRecord::from_bytes(&found.record.value)
                                .ok()
                                .filter(|r| found.record.key.as_ref() == r.id.as_bytes())
                                .filter(|r| r.verify(now_unix()).is_ok());
                            if let Some(record) = verified {
                                cache_newest(&mut cache, record.clone());
                                if let Some(reply) = pending_get.remove(&id) {
                                    let _ = reply.send(Ok(Some(record)));
                                }
                            }
                            // An unverifiable result is dropped; the query keeps
                            // progressing and ends in `FinishedWithNoAdditionalRecord`
                            // if nothing legitimate turns up.
                        }
                        QueryResult::GetRecord(Ok(
                            GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                        )) => {
                            if let Some(reply) = pending_get.remove(&id) {
                                let _ = reply.send(Ok(None));
                            }
                        }
                        QueryResult::GetRecord(Err(_)) => {
                            if let Some(reply) = pending_get.remove(&id) {
                                let _ = reply.send(Ok(None));
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_core::NodeIdentity;
    use std::time::Duration;

    fn signed_relay_record(identity: &NodeIdentity) -> PeerRecord {
        PeerRecord::build_signed(
            identity,
            vec!["10.0.0.1:9000".into()],
            true,
            false,
            now_unix() + 3600,
            1,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn two_nodes_connect_over_libp2p() {
        let mut a = Libp2pNode::new(NodeRole::Relay).unwrap();
        let a_peer = a.peer_id();
        a.listen("/ip4/127.0.0.1/tcp/0").unwrap();

        // Learn node A's actual listen address.
        let a_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = a.next_event().await {
                break address;
            }
        };

        let mut b = Libp2pNode::new(NodeRole::Relay).unwrap();
        b.add_address(a_peer, a_addr.clone());
        b.dial(a_addr).unwrap();

        // Drive both swarms until B establishes a connection to A.
        let connected = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                tokio::select! {
                    _ = a.next_event() => {}
                    event = b.next_event() => {
                        if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                            if peer_id == a_peer {
                                break true;
                            }
                        }
                    }
                }
            }
        })
        .await;

        assert!(connected.is_ok(), "nodes should connect within the timeout");
    }

    #[tokio::test]
    async fn record_announced_on_one_node_is_found_via_the_dht() {
        let a = Libp2pDiscovery::spawn(NodeRole::Relay).unwrap();
        let a_addr = a.listen("/ip4/127.0.0.1/tcp/0").await.unwrap();
        let b = Libp2pDiscovery::spawn(NodeRole::Relay).unwrap();
        // B dials A only (one direction avoids localhost dial churn).
        b.add_and_dial(a.peer_id(), a_addr).await.unwrap();
        // Let the connection, identify exchange, and routing tables settle.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let identity = NodeIdentity::generate().unwrap();
        let record = signed_relay_record(&identity);
        a.announce(record.clone()).await.unwrap();

        // Same node finds it immediately (from cache).
        assert_eq!(a.lookup(&record.id).await.unwrap(), Some(record.clone()));

        // The other node finds it via the DHT (retry until it propagates).
        let found = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(found) = b.lookup(&record.id).await.unwrap() {
                    return found;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await;
        assert_eq!(found.expect("DHT lookup timed out").id, record.id);
    }

    #[tokio::test]
    async fn clients_stay_dark_and_forged_records_never_land() {
        // A client role refuses to announce at all.
        let client = Libp2pDiscovery::spawn(NodeRole::Client).unwrap();
        let identity = NodeIdentity::generate().unwrap();
        let record = signed_relay_record(&identity);
        assert!(client.announce(record.clone()).await.is_err());

        // A tampered record is rejected by announce-side verification too.
        let server = Libp2pDiscovery::spawn(NodeRole::Relay).unwrap();
        let mut forged = record;
        forged.exit = true;
        assert!(server.announce(forged).await.is_err());
    }

    #[tokio::test]
    async fn unverifiable_dht_records_are_not_returned() {
        // Wire two server nodes together, then have B push a garbage value
        // under a plausible key straight into the DHT layer.
        let mut a = Libp2pNode::new(NodeRole::Relay).unwrap();
        let a_peer = a.peer_id();
        a.listen("/ip4/127.0.0.1/tcp/0").unwrap();
        let a_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = a.next_event().await {
                break address;
            }
        };

        let mut b = Libp2pNode::new(NodeRole::Relay).unwrap();
        b.add_address(a_peer, a_addr.clone());
        b.dial(a_addr).unwrap();

        let victim = NodeIdentity::generate().unwrap();
        let key = victim.id().as_bytes().to_vec();
        let garbage = vec![0u8; 64];

        // Drive both swarms; once connected, push the forged record and keep
        // driving so replication happens; A's inbound filter must drop it.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut pushed = false;
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                _ = a.next_event() => {}
                event = b.next_event() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == a_peer && !pushed {
                            b.put_record(key.clone(), garbage.clone(), now_unix() + 600).unwrap();
                            pushed = true;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
        assert!(pushed, "nodes never connected");

        // A's store must not contain the forged record.
        let stored = a
            .swarm
            .behaviour_mut()
            .kademlia
            .store_mut()
            .get(&RecordKey::new(&key));
        assert!(stored.is_none(), "forged record must not be stored");
    }
}
