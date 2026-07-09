//! `neo-node` — the engine that wires the neo crates together.
//!
//! Owns the node lifecycle and its roles (client, relay, mix, exit, committee
//! member) driven by [`NodeConfig`]. Every platform shell — desktop, iOS,
//! Android — runs a `neo-node` behind a thin adapter.
//!
//! Networking lives in [`run`]. The end-to-end pipeline that ties information
//! slicing (M3), Sphinx onion routing (M2), and the PQ-hybrid session (M1)
//! together is exercised by the integration tests below.

#![forbid(unsafe_code)]

pub mod circuit;
pub mod forward;
pub mod run;
pub mod stream;
pub mod tunnel;

use neo_core::{NodeConfig, NodeId, NodeIdentity};

/// A neo node: an identity plus its configuration.
pub struct Node {
    identity: NodeIdentity,
    config: NodeConfig,
}

impl Node {
    /// Create a node from an identity and configuration.
    pub fn new(identity: NodeIdentity, config: NodeConfig) -> Self {
        Self { identity, config }
    }

    /// The node's configuration.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// The node's stable identifier.
    pub fn id(&self) -> NodeId {
        self.identity.id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_crypto::{
        create_packet, initiator_finish, initiator_message1, process, responder_confirm,
        responder_cookie, responder_process, CookieKey, Processed, ReplayCache, SphinxHop,
    };
    use neo_routing::{Relay, Router};
    use neo_slicing::{encrypt_and_slice, reassemble_and_decrypt, Share};
    use std::collections::HashMap;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn sphinx_hop(identity: &NodeIdentity) -> SphinxHop {
        SphinxHop {
            id: *identity.id().as_bytes(),
            public: identity.sphinx_public(),
        }
    }

    #[test]
    fn node_reports_its_identity() {
        let identity = NodeIdentity::generate().unwrap();
        let expected = identity.id();
        let node = Node::new(identity, NodeConfig::default());
        assert_eq!(node.id(), expected);
    }

    /// The novel core end-to-end, in memory: a message is encrypt-then-sliced
    /// into k-of-n shares (M3), each share is carried in its own Sphinx packet
    /// over a node-disjoint path (M2), every relay peels exactly one layer, and
    /// the destination reassembles and decrypts (M3) — proving no single relay
    /// ever held a complete, readable flow.
    #[test]
    fn sliced_sphinx_pipeline_end_to_end() {
        let dest = NodeIdentity::generate().unwrap();
        let relay_ids: Vec<NodeIdentity> =
            (0..6).map(|_| NodeIdentity::generate().unwrap()).collect();
        let router = Router::new(
            relay_ids
                .iter()
                .map(|id| {
                    let p = id.public();
                    Relay {
                        id: p.id,
                        kex: *p.kex.as_bytes(),
                        sphinx: p.sphinx,
                        addr: String::new(),
                    }
                })
                .collect(),
        );
        let identity_by_id: HashMap<NodeId, &NodeIdentity> =
            relay_ids.iter().map(|id| (id.id(), id)).collect();

        // M3: encrypt then slice into 2-of-3 shares.
        let key = [42u8; 32];
        let message = b"packets no single relay can read or attribute to one user";
        let shares = encrypt_and_slice(&key, message, 2, 1).unwrap();
        assert_eq!(shares.len(), 3);

        // M2: each share travels its own node-disjoint 2-relay Sphinx path to the exit.
        let paths = router.select_disjoint_paths(3, 2).unwrap();
        let mut delivered: Vec<Share> = Vec::new();
        for (share, path) in shares.iter().zip(paths.iter()) {
            let mut hops: Vec<SphinxHop> = path
                .iter()
                .map(|r| SphinxHop {
                    id: *r.id.as_bytes(),
                    public: r.sphinx,
                })
                .collect();
            hops.push(sphinx_hop(&dest));

            let mut packet = create_packet(&hops, &share.to_bytes()).unwrap();
            for (j, relay) in path.iter().enumerate() {
                let node = identity_by_id[&relay.id];
                let mut cache = ReplayCache::new();
                packet = match process(node, &mut cache, &packet).unwrap() {
                    Processed::Forward { next, packet } => {
                        let expected = if j + 1 < path.len() {
                            *path[j + 1].id.as_bytes()
                        } else {
                            *dest.id().as_bytes()
                        };
                        assert_eq!(next, expected, "each hop learns the correct next hop");
                        *packet
                    }
                    Processed::Deliver { .. } => panic!("a relay should forward, not exit"),
                };
            }
            let mut cache = ReplayCache::new();
            match process(&dest, &mut cache, &packet).unwrap() {
                Processed::Deliver { payload } => {
                    delivered.push(Share::from_bytes(&payload).unwrap())
                }
                Processed::Forward { .. } => panic!("the destination should be the exit"),
            }
        }

        // M3: reassemble at the exit from any k = 2 of the 3 delivered shares.
        assert_eq!(
            reassemble_and_decrypt(&key, &delivered[..2]).unwrap(),
            message
        );
        assert_eq!(reassemble_and_decrypt(&key, &delivered).unwrap(), message);
    }

    // ---- M9: adversary simulations ----

    /// Colluding relays holding fewer than `k` shares recover nothing.
    #[test]
    fn colluding_relays_below_threshold_learn_nothing() {
        let key = [9u8; 32];
        let secret = b"only k cooperating relays should ever recover this";
        let shares = encrypt_and_slice(&key, secret, 3, 2).unwrap(); // k = 3 of 5
        let captured = &shares[..2]; // two colluding relays, one share each
        assert!(reassemble_and_decrypt(&key, captured).is_err());
    }

    /// A relay peels only its own Sphinx layer: it learns the next hop, never the
    /// payload, and cannot process the packet meant for the next hop.
    #[test]
    fn a_relay_learns_only_the_next_hop() {
        let h1 = NodeIdentity::generate().unwrap();
        let h2 = NodeIdentity::generate().unwrap();
        let h3 = NodeIdentity::generate().unwrap();
        let packet = create_packet(
            &[sphinx_hop(&h1), sphinx_hop(&h2), sphinx_hop(&h3)],
            b"PAYLOAD-SECRET",
        )
        .unwrap();

        let mut cache = ReplayCache::new();
        let forwarded = match process(&h1, &mut cache, &packet).unwrap() {
            Processed::Forward { next, packet } => {
                assert_eq!(&next, h2.id().as_bytes()); // only the next hop
                packet
            }
            Processed::Deliver { .. } => panic!("first hop should forward"),
        };
        assert!(
            !contains(&forwarded.to_bytes(), b"PAYLOAD-SECRET"),
            "relay must not see the payload"
        );
        let mut cache2 = ReplayCache::new();
        assert!(
            process(&h1, &mut cache2, &forwarded).is_err(),
            "a relay cannot process the next hop's packet"
        );
    }

    /// An on-path observer captures only ciphertext: the sealed session frame
    /// never contains the plaintext, yet the peer recovers it.
    #[test]
    fn on_path_observer_sees_only_ciphertext() {
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (state, m1) = initiator_message1(&alice).unwrap();
        let cookie_key = CookieKey::generate().unwrap();
        let challenge = responder_cookie(&cookie_key, &m1).unwrap();
        let init2 = state.with_cookie(&challenge);
        let (m2, pending) = responder_process(&bob, &init2, &cookie_key).unwrap();
        let (m3, alice_res) = initiator_finish(state, &m2).unwrap();
        let bob_res = responder_confirm(pending, &m3).unwrap();

        let mut a = alice_res.session;
        let mut b = bob_res.session;
        let frame = a.seal(b"TOP-SECRET-PLAINTEXT").unwrap();
        assert!(
            !contains(&frame, b"TOP-SECRET-PLAINTEXT"),
            "the wire must not leak plaintext"
        );
        assert_eq!(b.open(&frame).unwrap(), b"TOP-SECRET-PLAINTEXT");
    }
}
