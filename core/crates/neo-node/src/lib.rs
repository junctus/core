//! `neo-node` — the engine that wires the neo crates together.
//!
//! Owns the node lifecycle and its roles (client, relay, mix, exit, committee
//! member) driven by [`NodeConfig`]. Every platform shell — desktop, iOS,
//! Android — runs a `neo-node` behind a thin adapter.
//!
//! Networking lives in [`run`]. The end-to-end pipeline that ties information
//! slicing (M3), onion routing (M2), and the PQ-hybrid session (M1) together is
//! exercised by the integration test below.

#![forbid(unsafe_code)]

pub mod run;

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
    use neo_crypto::{peel, wrap, OnionHop, Peeled};
    use neo_routing::{Relay, Router};
    use neo_slicing::{encrypt_and_slice, reassemble_and_decrypt, Share};
    use std::collections::HashMap;

    #[test]
    fn node_reports_its_identity() {
        let identity = NodeIdentity::generate().unwrap();
        let expected = identity.id();
        let node = Node::new(identity, NodeConfig::default());
        assert_eq!(node.id(), expected);
    }

    /// The novel core end-to-end, in memory: a message is encrypt-then-sliced
    /// into k-of-n shares (M3), each share is onion-routed over its own disjoint
    /// path (M2), every relay peels exactly one layer, and the destination
    /// reassembles and decrypts (M3) — proving no single relay ever held a
    /// complete, readable flow.
    #[test]
    fn sliced_onion_pipeline_end_to_end() {
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

        // M2: each share travels its own node-disjoint 2-relay path to the exit.
        let paths = router.select_disjoint_paths(3, 2).unwrap();
        let mut delivered: Vec<Share> = Vec::new();
        for (share, path) in shares.iter().zip(paths.iter()) {
            let mut hops: Vec<OnionHop> = path
                .iter()
                .map(|r| OnionHop::new(r.kex, r.id.as_bytes().to_vec()))
                .collect();
            let dp = dest.public();
            hops.push(OnionHop::new(*dp.kex.as_bytes(), dp.id.as_bytes().to_vec()));

            let mut wire = wrap(&hops, &share.to_bytes()).unwrap();
            for relay in path {
                wire = match peel(identity_by_id[&relay.id], &wire).unwrap() {
                    Peeled::Relay { onion, .. } => onion,
                    Peeled::Final { .. } => panic!("a relay should forward, not exit"),
                };
            }
            match peel(&dest, &wire).unwrap() {
                Peeled::Final { payload } => delivered.push(Share::from_bytes(&payload).unwrap()),
                Peeled::Relay { .. } => panic!("the destination should be the exit"),
            }
        }

        // M3: reassemble at the exit from any k = 2 of the 3 delivered shares.
        assert_eq!(
            reassemble_and_decrypt(&key, &delivered[..2]).unwrap(),
            message
        );
        assert_eq!(reassemble_and_decrypt(&key, &delivered).unwrap(), message);
    }
}
