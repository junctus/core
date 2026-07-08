//! `neo-node` — the engine that wires the neo crates together.
//!
//! Owns the node lifecycle and its roles (client, relay, mix, exit, committee
//! member) driven by [`NodeConfig`]. Every platform shell — desktop, iOS,
//! Android — runs a `neo-node` behind a thin adapter.
//!
//! Status: stub — grows from milestone M1 onward.

use neo_core::{NodeConfig, NodeIdentity};

/// A neo node: an identity plus its configuration. Networking arrives in M1+.
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
    pub fn id(&self) -> neo_core::NodeId {
        self.identity.id()
    }
}
