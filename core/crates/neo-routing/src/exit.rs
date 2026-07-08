//! M7 — opt-in clearnet exits, exit policy, and per-request route diffusion.
//!
//! Reaching the open web is opt-in and off by default. When enabled, exits rotate
//! per request and concurrent requests are kept to disjoint full routes, so exit
//! responsibility is spread thin and rotated (the *statistical* "no responsible
//! exit"; the cryptographic committee exit is M12).

use std::collections::HashSet;

use neo_core::{Error, NodeId, Result};

use crate::{rand_below, Relay};

/// A clearnet destination an exit might connect to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    /// Destination host (name or IP literal).
    pub host: String,
    /// Destination port.
    pub port: u16,
}

impl Destination {
    /// Build a destination.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// Whether and how this node acts as a clearnet exit. **Off by default** — running
/// an exit carries real legal liability even though neo diffuses responsibility.
#[derive(Clone, Debug)]
pub struct ExitPolicy {
    /// Master switch; exits do nothing unless this is `true`.
    pub enabled: bool,
    /// Ports never exited to (defaults block common abuse ports, e.g. SMTP).
    pub blocked_ports: HashSet<u16>,
    /// If `Some`, only these ports are exited to; `None` means all but blocked.
    pub allowed_ports: Option<HashSet<u16>>,
}

impl Default for ExitPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            blocked_ports: [25, 465, 587].into_iter().collect(),
            allowed_ports: None,
        }
    }
}

impl ExitPolicy {
    /// Whether this node will exit traffic to `dest`.
    pub fn permits(&self, dest: &Destination) -> bool {
        if !self.enabled {
            return false;
        }
        if self.blocked_ports.contains(&dest.port) {
            return false;
        }
        match &self.allowed_ports {
            Some(allowed) => allowed.contains(&dest.port),
            None => true,
        }
    }
}

/// Selects a fresh exit per request, never repeating the immediately-previous one.
pub struct ExitSelector {
    exits: Vec<Relay>,
    last: Option<NodeId>,
}

impl ExitSelector {
    /// Build a selector over the exit-capable relays.
    pub fn new(exits: Vec<Relay>) -> Self {
        Self { exits, last: None }
    }

    /// Pick the next exit, avoiding the one used immediately before.
    pub fn select(&mut self) -> Result<Relay> {
        if self.exits.is_empty() {
            return Err(Error::Config("no exit relays available".into()));
        }
        loop {
            let choice = self.exits[rand_below(self.exits.len())?].clone();
            if self.exits.len() == 1 || self.last != Some(choice.id) {
                self.last = Some(choice.id);
                return Ok(choice);
            }
        }
    }
}

/// Tracks routes currently in use so no two *concurrent* requests share a full route.
#[derive(Default)]
pub struct RouteRegistry {
    active: HashSet<Vec<[u8; 32]>>,
}

impl RouteRegistry {
    /// A new, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    fn key(route: &[Relay]) -> Vec<[u8; 32]> {
        route.iter().map(|r| *r.id.as_bytes()).collect()
    }

    /// Register a route as active. Returns `false` if an identical route is already active.
    pub fn try_register(&mut self, route: &[Relay]) -> bool {
        self.active.insert(Self::key(route))
    }

    /// Release a route when its request completes.
    pub fn release(&mut self, route: &[Relay]) {
        self.active.remove(&Self::key(route));
    }

    /// Number of routes currently active.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_core::NodeIdentity;

    fn relay() -> Relay {
        let id = NodeIdentity::generate().unwrap();
        let p = id.public();
        Relay {
            id: p.id,
            kex: *p.kex.as_bytes(),
            sphinx: p.sphinx,
            addr: String::new(),
        }
    }

    #[test]
    fn exit_is_off_by_default() {
        assert!(!ExitPolicy::default().permits(&Destination::new("example.com", 443)));
    }

    #[test]
    fn enabled_policy_enforces_ports() {
        let mut policy = ExitPolicy {
            enabled: true,
            ..ExitPolicy::default()
        };
        assert!(policy.permits(&Destination::new("example.com", 443)));
        assert!(
            !policy.permits(&Destination::new("spam", 25)),
            "SMTP is blocked"
        );

        policy.allowed_ports = Some([443].into_iter().collect());
        assert!(policy.permits(&Destination::new("x", 443)));
        assert!(!policy.permits(&Destination::new("x", 80)));
    }

    #[test]
    fn exit_selector_never_repeats_immediately() {
        let mut selector = ExitSelector::new(vec![relay(), relay(), relay()]);
        let mut prev = None;
        for _ in 0..50 {
            let exit = selector.select().unwrap();
            assert_ne!(
                Some(exit.id),
                prev,
                "consecutive requests must use different exits"
            );
            prev = Some(exit.id);
        }
    }

    #[test]
    fn concurrent_routes_must_be_disjoint() {
        let route = [relay(), relay()];
        let mut registry = RouteRegistry::new();
        assert!(registry.try_register(&route));
        assert!(
            !registry.try_register(&route),
            "a concurrent identical route is rejected"
        );
        assert_eq!(registry.active_count(), 1);
        registry.release(&route);
        assert!(registry.try_register(&route), "reusable once released");
    }
}
