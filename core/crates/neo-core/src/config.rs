//! Node configuration and the adaptive privacy dial.

use serde::{Deserialize, Serialize};

/// The privacy dial: trades latency and bandwidth for anonymity strength.
///
/// Higher levels enable more cover traffic, deeper timing mixing, more hops,
/// higher share redundancy, and (eventually) committee exits and PIR discovery.
/// On mobile the *effective* level is throttled automatically on battery or
/// metered connections — see the mobile shells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyLevel {
    /// No mixing or cover traffic — fastest, weakest privacy. Development only.
    Off,
    /// A sane default: moderate mixing and cover traffic.
    #[default]
    Balanced,
    /// Maximum anonymity: heavy cover traffic, deep mixing, committee exits.
    Paranoid,
}

/// Top-level node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    /// The privacy dial setting.
    pub privacy_level: PrivacyLevel,
    /// Whether this node will relay traffic for other nodes.
    pub relay: bool,
    /// Whether this node will act as a clearnet exit.
    ///
    /// Opt-in and off by default: operating an exit carries real-world legal
    /// liability even though neo diffuses and rotates exit responsibility.
    pub exit: bool,
    /// Directory for persistent state (identity, credits, config).
    pub data_dir: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            privacy_level: PrivacyLevel::default(),
            relay: true,
            exit: false,
            data_dir: ".neo".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let cfg = NodeConfig::default();
        assert_eq!(cfg.privacy_level, PrivacyLevel::Balanced);
        assert!(cfg.relay);
        assert!(!cfg.exit, "exit must be opt-in");
    }

    #[test]
    fn privacy_level_serializes_snake_case() {
        let toml = serde_json::to_string(&PrivacyLevel::Paranoid).unwrap();
        assert_eq!(toml, "\"paranoid\"");
    }
}
