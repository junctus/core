//! Dial-target safety — an SSRF / metadata-service guard.
//!
//! A public-facing neo service (a seed doing dial-back attestation, an exit
//! splicing a TCP connection) must never be tricked into dialing an internal
//! address named in an attacker-supplied record: loopback, RFC1918, link-local
//! (which includes the `169.254.169.254` cloud metadata service), ULA, CGNAT, and
//! friends. This module centralizes that check.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// True if `ip` is in a private / loopback / link-local / special-use range that
/// should never be dialed from a public service.
pub fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local() // includes 169.254.169.254 metadata
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || is_cgnat(v4)
                || v4.octets()[0] == 0 // 0.0.0.0/8
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_ula(v6) // fc00::/7 unique-local
                || is_link_local_v6(v6) // fe80::/10
        }
    }
}

/// Whether `addr` (a `host:port` string) is a safe public dial target. It must be
/// an **IP literal** (no hostname — so no DNS-rebinding surface) and outside every
/// internal range. Loopback is permitted only when `allow_loopback` (local
/// dev/test); production callers pass `false`.
pub fn is_safe_dial_target(addr: &str, allow_loopback: bool) -> bool {
    match addr.parse::<SocketAddr>() {
        Ok(sa) => {
            let ip = sa.ip();
            if ip.is_loopback() {
                return allow_loopback;
            }
            !is_internal_ip(&ip)
        }
        // Reject hostnames / unparseable inputs: literals only.
        Err(_) => false,
    }
}

/// A coarse network identifier for Sybil-resistance checks (M36): the IPv4 **/24**
/// or IPv6 **/64** an address sits in. Two relays with the same `SubnetKey` are
/// treated as the same network (a proxy for "same operator"), so the seed caps how
/// many it attests per subnet and clients never place two circuit hops in one. It
/// is a coarse heuristic, not identity — an adversary spanning many /24s defeats
/// it (that is the honest limit of subnet diversity; ASN-level caps are a
/// follow-on needing a BGP dataset).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubnetKey {
    /// IPv4 /24 — the first three octets.
    V4([u8; 3]),
    /// IPv6 /64 — the first four 16-bit segments.
    V6([u16; 4]),
}

impl SubnetKey {
    /// The subnet of a `host:port` string, or `None` if it is not an IP literal
    /// (a hostname or malformed input has no checkable subnet). The port is
    /// irrelevant, so `1.2.3.4:9000` and `1.2.3.4:9001` share a key.
    pub fn from_addr(addr: &str) -> Option<Self> {
        let ip = addr.parse::<SocketAddr>().ok()?.ip();
        Some(match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                SubnetKey::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                SubnetKey::V6([s[0], s[1], s[2], s[3]])
            }
        })
    }
}

fn is_cgnat(v4: &Ipv4Addr) -> bool {
    // 100.64.0.0/10 carrier-grade NAT.
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

fn is_ula(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

fn is_link_local_v6(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_targets_are_rejected() {
        for a in [
            "127.0.0.1:443",
            "10.0.0.5:80",
            "192.168.1.1:8080",
            "172.16.0.1:22",
            "169.254.169.254:80", // cloud metadata
            "100.64.0.1:443",     // CGNAT
            "0.0.0.0:80",
            "[::1]:443",
            "[fe80::1]:80",
            "[fc00::1]:80",
            "example.com:443", // hostname → rejected (no literals)
            "not-an-addr",
        ] {
            assert!(
                !is_safe_dial_target(a, false),
                "{a} must be rejected as a public dial target"
            );
        }
    }

    #[test]
    fn public_targets_are_allowed_and_loopback_is_opt_in() {
        assert!(is_safe_dial_target("1.1.1.1:443", false));
        assert!(is_safe_dial_target("[2606:4700:4700::1111]:443", false));
        // Loopback only when explicitly allowed (dev/test).
        assert!(!is_safe_dial_target("127.0.0.1:9000", false));
        assert!(is_safe_dial_target("127.0.0.1:9000", true));
    }

    #[test]
    fn subnet_key_groups_a_24_and_a_64() {
        // IPv4 /24: the port is irrelevant, the 4th octet is ignored.
        let a = SubnetKey::from_addr("1.2.3.4:9000").unwrap();
        assert_eq!(a, SubnetKey::V4([1, 2, 3]));
        assert_eq!(a, SubnetKey::from_addr("1.2.3.4:9001").unwrap()); // same IP, diff port
        assert_eq!(a, SubnetKey::from_addr("1.2.3.99:443").unwrap()); // same /24
        assert_ne!(a, SubnetKey::from_addr("1.2.4.4:9000").unwrap()); // different /24
                                                                      // IPv6 /64: first four segments.
        let v6 = SubnetKey::from_addr("[2606:4700:4700::1111]:443").unwrap();
        assert_eq!(v6, SubnetKey::V6([0x2606, 0x4700, 0x4700, 0]));
        assert_ne!(a, v6);
        // Non-literals and garbage have no subnet.
        for bad in ["example.com:443", "not-an-addr", "1.2.3.4", ":9000", ""] {
            assert_eq!(SubnetKey::from_addr(bad), None, "{bad} has no subnet");
        }
    }
}
