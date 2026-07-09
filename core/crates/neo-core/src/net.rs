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
}
