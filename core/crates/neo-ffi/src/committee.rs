//! `committee_fetch` — the client side of the **committee 2PC-TLS exit**, as a
//! coarse FFI call an app opts into per request.
//!
//! Unlike the packet tunnel (which carries an app's *own* end-to-end TLS as raw
//! TCP), committee 2PC-TLS is a **request/response** model: the client hands a
//! plaintext request to a self-formed two-member committee, the committee jointly
//! runs TLS 1.3 to the real destination (neither member holds the session key or
//! sees the plaintext), and the client reconstructs the plaintext reply from the
//! two members' XOR-shares. That does not compose with a transparent raw-TCP
//! tunnel — so it is exposed here as a direct fetch the app calls for the specific
//! flows a user opts in to, not a tunnel branch.
//!
//! This is an **opt-in, experimental** surface: the 2PC stack is unaudited, is
//! semi-honest (assumes the two members don't actively cheat), and each fetch is
//! far slower than a normal splice — right for small, sensitive requests, wrong as
//! a browsing default. Server authentication is still whatever the *relay*
//! (member) side pins; hardening that verifier is a separate, relay-side change.

use neo_core::NodeIdentity;
use neo_discovery::PeerRecord;
use neo_node::forward::Hop;

use crate::tunnel::NeoTunnelError;
use crate::tunnel_stack::fetch_relays;

/// A committee: two members that jointly run the TLS (`lead` egresses to the
/// destination, `follower` is the other share-holder) and a path of relays the
/// onion circuits route *through* — disjoint from both members, so no member
/// learns the client. Mirrors what the desktop `committee2pc-onion` command picks.
struct Committee {
    path: Vec<Hop>,
    lead: Hop,
    follower: Hop,
}

/// Uniform random index in `0..n` (needs `n > 0`), or `None` if the RNG fails.
/// Matches the `tunnel_stack` picker's modulo approach.
fn rand_index(n: usize) -> Option<usize> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).ok()?;
    Some((u64::from_le_bytes(bytes) % n as u64) as usize)
}

fn hop_of(r: &PeerRecord) -> Option<Hop> {
    Some(Hop {
        id: r.id,
        sphinx: r.sphinx,
        addr: r.addrs.first().cloned()?,
    })
}

/// Self-form a committee from the verified relay set: shuffle, take an
/// exit-capable relay as the lead (it egresses), then a follower and one path hop
/// from the rest — all distinct, so the two members are disjoint from the path
/// that anonymizes the client. Needs ≥3 relays and at least one exit.
fn pick_committee(relays: &[&PeerRecord]) -> Result<Committee, NeoTunnelError> {
    if relays.len() < 3 {
        return Err(NeoTunnelError::Discovery {
            detail: format!(
                "committee 2PC needs ≥3 relays (2 members + ≥1 disjoint path hop); found {}",
                relays.len()
            ),
        });
    }
    let rng_err = || NeoTunnelError::Connect {
        detail: "system RNG unavailable".to_string(),
    };

    // Fisher–Yates shuffle of the indices, same as the desktop selector.
    let mut idx: Vec<usize> = (0..relays.len()).collect();
    for i in (1..idx.len()).rev() {
        let j = rand_index(i + 1).ok_or_else(rng_err)?;
        idx.swap(i, j);
    }

    let lead_pos = idx
        .iter()
        .position(|&i| relays[i].exit)
        .ok_or_else(|| NeoTunnelError::Discovery {
            detail: "no exit-capable relay to lead the committee".to_string(),
        })?;
    let lead_i = idx.remove(lead_pos);
    let follower_i = idx.remove(0);
    let path_i = idx.remove(0);

    let addr_err = || NeoTunnelError::Discovery {
        detail: "a chosen relay has no dialable address".to_string(),
    };
    Ok(Committee {
        lead: hop_of(relays[lead_i]).ok_or_else(addr_err)?,
        follower: hop_of(relays[follower_i]).ok_or_else(addr_err)?,
        path: vec![hop_of(relays[path_i]).ok_or_else(addr_err)?],
    })
}

/// Normalize a destination to `host:port`, defaulting to `:443` (committee 2PC-TLS
/// only speaks TLS). An explicit port — including one on an IPv6 literal in
/// brackets — is left untouched.
fn with_default_port(dest: &str) -> String {
    let has_port = if let Some(close) = dest.rfind(']') {
        dest[close + 1..].starts_with(':') // [v6]:port
    } else {
        dest.contains(':')
    };
    if has_port {
        dest.to_string()
    } else {
        format!("{dest}:443")
    }
}

/// A synthetic `GET /` for `dest` when the caller passes an empty request, so the
/// simplest opt-in ("fetch this host over a committee") needs no request bytes.
fn default_request(dest: &str) -> Vec<u8> {
    let host = dest.rsplit_once(':').map(|(h, _)| h).unwrap_or(dest);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: neo-committee2pc\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// Fetch `dest` (`host[:port]`, default port 443) through a self-formed two-member
/// committee 2PC-TLS exit and return the **reconstructed plaintext response**.
///
/// `request` is the raw plaintext request bytes to send inside the committee's TLS
/// (e.g. an HTTP request); pass an empty vector for a default `GET /`. `secret` is
/// the caller's identity; `mirrors`/`witnesses`/`threshold` are the same
/// discovery inputs as [`crate::tunnel_stack_connect`]. `net_interface_index` pins
/// the relay sockets to the physical interface (as the tunnel does) so they don't
/// loop back when a tunnel is up; pass 0 when unscoped.
///
/// This is an opt-in, experimental, unaudited path — see the module docs. It
/// blocks until the (deliberately slow) 2PC completes, so call it off the UI
/// thread.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn committee_fetch(
    secret: Vec<u8>,
    mirrors: Vec<String>,
    witnesses: Vec<String>,
    threshold: u32,
    net_interface_index: u32,
    dest: String,
    request: Vec<u8>,
) -> Result<Vec<u8>, NeoTunnelError> {
    // Same interface pinning as the packet tunnel: relay connections opened after
    // the OS points the default route at a TUN must use the physical interface or
    // they loop back. 0 = unscoped (no tunnel up). Process-wide, like the relay's
    // `--net-interface`; harmless to re-assert the interface an active tunnel set.
    if net_interface_index != 0 {
        neo_node::netif::set_bound_interface(net_interface_index);
    }

    let identity = NodeIdentity::from_bytes(&secret).map_err(|_| NeoTunnelError::Identity)?;

    let mut trusted = Vec::with_capacity(witnesses.len());
    for hex_key in &witnesses {
        let raw = hex::decode(hex_key.trim()).map_err(|_| NeoTunnelError::Discovery {
            detail: format!("witness key is not valid hex: {hex_key}"),
        })?;
        let key: [u8; 32] = raw.try_into().map_err(|_| NeoTunnelError::Discovery {
            detail: "witness key must be 32 bytes".to_string(),
        })?;
        trusted.push(key);
    }

    let dest = with_default_port(&dest);
    let request = if request.is_empty() {
        default_request(&dest)
    } else {
        request
    };

    let rt = crate::tunnel::runtime();
    rt.block_on(async {
        // `fetch_relays` already returns only live, verified relays.
        let relays = fetch_relays(&mirrors, &trusted, threshold as usize).await?;
        let live: Vec<&PeerRecord> = relays.iter().collect();
        let committee = pick_committee(&live)?;
        neo_node::committee_2pc::committee_2pc_fetch(
            &identity,
            &committee.path,
            &committee.lead,
            &committee.follower,
            &dest,
            &request,
        )
        .await
        .map_err(|e| NeoTunnelError::Connect {
            detail: e.to_string(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_discovery::now_unix;

    fn relay(port: u16, exit: bool) -> PeerRecord {
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

    #[test]
    fn default_port_and_request_are_sane() {
        assert_eq!(with_default_port("example.com"), "example.com:443");
        assert_eq!(with_default_port("example.com:8443"), "example.com:8443");
        assert_eq!(with_default_port("[::1]"), "[::1]:443");
        assert_eq!(with_default_port("[::1]:9000"), "[::1]:9000");

        let req = default_request("example.com:443");
        let text = String::from_utf8(req).unwrap();
        assert!(text.starts_with("GET / HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
    }

    #[test]
    fn pick_committee_needs_three_relays_and_an_exit() {
        // Too few relays → rejected.
        let two = [relay(9001, true), relay(9002, false)];
        let two_refs: Vec<&PeerRecord> = two.iter().collect();
        assert!(pick_committee(&two_refs).is_err());

        // Three relays but no exit → rejected.
        let no_exit = [relay(9003, false), relay(9004, false), relay(9005, false)];
        let no_exit_refs: Vec<&PeerRecord> = no_exit.iter().collect();
        assert!(pick_committee(&no_exit_refs).is_err());

        // Three relays with an exit → a committee whose members are distinct from
        // each other and from the path, with an exit-capable lead.
        let ok = [relay(9006, true), relay(9007, false), relay(9008, false)];
        let ok_refs: Vec<&PeerRecord> = ok.iter().collect();
        let c = pick_committee(&ok_refs).expect("valid committee");
        assert_eq!(c.path.len(), 1);
        assert_ne!(c.lead.id, c.follower.id);
        assert_ne!(c.lead.id, c.path[0].id);
        assert_ne!(c.follower.id, c.path[0].id);
        let lead_is_exit = ok
            .iter()
            .any(|r| r.id == c.lead.id && r.exit);
        assert!(lead_is_exit, "the lead must be an exit-capable relay");
    }
}
