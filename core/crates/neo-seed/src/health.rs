//! Dial-back health verification.
//!
//! Admission proves a record is *internally* valid (self-certifying + signed).
//! It does not prove the operator actually controls the advertised address —
//! anyone can sign a record naming someone else's IP, or an IP that black-holes
//! traffic. So before a seed *attests* to a relay, it dials the relay itself
//! and runs the neo handshake: the connection only succeeds if the far side
//! holds the record's long-term signing key, which simultaneously confirms
//! reachability and binds the address to the identity. This is what stops a
//! seed from amplifying bogus or hijacked relay entries into its snapshot.

use std::time::Duration;

use neo_core::NodeIdentity;
use neo_discovery::PeerRecord;

/// How long a single dial-back may take before it's counted as a failure.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Dial the relay and confirm it authenticates as the record's signing key.
///
/// Returns the **first advertised address that verified** (completed the
/// handshake with a peer key equal to `record.signing`), or `None` if none did.
/// Uses `prober` as the local identity for the handshake (a seed's own identity
/// is fine — the check is one-directional).
///
/// Returning *which* address verified matters for the Sybil subnet cap (M36): a
/// record may advertise addresses the operator does **not** control (padding its
/// `addrs` with IPs in a victim's /24 to weaponize the cap against honest relays
/// there). Only the address that actually answered the dial-back is proven, so
/// only its subnet may be counted toward the cap.
///
/// **SSRF guard:** an advertised address that is not a safe *public* IP:port
/// literal (loopback, RFC1918, link-local / cloud metadata, ULA, CGNAT, or a
/// hostname) is skipped, so an attacker cannot register a record naming an
/// internal address and make the seed dial it. `allow_loopback` opens localhost
/// for local dev/test only.
pub async fn dial_back(
    prober: &NodeIdentity,
    record: &PeerRecord,
    allow_loopback: bool,
) -> Option<String> {
    for addr in &record.addrs {
        if !neo_core::net::is_safe_dial_target(addr, allow_loopback) {
            continue;
        }
        if handshake_matches(prober, addr, &record.signing).await {
            return Some(addr.clone());
        }
    }
    None
}

async fn handshake_matches(prober: &NodeIdentity, addr: &str, expected: &[u8; 32]) -> bool {
    match tokio::time::timeout(DIAL_TIMEOUT, neo_node::run::connect(addr, prober)).await {
        Ok(Ok((_stream, result))) => &result.peer.to_bytes() == expected,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_discovery::now_unix;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn dial_back_confirms_a_real_relay() {
        // Stand up a real relay that runs the responder handshake.
        let relay_id = NodeIdentity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = {
            let relay_id = NodeIdentity::from_bytes(&relay_id.to_bytes()).unwrap();
            tokio::spawn(async move {
                let _ = neo_node::run::accept(&listener, &relay_id).await;
            })
        };

        let record =
            PeerRecord::build_signed(&relay_id, vec![addr], true, false, now_unix() + 3600, 1)
                .unwrap();
        let prober = NodeIdentity::generate().unwrap();
        assert!(dial_back(&prober, &record, true).await.is_some());
        let _ = server.await;
    }

    #[tokio::test]
    async fn dial_back_rejects_an_address_that_isnt_the_claimed_node() {
        // A relay listens, but the record claims a *different* signing key
        // (an operator advertising someone else's identity, or a hijack).
        let real = NodeIdentity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let _ = neo_node::run::accept(&listener, &real).await;
        });

        let imposter = NodeIdentity::generate().unwrap();
        let record =
            PeerRecord::build_signed(&imposter, vec![addr], true, false, now_unix() + 3600, 1)
                .unwrap();
        let prober = NodeIdentity::generate().unwrap();
        assert!(dial_back(&prober, &record, true).await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn dial_back_fails_on_a_dead_address() {
        // A safe (loopback, dev) but closed port: dial fails, so attestation fails.
        let relay_id = NodeIdentity::generate().unwrap();
        let record = PeerRecord::build_signed(
            &relay_id,
            vec!["127.0.0.1:1".into()],
            true,
            false,
            now_unix() + 3600,
            1,
        )
        .unwrap();
        let prober = NodeIdentity::generate().unwrap();
        assert!(dial_back(&prober, &record, true).await.is_none());
    }

    #[tokio::test]
    async fn dial_back_refuses_internal_ssrf_targets() {
        // A record naming internal addresses must never be dialed (SSRF guard),
        // even though the record itself is validly signed.
        let relay_id = NodeIdentity::generate().unwrap();
        let record = PeerRecord::build_signed(
            &relay_id,
            vec![
                "169.254.169.254:80".into(), // cloud metadata
                "10.0.0.1:443".into(),       // RFC1918
                "127.0.0.1:9000".into(),     // loopback (allow_loopback=false)
            ],
            true,
            false,
            now_unix() + 3600,
            1,
        )
        .unwrap();
        let prober = NodeIdentity::generate().unwrap();
        assert!(
            dial_back(&prober, &record, false).await.is_none(),
            "internal targets must not be dialed"
        );
    }
}
