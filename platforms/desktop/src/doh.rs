//! DoH rendezvous: fetch a signed [`BootstrapRecord`] over DNS-over-HTTPS (M18).
//!
//! The client asks a DoH resolver for the TXT record at a well-known name, joins
//! the returned character-strings, decodes a [`BootstrapRecord`], and verifies
//! it against the baked bootstrap keys. On success it yields the *current*
//! mirrors and witnesses — letting operators rotate them without a client
//! rebuild, over a lookup that is encrypted (so it resists on-path blocking).
//!
//! Only the DoH *transport* is here; the record format + signature check are in
//! `neo_discovery::bootstrap` (network-free and unit-tested).

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use neo_discovery::bootstrap::BootstrapRecord;
use neo_discovery::now_unix;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve current mirrors + witnesses via DoH. `resolver` is a DoH JSON
/// endpoint (e.g. `https://cloudflare-dns.com/dns-query`), `name` the TXT record
/// name, `trusted_keys` the baked bootstrap keys, and `not_before` the highest
/// `created_at` previously accepted (rollback protection; 0 if none).
pub async fn resolve_via_doh(
    resolver: &str,
    name: &str,
    trusted_keys: &[[u8; 32]],
    not_before: u64,
) -> Result<(Vec<String>, Vec<[u8; 32]>)> {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("building DoH client")?;
    let resp = client
        .get(resolver)
        .query(&[("name", name), ("type", "TXT")])
        .header("accept", "application/dns-json")
        .send()
        .await
        .context("DoH request failed")?;
    if !resp.status().is_success() {
        bail!("DoH resolver returned HTTP {}", resp.status());
    }
    let body = resp.text().await.context("reading DoH response")?;

    // Each TXT answer may be split into <=255-char strings; try each joined
    // candidate until one parses and verifies.
    for candidate in parse_doh_txt(&body) {
        if let Ok(record) = BootstrapRecord::from_txt(&candidate) {
            if record.verify(trusted_keys, not_before).is_ok() {
                let now = now_unix();
                // A record valid now but stamped far in the future is suspect.
                if record.created_at <= now + 300 {
                    return Ok((record.mirrors, record.witnesses));
                }
            }
        }
    }
    Err(anyhow!(
        "no valid bootstrap record in the DoH answer for {name}"
    ))
}

/// Extract candidate TXT payloads from a DoH JSON response. Each `Answer` of
/// type 16 (TXT) has a `data` field of one or more quoted strings; we strip the
/// quotes and concatenate them into one candidate per answer.
fn parse_doh_txt(json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(answers) = value.get("Answer").and_then(|a| a.as_array()) else {
        return Vec::new();
    };
    answers
        .iter()
        .filter(|a| a.get("type").and_then(|t| t.as_u64()) == Some(16))
        .filter_map(|a| a.get("data").and_then(|d| d.as_str()))
        .map(|data| {
            // `"chunk1" "chunk2"` → `chunk1chunk2`
            data.split('"')
                .enumerate()
                .filter(|(i, _)| i % 2 == 1)
                .map(|(_, s)| s)
                .collect::<String>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_core::NodeIdentity;

    #[test]
    fn parses_txt_out_of_doh_json_and_joins_chunks() {
        let json = r#"{
            "Status": 0,
            "Answer": [
                {"name":"_neo.example.","type":16,"data":"\"aabb\" \"ccdd\""},
                {"name":"_neo.example.","type":5,"data":"ignored-cname"}
            ]
        }"#;
        let txt = parse_doh_txt(json);
        assert_eq!(txt, vec!["aabbccdd".to_string()]);
    }

    #[test]
    fn end_to_end_record_survives_the_txt_channel() {
        // A signed record → hex TXT → wrapped in a DoH JSON answer → parsed back
        // → verifies. (No network; exercises the full encode/transport/decode.)
        let boot = NodeIdentity::generate().unwrap();
        let rec = BootstrapRecord::sign(
            &boot,
            now_unix(),
            vec!["https://discovery.junctus.org".into()],
            vec![[3u8; 32]],
        )
        .unwrap();
        let json = format!(
            r#"{{"Answer":[{{"type":16,"data":"\"{}\""}}]}}"#,
            rec.to_txt()
        );
        let candidates = parse_doh_txt(&json);
        let parsed = BootstrapRecord::from_txt(&candidates[0]).unwrap();
        parsed
            .verify(&[boot.public().signing.to_bytes()], 0)
            .unwrap();
        assert_eq!(parsed.mirrors, rec.mirrors);
    }

    #[test]
    fn malformed_json_yields_no_candidates() {
        assert!(parse_doh_txt("not json").is_empty());
        assert!(parse_doh_txt("{}").is_empty());
    }
}
