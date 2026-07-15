#![no_main]

use libfuzzer_sys::fuzz_target;
use neo_core::NodeIdentity;
use neo_crypto::CookieKey;
use std::sync::OnceLock;

// A fixed responder identity, reused across runs.
static RESPONDER: OnceLock<NodeIdentity> = OnceLock::new();
static COOKIE_KEY: OnceLock<CookieKey> = OnceLock::new();

// Feeding an arbitrary first handshake message to the responder must never panic
// (it should reject invalid input with an error).
fuzz_target!(|data: &[u8]| {
    let identity = RESPONDER.get_or_init(|| NodeIdentity::generate().expect("identity"));
    let cookie_key = COOKIE_KEY.get_or_init(|| CookieKey::generate().expect("cookie key"));

    // Treat fuzz bytes as the raw m1. First exercise the cheap cookie parser,
    // then synthesize the valid wrapper needed to reach deep signature/KEM parsing.
    let mut uncookied = Vec::with_capacity(4 + data.len());
    uncookied.extend_from_slice(&0u32.to_be_bytes());
    uncookied.extend_from_slice(data);
    if let Ok(cookie) = neo_crypto::responder_cookie(cookie_key, &uncookied) {
        let mut cookied = Vec::with_capacity(4 + cookie.len() + data.len());
        cookied.extend_from_slice(&(cookie.len() as u32).to_be_bytes());
        cookied.extend_from_slice(&cookie);
        cookied.extend_from_slice(data);
        let _ = neo_crypto::responder_process(identity, &cookied, cookie_key);
    }
});
