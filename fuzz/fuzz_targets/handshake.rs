#![no_main]

use libfuzzer_sys::fuzz_target;
use neo_core::NodeIdentity;
use std::sync::OnceLock;

// A fixed responder identity, reused across runs.
static RESPONDER: OnceLock<NodeIdentity> = OnceLock::new();

// Feeding an arbitrary first handshake message to the responder must never panic
// (it should reject invalid input with an error).
fuzz_target!(|data: &[u8]| {
    let identity = RESPONDER.get_or_init(|| NodeIdentity::generate().expect("identity"));
    let _ = neo_crypto::responder_process(identity, data);
});
