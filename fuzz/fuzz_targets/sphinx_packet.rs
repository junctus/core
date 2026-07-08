#![no_main]

use libfuzzer_sys::fuzz_target;

// Parsing an arbitrary byte string as a Sphinx packet must never panic.
fuzz_target!(|data: &[u8]| {
    let _ = neo_crypto::SphinxPacket::from_bytes(data);
});
