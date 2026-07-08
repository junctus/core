#![no_main]

use libfuzzer_sys::fuzz_target;

// Parsing an arbitrary byte string as a discovery peer record must never panic.
fuzz_target!(|data: &[u8]| {
    let _ = neo_discovery::PeerRecord::from_bytes(data);
});
