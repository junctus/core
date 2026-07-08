#![no_main]

use libfuzzer_sys::fuzz_target;

// Parsing an arbitrary byte string as a slicing share must never panic.
fuzz_target!(|data: &[u8]| {
    let _ = neo_slicing::Share::from_bytes(data);
});
