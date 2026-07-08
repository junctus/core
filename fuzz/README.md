# neo fuzz targets

Coverage-guided fuzzing of neo's wire parsers — the code most exposed to
adversary-controlled bytes. Each target must never panic on any input; errors are
fine.

Runnable smoke coverage of the same parsers exists as ordinary tests (the
`*_survives_garbage` tests), so panics get caught on stable CI too. These targets
go deeper with a coverage-guided fuzzer.

## Run

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run sphinx_packet   # or: share | peer_record | handshake
```

## Targets

- `sphinx_packet` — `neo_crypto::SphinxPacket::from_bytes`
- `share` — `neo_slicing::Share::from_bytes`
- `peer_record` — `neo_discovery::PeerRecord::from_bytes`
- `handshake` — `neo_crypto::responder_process` (message-1 parsing/verification)
