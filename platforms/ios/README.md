# neo — iOS shell (scaffold)

A thin iOS app + **Network Extension** that runs the shared Rust core (`neo-ffi`) inside a
`NEPacketTunnelProvider`. This directory is a scaffold: building it needs Xcode + an Apple developer
account and cannot be produced in this environment.

## How it fits together

```
Swift app ──(start VPN)──▶ NEPacketTunnelProvider extension
                                   │  UniFFI-generated Swift bindings
                                   ▼
                            neo-ffi (Rust core)  ── neo-node / neo-crypto / …
```

## Build outline

1. Build the core as an `xcframework` for device + simulator:
   ```sh
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
   cargo build -p neo-ffi --features uniffi --release --target aarch64-apple-ios
   cargo build -p neo-ffi --features uniffi --release --target aarch64-apple-ios-sim
   cargo run -p uniffi-bindgen -- generate --library <libneo_ffi> --language swift --out-dir Generated
   # package the static libs + headers into neo_ffi.xcframework
   ```
2. Add a **Packet Tunnel Provider** extension target; link `neo_ffi.xcframework` and the generated
   Swift bindings.
3. Entitlement: `com.apple.developer.networking.networkextension` (packet-tunnel-provider).

## Constraints to respect (see `docs/MILESTONES.md` M8)

- The extension process has a **hard ~50 MiB memory cap** — keep packet buffers small; do committee
  exit (M12) and PIR (M13) off-device.
- Batch packets across the FFI boundary; never call Rust per packet.
- The adaptive privacy dial should drop to a lighter level on cellular / low battery.

See `PacketTunnelProvider.swift` for the skeleton.
