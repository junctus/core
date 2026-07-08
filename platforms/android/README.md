# neo — Android shell (scaffold)

A thin Android app + **`VpnService`** that runs the shared Rust core (`neo-ffi`) via JNI. This is a
scaffold: building it needs the Android SDK/NDK + Gradle and cannot be produced in this environment.

## How it fits together

```
Kotlin app ──(prepare + start)──▶ NeoVpnService (VpnService)
                                        │  UniFFI-generated Kotlin bindings (JNI)
                                        ▼
                                 neo-ffi (Rust core)  ── neo-node / neo-crypto / …
```

## Build outline

1. Build the core `.so` for Android ABIs with `cargo-ndk`:
   ```sh
   cargo install cargo-ndk
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   cargo ndk -t arm64-v8a -t armeabi-v7a -o app/src/main/jniLibs \
     build -p neo-ffi --features uniffi --release
   uniffi-bindgen generate --library <libneo_ffi.so> --language kotlin --out-dir app/src/main/java
   ```
2. Declare the service in `AndroidManifest.xml` with `BIND_VPN_SERVICE` and a foreground-service type.
3. Start it as a **foreground service** with a persistent notification (required on Android 8+).

## Constraints to respect (see `docs/MILESTONES.md` M8)

- **Doze mode throttles background network** regardless of the foreground service — expect
  interruptions; design for reconnect.
- Batch packets across the JNI boundary.
- The adaptive privacy dial should drop to a lighter level on metered connections / low battery.

See `NeoVpnService.kt` for the skeleton.
