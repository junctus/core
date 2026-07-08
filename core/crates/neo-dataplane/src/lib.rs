//! `neo-dataplane` — the OS data plane.
//!
//! Reads and writes IP packets on a TUN interface (macOS `utun`, Linux `tun`)
//! via `tun-rs` + tokio, and multiplexes packets to and from neo flows. On
//! mobile the TUN file descriptor is supplied by the OS (NetworkExtension /
//! VpnService) and handed to this crate through `neo-ffi`.
//!
//! Status: stub — implemented in milestone M1.
