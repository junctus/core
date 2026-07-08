//! `neo-dataplane` — the OS data plane.
//!
//! Provides a uniform async source/sink of IP packets ([`PacketIo`]) with two
//! implementations:
//! - [`MemoryLink`] — an in-memory duplex used for tests and local wiring, and
//! - `TunDevice` (behind the `tun` feature) — a real TUN interface (macOS
//!   `utun` / Linux `tun`) via `tun-rs`. Creating a TUN device needs root, so it
//!   is off by default and cannot run in CI.
//!
//! On mobile the OS supplies the TUN file descriptor (NetworkExtension /
//! VpnService) and hands it to this crate through `neo-ffi` (milestone M8).

#![forbid(unsafe_code)]

use neo_core::{Error, Result};
use tokio::sync::mpsc;

/// A single IP packet.
pub type Packet = Vec<u8>;

/// An async source and sink of IP packets.
#[allow(async_fn_in_trait)]
pub trait PacketIo {
    /// Receive the next inbound packet.
    async fn recv(&mut self) -> Result<Packet>;
    /// Send a packet outbound.
    async fn send(&mut self, packet: &[u8]) -> Result<()>;
}

/// One end of an in-memory, bidirectional packet link.
pub struct MemoryLink {
    tx: mpsc::Sender<Packet>,
    rx: mpsc::Receiver<Packet>,
}

/// Create a connected pair of in-memory links (what one sends, the other receives).
pub fn memory_pair(capacity: usize) -> (MemoryLink, MemoryLink) {
    let (a_tx, b_rx) = mpsc::channel(capacity);
    let (b_tx, a_rx) = mpsc::channel(capacity);
    (
        MemoryLink { tx: a_tx, rx: a_rx },
        MemoryLink { tx: b_tx, rx: b_rx },
    )
}

fn broken_pipe() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "packet link peer closed",
    ))
}

impl PacketIo for MemoryLink {
    async fn recv(&mut self) -> Result<Packet> {
        self.rx.recv().await.ok_or_else(broken_pipe)
    }

    async fn send(&mut self, packet: &[u8]) -> Result<()> {
        self.tx
            .send(packet.to_vec())
            .await
            .map_err(|_| broken_pipe())
    }
}

#[cfg(feature = "tun")]
mod tun;
#[cfg(feature = "tun")]
pub use tun::TunDevice;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_link_carries_packets_both_ways() {
        let (mut a, mut b) = memory_pair(4);
        a.send(b"outbound packet").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"outbound packet");
        b.send(b"return packet").await.unwrap();
        assert_eq!(a.recv().await.unwrap(), b"return packet");
    }

    #[tokio::test]
    async fn closed_peer_surfaces_error() {
        let (a, mut b) = memory_pair(1);
        drop(a);
        assert!(b.recv().await.is_err());
    }
}
