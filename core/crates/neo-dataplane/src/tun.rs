//! Real TUN device (macOS `utun` / Linux `tun`) via `tun-rs`.
//!
//! Requires root to create the interface, so this module is behind the `tun`
//! feature and is not exercised in CI. It reads and writes raw IP packets.

use std::net::Ipv4Addr;

use neo_core::{Error, Result};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::{Packet, PacketIo};

/// A live TUN interface.
pub struct TunDevice {
    device: AsyncDevice,
    mtu: usize,
}

impl TunDevice {
    /// Create and bring up a TUN interface with the given name, address, prefix
    /// length, and MTU. Requires elevated privileges.
    pub fn open(name: &str, address: Ipv4Addr, prefix_len: u8, mtu: u16) -> Result<Self> {
        let device = DeviceBuilder::new()
            .name(name)
            .ipv4(address, prefix_len, None)
            .mtu(mtu)
            .build_async()
            .map_err(Error::Io)?;
        Ok(Self {
            device,
            mtu: mtu as usize,
        })
    }
}

impl PacketIo for TunDevice {
    async fn recv(&mut self) -> Result<Packet> {
        let mut buf = vec![0u8; self.mtu];
        let n = self.device.recv(&mut buf).await.map_err(Error::Io)?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn send(&mut self, packet: &[u8]) -> Result<()> {
        self.device.send(packet).await.map_err(Error::Io)?;
        Ok(())
    }
}
