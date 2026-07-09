//! A smoltcp [`Device`] backed by two in-memory packet queues.
//!
//! The stack's poll loop owns the device: it pushes IP packets that arrived from
//! the TUN onto [`rx`](ChannelDevice::rx) before polling, and drains packets the
//! stack produced from [`tx`](ChannelDevice::tx) afterwards to send to the TUN.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

/// Default MTU for the virtual interface. Matches the tunnel's cell payload room.
pub const MTU: usize = 1500;

/// A packet device whose "wire" is two [`VecDeque`]s the poll loop manages.
pub struct ChannelDevice {
    /// Inbound IP packets (from the TUN) waiting to be processed by the stack.
    pub rx: VecDeque<Vec<u8>>,
    /// Outbound IP packets the stack produced, to be written to the TUN.
    pub tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl ChannelDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }
}

pub struct RxTok(Vec<u8>);

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((RxTok(packet), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
