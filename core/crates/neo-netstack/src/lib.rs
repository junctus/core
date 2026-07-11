//! `neo-netstack` — a userspace TCP/IP stack that turns a stream of raw IP
//! packets (from a platform TUN) into intercepted TCP flows.
//!
//! A packet tunnel gets raw IP packets, but neo carries **TCP connections** (the
//! exit splices a `TcpStream` to the target — see `neo_node::circuit`). This crate
//! bridges the two: it runs [`smoltcp`] as a "tun2socks" gateway that terminates
//! TCP locally and, for every flow the device tries to open, emits a
//! [`Connection`] carrying the original destination and an async byte stream. The
//! caller pumps that byte stream through a neo circuit to the same destination.

mod device;
mod stack;

pub use device::MTU;
pub use stack::{
    ConnReader, ConnWriter, Connection, Connections, NetStack, Outbound, UdpConnections, UdpFlow,
    UdpReply,
};
