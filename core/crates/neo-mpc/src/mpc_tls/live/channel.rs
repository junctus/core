//! The transport a live 2PC-TLS session speaks over.
//!
//! A [`Channel`] is a bidirectional byte pipe — exactly what a TLS record layer needs.
//! Two impls ship:
//!
//! - [`TcpChannel`] — a real `std::net::TcpStream` to an actual TLS 1.3 server (the live
//!   path).
//! - [`Loopback`] — an in-memory duplex pair, so the handshake state machine can be
//!   driven deterministically in tests without a socket (and so a second party or a mock
//!   server can sit on the other end).
//!
//! On top of raw bytes, [`read_tls_record`] frames the wire into TLS 1.3 records
//! (5-byte header + body), the unit the record layer consumes.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use neo_core::{Error, Result};

use super::super::kos::{KosReceiverSetup, KosSenderSetup};

/// A bidirectional byte transport (the client↔server leg of a live TLS session).
pub trait Channel {
    /// Write all of `buf`, or error.
    fn send(&mut self, buf: &[u8]) -> Result<()>;
    /// Read up to `buf.len()` bytes, returning how many were read (0 = clean EOF).
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Read exactly `n` bytes (looping over [`recv`](Channel::recv)); errors on early EOF.
    fn recv_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; n];
        let mut got = 0;
        while got < n {
            let k = self.recv(&mut out[got..])?;
            if k == 0 {
                return Err(Error::Crypto(format!(
                    "channel: unexpected EOF ({got}/{n} bytes)"
                )));
            }
            got += k;
        }
        Ok(out)
    }

    // ── KOS base-OT amortization (opt-in) ──
    //
    // By default a channel does NOT amortize: every networked garbled gadget runs its own
    // 128 public-key base OTs ([`kos::cot_sender`]/[`kos::cot_receiver`]). A session that
    // wraps its transport in [`AmortizingChannel`] returns `true` from `kos_amortized`, so
    // [`garble_net`](super::super::garble_net) instead holds ONE persistent
    // [`KosSenderSetup`]/[`KosReceiverSetup`] per role and reuses it for every gadget — the
    // base OTs are paid once per session. The setups are taken out (moved) for the duration
    // of one extend then returned, so a setup never borrows the channel it runs over.

    /// Whether this channel amortizes KOS base OTs across gadgets (default: no).
    fn kos_amortized(&self) -> bool {
        false
    }
    /// Take the persistent KOS **sender** setup, or `None` if base OTs are not yet done for
    /// this session (the caller then runs [`KosSenderSetup::new`] once). Returned via
    /// [`put_kos_sender`](Channel::put_kos_sender).
    fn take_kos_sender(&mut self) -> Option<KosSenderSetup> {
        None
    }
    /// Return a KOS sender setup after one extend batch, so the next gadget reuses it.
    fn put_kos_sender(&mut self, _setup: KosSenderSetup) {}
    /// Take the persistent KOS **receiver** setup, or `None` if not yet established.
    fn take_kos_receiver(&mut self) -> Option<KosReceiverSetup> {
        None
    }
    /// Return a KOS receiver setup after one extend batch, so the next gadget reuses it.
    fn put_kos_receiver(&mut self, _setup: KosReceiverSetup) {}
}

/// Wraps a live session's member↔member channel so all of the session's networked garbled
/// gadgets share ONE KOS base-OT setup per role — the 128 public-key base OTs are paid once
/// for the whole handshake instead of once per gadget (the dominant per-gadget cost after
/// [HS-open] removed the certificate-flight 2PC). All byte I/O delegates to `inner`; the two
/// `Option`s hold the per-role persistent setup, lazily established on the first gadget's COT
/// (party A garbles → sender slot; party B evaluates → receiver slot).
pub struct AmortizingChannel<'a> {
    inner: &'a mut dyn Channel,
    sender: Option<KosSenderSetup>,
    receiver: Option<KosReceiverSetup>,
}

impl<'a> AmortizingChannel<'a> {
    pub fn new(inner: &'a mut dyn Channel) -> Self {
        Self { inner, sender: None, receiver: None }
    }
}

impl Channel for AmortizingChannel<'_> {
    fn send(&mut self, buf: &[u8]) -> Result<()> {
        self.inner.send(buf)
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.recv(buf)
    }
    fn kos_amortized(&self) -> bool {
        true
    }
    fn take_kos_sender(&mut self) -> Option<KosSenderSetup> {
        self.sender.take()
    }
    fn put_kos_sender(&mut self, setup: KosSenderSetup) {
        self.sender = Some(setup);
    }
    fn take_kos_receiver(&mut self) -> Option<KosReceiverSetup> {
        self.receiver.take()
    }
    fn put_kos_receiver(&mut self, setup: KosReceiverSetup) {
        self.receiver = Some(setup);
    }
}

/// Read one TLS record: the 5-byte header `type(1) ‖ legacy_version(2) ‖ length(2)`
/// followed by `length` body bytes. Returns `(content_type, body)`.
pub fn read_tls_record<C: Channel + ?Sized>(ch: &mut C) -> Result<(u8, Vec<u8>)> {
    let header = ch.recv_exact(5)?;
    let content_type = header[0];
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if length > 16 * 1024 + 256 {
        return Err(Error::Crypto(format!(
            "channel: oversized TLS record ({length})"
        )));
    }
    let body = ch.recv_exact(length)?;
    Ok((content_type, body))
}

/// A real TCP connection to a TLS server.
pub struct TcpChannel {
    stream: TcpStream,
}

impl TcpChannel {
    pub fn connect(addr: std::net::SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok(); // low-latency flights (chunked sends must not wait on Nagle)
        Ok(TcpChannel { stream })
    }
    pub fn from_stream(stream: TcpStream) -> Self {
        stream.set_nodelay(true).ok();
        TcpChannel { stream }
    }
}

impl Channel for TcpChannel {
    fn send(&mut self, buf: &[u8]) -> Result<()> {
        self.stream.write_all(buf)?;
        Ok(())
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.stream.read(buf)?)
    }
}

/// One end of an in-memory duplex: bytes written here appear on the peer's read side.
/// Backed by two shared queues so a [`pair`](Loopback::pair) can be driven on one thread
/// (mock peer) or two.
#[derive(Clone)]
pub struct Loopback {
    outbound: Arc<Mutex<VecDeque<u8>>>, // this end writes here
    inbound: Arc<Mutex<VecDeque<u8>>>,  // this end reads here
}

impl Loopback {
    /// A connected pair of endpoints; `a.send` is readable by `b.recv` and vice-versa.
    pub fn pair() -> (Loopback, Loopback) {
        let x = Arc::new(Mutex::new(VecDeque::new()));
        let y = Arc::new(Mutex::new(VecDeque::new()));
        let a = Loopback {
            outbound: x.clone(),
            inbound: y.clone(),
        };
        let b = Loopback {
            outbound: y,
            inbound: x,
        };
        (a, b)
    }

    /// Bytes currently queued for this end to read (test introspection).
    pub fn pending(&self) -> usize {
        self.inbound.lock().expect("loopback lock").len()
    }
}

impl Channel for Loopback {
    fn send(&mut self, buf: &[u8]) -> Result<()> {
        self.outbound
            .lock()
            .expect("loopback lock")
            .extend(buf.iter().copied());
        Ok(())
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut q = self.inbound.lock().expect("loopback lock");
        let n = buf.len().min(q.len());
        for slot in buf.iter_mut().take(n) {
            *slot = q.pop_front().expect("checked len");
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_round_trips_and_frames_records() {
        let (mut a, mut b) = Loopback::pair();
        a.send(b"hello").unwrap();
        assert_eq!(b.recv_exact(5).unwrap(), b"hello");

        // A framed TLS record: header + body.
        let body = [0xAAu8; 20];
        let mut rec = vec![0x16, 0x03, 0x03, 0x00, body.len() as u8];
        rec.extend_from_slice(&body);
        a.send(&rec).unwrap();
        let (ct, got) = read_tls_record(&mut b).unwrap();
        assert_eq!(ct, 0x16);
        assert_eq!(got, body);
    }

    #[test]
    fn recv_exact_errors_on_eof() {
        let (mut a, mut b) = Loopback::pair();
        a.send(b"ab").unwrap();
        assert!(b.recv_exact(4).is_err(), "short read must error, not hang");
    }
}
