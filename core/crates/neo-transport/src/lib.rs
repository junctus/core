//! `neo-transport` — pluggable, DPI-resistant transport.
//!
//! A [`Transport`] carries neo's own encrypted protocol (and all `libp2p`
//! traffic, whose wire protocol is itself fingerprintable) under an
//! [`Obfuscation`] strategy chosen at runtime:
//! - [`Plain`] — no obfuscation (baseline / development), and
//! - [`Bucketed`] — quantizes every record's length to a multiple of a bucket
//!   size with random padding, so an observer sees only coarse, uniform lengths
//!   instead of exact payload sizes.
//!
//! This is the pluggable *shape* of M6. The strong transports named in the plan
//! — QUIC/MASQUE, Snowflake-style WebRTC, and REALITY — are larger efforts that
//! slot in as further `Obfuscation`/`Transport` implementations behind this same
//! interface. Rendezvous uses DoH, not domain fronting (which is dead).

#![forbid(unsafe_code)]

#[cfg(feature = "quic")]
pub mod quic;

use neo_core::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_RECORD: usize = 16 * 1024 * 1024;

/// A reversible transformation applied to each record before it hits the wire.
pub trait Obfuscation: Clone + Send + Sync + 'static {
    /// Turn an application payload into a wire record.
    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>>;
    /// Recover the payload from a wire record.
    fn unframe(&self, record: &[u8]) -> Result<Vec<u8>>;
}

/// No obfuscation: the record is the payload. Baseline and for development.
#[derive(Clone, Copy, Debug, Default)]
pub struct Plain;

impl Obfuscation for Plain {
    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>> {
        Ok(payload.to_vec())
    }
    fn unframe(&self, record: &[u8]) -> Result<Vec<u8>> {
        Ok(record.to_vec())
    }
}

/// Pads every record up to a multiple of `bucket` bytes with random data, so the
/// observable length is quantized rather than exact.
#[derive(Clone, Copy, Debug)]
pub struct Bucketed {
    bucket: usize,
}

impl Bucketed {
    /// Create a bucketed obfuscator with the given quantum (must be > 0).
    pub fn new(bucket: usize) -> Result<Self> {
        if bucket == 0 {
            return Err(Error::Config("bucket size must be > 0".into()));
        }
        Ok(Self { bucket })
    }
}

impl Obfuscation for Bucketed {
    fn frame(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut record = Vec::with_capacity(payload.len() + self.bucket);
        record.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        record.extend_from_slice(payload);

        let target = record.len().div_ceil(self.bucket) * self.bucket;
        let pad = target - record.len();
        let mut padding = vec![0u8; pad];
        getrandom::getrandom(&mut padding).map_err(|e| Error::Rng(e.to_string()))?;
        record.extend_from_slice(&padding);
        Ok(record)
    }

    fn unframe(&self, record: &[u8]) -> Result<Vec<u8>> {
        if record.len() < 4 {
            return Err(Error::Decode("obfuscated record too short".into()));
        }
        let len = u32::from_be_bytes(record[..4].try_into().expect("checked")) as usize;
        if record.len() < 4 + len {
            return Err(Error::Decode("obfuscated record truncated".into()));
        }
        Ok(record[4..4 + len].to_vec())
    }
}

/// A transport that dials and listens with a chosen obfuscation strategy.
#[derive(Clone)]
pub struct Transport<O: Obfuscation> {
    obfuscation: O,
}

impl<O: Obfuscation> Transport<O> {
    /// Create a transport using the given obfuscation.
    pub fn new(obfuscation: O) -> Self {
        Self { obfuscation }
    }

    /// Dial a peer.
    pub async fn dial(&self, addr: &str) -> Result<Conn<O>> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Conn {
            stream,
            obfuscation: self.obfuscation.clone(),
        })
    }

    /// Bind a listener.
    pub async fn listen(&self, addr: &str) -> Result<Listener<O>> {
        Ok(Listener {
            listener: TcpListener::bind(addr).await?,
            obfuscation: self.obfuscation.clone(),
        })
    }
}

/// A bound listener that accepts obfuscated connections.
pub struct Listener<O: Obfuscation> {
    listener: TcpListener,
    obfuscation: O,
}

impl<O: Obfuscation> Listener<O> {
    /// Accept one connection.
    pub async fn accept(&self) -> Result<Conn<O>> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(Conn {
            stream,
            obfuscation: self.obfuscation.clone(),
        })
    }

    /// The local address the listener is bound to.
    pub fn local_addr(&self) -> Result<String> {
        Ok(self.listener.local_addr()?.to_string())
    }
}

/// A message-oriented connection that obfuscates every record.
pub struct Conn<O: Obfuscation> {
    stream: TcpStream,
    obfuscation: O,
}

impl<O: Obfuscation> Conn<O> {
    /// Send one payload as an obfuscated, length-prefixed record.
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let record = self.obfuscation.frame(payload)?;
        self.stream
            .write_all(&(record.len() as u32).to_be_bytes())
            .await?;
        self.stream.write_all(&record).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive one payload.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_RECORD {
            return Err(Error::Decode("record exceeds maximum size".into()));
        }
        let mut record = vec![0u8; n];
        self.stream.read_exact(&mut record).await?;
        self.obfuscation.unframe(&record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucketed_quantizes_length_and_roundtrips() {
        let obf = Bucketed::new(256).unwrap();
        for size in [0usize, 1, 100, 255, 256, 300, 1000] {
            let payload = vec![0xabu8; size];
            let record = obf.frame(&payload).unwrap();
            assert_eq!(record.len() % 256, 0, "record length must be quantized");
            assert!(record.len() > size, "padding must be present");
            assert_eq!(obf.unframe(&record).unwrap(), payload);
        }
    }

    #[test]
    fn distinct_payload_sizes_can_share_a_bucket() {
        let obf = Bucketed::new(256).unwrap();
        // 100 and 200 byte payloads both fit one 256-byte bucket → same wire length.
        assert_eq!(
            obf.frame(&[1u8; 100]).unwrap().len(),
            obf.frame(&[2u8; 200]).unwrap().len()
        );
    }

    #[tokio::test]
    async fn obfuscated_transport_roundtrips_over_tcp() {
        let transport = Transport::new(Bucketed::new(512).unwrap());
        let listener = transport.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            let msg = conn.recv().await.unwrap();
            conn.send(b"pong").await.unwrap();
            msg
        });

        let mut client = transport.dial(&addr).await.unwrap();
        client.send(b"ping").await.unwrap();
        assert_eq!(client.recv().await.unwrap(), b"pong");
        assert_eq!(server.await.unwrap(), b"ping");
    }
}
