//! `neo-discovery` — decentralized discovery and NAT traversal.
//!
//! Trackerless peer/relay discovery over a `libp2p` Kademlia DHT, with QUIC
//! links, DCUtR hole-punching, and Circuit Relay v2 fallback. Rendezvous uses
//! DoH (domain fronting is dead). Later hardened with **PIR/oblivious lookups**
//! so a query doesn't leak *what* is being looked up. Discovery only — user data
//! never rides libp2p routing.
//!
//! Status: stub — grows across M4 (DHT/NAT) and M13 (PIR).
