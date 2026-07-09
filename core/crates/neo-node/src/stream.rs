//! Bidirectional request/response over an onion circuit (M15).
//!
//! [`forward`](crate::forward) delivers a payload one-way to the exit. This
//! module adds the **return path**, giving a full round-trip: the client sends a
//! request to the exit through the circuit and receives the exit's response back
//! through the same relays — with the response **onion-encrypted on the way
//! back** so no intermediate relay can read it.
//!
//! ## How the return path is keyed
//!
//! Sphinx already makes the *forward* payload confidential to the exit, so only
//! the *reverse* direction needs layering. Each hop derives a **stream key**
//! from the Sphinx shared secret it already computes (`stream_key(s_i)`); the
//! client learns every `s_i` from [`create_packet_keyed`]. On the way back the
//! exit encrypts its response under `s_n`, and each relay adds its own layer
//! under `s_i`; the client, holding all keys, peels them in order. A relay `i`
//! only ever sees the response still wrapped in layers `i+1..n`, which it cannot
//! remove.
//!
//! The response carries an **end-to-end integrity tag** keyed by the exit's
//! shared secret, so a middle relay that mauls the (XOR-layered) response bits
//! cannot forge a matching tag — the client rejects a tampered response rather
//! than accepting attacker-chosen bytes (parity with the forward Sphinx payload:
//! a tamper is dropped, not delivered).
//!
//! **Honest scope:** this is a single request → single response round-trip (the
//! hard part — a working, integrity-protected, layered return path). A
//! persistent multi-cell byte stream / TCP tunnel builds on this with per-cell
//! counters and connection splicing (deferred).

use std::collections::HashMap;
use std::sync::Mutex;

use neo_core::{Error, NodeId, NodeIdentity, Result};
use neo_crypto::{create_packet_keyed, process, Processed, ReplayCache, Session, SphinxPacket};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::forward::{Hop, NextHop};
use crate::run::{connect, read_frame, write_frame};

/// Length of the end-to-end return-path integrity tag.
const RETURN_MAC_LEN: usize = 16;

/// Derive a per-hop return-path stream key from a Sphinx shared secret.
fn stream_key(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("neo-stream-return-v1", secret)
}

/// End-to-end return-path integrity tag, keyed by the **exit's** shared secret.
/// The exit prepends it and the client verifies it, so a middle relay that
/// mauls the (XOR-layered) response bits cannot forge a matching tag — the
/// client rejects the tampered response instead of accepting attacker-chosen
/// bytes. This gives the return path the same integrity the forward Sphinx
/// payload has (a tamper is dropped, not delivered).
fn return_mac(exit_secret: &[u8; 32], body: &[u8]) -> [u8; RETURN_MAC_LEN] {
    let key = blake3::derive_key("neo-stream-return-mac-v1", exit_secret);
    let full = blake3::keyed_hash(&key, body);
    let mut out = [0u8; RETURN_MAC_LEN];
    out.copy_from_slice(&full.as_bytes()[..RETURN_MAC_LEN]);
    out
}

/// Constant-time equality for the return MAC.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// XOR `data` with a keystream derived from `key` (one layer, one cell).
fn xor_layer(data: &mut [u8], key: &[u8; 32]) {
    let mut ks = vec![0u8; data.len()];
    blake3::Hasher::new_keyed(key).finalize_xof().fill(&mut ks);
    for (b, k) in data.iter_mut().zip(&ks) {
        *b ^= k;
    }
}

/// Client: send `request` to the exit through `circuit` and return the exit's
/// response, received back through the same circuit (layers peeled).
pub async fn request_response(
    identity: &NodeIdentity,
    circuit: &[Hop],
    request: &[u8],
) -> Result<Vec<u8>> {
    if circuit.is_empty() {
        return Err(Error::Config("a circuit needs at least one hop".into()));
    }
    let hops: Vec<neo_crypto::SphinxHop> = circuit
        .iter()
        .map(|h| neo_crypto::SphinxHop {
            id: *h.id.as_bytes(),
            public: h.sphinx,
        })
        .collect();
    let (packet, secrets) = create_packet_keyed(&hops, request)?;

    let (mut stream, mut result) = connect(&circuit[0].addr, identity).await?;
    let framed = result.session.seal(&packet.to_bytes())?;
    write_frame(&mut stream, &framed).await?;

    // Read the layered response and peel every hop's layer, in path order.
    let sealed = read_frame(&mut stream).await?;
    let mut framed = result.session.open(&sealed)?;
    for secret in &secrets {
        xor_layer(&mut framed, &stream_key(secret));
    }
    // The exit prepended an integrity tag over the response; verify it so a
    // middle relay cannot maul the response undetectably.
    if framed.len() < RETURN_MAC_LEN {
        return Err(Error::Decode("return frame too short".into()));
    }
    let (mac, body) = framed.split_at(RETURN_MAC_LEN);
    let exit_secret = secrets.last().expect("non-empty circuit");
    if !ct_eq(mac, &return_mac(exit_secret, body)) {
        return Err(Error::Crypto(
            "return payload failed integrity check".into(),
        ));
    }
    Ok(body.to_vec())
}

/// What an exit does with a delivered request to produce a response. The default
/// echoes; a real clearnet exit (M7 policy) would perform the request.
pub type ExitHandler = fn(&[u8]) -> Vec<u8>;

/// Echo exit handler (for demos/tests).
pub fn echo_exit(request: &[u8]) -> Vec<u8> {
    request.to_vec()
}

/// Relay/exit: handle one circuit connection with a return path. Reads the
/// Sphinx frame from `prev`, and either forwards to the next hop and relays the
/// response back (adding this hop's layer) or, at the exit, runs `exit` and
/// sends the layered response back.
pub async fn handle_circuit<S, R>(
    identity: &NodeIdentity,
    prev: &mut S,
    prev_session: &mut Session,
    resolver: &R,
    replay: &Mutex<ReplayCache>,
    exit: ExitHandler,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: NextHop,
{
    let sealed = read_frame(prev).await?;
    let packet_bytes = prev_session.open(&sealed)?;
    let packet = SphinxPacket::from_bytes(&packet_bytes)?;

    // Derive this hop's return-path key from the same shared secret Sphinx uses.
    let secret = identity.sphinx_shared(packet.alpha())?;
    let key = stream_key(&secret);

    let processed = {
        let mut cache = replay.lock().expect("replay cache poisoned");
        process(identity, &mut cache, &packet)?
    };

    let mut response = match processed {
        Processed::Deliver { payload } => {
            // We are the exit: produce the response and prepend an integrity tag
            // (keyed by our shared secret) that only the client can verify.
            let body = exit(&payload);
            let mac = return_mac(&secret, &body);
            let mut framed = Vec::with_capacity(RETURN_MAC_LEN + body.len());
            framed.extend_from_slice(&mac);
            framed.extend_from_slice(&body);
            framed
        }
        Processed::Forward { next, packet } => {
            // Forward to the next hop and read its (layered) response.
            let next_id = NodeId::from_bytes(next);
            let addr = resolver
                .addr_of(&next_id)
                .ok_or_else(|| Error::Config(format!("no address for next hop {next_id}")))?;
            let (mut next_stream, mut next_result) = connect(&addr, identity).await?;
            let framed = next_result.session.seal(&packet.to_bytes())?;
            write_frame(&mut next_stream, &framed).await?;
            let sealed = read_frame(&mut next_stream).await?;
            next_result.session.open(&sealed)?
        }
    };

    // Add this hop's return layer and send it back toward the client.
    xor_layer(&mut response, &key);
    let out = prev_session.seal(&response)?;
    write_frame(prev, &out).await?;
    Ok(())
}

/// A relay's next-hop address book (same shape used by [`crate::forward`]).
pub type Resolver = HashMap<NodeId, String>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::accept;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    fn hop_of(identity: &NodeIdentity, addr: &str) -> Hop {
        let p = identity.public();
        Hop {
            id: p.id,
            sphinx: p.sphinx,
            addr: addr.to_string(),
        }
    }

    /// Spawn a relay/exit that handles one circuit connection.
    async fn spawn_hop(
        identity_bytes: Vec<u8>,
        resolver: Resolver,
    ) -> (String, JoinHandle<Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&identity_bytes).unwrap();
            let (mut stream, mut result) = accept(&listener, &identity).await.unwrap();
            let replay = Mutex::new(ReplayCache::new());
            handle_circuit(
                &identity,
                &mut stream,
                &mut result.session,
                &resolver,
                &replay,
                echo_exit,
            )
            .await
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn two_hop_round_trip_returns_the_response() {
        // client → relay → exit(echo). The response returns through the relay.
        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();

        let (exit_addr, exit_task) = spawn_hop(exit.to_bytes(), Resolver::new()).await;
        let mut resolver = Resolver::new();
        resolver.insert(exit.id(), exit_addr.clone());
        let (relay_addr, relay_task) = spawn_hop(relay.to_bytes(), resolver).await;

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];
        let request = b"ping through the circuit";
        let response = request_response(&client, &circuit, request).await.unwrap();
        assert_eq!(response, request, "echo response returns intact");

        relay_task.await.unwrap().unwrap();
        exit_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn single_hop_round_trip() {
        let exit = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();
        let (exit_addr, exit_task) = spawn_hop(exit.to_bytes(), Resolver::new()).await;
        let circuit = vec![hop_of(&exit, &exit_addr)];
        let response = request_response(&client, &circuit, b"hi").await.unwrap();
        assert_eq!(response, b"hi");
        exit_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_middle_relay_cannot_read_the_response() {
        // Capture what the middle relay writes back toward the client and show it
        // is NOT the plaintext response (it still carries the exit's layer).
        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();

        let (exit_addr, exit_task) = spawn_hop(exit.to_bytes(), Resolver::new()).await;
        let mut resolver = Resolver::new();
        resolver.insert(exit.id(), exit_addr.clone());

        // Run the middle relay inline, capturing the response it produces before
        // it seals it to the client — i.e. after adding only its own layer.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap().to_string();
        let relay_bytes = relay.to_bytes();
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = captured.clone();
        let relay_task = tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&relay_bytes).unwrap();
            let (mut stream, mut result) = accept(&listener, &identity).await.unwrap();
            let sealed = read_frame(&mut stream).await.unwrap();
            let packet_bytes = result.session.open(&sealed).unwrap();
            let packet = SphinxPacket::from_bytes(&packet_bytes).unwrap();
            let secret = identity.sphinx_shared(packet.alpha()).unwrap();
            let mut cache = ReplayCache::new();
            let Processed::Forward { next, packet } =
                process(&identity, &mut cache, &packet).unwrap()
            else {
                panic!("relay should forward");
            };
            let addr = resolver.get(&NodeId::from_bytes(next)).unwrap().clone();
            let (mut ns, mut nr) = connect(&addr, &identity).await.unwrap();
            let f = nr.session.seal(&packet.to_bytes()).unwrap();
            write_frame(&mut ns, &f).await.unwrap();
            let s = read_frame(&mut ns).await.unwrap();
            let downstream = nr.session.open(&s).unwrap();
            // This is the response as the relay sees it (exit's layer still on).
            *cap.lock().unwrap() = downstream.clone();
            let mut resp = downstream;
            xor_layer(&mut resp, &stream_key(&secret));
            let out = result.session.seal(&resp).unwrap();
            write_frame(&mut stream, &out).await.unwrap();
        });

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];
        let request = b"secret-response-please";
        let response = request_response(&client, &circuit, request).await.unwrap();
        assert_eq!(response, request);

        relay_task.await.unwrap();
        exit_task.await.unwrap().unwrap();
        // What the middle relay saw was NOT the plaintext response.
        assert_ne!(
            captured.lock().unwrap().as_slice(),
            request,
            "the middle relay must not see the plaintext response"
        );
    }

    #[tokio::test]
    async fn a_mauled_response_is_rejected_by_the_client() {
        // A malicious middle relay flips a response byte; the client's end-to-end
        // return MAC (keyed by the exit) must reject it, not deliver mangled data.
        let exit = NodeIdentity::generate().unwrap();
        let relay = NodeIdentity::generate().unwrap();
        let client = NodeIdentity::generate().unwrap();

        let (exit_addr, exit_task) = spawn_hop(exit.to_bytes(), Resolver::new()).await;
        let mut resolver = Resolver::new();
        resolver.insert(exit.id(), exit_addr.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap().to_string();
        let relay_bytes = relay.to_bytes();
        let relay_task = tokio::spawn(async move {
            let identity = NodeIdentity::from_bytes(&relay_bytes).unwrap();
            let (mut stream, mut result) = accept(&listener, &identity).await.unwrap();
            let sealed = read_frame(&mut stream).await.unwrap();
            let packet = SphinxPacket::from_bytes(&result.session.open(&sealed).unwrap()).unwrap();
            let secret = identity.sphinx_shared(packet.alpha()).unwrap();
            let mut cache = ReplayCache::new();
            let Processed::Forward { next, packet } =
                process(&identity, &mut cache, &packet).unwrap()
            else {
                panic!("relay should forward");
            };
            let addr = resolver.get(&NodeId::from_bytes(next)).unwrap().clone();
            let (mut ns, mut nr) = connect(&addr, &identity).await.unwrap();
            write_frame(&mut ns, &nr.session.seal(&packet.to_bytes()).unwrap())
                .await
                .unwrap();
            let mut resp = nr
                .session
                .open(&read_frame(&mut ns).await.unwrap())
                .unwrap();
            resp[RETURN_MAC_LEN + 1] ^= 0xff; // maul a response body byte
            xor_layer(&mut resp, &stream_key(&secret));
            write_frame(&mut stream, &result.session.seal(&resp).unwrap())
                .await
                .unwrap();
        });

        let circuit = vec![hop_of(&relay, &relay_addr), hop_of(&exit, &exit_addr)];
        let outcome = request_response(&client, &circuit, b"give me an honest answer").await;
        assert!(outcome.is_err(), "a tampered response must be rejected");

        relay_task.await.unwrap();
        exit_task.await.unwrap().unwrap();
    }
}
