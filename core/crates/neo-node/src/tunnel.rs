//! The encrypted tunnel data plane (M1 data plane + M5 mixing).
//!
//! [`bridge_packet_io`] adapts a TUN device (or any [`PacketIo`]) to a pair of
//! packet channels. [`run_tunnel`] carries those packets to a peer: outbound
//! packets go through the [`Mixer`] (timing delay + cover traffic), are packed
//! into a **fixed-size cell** and sealed with the session, and become wire frames;
//! inbound frames are opened, cover is dropped, and real packets are delivered.
//!
//! Every cell — real or cover — is padded to exactly `CELL_HEADER + CELL_PAYLOAD`
//! bytes before sealing, so a passive observer sees a uniform stream of
//! identical-length frames: real and cover are indistinguishable by **length** as
//! well as by content (the mixer already handles inter-packet timing). The wire
//! frames are what the transport (`neo-transport`, or the M1 TCP link) carries.

use neo_core::{Error, Result};
use neo_crypto::Session;
use neo_dataplane::PacketIo;
use neo_mix::{MixOut, MixParams, Mixer, COVER_SIZE};
use tokio::sync::mpsc;

const TAG_REAL: u8 = 0;
const TAG_COVER: u8 = 1;

/// Fixed cell payload capacity. Every outbound cell (real or cover) is padded to
/// exactly this size before sealing, so a passive observer sees a uniform stream
/// of identical-length frames — real and cover are indistinguishable by length.
/// Sized to hold a full-MTU packet and to be at least `COVER_SIZE`.
const CELL_PAYLOAD: usize = if COVER_SIZE > 1500 { COVER_SIZE } else { 1500 };
/// Cell header: a 1-byte tag + a 2-byte real-payload length.
const CELL_HEADER: usize = 3;

/// Bridge a packet interface to channels: packets read from `io` go to `app_out`,
/// packets from `app_in` are written to `io`. Runs until either side closes.
pub async fn bridge_packet_io<T: PacketIo>(
    mut io: T,
    app_out: mpsc::Sender<Vec<u8>>,
    mut app_in: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    loop {
        tokio::select! {
            packet = io.recv() => {
                if app_out.send(packet?).await.is_err() {
                    break;
                }
            }
            inbound = app_in.recv() => {
                match inbound {
                    Some(packet) => io.send(&packet).await?,
                    None => break,
                }
            }
        }
    }
    Ok(())
}

/// Run the encrypted tunnel data plane for one peer session.
///
/// - `app_out`: local packets to send (from the TUN).
/// - `wire_out`: sealed frames to hand to the transport.
/// - `wire_in`: sealed frames received from the transport.
/// - `app_in`: recovered packets to write to the TUN.
pub async fn run_tunnel(
    session: Session,
    mix: MixParams,
    mut app_out: mpsc::Receiver<Vec<u8>>,
    wire_out: mpsc::Sender<Vec<u8>>,
    mut wire_in: mpsc::Receiver<Vec<u8>>,
    app_in: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let (mut sealer, mut opener) = session.split();

    // Outbound: app_out -> mixer -> seal(tagged) -> wire_out.
    let (mix_in_tx, mix_in_rx) = mpsc::channel::<Vec<u8>>(64);
    let (mix_out_tx, mut mix_out_rx) = mpsc::channel::<MixOut>(64);
    let mix_task = tokio::spawn(Mixer::new(mix).run(mix_in_rx, mix_out_tx));
    let feed_task = tokio::spawn(async move {
        while let Some(packet) = app_out.recv().await {
            if mix_in_tx.send(packet).await.is_err() {
                break;
            }
        }
    });

    let outbound = async {
        while let Some(item) = mix_out_rx.recv().await {
            // Every cell is a fixed size: [tag][u16 real-len][payload ‖ zero pad].
            // Real and cover cells are therefore byte-identical in length.
            let mut cell = vec![0u8; CELL_HEADER + CELL_PAYLOAD];
            match item {
                MixOut::Real(packet) => {
                    if packet.len() > CELL_PAYLOAD {
                        return Err(Error::Decode("packet exceeds tunnel cell size".into()));
                    }
                    cell[0] = TAG_REAL;
                    cell[1..3].copy_from_slice(&(packet.len() as u16).to_be_bytes());
                    cell[CELL_HEADER..CELL_HEADER + packet.len()].copy_from_slice(&packet);
                }
                MixOut::Cover(_) => {
                    cell[0] = TAG_COVER; // real-len stays 0, all pad
                }
            }
            let frame = sealer.seal(&cell)?;
            if wire_out.send(frame).await.is_err() {
                break;
            }
        }
        Ok::<(), Error>(())
    };

    let inbound = async {
        while let Some(frame) = wire_in.recv().await {
            let plain = opener.open(&frame)?;
            if plain.len() < CELL_HEADER {
                return Err(Error::Decode("short tunnel cell".into()));
            }
            match plain[0] {
                TAG_REAL => {
                    let len = u16::from_be_bytes([plain[1], plain[2]]) as usize;
                    if CELL_HEADER + len > plain.len() {
                        return Err(Error::Decode("bad tunnel cell length".into()));
                    }
                    let payload = plain[CELL_HEADER..CELL_HEADER + len].to_vec();
                    if app_in.send(payload).await.is_err() {
                        break;
                    }
                }
                TAG_COVER => {} // decoy traffic: drop
                _ => return Err(Error::Decode("unknown tunnel cell tag".into())),
            }
        }
        Ok::<(), Error>(())
    };

    let (out_res, in_res) = tokio::join!(outbound, inbound);
    feed_task.abort();
    mix_task.abort();
    out_res?;
    in_res?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo_core::{NodeIdentity, PrivacyLevel};
    use neo_crypto::{
        initiator_finish, initiator_message1, responder_confirm, responder_cookie,
        responder_process, CookieKey,
    };
    use std::time::Duration;

    #[tokio::test]
    async fn bridge_moves_packets_both_ways() {
        let (io, mut os) = neo_dataplane::memory_pair(8);
        let (app_out_tx, mut app_out_rx) = mpsc::channel(8);
        let (app_in_tx, app_in_rx) = mpsc::channel(8);
        let handle = tokio::spawn(bridge_packet_io(io, app_out_tx, app_in_rx));

        // A packet arriving from the "OS" side surfaces on app_out.
        os.send(b"outbound").await.unwrap();
        assert_eq!(app_out_rx.recv().await.unwrap(), b"outbound");
        // A packet pushed to app_in is written back to the "OS" side.
        app_in_tx.send(b"inbound".to_vec()).await.unwrap();
        assert_eq!(os.recv().await.unwrap(), b"inbound");

        drop(app_in_tx);
        drop(os);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn packets_tunnel_between_two_peers() {
        // Establish interoperating sessions via the handshake.
        let alice = NodeIdentity::generate().unwrap();
        let bob = NodeIdentity::generate().unwrap();
        let (state, init1) = initiator_message1(&alice).unwrap();
        let cookie_key = CookieKey::generate().unwrap();
        let challenge = responder_cookie(&cookie_key, &init1).unwrap();
        let init2 = state.with_cookie(&challenge);
        let (m2, pending) = responder_process(&bob, &init2, &cookie_key).unwrap();
        let (m3, alice_res) = initiator_finish(state, &m2).unwrap();
        let bob_res = responder_confirm(pending, &m3).unwrap();
        let mix = MixParams::for_level(PrivacyLevel::Off); // deterministic: no delay/cover

        let (a_app_out_tx, a_app_out_rx) = mpsc::channel(16);
        let (a_app_in_tx, _a_app_in_rx) = mpsc::channel(16);
        let (a_wire_out_tx, mut a_wire_out_rx) = mpsc::channel(16);
        let (a_wire_in_tx, a_wire_in_rx) = mpsc::channel(16);

        let (b_app_out_tx, b_app_out_rx) = mpsc::channel(16);
        let (b_app_in_tx, mut b_app_in_rx) = mpsc::channel(16);
        let (b_wire_out_tx, mut b_wire_out_rx) = mpsc::channel(16);
        let (b_wire_in_tx, b_wire_in_rx) = mpsc::channel(16);

        // Cross-wire the two tunnels' transports.
        tokio::spawn(async move {
            while let Some(frame) = a_wire_out_rx.recv().await {
                if b_wire_in_tx.send(frame).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(frame) = b_wire_out_rx.recv().await {
                if a_wire_in_tx.send(frame).await.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(run_tunnel(
            alice_res.session,
            mix,
            a_app_out_rx,
            a_wire_out_tx,
            a_wire_in_rx,
            a_app_in_tx,
        ));
        tokio::spawn(run_tunnel(
            bob_res.session,
            mix,
            b_app_out_rx,
            b_wire_out_tx,
            b_wire_in_rx,
            b_app_in_tx,
        ));
        let _ = (b_app_out_tx, a_app_out_tx.clone()); // keep senders alive

        a_app_out_tx
            .send(b"hello over the tunnel".to_vec())
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), b_app_in_rx.recv())
            .await
            .expect("tunnel delivered in time")
            .expect("a packet arrived");
        assert_eq!(got, b"hello over the tunnel");
    }
}
