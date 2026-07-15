//! **The networked two-party TLS 1.3 key-agreement driver** — the whole 2PC core of the
//! handshake, orchestrated over a [`Channel`](super::channel::Channel) between two separate
//! parties, each holding only its own share.
//!
//! [`schedule`](super::schedule)'s [`KeySchedule`](super::schedule::KeySchedule) runs the
//! RFC 8446 §7.1 ladder with both parties modelled *in-process*. This module runs the same
//! ladder as **two networked parties**: party A (garbler) and party B (evaluator) each hold
//! a scalar share of the client ephemeral key and a share of every derived secret, and every
//! secret-dependent step goes over the wire via the constant-round garbled online
//! ([`netengine::masked_eval`](super::super::netengine::masked_eval)) — no party ever
//! assembles the ECDHE secret, a traffic key, or a Finished MAC key.
//!
//! The full path is networked end-to-end:
//! 1. **ECDHE conversion** — each party forms its point-share `P_i = x_i·Y`, then
//!    [`ectf_a`/`ectf_b`](super::super::ectf) (Gilboa MtA over networked KOS-COT) give
//!    additive x-coordinate shares, and [`a2b_shared_net`](super::super::convert::a2b_shared_net)
//!    converts those to XOR bit-shares — all over `ch`.
//! 2. **Key schedule** — Handshake Secret, both handshake-traffic secrets, their keys/IVs,
//!    both Finished MACs, the Master Secret and both application-traffic secrets, each a
//!    networked HKDF/HMAC gadget ([`hkdf`](super::super::hkdf)'s `*_net` functions).
//!
//! # Honest boundary
//! - **Semi-honest** (the constant-round garbled online is [`garble_net`](super::super::garble_net);
//!   a malicious garbler is authenticated garbling — networking *that* constant-round is a
//!   further step, as in [`netengine`](super::super::netengine)).
//! - **Validated over TCP against the stock RFC 8446 schedule**: the two parties, given only
//!   their scalar shares and a real P-256 server key share, reproduce the vetted
//!   `hkdf`/`hmac`/`sha2` key schedule at every node (see the tests). The record-layer AEAD
//!   over the network (encrypting live TLS records against a server) is the remaining
//!   integration on top of this key agreement.

use neo_core::{Error, Result};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, PublicKey, Scalar};

use super::super::convert::a2b_shared_net;
use super::super::ectf::{ectf_a, ectf_b};
use super::super::hkdf::{
    expand_label_prepared_net, hkdf_extract_shared_net, hmac_prepared_net, prepare_key_net,
    PreparedKey,
};
use super::super::netengine::Party;
use super::super::sha256::sha256;
use super::channel::Channel;
use super::ecdhe::P256_PRIME_BE;
use super::schedule::derived_early;

fn reverse32(x: &[u8; 32]) -> [u8; 32] {
    let mut o = *x;
    o.reverse();
    o
}

/// This party's affine point-share coordinates `(x, y)` of `P_i = x_i·Y`, big-endian.
fn point_coords(p: &ProjectivePoint) -> ([u8; 32], [u8; 32]) {
    let enc = p.to_affine().to_encoded_point(false);
    let x = <[u8; 32]>::try_from(enc.x().expect("affine x").as_slice()).expect("32-byte x");
    let y = <[u8; 32]>::try_from(enc.y().expect("affine y").as_slice()).expect("32-byte y");
    (x, y)
}

/// **Networked ECDHE conversion.** Given this party's ephemeral scalar share `x_i` and the
/// server's SEC1 `key_share` `Y`, run ECtF + A2B over `ch` and return this party's **XOR
/// bit-share** of the ECDHE shared secret `x((x_A + x_B)·Y)` (big-endian). Neither party
/// learns the shared secret. Party A drives `ectf_a` / the A2B garbler side; party B the
/// mirror.
pub fn derive_ecdhe_share_net(
    ch: &mut dyn Channel,
    party: Party,
    x_scalar: &Scalar,
    server_key_share: &[u8],
) -> Result<[u8; 32]> {
    let y = PublicKey::from_sec1_bytes(server_key_share)
        .map_err(|_| Error::Crypto("netschedule: invalid server key_share (not on P-256)".into()))?
        .to_projective();
    let (px, py) = point_coords(&(y * *x_scalar)); // P_i = x_i·Y

    // ECtF → additive x-coordinate share (big-endian).
    let s_be = match party {
        Party::A => ectf_a(ch, (&px, &py), &P256_PRIME_BE)?,
        Party::B => ectf_b(ch, (&px, &py), &P256_PRIME_BE)?,
    };
    // A2B works little-endian; reverse the share + prime, convert, reverse back to big-endian.
    let xor_le = a2b_shared_net(ch, party, &reverse32(&s_be), &reverse32(&P256_PRIME_BE))?;
    Ok(reverse32(&xor_le))
}

/// The running TLS 1.3 key schedule for `TLS_CHACHA20_POLY1305_SHA256`, holding **this
/// party's** XOR-share of each current-epoch secret. The networked mirror of
/// [`KeySchedule`](super::schedule::KeySchedule): every method that touches a secret runs a
/// 2PC gadget over `ch`, and both parties must invoke the same methods in the same order so
/// the channel stays in lockstep.
pub struct KeyScheduleNet {
    party: Party,
    /// The prepared Handshake Secret (ipad/opad states precomputed once) — reused for the
    /// c/s hs traffic secrets AND the app-epoch "derived" step, so it's prepared just once.
    hs_prepared: PreparedKey,
    client_hs: [u8; 32],
    server_hs: [u8; 32],
    master: Option<[u8; 32]>,
    client_ap: Option<[u8; 32]>,
    server_ap: Option<[u8; 32]>,
}

impl KeyScheduleNet {
    /// From this party's ECDHE XOR-share and the public `ClientHello ‖ ServerHello`
    /// transcript, derive shares of the Handshake Secret and both handshake-traffic secrets.
    pub fn derive_handshake(
        ch: &mut dyn Channel,
        party: Party,
        ecdhe_share: &[u8; 32],
        transcript_ch_sh: &[u8],
    ) -> Result<Self> {
        let salt = derived_early(); // public constant
        let handshake_secret = hkdf_extract_shared_net(ch, party, &salt, ecdhe_share)?;
        // handshake_secret keys 3 derivations (c/s hs traffic here + "derived" in the app
        // epoch) — prepare its ipad/opad states once and reuse.
        let pk_hs = prepare_key_net(ch, party, &handshake_secret)?;
        let client_hs = derive_secret(ch, party, &pk_hs, b"c hs traffic", transcript_ch_sh)?;
        let server_hs = derive_secret(ch, party, &pk_hs, b"s hs traffic", transcript_ch_sh)?;
        Ok(KeyScheduleNet {
            party,
            hs_prepared: pk_hs,
            client_hs,
            server_hs,
            master: None,
            client_ap: None,
            server_ap: None,
        })
    }

    /// This party's share of the client handshake-traffic secret.
    pub fn client_handshake_secret_share(&self) -> [u8; 32] {
        self.client_hs
    }
    /// This party's share of the server handshake-traffic secret.
    pub fn server_handshake_secret_share(&self) -> [u8; 32] {
        self.server_hs
    }

    /// **Open both handshake-traffic secrets to cleartext** on both members (returns
    /// `(client_hs, server_hs)`). Safe: in TLS 1.3 the server flight (Certificate,
    /// CertificateVerify, both Finished MACs) is public/authenticated, and these two secrets
    /// are *siblings* of the still-shared `handshake_secret` — HMAC-SHA256 is one-way, so
    /// revealing them leaks nothing about `handshake_secret`, hence nothing about the Master
    /// Secret or any application key (which stay XOR-shared, derived on the untouched app
    /// branch). This lets the cert flight + Finished + client Finished run **in the clear**,
    /// removing the certificate-flight 2PC — the dominant handshake cost — while the
    /// application epoch stays under 2PC. **Never** open `handshake_secret` itself: that would
    /// expose the application branch.
    pub fn open_handshake_secrets(&self, ch: &mut dyn Channel) -> Result<([u8; 32], [u8; 32])> {
        let client_hs = open_secret(ch, &self.client_hs)?;
        let server_hs = open_secret(ch, &self.server_hs)?;
        Ok((client_hs, server_hs))
    }

    /// This party's shares of the client handshake `(key, iv)` (the IV is 12 bytes; both are
    /// XOR-shares — the record layer opens the IV and keeps the key shared).
    pub fn client_handshake_keys_share(
        &self,
        ch: &mut dyn Channel,
    ) -> Result<([u8; 32], [u8; 32])> {
        traffic_keys(ch, self.party, &self.client_hs)
    }
    /// This party's shares of the server handshake `(key, iv)`.
    pub fn server_handshake_keys_share(
        &self,
        ch: &mut dyn Channel,
    ) -> Result<([u8; 32], [u8; 32])> {
        traffic_keys(ch, self.party, &self.server_hs)
    }

    /// This party's share of the server's Finished MAC over `transcript_hash`
    /// (`Hash(CH..CertVerify)`); combine both parties' shares to compare to the wire value.
    pub fn server_finished_share(
        &self,
        ch: &mut dyn Channel,
        transcript_hash: &[u8; 32],
    ) -> Result<[u8; 32]> {
        finished_mac(ch, self.party, &self.server_hs, transcript_hash)
    }
    /// This party's share of the client's Finished MAC over `transcript_hash`
    /// (`Hash(CH..server Finished)`); combined and placed on the wire.
    pub fn client_finished_share(
        &self,
        ch: &mut dyn Channel,
        transcript_hash: &[u8; 32],
    ) -> Result<[u8; 32]> {
        finished_mac(ch, self.party, &self.client_hs, transcript_hash)
    }

    /// Advance to the application epoch: Master Secret then both application-traffic secrets
    /// over the full `CH..server Finished` transcript, all under 2PC over `ch`.
    pub fn derive_application(
        &mut self,
        ch: &mut dyn Channel,
        transcript_ch_sfin: &[u8],
    ) -> Result<()> {
        // Reuse the Handshake Secret prepared in derive_handshake (no second prepare).
        let derived = derive_secret(ch, self.party, &self.hs_prepared, b"derived", b"")?;
        // Master Secret = HKDF-Extract(salt=derived(shared), IKM=0) = HMAC(derived, 0^32).
        let pk_derived = prepare_key_net(ch, self.party, &derived)?;
        let master = hmac_prepared_net(ch, self.party, &pk_derived, &[0u8; 32])?;
        // master keys both application-traffic secrets — prepare once.
        let pk_master = prepare_key_net(ch, self.party, &master)?;
        self.client_ap = Some(derive_secret(
            ch,
            self.party,
            &pk_master,
            b"c ap traffic",
            transcript_ch_sfin,
        )?);
        self.server_ap = Some(derive_secret(
            ch,
            self.party,
            &pk_master,
            b"s ap traffic",
            transcript_ch_sfin,
        )?);
        self.master = Some(master);
        Ok(())
    }

    /// This party's share of the client application-traffic secret.
    pub fn client_application_secret_share(&self) -> [u8; 32] {
        self.client_ap.expect("derive_application first")
    }
    /// This party's share of the server application-traffic secret.
    pub fn server_application_secret_share(&self) -> [u8; 32] {
        self.server_ap.expect("derive_application first")
    }
    /// This party's shares of the client application `(key, iv)`.
    pub fn client_application_keys_share(
        &self,
        ch: &mut dyn Channel,
    ) -> Result<([u8; 32], [u8; 32])> {
        traffic_keys(
            ch,
            self.party,
            &self.client_ap.expect("derive_application first"),
        )
    }
    /// This party's shares of the server application `(key, iv)`.
    pub fn server_application_keys_share(
        &self,
        ch: &mut dyn Channel,
    ) -> Result<([u8; 32], [u8; 32])> {
        traffic_keys(
            ch,
            self.party,
            &self.server_ap.expect("derive_application first"),
        )
    }

    /// **KeyUpdate** (RFC 8446 §7.2) on the client write path: advance this party's client
    /// application-traffic secret share one generation via `"traffic upd"`, over `ch`.
    pub fn update_client_application(&mut self, ch: &mut dyn Channel) -> Result<()> {
        let pk = prepare_key_net(
            ch,
            self.party,
            &self.client_ap.expect("derive_application first"),
        )?;
        let next = expand_label_prepared_net(ch, self.party, &pk, b"traffic upd", b"", 32)?;
        self.client_ap = Some(next);
        Ok(())
    }
}

/// Exchange + XOR a 32-byte secret share with the peer member → the reconstructed secret.
fn open_secret(ch: &mut dyn Channel, share: &[u8; 32]) -> Result<[u8; 32]> {
    ch.send(share)?;
    let peer = ch.recv_exact(32)?;
    Ok(core::array::from_fn(|i| share[i] ^ peer[i]))
}

/// `Derive-Secret(secret, label, messages)` under 2PC over `ch`, from a **prepared** key
/// (its ipad/opad states precomputed once): HKDF-Expand-Label with the public transcript
/// hash as context. Returns this party's share.
fn derive_secret(
    ch: &mut dyn Channel,
    party: Party,
    prepared: &PreparedKey,
    label: &[u8],
    transcript: &[u8],
) -> Result<[u8; 32]> {
    let th = sha256(transcript);
    expand_label_prepared_net(ch, party, prepared, label, &th, 32)
}

/// `(key, iv)` shares from a traffic-secret share: prepare the key once, then
/// `HKDF-Expand-Label(secret, "key"/"iv")`. Both under 2PC over `ch`.
fn traffic_keys(
    ch: &mut dyn Channel,
    party: Party,
    secret_share: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    let pk = prepare_key_net(ch, party, secret_share)?;
    let key = expand_label_prepared_net(ch, party, &pk, b"key", b"", 32)?;
    let iv = expand_label_prepared_net(ch, party, &pk, b"iv", b"", 12)?;
    Ok((key, iv))
}

/// The Finished MAC key `HKDF-Expand-Label(secret, "finished", "", 32)` (shared), then
/// `HMAC(finished_key, transcript_hash)` under 2PC over `ch` — both via prepared keys.
/// Returns this party's share of the MAC (combine both to open).
fn finished_mac(
    ch: &mut dyn Channel,
    party: Party,
    secret_share: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let pk = prepare_key_net(ch, party, secret_share)?;
    let fk = expand_label_prepared_net(ch, party, &pk, b"finished", b"", 32)?;
    let pk_fk = prepare_key_net(ch, party, &fk)?;
    hmac_prepared_net(ch, party, &pk_fk, transcript_hash)
}

/// **The networked handshake key-agreement driver.** Runs the ECDHE conversion and the
/// handshake-epoch key schedule over `ch`, returning this party's [`KeyScheduleNet`]. Both
/// parties call this with their own scalar share; the returned schedule then drives the rest
/// of the handshake (Finished, application epoch) with matching method calls on both sides.
pub fn client_key_agreement_net(
    ch: &mut dyn Channel,
    party: Party,
    x_scalar: &Scalar,
    server_key_share: &[u8],
    transcript_ch_sh: &[u8],
) -> Result<KeyScheduleNet> {
    let ecdhe_share = derive_ecdhe_share_net(ch, party, x_scalar, server_key_share)?;
    KeyScheduleNet::derive_handshake(ch, party, &ecdhe_share, transcript_ch_sh)
}

#[cfg(test)]
mod tests {
    use super::super::super::hkdf::hkdf_label;
    use super::super::channel::TcpChannel;
    use super::*;
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::{Digest, Sha256};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    type HmacSha256 = Hmac<Sha256>;

    // ---- stock RFC 8446 §7.1 reference (independent oracle) ------------------------
    fn ref_expand_label(secret: &[u8; 32], label: &[u8], ctx: &[u8], len: u16) -> Vec<u8> {
        let info = hkdf_label(label, ctx, len);
        let hk = Hkdf::<Sha256>::from_prk(secret).unwrap();
        let mut okm = vec![0u8; len as usize];
        hk.expand(&info, &mut okm).unwrap();
        okm
    }
    fn ref_derive_secret(secret: &[u8; 32], label: &[u8], transcript: &[u8]) -> [u8; 32] {
        let th = Sha256::digest(transcript);
        ref_expand_label(secret, label, &th, 32).try_into().unwrap()
    }
    fn ref_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        Hkdf::<Sha256>::extract(Some(salt), ikm).0.into()
    }
    fn ref_finished(secret: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
        let fk = ref_expand_label(secret, b"finished", b"", 32);
        let mut mac = HmacSha256::new_from_slice(&fk).unwrap();
        mac.update(&Sha256::digest(transcript));
        mac.finalize().into_bytes().into()
    }

    fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        core::array::from_fn(|i| a[i] ^ b[i])
    }

    /// Everything one party derives, collected so the two threads' shares can be combined
    /// and checked against the stock reference.
    struct Shares {
        ecdhe: [u8; 32],
        client_hs: [u8; 32],
        server_hs: [u8; 32],
        client_hs_key: [u8; 32],
        client_hs_iv: [u8; 32],
        server_finished: [u8; 32],
        client_ap: [u8; 32],
        server_ap: [u8; 32],
        server_ap_key: [u8; 32],
    }

    /// One party's full networked run: ECDHE conversion + the whole handshake+application
    /// schedule, in the exact order both parties must share.
    fn run_party(
        ch: &mut dyn Channel,
        party: Party,
        x: &Scalar,
        y_sec1: &[u8],
        ch_sh: &[u8],
        ch_sfin: &[u8],
        cv_transcript: &[u8],
    ) -> Shares {
        let ecdhe = derive_ecdhe_share_net(ch, party, x, y_sec1).unwrap();
        let mut ks = KeyScheduleNet::derive_handshake(ch, party, &ecdhe, ch_sh).unwrap();
        let client_hs = ks.client_handshake_secret_share();
        let server_hs = ks.server_handshake_secret_share();
        let (client_hs_key, client_hs_iv) = ks.client_handshake_keys_share(ch).unwrap();
        let server_finished = ks
            .server_finished_share(ch, &Sha256::digest(cv_transcript).into())
            .unwrap();
        ks.derive_application(ch, ch_sfin).unwrap();
        let client_ap = ks.client_application_secret_share();
        let server_ap = ks.server_application_secret_share();
        let (server_ap_key, _iv) = ks.server_application_keys_share(ch).unwrap();
        Shares {
            ecdhe,
            client_hs,
            server_hs,
            client_hs_key,
            client_hs_iv,
            server_finished,
            client_ap,
            server_ap,
            server_ap_key,
        }
    }

    #[test]
    fn networked_key_schedule_matches_stock_over_tcp() {
        // Two parties, each holding only its own ephemeral scalar share, run the entire 2PC
        // key agreement over a real TCP socket — ECDHE (ECtF+A2B) then the full TLS 1.3 key
        // schedule — and their combined shares reproduce the stock RFC 8446 schedule derived
        // from the true P-256 ECDHE secret. This is the handshake's 2PC core, networked.
        let x1 = Scalar::from(0x1234_5678u64);
        let x2 = Scalar::from(0x0f0f_a5a5u64);
        let server_secret = Scalar::from(0x9e37_79b9u64);
        let y = ProjectivePoint::GENERATOR * server_secret;
        let y_sec1 = y.to_affine().to_encoded_point(false).as_bytes().to_vec();

        // Ground-truth ECDHE secret = x((x1+x2)·Y), big-endian.
        let z = (y * (x1 + x2)).to_affine();
        let zx = <[u8; 32]>::try_from(z.to_encoded_point(false).x().unwrap().as_slice()).unwrap();

        let ch_sh = b"<ClientHello||ServerHello public bytes>".to_vec();
        let ch_sfin = b"<ClientHello .. server Finished public bytes>".to_vec();
        let cv = b"<CH..CertVerify>".to_vec();

        // Party A (garbler) on its own thread; party B (evaluator) here.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (ys_a, sh_a, sf_a, cv_a) = (y_sec1.clone(), ch_sh.clone(), ch_sfin.clone(), cv.clone());
        let a = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut ch = TcpChannel::from_stream(sock);
            run_party(&mut ch, Party::A, &x1, &ys_a, &sh_a, &sf_a, &cv_a)
        });
        let mut ch = TcpChannel::from_stream(TcpStream::connect(addr).unwrap());
        let sb = run_party(&mut ch, Party::B, &x2, &y_sec1, &ch_sh, &ch_sfin, &cv);
        let sa = a.join().unwrap();

        // ECDHE share reconstruction == the real P-256 shared-secret x-coordinate.
        assert_eq!(
            xor32(&sa.ecdhe, &sb.ecdhe),
            zx,
            "networked ECDHE == p256 x(Z)"
        );

        // Reference schedule from the true secret.
        let derived0 = super::super::schedule::derived_early();
        let hs = ref_extract(&derived0, &zx);
        let chs = ref_derive_secret(&hs, b"c hs traffic", &ch_sh);
        let shs = ref_derive_secret(&hs, b"s hs traffic", &ch_sh);
        let master = ref_extract(&ref_derive_secret(&hs, b"derived", b""), &[0u8; 32]);
        let cap = ref_derive_secret(&master, b"c ap traffic", &ch_sfin);
        let sap = ref_derive_secret(&master, b"s ap traffic", &ch_sfin);

        assert_eq!(xor32(&sa.client_hs, &sb.client_hs), chs, "client_hs_secret");
        assert_eq!(xor32(&sa.server_hs, &sb.server_hs), shs, "server_hs_secret");
        assert_eq!(
            xor32(&sa.client_hs_key, &sb.client_hs_key).to_vec(),
            ref_expand_label(&chs, b"key", b"", 32),
            "client hs key"
        );
        assert_eq!(
            xor32(&sa.client_hs_iv, &sb.client_hs_iv)[..12].to_vec(),
            ref_expand_label(&chs, b"iv", b"", 12),
            "client hs iv"
        );
        assert_eq!(
            xor32(&sa.server_finished, &sb.server_finished),
            ref_finished(&shs, &cv),
            "server Finished MAC"
        );
        assert_eq!(xor32(&sa.client_ap, &sb.client_ap), cap, "client_ap_secret");
        assert_eq!(xor32(&sa.server_ap, &sb.server_ap), sap, "server_ap_secret");
        assert_eq!(
            xor32(&sa.server_ap_key, &sb.server_ap_key).to_vec(),
            ref_expand_label(&sap, b"key", b"", 32),
            "server ap key"
        );
    }
}
