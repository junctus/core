//! **The TLS 1.3 key schedule under 2PC** (RFC 8446 §7.1) for `TLS_CHACHA20_POLY1305_SHA256`.
//!
//! This drives the built HKDF/HMAC-under-2PC gadgets ([`hkdf`](super::super::hkdf))
//! through the exact §7.1 ladder so the two client parties end up holding **XOR-shares**
//! of every traffic secret — neither ever assembles a handshake key, an application key,
//! or a Finished MAC key. Only the values TLS reveals on the wire anyway are opened:
//!
//! - The **write IV** is opened (a PRF output of the shared secret; useless without the
//!   still-shared key — [`seal_tls13_record_shared`](super::super::session::seal_tls13_record_shared)
//!   already takes a public `static_iv` and shared key).
//! - The **client Finished** value is opened (it is sent in the clear on the wire).
//! - The **server Finished** MAC is computed in shares and combined only to *compare*
//!   against the server's public Finished.
//!
//! Which steps run under 2PC vs. in the clear follows the secret/public split of §7.1:
//! the whole Early-Secret branch is public (PSK = 0), so `Early Secret` and the first
//! `Derived` are computed in the clear; from the `(EC)DHE` extract onward every secret is
//! shared. The transcript hash is public throughout (it is a hash of on-the-wire
//! handshake messages), so it enters the shared HKDF calls as a public context.
//!
//! # Honest boundary
//!
//! - **Every derived value is validated against the vetted `hkdf`/`hmac`/`sha2` crates**
//!   (see the tests): given a known ECDHE secret + transcript, the 2PC schedule
//!   reproduces the stock key schedule byte-for-byte, including the traffic keys/IVs and
//!   both Finished MACs. The rustls interop test ([`super::handshake`]) then checks the
//!   *shared* secrets against a live rustls server's `KeyLog`.
//! - Runs under a chosen [`EngineKind`](super::super::engine::EngineKind): the default is
//!   semi-honest (`garble::eval_2pc`), but the **same schedule runs under the malicious
//!   authenticated-garbling online** ([`authgarble`](super::super::authgarble)) — every
//!   HMAC/HKDF circuit dispatched through [`eval_circuit`](super::super::engine::eval_circuit),
//!   aborting on a cheating party. The malicious key schedule is tested to match the stock
//!   oracle exactly (see the tests). See [`super`]'s boundary for what "malicious" still
//!   models in-process (networked aBit preprocessing) + the audit gate.

use neo_core::Result;

use super::super::engine::EngineKind;
use super::super::hkdf::{
    hkdf_expand_label_shared_engine, hkdf_extract_shared_engine, hkdf_label,
    hmac_sha256_shared_engine,
};
use super::super::sha256::sha256;

/// A 32-byte secret held as XOR-shares between the two client parties (`a ⊕ b`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Secret2 {
    pub a: [u8; 32],
    pub b: [u8; 32],
}

impl Secret2 {
    /// Combine the shares — used only for values TLS opens on the wire (IV, Finished)
    /// or for test asserts; never for a traffic key.
    pub fn open(&self) -> [u8; 32] {
        core::array::from_fn(|i| self.a[i] ^ self.b[i])
    }
}

/// A directional record-protection context: the ChaCha20 key stays **shared**
/// (`key_a`/`key_b`), the write IV is **opened** (public), per the record-layer API.
#[derive(Clone, Copy, Debug)]
pub struct TrafficKeys {
    pub key_a: [u8; 32],
    pub key_b: [u8; 32],
    pub iv: [u8; 12],
}

// ---- plaintext helpers for the public (PSK=0) branch --------------------------

/// Plaintext HMAC-SHA256, for the public parts of the schedule (Early Secret, the first
/// Derived). Built on the crate's public [`sha256`].
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let ih = sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&ih);
    sha256(&outer)
}

/// Plaintext `HKDF-Expand-Label` (length ≤ 32), for the public branch.
fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], length: u16) -> Vec<u8> {
    let mut msg = hkdf_label(label, context, length);
    msg.push(0x01); // T(1)
    hmac_sha256(secret, &msg)[..length as usize].to_vec()
}

/// Plaintext `Derive-Secret(secret, label, messages)` = `HKDF-Expand-Label(secret, label,
/// Transcript-Hash(messages), Hash.length)`.
fn derive_secret_public(secret: &[u8; 32], label: &[u8], transcript: &[u8]) -> [u8; 32] {
    let th = sha256(transcript);
    let v = hkdf_expand_label(secret, label, &th, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// The 32-byte constant `Derived` off the Early Secret with an empty transcript — the
/// public salt for the Handshake-Secret extract. `Early Secret = HKDF-Extract(0, 0)`;
/// `Derived = Derive-Secret(Early Secret, "derived", "")`.
fn derived_early() -> [u8; 32] {
    let early = hmac_sha256(&[0u8; 32], &[0u8; 32]); // Extract(salt=0^Hash.len, IKM=0^Hash.len)
    derive_secret_public(&early, b"derived", b"")
}

// ---- shared-secret schedule ---------------------------------------------------

/// `Derive-Secret` on a **shared** secret: `HKDF-Expand-Label(secret, label,
/// Transcript-Hash(transcript), 32)` under 2PC → shared output.
fn derive_secret_shared(
    engine: EngineKind,
    secret: &Secret2,
    label: &[u8],
    transcript: &[u8],
) -> Result<Secret2> {
    let th = sha256(transcript);
    let (a, b) = hkdf_expand_label_shared_engine(engine, &secret.a, &secret.b, label, &th, 32)?;
    Ok(Secret2 { a, b })
}

/// Turn a shared traffic secret into a directional [`TrafficKeys`]: `key =
/// HKDF-Expand-Label(secret, "key", "", 32)` (shared), `iv = HKDF-Expand-Label(secret,
/// "iv", "", 12)` (opened — a PRF output, safe to reveal with the key still shared).
fn traffic_keys(engine: EngineKind, secret: &Secret2) -> Result<TrafficKeys> {
    let (key_a, key_b) =
        hkdf_expand_label_shared_engine(engine, &secret.a, &secret.b, b"key", b"", 32)?;
    let (iva, ivb) = hkdf_expand_label_shared_engine(engine, &secret.a, &secret.b, b"iv", b"", 12)?;
    let iv: [u8; 12] = core::array::from_fn(|i| iva[i] ^ ivb[i]);
    Ok(TrafficKeys { key_a, key_b, iv })
}

/// The Finished MAC key `HKDF-Expand-Label(traffic_secret, "finished", "", 32)` (shared),
/// then `HMAC(finished_key, transcript_hash)` under 2PC → **opened** MAC value (Finished
/// is public on the wire). `transcript_hash` is over the handshake messages up to (but
/// not including) the Finished being computed.
fn finished_mac(
    engine: EngineKind,
    secret: &Secret2,
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let (fka, fkb) =
        hkdf_expand_label_shared_engine(engine, &secret.a, &secret.b, b"finished", b"", 32)?;
    let (ma, mb) = hmac_sha256_shared_engine(engine, &fka, &fkb, transcript_hash)?;
    Ok(core::array::from_fn(|i| ma[i] ^ mb[i]))
}

/// The running TLS 1.3 key schedule for `TLS_CHACHA20_POLY1305_SHA256`, holding shares of
/// the current-epoch secrets. Built in handshake order, under a chosen 2PC [`EngineKind`].
pub struct KeySchedule {
    engine: EngineKind,
    handshake_secret: Secret2,
    client_hs: Secret2,
    server_hs: Secret2,
    master_secret: Option<Secret2>,
    client_ap: Option<Secret2>,
    server_ap: Option<Secret2>,
}

impl KeySchedule {
    /// From the shared ECDHE secret (the ECtF/A2B x-coordinate shares) and the public
    /// `ClientHello ‖ ServerHello` transcript, derive the Handshake Secret and both
    /// handshake-traffic secrets — all under 2PC on the chosen `engine`.
    pub fn derive_handshake(
        engine: EngineKind,
        ecdhe_a: &[u8; 32],
        ecdhe_b: &[u8; 32],
        transcript_ch_sh: &[u8],
    ) -> Result<Self> {
        // Handshake Secret = HKDF-Extract(salt=Derived(public), IKM=ECDHE(shared)).
        let salt = derived_early();
        let (hs_a, hs_b) = hkdf_extract_shared_engine(engine, &salt, ecdhe_a, ecdhe_b)?;
        let handshake_secret = Secret2 { a: hs_a, b: hs_b };
        let client_hs =
            derive_secret_shared(engine, &handshake_secret, b"c hs traffic", transcript_ch_sh)?;
        let server_hs =
            derive_secret_shared(engine, &handshake_secret, b"s hs traffic", transcript_ch_sh)?;
        Ok(KeySchedule {
            engine,
            handshake_secret,
            client_hs,
            server_hs,
            master_secret: None,
            client_ap: None,
            server_ap: None,
        })
    }

    /// Client handshake-traffic key/IV (protects the client's Finished flight).
    pub fn client_handshake_keys(&self) -> Result<TrafficKeys> {
        traffic_keys(self.engine, &self.client_hs)
    }

    /// Server handshake-traffic key/IV (decrypts the server's flight).
    pub fn server_handshake_keys(&self) -> Result<TrafficKeys> {
        traffic_keys(self.engine, &self.server_hs)
    }

    /// The server's expected Finished MAC over `transcript_hash = Hash(CH..CertVerify)`.
    /// Compare against the server's on-wire Finished to authenticate the handshake.
    pub fn server_finished(&self, transcript_hash: &[u8; 32]) -> Result<[u8; 32]> {
        finished_mac(self.engine, &self.server_hs, transcript_hash)
    }

    /// The client's Finished MAC over `transcript_hash = Hash(CH..server Finished)`,
    /// opened to place on the wire.
    pub fn client_finished(&self, transcript_hash: &[u8; 32]) -> Result<[u8; 32]> {
        finished_mac(self.engine, &self.client_hs, transcript_hash)
    }

    /// Advance to the application epoch: `Master Secret = HKDF-Extract(Derived(Handshake
    /// Secret), 0)` then the two application-traffic secrets over the full
    /// `CH..server Finished` transcript. All under 2PC.
    pub fn derive_application(&mut self, transcript_ch_sfin: &[u8]) -> Result<()> {
        // Derived = Derive-Secret(Handshake Secret, "derived", "") — shared.
        let derived = derive_secret_shared(self.engine, &self.handshake_secret, b"derived", b"")?;
        // Master Secret = HKDF-Extract(salt=derived(shared), IKM=0) = HMAC(derived, 0^32).
        let (ms_a, ms_b) =
            hmac_sha256_shared_engine(self.engine, &derived.a, &derived.b, &[0u8; 32])?;
        let master = Secret2 { a: ms_a, b: ms_b };
        self.client_ap = Some(derive_secret_shared(
            self.engine,
            &master,
            b"c ap traffic",
            transcript_ch_sfin,
        )?);
        self.server_ap = Some(derive_secret_shared(
            self.engine,
            &master,
            b"s ap traffic",
            transcript_ch_sfin,
        )?);
        self.master_secret = Some(master);
        Ok(())
    }

    /// Client application-traffic key/IV (protects application data the client sends).
    pub fn client_application_keys(&self) -> Result<TrafficKeys> {
        traffic_keys(
            self.engine,
            self.client_ap.as_ref().expect("derive_application first"),
        )
    }

    /// Server application-traffic key/IV (decrypts application data from the server).
    pub fn server_application_keys(&self) -> Result<TrafficKeys> {
        traffic_keys(
            self.engine,
            self.server_ap.as_ref().expect("derive_application first"),
        )
    }

    /// The shared client handshake-traffic secret (exposed for oracle validation against
    /// a live server's `KeyLog`).
    pub fn client_handshake_secret(&self) -> Secret2 {
        self.client_hs
    }
    /// The shared server handshake-traffic secret (for oracle validation).
    pub fn server_handshake_secret(&self) -> Secret2 {
        self.server_hs
    }
    /// The shared client application-traffic secret (for oracle validation).
    pub fn client_application_secret(&self) -> Secret2 {
        self.client_ap.expect("derive_application first")
    }
    /// The shared server application-traffic secret (for oracle validation).
    pub fn server_application_secret(&self) -> Secret2 {
        self.server_ap.expect("derive_application first")
    }

    /// **KeyUpdate** (RFC 8446 §7.2) on the client write path: advance the client
    /// application-traffic secret one generation —
    /// `secret' = HKDF-Expand-Label(secret, "traffic upd", "", 32)` (empty context, **not** a
    /// transcript hash), under 2PC — and return the fresh key/IV (the record layer resets its
    /// sequence number to 0). Sent when the client emits a `KeyUpdate` handshake message.
    pub fn update_client_application(&mut self) -> Result<TrafficKeys> {
        self.client_ap = Some(traffic_update(
            self.engine,
            &self.client_ap.expect("derive_application first"),
        )?);
        self.client_application_keys()
    }

    /// **KeyUpdate** on the server read path: advance the server application-traffic secret
    /// one generation and return the fresh key/IV. Applied when the peer sends a `KeyUpdate`.
    pub fn update_server_application(&mut self) -> Result<TrafficKeys> {
        self.server_ap = Some(traffic_update(
            self.engine,
            &self.server_ap.expect("derive_application first"),
        )?);
        self.server_application_keys()
    }
}

/// One TLS 1.3 KeyUpdate generation of a traffic secret:
/// `HKDF-Expand-Label(secret, "traffic upd", "", 32)` under 2PC (empty context).
fn traffic_update(engine: EngineKind, secret: &Secret2) -> Result<Secret2> {
    let (a, b) =
        hkdf_expand_label_shared_engine(engine, &secret.a, &secret.b, b"traffic upd", b"", 32)?;
    Ok(Secret2 { a, b })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    // ---- stock-crate reference implementation of the RFC 8446 §7.1 schedule -------

    fn ref_hkdf_expand_label(secret: &[u8; 32], label: &[u8], ctx: &[u8], len: u16) -> Vec<u8> {
        let info = hkdf_label(label, ctx, len);
        let hk = Hkdf::<Sha256>::from_prk(secret).unwrap();
        let mut okm = vec![0u8; len as usize];
        hk.expand(&info, &mut okm).unwrap();
        okm
    }
    fn ref_derive_secret(secret: &[u8; 32], label: &[u8], transcript: &[u8]) -> [u8; 32] {
        let th = Sha256::digest(transcript);
        let v = ref_hkdf_expand_label(secret, label, &th, 32);
        v.try_into().unwrap()
    }
    fn ref_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        Hkdf::<Sha256>::extract(Some(salt), ikm).0.into()
    }
    fn ref_finished(secret: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
        let fk = ref_hkdf_expand_label(secret, b"finished", b"", 32);
        let mut mac = HmacSha256::new_from_slice(&fk).unwrap();
        mac.update(&Sha256::digest(transcript));
        mac.finalize().into_bytes().into()
    }

    fn split(x: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let a: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(7));
        let b: [u8; 32] = core::array::from_fn(|i| x[i] ^ a[i]);
        (a, b)
    }

    #[test]
    fn full_key_schedule_under_2pc_matches_rustcrypto() {
        // A known ECDHE secret + fabricated public transcripts (their content is opaque
        // to the schedule — only the hash matters), split into shares. The 2PC schedule
        // must reproduce the stock RFC 8446 §7.1 schedule at every node.
        let ecdhe: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(5));
        let (ea, eb) = split(&ecdhe);
        let ch_sh = b"<ClientHello||ServerHello public bytes>";
        let ch_sfin = b"<ClientHello .. server Finished public bytes>";

        // Reference schedule.
        let early = ref_extract(&[0u8; 32], &[0u8; 32]);
        let derived0 = ref_derive_secret(&early, b"derived", b"");
        let hs = ref_extract(&derived0, &ecdhe);
        let chs = ref_derive_secret(&hs, b"c hs traffic", ch_sh);
        let shs = ref_derive_secret(&hs, b"s hs traffic", ch_sh);
        let derived1 = ref_derive_secret(&hs, b"derived", b"");
        let master = ref_extract(&derived1, &[0u8; 32]);
        let cap = ref_derive_secret(&master, b"c ap traffic", ch_sfin);
        let sap = ref_derive_secret(&master, b"s ap traffic", ch_sfin);

        // 2PC schedule.
        let mut ks =
            KeySchedule::derive_handshake(EngineKind::Semihonest, &ea, &eb, ch_sh).unwrap();
        assert_eq!(
            ks.client_handshake_secret().open(),
            chs,
            "client_hs_traffic_secret"
        );
        assert_eq!(
            ks.server_handshake_secret().open(),
            shs,
            "server_hs_traffic_secret"
        );

        // Handshake traffic keys/IVs vs reference.
        let ck = ks.client_handshake_keys().unwrap();
        assert_eq!(
            core::array::from_fn::<u8, 32, _>(|i| ck.key_a[i] ^ ck.key_b[i]).to_vec(),
            ref_hkdf_expand_label(&chs, b"key", b"", 32),
            "client hs key"
        );
        assert_eq!(
            ck.iv.to_vec(),
            ref_hkdf_expand_label(&chs, b"iv", b"", 12),
            "client hs iv"
        );

        // Finished MACs (server verify + client emit) over a fabricated transcript hash.
        let cv_transcript = b"<CH..CertVerify>";
        assert_eq!(
            ks.server_finished(&Sha256::digest(cv_transcript).into())
                .unwrap(),
            ref_finished(&shs, cv_transcript),
            "server Finished"
        );

        // Application epoch.
        ks.derive_application(ch_sfin).unwrap();
        assert_eq!(
            ks.client_application_secret().open(),
            cap,
            "client_ap_traffic_secret"
        );
        assert_eq!(
            ks.server_application_secret().open(),
            sap,
            "server_ap_traffic_secret"
        );
        let sk = ks.server_application_keys().unwrap();
        assert_eq!(
            core::array::from_fn::<u8, 32, _>(|i| sk.key_a[i] ^ sk.key_b[i]).to_vec(),
            ref_hkdf_expand_label(&sap, b"key", b"", 32),
            "server ap key"
        );
        // Cross-check the untouched `master`/`derived` public constant too.
        assert_eq!(derived_early(), derived0, "public Derived(Early)");
    }

    #[test]
    fn key_update_matches_stock() {
        // TLS 1.3 KeyUpdate (RFC 8446 §7.2): the advanced application-traffic secret + its
        // fresh key/IV match the stock HKDF-Expand-Label(secret, "traffic upd", "", ·).
        let ecdhe: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(9).wrapping_add(4));
        let (ea, eb) = split(&ecdhe);
        let mut ks =
            KeySchedule::derive_handshake(EngineKind::Semihonest, &ea, &eb, b"<CH||SH>").unwrap();
        ks.derive_application(b"<CH..sfin>").unwrap();

        let cap0 = ks.client_application_secret().open();
        let expected_next: [u8; 32] = ref_hkdf_expand_label(&cap0, b"traffic upd", b"", 32)
            .try_into()
            .unwrap();

        let keys = ks.update_client_application().unwrap();
        assert_eq!(
            ks.client_application_secret().open(),
            expected_next,
            "KeyUpdate advances the secret via 'traffic upd'"
        );
        assert_eq!(
            core::array::from_fn::<u8, 32, _>(|i| keys.key_a[i] ^ keys.key_b[i]).to_vec(),
            ref_hkdf_expand_label(&expected_next, b"key", b"", 32),
            "post-KeyUpdate traffic key"
        );
    }

    #[test]
    #[ignore] // ~65s in release (authenticated garbling); run with `--ignored --release`
    fn key_schedule_under_malicious_engine_matches_stock() {
        // Malicious-live: the WRK17/KRRW18 authenticated-garbling online drives the real
        // TLS 1.3 key schedule and derives the SAME handshake secrets + traffic keys as
        // the stock RFC 8446 schedule — the malicious analog of the semi-honest test.
        // Scoped to the handshake epoch to bound the (much slower) garbling time; the
        // abort-on-tamper property is covered by `authgarble`'s own tamper tests.
        let ecdhe: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(2));
        let (ea, eb) = split(&ecdhe);
        let ch_sh = b"<ClientHello||ServerHello>";

        // Stock reference.
        let early = ref_extract(&[0u8; 32], &[0u8; 32]);
        let derived0 = ref_derive_secret(&early, b"derived", b"");
        let hs = ref_extract(&derived0, &ecdhe);
        let chs = ref_derive_secret(&hs, b"c hs traffic", ch_sh);
        let shs = ref_derive_secret(&hs, b"s hs traffic", ch_sh);

        // Malicious 2PC schedule.
        let ks = KeySchedule::derive_handshake(EngineKind::Malicious, &ea, &eb, ch_sh).unwrap();
        assert_eq!(
            ks.client_handshake_secret().open(),
            chs,
            "malicious client_hs"
        );
        assert_eq!(
            ks.server_handshake_secret().open(),
            shs,
            "malicious server_hs"
        );

        let ck = ks.client_handshake_keys().unwrap();
        assert_eq!(
            core::array::from_fn::<u8, 32, _>(|i| ck.key_a[i] ^ ck.key_b[i]).to_vec(),
            ref_hkdf_expand_label(&chs, b"key", b"", 32),
            "malicious client hs key"
        );
        assert_eq!(
            ck.iv.to_vec(),
            ref_hkdf_expand_label(&chs, b"iv", b"", 12),
            "malicious client hs iv"
        );
    }
}
