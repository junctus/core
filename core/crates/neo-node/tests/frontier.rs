//! Frontier capstone (M10–M13): the four research-grade capabilities exercised
//! individually and then composed into one coherent request flow.
//!
//! This is an integration test, so it only uses the crates' public APIs — the
//! same surface a real client would. It proves the milestones interlock:
//! a client pays with an **unlinkable credit** (M10), discovers a relay
//! **obliviously** (M13), builds a **verifiably-unbiasable path** (M11), and
//! hands its request to a **committee** no minority can read (M12).

use neo_core::NodeIdentity;
use neo_credits::{finalize, request, Issuer};
use neo_mpc::{ClearnetRequest, Committee, CommitteeConfig};
use neo_routing::{Relay, Router};
use neo_verify::oblivious::{decode, DirectoryParams, ObliviousDirectory};
use neo_verify::pir::combine;
use neo_verify::selection::{beacon_respond, commitment, verify_seed};
use neo_verify::vrf::VrfKeypair;

/// A set of relays with real identities, for routing and the directory.
fn relays(n: usize) -> Vec<Relay> {
    (0..n)
        .map(|i| {
            let p = NodeIdentity::generate().unwrap().public();
            Relay {
                id: p.id,
                kex: *p.kex.as_bytes(),
                sphinx: p.sphinx,
                addr: format!("10.0.0.{i}:9000"),
            }
        })
        .collect()
}

/// M10 — earn an unlinkable credit and spend it once.
#[test]
fn m10_credit_is_unlinkable_and_single_use() {
    let mut issuer = Issuer::new().unwrap();
    let (blinded, secret) = request().unwrap();
    let issued = issuer.issue(&blinded).unwrap();
    let credit = finalize(secret, issued).unwrap();

    assert!(issuer.redeem(&credit).is_ok(), "first spend accepted");
    assert!(issuer.redeem(&credit).is_err(), "double-spend rejected");
}

/// M11 — client and beacon derive the same verifiable seed, and it drives a path.
#[test]
fn m11_unbiasable_seed_selects_a_verifiable_path() {
    let router = Router::new(relays(8));
    let beacon = VrfKeypair::generate();

    // Client commits first; beacon responds with a VRF neither side can grind.
    let commit = commitment(b"request-nonce");
    let (proof, beacon_seed) = beacon_respond(&beacon, &commit);
    let client_seed =
        verify_seed(&beacon.public(), &commit, &proof).expect("beacon proof verifies");
    assert_eq!(beacon_seed, client_seed);

    // The verifiable seed reproduces the same path for anyone who checks it.
    let path_a = router.select_path_seeded(&client_seed, 3).unwrap();
    let path_b = router.select_path_seeded(&beacon_seed, 3).unwrap();
    let ids = |p: &[Relay]| p.iter().map(|r| r.id).collect::<Vec<_>>();
    assert_eq!(ids(&path_a), ids(&path_b));
    assert_eq!(path_a.len(), 3);
}

/// M12 — a committee threshold reconstructs the request; a minority cannot.
#[test]
fn m12_committee_splits_the_request() {
    let cfg = CommitteeConfig {
        members: 5,
        threshold: 3,
    };
    let req = ClearnetRequest {
        destination: "example.com:443".into(),
        payload: b"hello".to_vec(),
    };
    let committee = Committee::deal(&req, cfg).unwrap();
    assert_eq!(committee.reconstruct_from(&[0, 1, 2]).unwrap(), req);
    assert!(committee.reconstruct_from(&[3, 4]).is_err());
}

/// M13 — fetch a relay's record by NodeId without either server learning which.
#[test]
fn m13_oblivious_directory_fetch() {
    let set = relays(10);
    let entries: Vec<(Vec<u8>, Vec<u8>)> = set
        .iter()
        .map(|r| (r.id.as_bytes().to_vec(), r.addr.clone().into_bytes()))
        .collect();
    let dir = ObliviousDirectory::build(&entries).unwrap();
    let params = DirectoryParams {
        n_buckets: dir.n_buckets(),
        salt: dir.salt(),
    };
    let (s1, s2) = dir.replicas().unwrap();

    let target = &set[6];
    let (q1, q2) = params.query(target.id.as_bytes()).unwrap();
    let record = decode(&combine(&s1.answer(&q1).unwrap(), &s2.answer(&q2).unwrap())).unwrap();
    assert_eq!(record, target.addr.clone().into_bytes());
}

/// The composed flow: pay (M10) → discover obliviously (M13) → verifiable path
/// (M11) → committee exit (M12), end to end.
#[test]
fn frontier_composed_request_flow() {
    // --- M10: the client earns and spends a credit to authorize the request. ---
    let mut issuer = Issuer::new().unwrap();
    let (blinded, secret) = request().unwrap();
    let credit = finalize(secret, issuer.issue(&blinded).unwrap()).unwrap();
    issuer
        .redeem(&credit)
        .expect("paid with an unlinkable credit");

    // --- M13: discover a relay obliviously, by id, from a 2-server directory. ---
    let set = relays(9);
    let entries: Vec<(Vec<u8>, Vec<u8>)> = set
        .iter()
        .map(|r| (r.id.as_bytes().to_vec(), r.addr.clone().into_bytes()))
        .collect();
    let dir = ObliviousDirectory::build(&entries).unwrap();
    let params = DirectoryParams {
        n_buckets: dir.n_buckets(),
        salt: dir.salt(),
    };
    let (s1, s2) = dir.replicas().unwrap();
    let want = &set[4];
    let (q1, q2) = params.query(want.id.as_bytes()).unwrap();
    let discovered = decode(&combine(&s1.answer(&q1).unwrap(), &s2.answer(&q2).unwrap())).unwrap();
    assert_eq!(discovered, want.addr.clone().into_bytes());

    // --- M11: build a verifiably-unbiasable path through the relay set. ---
    let router = Router::new(set);
    let beacon = VrfKeypair::generate();
    let commit = commitment(b"composed-flow-nonce");
    let (proof, seed) = beacon_respond(&beacon, &commit);
    assert_eq!(verify_seed(&beacon.public(), &commit, &proof), Some(seed));
    let path = router.select_path_seeded(&seed, 3).unwrap();
    assert_eq!(path.len(), 3);

    // --- M12: hand the clearnet request to a committee no minority can read. ---
    let cfg = CommitteeConfig {
        members: 5,
        threshold: 3,
    };
    let req = ClearnetRequest {
        destination: "example.com:443".into(),
        payload: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
    };
    let committee = Committee::deal(&req, cfg).unwrap();
    assert!(
        committee.reconstruct_from(&[0, 1]).is_err(),
        "a minority of the committee cannot read the request"
    );
    assert_eq!(
        committee.reconstruct_from(&[0, 2, 4]).unwrap(),
        req,
        "a threshold reconstructs it to perform the exit"
    );
}
