//! A BasicCredential member and a `did_webvh` user in one group
//! (decisions mimid-1wgh.4.81.21, mimid-1wgh.4.81.22, mimid-1wgh.4.81.23).
//!
//! Bob holds a BasicCredential and supports `did_webvh`
//! ([`Identity::support_did_webvh`]); Alice has two devices whose log lists
//! her MIMI user URI in `alsoKnownAs`. Bob adds both devices, Alice revokes
//! one, and a hub Observer enforcing the rules follows along.
//!
//! Oracles: the logs come from `mls_didwebvh::controller`, which the
//! mls-didwebvh tests check against an independent did:webvh verifier; the
//! user URI, the SCID and who is a member are what the test put into the
//! logs and the Commits, not values computed by the code under test.

#![forbid(unsafe_code)]

use mimi_mls::didwebvh::mimi_user_uri;
use mimi_mls::member::{ComponentOp, Incoming, Member};
use mimi_mls::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimi_mls::mls_didwebvh::{CodePoints, PublicKey};
use mimi_mls::observer::{Observed, Observer, ObserverStart, ProposalKind};
use mimi_mls::tls_codec::Deserialize;
use mimi_mls::wire::KeyPackage;
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};

const CP: CodePoints = CodePoints::SUGGESTED;
const ALICE: &str = "mimi://example.com/u/alice";
const BOB: &[u8] = b"mimi://example.org/u/bob";

fn device(identity: &[u8]) -> Identity {
    Identity::generate(identity, Store::open_in_memory().expect("store")).expect("identity")
}

fn key(identity: &Identity) -> PublicKey {
    identity
        .signature_public_key()
        .try_into()
        .expect("Ed25519 key")
}

fn time(s: u32) -> String {
    format!("2026-11-20T09:00:{s:02}Z")
}

fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

/// Alice's log listing `devices`, her user URI in `alsoKnownAs`; one update
/// key signs every entry.
fn alice_log(devices: &[PublicKey]) -> DidLog {
    let signer = UpdateKey::from_seed(&[0x11; 32]);
    DidLog::create_also_known_as(
        "example.com",
        "alice",
        &time(1),
        &Parameters {
            update_keys: Some(vec![signer.multikey()]),
            next_key_hashes: None,
        },
        &signer,
        devices,
        &[ALICE.to_owned(), "did:web:example.com:alice".to_owned()],
    )
    .expect("create")
}

#[test]
fn a_basic_member_shares_a_group_with_a_did_webvh_user() {
    let mut bob = device(BOB);
    bob.support_did_webvh(CP);
    let mut alice_d1 = device(b"unset");
    let mut alice_d2 = device(b"unset");
    let mut log = alice_log(&[key(&alice_d1), key(&alice_d2)]);
    let scid = log.verified().scid().to_owned();
    alice_d1
        .set_did_webvh_credential(CP, log.credential().expect("credential"))
        .expect("d1");
    alice_d2
        .set_did_webvh_credential(CP, log.credential().expect("credential"))
        .expect("d2");

    // A KeyPackage tells its user URI and SCID once verified.
    let d1_kp = alice_d1.key_package(KeyPackageKind::OneTime).expect("kp");
    let d2_kp = alice_d2.key_package(KeyPackageKind::OneTime).expect("kp");
    let info = KeyPackage::tls_deserialize_exact(&d1_kp[..])
        .expect("decode")
        .verify(std::time::SystemTime::now())
        .expect("verify");
    assert_eq!(info.identity(), None, "not a BasicCredential");
    let verified = info.did_webvh(CP).expect("verifies").expect("did_webvh");
    assert_eq!(verified.scid(), scid);
    assert_eq!(mimi_user_uri(&verified), Some(ALICE));
    // Under other code points it is not a did_webvh credential.
    let other = CodePoints::new(0xf008, 0xf013).expect("code points");
    assert!(info.did_webvh(other).expect("no error").is_none());

    // Bob creates the group: no record yet, since his leaf is basic.
    let mut b = Member::create(&bob, b"room", &[], &[]).expect("create");
    assert!(b.did_webvh_heads(&bob).expect("heads").is_none());
    // An empty Commit gives the hub a GroupInfo to start from.
    let first = b
        .commit(&bob, &[], &[], &[], no_components)
        .expect("empty Commit");
    b.merge_pending_commit(&bob).expect("merge");
    let hub_store = Store::open_in_memory().expect("store");
    let tree = b.ratchet_tree().expect("tree");
    let group_info = first.group_info;
    let ObserverStart {
        observer: mut hub, ..
    } = Observer::from_group_info(&hub_store, &group_info, Some(&tree)).expect("hub");
    hub.enforce_did_webvh(CP).expect("nothing to check yet");

    // Bob adds both of Alice's devices. The Commit sets the record with a
    // GroupContextExtensions proposal Bob did not ask for, and the hub sees
    // it as the record change and nothing else.
    let bundle = b
        .commit(&bob, &[&d1_kp, &d2_kp], &[], &[], no_components)
        .expect("add alice");
    let Observed::Commit(_) = hub
        .process(&hub_store, &bundle.commit, no_components)
        .expect("the hub accepts")
    else {
        panic!("not a Commit");
    };
    let detail = hub.pending_commit_detail().expect("detail");
    let kinds: Vec<&ProposalKind> = detail.proposals.iter().map(|p| &p.proposal).collect();
    assert!(kinds.contains(&&ProposalKind::DidWebvhRecord), "{kinds:?}");
    assert!(
        !kinds.contains(&&ProposalKind::GroupContextExtensions),
        "{kinds:?}"
    );
    let added: Vec<&[u8]> = detail
        .proposals
        .iter()
        .filter_map(|p| match &p.proposal {
            ProposalKind::Add { identity, .. } => Some(identity.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(added, [ALICE.as_bytes(), ALICE.as_bytes()]);
    hub.merge_pending_commit(&hub_store).expect("hub merges");
    b.merge_pending_commit(&bob).expect("merge");

    let heads = b.did_webvh_heads(&bob).expect("heads").expect("record");
    assert!(
        heads
            .get(&scid)
            .is_some_and(|h| h.authorizes(&key(&alice_d2)))
    );

    // Members are known by user URI, did_webvh leaves also by SCID.
    let mut members = hub.members();
    members.sort();
    assert_eq!(
        members,
        [
            (0, BOB.to_vec()),
            (1, ALICE.as_bytes().to_vec()),
            (2, ALICE.as_bytes().to_vec())
        ]
    );
    assert_eq!(
        hub.did_webvh_members(),
        [(1, scid.clone()), (2, scid.clone())]
    );

    let tree = b.ratchet_tree().expect("tree");
    let welcome = bundle.welcome.expect("Welcome");
    assert_eq!(
        Member::welcome_sender(&alice_d1, &welcome, Some(&tree)).expect("sender"),
        BOB
    );
    let mut a1 = Member::join_welcome(&alice_d1, &welcome, Some(&tree))
        .expect("d1 joins")
        .member;
    let mut a2 = Member::join_welcome(&alice_d2, &welcome, Some(&tree))
        .expect("d2 joins")
        .member;
    assert_eq!(a1.members(), b.members());

    // Messages flow both ways, senders reported by user URI.
    let message = a2.send(&alice_d2, b"hi bob", &[]).expect("send");
    let Incoming::Application {
        sender_identity, ..
    } = b.process(&bob, &message, no_components).expect("bob reads")
    else {
        panic!("not an application message");
    };
    assert_eq!(sender_identity, ALICE.as_bytes());
    let message = b.send(&bob, b"hi alice", &[]).expect("send");
    let Incoming::Application {
        sender_identity, ..
    } = a1
        .process(&alice_d1, &message, no_components)
        .expect("d1 reads")
    else {
        panic!("not an application message");
    };
    assert_eq!(sender_identity, BOB);
    a2.process(&alice_d2, &message, no_components)
        .expect("d2 reads");

    // Alice revokes d2; d1 takes the new log and commits. The Remove and
    // the record change are added by Member::commit.
    let signer = UpdateKey::from_seed(&[0x11; 32]);
    log.append(&time(2), &Parameters::default(), &signer, &[key(&alice_d1)])
        .expect("append");
    alice_d1
        .set_did_webvh_credential(CP, log.credential().expect("credential"))
        .expect("d1 takes v2");
    let bundle = a1
        .commit(&alice_d1, &[], &[], &[], no_components)
        .expect("revocation");
    hub.process(&hub_store, &bundle.commit, no_components)
        .expect("the hub accepts");
    let detail = hub.pending_commit_detail().expect("detail");
    assert!(
        detail
            .proposals
            .iter()
            .any(|p| p.proposal == ProposalKind::DidWebvhRecord)
    );
    assert!(detail.proposals.iter().any(|p| matches!(
        &p.proposal,
        ProposalKind::Remove { removed: 2, identity } if identity == ALICE.as_bytes()
    )));
    // The UpdatePath's leaf has a newer log but the same user: not an
    // identity change.
    let path = detail.path.expect("UpdatePath");
    assert_eq!(path.identity, ALICE.as_bytes());
    assert!(!path.identity_changed);
    hub.merge_pending_commit(&hub_store).expect("hub merges");
    a1.merge_pending_commit(&alice_d1).expect("merge");
    let Incoming::Commit(summary) = b
        .process(&bob, &bundle.commit, no_components)
        .expect("bob accepts")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![2]);
    assert!(matches!(
        a2.process(&alice_d2, &bundle.commit, no_components),
        Ok(Incoming::Commit(summary)) if summary.self_removed
    ));
    assert_eq!(hub.did_webvh_members(), [(1, scid.clone())]);
}

#[test]
fn a_basic_member_without_support_cannot_add_a_did_webvh_user() {
    // RFC 9420 §7.2: every member must support every credential type in
    // use. Bob does not list did_webvh, so Alice's leaf cannot join.
    let bob = device(BOB);
    let mut alice = device(b"unset");
    let log = alice_log(&[key(&alice)]);
    alice
        .set_did_webvh_credential(CP, log.credential().expect("credential"))
        .expect("alice");
    let kp = alice.key_package(KeyPackageKind::OneTime).expect("kp");
    let mut b = Member::create(&bob, b"room", &[], &[]).expect("create");
    let refused = b.commit(&bob, &[&kp], &[], &[], no_components);
    // OpenMLS: LeafNodeValidation(UnsupportedCredentials).
    assert!(
        format!("{refused:?}").contains("UnsupportedCredentials"),
        "{refused:?}"
    );
}

#[test]
fn a_log_naming_two_mimi_uris_gives_no_user() {
    let mut bob = device(BOB);
    bob.support_did_webvh(CP);
    let mut alice = device(b"unset");
    let signer = UpdateKey::from_seed(&[0x22; 32]);
    let log = DidLog::create_also_known_as(
        "example.com",
        "alice",
        &time(1),
        &Parameters {
            update_keys: Some(vec![signer.multikey()]),
            next_key_hashes: None,
        },
        &signer,
        &[key(&alice)],
        &[ALICE.to_owned(), "MIMI://example.com/u/mallory".to_owned()],
    )
    .expect("create");
    assert_eq!(mimi_user_uri(log.verified()), None);
    alice
        .set_did_webvh_credential(CP, log.credential().expect("credential"))
        .expect("alice");
    let kp = alice.key_package(KeyPackageKind::OneTime).expect("kp");
    let mut b = Member::create(&bob, b"room", &[], &[]).expect("create");
    b.commit(&bob, &[&kp], &[], &[], no_components)
        .expect("MLS and the rules allow it");
    b.merge_pending_commit(&bob).expect("merge");
    // The leaf is in the group, but no user claims it: the application
    // (the hub's participant list check) refuses it.
    assert_eq!(b.members()[1], (1, Vec::new()));
}
