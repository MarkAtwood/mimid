//! draft-atwood-mls-didwebvh-credential-00 end to end over OpenMLS: two
//! users whose devices carry `did_webvh` credentials share a group, and
//! revoking one of Alice's devices in her log removes it from the group.
//!
//! Oracles: the logs are written by `mls_didwebvh::controller`, whose
//! output the mls-didwebvh tests check against an independent did:webvh
//! verifier; every expectation (who is a member, which record the group
//! holds) follows from the device keys the test puts in each log, not from
//! the code under test.

#![forbid(unsafe_code)]

use mimi_mls::didwebvh::DidWebvhError;
use mimi_mls::member::{ComponentOp, Incoming, Member, MemberError};
use mimi_mls::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimi_mls::mls_didwebvh::{CodePoints, PublicKey};
use mimi_mls::observer::{Observed, Observer, ObserverStart};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};

const CP: CodePoints = CodePoints::DEFAULT;

fn device() -> Identity {
    Identity::generate(b"unset", Store::open_in_memory().expect("store")).expect("identity")
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

/// A user's controller: update keys with pre-rotation and a recovery key.
struct Controller {
    log: DidLog,
    next: u8,
    recovery: UpdateKey,
}

impl Controller {
    fn create(name: &str, seed: u8, devices: &[PublicKey]) -> Self {
        let first = UpdateKey::from_seed(&[seed; 32]);
        let recovery = UpdateKey::from_seed(&[seed ^ 0xff; 32]);
        let second = UpdateKey::from_seed(&[seed + 1; 32]);
        let log = DidLog::create(
            "example.com",
            name,
            &time(1),
            &Parameters {
                update_keys: Some(vec![first.multikey()]),
                next_key_hashes: Some(vec![second.key_hash(), recovery.key_hash()]),
            },
            &first,
            devices,
        )
        .expect("create");
        Self {
            log,
            next: seed + 1,
            recovery,
        }
    }

    /// Appends an entry listing `devices`, signed by the next update key.
    fn set_devices(&mut self, devices: &[PublicKey]) {
        let signer = UpdateKey::from_seed(&[self.next; 32]);
        let after = UpdateKey::from_seed(&[self.next + 1; 32]);
        let n = u32::try_from(self.log.verified().version_ids().len()).expect("small") + 1;
        self.log
            .append(
                &time(n),
                &Parameters {
                    update_keys: Some(vec![signer.multikey()]),
                    next_key_hashes: Some(vec![after.key_hash(), self.recovery.key_hash()]),
                },
                &signer,
                devices,
            )
            .expect("append");
        self.next += 1;
    }

    fn credential(&self) -> mimi_mls::mls_didwebvh::DidWebvhCredential {
        self.log.credential().expect("credential")
    }
}

struct Room {
    alice: Controller,
    alice_d1: Identity,
    alice_d2: Identity,
    bob_d1: Identity,
    a1: Member,
    a2: Member,
    b1: Member,
    /// The hub's view of the group, enforcing the rules.
    hub: Observer,
    hub_store: Store,
}

/// Alice (devices d1, d2) and Bob (d1) in one group. Alice's d1 carries her
/// v1 log (d1 only), d2 her v2 log (d1 and d2).
fn room() -> Room {
    let mut alice_d1 = device();
    let mut alice_d2 = device();
    let mut bob_d1 = device();

    let mut alice = Controller::create("alice", 10, &[key(&alice_d1)]);
    alice_d1
        .set_did_webvh_credential(CP, alice.credential())
        .expect("alice d1 v1");
    alice.set_devices(&[key(&alice_d1), key(&alice_d2)]);
    alice_d2
        .set_did_webvh_credential(CP, alice.credential())
        .expect("alice d2 v2");
    let bob = Controller::create("bob", 50, &[key(&bob_d1)]);
    bob_d1
        .set_did_webvh_credential(CP, bob.credential())
        .expect("bob d1");

    let mut a1 = Member::create(&alice_d1, b"room", &[], &[]).expect("create");
    let heads = a1
        .did_webvh_heads(&alice_d1)
        .expect("heads")
        .expect("record");
    assert_eq!(heads.heads().len(), 1);

    let bob_kp = bob_d1.key_package(KeyPackageKind::OneTime).expect("bob kp");
    let d2_kp = alice_d2
        .key_package(KeyPackageKind::OneTime)
        .expect("d2 kp");
    let bundle = a1
        .commit(&alice_d1, &[&bob_kp, &d2_kp], &[], &[], no_components)
        .expect("add bob and d2");
    a1.merge_pending_commit(&alice_d1).expect("merge");

    // The Commit raised Alice's record to v2 and recorded Bob, although the
    // caller asked only for the Adds (§Expected Heads).
    let heads = a1
        .did_webvh_heads(&alice_d1)
        .expect("heads")
        .expect("record");
    let alice_head = heads.get(alice.log.verified().scid()).expect("alice entry");
    assert_eq!(
        alice_head.version_id(),
        alice.log.verified().head_version_id()
    );
    assert!(alice_head.authorizes(&key(&alice_d2)));
    assert!(heads.get(bob.log.verified().scid()).is_some());

    let tree = a1.ratchet_tree().expect("tree");
    let welcome = bundle.welcome.expect("Welcome");
    let b1 = Member::join_welcome(&bob_d1, &welcome, Some(&tree))
        .expect("bob joins")
        .member;
    let a2 = Member::join_welcome(&alice_d2, &welcome, Some(&tree))
        .expect("alice d2 joins")
        .member;
    let hub_store = Store::open_in_memory().expect("store");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&hub_store, &bundle.group_info, Some(&tree)).expect("hub");
    observer
        .enforce_did_webvh(CP)
        .expect("the hub checks the GroupInfo");
    Room {
        alice,
        alice_d1,
        alice_d2,
        bob_d1,
        a1,
        a2,
        b1,
        hub: observer,
        hub_store,
    }
}

#[test]
fn two_users_share_a_group_and_a_revocation_removes_a_device() {
    let Room {
        mut alice,
        mut alice_d1,
        alice_d2,
        bob_d1,
        mut a1,
        mut a2,
        mut b1,
        mut hub,
        hub_store,
    } = room();

    // Messages flow.
    let message = a1.send(&alice_d1, b"hello bob", &[]).expect("send");
    let received = b1
        .process(&bob_d1, &message, no_components)
        .expect("bob reads");
    assert!(
        matches!(received, Incoming::Application { ref data, .. } if data == b"hello bob"),
        "{received:?}"
    );
    let members = b1.did_webvh_members(&bob_d1);
    assert_eq!(members.len(), 3);

    // Alice revokes d2: her controller appends v3 listing d1 only, and d1
    // takes the new log.
    let d2_leaf = a2.own_leaf_index();
    alice.set_devices(&[key(&alice_d1)]);
    alice_d1
        .set_did_webvh_credential(CP, alice.credential())
        .expect("d1 takes v3");

    // d1 commits with no explicit Remove: the rules require one, and the
    // Commit carries it with the new record (§Revoking a Device).
    let bundle = a1
        .commit(&alice_d1, &[], &[], &[], no_components)
        .expect("revocation Commit");
    a1.merge_pending_commit(&alice_d1).expect("merge");

    // The hub, enforcing the same rules, accepts it.
    let Observed::Commit(summary) = hub
        .process(&hub_store, &bundle.commit, no_components)
        .expect("the hub accepts")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![d2_leaf]);
    hub.merge_pending_commit(&hub_store).expect("hub merges");

    let Incoming::Commit(summary) = b1
        .process(&bob_d1, &bundle.commit, no_components)
        .expect("bob accepts")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![d2_leaf]);
    let Incoming::Commit(summary) = a2
        .process(&alice_d2, &bundle.commit, no_components)
        .expect("d2 sees its removal")
    else {
        panic!("not a Commit");
    };
    assert!(summary.self_removed);
    assert!(!a2.is_active());

    for (member, identity) in [(&a1, &alice_d1), (&b1, &bob_d1)] {
        let heads = member
            .did_webvh_heads(identity)
            .expect("heads")
            .expect("record");
        let head = heads.get(alice.log.verified().scid()).expect("alice");
        assert_eq!(head.version_id(), alice.log.verified().head_version_id());
        assert!(!head.authorizes(&key(&alice_d2)));
        assert_eq!(member.did_webvh_members(identity).len(), 2);
    }

    // The group stays usable.
    let message = b1.send(&bob_d1, b"bye d2", &[]).expect("send");
    assert!(matches!(
        a1.process(&alice_d1, &message, no_components),
        Ok(Incoming::Application { .. })
    ));
}

#[test]
fn a_revoked_devices_old_key_package_cannot_be_added() {
    let Room {
        mut alice,
        mut alice_d1,
        alice_d2,
        bob_d1,
        mut a1,
        a2: _,
        mut b1,
        ..
    } = room();
    // d2's KeyPackage carries the v2 log, which authorizes it.
    let stale = alice_d2
        .key_package(KeyPackageKind::OneTime)
        .expect("stale kp");
    let d2_leaf = 2;
    alice.set_devices(&[key(&alice_d1)]);
    alice_d1
        .set_did_webvh_credential(CP, alice.credential())
        .expect("v3");
    let bundle = a1
        .commit(&alice_d1, &[], &[d2_leaf], &[], no_components)
        .expect("revocation with an explicit Remove");
    a1.merge_pending_commit(&alice_d1).expect("merge");
    b1.process(&bob_d1, &bundle.commit, no_components)
        .expect("bob accepts");

    // §Withheld or Stale Logs: the record keeps v3, so the provider replaying
    // d2's old KeyPackage gets nowhere.
    let refused = b1.commit(&bob_d1, &[&stale], &[], &[], no_components);
    assert!(
        matches!(
            refused,
            Err(MemberError::DidWebvh(DidWebvhError::AddedUnauthorized))
        ),
        "{refused:?}"
    );
}

#[test]
fn a_device_the_log_does_not_list_cannot_take_the_credential() {
    let Room { alice, .. } = room();
    // The provider builds a device of its own and tries to give it Alice's
    // real log, which does not list its key (§Binding to the LeafNode).
    // A client that skips this check is refused by the receivers; see
    // didwebvh_rogue.rs.
    let mut ghost = device();
    let refused = ghost.set_did_webvh_credential(CP, alice.credential());
    assert!(
        matches!(
            refused,
            Err(mimi_mls::Error::DidWebvh(DidWebvhError::NotAuthorized))
        ),
        "{refused:?}"
    );
}

#[test]
fn a_device_not_yet_in_the_record_joins_externally_and_raises_it() {
    let Room {
        mut alice,
        alice_d1,
        mut a1,
        ..
    } = room();
    let group_info = a1
        .commit(&alice_d1, &[], &[], &[], no_components)
        .expect("refresh")
        .group_info;
    a1.merge_pending_commit(&alice_d1).expect("merge");
    let tree = a1.ratchet_tree().expect("tree");

    // Alice adds d3 to her log; d3 tries to join by external Commit.
    let mut alice_d3 = device();
    let d2 = alice
        .log
        .verified()
        .authorized_keys()
        .iter()
        .copied()
        .collect::<Vec<_>>();
    let mut devices = d2;
    devices.push(key(&alice_d3));
    alice.set_devices(&devices);
    alice_d3
        .set_did_webvh_credential(CP, alice.credential())
        .expect("d3");
    // The draft's §Rules say an external Commit cannot change the record,
    // so d3, whose log is newer than the recorded head, could not join. As
    // an app_data_dictionary component the record can be set by an
    // AppDataUpdate in the external Commit (mls-extensions-11 §4.7;
    // decision mimid-1wgh.4.81.33), and d3 raises Alice's entry itself.
    let joined = Member::join_external(&alice_d3, &group_info, Some(&tree)).expect("d3 joins");
    let record = joined
        .member
        .did_webvh_heads(&alice_d3)
        .expect("heads")
        .expect("record");
    let head = record.get(alice.log.verified().scid()).expect("alice");
    assert_eq!(head.version_id(), alice.log.verified().head_version_id());
    a1.process(&alice_d1, &joined.commit_bundle.commit, no_components)
        .expect("d1 accepts the external Commit");
    assert_eq!(
        a1.did_webvh_heads(&alice_d1)
            .expect("heads")
            .expect("record"),
        record
    );
}

/// §Rules: "A committer whose own key the new head does not authorize
/// cannot send that Commit ... Another member has to commit it, for example
/// by committing an Update proposal, sent by one of the user's other
/// devices, that carries the new log." Alice revokes d1 from d2; Bob
/// commits d2's Update and the Commit removes d1.
#[test]
fn another_member_commits_a_revocation_sent_as_an_update_proposal() {
    let Room {
        mut alice,
        mut alice_d1,
        mut alice_d2,
        bob_d1,
        mut a1,
        mut a2,
        mut b1,
        mut hub,
        hub_store,
    } = room();
    let d1_leaf = a1.own_leaf_index();

    // d1 cannot take a log that does not list it, and so cannot commit it
    // (a Commit cannot remove its committer, RFC 9420 §12.2).
    alice.set_devices(&[key(&alice_d2)]);
    let refused = alice_d1.set_did_webvh_credential(CP, alice.credential());
    assert!(
        matches!(
            refused,
            Err(mimi_mls::Error::DidWebvh(DidWebvhError::NotAuthorized))
        ),
        "{refused:?}"
    );

    // d2 takes the new log and proposes it; Bob commits.
    alice_d2
        .set_did_webvh_credential(CP, alice.credential())
        .expect("d2 takes v3");
    let proposal = a2.propose_credential_update(&alice_d2).expect("Update");
    b1.process(&bob_d1, &proposal, no_components)
        .expect("bob stores it");
    a1.process(&alice_d1, &proposal, no_components)
        .expect("d1 stores it");
    hub.process(&hub_store, &proposal, no_components)
        .expect("the hub stores it");
    let bundle = b1
        .commit(&bob_d1, &[], &[], &[], no_components)
        .expect("bob commits the revocation");
    b1.merge_pending_commit(&bob_d1).expect("merge");

    let Observed::Commit(summary) = hub
        .process(&hub_store, &bundle.commit, no_components)
        .expect("the hub accepts")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![d1_leaf]);
    let Incoming::Commit(summary) = a2
        .process(&alice_d2, &bundle.commit, no_components)
        .expect("d2 accepts")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![d1_leaf]);
    let Incoming::Commit(summary) = a1
        .process(&alice_d1, &bundle.commit, no_components)
        .expect("d1 sees its removal")
    else {
        panic!("not a Commit");
    };
    assert!(summary.self_removed);
    let heads = b1.did_webvh_heads(&bob_d1).expect("heads").expect("record");
    let head = heads.get(alice.log.verified().scid()).expect("alice");
    assert_eq!(head.version_id(), alice.log.verified().head_version_id());
}
