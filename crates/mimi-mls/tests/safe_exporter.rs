//! The forward-secure exporter of mls-extensions-11 §4.4 through
//! `mimi_mls::member::Member::safe_export_secret` (bead mimid-1wgh.4.82).
//!
//! The two properties under test are the ones draft-atwood-mimi-calls §3
//! turns on, so they are worth holding down rather than assuming:
//!
//! - every member of the group derives the SAME secret for a component,
//!   which is what makes it usable as a shared key at all, and equally
//!   what stops it confining anything to a subset of the group;
//! - a different component gets a different secret, and a new epoch
//!   gets a different secret again, so a media key rolls when the group
//!   does.
//!
//! Oracle: §4.4's own construction. The secret for a ComponentID is the
//! leaf of an Exporter Tree whose root descends from the epoch secret,
//! so it is a function of (group, epoch, component) and of nothing else.
//! Two members in the same epoch must agree; anything else must differ.

#![forbid(unsafe_code)]

use mimi_mls::member::{ComponentOp, Member, WelcomeJoin};
use mimi_mls::{Identity, KeyPackageKind, Store};

/// mls-extensions-11 §7.5 private-use component ids, for tests only.
const MEDIA: u16 = 0x8010;
/// See [`MEDIA`].
const OTHER: u16 = 0x8011;

/// No component operations are expected in these groups.
fn refuse_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, mimi_mls::ErrorSource> {
    Err(format!("unexpected component {component_id:#06x}").into())
}

fn identity(name: &[u8]) -> Identity {
    Identity::generate(name, Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity")
}

/// Two members of one group, in the same epoch.
fn pair() -> (Identity, Member, Identity, Member) {
    let alice = identity(b"mimi://a.example/u/alice");
    let bob = identity(b"mimi://a.example/u/bob");
    let mut alice_group = Member::create(&alice, b"room-safe-export", &[], &[]).expect("create");
    let bob_key_package = bob
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = alice_group
        .commit(&alice, &[&bob_key_package], &[], &[], refuse_components)
        .expect("commit adding bob");
    alice_group
        .merge_pending_commit(&alice)
        .expect("merge the add");
    let WelcomeJoin {
        member: bob_group, ..
    } = Member::join_welcome(
        &bob,
        &bundle.welcome.expect("a Welcome for bob"),
        Some(&alice_group.ratchet_tree().expect("tree")),
    )
    .expect("bob joins");
    (alice, alice_group, bob, bob_group)
}

/// Both members derive the same secret for a component, and a different
/// one for a different component.
#[test]
fn every_member_derives_the_same_component_secret() {
    let (alice, mut alice_group, bob, mut bob_group) = pair();

    let alice_media = alice_group
        .safe_export_secret(&alice, MEDIA)
        .expect("alice exports the media secret");
    let bob_media = bob_group
        .safe_export_secret(&bob, MEDIA)
        .expect("bob exports the media secret");

    assert_eq!(
        alice_media, bob_media,
        "a component's secret is a function of the group and epoch, so \
         both members derive it"
    );
    assert!(!alice_media.is_empty());

    // The same construction is what makes it unusable for confining a
    // call to a subset: bob did not have to be told anything.
    let alice_other = alice_group
        .safe_export_secret(&alice, OTHER)
        .expect("alice exports another component's secret");
    assert_ne!(
        alice_media, alice_other,
        "a different ComponentID is a different leaf of the Exporter Tree"
    );
}

/// A new epoch gives a new secret, which is what rolls a media key when
/// the group changes.
#[test]
fn a_new_epoch_gives_a_new_secret() {
    let (alice, mut alice_group, _bob, _bob_group) = pair();

    let before = alice_group
        .safe_export_secret(&alice, MEDIA)
        .expect("export in the first epoch");

    // Any Commit moves the epoch; an empty one is enough.
    alice_group
        .commit(&alice, &[], &[], &[], refuse_components)
        .expect("empty commit");
    alice_group
        .merge_pending_commit(&alice)
        .expect("merge the empty commit");

    let after = alice_group
        .safe_export_secret(&alice, MEDIA)
        .expect("export in the next epoch");

    assert_ne!(
        before, after,
        "the exported secret descends from the epoch secret, so a Commit \
         rolls it; draft-atwood-mimi-calls §4.4 relies on this"
    );
}

/// A member removed from the group exports nothing further.
#[test]
fn a_removed_member_cannot_export() {
    let (alice, mut alice_group, bob, mut bob_group) = pair();
    let bob_leaf = bob_group.own_leaf_index();

    let removal = alice_group
        .commit(&alice, &[], &[bob_leaf], &[], refuse_components)
        .expect("commit removing bob");
    alice_group
        .merge_pending_commit(&alice)
        .expect("merge the removal");
    // Bob processes his own removal and is evicted.
    let _ = bob_group.process(&bob, &removal.commit, refuse_components);

    assert!(
        bob_group.safe_export_secret(&bob, MEDIA).is_err(),
        "a removed member has no epoch to export from"
    );
}
