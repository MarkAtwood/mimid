//! `Member::welcome_sender` and `WelcomeJoin::inviter`: the identity of the
//! member whose GroupInfo signature a Welcome carries (RFC 9420
//! §12.4.3.1), read before joining without consuming the KeyPackage.
//!
//! Oracle: the group is built so the inviter is a known member that is
//! not the creator (carol, leaf 1, adds bob), so a reading of leaf 0 or of
//! the joiner's own leaf would fail.

use mimi_mls::member::{ComponentOp, Member, WelcomeJoin};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};

fn identity(name: &[u8]) -> Identity {
    Identity::generate(name, Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity")
}

fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

#[test]
fn welcome_sender_names_the_committer_and_leaves_the_key_package() {
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    let bob = identity(b"bob");

    let mut alice_group = Member::create(&alice, b"room-welcome-sender", &[], &[]).expect("create");
    let carol_kp = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = alice_group
        .commit(&alice, &[&carol_kp], &[], &[], no_components)
        .expect("add carol");
    alice_group.merge_pending_commit(&alice).expect("merge");
    let welcome = bundle.welcome.expect("Welcome");
    let tree = alice_group.ratchet_tree().expect("tree");
    assert_eq!(
        Member::welcome_sender(&carol, &welcome, Some(&tree)).expect("sender"),
        b"alice"
    );
    let WelcomeJoin {
        member: mut carol_group,
        inviter,
        ..
    } = Member::join_welcome(&carol, &welcome, Some(&tree)).expect("carol joins");
    assert_eq!(inviter, b"alice");

    let bob_kp = bob
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = carol_group
        .commit(&carol, &[&bob_kp], &[], &[], no_components)
        .expect("carol adds bob");
    carol_group.merge_pending_commit(&carol).expect("merge");
    let welcome = bundle.welcome.expect("Welcome");
    let tree = carol_group.ratchet_tree().expect("tree");

    // Read twice: staging stores nothing, so the one-time KeyPackage is
    // still there for the second read and for the join.
    for _ in 0..2 {
        assert_eq!(
            Member::welcome_sender(&bob, &welcome, Some(&tree)).expect("sender"),
            b"carol"
        );
    }
    let WelcomeJoin {
        member: bob_group,
        inviter,
        ..
    } = Member::join_welcome(&bob, &welcome, Some(&tree)).expect("bob joins");
    assert_eq!(inviter, b"carol");
    assert_eq!(
        bob_group.epoch_authenticator(),
        carol_group.epoch_authenticator()
    );

    // After the join the KeyPackage is consumed, so the Welcome no longer
    // stages.
    assert!(Member::welcome_sender(&bob, &welcome, Some(&tree)).is_err());
}

/// `Member::welcome_group_id`: the group ID the creator chose, read
/// before joining, and the KeyPackage stays usable for the join.
#[test]
fn welcome_group_id_is_the_groups_and_leaves_the_key_package() {
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    let mut group = Member::create(&alice, b"room-welcome-group-id", &[], &[]).expect("create");
    let carol_kp = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = group
        .commit(&alice, &[&carol_kp], &[], &[], no_components)
        .expect("add carol");
    group.merge_pending_commit(&alice).expect("merge");
    let welcome = bundle.welcome.expect("Welcome");
    let tree = group.ratchet_tree().expect("tree");
    assert_eq!(
        Member::welcome_group_id(&carol, &welcome, Some(&tree)).expect("group ID"),
        b"room-welcome-group-id"
    );
    let joined = Member::join_welcome(&carol, &welcome, Some(&tree)).expect("carol joins");
    assert_eq!(joined.member.group_id(), b"room-welcome-group-id");
}

/// `Member::delete`: carol builds an external Commit into alice's group
/// that is never sent. While her state for the group is kept, OpenMLS
/// refuses a Welcome to the same group; once deleted, she joins from the
/// Welcome and agrees with alice.
#[test]
fn a_deleted_external_join_leaves_room_for_a_welcome() {
    let alice = identity(b"alice");
    let mut group = Member::create(&alice, b"room-delete", &[], &[]).expect("create");
    let group_info = group
        .commit(&alice, &[], &[], &[], no_components)
        .expect("refresh")
        .group_info;
    group.merge_pending_commit(&alice).expect("merge");
    let tree = group.ratchet_tree().expect("tree");

    let carol = identity(b"carol");
    let unsent = Member::join_external(&carol, &group_info, Some(&tree))
        .expect("external join")
        .member;
    let add = |group: &mut Member| {
        let carol_kp = carol
            .key_package(KeyPackageKind::OneTime)
            .expect("KeyPackage");
        let bundle = group
            .commit(&alice, &[&carol_kp], &[], &[], no_components)
            .expect("add carol");
        group.merge_pending_commit(&alice).expect("merge");
        (
            bundle.welcome.expect("Welcome"),
            group.ratchet_tree().expect("tree"),
        )
    };
    let (welcome, tree) = add(&mut group);
    assert!(
        Member::join_welcome(&carol, &welcome, Some(&tree)).is_err(),
        "a Welcome to a group carol holds is refused"
    );

    unsent.delete(&carol).expect("delete");
    assert!(Member::load(&carol, b"room-delete").is_err());
    let joined = Member::join_welcome(&carol, &welcome, Some(&tree)).expect("carol joins");
    assert_eq!(
        joined.member.epoch_authenticator(),
        group.epoch_authenticator()
    );
}

/// `Member::welcome_details`: one staging gives the sender and the
/// GroupContext's components, the ones the creator set; it stores
/// nothing, so it can be read twice and the KeyPackage still serves the
/// join.
#[test]
fn welcome_details_read_the_components_and_leave_the_key_package() {
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    // mls-extensions-11 §7.5 app_components (0x0001), an empty
    // ComponentsList, hand-encoded: its length octet, 0.
    let component: (u16, Vec<u8>) = (0x0001, vec![0x00]);
    let mut group = Member::create(
        &alice,
        b"room-welcome-details",
        &[],
        std::slice::from_ref(&component),
    )
    .expect("create");
    let carol_kp = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = group
        .commit(&alice, &[&carol_kp], &[], &[], no_components)
        .expect("add carol");
    group.merge_pending_commit(&alice).expect("merge");
    let welcome = bundle.welcome.expect("Welcome");
    let tree = group.ratchet_tree().expect("tree");
    for _ in 0..2 {
        let details = Member::welcome_details(&carol, &welcome, Some(&tree)).expect("details");
        assert_eq!(details.sender, b"alice");
        assert_eq!(details.group.group_id, b"room-welcome-details");
        assert_eq!(details.group.epoch, 1);
        assert_eq!(
            details.group.components.get(&component.0),
            Some(&component.1)
        );
    }
    let joined = Member::join_welcome(&carol, &welcome, Some(&tree)).expect("carol joins");
    assert_eq!(
        joined.member.epoch_authenticator(),
        group.epoch_authenticator()
    );
    assert!(Member::welcome_details(&carol, &welcome, Some(&tree)).is_err());
}
