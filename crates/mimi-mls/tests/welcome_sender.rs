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
