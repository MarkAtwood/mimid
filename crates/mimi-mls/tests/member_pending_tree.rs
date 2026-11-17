//! `Member::pending_ratchet_tree`: the tree that goes with a pending
//! Commit's GroupInfo (draft-ietf-mls-ratchet-tree-options-02 §3), for a
//! CommitBundle sent with a `full` RatchetTreeOption (protocol-07 §5.3).
//! A hub that keeps a room's tree seeds it from that GroupInfo and tree
//! (Haven mimi-hubd, bead mimid-1wgh.46.20.3), so the tree must be the
//! next epoch's, not the current one.

use mimi_mls::member::{ComponentOp, Member, MemberError};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};

fn identity(name: &[u8]) -> Identity {
    Identity::generate(name, Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity")
}

/// An `apply` function for Commits that carry no AppDataUpdate.
fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

#[test]
fn pending_ratchet_tree_is_the_tree_after_the_commit() {
    let alice = identity(b"alice");
    let mut group = Member::create(&alice, b"room-pending-tree", &[], &[]).expect("create");
    let before = group.ratchet_tree().expect("tree before");
    let bob = identity(b"bob");
    let bob_key_package = bob
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    group
        .commit(&alice, &[&bob_key_package], &[], &[], no_components)
        .expect("commit");

    let pending = group.pending_ratchet_tree(&alice).expect("pending tree");
    assert_ne!(pending, before, "the pending tree must hold bob's leaf");
    // Until the merge, the group's own tree is still the current epoch's.
    assert_eq!(group.ratchet_tree().expect("tree"), before);

    group.merge_pending_commit(&alice).expect("merge");
    assert_eq!(group.ratchet_tree().expect("tree after"), pending);
}

#[test]
fn pending_ratchet_tree_needs_a_pending_commit() {
    let alice = identity(b"alice");
    let group = Member::create(&alice, b"room-no-pending", &[], &[]).expect("create");
    assert!(matches!(
        group.pending_ratchet_tree(&alice),
        Err(MemberError::Commit(_))
    ));
}
