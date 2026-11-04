//! Tests for the hub-tracked component apply logic (`hub::components`).
//!
//! Oracle: the expected lists are worked by hand from protocol-07 §7.5 and
//! decision mimid-1wgh.6.75 (every update's indices refer to the list at
//! the start of the epoch; role changes in place, removals without
//! shifting, additions appended; any bad index or resulting duplicate
//! rejects the whole update; a commit operates on each user at most
//! once). The
//! byte fixtures are hand-encoded from the TLS presentation language of
//! protocol-07 §7.5 and room-policy-04 §3-§5, with MLS variable-length
//! vector lengths (RFC 9420 §2.1.2), commented byte by byte.

use mimi_protocol::component_id::{PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::{ParticipantListData, ParticipantListUpdate, UserRolePair, UserindexRolePair};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, PREAUTH_LIST, ROLES_LIST};
use mimid_server::hub::components::{
    ComponentError, ParticipantChange, ParticipantListCommit, apply_updates,
};

fn list(entries: &[(&str, u32)]) -> ParticipantListData {
    ParticipantListData {
        participants: entries
            .iter()
            .map(|&(user, role_index)| UserRolePair {
                user: user.as_bytes().to_vec(),
                role_index,
            })
            .collect(),
    }
}

fn update(changed: &[(u32, u32)], removed: &[u32], added: &[(&str, u32)]) -> ParticipantListUpdate {
    ParticipantListUpdate {
        changed_role_participants: changed
            .iter()
            .map(|&(user_index, role_index)| UserindexRolePair {
                user_index,
                role_index,
            })
            .collect(),
        removed_indices: removed.to_vec(),
        added_participants: list(added).participants,
    }
}

fn change(user: &str, from_role_index: u32, target_role_index: u32) -> ParticipantChange {
    ParticipantChange {
        user: user.as_bytes().to_vec(),
        from_role_index,
        target_role_index,
    }
}

/// alice (index 0, role 2), bob (1, role 2), carol (2, role 3).
fn before() -> ParticipantListData {
    list(&[("alice", 2), ("bob", 2), ("carol", 3)])
}

#[test]
fn participant_list_update_apply_table() {
    type Expected = Result<(ParticipantListData, Vec<ParticipantChange>), ComponentError>;
    let rows: Vec<(&str, ParticipantListUpdate, Expected)> = vec![
        (
            "role change in place",
            update(&[(1, 3)], &[], &[]),
            Ok((
                list(&[("alice", 2), ("bob", 3), ("carol", 3)]),
                vec![change("bob", 2, 3)],
            )),
        ),
        (
            "removals use indices before the update, no shifting",
            update(&[], &[0, 2], &[]),
            Ok((
                list(&[("bob", 2)]),
                vec![change("alice", 2, 0), change("carol", 3, 0)],
            )),
        ),
        (
            "role changes apply before removals, both on pre-update indices",
            update(&[(2, 2)], &[0], &[]),
            Ok((
                list(&[("bob", 2), ("carol", 2)]),
                vec![change("carol", 3, 2), change("alice", 2, 0)],
            )),
        ),
        (
            "additions are appended after removals",
            update(&[], &[1], &[("dave", 2)]),
            Ok((
                list(&[("alice", 2), ("carol", 3), ("dave", 2)]),
                vec![change("bob", 2, 0), change("dave", 0, 2)],
            )),
        ),
        (
            "changed index out of range",
            update(&[(3, 2)], &[], &[]),
            Err(ComponentError::IndexOutOfRange { index: 3, len: 3 }),
        ),
        (
            "removed index out of range",
            update(&[], &[3], &[]),
            Err(ComponentError::IndexOutOfRange { index: 3, len: 3 }),
        ),
        (
            "u32::MAX index",
            update(&[], &[u32::MAX], &[]),
            Err(ComponentError::IndexOutOfRange {
                index: u32::MAX,
                len: 3,
            }),
        ),
        (
            "duplicate removed index",
            update(&[], &[1, 1], &[]),
            Err(ComponentError::DuplicateIndex(1)),
        ),
        (
            "duplicate changed index",
            update(&[(1, 3), (1, 2)], &[], &[]),
            Err(ComponentError::DuplicateIndex(1)),
        ),
        (
            "index both changed and removed",
            update(&[(1, 3)], &[1], &[]),
            Err(ComponentError::DuplicateIndex(1)),
        ),
        (
            "adding a listed user leaves a duplicate",
            update(&[], &[], &[("alice", 2)]),
            Err(ComponentError::DuplicateUser),
        ),
        (
            "removing and re-adding a user operates on it twice (§7.5)",
            update(&[], &[0], &[("alice", 3)]),
            Err(ComponentError::UserChangedTwice),
        ),
        (
            "adding the same user twice operates on it twice (§7.5)",
            update(&[], &[], &[("dave", 2), ("dave", 3)]),
            Err(ComponentError::UserChangedTwice),
        ),
    ];
    for (why, update, expected) in rows {
        let mut commit = ParticipantListCommit::new(before());
        let result = commit.apply(&update);
        match expected {
            Ok((expected_list, expected_changes)) => {
                assert_eq!(result, Ok(expected_changes), "{why}");
                assert_eq!(commit.list(), &expected_list, "{why}");
            }
            Err(expected) => {
                assert_eq!(result, Err(expected), "{why}");
                assert_eq!(commit.list(), &before(), "{why}: nothing applied");
            }
        }
    }
}

#[test]
fn rejected_update_leaves_list_and_users_untouched() {
    let mut commit = ParticipantListCommit::new(before());
    // A valid role change followed by a bad removal: the whole update fails.
    assert_eq!(
        commit.apply(&update(&[(0, 3)], &[9], &[])),
        Err(ComponentError::IndexOutOfRange { index: 9, len: 3 })
    );
    assert_eq!(commit.list(), &before());
    // alice was not marked as operated on, so a later update may change her.
    assert_eq!(
        commit.apply(&update(&[(0, 3)], &[], &[])),
        Ok(vec![change("alice", 2, 3)])
    );
}

#[test]
fn later_update_indices_refer_to_epoch_start() {
    let mut commit = ParticipantListCommit::new(before());
    assert_eq!(
        commit.apply(&update(&[], &[0], &[])),
        Ok(vec![change("alice", 2, 0)])
    );
    // protocol-07 §7.5: index 0 is still alice, already operated on.
    assert_eq!(
        commit.apply(&update(&[(0, 3)], &[], &[])),
        Err(ComponentError::UserChangedTwice)
    );
    assert_eq!(commit.into_list(), list(&[("bob", 2), ("carol", 3)]));
}

#[test]
fn updates_in_one_commit_share_epoch_start_indices() {
    // protocol-07 §7.5: "All indices ... refer to the participants vector
    // at the end of the epoch in which the proposal is sent ... This holds
    // even when a commit contains more than one ParticipantListUpdate.
    // Removing one entry does not shift the indices of the other removals."
    // Every row starts from before(): alice 0, bob 1, carol 2.
    type Expected = Result<(ParticipantListData, Vec<ParticipantChange>), ComponentError>;
    let rows: Vec<(&str, [ParticipantListUpdate; 2], Expected)> = vec![
        (
            "a role change after a removal names the epoch-start user",
            [update(&[], &[0], &[]), update(&[(1, 3)], &[], &[])],
            Ok((list(&[("bob", 3), ("carol", 3)]), vec![change("bob", 2, 3)])),
        ),
        (
            "a removal after a removal does not shift",
            [update(&[], &[0], &[]), update(&[], &[1], &[])],
            Ok((list(&[("carol", 3)]), vec![change("bob", 2, 0)])),
        ),
        (
            "the last epoch-start index stays in range after a removal",
            [update(&[], &[0], &[]), update(&[], &[2], &[])],
            Ok((list(&[("bob", 2)]), vec![change("carol", 3, 0)])),
        ),
        (
            "an earlier update's addition has no index",
            [
                update(&[], &[], &[("dave", 2)]),
                update(&[(3, 3)], &[], &[]),
            ],
            Err(ComponentError::IndexOutOfRange { index: 3, len: 3 }),
        ),
        (
            "the same index removed by two updates is the same user",
            [update(&[], &[0], &[]), update(&[], &[0], &[])],
            Err(ComponentError::UserChangedTwice),
        ),
        (
            "re-adding a user an earlier update removed",
            [update(&[], &[0], &[]), update(&[], &[], &[("alice", 3)])],
            Err(ComponentError::UserChangedTwice),
        ),
        (
            "adding a user an earlier update added",
            [
                update(&[], &[], &[("dave", 2)]),
                update(&[], &[], &[("dave", 3)]),
            ],
            Err(ComponentError::UserChangedTwice),
        ),
    ];
    for (why, [first, second], expected) in rows {
        let mut commit = ParticipantListCommit::new(before());
        assert!(commit.apply(&first).is_ok(), "{why}: first update");
        let after_first = commit.list().clone();
        let result = commit.apply(&second);
        match expected {
            Ok((expected_list, expected_changes)) => {
                assert_eq!(result, Ok(expected_changes), "{why}");
                assert_eq!(commit.list(), &expected_list, "{why}");
            }
            Err(expected) => {
                assert_eq!(result, Err(expected), "{why}");
                assert_eq!(commit.list(), &after_first, "{why}: nothing applied");
            }
        }
    }
}

#[test]
fn commit_operates_on_each_user_once() {
    // protocol-07 §7.5: "not valid if it contain any combination of
    // Participant list updates that operate on ... the same user ... more
    // than once"
    let mut commit = ParticipantListCommit::new(before());
    assert!(commit.apply(&update(&[(1, 3)], &[], &[])).is_ok());
    assert_eq!(
        commit.apply(&update(&[], &[1], &[])),
        Err(ComponentError::UserChangedTwice)
    );
    assert_eq!(
        commit.list(),
        &list(&[("alice", 2), ("bob", 3), ("carol", 3)])
    );
}

#[test]
fn existing_duplicate_rejects_any_update() {
    let mut commit = ParticipantListCommit::new(list(&[("alice", 2), ("alice", 3)]));
    assert_eq!(
        commit.apply(&update(&[], &[], &[])),
        Err(ComponentError::DuplicateUser)
    );
}

// --- apply_updates over hand-encoded bytes ---------------------------------

/// ParticipantListData [("a", 2)].
const LIST_A2: &[u8] = &[
    0x06, // participants<V>: 6 bytes
    0x01, 0x61, // user<V> "a"
    0x00, 0x00, 0x00, 0x02, // role_index 2
];

/// ParticipantListUpdate: change index 0 to role 3, remove none, add ("b", 2).
const UPDATE_CHANGE_A_ADD_B: &[u8] = &[
    0x08, // changedRoleParticipants<V>: 8 bytes
    0x00, 0x00, 0x00, 0x00, // user_index 0
    0x00, 0x00, 0x00, 0x03, // role_index 3
    0x00, // removedIndices<V>: empty
    0x06, // addedParticipants<V>: 6 bytes
    0x01, 0x62, // user<V> "b"
    0x00, 0x00, 0x00, 0x02, // role_index 2
];

/// ParticipantListData [("a", 3), ("b", 2)].
const LIST_A3_B2: &[u8] = &[
    0x0c, // participants<V>: 12 bytes
    0x01, 0x61, // user<V> "a"
    0x00, 0x00, 0x00, 0x03, // role_index 3
    0x01, 0x62, // user<V> "b"
    0x00, 0x00, 0x00, 0x02, // role_index 2
];

/// ParticipantListUpdate: remove index 0 only.
const UPDATE_REMOVE_0: &[u8] = &[
    0x00, // changedRoleParticipants<V>: empty
    0x04, // removedIndices<V>: 4 bytes
    0x00, 0x00, 0x00, 0x00, // index 0
    0x00, // addedParticipants<V>: empty
];

/// ParticipantListUpdate: remove index 1 only.
const UPDATE_REMOVE_1: &[u8] = &[
    0x00, // changedRoleParticipants<V>: empty
    0x04, // removedIndices<V>: 4 bytes
    0x00, 0x00, 0x00, 0x01, // index 1
    0x00, // addedParticipants<V>: empty
];

/// ParticipantListData with no participants.
const LIST_EMPTY: &[u8] = &[
    0x00, // participants<V>: empty
];

/// ParticipantListData [("b", 2)].
const LIST_B2: &[u8] = &[
    0x06, // participants<V>: 6 bytes
    0x01, 0x62, // user<V> "b"
    0x00, 0x00, 0x00, 0x02, // role_index 2
];

/// RoleData with one role: index `index`, name "r", no capabilities or
/// constraints.
fn roles_bytes(index: u8) -> Vec<u8> {
    vec![
        0x13, // roles<V>: 19 bytes
        0x00, 0x00, 0x00, index, // role_index
        0x01, 0x72, // role_name<V> "r"
        0x00, // role_description<V>: empty
        0x00, // role_capabilities<V>: empty
        0x00, 0x00, 0x00, 0x00, // minimum_participants_constraint 0
        0x00, // maximum_participants_constraint: absent
        0x00, 0x00, 0x00, 0x00, // minimum_active_participants_constraint 0
        0x00, // maximum_active_participants_constraint: absent
        0x00, // authorized_role_changes<V>: empty
    ]
}

/// BaseRoomPolicy with every flag false except multi_device and
/// persistent_room, no limits, no component IDs.
const BASE: &[u8] = &[
    0x00, // fixed_membership false
    0x00, // parent_dependant false
    0x00, // parent_room<V>: empty
    0x01, // multi_device true
    0x00, // max_clients: absent
    0x00, // max_users: absent
    0x00, // pseudonyms_allowed false
    0x01, // persistent_room true
    0x00, // discoverable false
    0x00, // policy_component_ids<V>: empty
];

/// BaseRoomPolicy with parent_dependant true but no parent_room, which §5
/// forbids.
const BASE_NO_PARENT: &[u8] = &[
    0x00, 0x01, // fixed_membership false, parent_dependant true
    0x00, // parent_room<V>: empty
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
];

/// PreAuthData with no entries.
const PREAUTH_EMPTY: &[u8] = &[0x00];

#[test]
fn participant_list_bytes_round_trip() {
    assert_eq!(
        apply_updates(PARTICIPANT_LIST, Some(LIST_A2), &[UPDATE_CHANGE_A_ADD_B]),
        Ok(LIST_A3_B2.to_vec())
    );
    // Two updates in commit order: the second's index 0 is "a" again, but
    // "a" was already operated on.
    assert_eq!(
        apply_updates(
            PARTICIPANT_LIST,
            Some(LIST_A2),
            &[UPDATE_CHANGE_A_ADD_B, UPDATE_REMOVE_0]
        ),
        Err(ComponentError::UserChangedTwice)
    );
    assert_eq!(
        apply_updates(PARTICIPANT_LIST, Some(LIST_A3_B2), &[UPDATE_REMOVE_0]),
        Ok(LIST_B2.to_vec())
    );
    // protocol-07 §7.5: both indices refer to the epoch-start list, so
    // the second update removes "b", not an index past the end.
    assert_eq!(
        apply_updates(
            PARTICIPANT_LIST,
            Some(LIST_A3_B2),
            &[UPDATE_REMOVE_0, UPDATE_REMOVE_1]
        ),
        Ok(LIST_EMPTY.to_vec())
    );
    // An absent list is empty; index 0 is then out of range.
    assert_eq!(
        apply_updates(PARTICIPANT_LIST, None, &[UPDATE_REMOVE_0]),
        Err(ComponentError::IndexOutOfRange { index: 0, len: 0 })
    );
}

#[test]
fn malformed_participant_list_bytes_rejected() {
    let trailing = [UPDATE_REMOVE_0, &[0x00]].concat();
    let truncated = &UPDATE_CHANGE_A_ADD_B[..UPDATE_CHANGE_A_ADD_B.len() - 1];
    // A non-minimal length: 0x40 0x00 is a two-byte encoding of 0.
    let non_minimal: &[u8] = &[0x40, 0x00, 0x00, 0x00];
    for (why, current, bad) in [
        ("trailing byte", LIST_A2, trailing.as_slice()),
        ("truncated", LIST_A2, truncated),
        ("non-minimal length", LIST_A2, non_minimal),
        (
            "current data trailing byte",
            &[LIST_A2, &[0x00]].concat()[..],
            UPDATE_REMOVE_0,
        ),
    ] {
        assert!(
            matches!(
                apply_updates(PARTICIPANT_LIST, Some(current), &[bad]),
                Err(ComponentError::Decode {
                    component_id: PARTICIPANT_LIST,
                    ..
                })
            ),
            "{why}"
        );
    }
}

#[test]
fn policy_components_are_replaced_by_last_update() {
    // room-policy-04 §3, §4, §5 "completely replaces"; decision
    // mimid-1wgh.3.20
    let (r2, r3) = (roles_bytes(2), roles_bytes(3));
    assert_eq!(
        apply_updates(ROLES_LIST, Some(&r2), &[&r3, &r2]),
        Ok(r2.clone())
    );
    assert_eq!(apply_updates(ROLES_LIST, None, &[&r3]), Ok(r3.clone()));
    assert_eq!(
        apply_updates(PREAUTH_LIST, None, &[PREAUTH_EMPTY]),
        Ok(PREAUTH_EMPTY.to_vec())
    );
    assert_eq!(
        apply_updates(BASE_ROOM_POLICY, Some(BASE), &[BASE]),
        Ok(BASE.to_vec())
    );
}

#[test]
fn malformed_policy_updates_rejected() {
    let r3_trailing = [roles_bytes(3), vec![0x00]].concat();
    for (why, component_id, updates) in [
        (
            "an earlier update is malformed",
            ROLES_LIST,
            vec![r3_trailing.as_slice(), BASE],
        ),
        (
            "base policy breaks §5 parent rule",
            BASE_ROOM_POLICY,
            vec![BASE_NO_PARENT],
        ),
        (
            "preauth trailing byte",
            PREAUTH_LIST,
            vec![&[0x00, 0x00][..]],
        ),
    ] {
        assert!(
            matches!(
                apply_updates(component_id, None, &updates),
                Err(ComponentError::Decode { component_id: c, .. }) if c == component_id
            ),
            "{why}"
        );
    }
}

#[test]
fn apply_updates_needs_hub_component_and_updates() {
    assert_eq!(
        apply_updates(ROOM_METADATA, None, &[BASE]),
        Err(ComponentError::NotHubTracked(ROOM_METADATA))
    );
    assert_eq!(
        apply_updates(PARTICIPANT_LIST, Some(LIST_A2), &[]),
        Err(ComponentError::NoUpdates)
    );
    assert_eq!(
        apply_updates(ROLES_LIST, None, &[]),
        Err(ComponentError::NoUpdates)
    );
}
