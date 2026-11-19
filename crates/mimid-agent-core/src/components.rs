//! The application logic for the MLS application components mimid
//! rooms carry: `participant_list` (protocol-07 §7.5), `room_metadata`
//! (§7.6), `franking_agent` (§5.4.1) and the room-policy-04 `roles_list`
//! (§3), `preauth_list` (§4) and `base_room_policy` (§5).
//!
//! A copy of mimid-server's `hub/components.rs` (bead mimid-1wgh.13.8):
//! a member must compute the same next GroupContext as the hub, and this
//! crate does not depend on mimid-server (its HTTP, SQLite and TLS stack
//! has no place on a phone). Keep the two in step; a change to one is a
//! change to the other.
//!
//! - every `ParticipantListUpdate` of a commit is resolved against the
//!   list at the start of the epoch (protocol-07 §7.5; decision
//!   mimid-1wgh.6.75): all indices refer to that list, removals never
//!   shift other indices, role changes are made in place, removed entries
//!   dropped and additions appended in commit order;
//! - `roles_list`, `preauth_list`, `base_room_policy`, `room_metadata` and
//!   `franking_agent` updates replace the data entirely (decision
//!   mimid-1wgh.3.20) once every update decodes strictly;
//! - a Commit with more than one `room_metadata` update is invalid
//!   (protocol-07 §7.6; decision mimid-1wgh.64).

use std::collections::HashSet;

use mimi_mls::member::ComponentOp;
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::tls_codec::{self, Deserialize, Serialize};
use mimi_protocol::{
    FrankingAgentUpdate, ParticipantListData, ParticipantListUpdate, RoomMetaUpdate, UserRolePair,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ComponentID, PREAUTH_LIST, ROLES_LIST};
use mimi_room_policy::{BaseRoomPolicy, PreAuthData, RoleData};

/// Why a component update is invalid (mls-extensions-11 §4.7: "the
/// application logic ... considers this update invalid").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ComponentError {
    /// The update, or the current data, does not decode as the component's
    /// type.
    #[error("component {component_id:#06x} data does not decode")]
    Decode {
        /// The component.
        component_id: ComponentID,
        /// The decoding failure.
        #[source]
        source: tls_codec::Error,
    },
    /// The new participant list does not encode.
    #[error("participant list does not encode")]
    Encode(#[source] tls_codec::Error),
    /// A `user_index` or `removedIndices` entry is not an index into the
    /// list at the start of the epoch (protocol-07 §7.5; decision
    /// mimid-1wgh.6.75).
    #[error("participant list index {index} is out of range for {len} entries")]
    IndexOutOfRange {
        /// The index.
        index: u32,
        /// The length of the list at the start of the epoch.
        len: usize,
    },
    /// An index appears more than once in `changedRoleParticipants` or in
    /// `removedIndices`, or in both (protocol-07 §7.5).
    #[error("participant list index {0} appears more than once")]
    DuplicateIndex(u32),
    /// An `addedParticipants` user is already in the list at the start of
    /// the epoch (protocol-07 §7.5), or the list would hold a user more
    /// than once.
    #[error("the update leaves a user in the participant list more than once")]
    DuplicateUser,
    /// The commit operates on a user more than once (protocol-07 §7.5).
    #[error("the commit operates on a participant list user more than once")]
    UserChangedTwice,
    /// [`apply_updates`] was given no updates; mls-extensions-11 §4.7
    /// calls the application with one or more.
    #[error("no updates to apply")]
    NoUpdates,
    /// A Commit updates `room_metadata` more than once: "Only a single
    /// Room metadata update is valid per commit" (protocol-07 §7.6;
    /// decision mimid-1wgh.64).
    #[error("component {0:#06x} is updated more than once in the commit")]
    RepeatedUpdate(ComponentID),
    /// The component is not one the hub tracks.
    #[error("component {0:#06x} is not tracked by the hub")]
    NotHubTracked(ComponentID),
    /// The component is unknown to the hub, so an AppDataUpdate for it is
    /// invalid (mls-extensions-11 §4.7; decision mimid-1wgh.6.53).
    #[error("component {0:#06x} is unknown to the hub")]
    UnknownComponent(ComponentID),
}

/// One user's participant-list change, from the role at the start of the
/// epoch to the role after the commit. A `from_role_index` of 0 is an
/// addition and a `target_role_index` of 0 a removal (room-policy-04 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantChange {
    /// The user.
    pub user: Vec<u8>,
    /// The user's role at the start of the epoch, 0 if it was not listed.
    pub from_role_index: u32,
    /// The user's role after the commit, 0 if it is removed.
    pub target_role_index: u32,
}

/// A commit's participant list updates, each resolved against the list at
/// the start of the epoch (protocol-07 §7.5; decision mimid-1wgh.6.75).
///
/// It remembers every user a previous update operated on, so a later
/// update in the same commit that operates on one again is rejected. As
/// each user is operated on at most once, the updates' order changes only
/// the order of the appended additions.
#[derive(Debug, Clone)]
pub struct ParticipantListCommit {
    start: ParticipantListData,
    roles: Vec<u32>,
    removed: Vec<bool>,
    added: Vec<UserRolePair>,
    touched: HashSet<Vec<u8>>,
    list: ParticipantListData,
}

impl ParticipantListCommit {
    /// Starts a commit on the list at the start of the epoch.
    pub fn new(start: ParticipantListData) -> Self {
        Self {
            roles: start
                .participants
                .iter()
                .map(|entry| entry.role_index)
                .collect(),
            removed: vec![false; start.participants.len()],
            added: Vec::new(),
            touched: HashSet::new(),
            list: start.clone(),
            start,
        }
    }

    /// The list after the updates applied so far.
    pub fn list(&self) -> &ParticipantListData {
        &self.list
    }

    /// Applies one update, its indices referring to the list at the start
    /// of the epoch, and returns its changes in the order role changes,
    /// removals, additions.
    ///
    /// # Errors
    ///
    /// The first rule the update breaks. On error the list is unchanged:
    /// no part of the update is applied.
    pub fn apply(
        &mut self,
        update: &ParticipantListUpdate,
    ) -> Result<Vec<ParticipantChange>, ComponentError> {
        let start = &self.start.participants;
        let len = start.len();
        let position = |index: u32| {
            usize::try_from(index)
                .ok()
                .filter(|&position| position < len)
                .ok_or(ComponentError::IndexOutOfRange { index, len })
        };
        let mut touched = self.touched.clone();
        let mut touch = |user: &[u8]| {
            if touched.insert(user.to_vec()) {
                Ok(())
            } else {
                Err(ComponentError::UserChangedTwice)
            }
        };
        let mut roles = self.roles.clone();
        let mut removed = self.removed.clone();
        let mut added = self.added.clone();
        let mut changes = Vec::new();
        let mut seen_indices = HashSet::new();
        for pair in &update.changed_role_participants {
            let position = position(pair.user_index)?;
            if !seen_indices.insert(position) {
                return Err(ComponentError::DuplicateIndex(pair.user_index));
            }
            let entry = &start[position];
            touch(&entry.user)?;
            changes.push(ParticipantChange {
                user: entry.user.clone(),
                from_role_index: entry.role_index,
                target_role_index: pair.role_index,
            });
            roles[position] = pair.role_index;
        }
        for &removed_index in &update.removed_indices {
            let position = position(removed_index)?;
            if !seen_indices.insert(position) {
                return Err(ComponentError::DuplicateIndex(removed_index));
            }
            let entry = &start[position];
            touch(&entry.user)?;
            changes.push(ParticipantChange {
                user: entry.user.clone(),
                from_role_index: entry.role_index,
                target_role_index: 0,
            });
            removed[position] = true;
        }
        for addition in &update.added_participants {
            touch(&addition.user)?;
            if start.iter().any(|entry| entry.user == addition.user) {
                return Err(ComponentError::DuplicateUser);
            }
            changes.push(ParticipantChange {
                user: addition.user.clone(),
                from_role_index: 0,
                target_role_index: addition.role_index,
            });
            added.push(addition.clone());
        }
        let participants: Vec<_> = start
            .iter()
            .zip(&roles)
            .zip(&removed)
            .filter(|&(_, &removed)| !removed)
            .map(|((entry, &role_index), _)| UserRolePair {
                user: entry.user.clone(),
                role_index,
            })
            .chain(added.iter().cloned())
            .collect();
        let mut users = HashSet::new();
        if !participants
            .iter()
            .all(|entry| users.insert(entry.user.as_slice()))
        {
            return Err(ComponentError::DuplicateUser);
        }
        self.roles = roles;
        self.removed = removed;
        self.added = added;
        self.touched = touched;
        self.list.participants = participants;
        Ok(changes)
    }

    /// The list after every update.
    pub fn into_list(self) -> ParticipantListData {
        self.list
    }
}

/// Decodes `bytes` as the data or update of `component_id`, rejecting
/// trailing bytes.
fn decode<T: Deserialize>(component_id: ComponentID, bytes: &[u8]) -> Result<T, ComponentError> {
    T::tls_deserialize_exact(bytes).map_err(|source| ComponentError::Decode {
        component_id,
        source,
    })
}

/// Encodes a participant list as component data.
fn encode_participant_list(list: &ParticipantListData) -> Result<Vec<u8>, ComponentError> {
    list.tls_serialize_detached()
        .map_err(ComponentError::Encode)
}

/// Whether the hub tracks `component_id` and [`apply_updates`] handles it.
pub fn is_hub_tracked(component_id: ComponentID) -> bool {
    matches!(
        component_id,
        PARTICIPANT_LIST | ROLES_LIST | PREAUTH_LIST | BASE_ROOM_POLICY
    )
}

/// mls-extensions-11 §5.1: the components whose AppDataUpdates mimi-mls
/// itself applies (app_components, safe_aad, content_media_types); the
/// hub's [`apply_commit_op`] is never asked about them.
pub const MLS_BUILT_IN: [ComponentID; 3] = [0x0001, 0x0002, 0x0003];

/// Whether the hub accepts an AppDataUpdate of `component_id`: the
/// hub-tracked components, `room_metadata` and `franking_agent`, which
/// [`apply_commit_op`] applies, and the [`MLS_BUILT_IN`] components, which
/// mimi-mls applies (decision mimid-1wgh.4.76.2). An AppDataUpdate of any
/// other component makes a Commit invalid, so the hub also refuses it as a
/// standalone proposal (bead mimid-1wgh.6.73).
pub fn is_known_component(component_id: ComponentID) -> bool {
    is_hub_tracked(component_id)
        || component_id == ROOM_METADATA
        || component_id == FRANKING_AGENT
        || MLS_BUILT_IN.contains(&component_id)
}

/// The mls-extensions-11 §4.7 application logic for a hub-tracked
/// component: the new data after a commit's `updates` to it, in commit
/// order. Participant list updates all index the list in `current`
/// (protocol-07 §7.5; decision mimid-1wgh.6.75).
///
/// `current` is the component's data before the commit, or `None` if the
/// GroupContext has no entry for it; an absent participant list is empty.
/// `current` is ignored for the full-replacement components.
///
/// # Errors
///
/// [`ComponentError::NotHubTracked`], [`ComponentError::NoUpdates`], or
/// the first update that does not decode or apply.
pub fn apply_updates(
    component_id: ComponentID,
    current: Option<&[u8]>,
    updates: &[&[u8]],
) -> Result<Vec<u8>, ComponentError> {
    match component_id {
        PARTICIPANT_LIST => {
            if updates.is_empty() {
                return Err(ComponentError::NoUpdates);
            }
            let list = current
                .map(|bytes| decode::<ParticipantListData>(component_id, bytes))
                .transpose()?
                .unwrap_or_default();
            let mut commit = ParticipantListCommit::new(list);
            for update in updates {
                commit.apply(&decode::<ParticipantListUpdate>(component_id, update)?)?;
            }
            encode_participant_list(commit.list())
        }
        ROLES_LIST => replace::<RoleData>(component_id, updates),
        PREAUTH_LIST => replace::<PreAuthData>(component_id, updates),
        BASE_ROOM_POLICY => replace::<BaseRoomPolicy>(component_id, updates),
        other => Err(ComponentError::NotHubTracked(other)),
    }
}

/// The hub's mls-extensions-11 §4.7 application logic for one component
/// of a Commit, as the `apply` function of
/// [`mimi_mls::member::Member::process`] and `commit` (decision mimid-1wgh.6.53):
///
/// - the four hub-tracked components go through [`apply_updates`];
/// - `room_metadata` (protocol-07 §7.6) and `franking_agent` (§5.4.1)
///   updates are decoded strictly, and the last one replaces the data. A
///   Commit may update `room_metadata` only once (protocol-07 §7.6;
///   decision mimid-1wgh.64). Room policy still refuses any
///   `franking_agent` change (decision mimid-1wgh.6.42);
/// - a `remove` of any of these components passes through; room policy
///   refuses it for the hub-tracked ones;
/// - every other component is unknown to the hub, and its AppDataUpdate is
///   invalid.
///
/// # Errors
///
/// [`ComponentError::UnknownComponent`] for any other component, and the
/// errors of [`apply_updates`] or of decoding an update.
pub fn apply_commit_op(
    component_id: ComponentID,
    current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ComponentError> {
    if !is_known_component(component_id) {
        return Err(ComponentError::UnknownComponent(component_id));
    }
    let ComponentOp::Update(updates) = op else {
        return Ok(None);
    };
    match component_id {
        // protocol-07 §7.6; decision mimid-1wgh.64
        ROOM_METADATA if updates.len() > 1 => Err(ComponentError::RepeatedUpdate(component_id)),
        ROOM_METADATA => replace::<RoomMetaUpdate>(component_id, updates),
        FRANKING_AGENT => replace::<FrankingAgentUpdate>(component_id, updates),
        _ => apply_updates(component_id, current, updates),
    }
    .map(Some)
}

/// Full replacement (decision mimid-1wgh.3.20): every update must decode
/// as `T`, and the last one is the new data.
fn replace<T: Deserialize>(
    component_id: ComponentID,
    updates: &[&[u8]],
) -> Result<Vec<u8>, ComponentError> {
    for update in updates {
        decode::<T>(component_id, update)?;
    }
    updates
        .last()
        .map(|last| last.to_vec())
        .ok_or(ComponentError::NoUpdates)
}

#[cfg(test)]
mod tests {
    //! Oracle: the same hand-encoded bytes as mimid-server's
    //! `tests/hub_policy_components.rs`, from the protocol-07 §7.6
    //! `RoomMetaData` struct with MLS variable-length vector lengths
    //! (RFC 9420 §2.1.2). A member must reach the same verdict as the hub.

    use super::*;

    /// protocol-07 §7.6 `RoomMetaData` with every field empty: six
    /// zero-length vectors (room_uri, room_name, room_descriptions,
    /// room_avatar, room_subject, room_mood).
    const EMPTY_ROOM_METADATA: &[u8] = &[0x00; 6];
    /// The same with room_name "x": length 1, then 0x78.
    const NAMED_ROOM_METADATA: &[u8] = &[0x00, 0x01, 0x78, 0x00, 0x00, 0x00, 0x00];

    #[test]
    fn one_room_metadata_update_replaces_the_data() {
        assert_eq!(
            apply_commit_op(
                ROOM_METADATA,
                Some(EMPTY_ROOM_METADATA),
                ComponentOp::Update(&[NAMED_ROOM_METADATA]),
            ),
            Ok(Some(NAMED_ROOM_METADATA.to_vec()))
        );
    }

    #[test]
    fn two_room_metadata_updates_in_one_commit_are_invalid() {
        // protocol-07 §7.6: "Only a single Room metadata update is valid
        // per commit"; decision mimid-1wgh.64 item 5.
        assert_eq!(
            apply_commit_op(
                ROOM_METADATA,
                Some(EMPTY_ROOM_METADATA),
                ComponentOp::Update(&[NAMED_ROOM_METADATA, EMPTY_ROOM_METADATA]),
            ),
            Err(ComponentError::RepeatedUpdate(ROOM_METADATA))
        );
    }
}
