//! Application logic for the MLS application components the hub tracks:
//! `participant_list` (protocol-06 §7.5) and the room-policy-04
//! `roles_list` (§3), `preauth_list` (§4) and `base_room_policy` (§5).
//!
//! mls-extensions-10 §4.7 hands the application, per component ID, the
//! `update` fields of a commit's AppDataUpdate proposals in commit order;
//! the application returns the new data or calls the update invalid.
//! [`apply_updates`] is that logic for the hub-tracked components:
//!
//! - a `ParticipantListUpdate` is applied per decision mimid-1wgh.5.70: all
//!   indices refer to the list before that update; role changes first,
//!   then removals, then the appended additions. An out-of-range or
//!   duplicate index, or a resulting duplicate user, rejects the whole
//!   update. Across the commit, no user may be operated on more than once
//!   (protocol-06 §7.5);
//! - a `RoleUpdate`, `PreAuthUpdate` or `BaseRoomUpdate` replaces the data
//!   entirely (room-policy-04 §3, §4, §5; decision mimid-1wgh.3.20), so the
//!   new data is the last update's bytes once every update has decoded.
//!
//! Every update is decoded strictly: trailing bytes, non-minimal lengths
//! and invalid enum values are rejected.
//!
//! # Limitations
//!
//! - A `roles_list` update is only decoded here. Its §3/§5 structural rules
//!   depend on the `base_room_policy` after the commit, so
//!   [`crate::hub::policy::authorize_commit`] validates it.
//! - A `participant_list` entry with role 0 is accepted here; room policy
//!   denies an action that gives a user role 0 (room-policy-04 §3).
//! - An AppDataUpdate `remove` operation is not handled here; room policy
//!   refuses it for these components.

use std::collections::HashSet;

use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::tls_codec::{self, Deserialize, Serialize};
use mimi_protocol::{ParticipantListData, ParticipantListUpdate};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ComponentID, PREAUTH_LIST, ROLES_LIST};
use mimi_room_policy::{BaseRoomPolicy, PreAuthData, RoleData};

/// Why a component update is invalid (mls-extensions-10 §4.7: "the
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
    /// list before the update (decision mimid-1wgh.5.70).
    #[error("participant list index {index} is out of range for {len} entries")]
    IndexOutOfRange {
        /// The index.
        index: u32,
        /// The length of the list before the update.
        len: usize,
    },
    /// An index appears more than once among `changedRoleParticipants`
    /// and `removedIndices` (decision mimid-1wgh.5.70).
    #[error("participant list index {0} appears more than once")]
    DuplicateIndex(u32),
    /// The update would leave a user in the list more than once (decision
    /// mimid-1wgh.5.70).
    #[error("the update leaves a user in the participant list more than once")]
    DuplicateUser,
    /// The commit operates on a user more than once (protocol-06 §7.5).
    #[error("the commit operates on a participant list user more than once")]
    UserChangedTwice,
    /// [`apply_updates`] was given no updates; mls-extensions-10 §4.7
    /// calls the application with one or more.
    #[error("no updates to apply")]
    NoUpdates,
    /// The component is not one the hub tracks.
    #[error("component {0:#06x} is not tracked by the hub")]
    NotHubTracked(ComponentID),
}

/// One user's participant-list change, from the role before the update to
/// the role after it. A `from_role_index` of 0 is an addition and a
/// `target_role_index` of 0 a removal (room-policy-04 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantChange {
    /// The user.
    pub user: Vec<u8>,
    /// The user's role before the update, 0 if it was not listed.
    pub from_role_index: u32,
    /// The user's role after the update, 0 if it is removed.
    pub target_role_index: u32,
}

/// The participant list as a commit's updates are applied to it in order.
///
/// It remembers every user a previous update operated on, so a later
/// update in the same commit that operates on one again is rejected
/// (protocol-06 §7.5).
#[derive(Debug, Clone)]
pub struct ParticipantListCommit {
    list: ParticipantListData,
    touched: HashSet<Vec<u8>>,
}

impl ParticipantListCommit {
    /// Starts a commit on the list as it stands before the commit.
    pub fn new(list: ParticipantListData) -> Self {
        Self {
            list,
            touched: HashSet::new(),
        }
    }

    /// The list after the updates applied so far.
    pub fn list(&self) -> &ParticipantListData {
        &self.list
    }

    /// Applies one update (decision mimid-1wgh.5.70) and returns its
    /// changes in the order role changes, removals, additions.
    ///
    /// # Errors
    ///
    /// The first rule the update breaks. On error the list is unchanged:
    /// no part of the update is applied.
    pub fn apply(
        &mut self,
        update: &ParticipantListUpdate,
    ) -> Result<Vec<ParticipantChange>, ComponentError> {
        let before = &self.list.participants;
        let len = before.len();
        let mut seen_indices = HashSet::new();
        let mut index = |index: u32| -> Result<usize, ComponentError> {
            let position = usize::try_from(index)
                .ok()
                .filter(|&position| position < len)
                .ok_or(ComponentError::IndexOutOfRange { index, len })?;
            if seen_indices.insert(index) {
                Ok(position)
            } else {
                Err(ComponentError::DuplicateIndex(index))
            }
        };
        let mut touched = self.touched.clone();
        let mut touch = |user: &[u8]| {
            if touched.insert(user.to_vec()) {
                Ok(())
            } else {
                Err(ComponentError::UserChangedTwice)
            }
        };
        let mut after = before.clone();
        let mut changes = Vec::new();
        for pair in &update.changed_role_participants {
            let position = index(pair.user_index)?;
            let entry = &mut after[position];
            touch(&entry.user)?;
            changes.push(ParticipantChange {
                user: entry.user.clone(),
                from_role_index: entry.role_index,
                target_role_index: pair.role_index,
            });
            entry.role_index = pair.role_index;
        }
        let mut removed = vec![false; len];
        for &removed_index in &update.removed_indices {
            let position = index(removed_index)?;
            // An index is never both changed and removed (DuplicateIndex),
            // so `before` holds the user's role before the update.
            let entry = &before[position];
            touch(&entry.user)?;
            removed[position] = true;
            changes.push(ParticipantChange {
                user: entry.user.clone(),
                from_role_index: entry.role_index,
                target_role_index: 0,
            });
        }
        let mut after: Vec<_> = after
            .into_iter()
            .zip(removed)
            .filter_map(|(entry, removed)| (!removed).then_some(entry))
            .collect();
        for added in &update.added_participants {
            touch(&added.user)?;
            changes.push(ParticipantChange {
                user: added.user.clone(),
                from_role_index: 0,
                target_role_index: added.role_index,
            });
            after.push(added.clone());
        }
        let mut users = HashSet::new();
        if !after
            .iter()
            .all(|entry| users.insert(entry.user.as_slice()))
        {
            return Err(ComponentError::DuplicateUser);
        }
        self.list.participants = after;
        self.touched = touched;
        Ok(changes)
    }

    /// The list after every update.
    pub fn into_list(self) -> ParticipantListData {
        self.list
    }
}

/// Decodes `bytes` as the data or update of `component_id`, rejecting
/// trailing bytes.
pub(crate) fn decode<T: Deserialize>(
    component_id: ComponentID,
    bytes: &[u8],
) -> Result<T, ComponentError> {
    T::tls_deserialize_exact(bytes).map_err(|source| ComponentError::Decode {
        component_id,
        source,
    })
}

/// Encodes a participant list as component data.
pub(crate) fn encode_participant_list(
    list: &ParticipantListData,
) -> Result<Vec<u8>, ComponentError> {
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

/// The mls-extensions-10 §4.7 application logic for a hub-tracked
/// component: the new data after a commit's `updates` to it, in commit
/// order.
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
