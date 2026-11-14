//! Size limits on variable-length fields mimid receives (bead
//! mimid-1wgh.52.2).
//!
//! The drafts type these fields `opaque<V>` (up to 2^30 octets) and state
//! no limit. Unbounded, they are a resource-exhaustion vector for the hub,
//! its store and every client that renders them. mimid refuses a value
//! longer than its setting, which is mimid's own policy choice (decision
//! mimid-1wgh.52); the defaults are the ones proposed for the drafts (IETF
//! notes 2026-11-14-mimi-issues-from-table-draft.md item 12: implementations
//! SHOULD accept at least this much, and a receiver MAY refuse more).
//!
//! Three classes:
//!
//! - names: `role_name`, room `room_name`, `room_subject`, `room_mood`;
//! - descriptions: `role_description`, room `description_content`, the
//!   abuse report `note`;
//! - URIs: participant-list users, room metadata URIs, a base policy's
//!   `parent_room`, and the URIs of identifierQuery, consent and
//!   keyMaterial.
//!
//! The codec crates stay limit-free: they implement the drafts as written.
//! The checks here read values that already decoded; a value that does not
//! decode is refused elsewhere, for that reason.

use mimi_protocol::component_id::{PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::tls_codec::Deserialize;
use mimi_protocol::{ParticipantListData, ParticipantListUpdate, RoomMetaData};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ComponentID, ROLES_LIST};
use mimi_room_policy::{BaseRoomPolicy, RoleData};

/// The default name limit, in octets.
pub const DEFAULT_MAX_NAME_OCTETS: usize = 1024;
/// The default description limit, in octets.
pub const DEFAULT_MAX_DESCRIPTION_OCTETS: usize = 4096;
/// The default URI limit, in octets.
pub const DEFAULT_MAX_URI_OCTETS: usize = 2048;

/// The three limits, in octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldLimits {
    /// Names, subjects and moods.
    pub name: usize,
    /// Descriptions and notes.
    pub description: usize,
    /// URIs.
    pub uri: usize,
}

impl Default for FieldLimits {
    fn default() -> Self {
        Self {
            name: DEFAULT_MAX_NAME_OCTETS,
            description: DEFAULT_MAX_DESCRIPTION_OCTETS,
            uri: DEFAULT_MAX_URI_OCTETS,
        }
    }
}

/// A field longer than its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{field} is {len} octets, over the limit of {limit}")]
pub struct TooLong {
    /// The field, as the drafts name it.
    pub field: &'static str,
    /// Its length.
    pub len: usize,
    /// The limit it exceeds.
    pub limit: usize,
}

impl FieldLimits {
    fn check(field: &'static str, value: &[u8], limit: usize) -> Result<(), TooLong> {
        if value.len() > limit {
            Err(TooLong {
                field,
                len: value.len(),
                limit,
            })
        } else {
            Ok(())
        }
    }

    /// Checks a name.
    ///
    /// # Errors
    ///
    /// [`TooLong`] if `value` is over the name limit.
    pub fn name(&self, field: &'static str, value: &[u8]) -> Result<(), TooLong> {
        Self::check(field, value, self.name)
    }

    /// Checks a description or note.
    ///
    /// # Errors
    ///
    /// [`TooLong`] if `value` is over the description limit.
    pub fn description(&self, field: &'static str, value: &[u8]) -> Result<(), TooLong> {
        Self::check(field, value, self.description)
    }

    /// Checks a URI.
    ///
    /// # Errors
    ///
    /// [`TooLong`] if `value` is over the URI limit.
    pub fn uri(&self, field: &'static str, value: &[u8]) -> Result<(), TooLong> {
        Self::check(field, value, self.uri)
    }

    /// Checks an AppDataUpdate's `update` for `component_id`, or a
    /// component's whole data when `whole` is true (room creation). Only
    /// the components with limited fields are read; a value that does not
    /// decode passes here and is refused where it is decoded.
    ///
    /// # Errors
    ///
    /// The first field over its limit.
    pub fn component(
        &self,
        component_id: ComponentID,
        bytes: &[u8],
        whole: bool,
    ) -> Result<(), TooLong> {
        match component_id {
            PARTICIPANT_LIST if whole => {
                if let Ok(data) = ParticipantListData::tls_deserialize_exact(bytes) {
                    for participant in &data.participants {
                        self.uri("participant user", &participant.user)?;
                    }
                }
            }
            PARTICIPANT_LIST => {
                if let Ok(update) = ParticipantListUpdate::tls_deserialize_exact(bytes) {
                    for participant in &update.added_participants {
                        self.uri("participant user", &participant.user)?;
                    }
                }
            }
            ROLES_LIST => {
                if let Ok(data) = RoleData::tls_deserialize_exact(bytes) {
                    for role in &data.roles {
                        self.name("role_name", role.role_name.as_bytes())?;
                        self.description("role_description", role.role_description.as_bytes())?;
                    }
                }
            }
            BASE_ROOM_POLICY => {
                if let Ok(base) = BaseRoomPolicy::tls_deserialize_exact(bytes) {
                    for parent in &base.parent_room {
                        self.uri("parent_room", parent.as_str().as_bytes())?;
                    }
                }
            }
            ROOM_METADATA => {
                if let Ok(metadata) = RoomMetaData::tls_deserialize_exact(bytes) {
                    self.uri("room_uri", metadata.room_uri.as_str().as_bytes())?;
                    self.uri("room_avatar", metadata.room_avatar.as_str().as_bytes())?;
                    self.name("room_name", metadata.room_name.as_str().as_bytes())?;
                    self.name("room_subject", metadata.room_subject.as_str().as_bytes())?;
                    self.name("room_mood", metadata.room_mood.as_str().as_bytes())?;
                    for description in &metadata.room_descriptions {
                        self.description("description_content", &description.description_content)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mimi_protocol::tls_codec::Serialize;
    use mimi_protocol::{UserRolePair, UserindexRolePair};
    use mimi_room_policy::Role;

    use super::*;

    fn roles(name: &str, description: &str) -> Vec<u8> {
        RoleData {
            roles: vec![Role {
                role_index: 2,
                role_name: name.to_owned(),
                role_description: description.to_owned(),
                role_capabilities: vec![],
                minimum_participants_constraint: 0,
                maximum_participants_constraint: None,
                minimum_active_participants_constraint: 0,
                maximum_active_participants_constraint: None,
                authorized_role_changes: vec![],
            }],
        }
        .tls_serialize_detached()
        .unwrap()
    }

    #[test]
    fn role_name_and_description_limits() {
        let limits = FieldLimits::default();
        let at = "n".repeat(1024);
        assert!(limits.component(ROLES_LIST, &roles(&at, ""), false).is_ok());
        let over = "n".repeat(1025);
        assert_eq!(
            limits.component(ROLES_LIST, &roles(&over, ""), false),
            Err(TooLong {
                field: "role_name",
                len: 1025,
                limit: 1024
            })
        );
        let long = "d".repeat(4097);
        assert_eq!(
            limits
                .component(ROLES_LIST, &roles("member", &long), true)
                .map_err(|e| e.field),
            Err("role_description")
        );
    }

    #[test]
    fn limits_count_octets_not_characters() {
        // 512 two-octet characters is 1024 octets: at the limit. One more
        // is over, though it is far fewer than 1024 characters.
        let limits = FieldLimits::default();
        assert!(
            limits
                .name("role_name", "\u{e9}".repeat(512).as_bytes())
                .is_ok()
        );
        assert!(
            limits
                .name("role_name", "\u{e9}".repeat(513).as_bytes())
                .is_err()
        );
    }

    #[test]
    fn added_participants_are_checked_as_uris() {
        let limits = FieldLimits::default();
        let user = format!("mimi://a.example/u/{}", "x".repeat(2048)).into_bytes();
        let update = ParticipantListUpdate {
            changed_role_participants: Vec::<UserindexRolePair>::new(),
            removed_indices: vec![],
            added_participants: vec![UserRolePair {
                user,
                role_index: 2,
            }],
        }
        .tls_serialize_detached()
        .unwrap();
        assert_eq!(
            limits
                .component(PARTICIPANT_LIST, &update, false)
                .map_err(|e| e.field),
            Err("participant user")
        );
    }

    #[test]
    fn undecodable_and_unlimited_components_pass() {
        let limits = FieldLimits::default();
        assert!(limits.component(ROLES_LIST, b"\xff\xff", false).is_ok());
        assert!(limits.component(0x7777, &[0; 9000], false).is_ok());
    }
}
