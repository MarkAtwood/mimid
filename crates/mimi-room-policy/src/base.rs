//! The `base_room_policy` component of room-policy-04 §5.

use std::io::Read;

use tls_codec::{Deserialize, TlsSerialize, TlsSize};

use crate::component_id::ComponentID;
use crate::{Bool, PolicyError, Uri};

/// The `BaseRoomPolicy` struct of room-policy-04 §5: top-level policy for a
/// room, and the data of the `base_room_policy` component.
///
/// The field `parent_dependant` keeps the struct's spelling; the §5 prose
/// says `parent_dependent` (decision mimid-1wgh.3.29).
///
/// Decoding checks the wire format and [`BaseRoomPolicy::validate`]. A
/// value built in code is not checked until `validate` is called; encoding
/// does not check it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize)]
pub struct BaseRoomPolicy {
    /// `bool fixed_membership`. If true, the participant list is fixed when
    /// the room is created; [`crate::RoleData::validate`] enforces the role
    /// rule this implies.
    pub fixed_membership: Bool,
    /// `bool parent_dependant`. If true, the room's participants must be a
    /// strict subset of the parent room's.
    pub parent_dependant: Bool,
    /// `Uri parent_room<V>`: one non-empty [`Uri`], the parent's room ID,
    /// when `parent_dependant` is true; otherwise empty (decisions
    /// mimid-1wgh.3.15, mimid-1wgh.3.18).
    pub parent_room: Vec<Uri>,
    /// `bool multi_device`. If false, only one client per user may be in
    /// the MLS group at a time.
    pub multi_device: Bool,
    /// `optional uint32 max_clients`: the most clients the MLS group may
    /// have; absent means no limit.
    pub max_clients: Option<u32>,
    /// `optional uint32 max_users`: the most non-banned participant list
    /// entries; absent means no limit.
    pub max_users: Option<u32>,
    /// `bool pseudonyms_allowed`. If false, MLS credentials must carry
    /// "real" long-term identifiers.
    pub pseudonyms_allowed: Bool,
    /// `bool persistent_room`. If false, the room becomes inaccessible when
    /// its MLS group is destroyed.
    pub persistent_room: Bool,
    /// `bool discoverable`. If true, the room is searchable in some way.
    pub discoverable: Bool,
    /// `Component policy_component_ids<V>`: the IDs of the other policy
    /// components relevant to the room. `Component` means `ComponentID`
    /// (decision mimid-1wgh.3.14). Unknown IDs are kept unchanged.
    pub policy_component_ids: Vec<ComponentID>,
}

/// `BaseRoomPolicy BaseRoomData` of room-policy-04 §5.
pub type BaseRoomData = BaseRoomPolicy;

/// `BaseRoomPolicy BaseRoomUpdate` of room-policy-04 §5: an
/// `AppDataUpdate` that replaces the whole `base_room_policy` (decision
/// mimid-1wgh.3.20).
pub type BaseRoomUpdate = BaseRoomPolicy;

impl BaseRoomPolicy {
    /// Checks the structural rule room-policy-04 §5 states for this
    /// component.
    ///
    /// If `parent_dependant` is true, `parent_room` holds exactly one
    /// non-empty [`Uri`]; otherwise `parent_room` is empty. §5: "the
    /// parent_room MUST be set with the room ID of the parent. Otherwise
    /// the field is zero-length." A zero-length `Uri` means absent, so it
    /// does not set the field (decisions mimid-1wgh.3.15,
    /// mimid-1wgh.3.18).
    ///
    /// # Errors
    ///
    /// [`PolicyError::ParentRoomMismatch`] if the rule is broken.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let consistent = match (
            bool::from(self.parent_dependant),
            self.parent_room.as_slice(),
        ) {
            (true, [parent]) => !parent.is_empty(),
            (false, []) => true,
            _ => false,
        };
        if consistent {
            Ok(())
        } else {
            Err(PolicyError::ParentRoomMismatch)
        }
    }
}

impl Deserialize for BaseRoomPolicy {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let policy = Self {
            fixed_membership: Bool::tls_deserialize(bytes)?,
            parent_dependant: Bool::tls_deserialize(bytes)?,
            parent_room: Vec::tls_deserialize(bytes)?,
            multi_device: Bool::tls_deserialize(bytes)?,
            max_clients: Option::tls_deserialize(bytes)?,
            max_users: Option::tls_deserialize(bytes)?,
            pseudonyms_allowed: Bool::tls_deserialize(bytes)?,
            persistent_room: Bool::tls_deserialize(bytes)?,
            discoverable: Bool::tls_deserialize(bytes)?,
            policy_component_ids: Vec::tls_deserialize(bytes)?,
        };
        policy
            .validate()
            .map_err(|error| tls_codec::Error::DecodingError(error.to_string()))?;
        Ok(policy)
    }
}
