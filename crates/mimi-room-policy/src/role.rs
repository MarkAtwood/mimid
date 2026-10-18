//! The `roles_list` component of room-policy-04 §3.

use std::collections::HashSet;

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::Capability;

/// The `role_index` reserved by room-policy-04 §3 for a participant that is
/// not (or no longer) in the participant list.
pub const NO_ROLE_INDEX: u32 = 0;

/// The `role_index` of the "banned" role (room-policy-04 §8.1.3).
pub const BANNED_ROLE_INDEX: u32 = 1;

/// The `role_name` the "banned" role must have (room-policy-04 §8.1.3).
pub const BANNED_ROLE_NAME: &str = "banned";

/// The `SingleSourceRoleChangeTargets` struct of room-policy-04 §3: the
/// roles a holder may move a participant to from one source role.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct SingleSourceRoleChangeTargets {
    /// `uint32 from_role_index`.
    pub from_role_index: u32,
    /// `uint32 target_role_indexes<V>`.
    pub target_role_indexes: Vec<u32>,
}

/// The `Role` struct of room-policy-04 §3.
///
/// `role_name` and `role_description` are `opaque<V>` that §3 calls text
/// strings; decoding requires UTF-8 and rejects anything else (decision
/// mimid-1wgh.3.41). Neither is normalized, and both may contain any Unicode scalar value, including
/// NUL and bidi controls: rendering them safely is the caller's job.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct Role {
    /// `uint32 role_index`.
    pub role_index: u32,
    /// `opaque role_name<V>`.
    pub role_name: String,
    /// `opaque role_description<V>`, which may be empty.
    pub role_description: String,
    /// `CapabilityType role_capabilities<V>`. Unregistered and private-use
    /// values are kept unchanged.
    pub role_capabilities: Vec<Capability>,
    /// `uint32 minimum_participants_constraint`; zero means no minimum.
    pub minimum_participants_constraint: u32,
    /// `optional uint32 maximum_participants_constraint`; absent means no
    /// maximum.
    pub maximum_participants_constraint: Option<u32>,
    /// `uint32 minimum_active_participants_constraint`; zero means no
    /// minimum.
    pub minimum_active_participants_constraint: u32,
    /// `optional uint32 maximum_active_participants_constraint`; absent
    /// means no maximum, zero means no participant in this role may have a
    /// client in the MLS group.
    pub maximum_active_participants_constraint: Option<u32>,
    /// `SingleSourceRoleChangeTargets authorized_role_changes<V>`.
    pub authorized_role_changes: Vec<SingleSourceRoleChangeTargets>,
}

impl Role {
    /// Whether this is the "banned" role of §8.1.3: `role_index` 1 and
    /// `role_name` exactly `banned`.
    ///
    /// A role 1 with any other name is allowed; it is simply not the
    /// banned role (decision mimid-1wgh.3.42).
    pub fn is_banned_role(&self) -> bool {
        self.role_index == BANNED_ROLE_INDEX && self.role_name == BANNED_ROLE_NAME
    }
}

/// The `RoleData` struct of room-policy-04 §3: the data of the
/// `roles_list` component.
///
/// Decoding checks only the wire format. Call [`RoleData::validate`] before
/// trusting the contents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct RoleData {
    /// `Role roles<V>`.
    pub roles: Vec<Role>,
}

/// `RoleData RoleUpdate` of room-policy-04 §3: an `AppDataUpdate` that
/// replaces the whole `roles_list` (decision mimid-1wgh.3.20).
pub type RoleUpdate = RoleData;

/// A rule of room-policy-04 that a policy component breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// Two roles have the same `role_index` (§3).
    #[error("role_index {0} is defined more than once")]
    DuplicateRoleIndex(u32),
    /// A role refers to a non-zero `role_index` that no role defines.
    #[error("role {role_index} refers to undefined role_index {referenced}")]
    UndefinedRoleIndex {
        /// The role holding the reference.
        role_index: u32,
        /// The undefined index.
        referenced: u32,
    },
    /// `canOpenJoin` is on a non-zero role (§8.1.1).
    #[error("role {0} holds canOpenJoin, which only role 0 may hold")]
    OpenJoinOnNonZeroRole(u32),
    /// A non-zero, non-banned role holds `canAddParticipant` in a
    /// fixed-membership room (§5).
    #[error("role {0} holds canAddParticipant in a fixed-membership room")]
    AddParticipantInFixedMembershipRoom(u32),
    /// `roles_that_can_share` names role 0, role 1, or a role whose
    /// `maximum_active_participants_constraint` is zero (§6.6).
    #[error("role {0} cannot be in roles_that_can_share")]
    RoleCannotShareHistory(u32),
    /// `roles_that_can_share` names a role that no role defines.
    #[error("roles_that_can_share names undefined role_index {0}")]
    UndefinedSharingRole(u32),
    /// A `BaseRoomPolicy` `parent_room` does not hold exactly one
    /// non-empty `Uri` when `parent_dependant` is true, or is not empty
    /// when it is false (§5).
    #[error("parent_room does not match parent_dependant")]
    ParentRoomMismatch,
    /// A `JoinLinksUpdate` `removedIndices` entry is not an index into the
    /// list before the update (§6.2; decision mimid-1wgh.3.19).
    #[error("removedIndices entry {0} is out of range")]
    RemovedIndexOutOfRange(u32),
    /// A `JoinLinksUpdate` `removedIndices` entry appears more than once
    /// (§6.2; decision mimid-1wgh.3.19).
    #[error("removedIndices entry {0} appears more than once")]
    DuplicateRemovedIndex(u32),
    /// A `LinkPreviewPolicy` `autodetect_hyperlinks_in_text` is `required`
    /// (§6.3; decision mimid-1wgh.3.13).
    #[error("autodetect_hyperlinks_in_text is required")]
    AutodetectHyperlinksRequired,
    /// A `LinkPreviewPolicy` `link_preview_proxy_use` is `required` or
    /// `optional` but `link_preview_proxy` holds no non-empty `Uri`
    /// (§6.3).
    #[error("link_preview_proxy holds no URI")]
    MissingLinkPreviewProxy,
    /// An `AssetPolicy` `asset_upload_location` is `hub` but
    /// `upload_domains` does not hold exactly one entry (§6.4). The value
    /// is the number of entries.
    #[error("asset_upload_location is hub but upload_domains holds {0} entries, not 1")]
    HubUploadDomainCount(usize),
    /// A `LoggingPolicy` `logging` is `required` but `logging_clients`
    /// holds no non-empty `Uri` (§6.5).
    #[error("logging is required but logging_clients holds no URI")]
    MissingLoggingClient,
    /// A `Bot` has `local_client_bot` true and a non-zero
    /// `bot_role_index` (§6.7).
    #[error("allowed_bots entry {bot} is a local client bot with bot_role_index {bot_role_index}")]
    LocalClientBotWithRole {
        /// The position of the bot in `allowed_bots`.
        bot: usize,
        /// Its `bot_role_index`.
        bot_role_index: u32,
    },
}

impl RoleData {
    /// The role with `role_index`, or `None` if there is none.
    ///
    /// After a successful [`RoleData::validate`] there is at most one.
    pub fn role(&self, role_index: u32) -> Option<&Role> {
        self.roles.iter().find(|role| role.role_index == role_index)
    }

    /// Checks the structural rules room-policy-04 states for a role list.
    ///
    /// Pass the room's [`crate::BaseRoomPolicy::fixed_membership`] (§5).
    ///
    /// The rules are:
    /// - every `role_index` is unique (§3);
    /// - every non-zero `from_role_index` and `target_role_indexes` entry
    ///   names a defined role; index 0 always has its §3 meaning, so it
    ///   need not be defined;
    /// - only role 0 holds `canOpenJoin` (§8.1.1);
    /// - if `fixed_membership`, no role other than role 0 and the "banned"
    ///   role ([`Role::is_banned_role`]) holds `canAddParticipant` (§5).
    ///
    /// Conditions §8.1 attaches to a single action, such as the need for
    /// an `authorized_role_changes` entry with `from_role_index` 0, are
    /// checked when the action is authorized, not here (decision
    /// mimid-1wgh.3.43).
    ///
    /// # Errors
    ///
    /// The [`PolicyError`] for the first rule broken, checking roles in
    /// list order.
    pub fn validate(&self, fixed_membership: bool) -> Result<(), PolicyError> {
        let mut defined = HashSet::new();
        for role in &self.roles {
            if !defined.insert(role.role_index) {
                return Err(PolicyError::DuplicateRoleIndex(role.role_index));
            }
        }
        for role in &self.roles {
            let references = role.authorized_role_changes.iter().flat_map(|change| {
                std::iter::once(&change.from_role_index).chain(&change.target_role_indexes)
            });
            for &referenced in references {
                // A dangling reference would give a participant a role with
                // no capabilities or constraints; §3 index 0 is exempt.
                // room-policy-04 §3; decision mimid-1wgh.3.40
                if referenced != NO_ROLE_INDEX && !defined.contains(&referenced) {
                    return Err(PolicyError::UndefinedRoleIndex {
                        role_index: role.role_index,
                        referenced,
                    });
                }
            }
            let holds = |capability| role.role_capabilities.contains(&capability);
            if role.role_index != NO_ROLE_INDEX && holds(Capability::CAN_OPEN_JOIN) {
                return Err(PolicyError::OpenJoinOnNonZeroRole(role.role_index));
            }
            // room-policy-04 §5 "non-banned" means is_banned_role();
            // decision mimid-1wgh.3.44
            if fixed_membership
                && role.role_index != NO_ROLE_INDEX
                && !role.is_banned_role()
                && holds(Capability::CAN_ADD_PARTICIPANT)
            {
                return Err(PolicyError::AddParticipantInFixedMembershipRoom(
                    role.role_index,
                ));
            }
        }
        Ok(())
    }

    /// Checks a `HistoryPolicy` `roles_that_can_share` list against this
    /// role list (§6.6).
    ///
    /// Role 0, role 1 and any role whose
    /// `maximum_active_participants_constraint` is zero may not appear,
    /// and every listed role must be defined.
    ///
    /// # Errors
    ///
    /// [`PolicyError::RoleCannotShareHistory`] or
    /// [`PolicyError::UndefinedSharingRole`] for the first offending entry.
    pub fn check_roles_that_can_share(
        &self,
        roles_that_can_share: &[u32],
    ) -> Result<(), PolicyError> {
        for &role_index in roles_that_can_share {
            // room-policy-04 §6.6 excludes index 1 whatever its name;
            // decision mimid-1wgh.3.46
            if role_index == NO_ROLE_INDEX || role_index == BANNED_ROLE_INDEX {
                return Err(PolicyError::RoleCannotShareHistory(role_index));
            }
            // room-policy-04 §6.6; decision mimid-1wgh.3.40
            let role = self
                .role(role_index)
                .ok_or(PolicyError::UndefinedSharingRole(role_index))?;
            if role.maximum_active_participants_constraint == Some(0) {
                return Err(PolicyError::RoleCannotShareHistory(role_index));
            }
        }
        Ok(())
    }
}
