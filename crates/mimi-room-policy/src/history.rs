//! The `chat_history_policy` component of room-policy-04 §6.6.

use std::io::Read;

use tls_codec::{Deserialize, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{BANNED_ROLE_INDEX, Bool, NO_ROLE_INDEX, OptionalitySelect, PolicyError, RoleData};

/// The fields of the room-policy-04 §6.6 `HistoryPolicy` that follow a
/// `history_sharing` value of `required` or `optional`. The draft gives
/// this arm no name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct HistorySharing {
    /// `uint32 roles_that_can_share<V>`: the role indexes authorized to
    /// share history, which the §6.6 prose calls `who_can_share`.
    pub roles_that_can_share: Vec<u32>,
    /// `bool automatically_share`. If true, clients may share history with
    /// new joiners without user initiation.
    pub automatically_share: Bool,
    /// `uint32 max_time_period`: how many seconds of history may be shared.
    pub max_time_period: u32,
}

/// The `HistoryPolicy` struct of room-policy-04 §6.6: whether chat history
/// is shared with new joiners, and the data of the `chat_history_policy`
/// component.
///
/// Decoding checks the wire format and [`HistoryPolicy::validate`]. A value
/// built in code is not checked until `validate` is called; encoding does
/// not check it. [`HistoryPolicy::check_roles`] checks the list against the
/// room's `roles_list`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize)]
pub struct HistoryPolicy {
    /// `Optionality history_sharing` and the fields it selects.
    pub history_sharing: OptionalitySelect<HistorySharing>,
}

/// `HistoryPolicy HistoryPolicyData` of room-policy-04 §6.6.
pub type HistoryPolicyData = HistoryPolicy;

/// `HistoryPolicy HistoryPolicyUpdate` of room-policy-04 §6.6: an
/// `AppDataUpdate` that replaces the whole `chat_history_policy` (decision
/// mimid-1wgh.3.20).
pub type HistoryPolicyUpdate = HistoryPolicy;

impl HistoryPolicy {
    /// The `roles_that_can_share` list, empty when `history_sharing` is
    /// `forbidden`.
    fn roles_that_can_share(&self) -> &[u32] {
        self.history_sharing
            .fields()
            .map_or(&[], |sharing| &sharing.roles_that_can_share)
    }

    /// Checks the part of the room-policy-04 §6.6 rule on
    /// `roles_that_can_share` that needs no role list: "The role index zero
    /// (non-participant) and one (banned) cannot be used". Index 1 is
    /// excluded whatever its name (decision mimid-1wgh.3.46).
    ///
    /// # Errors
    ///
    /// [`PolicyError::RoleCannotShareHistory`] for the first index 0 or 1.
    pub fn validate(&self) -> Result<(), PolicyError> {
        // room-policy-04 §6.6; decision mimid-1wgh.3.46
        match self
            .roles_that_can_share()
            .iter()
            .find(|&&index| index == NO_ROLE_INDEX || index == BANNED_ROLE_INDEX)
        {
            Some(&index) => Err(PolicyError::RoleCannotShareHistory(index)),
            None => Ok(()),
        }
    }

    /// Checks the whole room-policy-04 §6.6 rule on `roles_that_can_share`
    /// against the room's role list, with
    /// [`RoleData::check_roles_that_can_share`]: no index 0 or 1, no role
    /// whose `maximum_active_participants_constraint` is zero, and every
    /// listed role defined.
    ///
    /// # Errors
    ///
    /// [`PolicyError::RoleCannotShareHistory`] or
    /// [`PolicyError::UndefinedSharingRole`] for the first offending entry.
    pub fn check_roles(&self, roles: &RoleData) -> Result<(), PolicyError> {
        roles.check_roles_that_can_share(self.roles_that_can_share())
    }
}

impl Deserialize for HistoryPolicy {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let policy = Self {
            history_sharing: OptionalitySelect::tls_deserialize(bytes)?,
        };
        policy
            .validate()
            .map_err(|error| tls_codec::Error::DecodingError(error.to_string()))?;
        Ok(policy)
    }
}
