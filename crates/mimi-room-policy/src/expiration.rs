//! The `message_expiration_policy` component of room-policy-04 §6.8.

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::OptionalitySelect;

/// The fields of the room-policy-04 §6.8 `MessageExpiration` that follow an
/// `expiring_messages` value of `required` or `optional`. The draft gives
/// this arm no name.
///
/// §6.8 does not state that the minimum is at most the maximum, or that the
/// default lies between them, so neither is checked (decision
/// mimid-1wgh.3.64).
// room-policy-04 §6.8; decision mimid-1wgh.3.64
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct ExpirationDurations {
    /// `uint32 min_expiration_duration`: the shortest acceptable expiration
    /// duration, in seconds.
    pub min_expiration_duration: u32,
    /// `uint32 max_expiration_duration`: the longest acceptable expiration
    /// duration, in seconds.
    pub max_expiration_duration: u32,
    /// `optional uint32 default_expiration_duration`: the preferred
    /// duration in seconds, if any.
    pub default_expiration_duration: Option<u32>,
}

/// The `MessageExpiration` struct of room-policy-04 §6.8: whether messages
/// expire automatically, and the data of the `message_expiration_policy`
/// component.
///
/// When `expiring_messages` is `forbidden` no further fields are encoded,
/// which is how the §6.8 rule that the durations are then zero and the
/// default absent holds.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct MessageExpiration {
    /// `Optionality expiring_messages` and the fields it selects.
    pub expiring_messages: OptionalitySelect<ExpirationDurations>,
}

/// `MessageExpiration MessageExpirationData` of room-policy-04 §6.8.
pub type MessageExpirationData = MessageExpiration;

/// `MessageExpiration MessageExpirationUpdate` of room-policy-04 §6.8: an
/// `AppDataUpdate` that replaces the whole `message_expiration_policy`
/// (decision mimid-1wgh.3.20).
pub type MessageExpirationUpdate = MessageExpiration;
