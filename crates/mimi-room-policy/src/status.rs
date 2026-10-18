//! The `status_notification_policy` component of room-policy-04 §6.1.

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::Optionality;

/// The `StatusNotificationPolicy` struct of room-policy-04 §6.1: whether
/// clients send delivery notifications and read receipts in the room, and
/// the data of the `status_notification_policy` component.
///
/// For [`Optionality::Optional`], each client follows its local
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct StatusNotificationPolicy {
    /// `Optionality delivery_notifications`.
    pub delivery_notifications: Optionality,
    /// `Optionality read_receipts`.
    pub read_receipts: Optionality,
}

/// `StatusNotificationPolicy StatusNotificationPolicyData` of
/// room-policy-04 §6.1.
pub type StatusNotificationPolicyData = StatusNotificationPolicy;

/// `StatusNotificationPolicy StatusNotificationPolicyUpdate` of
/// room-policy-04 §6.1: an `AppDataUpdate` that replaces the whole
/// component (decision mimid-1wgh.3.20).
pub type StatusNotificationPolicyUpdate = StatusNotificationPolicy;
