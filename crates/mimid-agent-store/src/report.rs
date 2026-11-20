//! What a received message keeps for an abuse report (bead mimid-oon0;
//! decisions mimid-1wgh.59, mimid-1wgh.60): for a franked message its
//! protocol-07 §5.9 `AbusiveMessage` (its `application_data` as received,
//! the hub's frank and the acceptance time), for an unfranked one its
//! `application_data` as received and the acceptance time (an
//! `UnverifiedAbusiveMessage`). The plaintext store saves it with the
//! message, so a report works after a restart.
//!
//! # Limitations
//!
//! - The record is kept as hex of the TLS encoding; it is decoded only
//!   when a report is sent, so a record damaged on disk is found then.

use serde::{Deserialize, Serialize};

/// What a received message keeps for a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptFrank {
    /// The room URI.
    pub room: String,
    /// The hex of the TLS-encoded `AbusiveMessage`, or of the
    /// `UnverifiedAbusiveMessage` if `unverified`.
    pub message: String,
    /// The message has no frank (decision mimid-1wgh.60). Absent in a file
    /// written before unfranked messages were kept, which kept only
    /// franked ones.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unverified: bool,
}
