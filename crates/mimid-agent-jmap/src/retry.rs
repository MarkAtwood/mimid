//! Received attachments whose fetch failed for a reason that may pass
//! (bead mimid-1wgh.14.5), retried on later syncs.
//!
//! A message is stored, and the agent's delivery acknowledged, even when
//! an attachment of it cannot be fetched: the message cannot be decrypted
//! again, and its text should not wait for a file. The ExternalPart (its
//! URL, key, nonce and hash: everything needed to fetch and open it) is
//! kept here, in the plaintext store beside the Messages, and each
//! [`crate::AgentChat::sync`] retries the ones that are due. A fetch that
//! succeeds adds the attachment to its Message. One that fails for good
//! (refused, not found, expired, or content that does not open) is given
//! up, as is one still failing after [`MAX_ATTEMPTS`].
//!
//! Which failures may pass: the server could not be reached, or answered
//! 408, 429 or 5xx (the provider or the hub behind it was down), or the
//! blob store could not be written. Everything else is final.
//!
//! The ExternalPart holds the attachment's key, so it is never logged; it
//! lives only in the 0600 plaintext store, which already holds the
//! messages it decrypts.
//!
//! # Limitations
//!
//! - Retries happen only when the client syncs: an idle agent does not
//!   retry.
//! - At most [`MAX_PENDING`] are kept; past that a failed fetch is given
//!   up at once.
//! - A retried attachment is appended to its Message's `attachments`, so
//!   the order can differ from the sender's.

use std::time::{SystemTime, UNIX_EPOCH};

use mimid_agent_core::{AgentError, ExternalPart};
use serde::{Deserialize, Serialize};

/// The most fetch attempts for one attachment, the first included.
/// INVENTED, NOT FROM SPEC.
pub const MAX_ATTEMPTS: u32 = 12;

/// The wait after the first failed attempt; it doubles after each.
/// INVENTED, NOT FROM SPEC.
pub const FIRST_DELAY_SECS: u64 = 30;

/// The longest wait between attempts. INVENTED, NOT FROM SPEC.
pub const MAX_DELAY_SECS: u64 = 3600;

/// The most attachments kept for retry. INVENTED, NOT FROM SPEC.
pub const MAX_PENDING: usize = 256;

/// The most retries one sync makes. INVENTED, NOT FROM SPEC.
pub const MAX_RETRIES_PER_SYNC: usize = 8;

/// Whether a failed fetch may succeed later (see the module
/// documentation).
pub(crate) fn may_pass(error: &AgentError) -> bool {
    match error {
        AgentError::Http { .. } => true,
        AgentError::Status { status, .. } => *status >= 500 || matches!(status, 408 | 429),
        _ => false,
    }
}

/// Seconds since the UNIX epoch.
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The wait after `attempts` failed attempts.
pub(crate) fn delay_after(attempts: u32) -> u64 {
    let doublings = attempts.saturating_sub(1).min(32);
    FIRST_DELAY_SECS
        .saturating_mul(1u64 << doublings)
        .min(MAX_DELAY_SECS)
}

/// An attachment waiting for another fetch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PendingAttachment {
    /// The id of the Message it belongs to.
    pub message: String,
    /// The room the message came from.
    pub room: String,
    /// Its position among the message's attachments, from 1, for reports.
    pub number: u32,
    /// The ExternalPart.
    pub part: StoredPart,
    /// The attempts so far.
    pub attempts: u32,
    /// When the next attempt is due, in seconds since the UNIX epoch.
    pub next_try: u64,
}

impl std::fmt::Debug for PendingAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Not the part: it holds the key.
        f.debug_struct("PendingAttachment")
            .field("message", &self.message)
            .field("number", &self.number)
            .field("attempts", &self.attempts)
            .field("next_try", &self.next_try)
            .finish_non_exhaustive()
    }
}

impl PendingAttachment {
    /// A new entry for `part`, after its first failed attempt.
    pub fn new(message: String, room: String, number: u32, part: &ExternalPart) -> Self {
        Self {
            message,
            room,
            number,
            part: StoredPart::from(part),
            attempts: 1,
            next_try: now_secs().saturating_add(delay_after(1)),
        }
    }
}

/// An ExternalPart (mimi-content-10 §4.5) as JSON; octet strings in hex.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredPart {
    content_type: String,
    url: String,
    expires: u32,
    size: u64,
    enc_alg: u16,
    key: String,
    nonce: String,
    aad: String,
    hash_alg: u8,
    content_hash: String,
    description: String,
    filename: String,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

impl From<&ExternalPart> for StoredPart {
    fn from(part: &ExternalPart) -> Self {
        Self {
            content_type: part.content_type.clone(),
            url: part.url.clone(),
            expires: part.expires,
            size: part.size,
            enc_alg: part.enc_alg,
            key: to_hex(&part.key),
            nonce: to_hex(&part.nonce),
            aad: to_hex(&part.aad),
            hash_alg: part.hash_alg,
            content_hash: to_hex(&part.content_hash),
            description: part.description.clone(),
            filename: part.filename.clone(),
        }
    }
}

impl StoredPart {
    /// The ExternalPart back, or `None` if a hex field was altered.
    pub fn external_part(&self) -> Option<ExternalPart> {
        Some(ExternalPart {
            content_type: self.content_type.clone(),
            url: self.url.clone(),
            expires: self.expires,
            size: self.size,
            enc_alg: self.enc_alg,
            key: from_hex(&self.key)?,
            nonce: from_hex(&self.nonce)?,
            aad: from_hex(&self.aad)?,
            hash_alg: self.hash_alg,
            content_hash: from_hex(&self.content_hash)?,
            description: self.description.clone(),
            filename: self.filename.clone(),
        })
    }
}

impl crate::AgentChat {
    /// Makes every attachment waiting for a retry due, so the next
    /// [`crate::AgentChat::sync`] fetches them again; for when the network
    /// is back. Each retry still counts towards [`MAX_ATTEMPTS`].
    pub fn retry_attachments_now(&self) {
        for entry in self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter_mut()
        {
            entry.next_try = 0;
        }
    }

    /// How many received attachments wait for a retry.
    pub fn pending_attachments(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_doubles_from_thirty_seconds_up_to_an_hour() {
        let waits: Vec<u64> = (1..=9).map(delay_after).collect();
        assert_eq!(waits, [30, 60, 120, 240, 480, 960, 1920, 3600, 3600]);
        assert_eq!(delay_after(u32::MAX), MAX_DELAY_SECS);
    }

    #[test]
    fn only_unreachable_and_server_side_failures_may_pass() {
        let status = |status| AgentError::Status {
            what: "GET assetDownloadUrl".into(),
            status,
            body: String::new(),
        };
        for passing in [500, 502, 503, 504, 408, 429] {
            assert!(may_pass(&status(passing)), "{passing}");
        }
        for fin in [400, 401, 403, 404, 410, 413] {
            assert!(!may_pass(&status(fin)), "{fin}");
        }
        assert!(!may_pass(&AgentError::Invalid(
            "the attachment has expired".into()
        )));
        assert!(!may_pass(&AgentError::Asset(
            mimid_agent_core::asset::AssetError::HashMismatch
        )));
    }

    #[test]
    fn a_stored_part_round_trips_and_altered_hex_is_refused() {
        let part = ExternalPart {
            content_type: "image/png".into(),
            url: "https://b.example/assets/x".into(),
            expires: 7,
            size: 48,
            enc_alg: 1,
            key: vec![0xab; 16],
            nonce: vec![0x01; 12],
            aad: vec![],
            hash_alg: 1,
            content_hash: vec![0x5a; 32],
            description: "d".into(),
            filename: "f.png".into(),
        };
        let stored = StoredPart::from(&part);
        let json = serde_json::to_value(&stored).unwrap();
        assert_eq!(json["key"], serde_json::json!("ab".repeat(16)));
        let back: StoredPart = serde_json::from_value(json).unwrap();
        assert_eq!(back.external_part(), Some(part));
        let mut altered = back;
        altered.nonce = "zz".into();
        assert_eq!(altered.external_part(), None);
    }

    #[test]
    fn the_debug_form_does_not_show_the_key() {
        let part = ExternalPart {
            content_type: String::new(),
            url: String::new(),
            expires: 0,
            size: 0,
            enc_alg: 1,
            key: vec![0xab; 16],
            nonce: vec![],
            aad: vec![],
            hash_alg: 0,
            content_hash: vec![],
            description: String::new(),
            filename: String::new(),
        };
        let pending = PendingAttachment::new("m".into(), "r".into(), 1, &part);
        assert!(!format!("{pending:?}").contains("abab"));
    }
}
