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
//! blob store could not be written. Everything else is final. The policy
//! and its constants are [`mimid_agent_store::retry`]'s, re-exported here.
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

pub use mimid_agent_store::retry::{
    FIRST_DELAY_SECS, MAX_ATTEMPTS, MAX_DELAY_SECS, MAX_PENDING, MAX_RETRIES_PER_SYNC,
};

impl crate::AgentChat {
    /// Makes every attachment waiting for a retry due, so the next
    /// [`crate::AgentChat::sync`] fetches them again; for when the network
    /// is back. Each retry still counts towards [`MAX_ATTEMPTS`].
    pub fn retry_attachments_now(&self) {
        self.store.retry_attachments_now();
    }

    /// How many received attachments wait for a retry.
    pub fn pending_attachments(&self) -> usize {
        self.store.pending_attachments()
    }
}
