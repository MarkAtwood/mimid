//! Received attachments (bead mimid-1wgh.14): fetched through the user's
//! server and decrypted (`Agent::fetch_attachment`), put in the blob
//! store, and listed in their message with the part's file name (made
//! safe) and media type and the plaintext's size and SHA-256. A fetch
//! that may pass later is kept and retried ([`crate::retry`]).
//!
//! # Limitations
//!
//! - Without a blob store every received attachment is left out.
//! - A received attachment's media type is not checked against its
//!   content, and an invalid one becomes [`FALLBACK_CONTENT_TYPE`].
//! - Attachments are fetched one at a time while the sync holds the
//!   agent.

use mimi_content::ExternalPart;
use mimid_agent_core::Agent;

use super::SyncReport;
use crate::blobs::{hex, is_media_type};
use crate::change::Change;
use crate::content::safe_filename;
use crate::record::Attachment;
use crate::retry::{MAX_ATTEMPTS, MAX_RETRIES_PER_SYNC, PendingAttachment, delay_after, now_secs};
use crate::store::Store;

/// The most attachments one message carries, sent or received.
/// INVENTED, NOT FROM SPEC.
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 8;

/// The media type of a received attachment whose own is not one.
pub const FALLBACK_CONTENT_TYPE: &str = "application/octet-stream";

impl Store {
    /// Fetches, opens and stores the attachments `parts` of a message in
    /// `room`. Also returns, by position, the ones whose fetch failed in a
    /// way that may pass, for [`crate::retry`]. Any other failure is
    /// reported in `report.problems` and left out, as are those past
    /// [`MAX_ATTACHMENTS_PER_MESSAGE`] and all of them without a blob
    /// store.
    pub(crate) async fn fetch_attachments(
        &self,
        // Not &Agent: that is not Send across an await.
        agent: &mut Agent,
        room: &str,
        parts: &[&ExternalPart],
        report: &mut SyncReport,
    ) -> (Vec<Attachment>, Vec<(u32, ExternalPart)>) {
        if parts.is_empty() {
            return (Vec::new(), Vec::new());
        }
        if self.blobs.get().is_none() {
            report.problems.push(format!(
                "{room}: {} attachments left out: no blob store",
                parts.len()
            ));
            return (Vec::new(), Vec::new());
        }
        if parts.len() > MAX_ATTACHMENTS_PER_MESSAGE {
            report.problems.push(format!(
                "{room}: {} attachments past the first {MAX_ATTACHMENTS_PER_MESSAGE} left out",
                parts.len() - MAX_ATTACHMENTS_PER_MESSAGE
            ));
        }
        let mut attachments = Vec::with_capacity(parts.len().min(MAX_ATTACHMENTS_PER_MESSAGE));
        let mut retry = Vec::new();
        // Problems name an attachment by its position, not its file name:
        // the daemon logs them, and a file name is message content.
        for (number, part) in (1..).zip(parts.iter().take(MAX_ATTACHMENTS_PER_MESSAGE)) {
            match self.fetch_one(agent, room, part).await {
                Ok(attachment) => attachments.push(attachment),
                Err((e, true)) => {
                    report.problems.push(format!(
                        "{room}: attachment {number} not fetched yet, will retry: {e}"
                    ));
                    retry.push((number, (*part).clone()));
                }
                Err((e, false)) => report
                    .problems
                    .push(format!("{room}: attachment {number} left out: {e}")),
            }
        }
        (attachments, retry)
    }

    /// Fetches, opens and stores one attachment. The error says whether it
    /// may pass ([`crate::retry`]; a blob store write failure may).
    async fn fetch_one(
        &self,
        agent: &mut Agent,
        room: &str,
        part: &ExternalPart,
    ) -> Result<Attachment, (String, bool)> {
        let Some(blobs) = self.blobs.get() else {
            return Err(("no blob store".to_owned(), false));
        };
        let plaintext = agent
            .fetch_attachment(room, part)
            .await
            .map_err(|e| (e.to_string(), crate::retry::may_pass(&e)))?;
        let info = blobs.put(&plaintext).map_err(|e| (e.to_string(), true))?;
        let media_type = if is_media_type(&part.content_type) {
            part.content_type.clone()
        } else {
            FALLBACK_CONTENT_TYPE.to_owned()
        };
        Ok(Attachment {
            blob_id: info.id.to_string(),
            file_name: safe_filename(&part.filename),
            media_type,
            size: info.size,
            sha256: hex(&info.sha256),
        })
    }

    /// Fetches again up to [`MAX_RETRIES_PER_SYNC`] pending attachments
    /// that are due; one that arrives is added to its message. Returns
    /// whether the pending list or a message changed.
    pub(crate) async fn retry_attachments(
        &self,
        agent: &mut Agent,
        report: &mut SyncReport,
        changes: &mut Vec<Change>,
    ) -> bool {
        let now = now_secs();
        let due: Vec<PendingAttachment> = self
            .state()
            .pending_attachments
            .iter()
            .filter(|p| p.next_try <= now)
            .take(MAX_RETRIES_PER_SYNC)
            .cloned()
            .collect();
        if due.is_empty() {
            return false;
        }
        for entry in due {
            let (room, number) = (entry.room.clone(), entry.number);
            let outcome = match entry.part.external_part() {
                None => Err(("the kept part is damaged".to_owned(), false)),
                Some(part) => self.fetch_one(agent, &room, &part).await,
            };
            let mut state = self.state();
            // The entry leaves the list unless it is kept for another try.
            let mut keep = None;
            match outcome {
                Ok(attachment) => {
                    // None: the message was deleted meanwhile.
                    if let Some(message) = state.messages.get_mut(&entry.message) {
                        message.attachments.push(attachment);
                        changes.push(Change::MessageChanged(entry.message.clone()));
                        report.attachments_retried += 1;
                    }
                }
                Err((e, true)) if entry.attempts + 1 < MAX_ATTEMPTS => {
                    let attempts = entry.attempts + 1;
                    keep = Some(PendingAttachment {
                        attempts,
                        next_try: now.saturating_add(delay_after(attempts)),
                        ..entry.clone()
                    });
                    report.problems.push(format!(
                        "{room}: attachment {number} still not fetched, will retry: {e}"
                    ));
                }
                Err((e, _)) => report
                    .problems
                    .push(format!("{room}: attachment {number} given up: {e}")),
            }
            let pending = &mut state.pending_attachments;
            if let Some(index) = pending.iter().position(|p| *p == entry) {
                match keep {
                    Some(updated) => pending[index] = updated,
                    None => {
                        pending.remove(index);
                    }
                }
            }
        }
        true
    }
}
