//! Received edits and retractions (mimi-content-10 §5.5, §5.6;
//! draft-atwood-jmap-chat-mimi-00 §Edits; decision mimid-1wgh.65): a
//! received message with `replaces` changes the message it names, and its
//! own reference octets become an alias of that message, so a reply to
//! any version resolves to it.
//!
//! # Limitations
//!
//! - Only the original sender may edit or retract a message (content-10
//!   §9.3). room-policy-04 §8.3 `canDeleteOtherMessage` (a moderator's
//!   retraction) is not honored, and `canEditOwnMessage` and
//!   `canDeleteOwnMessage` are not checked: the agent evaluates no message
//!   capability on receive.
//! - An edit's attachments are not applied (a message's attachments are
//!   set when it is stored); they are reported in
//!   [`super::SyncReport::problems`].
//! - An edit or retraction of a message not stored here (sent before this
//!   device joined, skipped, or deleted here) is dropped and listed in
//!   [`super::SyncReport::skipped`]; it is not held.
//! - A retracted message's kept report record is dropped with its
//!   content, so it cannot be reported. Its attachment blobs stay in the
//!   blob store.

use mimi_content::{MessageId, Part};
use mimid_agent_core::ReceivedMessage;

use super::{SyncReport, keep_reportable};
use crate::change::Change;
use crate::content::BodyType;
use crate::convert::message_ref;
use crate::record::Sender;
use crate::store::Store;

/// The most revisions a message's edit history keeps; past it the oldest
/// is dropped (draft-atwood-jmap-chat-00 §Message: "Servers MAY limit the
/// number of retained revisions"). INVENTED, NOT FROM SPEC: the value.
pub const MAX_EDIT_HISTORY: usize = 32;

/// The most aliases one message has; an edit or retraction past it is
/// refused (decision mimid-1wgh.65). INVENTED, NOT FROM SPEC.
pub const MAX_ALIASES: usize = 256;

/// What a received replacement does.
enum Replacement {
    /// A NullPart body: the message is retracted.
    Retraction,
    /// The new text and body type, and how many attachments are left out.
    Edit(String, BodyType, usize),
}

impl Store {
    /// Applies `received`, whose `replaces` is set, in room `room`
    /// (decision mimid-1wgh.65): an edit or retraction by the original
    /// sender changes the message `replaces` resolves to; one by anyone
    /// else is refused and reported in `report.problems`; one of a message
    /// not stored here, or already deleted, is listed in `report.skipped`.
    pub(crate) fn apply_replacement(
        &self,
        room: &str,
        replaces: &MessageId,
        received: &ReceivedMessage,
        report: &mut SyncReport,
        changes: &mut Vec<Change>,
    ) {
        let uri = &received.room;
        let mut state = self.state();
        let target = state.message_of_ref(room, &message_ref(replaces)).cloned();
        let Some(stored) = target.and_then(|key| state.messages.get(&key).cloned()) else {
            report.skipped.push(format!(
                "{uri}: an edit or retraction of a message not stored here"
            ));
            return;
        };
        // A notice is the account's own message to a JMAP client, as it
        // was before the store.
        let original_sender = match &stored.sender {
            Sender::User(user) => user.as_str(),
            Sender::Agent => self.user.as_str(),
        };
        // content-10 §9.3: "Receiving clients MUST NOT allow parties other
        // than the original sender of a message to edit or delete that
        // message"; jmap-chat-mimi-00 §Security: verify before recording
        // the alias.
        if original_sender != received.sender {
            report.problems.push(format!(
                "{uri}: refused an edit or retraction by {} of a message it did not send",
                received.sender
            ));
            return;
        }
        if stored.deleted.is_some() {
            report.skipped.push(format!(
                "{uri}: an edit or retraction of a retracted message"
            ));
            return;
        }
        if stored.aliases.len() >= MAX_ALIASES {
            report.problems.push(format!(
                "{uri}: refused an edit or retraction: the message has {MAX_ALIASES} versions"
            ));
            return;
        }
        let content = &received.content;
        let replacement = match (&content.nested_part.part, received.text.clone()) {
            (Part::Null, _) => Replacement::Retraction,
            (_, text) => {
                let attachments = received.attachments().len();
                match text {
                    Some(text) => {
                        Replacement::Edit(text, crate::content::body_type(content), attachments)
                    }
                    None if attachments > 0 => {
                        Replacement::Edit(String::new(), BodyType::Plain, attachments)
                    }
                    None => {
                        report
                            .skipped
                            .push(format!("{uri}: an edit with neither text nor attachments"));
                        return;
                    }
                }
            }
        };
        let at = received.accepted_at;
        let key = stored.key.clone();
        match replacement {
            Replacement::Retraction => {
                state.retract_message(&key, at);
            }
            Replacement::Edit(text, body_type, attachments) => {
                if attachments > 0 {
                    report.problems.push(format!(
                        "{uri}: {attachments} attachments of an edit left out: \
                         a Message's attachments are set when it is created"
                    ));
                }
                // What is reported is what is shown: the latest version.
                let kept = keep_reportable(received, report);
                state.edit_message(&key, text, body_type, at);
                if let Some(message) = state.messages.get_mut(&key)
                    && kept.is_some()
                {
                    message.kept_frank = kept;
                }
            }
        }
        state.add_alias(&key, &received.message_id);
        changes.push(Change::MessageChanged(key));
        report.edits += 1;
    }
}
