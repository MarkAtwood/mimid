//! Edits and retractions (mimi-content-10 §5.5, §5.6; draft-atwood-jmap-
//! chat-mimi-00 §Edits; decision mimid-1wgh.65): a received message with
//! `replaces` changes the Message it names, and the owner's `Message/set`
//! edit or `deletedForAll` goes to the room as one.
//!
//! A MIMI `replaces` is a whole 32-octet message ID, and a Message keeps
//! only octets 1 through 10 of it (`senderMsgId`). So each Message's first
//! version's message ID, and the reference octets of its later versions
//! (its aliases, §Edits), are kept beside it in a `MimiIds` record, in the
//! plaintext store (`persist`). INVENTED, NOT FROM SPEC: that
//! record; it is not a Message property.
//!
//! # Limitations
//!
//! - Only the original sender may edit or retract a message (content-10
//!   §9.3). room-policy-04 §8.3 `canDeleteOtherMessage` (a moderator's
//!   retraction) is not honored, and `canEditOwnMessage` and
//!   `canDeleteOwnMessage` are not checked: the agent evaluates no message
//!   capability on receive.
//! - An edit's attachments are not applied (a Message's `attachments` are
//!   set when it is created, draft-atwood-jmap-chat-00); they are reported
//!   in [`SyncReport::problems`].
//! - An edit or retraction of a message not stored here (sent before this
//!   device joined, skipped, or destroyed by the client) is dropped and
//!   listed in [`SyncReport::skipped`]; it is not held.
//! - A retracted Message's kept report record is dropped with its content,
//!   so it cannot be reported. Its attachment blobs stay in the blob store.
//! - A Message stored before these records were kept has no first-version
//!   ID, so the owner cannot edit or retract it.

use jmap_chat_types::{BodyType, Message};
use jmap_server::{BackendSetError, Id, UTCDate};
use mimi_content::{MessageId, Part};
use mimid_agent_core::ReceivedMessage;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::backend::{AgentChat, agent_failure, forbidden, serde_failure};
use crate::convert::{MessageRef, message_ref, utc_date};
use crate::sync::{SyncError, SyncReport, body_type};
use jmap_chat_server::ChatStore;
use jmap_chat_server::memory::MemoryError;

/// The most revisions a Message's `editHistory` keeps; past it the oldest
/// is dropped (draft-atwood-jmap-chat-00 §Message: "Servers MAY limit the
/// number of retained revisions"). INVENTED, NOT FROM SPEC: the value.
pub const MAX_EDIT_HISTORY: usize = 32;

/// The most aliases one Message has; an edit or retraction past it is
/// refused (decision mimid-1wgh.65). INVENTED, NOT FROM SPEC.
pub const MAX_ALIASES: usize = 256;

/// The MIMI message IDs of one Message, kept in the plaintext store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MimiIds {
    /// The hex of the first version's message ID. Absent for a Message
    /// that does not come from a MIMI message of its own (an identity
    /// notice) but was edited anyway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first: Option<String>,
    /// The hex of the reference octets of each later version, oldest
    /// first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    aliases: Vec<String>,
}

impl MimiIds {
    /// The first version's message ID, if kept and well formed.
    fn first(&self) -> Option<MessageId> {
        let bytes = hex::decode(self.first.as_deref()?).ok()?;
        Some(MessageId(bytes.try_into().ok()?))
    }

    /// The aliases that are well formed.
    pub(crate) fn aliases(&self) -> impl Iterator<Item = MessageRef> + '_ {
        self.aliases
            .iter()
            .filter_map(|a| hex::decode(a).ok()?.try_into().ok())
    }
}

/// What a received replacement does.
enum Replacement {
    /// A NullPart body: the message is retracted.
    Retraction,
    /// The new text and body type, and how many attachments are left out.
    Edit(String, BodyType, usize),
}

impl AgentChat {
    fn mimi_ids(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<String, MimiIds>> {
        self.mimi_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Keeps `first` as the first version's message ID of Message
    /// `message`.
    pub(crate) fn keep_first_id(&self, message: &Id, first: &MessageId) {
        self.mimi_ids()
            .entry(message.as_ref().to_owned())
            .or_default()
            .first = Some(hex::encode(first.0));
    }

    /// The number of aliases of Message `message`.
    fn alias_count(&self, message: &Id) -> usize {
        self.mimi_ids()
            .get(message.as_ref())
            .map_or(0, |ids| ids.aliases.len())
    }

    /// Records `version`'s reference octets as an alias of Message
    /// `message` in `chat`, so references to that version resolve to it
    /// (§Edits).
    fn add_alias(&self, chat: &Id, message: &Id, version: &MessageId) {
        let reference = message_ref(version);
        self.link_message(chat, reference, message);
        self.mimi_ids()
            .entry(message.as_ref().to_owned())
            .or_default()
            .aliases
            .push(hex::encode(reference));
    }

    /// The kept MIMI IDs of Message `message`.
    pub(crate) fn kept_ids(&self, message: &str) -> Option<MimiIds> {
        self.mimi_ids().get(message).cloned()
    }

    /// Applies a received message whose `replaces` is set, in Chat `chat`
    /// (decision mimid-1wgh.65): an edit or retraction by the original
    /// sender changes the Message `replaces` resolves to; one by anyone
    /// else is refused and reported in `report.problems`; one of a message
    /// not stored here, or already retracted, is listed in
    /// `report.skipped`.
    pub(crate) async fn apply_replacement(
        &self,
        chat: &Id,
        replaces: &MessageId,
        received: &ReceivedMessage,
        report: &mut SyncReport,
    ) -> Result<(), SyncError> {
        let room = &received.room;
        let target = self
            .links()
            .messages
            .get(&(chat.as_ref().to_owned(), message_ref(replaces)))
            .cloned();
        let stored = match target {
            Some(id) => self.stored::<Message>(&id).await?,
            None => None,
        };
        let Some(stored) = stored else {
            report.skipped.push(format!(
                "{room}: an edit or retraction of a message not stored here"
            ));
            return Ok(());
        };
        let original_sender = if stored.sender_id == self.account {
            Some(self.user.clone())
        } else {
            self.contact_identity(&stored.sender_id).await?
        };
        // content-10 §9.3: "Receiving clients MUST NOT allow parties other
        // than the original sender of a message to edit or delete that
        // message"; jmap-chat-mimi-00 §Security: verify before recording
        // the alias.
        if original_sender.as_deref() != Some(received.sender.as_str()) {
            report.problems.push(format!(
                "{room}: refused an edit or retraction by {} of a message it did not send",
                received.sender
            ));
            return Ok(());
        }
        if stored.deleted_at.is_some() {
            report.skipped.push(format!(
                "{room}: an edit or retraction of a retracted message"
            ));
            return Ok(());
        }
        if self.alias_count(&stored.id) >= MAX_ALIASES {
            report.problems.push(format!(
                "{room}: refused an edit or retraction: the message has {MAX_ALIASES} versions"
            ));
            return Ok(());
        }
        let content = &received.content;
        let replacement = match (&content.nested_part.part, received.text.clone()) {
            (Part::Null, _) => Replacement::Retraction,
            (_, text) => {
                let attachments = received.attachments().len();
                match text {
                    Some(text) => Replacement::Edit(text, body_type(content), attachments),
                    None if attachments > 0 => {
                        Replacement::Edit(String::new(), BodyType::Plain, attachments)
                    }
                    None => {
                        report
                            .skipped
                            .push(format!("{room}: an edit with neither text nor attachments"));
                        return Ok(());
                    }
                }
            }
        };
        let at = utc_date(received.accepted_at);
        let patch = match replacement {
            Replacement::Retraction => {
                // The content goes with the deletion: the kept report
                // record and any attachment still to fetch.
                self.franks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(stored.id.as_ref());
                self.pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retain(|p| p.message != stored.id.as_ref());
                retraction_patch(&at)
            }
            Replacement::Edit(text, body_type, attachments) => {
                if attachments > 0 {
                    report.problems.push(format!(
                        "{room}: {attachments} attachments of an edit left out: \
                         a Message's attachments are set when it is created"
                    ));
                }
                // What is reported is what is shown: the latest version.
                self.keep_reportable(&stored.id, received, report);
                edit_patch(&stored, &text, &body_type, &at)
                    .map_err(|e| SyncError::Store(e.to_string()))?
            }
        };
        let patch = serde_json::from_value(patch).map_err(|e| SyncError::Store(e.to_string()))?;
        self.inner
            .update_object::<Message>(&(), &self.account, &stored.id, patch)
            .await?;
        self.add_alias(chat, &stored.id, &received.message_id);
        report.edits += 1;
        Ok(())
    }

    /// The owner's `Message/set` update `patch` of Message `id`, as the
    /// handler passes it: an edit (`body`, `bodyType`) or a retraction
    /// (`deletedForAll: true`) is sent to the room first (decision
    /// mimid-1wgh.65), and the patch to store is returned, with the hub's
    /// acceptance time as `editedAt` or `deletedAt` and, for an edit, the
    /// old body in `editHistory`. `None` for any other update, and for a
    /// local deletion (`deletedAt` alone), which stay local. crate-jmap has
    /// already checked that the owner sent the Message and that it is not
    /// deleted.
    pub(crate) async fn send_change(
        &self,
        id: &Id,
        patch: &Value,
    ) -> Result<Option<Value>, BackendSetError<MemoryError>> {
        let retracts = patch.get("deletedForAll").and_then(Value::as_bool) == Some(true);
        let deletes_locally = patch.get("deletedAt").is_some_and(|v| !v.is_null());
        let edits = patch.get("body").is_some() || patch.get("bodyType").is_some();
        if !retracts && (deletes_locally || !edits) {
            return Ok(None);
        }
        let Some(stored) = self
            .stored::<Message>(id)
            .await
            .map_err(BackendSetError::Other)?
        else {
            return Ok(None);
        };
        let Some(room) = self.room_of_chat(&stored.chat_id) else {
            return Ok(None);
        };
        let Some(first) = self.kept_ids(id.as_ref()).and_then(|ids| ids.first()) else {
            return Err(forbidden(
                "no MIMI message ID is kept for this Message, so it cannot be edited or retracted",
            ));
        };
        if self.alias_count(id) >= MAX_ALIASES {
            return Err(forbidden("the Message has too many versions"));
        }
        let mut patch = patch.clone();
        let mut agent = self.agent.lock().await;
        if retracts {
            let sent = agent
                .send_retraction(&room, &first)
                .await
                .map_err(agent_failure)?;
            drop(agent);
            self.add_alias(&stored.chat_id, id, &sent.message_id);
            if let Some(obj) = patch.as_object_mut() {
                obj.insert("deletedAt".to_owned(), json!(utc_date(sent.accepted_at)));
            }
        } else {
            let text = patch
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or(&stored.body)
                .to_owned();
            let sent = agent
                .send_edit(&room, &first, &text)
                .await
                .map_err(agent_failure)?;
            drop(agent);
            self.add_alias(&stored.chat_id, id, &sent.message_id);
            let body_type = match patch.get("bodyType") {
                Some(v) => serde_json::from_value(v.clone()).map_err(serde_failure)?,
                None => stored.body_type.clone(),
            };
            let edit = edit_patch(&stored, &text, &body_type, &utc_date(sent.accepted_at))
                .map_err(serde_failure)?;
            if let (Some(obj), Value::Object(edit)) = (patch.as_object_mut(), edit) {
                obj.extend(edit);
            }
        }
        Ok(Some(patch))
    }
}

/// The patch retracting a Message at `at` (draft-atwood-jmap-chat-00
/// §Message `deletedAt`: `body` and `attachments` empty, no `editHistory`).
fn retraction_patch(at: &UTCDate) -> Value {
    json!({
        "deletedAt": at,
        "deletedForAll": true,
        "body": "",
        "attachments": [],
        "editHistory": null,
    })
}

/// The patch editing `stored` to `text` of `body_type` at `at`
/// (draft-atwood-jmap-chat-00 §Editing a Message): its old body becomes
/// the last of at most [`MAX_EDIT_HISTORY`] MessageRevisions.
fn edit_patch(
    stored: &Message,
    text: &str,
    body_type: &BodyType,
    at: &UTCDate,
) -> Result<Value, serde_json::Error> {
    let mut history = match &stored.edit_history {
        Some(history) => serde_json::to_value(history)?,
        None => json!([]),
    };
    if let Value::Array(revisions) = &mut history {
        // MessageRevision is #[non_exhaustive]: built as JSON.
        revisions.push(json!({
            "body": stored.body,
            "bodyType": stored.body_type,
            "editedAt": at,
        }));
        let excess = revisions.len().saturating_sub(MAX_EDIT_HISTORY);
        revisions.drain(..excess);
    }
    Ok(json!({
        "body": text,
        "bodyType": body_type,
        "editedAt": at,
        "editHistory": history,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(body: &str) -> Message {
        Message::new(
            Id::from("m"),
            Id::from("01HF7YAT01041061050R3GG28A"),
            Id::from("alice"),
            Id::from("c"),
            body.to_owned(),
            BodyType::Plain,
            UTCDate::from("2026-11-16T12:00:00Z"),
            UTCDate::from("2026-11-16T12:00:00Z"),
            jmap_chat_types::DeliveryState::Delivered,
        )
    }

    /// Oracle: draft-atwood-jmap-chat-00 §Editing a Message steps 1 to 3,
    /// written out by hand as the JSON a client reads.
    #[test]
    fn an_edit_keeps_the_old_body_as_a_revision() {
        let at = UTCDate::from("2026-11-16T12:01:00Z");
        let patch = edit_patch(&message("hi"), "hello", &BodyType::Plain, &at).unwrap();
        assert_eq!(
            patch,
            json!({
                "body": "hello",
                "bodyType": "text/plain",
                "editedAt": "2026-11-16T12:01:00Z",
                "editHistory": [{
                    "body": "hi",
                    "bodyType": "text/plain",
                    "editedAt": "2026-11-16T12:01:00Z",
                }],
            })
        );
    }

    #[test]
    fn edit_history_is_capped_oldest_first() {
        let mut stored = message("v0");
        let mut history = Vec::new();
        for n in 0..MAX_EDIT_HISTORY {
            history.push(json!({
                "body": format!("old{n}"),
                "bodyType": "text/plain",
                "editedAt": "2026-11-16T12:00:00Z",
            }));
        }
        stored.edit_history = Some(serde_json::from_value(json!(history)).unwrap());
        let at = UTCDate::from("2026-11-16T12:01:00Z");
        let patch = edit_patch(&stored, "v1", &BodyType::Plain, &at).unwrap();
        let revisions = patch["editHistory"].as_array().unwrap();
        assert_eq!(revisions.len(), MAX_EDIT_HISTORY);
        assert_eq!(revisions[0]["body"], json!("old1"));
        assert_eq!(revisions[MAX_EDIT_HISTORY - 1]["body"], json!("v0"));
    }

    /// Oracle: draft-atwood-jmap-chat-00 §Message `deletedAt`.
    #[test]
    fn a_retraction_empties_the_message() {
        assert_eq!(
            retraction_patch(&UTCDate::from("2026-11-16T12:02:00Z")),
            json!({
                "deletedAt": "2026-11-16T12:02:00Z",
                "deletedForAll": true,
                "body": "",
                "attachments": [],
                "editHistory": null,
            })
        );
    }

    #[test]
    fn kept_ids_read_back_and_damaged_ones_are_ignored() {
        let ids = MimiIds {
            first: Some("01".repeat(32)),
            aliases: vec!["02".repeat(10), "zz".to_owned(), "03".repeat(11)],
        };
        assert_eq!(ids.first(), Some(MessageId([1; 32])));
        assert_eq!(ids.aliases().collect::<Vec<_>>(), [[2u8; 10]]);
        let short = MimiIds {
            first: Some("01".repeat(31)),
            aliases: vec![],
        };
        assert_eq!(short.first(), None);
    }
}
