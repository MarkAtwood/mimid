//! Edits and retractions (mimi-content-10 §5.5, §5.6; draft-atwood-jmap-
//! chat-mimi-00 §Edits; decision mimid-1wgh.65): a received message with
//! `replaces` changes the Message it names, and the owner's `Message/set`
//! edit or `deletedForAll` goes to the room as one.
//!
//! A MIMI `replaces` is a whole 32-octet message ID, and a Message keeps
//! only octets 1 through 10 of it (`senderMsgId`). So each Message's first
//! version's message ID, and the reference octets of its later versions
//! (its aliases, §Edits), are kept in its record in the store
//! ([`mimid_agent_store::record::Message`]), and saved beside it in the
//! plaintext store (`persist`). Received edits and retractions are the
//! store's ([`mimid_agent_store::sync::replace`]); this module sends the
//! owner's and shows both.
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
//!   in [`crate::SyncReport::problems`].
//! - An edit or retraction of a message not stored here (sent before this
//!   device joined, skipped, or destroyed by the client) is dropped and
//!   listed in [`crate::SyncReport::skipped`]; it is not held.
//! - A retracted Message's kept report record is dropped with its content,
//!   so it cannot be reported. Its attachment blobs stay in the blob store.
//! - A Message stored before these records were kept has no first-version
//!   ID, so the owner cannot edit or retract it.

use jmap_chat_types::{BodyType, Message};
use jmap_server::{BackendSetError, Id, UTCDate};
use mimi_content::MessageId;
use serde_json::{Value, json};

use crate::backend::{AgentChat, agent_failure, forbidden, serde_failure};
use crate::convert::{message_ref, utc_date};
use jmap_chat_server::memory::MemoryError;

pub use mimid_agent_store::sync::{MAX_ALIASES, MAX_EDIT_HISTORY};

impl AgentChat {
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
        let (first, aliases) = self
            .store
            .state()
            .messages
            .get(id.as_ref())
            .map_or((None, 0), |m| (m.mimi_id, m.aliases.len()));
        let Some(first) = first.map(|first| MessageId(first.0)) else {
            return Err(forbidden(
                "no MIMI message ID is kept for this Message, so it cannot be edited or retracted",
            ));
        };
        if aliases >= MAX_ALIASES {
            return Err(forbidden("the Message has too many versions"));
        }
        let mut patch = patch.clone();
        let mut agent = self.agent().lock().await;
        if retracts {
            let sent = agent
                .send_retraction(&room, &first)
                .await
                .map_err(agent_failure)?;
            drop(agent);
            self.store
                .state()
                .add_alias(id.as_ref(), message_ref(&sent.message_id));
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
            self.store
                .state()
                .add_alias(id.as_ref(), message_ref(&sent.message_id));
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
/// §Message `deletedAt`: `body` and `attachments` empty, no `editHistory`):
/// how a retracted record is shown ([`crate::project`]).
pub(crate) fn retraction_patch(at: &UTCDate) -> Value {
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
}
