//! Reactions (mimi-content-10 §5.3, §5.7; draft-atwood-jmap-chat-00
//! §Adding and Removing Reactions; docs/design/agent-frontends.md §7.27):
//! the owner's `Message/set` patch `reactions/<senderReactionId>` sends a
//! MIMI reaction, and `null` takes it back; every reaction the store
//! keeps is shown in the Message's `reactions` (the projection).
//!
//! # Limitations
//!
//! - `customEmojiId` is refused: there are no custom emoji over MIMI.
//! - Changing a reaction's `emoji` takes the old one back and sends the
//!   new one, under the same `senderReactionId`.

use jmap_chat_types::Message;
use jmap_server::{BackendSetError, Id, SetErrorType};
use serde_json::{Value, json};

use crate::backend::{AgentChat, action_failure, set_error};
use crate::convert::utc_date;
use jmap_chat_server::memory::MemoryError;

/// The prefix of a reaction's patch key.
const REACTIONS: &str = "reactions/";

impl AgentChat {
    /// The owner's `Message/set` update `patch` of Message `id`: each
    /// `reactions/<senderReactionId>` key with an object sends its
    /// `emoji` as a reaction ([`mimid_agent_store::Store::react`]),
    /// keyed in the store by the `senderReactionId`, and its `sentAt`
    /// becomes the hub's acceptance time; one with `null` takes the
    /// owner's reaction back ([`mimid_agent_store::Store::unreact`]).
    /// Returns the patch to store, or `None` if it names no reaction, or
    /// the Message's Chat is bound to no room. crate-jmap has already
    /// checked the keys and that a reaction changed is the owner's, and
    /// set its `senderId`.
    pub(crate) async fn send_reactions(
        &self,
        id: &Id,
        patch: &Value,
    ) -> Result<Option<Value>, BackendSetError<MemoryError>> {
        let Some(fields) = patch.as_object() else {
            return Ok(None);
        };
        let keys: Vec<String> = fields
            .keys()
            .filter(|k| k.starts_with(REACTIONS))
            .cloned()
            .collect();
        if keys.is_empty() {
            return Ok(None);
        }
        let Some(stored) = self
            .stored::<Message>(id)
            .await
            .map_err(BackendSetError::Other)?
        else {
            return Ok(None);
        };
        if self.room_of_chat(&stored.chat_id).is_none() {
            return Ok(None);
        }
        let mut patch = patch.clone();
        for key in keys {
            let reaction = &key[REACTIONS.len()..];
            let held = self
                .store
                .state()
                .messages
                .get(id.as_ref())
                .is_some_and(|m| m.reactions.iter().any(|r| r.key == reaction));
            if held {
                self.store
                    .unreact(id.as_ref(), reaction)
                    .await
                    .map_err(action_failure)?;
            }
            let Some(Value::Object(value)) = fields.get(&key) else {
                continue;
            };
            if value.get("customEmojiId").is_some_and(|v| !v.is_null()) {
                return Err(BackendSetError::SetError(Box::new(
                    set_error(
                        SetErrorType::InvalidProperties,
                        "customEmojiId: there are no custom emoji over MIMI",
                    )
                    .with_properties(["reactions"]),
                )));
            }
            let emoji = value.get("emoji").and_then(Value::as_str).unwrap_or("");
            let record = self
                .store
                .react(reaction.to_owned(), id.as_ref(), emoji)
                .await
                .map_err(action_failure)?;
            let at = record
                .reactions
                .iter()
                .find(|r| r.key == reaction)
                .map_or(record.accepted_at, |r| r.accepted_at);
            patch[&key]["sentAt"] = json!(utc_date(at));
        }
        Ok(Some(patch))
    }
}
