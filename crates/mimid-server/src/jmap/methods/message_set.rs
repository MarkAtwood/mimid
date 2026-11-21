//! `Message/set` (draft-atwood-jmap-chat-00 §Message/set; decision
//! mimid-1wgh.12.22).
//!
//! Every Message is a server-made `application/mimi-fanout` Message in a
//! Chat with a `roomId`, so (draft-atwood-jmap-chat-mimi-00
//! §private-messages, §fanout-messages, as jmap-chat-spec 735503c words
//! them; clean-room finding C17):
//!
//! - a create in a Chat the account sees, every one of which has a
//!   `roomId`, gets the SetError `forbidden`, whatever its `bodyType`:
//!   messages are sent with Room/send. A create naming no Chat of the
//!   account gets `invalidProperties` naming `chatId`. The
//!   `invalidProperties` rule for `bodyType` `application/mimi-fanout`
//!   applies only to Chats without a `roomId`, which mimid has none of;
//! - an update that changes `body`, `bodyType` or `reactions` of an
//!   existing Message gets `invalidProperties` naming the changed
//!   properties (§private-messages);
//! - any other update, and every destroy, gets `forbidden`.
//!
//! Each SetError says in `description` which rule refused it (clean-room
//! finding C5). These replace decision mimid-1wgh.11.8, under which a
//! create or a content change refused the whole call with
//! `invalidArguments`.
//!
//! # Limitations
//!
//! - Marking as read (`readAt`) and local deletion (`deletedAt`) are
//!   refused: there is no ReadPosition or per-user Message state
//!   (decisions mimid-1wgh.12.22, mimid-1wgh.12.29).

use serde_json::{Map, Value, json};

use super::Services;
use crate::jmap::api::Methods;
use crate::jmap::projection::{RefusingSet, register_message_set};

/// The properties of a Message an update may not change.
const CONTENT: [&str; 3] = ["body", "bodyType", "reactions"];

/// Registers `Message/set`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    register_message_set(
        methods,
        &services.projection,
        RefusingSet {
            create: create_refusal,
            update: update_refusal,
        },
    );
}

/// What a create gets; `known_chat` is whether its `chatId` names a Chat
/// of the account.
fn create_refusal(_object: &Map<String, Value>, known_chat: bool) -> Value {
    if known_chat {
        json!({
            "type": "forbidden",
            "description": "this Chat has a roomId; send messages to its room with Room/send",
        })
    } else {
        json!({
            "type": "invalidProperties",
            "properties": ["chatId"],
            "description": "chatId names no Chat of this account",
        })
    }
}

/// What an update with `patch` gets. A PatchObject key is a property name
/// or a JSON Pointer into one (RFC 8620 §5.3).
fn update_refusal(patch: &Map<String, Value>) -> Value {
    let mut changed: Vec<&str> = patch
        .keys()
        .filter_map(|key| {
            let property = key.split('/').next().unwrap_or(key);
            CONTENT.iter().copied().find(|c| *c == property)
        })
        .collect();
    changed.sort_unstable();
    changed.dedup();
    if changed.is_empty() {
        json!({
            "type": "forbidden",
            "description": "server-created Messages cannot be changed",
        })
    } else {
        json!({
            "type": "invalidProperties",
            "properties": changed,
            "description": "MIMI edits, reactions and retractions are sent as new messages",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn content_changes_are_invalid_properties_and_the_rest_forbidden() {
        for (content, properties) in [
            (json!({"body": "x"}), json!(["body"])),
            (json!({"bodyType": "text/plain"}), json!(["bodyType"])),
            (
                json!({"reactions/01ARYZ6S41TSV4RRFFQ69G5FAV": null}),
                json!(["reactions"]),
            ),
            (
                json!({"readAt": "2026-01-01T00:00:00Z", "body": "x", "body/x": 1}),
                json!(["body"]),
            ),
        ] {
            let error = update_refusal(&object(content.clone()));
            assert_eq!(error["type"], "invalidProperties", "{content}");
            assert_eq!(error["properties"], properties, "{content}");
        }
        for other in [
            json!({"readAt": "2026-01-01T00:00:00Z"}),
            json!({"deletedAt": "2026-01-01T00:00:00Z"}),
            json!({"bodyTypeX": 1}),
            json!({}),
        ] {
            assert_eq!(
                update_refusal(&object(other.clone()))["type"],
                "forbidden",
                "{other}"
            );
        }
    }

    #[test]
    fn creates_in_a_known_chat_are_forbidden_whatever_the_body_type() {
        for body_type in ["text/plain", "application/mimi-fanout", "message/mls"] {
            let create = object(json!({"chatId": "c", "bodyType": body_type}));
            assert_eq!(create_refusal(&create, true)["type"], "forbidden");
            let unknown = create_refusal(&create, false);
            assert_eq!(unknown["type"], "invalidProperties");
            assert_eq!(unknown["properties"], json!(["chatId"]));
        }
    }
}
