//! `Message/set` (draft-atwood-jmap-chat-00 §Message/set; decision
//! mimid-1wgh.12.22).
//!
//! Every Message is a server-made `application/mimi-fanout` Message in a
//! roomed Chat, so (draft-atwood-jmap-chat-mimi-00 §mls-messages):
//!
//! - a create, or an update that changes `body`, `bodyType` or `reactions`
//!   of an existing Message, refuses the whole call with the method-level
//!   error `invalidArguments` (mimi-00 L424, L426, L430; RFC 8620 L1189;
//!   decision mimid-1wgh.11.8);
//! - any other update, and every destroy, gets the SetError `forbidden`.
//!
//! # Limitations
//!
//! - Marking as read (`readAt`) and local deletion (`deletedAt`) are
//!   refused: there is no ReadPosition or per-user Message state
//!   (decisions mimid-1wgh.12.22, mimid-1wgh.12.29).

use serde_json::{Map, Value};

use super::Services;
use crate::jmap::api::Methods;
use crate::jmap::projection::{Refusal, RefusingSet, register_message_set};

/// Registers `Message/set`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    register_message_set(
        methods,
        &services.projection,
        RefusingSet {
            create: Refusal::InvalidArguments,
            update: update_refusal,
        },
    );
}

/// What an update with `patch` gets. A PatchObject key is a property name
/// or a JSON Pointer into one (RFC 8620 §5.3).
fn update_refusal(patch: &Map<String, Value>) -> Refusal {
    let changes_content = patch.keys().any(|key| {
        let property = key.split('/').next().unwrap_or(key);
        matches!(property, "body" | "bodyType" | "reactions")
    });
    if changes_content {
        Refusal::InvalidArguments
    } else {
        Refusal::Forbidden
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn patch(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn content_changes_are_invalid_arguments_and_the_rest_forbidden() {
        for content in [
            json!({"body": "x"}),
            json!({"bodyType": "text/plain"}),
            json!({"reactions/01ARYZ6S41TSV4RRFFQ69G5FAV": null}),
            json!({"readAt": "2026-01-01T00:00:00Z", "body": "x"}),
        ] {
            assert_eq!(
                update_refusal(&patch(content.clone())),
                Refusal::InvalidArguments,
                "{content}"
            );
        }
        for other in [
            json!({"readAt": "2026-01-01T00:00:00Z"}),
            json!({"deletedAt": "2026-01-01T00:00:00Z"}),
            json!({"bodyTypeX": 1}),
            json!({}),
        ] {
            assert_eq!(
                update_refusal(&patch(other.clone())),
                Refusal::Forbidden,
                "{other}"
            );
        }
    }
}
