//! `Chat/set` (draft-atwood-jmap-chat-00 §Chat/set; decision mimid-1wgh.12.22).
//!
//! Every Chat is roomed, and its name, members and metadata are MLS group
//! state (draft-atwood-jmap-chat-mimi-00 §Chat.roomId), so every create,
//! update and destroy is refused with `forbidden`.
//!
//! # Limitations
//!
//! - The per-user updates base L1026 allows (`muted`, `muteUntil`,
//!   `receiveTypingIndicators`, `messageExpirySeconds`, `receiptSharing`)
//!   and `pinnedMessageIds` are refused too (decisions mimid-1wgh.12.22,
//!   mimid-1wgh.12.29).
//! - A Chat cannot be destroyed (base §Destroying a Chat).

use super::Services;
use crate::jmap::api::Methods;
use crate::jmap::projection::{Refusal, RefusingSet, register_chat_set};

/// Registers `Chat/set`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    register_chat_set(
        methods,
        &services.projection,
        RefusingSet {
            create: Refusal::Forbidden,
            update: |_| Refusal::Forbidden,
        },
    );
}
