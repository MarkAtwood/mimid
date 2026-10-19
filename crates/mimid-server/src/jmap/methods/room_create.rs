//! `Room/create` (draft-atwood-jmap-chat-mimi-00 §Room/create).
//!
//! Not implemented yet (mimid-1wgh.12.4): until then the method answers
//! `unknownMethod`.

use super::Services;
use crate::jmap::api::Methods;

/// Registers this file's methods. None yet.
pub(super) fn register(_methods: &mut Methods, _services: &Services) {}
