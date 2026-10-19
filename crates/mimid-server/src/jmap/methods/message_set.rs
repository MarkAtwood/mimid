//! `Message/set` (draft-atwood-jmap-chat-00 §Message/set; draft-atwood-jmap-chat-mimi-00 §MLS Messages; decision mimid-1wgh.12.22).
//!
//! Not implemented yet (mimid-1wgh.11.3): until then the method answers
//! `unknownMethod`.

use super::Services;
use crate::jmap::api::Methods;

/// Registers this file's methods. None yet.
pub(super) fn register(_methods: &mut Methods, _services: &Services) {}
