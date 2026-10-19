//! `Room/unbind` (draft-atwood-jmap-chat-mimi-00 §Room/unbind).
//!
//! Not implemented yet (no bead owns it yet): until then the method answers
//! `unknownMethod`.

use super::Services;
use crate::jmap::api::Methods;

/// Registers this file's methods. None yet.
pub(super) fn register(_methods: &mut Methods, _services: &Services) {}
