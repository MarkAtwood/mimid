//! The consent hook consulted before serving key material (protocol-06
//! §5.2 `noConsent`).
//!
//! # Limitations
//!
//! - v1 allows every request for a known user (decision mimid-1wgh.7.9):
//!   the protocol-06 §5.7 consent endpoints are not implemented, so users
//!   cannot grant or refuse consent.

use mimi_protocol::KeyMaterialRequestTbs;

/// Whether the target user consents to `request`'s requester fetching key
/// material for `request`'s room. Always `true` in v1 (decision
/// mimid-1wgh.7.9).
pub fn allows(_request: &KeyMaterialRequestTbs) -> bool {
    true
}
