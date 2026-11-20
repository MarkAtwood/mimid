//! The plaintext layer of mimid-agent, shared by its front ends
//! (docs/design/agent-frontends.md, epic mimid-1vul).
//!
//! mimid-agent-core holds the MLS keys and rooms; this crate holds what the
//! agent keeps in plaintext once a message is decrypted, in terms of no
//! one front end: the blob store of attachment content ([`blobs`]), the
//! retry policy of attachment fetches ([`retry`]), the identifiers every
//! front end shows a message under ([`convert`]), the agent's own notices
//! ([`notice`]), body types and safe file names ([`content`]), and what a
//! message keeps for an abuse report ([`report`]). mimid-agent-jmap's JMAP
//! Chat front end is built on it; it depends on neither crate-jmap nor any
//! IRC code.
//!
//! # Limitations
//!
//! - This is step 1 of the migration in docs/design/agent-frontends.md §3:
//!   the pieces that need no state. The records, the store file and the
//!   journal consumer are still in mimid-agent-jmap.
//! - See each module for its own limits.

#![forbid(unsafe_code)]

pub mod blobs;
pub mod content;
pub mod convert;
pub mod notice;
pub mod report;
pub mod retry;
