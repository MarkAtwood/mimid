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
//! The store itself is [`Store`]: the records of [`record`] in a [`State`],
//! kept in one file ([`mod@file`]) that it reads in the format mimid-agent-jmap
//! writes today (format 1) or in its own (format 2).
//!
//! # Limitations
//!
//! - This is step 2 of the migration in docs/design/agent-frontends.md §3:
//!   the model and the file, not wired in. Nothing builds a [`Store`] yet;
//!   mimid-agent-jmap still keeps its JMAP objects in format 1 and is the
//!   journal consumer.
//! - See each module for its own limits.

#![forbid(unsafe_code)]

pub mod blobs;
pub mod content;
pub mod convert;
pub mod file;
pub mod notice;
pub mod record;
pub mod report;
pub mod retry;
mod state;
mod store;

pub use file::FileError;
pub use state::{State, accepted_at_of, reference_of};
pub use store::Store;
