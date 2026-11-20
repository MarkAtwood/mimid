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
//! The store itself is [`Store`]: the agent, the records of [`record`] in
//! a [`State`], and the blob store. [`Store::sync`] is the agent's only
//! journal consumer ([`mod@sync`]): it writes what the agent received into
//! the records and hands each round's [`Change`]s to the front end that
//! called it ([`Commit`]) before acknowledging. The records are kept in
//! one file ([`mod@file`]), read in the format mimid-agent-jmap writes
//! (format 1) or in the store's own (format 2).
//!
//! # Limitations
//!
//! - This is step 3 of the migration in docs/design/agent-frontends.md §3:
//!   inbound goes through the store, while the JMAP front end still sends
//!   for the user itself and writes its own changes into the records
//!   ([`file::merge_object`]), and still saves the file in format 1.
//! - See each module for its own limits.

#![forbid(unsafe_code)]

pub mod blobs;
mod change;
pub mod content;
pub mod convert;
pub mod file;
pub mod notice;
pub mod record;
pub mod report;
pub mod retry;
mod state;
mod store;
pub mod sync;

pub use change::Change;
pub use file::FileError;
pub use state::{State, accepted_at_of, reference_of};
pub use store::Store;
pub use sync::{Commit, InvitePolicy, SyncError, SyncReport};
