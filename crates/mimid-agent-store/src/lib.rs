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
//! called it ([`Commit`]) before saving and acknowledging. Every action of
//! the user's is a `Store` method too ([`action`]): it makes the agent
//! call and writes the result into the records. The records are kept in
//! an SQLite database ([`db`], [`Store::open_database`]); each save first
//! has every registered front end bring what it keeps in the records up
//! to date ([`Frontend`]).
//!
//! # Limitations
//!
//! - This is step 5 of the migration in docs/design/agent-frontends.md §3:
//!   inbound and outbound go through the store, and the store owns its
//!   file. There is no change feed yet (step 6): a sync's changes go to
//!   the front end that called it, and a write is shown by the front end
//!   that made it.
//! - See each module for its own limits.

#![forbid(unsafe_code)]

pub mod action;
pub mod blobs;
mod change;
pub mod content;
pub mod convert;
pub mod db;
pub mod notice;
pub mod record;
pub mod report;
pub mod retry;
mod state;
mod store;
pub mod sync;

pub use action::ActionError;
pub use change::Change;
pub use db::FileError;
pub use state::{State, accepted_at_of, reference_of};
pub use store::{Frontend, Store};
pub use sync::{Commit, InvitePolicy, SyncError, SyncReport};
