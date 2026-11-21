//! The plaintext layer of mimid-agent, shared by its front ends
//! (docs/design/agent-frontends.md, epic mimid-1vul).
//!
//! mimid-agent-core holds the MLS keys and rooms; this crate holds what the
//! agent keeps in plaintext once a message is decrypted, in terms of no
//! one front end: the blob store of attachment content ([`blobs`]), the
//! retry policy of attachment fetches ([`retry`]), the identifiers every
//! front end shows a message under ([`convert`]), the agent's own notices
//! ([`notice`]), body types and safe file names ([`content`]), and what a
//! message keeps for an abuse report ([`report`]), and attachment links a
//! front end can hand any client ([`links`]). A room's history comes a
//! page at a time ([`history`]). mimid-agent-jmap's JMAP
//! Chat front end and mimid-agent-irc's IRC front end are built on it; it
//! depends on neither crate-jmap nor any IRC code.
//!
//! The store itself is [`Store`]: the agent, the records of [`record`] in
//! a [`State`], the blob store, and the change feed ([`feed`]).
//! [`Store::sync`] is the agent's only journal consumer ([`mod@sync`]): it
//! writes what the agent received into the records. Every action of the
//! user's is a `Store` method too ([`action`]): it makes the agent call
//! and writes the result into the records. Both record what they changed
//! ([`Change`]), and the next save publishes it: every registered front
//! end ([`Frontend`]) is handed the changes, shows them and brings what it
//! keeps in the records up to date, then the records are written to the
//! agent's own SQLite database ([`db`], [`Store::open_database`]), where a
//! sync's records and the agent's acknowledgement of them commit
//! together, and the changes
//! are logged under sequence numbers for any number of subscribers
//! ([`Store::subscribe`], [`Store::changes_since`]). So several front ends
//! can serve one store, each seeing what the others did.
//!
//! # Limitations
//!
//! - The change log is in memory and bounded ([`feed`]); a front end that
//!   falls behind it shows its state again from the records.
//! - See each module for its own limits.

#![forbid(unsafe_code)]

pub mod action;
pub mod blobs;
mod change;
pub mod content;
pub mod convert;
pub mod credentials;
pub mod db;
pub mod expiry;
pub mod feed;
pub mod history;
pub mod links;
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
pub use expiry::ExpiryError;
pub use feed::TooOld;
pub use history::{Direction, Page, Point};
pub use state::{RemovedRoom, State, accepted_at_of, reference_of};
pub use store::{Frontend, Store};
pub use sync::{InvitePolicy, SyncError, SyncReport};
