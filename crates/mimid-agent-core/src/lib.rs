//! The client engine of mimid-agent (bead mimid-1wgh.13.8): everything a
//! user's device does to take part in MIMI rooms, through the user's own
//! mimid server's JMAP API (draft-atwood-jmap-chat-mimi-00). The device does
//! the MLS work (mimi-mls) and keeps its keys; the server hosts rooms,
//! relays to other providers and stores what arrives.
//!
//! An [`Agent`] is one user on one device:
//!
//! - [`Agent::publish_key_packages`]: KeyPackages for others to add this
//!   user with (KeyPackage/set);
//! - [`Agent::host_room`]: a room hosted by the user's server
//!   (Room/create), with franking, the default room policy and, optionally,
//!   room metadata;
//! - [`Agent::invite`]: KeyMaterial/fetch for another user (any provider),
//!   then a Commit adding them (Room/update);
//! - [`Agent::join`]: accept a Welcome that [`Agent::poll`] reported;
//! - [`Agent::send_text`] / [`Agent::send_content`]: an application
//!   message (Room/send), with a `frank_aad` item when the room requires
//!   franking;
//! - [`Agent::leave`]: protocol-07 §3.5, proposals another member commits;
//! - [`Agent::allow`], [`Agent::deny`], [`Agent::request_consent`],
//!   [`Agent::cancel_consent`], [`Agent::consents`]: Consent/set and
//!   Consent/get;
//! - [`Agent::poll`]: everything the server stored since the last poll
//!   (Message/changes), as [`Event`]s for the caller (the future inward
//!   JMAP layer, bead mimid-1wgh.13.9) to turn into its own objects.
//!
//! The crate has no UI, no HTTP server and no runtime of its own: its
//! async fns run on the caller's runtime, so a desktop daemon or a mobile
//! app can embed it (mimid-1wgh.39).
//!
//! # State
//!
//! The state directory (mode 0700) holds `mls.sqlite`, the MLS store with
//! the identity's private keys and the groups, and `state.json`: rooms,
//! pending invites, held messages, the JMAP Message state and the digests
//! of sent messages. Both files are 0600.
//!
//! # Limitations
//!
//! - One client per user: the identity is the user URI in a
//!   BasicCredential, so a second device of the same user cannot join the
//!   same room (mls-rs refuses two leaves with the same identity; the
//!   multi-device limit H1).
//! - Every proposal from another member is taken as that member's
//!   protocol-07 §3.5 leave, and the remaining member with the lowest leaf
//!   index commits it. No other proposals are sent by this crate.
//! - No room-policy actions beyond the defaults: no role changes, bans or
//!   policy edits; no external joins (GroupInfo/fetch); no attachments.
//! - Delivery to users of other providers is the server's job (fanout);
//!   this crate talks only to its own server.
//! - `components` and `uri` are copies of mimid-server code, kept so this
//!   crate does not depend on the server's stack; they must stay in step.
//! - Received messages are returned, not stored: keeping the plaintext is
//!   the caller's job (bead mimid-1wgh.13.12).

#![forbid(unsafe_code)]

mod agent;
mod client;
pub mod components;
mod error;
mod state;
pub mod uri;

pub use agent::{
    Agent, AgentConfig, Event, HostOptions, MAX_TEXT_LEN, PendingInvite, ReceivedMessage, RoomInfo,
    Sent,
};
pub use client::ConsentRecord;
pub use error::{AgentError, Source};
pub use mimi_content::{MessageId, MimiContent};
pub use state::RoomStatus;
