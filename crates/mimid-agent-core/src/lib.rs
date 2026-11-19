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
//! - [`Agent::report_abuse`]: a protocol-07 §5.9 AbuseReport of received
//!   messages ([`ReceivedMessage::reported_message`]), sent to the room's
//!   hub through the server (`Room/reportAbuse`, INVENTED, NOT FROM SPEC;
//!   decision mimid-1wgh.59); unfranked messages go unverified in mimid's
//!   own `abuse_extensions` component (decision mimid-1wgh.60);
//! - [`Agent::poll`]: everything the server stored since the last poll
//!   (Message/changes), with each received message's frank checked
//!   ([`frank`], protocol-07 §5.4.1.3), as [`Event`]s for the caller (the future inward
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
//! pending invites, held messages, the JMAP Message state, the digests
//! of sent messages, the device's `did_webvh` credential if it has one and
//! the SCIDs pinned for contacts. Both files are 0600.
//!
//! # Limitations
//!
//! - One client per user with a BasicCredential: the identity is the user
//!   URI, so a second device of the same user cannot join the same room
//!   (mls-rs refuses two leaves with the same identity; the multi-device
//!   limit H1). With a `did_webvh` credential ([`didwebvh`]) several
//!   devices of one user can share a room with mimid members.
//! - draft-atwood-mls-didwebvh-credential-01: see [`didwebvh`]. A
//!   BasicCredential agent supports `did_webvh` rooms by default (decision
//!   mimid-1wgh.4.81.23). Contacts are pinned by SCID per agent; a change
//!   is reported as [`Event::IdentityChanged`] for a room the agent is in,
//!   and refused when the agent itself adds the contact.
//! - Every proposal from another member is taken as that member's
//!   protocol-07 §3.5 leave, and the remaining member with the lowest leaf
//!   index commits it. No other proposals are sent by this crate.
//! - No room-policy actions beyond the defaults: no role changes, bans or
//!   policy edits; no external joins (GroupInfo/fetch); no attachments.
//!   A hosted room's creator gets the "admin" role, which holds `canKick`,
//!   bans and role changes, but this crate has no operation that uses
//!   them; another client of the creator, or the operator (`mimid admin
//!   remove|ban`), must (decision mimid-1wgh.56; bead mimid-90cd).
//! - A room keeps the `roles_list` it was created with. Rooms hosted by an
//!   earlier version have no admin role, and in them every member holds
//!   `canChangeRoleDefinitions`, so any member can give itself any
//!   capability (bug mimid-y2hi), until someone changes the role list.
//! - The admin role has no minimum participant count, so if the creator
//!   leaves, the room has no admin (decision mimid-1wgh.56 item 5; bead
//!   mimid-f3bk).
//! - Delivery to users of other providers is the server's job (fanout);
//!   this crate talks only to its own server.
//! - `components` and `uri` are copies of mimid-server code, kept so this
//!   crate does not depend on the server's stack; they must stay in step.
//! - Received messages are returned, not stored: keeping the plaintext is
//!   the caller's job (bead mimid-1wgh.13.12). So is keeping a message's
//!   frank and `application_data` until the user reports it.
//! - [`Agent::report_abuse`] reports messages of one sender, with this
//!   user as `reportingUser` (no anonymous reports, no report without
//!   messages). It does not check the franks again before sending.
//!   Unfranked messages travel in a component only a mimid hub reads
//!   (INVENTED, NOT FROM SPEC; decision mimid-1wgh.60): another hub sees a
//!   report without them, and a mimid hub records them as unverified. A
//!   message whose content has no `senderUri` and `roomUri` cannot be
//!   reported, franked or not (mimid's own messages always carry both). Whether the user may report is the
//!   hub's room policy (`canReportAbuse`), which the default member and
//!   admin roles hold (bead mimid-14bu); [`HostOptions::roles`] can
//!   replace them.

#![forbid(unsafe_code)]

mod agent;
pub mod asset;
mod client;
pub mod components;
pub mod didwebvh;
mod error;
pub mod frank;
mod journal;
mod state;
pub mod uri;

pub use agent::{
    Agent, AgentConfig, DidWebvhApplied, Event, HostOptions, MAX_NOTE_LEN, MAX_REPORTED_MESSAGES,
    MAX_TEXT_LEN, OutgoingAttachment, PendingInvite, ReceivedMessage, ReportOutcome,
    ReportedMessage, RoomInfo, Sent,
};
pub use client::ConsentRecord;
pub use didwebvh::{DidWebvhConfig, RoomClient};
pub use error::{AgentError, Source};
pub use journal::Receipt;
pub use mimi_content::{ExternalPart, MessageId, MimiContent};
pub use mimi_mls::mls_didwebvh;
pub use mimi_protocol::{AbuseType, AbusiveMessage, UnverifiedAbusiveMessage};
pub use state::RoomStatus;
