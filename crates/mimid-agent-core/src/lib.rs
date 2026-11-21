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
//! - [`Agent::join_own_rooms`]: a new device of the user joins the user's
//!   rooms by external Commit (protocol-07 §3.6, §5.6; GroupInfo/fetch,
//!   then Room/update; decision mimid-1wgh.61);
//! - [`Agent::send_text`] / [`Agent::send_content`]: an application
//!   message (Room/send), with a `frank_aad` item when the room requires
//!   franking;
//! - [`Agent::leave`]: protocol-07 §3.5, proposals another member commits;
//! - [`Agent::kick`], [`Agent::remove`], [`Agent::ban`], [`Agent::unban`],
//!   [`Agent::change_role`]: moderation of another user by one Commit
//!   (room-policy-04 §8.1.2, §8.1.3; decision mimid-1wgh.62), which the
//!   hub allows to the room's admin role;
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
//!   JMAP layer, bead mimid-1wgh.13.9) to turn into its own objects;
//! - [`Agent::push_source`]: the server's EventSource ([`push`]), which
//!   tells the caller when to poll; it reads nothing itself.
//!
//! The crate has no UI, no HTTP server and no runtime of its own: its
//! async fns run on the caller's runtime, so a desktop daemon or a mobile
//! app can embed it (mimid-1wgh.39).
//!
//! # State
//!
//! The state directory (mode 0700) holds one SQLite database,
//! `agent.sqlite` ([`DATABASE_FILE`], mode 0600): OpenMLS's store with the
//! identity's private keys and the groups, the agent's state (rooms,
//! pending invites, held messages, the JMAP Message state, the digests of
//! sent messages, the device's `did_webvh` credential if it has one and
//! the SCIDs pinned for contacts), and the delivery journal. OpenMLS
//! writes through the agent's connection with no transaction of its own,
//! so [`Agent::receive`] handles each server Message in one transaction:
//! the secrets it consumes and its events in the journal commit together
//! (bead mimid-1vul.10). A caller may keep its own tables in the same
//! database ([`Agent::database_path`]) and acknowledge in the transaction
//! that stores the events ([`Agent::acknowledge_in`]). The schema version
//! is a row of the `schema_version` table ([`SCHEMA_VERSION`]); another
//! version is refused, and so is a directory of the layout before
//! (`state.json`, `mls.sqlite`): nothing is converted.
//!
//! # Limitations
//!
//! - With a BasicCredential the identity is the user URI, so the devices
//!   of one user present the same identity: mimid members accept that,
//!   but mls-rs refuses two leaves with the same identity (the
//!   multi-device limit H1), so such a room cannot have an mls-rs member.
//!   With a `did_webvh` credential ([`didwebvh`]) the leaves differ.
//! - [`Agent::join_own_rooms`] joins only rooms a device of the user
//!   accepted, recorded in the Chat's `privateMetadata` on the user's
//!   server (draft-ietf-jmap-metadata-05; decision mimid-1wgh.63), and
//!   joins nothing on a server without it. A device records acceptance
//!   of the rooms it is in at its next [`Agent::join_own_rooms`], so a
//!   room accepted on a device that has not synced since is not joined
//!   yet. A device removed alone withdraws the record until another
//!   device of the user syncs and sets it again. It never joins a room
//!   this device knows, left ones included. Rooms hosted before the
//!   default roles held `canAddOwnClient` refuse new devices. Messages
//!   from before the join are not readable on the new device.
//! - [`Agent::leave`] removes every device of the user (room-policy-04
//!   §8.1.2); there is no leaving on one device only. The Removes of the
//!   other devices are proposals of this device, so a room whose roles
//!   lack `canRemoveOwnClient` refuses the leave of a user with several
//!   devices there. A leave is committed by a client of another user; a
//!   room whose only other members are the user's own devices is left at
//!   once on this device and its other devices stay. The same rule makes
//!   another user's client commit a member's credential Update proposal.
//! - [`Event::RemovedWithoutAppDataUpdate`] names the removed client's
//!   user from the tree before the Commit; it is not tested end to end
//!   through a hub with a client lacking AppDataUpdate, only below the
//!   agent (mimi-mls) and at the event and notice level (bead
//!   mimid-4lp4.4).
//! - draft-atwood-mls-didwebvh-credential-01: see [`didwebvh`]. A
//!   BasicCredential agent supports `did_webvh` rooms by default (decision
//!   mimid-1wgh.4.81.23). Contacts are pinned by SCID per agent; a change
//!   is reported as [`Event::IdentityChanged`] for a room the agent is in,
//!   and refused when the agent itself adds the contact.
//! - Every proposal from another member is taken as that member's
//!   protocol-07 §3.5 leave, and the remaining member of another user
//!   with the lowest leaf index commits it. This crate sends no proposals
//!   but a leave's and a credential Update.
//! - No policy edits (role definitions, preauthorization, membership
//!   style, room metadata); no external joins other than
//!   [`Agent::join_own_rooms`] (no open rooms, join links or codes).
//! - Moderation: [`Agent::ban`] takes only a current participant;
//!   [`Agent::unban`] gives role 2 back and adds no client, and the
//!   user's devices do not rejoin by themselves (an admin removes and
//!   invites the user again); a kicked user stays a participant whose
//!   devices do not come back by themselves either. Every operation is
//!   one Commit by this device; there are no moderation proposals.
//! - A room keeps the `roles_list` it was created with. Rooms hosted by an
//!   earlier version have no admin role, and in them every member holds
//!   `canChangeRoleDefinitions`, so any member can give itself any
//!   capability (bug mimid-y2hi), until someone changes the role list.
//! - The admin role has no minimum participant count, so if the creator
//!   leaves, the room has no admin (decision mimid-1wgh.56 item 5; bead
//!   mimid-f3bk).
//! - Delivery to users of other providers is the server's job (fanout);
//!   this crate talks only to its own server.
//! - `uri` is a copy of mimid-server code, kept so this crate does not
//!   depend on the server's stack (its HTTP, SQLite and TLS stack has no
//!   place on a phone); the two must stay in step. Component application
//!   is shared through `mimi_protocol::components` (bead mimid-mxm5).
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
pub mod didwebvh;
mod error;
pub mod frank;
mod journal;
mod outbox;
mod provider;
pub mod push;
mod state;
mod stream;
pub mod uri;

#[cfg(feature = "fail-points")]
#[doc(hidden)]
pub use agent::FailPoint;
pub use agent::{
    Agent, AgentConfig, DidWebvhApplied, Event, HostOptions, MAX_NOTE_LEN, MAX_REPORTED_MESSAGES,
    MAX_TEXT_LEN, OutgoingAttachment, OwnRoomsJoined, PendingInvite, ReceivedMessage,
    ReportOutcome, ReportedMessage, RoomInfo, Sent,
};
pub use client::{ACCEPTED_NAMESPACE, ConsentRecord};
pub use didwebvh::{DidWebvhConfig, RoomClient};
pub use error::{AgentError, Source};
pub use journal::Receipt;
pub use mimi_content::{ExternalPart, MessageId, MimiContent};
pub use mimi_mls::mls_didwebvh;
pub use mimi_protocol::{AbuseType, AbusiveMessage, UnverifiedAbusiveMessage};
pub use provider::Binding;
pub use state::RoomStatus;
pub use state::{DATABASE_FILE, SCHEMA_VERSION};
