//! JMAP Chat (draft-atwood-jmap-chat-00) over a [`mimid_agent_core::Agent`]:
//! the inward face of mimid-agent (bead mimid-1wgh.13.9). The agent does
//! MLS on the user's device; this crate shows its rooms to the user's apps
//! as Chats and Messages, decrypted, the way draft-atwood-jmap-chat-mimi-00
//! §Message Identifiers through §Message Status describe a party that
//! converts MIMI messages.
//!
//! [`AgentChat`] is a crate-jmap `ChatBackend`. Objects are kept in
//! crate-jmap's `MemoryBackend`; client writes with MIMI meaning go to the
//! agent first, and [`AgentChat::sync`] stores what the agent received. It
//! has no transport and no runtime of its own: a daemon or an app builds a
//! `jmap_server::Dispatcher<()>`, calls [`AgentChat::register`], serves it,
//! and calls `sync` (decision mimid-1wgh.39).
//!
//! # Mapping
//!
//! - **Chat**: one per MIMI room, kind `"group"`, with the room URI in
//!   `roomId` (draft-atwood-jmap-chat-mimi-00 §Chat.roomId) and the room's
//!   `room_name` as `name`. `Chat/set` create of a group Chat hosts a room
//!   named by the Chat's `name` and invites the members of `memberIds`; if
//!   an invite fails the room is left and the create fails. `addMembers`
//!   invites. The owner's own removal, and destroying the Chat, leave the
//!   room. Rooms the agent joins become Chats at the next `sync`.
//! - **members**: the room's participant list, mirrored at each `sync`.
//!   The owner's entry is the accountId; every other participant is a
//!   ChatContact whose `identity` and `login` are its MIMI user URI, made
//!   when first seen (§Senders). The owner is `admin` of a Chat it created
//!   here and `member` of one it joined; everyone else is `member`.
//! - **Message**: `Message/set` create sends `body` as one `text/plain`
//!   part. Received messages with a `text/*` single part are stored with
//!   `bodyType` `text/markdown` for `text/markdown` and `text/plain`
//!   otherwise. `senderMsgId` is the ULID of the hub's acceptance time and
//!   the message ID (§Message Identifiers), so sender and receivers agree;
//!   `sentAt` is the hub's acceptance time; `senderId` follows §Senders.
//!   `inReplyTo` resolves to `replyTo` within the Chat; `topicId` follows
//!   §Topics. Own Messages are `deliveryState` `"delivered"` with
//!   `deliveredAt` once the hub accepts them; received ones are
//!   `"delivered"`.
//! - **Invites**: [`Options::invites`] decides which Welcomes `sync`
//!   joins; by default only those sent by a user this user allowed
//!   (`Agent::allow`).
//! - **Local objects**: ChatContact and ReadPosition writes, `readAt` and
//!   `privateMetadata` on a Message, and destroying a Message change only
//!   this account.
//!
//! # Limitations
//!
//! - Space, SpaceInvite, SpaceBan, CustomEmoji and PresenceStatus writes
//!   are `forbidden`, and `supports_type` is false for them.
//! - Direct Chats are `forbidden` (only group Chats map to rooms).
//! - On a room-bound Chat, `name`, `description`, `avatarBlobId` and
//!   `updateMemberRoles` are `forbidden` (§Chat.roomId), and removing a
//!   member other than the owner is `forbidden`: the agent has no remove.
//!   MIMI roles are not mapped.
//! - The account's limits are what the agent takes: `text/plain` only,
//!   at most `MAX_TEXT_LEN` octets, no attachments, no threads. A
//!   `bodyType` other than `text/plain` is `invalidProperties` and a longer
//!   body `tooLarge`, from crate-jmap's checks against those limits.
//! - `Message/set` create with `attachments`, `mentions`, `broadcastMentions`, `replyTo`,
//!   `threadRootId`, `topicId`, `subject`, or expiry or burn settings, is
//!   `forbidden`, naming the property. Updating a Message other than its
//!   `readAt` or `privateMetadata` (edits, `deletedForAll`, reactions) is
//!   `forbidden`.
//! - Received edits and retractions (`replaces`, §Edits) and non-text
//!   messages are not stored; [`SyncReport::skipped`] lists them. Message
//!   status reports (§Message Status) are neither sent nor read, and typing
//!   is not sent.
//! - Invites the policy refuses stay pending in the agent; JMAP Chat has
//!   no object for them.
//! - The store is in memory: after a restart, `sync` makes new Chats (with
//!   new ids) for the rooms the agent is in, without earlier Messages, and
//!   hosted rooms come back with the owner as `member`.
//! - `/set` methods on Chats and Messages hold the agent while they send,
//!   so they wait for a running `sync` and for the hub.

#![forbid(unsafe_code)]

mod backend;
mod convert;
mod sync;

pub use backend::{AgentChat, InvitePolicy, Options};
pub use sync::{SyncError, SyncReport};
