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
//!   otherwise.
//! - **Attachments** (bead mimid-1wgh.14), with a blob store
//!   ([`AgentChat::with_blobs`], a [`BlobStore`] of plaintext files): a
//!   created Message's attachments are read from the store, and
//!   `Agent::send_message` encrypts each, uploads it to the user's mimid
//!   server and sends it as an ExternalPart (mimi-content-10 §4.5) beside
//!   the text; the stored Message keeps the client's Attachments. A
//!   received message's ExternalParts are fetched through the user's
//!   server and decrypted (`Agent::fetch_attachment`), stored, and listed
//!   in `attachments` with the part's file name and media type and the
//!   plaintext's `size` and `sha256`; a message with attachments and no
//!   text is stored with an empty `body`. The account allows
//!   [`MAX_ATTACHMENTS_PER_MESSAGE`] attachments of at most
//!   [`MAX_ATTACHMENT_LEN`] octets each, and none without a store. `senderMsgId` is the ULID of the hub's acceptance time and
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
//!   at most `MAX_TEXT_LEN` octets, no threads, and attachments only with
//!   a blob store. A `bodyType` other than `text/plain` is
//!   `invalidProperties` and a longer body `tooLarge`, from crate-jmap's
//!   checks against those limits.
//! - `Message/set` create with `mentions`, `broadcastMentions`, `replyTo`,
//!   `threadRootId`, `topicId`, `subject`, or expiry or burn settings, is
//!   `forbidden`, naming the property.
//! - Sending attachments needs a mimid server that stores them (its
//!   Session's mimi capability has `assetUrl`); otherwise a create with
//!   attachments is refused with the agent's error.
//! - A received attachment whose fetch fails for a reason that may pass
//!   (the server or the peer's hub unreachable or failing) is kept and
//!   fetched again on later syncs, then added to its Message ([`retry`]).
//!   One that fails for good, or still fails after
//!   [`retry::MAX_ATTEMPTS`], is left out and reported in
//!   [`SyncReport::problems`], as are attachments past
//!   [`MAX_ATTACHMENTS_PER_MESSAGE`], and all of them without a blob
//!   store. A received attachment's media type is not
//!   checked against its content, and an invalid one becomes
//!   `application/octet-stream`.
//! - Blobs are never deleted (see [`BlobStore`]), and attachments are
//!   fetched one at a time while `sync` holds the agent. Updating a Message other than its
//!   `readAt` or `privateMetadata` (edits, `deletedForAll`, reactions) is
//!   `forbidden`.
//! - Received edits and retractions (`replaces`, §Edits) and messages with
//!   neither text nor attachments are not stored; [`SyncReport::skipped`] lists them. Message
//!   status reports (§Message Status) are neither sent nor read, and typing
//!   is not sent.
//! - Invites the policy refuses stay pending in the agent; JMAP Chat has
//!   no object for them.
//! - Without [`AgentChat::persisted_at`] the store is in memory: after a
//!   restart, `sync` makes new Chats (with new ids) for the rooms the
//!   agent is in, without earlier Messages. With it, objects come back
//!   under their ids (see `persist` for its limits).
//! - `/set` methods on Chats and Messages hold the agent while they send,
//!   so they wait for a running `sync` and for the hub.

#![forbid(unsafe_code)]

mod backend;
mod blobs;
mod convert;
mod persist;
pub mod retry;
mod sync;

pub use backend::{AgentChat, InvitePolicy, MAX_ATTACHMENTS_PER_MESSAGE, Options};
pub use blobs::{BlobError, BlobInfo, BlobStore, MAX_ATTACHMENT_LEN, is_media_type};
pub use persist::PersistError;
pub use sync::{SyncError, SyncReport};
