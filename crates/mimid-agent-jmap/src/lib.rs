//! JMAP Chat (draft-atwood-jmap-chat-00) over a [`mimid_agent_core::Agent`]:
//! the inward face of mimid-agent (bead mimid-1wgh.13.9). The agent does
//! MLS on the user's device; this crate shows its rooms to the user's apps
//! as Chats and Messages, decrypted, the way draft-atwood-jmap-chat-mimi-00
//! §Message Identifiers through §Message Status describe a party that
//! converts MIMI messages.
//!
//! [`AgentChat`] is a crate-jmap `ChatBackend` over a
//! [`mimid_agent_store::Store`], the agent's plaintext records. Objects are
//! kept in crate-jmap's `MemoryBackend`, a projection of the records
//! under their keys; each client write is the store's method for it
//! ([`mimid_agent_store::action`]), which sends what has MIMI meaning
//! through the agent and writes the records, and [`AgentChat::sync`]
//! runs the store's sync, which writes what the agent received into the
//! records, then shows the changed records as JMAP objects and saves. It
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
//!   invites, `removeMembers` of another member removes that user from
//!   the room, and `updateMemberRoles` changes its role in the room; the
//!   hub's room policy decides (decision mimid-1wgh.62). The owner's own
//!   removal, and destroying the Chat, leave the room. Destroying the Chat
//!   also deletes its Messages, ChatBans and attachments here
//!   (docs/design/agent-frontends.md §7.9); the other members keep their
//!   history. Rooms the agent joins become Chats at the next `sync`,
//!   including the user's rooms that a new device joins by external
//!   Commit at each `sync` (`Agent::join_own_rooms`; decision
//!   mimid-1wgh.61).
//! - **members**: the room's participant list, mirrored at each `sync`.
//!   The owner's entry is the accountId; every other participant is a
//!   ChatContact whose `identity` and `login` are its MIMI user URI, made
//!   when first seen (§Senders). A participant whose room role is named
//!   "admin" is `admin`, any other `member`, and a banned one (role 1,
//!   "banned") is not listed.
//! - **Moderation** ([`moderate`]; draft-atwood-jmap-chat-mimi-00
//!   §Moderation, decision mimid-1wgh.62): `ChatBan/set` create and
//!   destroy ban and unban a member of a room-bound Chat through the
//!   agent, and the `Chat/set` patch key `kickMembers` kicks one. Each
//!   participant a room holds in its "banned" role has a ChatBan, made at
//!   `sync` when the ban was made elsewhere.
//! - **Message**: `Message/set` create sends `body` as one `text/plain`
//!   part; with `replyTo`, naming a Message of the same Chat, as a reply
//!   whose MIMI `inReplyTo` is that Message's first version
//!   ([`mimid_agent_store::Store::send_message`]). Received messages with a `text/*` single part are stored with
//!   `bodyType` `text/markdown` for `text/markdown` and `text/plain`
//!   otherwise.
//! - **Edits and retractions** ([`edits`]; §Edits, decision
//!   mimid-1wgh.65): a received message with `replaces` from the original
//!   message's sender edits that Message (`body`, `bodyType`, `editedAt`,
//!   the old body kept in `editHistory`) or, with a NullPart body,
//!   retracts it (`deletedAt`, `deletedForAll`, `body` emptied), and its
//!   own ID becomes an alias, so a reply to any version resolves to the
//!   Message. One from anyone else is refused and reported in
//!   [`SyncReport::problems`]. The owner's `Message/set` update of `body`
//!   on their own Message sends an edit, and `deletedForAll: true` a
//!   retraction, each naming the first version; `deletedAt` alone is a
//!   local deletion.
//! - **Reactions** ([`reactions`]; mimi-content-10 §5.3, §5.7): every
//!   reaction the store keeps is in its Message's `reactions`, keyed by
//!   the reaction message's `senderMsgId`; the owner's patch
//!   `reactions/<senderReactionId>` sends one, and `null` takes it back.
//! - **On behalf of** (docs/design/marmot-bridge.md §3.2;
//!   docs/design/agent-frontends.md §7.28): a received message's
//!   `mimid-on-behalf-of` extension is the Message's vendor property
//!   `mimid.invalid:onBehalfOf`, `{"uri", "name", "src"}`, for a client
//!   to show as "name (via sender)". INVENTED, NOT FROM SPEC: the
//!   property.
//! - **Calls to join** (mimi-content-10 §5.10; docs/design/agent-frontends.md
//!   §7.24): a received part of disposition `session` is never fetched;
//!   an `https` or `wss` URL is a MessageAction of `type`
//!   `urn:ietf:params:jmap:chat:cap:vtc` in `actions` (the description as
//!   its `label`), any other a line of `body`. A `Message/set` create with
//!   one such action sends it as the §5.10 ExternalPart.
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
//! - **did:webvh contacts** (draft-atwood-mls-didwebvh-credential-01
//!   §Reference Identifiers; bead mimid-1wgh.4.81.27): a ChatContact whose
//!   user has `did_webvh` leaves in the agent's rooms carries that user's
//!   DID in `did` (draft-atwood-jmap-chat-did-00 §Optional `did` field:
//!   the `id` of the head DID document, not the bare SCID); a user seen
//!   only with BasicCredential leaves has none. It is set again whenever
//!   a room's epoch moves. When the agent reports that a contact's SCID
//!   changed (`Event::IdentityChanged`: another SCID, or a
//!   BasicCredential device for a contact pinned to an SCID), `sync`
//!   stores one plain-text notice Message in that room's Chat naming the
//!   contact (its `displayName`, else its user URI), saying the identity
//!   changed and should be verified; `did` changes to the new DID at the
//!   same time, and `didChangedAt` is set (draft-atwood-jmap-chat-did-00
//!   §DID changes; a first binding does not set it). The notice's `senderId` is the accountId (JMAP Chat has no
//!   system sender; the store keeps it as a notice of the agent's,
//!   `mimid_agent_store::record::Sender::Agent`), and it is stored
//!   once per room and change, however often the agent reports it.
//!   INVENTED, NOT FROM SPEC: the notice and its text.
//! - **Removed for lacking AppDataUpdate** (bead mimid-4lp4.4): when a
//!   Commit that changes the `did_webvh` record removes a client whose
//!   app lacks AppDataUpdate (`Event::RemovedWithoutAppDataUpdate`;
//!   decision mimid-1wgh.4.81.37), `sync` stores one plain-text notice in
//!   that room's Chat, sent by the accountId like the identity notice,
//!   saying the member's app could not take part in a security update
//!   and was removed, and that the member can rejoin. One per room, user
//!   and epoch, however often it is replayed. INVENTED, NOT FROM SPEC:
//!   the notice and its text.
//! - **Messages lost** (decision mimid-1wgh.83): when the agent missed
//!   Commits its server no longer had (deleted after `messageRetention`,
//!   or by the operator) and rejoined the room, or left it as needing a
//!   new invite (`Event::MessagesLost`), `sync` stores one plain-text
//!   notice in that room's Chat, sent by the accountId like the others,
//!   saying that messages from one time to another could not be
//!   delivered. One per gap. INVENTED, NOT FROM SPEC: the notice and its
//!   text.
//!
//!   Decision note (bead mimid-1wgh.4.81.27): the Session does not
//!   advertise `urn:ietf:params:jmap:chat:did`. draft-atwood-jmap-chat-did-00
//!   §Capability and §Mandatory DID Methods let a server advertise it only
//!   if it also advertises `urn:ietf:params:jmap:did` and can resolve
//!   `did:web`, `did:key` and `did:plc`; the agent resolves no DID (it
//!   verifies the did:webvh logs its peers carry in their MLS
//!   credentials). `did` is a property of ChatContact that the server sets
//!   and a client may ignore, so it is set without the capability.
//! - **Invites**: [`Options::invites`] decides which Welcomes `sync`
//!   joins; by default only those sent by a user this user allowed
//!   (`Agent::allow`).
//! - **Abuse reports** ([`report`]; decisions mimid-1wgh.59,
//!   mimid-1wgh.60): each received Message keeps its content as received
//!   and its frank, if any, and `Message/reportAbuse` (INVENTED, NOT FROM
//!   SPEC) reports Messages to the room's hub through the agent, unfranked
//!   ones as unverified.
//! - **Disappearing messages** (docs/design/agent-frontends.md §7.20 to
//!   §7.23; [`mimid_agent_store::expiry`]): `Message/set` create takes
//!   `senderExpiresAt` (sent as the MIMI `expires`, absolute, in whole
//!   seconds; refused with `invalidProperties` when past or more than a
//!   year ahead), `burnOnRead` and `expiresAfterReadSeconds` (sent in
//!   mimid's own extension); a received message shows them. The store
//!   deletes each record at its time, and the Message is hard-deleted:
//!   `destroyed` in `Message/changes`. A read is the owner's `readAt`, or
//!   a `ReadPosition` at or past the Message. `messageExpirySeconds` on a
//!   Chat is the room's local policy, kept in the store.
//! - **Local objects**: ChatContact and ReadPosition writes, `readAt` and
//!   `privateMetadata` on a Message, and destroying a Message change only
//!   this account.
//!
//! # Limitations
//!
//! - Space, SpaceInvite, SpaceBan, CustomEmoji and PresenceStatus writes
//!   are `forbidden`, and `supports_type` is false for them.
//! - See [`moderate`] for the limits of bans and kicks; a ChatBan
//!   mirrored from a room whose banner is not known names the accountId
//!   as `bannedBy`.
//! - The store keeps [`CHANGE_LOG_LIMIT`] change-log entries per data
//!   type ([`Options::with_change_log_limit`]); a `/changes` from an older
//!   state is `cannotCalculateChanges` and the client resyncs (decision
//!   mimid-1wgh.66).
//!   Destroying a Chat writes one Message change per Message it held,
//!   so a long history can push a client's state out of the log.
//! - A destroyed Chat's attachments that are the user's own uploads from
//!   the last hour stay in the blob store until its quota deletes them
//!   (RFC 8620 §6); if the save after the destroy fails, all of them stay
//!   until a save succeeds, and a restart before that leaves them to the
//!   quota.
//! - Direct Chats are `forbidden` (only group Chats map to rooms).
//! - On a room-bound Chat, `name`, `description` and `avatarBlobId` are
//!   `forbidden` (§Chat.roomId). Roles map only to "admin" and "member",
//!   the room's roles of those names (draft-atwood-jmap-chat-mimi-00
//!   §Moderation); other roles of a room show
//!   as `member`, and the owner's own role cannot be changed.
//! - The account's limits are what the agent takes: `text/plain` only,
//!   at most `MAX_TEXT_LEN` octets, no threads, and attachments only with
//!   a blob store. A `bodyType` other than `text/plain` is
//!   `invalidProperties` and a longer body `tooLarge`, from crate-jmap's
//!   checks against those limits.
//! - `Message/set` create with `mentions`, `broadcastMentions`,
//!   `threadRootId`, `topicId` or `subject` is `forbidden`, naming the
//!   property, and so is `replyTo` beside a call to join. A `replyTo` to a
//!   notice, which has no MIMI message ID, is `invalidProperties`.
//! - `burnOnRead` and `expiresAfterReadSeconds` reach only mimid
//!   receivers (an INVENTED extension, decision mimid-1wgh.84); other
//!   implementations keep such a Message. The `Chat/set` update of
//!   `messageExpirySeconds` is honoured only on a room-bound Chat.
//! - Sending attachments needs a server that stores them (its Session's
//!   mimi capability has `assetUrl`), and receiving them one that fetches
//!   them (`assetDownloadUrl`; draft-atwood-jmap-chat-mimi-00
//!   §Account-Level Capability Object); otherwise a create with
//!   attachments is refused with the agent's error, and a received
//!   attachment is left out and reported.
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
//! - Unreferenced blobs are deleted only when an upload needs room, and
//!   referenced ones have no quota (see [`BlobStore`]; decision
//!   mimid-1wgh.68). Attachments are fetched one at a time while `sync`
//!   holds the agent. Updating a
//!   Message's `mentions`, `broadcastMentions` or `readDisposition` is
//!   `forbidden`. See [`edits`] for the limits of edits
//!   and retractions.
//! - Received messages from rooms without franking are reported
//!   unverified, in a component only a mimid hub reads; see [`report`]
//!   for its limits.
//! - Received messages with neither text nor attachments, and edits and
//!   retractions of messages not stored here, are not stored;
//!   [`SyncReport::skipped`] lists them. Message
//!   status reports (§Message Status) are neither sent nor read, and typing
//!   is not sent.
//! - Invites the policy refuses stay pending in the agent; JMAP Chat has
//!   no object for them.
//! - Without [`AgentChat::persisted`] the store is in memory: after a
//!   restart, `sync` makes new Chats (with new ids) for the rooms the
//!   agent is in, without earlier Messages. With it, objects come back
//!   under their ids (see `persist` for its limits).
//! - `/set` methods on Chats and Messages hold the agent while they send,
//!   so they wait for a running `sync` and for the hub.
//! - The identity notice is local to this account: it is not sent to the
//!   room, and a client may show it as the user's own message. A notice is
//!   kept until the client destroys it.
//! - ChatContact `did` follows the rooms the agent is in; a user who
//!   leaves every room keeps the last DID seen. Per-member did_webvh
//!   status in a Chat (§Negotiation's SHOULD) waits for JMAP Chat
//!   properties (Mark's decision (3) on bead mimid-1wgh.4.81.27).

#![forbid(unsafe_code)]

mod backend;
mod convert;
pub mod edits;
pub mod moderate;
mod persist;
mod project;
pub mod reactions;
mod render;
pub mod report;
pub mod retry;
mod sync;

pub use backend::{
    AgentChat, CHANGE_LOG_LIMIT, InvitePolicy, MAX_ATTACHMENTS_PER_MESSAGE, Options,
};
pub use mimid_agent_store::blobs::{
    BlobError, BlobInfo, BlobQuota, BlobStore, MAX_ATTACHMENT_LEN, MAX_UNREFERENCED_BLOB_BYTES,
    MAX_UNREFERENCED_BLOBS, MIN_UNREFERENCED_AGE, is_media_type,
};
pub use persist::PersistError;
pub use sync::{SyncError, SyncReport};
