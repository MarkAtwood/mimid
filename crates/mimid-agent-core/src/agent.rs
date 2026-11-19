//! [`Agent`]: one user's MIMI client, reached through the user's mimid
//! server's JMAP API.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::SystemTime;

use mimi_content::{
    Disposition, Extensions, ExternalPart, MessageId, MimiContent, NestedPart, Part, PartSemantics,
};
use mimi_mls::member::{
    AppDataUpdate, CommitBundle, ExternalSender, Incoming, Member, OutOfSync, Sender,
};
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::{
    AppDataDictionary, CipherSuite, ContentType, Credential, GroupInfo, HPKEPublicKey, MLSMessage,
    RatchetTreeOption, RequiredCapabilities, SignaturePublicKey, Welcome,
};
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANK_AAD, FRANKING_AGENT, PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::{
    AbuseReport, AbuseType, AbusiveMessage, ClientKeyMaterial, FanoutEvent, FanoutMessage, Frank,
    FrankingAgentData, GroupInfoOption, GroupInfoRequestTbs, GroupInfoResponse, HandshakeBundle,
    IdentifierUri, KeyMaterialRequestTbs, KeyMaterialUserCode, MAX_UNVERIFIED_ABUSIVE_MESSAGES,
    ParticipantListData, ParticipantListUpdate, Protocol, RoomMetaData, UnverifiedAbusiveMessage,
    UnverifiedAbusiveMessages, UpdateRequest, UpdateResult, UserRolePair, UserindexRolePair,
    Utf8String, franking_tag,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{
    BANNED_ROLE_INDEX, BaseRoomPolicy, Bool, Capability, Role, RoleData,
    SingleSourceRoleChangeTargets,
};
use serde_json::json;

use crate::AgentError;
use crate::client::{ConsentRecord, Jmap};
use crate::didwebvh::{DidWebvhConfig, Pin, RoomClient, check_pin, required_capabilities};
use crate::frank::{self, VerifiedFrank};
use crate::journal::{Journaled, Receipt};
use crate::state::{Held, Room, RoomStatus, State, StateDir};
use crate::uri::{normalized_uri, user_uri_domain};
use mimi_protocol::components::apply_commit_op;

/// mls-extensions-11 §5 `app_components`.
const APP_COMPONENTS: u16 = 0x0001;
/// mls-extensions-11 §5 `safe_aad` component.
const SAFE_AAD: u16 = 0x0002;
/// RFC 9420 §6 MLSMessage headers: mls10, then wire_format.
const GROUP_INFO_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];
const WELCOME_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x03];
/// Joined Welcomes remembered, so a second copy is dropped.
const MAX_CONSUMED_WELCOMES: usize = 16;
/// Messages kept for rooms not joined yet.
const MAX_HELD: usize = 256;
/// The role every participant this agent adds gets: 2, "member" in
/// [`default_roles`] (room-policy-04 §8.1.3 reserves 1 for "banned").
const ROLE: u32 = 2;
/// The role the creator of a room this agent hosts gets: 3, "admin" in
/// [`default_roles`] (decision mimid-1wgh.56).
const ADMIN_ROLE: u32 = 3;
/// room-policy-04 §8.1.3: role 1 must have this name for canBan and
/// canUnban.
const BANNED_ROLE_NAME: &str = "banned";
/// The longest text sent as one message, in octets. INVENTED, NOT FROM
/// SPEC.
pub const MAX_TEXT_LEN: usize = 16 * 1024;
const TEXT_PLAIN: &str = "text/plain;charset=utf-8";

/// What [`Agent::open`] needs.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The mimid server's base URL; the Session is at
    /// `<server_url>/.well-known/jmap`.
    pub server_url: String,
    /// The user's bearer token at that server.
    pub token: String,
    /// The user's URI, `mimi://<domain>/u/<id>`.
    pub user_uri: String,
    /// The state directory (created 0700).
    pub state_dir: PathBuf,
    /// The provider domains of hubs whose rooms get the full ratchet tree
    /// with every Commit (RatchetTreeOption `full`) instead of
    /// `distributionService`, which is the default (bead mimid-1wgh.46.20.7).
    /// Both are allowed (protocol-07 §5.3, ratchet-tree-options-02 §3);
    /// `full` is for a hub that does not rebuild the tree from the Commits
    /// it sees, and so cannot check who made a change without it. It costs
    /// the tree, which grows with the room, on every Commit. Compared
    /// without regard to ASCII case.
    pub full_tree_hubs: Vec<String>,
    /// draft-atwood-mls-didwebvh-credential-01: the code points, whether a
    /// BasicCredential identity supports `did_webvh` (default yes), and an
    /// optional log file from the user's controller that switches this
    /// device to a `did_webvh` credential (bead mimid-1wgh.4.81.18).
    pub did_webvh: DidWebvhConfig,
}

/// How [`Agent::host_room`] makes a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOptions {
    /// The room's name, put in its `room_metadata`.
    pub name: String,
    /// Whether the room carries `room_metadata` (protocol-07 §7.6). A room
    /// with it requires every member to support the component
    /// (mls-extensions-11 §5), so a room for users of providers that do
    /// not can leave it out (draft-atwood-jmap-chat-mimi-00 §Room/create).
    pub metadata: bool,
    /// An open room: no franking and no room policy, only the participant
    /// list (decision mimid-1wgh.52). A mimid hub refuses to host it
    /// unless its operator sets `require_room_policy = false` (bead
    /// mimid-jf20), and so does any hub that requires franking.
    pub open: bool,
    /// The room's `roles_list` in place of the default one (room-policy-04
    /// §3), for a room that is not open. The creator gets role 3 and
    /// participants this agent adds get role 2, so the list must define
    /// both.
    pub roles: Option<RoleData>,
}

impl HostOptions {
    /// A room named `name` with metadata, franking and the default room
    /// policy.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            metadata: true,
            open: false,
            roles: None,
        }
    }
}

/// A room this agent knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomInfo {
    /// The room URI.
    pub uri: String,
    /// Where it stands.
    pub status: RoomStatus,
}

/// The most messages [`Agent::report_abuse`] puts in one report.
/// INVENTED, NOT FROM SPEC.
pub const MAX_REPORTED_MESSAGES: usize = 16;

// Every report's unfranked messages fit the component (decision
// mimid-1wgh.60).
const _: () = assert!(MAX_REPORTED_MESSAGES <= MAX_UNVERIFIED_ABUSIVE_MESSAGES);

/// The longest `note` [`Agent::report_abuse`] sends, in octets: mimid-server's
/// default description limit. INVENTED, NOT FROM SPEC.
pub const MAX_NOTE_LEN: usize = 4096;

/// The hub's answer to [`Agent::report_abuse`], as the user's server
/// relays it (decision mimid-1wgh.58).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportOutcome {
    /// The hub accepted the report. That says nothing about any action
    /// taken (protocol-07 §5.9).
    Accepted,
    /// The hub's room policy does not let this user report
    /// (room-policy-04 §8.3 `canReportAbuse`; decision mimid-1wgh.57).
    NotAllowed,
    /// A reported message's frank did not verify at the hub (decision
    /// mimid-1wgh.6.65).
    UnverifiedMessage,
    /// Another provider's hub refused the report with this HTTP status.
    Refused {
        /// The `4xx` status.
        status: u16,
    },
}

/// A Welcome waiting for [`Agent::join`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInvite {
    /// The number [`Agent::join`] takes.
    pub number: u64,
    /// Whether the full ratchet tree came with it (a join needs it).
    pub has_ratchet_tree: bool,
}

/// A decrypted application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMessage {
    /// The room URI.
    pub room: String,
    /// The sender's user URI, from its MLS credential.
    pub sender: String,
    /// The MIMI message ID (mimi-content-10 §3.3).
    pub message_id: MessageId,
    /// The hub's acceptance time, in milliseconds since the epoch (the
    /// FanoutMessage `timestamp`, protocol-07 §5.5). With `message_id` it
    /// gives the JMAP `senderMsgId` (draft-atwood-jmap-chat-mimi-00
    /// §Message Identifiers).
    pub accepted_at: u64,
    /// The decoded content.
    pub content: MimiContent,
    /// The MLS `application_data` exactly as received: the content's
    /// encoding, which the `franking_tag` and the message ID cover. An
    /// abuse report carries these bytes (protocol-07 §5.9; decision
    /// mimid-1wgh.6.66), never a re-encoding of `content`.
    pub application_data: Vec<u8>,
    /// The text, when the content is one `text/*` part.
    pub text: Option<String>,
    /// The hub's frank, verified (protocol-07 §5.4.1.3), or `None` for an
    /// unfranked message in a room that does not require franking.
    pub frank: Option<VerifiedFrank>,
}

impl ReceivedMessage {
    /// The message's attachments: the ExternalParts at the top level or
    /// in a top-level `processAll` MultiPart (mimi-content-10 §4.5). Fetch
    /// one with [`Agent::fetch_attachment`].
    pub fn attachments(&self) -> Vec<&ExternalPart> {
        top_level_parts(&self.content.nested_part)
            .filter_map(|part| match &part.part {
                Part::External(external) => Some(external),
                _ => None,
            })
            .collect()
    }

    /// The protocol-07 §5.9 `AbusiveMessage` for reporting this message
    /// with [`Agent::report_abuse`]: its `application_data`, its frank and
    /// the hub's acceptance time. `None` for an unfranked message; report
    /// that with [`ReceivedMessage::reported_message`].
    pub fn abusive_message(&self) -> Option<AbusiveMessage> {
        self.frank.as_ref().map(|verified| AbusiveMessage {
            message_content: self.application_data.clone(),
            frank: verified.frank.clone(),
            accepted_timestamp: verified.context.accepted_timestamp,
        })
    }

    /// The message as [`Agent::report_abuse`] takes it: its
    /// [`ReceivedMessage::abusive_message`] if it is franked, otherwise its
    /// `application_data` and acceptance time, unverified (decision
    /// mimid-1wgh.60).
    pub fn reported_message(&self) -> ReportedMessage {
        self.abusive_message().map_or_else(
            || {
                ReportedMessage::Unfranked(UnverifiedAbusiveMessage {
                    message_content: self.application_data.clone(),
                    accepted_timestamp: self.accepted_at,
                })
            },
            ReportedMessage::Franked,
        )
    }
}

/// A message for [`Agent::report_abuse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportedMessage {
    /// A franked message: a protocol-07 §5.9 `AbusiveMessage`, which the
    /// hub verifies.
    Franked(AbusiveMessage),
    /// A message without a frank, sent unverified in the report's
    /// `abuse_extensions` (INVENTED, NOT FROM SPEC; decision
    /// mimid-1wgh.60). Only a mimid hub reads it.
    Unfranked(UnverifiedAbusiveMessage),
}

impl ReportedMessage {
    /// The message's `application_data` as received.
    pub fn message_content(&self) -> &[u8] {
        match self {
            Self::Franked(message) => &message.message_content,
            Self::Unfranked(message) => &message.message_content,
        }
    }
}

/// The part itself, or the parts of a top-level `processAll` MultiPart.
fn top_level_parts(part: &NestedPart) -> impl Iterator<Item = &NestedPart> {
    let parts: &[NestedPart] = match &part.part {
        Part::Multi {
            part_semantics: PartSemantics::ProcessAll,
            parts,
        } => parts,
        _ => std::slice::from_ref(part),
    };
    parts.iter()
}

/// A file to send with [`Agent::send_message`].
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingAttachment {
    /// The file's content.
    pub content: Vec<u8>,
    /// Its media type.
    pub content_type: String,
    /// A suggested file name, or empty.
    pub filename: String,
}

impl std::fmt::Debug for OutgoingAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutgoingAttachment")
            .field("len", &self.content.len())
            .field("content_type", &self.content_type)
            .field("filename", &self.filename)
            .finish()
    }
}

/// A message this agent sent: its MIMI message ID and the hub's
/// acceptance time in milliseconds (the SubmitMessageResponse's
/// `accepted_timestamp`, protocol-07 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sent {
    /// The MIMI message ID (mimi-content-10 §3.3).
    pub message_id: MessageId,
    /// The hub's acceptance time, milliseconds since the epoch.
    pub accepted_at: u64,
}

/// What [`Agent::use_did_webvh_credential`] did with a log
/// (bead mimid-1wgh.4.81.28).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DidWebvhApplied {
    /// The version number of the log's last entry.
    pub version: u64,
    /// The log is the credential the agent already holds; nothing was
    /// done.
    pub unchanged: bool,
    /// The active rooms where this device committed the new credential.
    pub committed: Vec<String>,
    /// The active rooms where the Commit could not be built, so the
    /// credential was sent as an Update proposal for another member to
    /// commit (`Member::propose_credential_update`).
    pub proposed: Vec<String>,
    /// The active rooms where neither worked, with why. Each is also an
    /// [`Event::Problem`].
    pub failed: Vec<(String, String)>,
}

/// How [`Agent::offer_credential`] offered a new credential to a room.
enum Offered {
    Committed,
    Proposed,
}

/// The user a moderation operation acts on, in one room.
struct Target {
    /// Its index in the participant list.
    index: u32,
    /// Its role.
    role_index: u32,
    /// Its leaves in the group.
    leaves: Vec<u32>,
}

/// What [`Agent::join_own_rooms`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OwnRoomsJoined {
    /// The rooms joined by external Commit.
    pub joined: Vec<String>,
    /// The rooms not joined because of an error, with why.
    pub failed: Vec<(String, String)>,
    /// The rooms not this device's to join, with why: no device of the
    /// user accepted the room's invite, the server keeps no record of
    /// accepted rooms, the hub does not let the user in, the group holds
    /// no client of the user, or this device has a pending invite to the
    /// room. A room not accepted is looked at again at the next call; the
    /// others not until the agent is opened again.
    pub skipped: Vec<(String, String)>,
}

/// Why a room of [`Agent::join_own_rooms`] was not joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotJoined {
    /// It may work later: tried again at the next call.
    Later,
    /// An error that will not pass.
    Never,
    /// Not this device's to join.
    Skip,
}

/// What [`Agent::poll`] (and [`Agent::join`]'s replay of held messages)
/// found, for the caller to turn into its own objects.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A Welcome arrived; [`Agent::join`] with `number` accepts it.
    InviteArrived {
        /// The invite's number.
        number: u64,
    },
    /// A message (boxed: it is far larger than the other events).
    Message(Box<ReceivedMessage>),
    /// A Commit changed the room; `participants` is the participant list
    /// after it.
    MembersChanged {
        /// The room URI.
        room: String,
        /// The epoch after the Commit.
        epoch: u64,
        /// The participants' user URIs.
        participants: Vec<String>,
        /// The user URI of the Commit's sender: the user of the leaf that
        /// sent it, as that leaf named it before the Commit, or for an
        /// external Commit (RFC 9420 §12.4.3.2) the joiner; this user's
        /// own URI for a Commit of this device. The hub is never the
        /// committer: RFC 9420 §6.1 lets an external sender send only
        /// proposals, so a hub proposal is committed by a member, who is
        /// then the committer. `None` when not known: a leaf whose
        /// credential names no user, or an event journaled before the
        /// committer was recorded (bead mimid-cqof).
        committer: Option<String>,
    },
    /// Another member proposed something (protocol-07 §3.5: a leave).
    Proposal {
        /// The room URI.
        room: String,
        /// The proposer's user URI, or `None` for an external sender.
        sender: Option<String>,
    },
    /// This user is out of the room.
    Left {
        /// The room URI.
        room: String,
    },
    /// draft-atwood-mls-didwebvh-credential-01 §Reference Identifiers: a
    /// leaf in a room presents another SCID for a contact than the one
    /// pinned for it, or a BasicCredential for a contact pinned to an SCID
    /// (decision mimid-1wgh.4.81.21). The draft's "MUST alert the user".
    /// The pin is kept.
    IdentityChanged {
        /// The room URI.
        room: String,
        /// The contact's user URI.
        user: String,
        /// The SCID pinned for the contact.
        pinned: String,
        /// The SCID the leaf presents, or `None` for a BasicCredential.
        presented: Option<String>,
    },
    /// A Commit that changed the `did_webvh` record removed a client of
    /// `user` because its leaf lacks the AppDataUpdate proposal type
    /// (mls-extensions-11 §4.7; decision mimid-1wgh.4.81.37; bead
    /// mimid-4lp4.4): its app could not take part in the update, and it
    /// can rejoin. Reported for Commits of other members and of this
    /// device, once per removed client.
    RemovedWithoutAppDataUpdate {
        /// The room URI.
        room: String,
        /// The removed client's user URI, empty if its leaf names none.
        user: String,
        /// The epoch the Commit made.
        epoch: u64,
    },
    /// An item could not be handled; it is dropped. Polling goes on.
    Problem {
        /// The room, when known.
        room: Option<String>,
        /// What went wrong.
        description: String,
    },
}

/// One user's MIMI client: its MLS groups and the JMAP connection to its
/// server. See the crate documentation.
pub struct Agent {
    me: String,
    identity: Identity,
    state: State,
    dir: StateDir,
    jmap: Jmap,
    members: BTreeMap<String, Member>,
    /// [`AgentConfig::full_tree_hubs`], lowercase.
    full_tree_hubs: std::collections::BTreeSet<String>,
    /// The room and leaf of a member whose leave proposals are stored and
    /// not yet committed.
    deferred_leaver: Option<(String, u32)>,
    /// The users of the clients the pending Commit of a room removes for
    /// lacking AppDataUpdate ([`Event::RemovedWithoutAppDataUpdate`]),
    /// reported once the hub accepts it.
    pending_removed: Option<(String, Vec<String>)>,
    /// [`AgentConfig::did_webvh`].
    did_webvh: DidWebvhConfig,
    /// Rooms [`Agent::join_own_rooms`] does not try again until a restart
    /// (decision mimid-1wgh.61 item 5).
    not_joinable: std::collections::BTreeSet<String>,
    /// Test only: building a credential-update Commit fails, to exercise
    /// the fallback of [`Agent::use_did_webvh_credential`] through a real
    /// hub.
    #[cfg(test)]
    fail_credential_commits: bool,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("user", &self.me)
            .field("rooms", &self.state.rooms.len())
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// Opens the state directory (minting an identity on first use) and
    /// reads the server's JMAP Session.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] if `user_uri` is not a user URI,
    /// [`AgentError::State`] if the state directory cannot be used or is
    /// another user's, and the errors of reading the Session.
    pub async fn open(config: AgentConfig) -> Result<Self, AgentError> {
        if user_uri_domain(&config.user_uri).is_none() {
            return Err(AgentError::Invalid(format!(
                "{} is not a mimi://<domain>/u/<id> user URI",
                config.user_uri
            )));
        }
        let dir = StateDir::open(&config.state_dir)?;
        let (identity, state) = dir.load_or_create(&config.user_uri, &config.did_webvh)?;
        let jmap = Jmap::open(&config.server_url, &config.token).await?;
        jmap.restore_sent(&state.sent);
        let mut agent = Self {
            me: config.user_uri,
            identity,
            state,
            dir,
            jmap,
            members: BTreeMap::new(),
            full_tree_hubs: config
                .full_tree_hubs
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            deferred_leaver: None,
            pending_removed: None,
            did_webvh: config.did_webvh.clone(),
            not_joinable: std::collections::BTreeSet::new(),
            #[cfg(test)]
            fail_credential_commits: false,
        };
        let rooms: Vec<(String, Room)> = agent
            .state
            .rooms
            .iter()
            .filter(|(_, room)| room.status != RoomStatus::Left)
            .map(|(uri, room)| (uri.clone(), room.clone()))
            .collect();
        for (uri, room) in rooms {
            let group_id = agent
                .state
                .group_rooms
                .iter()
                .find(|(_, r)| **r == uri)
                .and_then(|(hex_id, _)| hex::decode(hex_id).ok())
                .unwrap_or_else(|| uri.as_bytes().to_vec());
            match Member::load(&agent.identity, &group_id) {
                Ok(mut member) => {
                    if let Some((epoch, reason)) = room.out_of_sync {
                        member.restore_out_of_sync(OutOfSync::new(epoch, reason));
                    }
                    agent.members.insert(uri, member);
                }
                Err(e) => agent.deliver(vec![Event::Problem {
                    room: Some(uri.clone()),
                    description: format!("cannot reload the MLS group: {e}"),
                }]),
            }
        }
        if let Some(path) = config.did_webvh.log_file.as_deref() {
            let credential = read_did_webvh_files(path, config.did_webvh.witness_file.as_deref())?;
            // A file older than the log the agent holds (one handed to the
            // running agent since, bead mimid-1wgh.4.81.28) is not an
            // error at start: the agent keeps the newer one.
            let older = match (
                agent.identity.did_webvh_log(),
                mimi_mls::mls_didwebvh::verify_credential(&credential),
            ) {
                (Some(current), Ok(file)) => {
                    file.is_prefix_of(current)
                        && file.head_version_number() < current.head_version_number()
                }
                _ => false,
            };
            if older {
                tracing::warn!(
                    name: "did_webvh_log_file_older",
                    "the did_webvh log file is older than the log the agent holds; keeping that"
                );
            } else {
                agent.use_did_webvh_credential(credential).await?;
            }
        }
        Ok(agent)
    }

    /// This device's Ed25519 signature public key: what the user's
    /// controller lists as an authorized key in the did:webvh log to give
    /// this device a `did_webvh` credential (draft-atwood-mls-didwebvh-
    /// credential-01 §Adding a Device, step 1).
    pub fn signature_public_key(&self) -> &[u8] {
        self.identity.signature_public_key()
    }

    /// The SCID of this device's `did_webvh` credential, or `None` with a
    /// BasicCredential.
    pub fn did_webvh_scid(&self) -> Option<&str> {
        self.identity.did_webvh_log().map(|log| log.scid())
    }

    /// The SCID pinned for `user` (draft-atwood-mls-didwebvh-credential-01
    /// §Reference Identifiers), if any.
    pub fn pinned_scid(&self, user: &str) -> Option<&str> {
        self.state
            .pinned_scids
            .get(normalized_uri(user).as_ref())
            .map(String::as_str)
    }

    /// Takes `credential`, a `did_webvh` credential from the user's
    /// controller (draft-atwood-mls-didwebvh-credential-01), and offers it
    /// to every active room. This is the one check-and-apply path for a
    /// new log, whether it comes from [`Agent::open`]'s log file, the
    /// daemon's endpoint or its watch of that file (bead
    /// mimid-1wgh.4.81.28).
    ///
    /// A log equal to the credential the agent holds changes nothing
    /// ([`DidWebvhApplied::unchanged`]). Otherwise the log must verify,
    /// authorize this device's signature key, and name this user's URI in
    /// `alsoKnownAs` (decision mimid-1wgh.4.81.21). The first credential
    /// may be taken only by a fresh identity, before any KeyPackage or
    /// room (see [`crate::didwebvh`]). A later one must extend the current
    /// log (§Successor Credentials). Each active room then gets a Commit
    /// whose UpdatePath carries it, with the record change and the Removes
    /// of devices the new log no longer lists (§Revoking a Device). Where
    /// that Commit cannot be built, the credential is sent instead as an
    /// Update proposal (`Member::propose_credential_update`) for another
    /// member to commit (§Rules). The record is an `app_data_dictionary`
    /// component (decision mimid-1wgh.4.81.33), so another party's pending
    /// GroupContextExtensions proposal does not stop the Commit (the
    /// draft's Open Issue 5). A room where
    /// neither works is in [`DidWebvhApplied::failed`] and reported as an
    /// [`Event::Problem`] at the next [`Agent::poll`]. A device the new log
    /// revokes cannot take it at all.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] if the log names another user or the
    /// identity is not fresh, [`AgentError::Mls`] if the credential does not
    /// verify, authorize this device, or extend the current one, and
    /// [`AgentError::State`] if it cannot be saved. Nothing is changed
    /// then.
    pub async fn use_did_webvh_credential(
        &mut self,
        credential: mimi_mls::mls_didwebvh::DidWebvhCredential,
    ) -> Result<DidWebvhApplied, AgentError> {
        let log = mimi_mls::mls_didwebvh::verify_credential(&credential)
            .map_err(|e| AgentError::mls("verifying the did_webvh log", e))?;
        if self.identity.did_webvh_credential() == Some(&credential) {
            return Ok(DidWebvhApplied {
                version: log.head_version_number(),
                unchanged: true,
                ..DidWebvhApplied::default()
            });
        }
        let named = mimi_mls::didwebvh::mimi_user_uri(&log).map(normalized_uri);
        if named != Some(normalized_uri(&self.me)) {
            return Err(AgentError::Invalid(format!(
                "the did_webvh log does not name {} in alsoKnownAs",
                self.me
            )));
        }
        let first = self.identity.did_webvh_credential().is_none();
        if first && (self.state.signature_key_bound || !self.state.rooms.is_empty()) {
            return Err(AgentError::Invalid(
                "a BasicCredential identity that published a KeyPackage or joined a room cannot \
                 switch to did_webvh"
                    .to_owned(),
            ));
        }
        let encoded = credential
            .encode()
            .map_err(|e| AgentError::encoding("the did_webvh credential", e))?;
        self.identity
            .set_did_webvh_credential(self.did_webvh.code_points, credential)
            .map_err(|e| AgentError::mls("taking the did_webvh credential", e))?;
        self.state.did_webvh_credential = Some(hex::encode(encoded));
        self.save()?;
        tracing::info!(
            name: "did_webvh_credential_taken",
            version = log.head_version_number(),
            "did_webvh credential taken"
        );
        let rooms: Vec<String> = self
            .state
            .rooms
            .iter()
            .filter(|(_, room)| room.status == RoomStatus::Active)
            .map(|(uri, _)| uri.clone())
            .collect();
        let mut applied = DidWebvhApplied {
            version: log.head_version_number(),
            ..DidWebvhApplied::default()
        };
        let mut events = Vec::new();
        for room in rooms {
            match self.offer_credential(&room).await {
                Ok(Offered::Committed) => {
                    events.push(Event::MembersChanged {
                        committer: Some(self.me.clone()),
                        epoch: self.members.get(&room).map_or(0, Member::epoch),
                        participants: self
                            .members
                            .get(&room)
                            .map(participants)
                            .transpose()
                            .ok()
                            .flatten()
                            .unwrap_or_default(),
                        room: room.clone(),
                    });
                    applied.committed.push(room);
                }
                Ok(Offered::Proposed) => applied.proposed.push(room),
                Err(e) => {
                    let description = format!("offering the new did_webvh credential: {e}");
                    events.push(Event::Problem {
                        room: Some(room.clone()),
                        description: description.clone(),
                    });
                    applied.failed.push((room, description));
                }
            }
        }
        tracing::info!(
            name: "did_webvh_credential_offered",
            committed = applied.committed.len(),
            proposed = applied.proposed.len(),
            failed = applied.failed.len(),
            "did_webvh credential offered to the rooms"
        );
        self.deliver(events);
        self.save()?;
        Ok(applied)
    }

    /// Offers the identity's new credential to `room`: a Commit, or, when
    /// that Commit cannot be built, an Update proposal (bead
    /// mimid-1wgh.4.81.28 (c)). A Commit the hub refuses is not retried as
    /// a proposal: the refusal is the answer.
    async fn offer_credential(&mut self, room: &str) -> Result<Offered, AgentError> {
        const WHAT: &str = "credential update";
        #[cfg(test)]
        let built = if self.fail_credential_commits {
            Err(AgentError::mls(
                format!("building the {WHAT} Commit"),
                mimi_mls::member::MemberError::Commit("injected by the test".into()),
            ))
        } else {
            self.build_commit(room, &[], &[], &[], WHAT)
        };
        #[cfg(not(test))]
        let built = self.build_commit(room, &[], &[], &[], WHAT);
        match built {
            Ok(request) => {
                self.send_commit(room, &request, WHAT).await?;
                Ok(Offered::Committed)
            }
            Err(error) => {
                tracing::info!(
                    name: "did_webvh_update_proposed",
                    error = &error as &dyn std::error::Error,
                    "the credential-update Commit cannot be built; proposing an Update instead"
                );
                let member = self
                    .members
                    .get_mut(room)
                    .ok_or_else(|| AgentError::NoSuchRoom(room.to_owned()))?;
                let proposal = member
                    .propose_credential_update(&self.identity)
                    .map_err(|e| AgentError::mls("building the credential Update proposal", e))?;
                let request = UpdateRequest {
                    bundle: HandshakeBundle::Proposal {
                        proposal_or_commit: MLSMessage::tls_deserialize_exact(&proposal[..])
                            .map_err(|e| AgentError::tls("own Update proposal", e))?,
                        more_proposals: vec![],
                    },
                };
                self.update_ok(room, &request, "credential Update proposal")
                    .await?;
                Ok(Offered::Proposed)
            }
        }
    }

    /// The leaves of an active room: each one's user and, for a `did_webvh`
    /// leaf, its SCID (draft-atwood-mls-didwebvh-credential-01 §Negotiation:
    /// "Applications SHOULD indicate to users which members are
    /// authenticated by a did_webvh credential").
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`].
    pub fn clients(&self, room: &str) -> Result<Vec<RoomClient>, AgentError> {
        let member = self.member(room)?;
        Ok(room_clients(member, &self.identity))
    }

    /// Checks every leaf of `room` against the contact pins, pinning new
    /// SCIDs, and returns an [`Event::IdentityChanged`] per mismatch.
    fn check_contacts(&mut self, room: &str) -> Vec<Event> {
        let Some(member) = self.members.get(room) else {
            return Vec::new();
        };
        let me = normalized_uri(&self.me);
        let mut events = Vec::new();
        for client in room_clients(member, &self.identity) {
            let user = normalized_uri(&client.user);
            if client.user.is_empty() || user == me {
                continue;
            }
            if let Pin::Changed { pinned, presented } =
                check_pin(&mut self.state.pinned_scids, &user, client.scid.as_deref())
            {
                tracing::warn!(
                    name: "did_webvh_scid_changed",
                    leaf = client.leaf,
                    "a contact's leaf presents another SCID than the pinned one"
                );
                events.push(Event::IdentityChanged {
                    room: room.to_owned(),
                    user: client.user,
                    pinned,
                    presented,
                });
            }
        }
        events
    }

    /// The user's URI.
    pub fn user(&self) -> &str {
        &self.me
    }

    /// The rooms this agent knows, including left ones.
    pub fn rooms(&self) -> Vec<RoomInfo> {
        self.state
            .rooms
            .iter()
            .map(|(uri, room)| RoomInfo {
                uri: uri.clone(),
                status: room.status,
            })
            .collect()
    }

    /// The participant list (protocol-07 §7.5) of an active room.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`], or [`AgentError::Encoding`] if the list
    /// does not decode.
    pub fn participants(&self, room: &str) -> Result<Vec<String>, AgentError> {
        participants(self.member(room)?)
    }

    /// The `room_name` of an active room's `room_metadata` (protocol-07
    /// §7.6), or `None` if the room has no metadata or it does not decode.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`].
    pub fn room_name(&self, room: &str) -> Result<Option<String>, AgentError> {
        Ok(self
            .member(room)?
            .component(ROOM_METADATA)
            .and_then(|data| RoomMetaData::tls_deserialize_exact(data).ok())
            .map(|metadata| metadata.room_name.as_str().to_owned()))
    }

    /// The Welcomes waiting for [`Agent::join`].
    pub fn invites(&self) -> Vec<PendingInvite> {
        self.state
            .invites
            .iter()
            .map(|i| PendingInvite {
                number: i.number,
                has_ratchet_tree: i.ratchet_tree.is_some(),
            })
            .collect()
    }

    /// The TLS-encoded ratchet tree (RFC 9420 §12.4.3.3) of an active
    /// room in the current epoch: public group state, for diagnostics and
    /// for checking that members agree.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`], and the MLS error of exporting it.
    pub fn ratchet_tree(&self, room: &str) -> Result<Vec<u8>, AgentError> {
        self.member(room)?
            .ratchet_tree()
            .map_err(|e| AgentError::mls("exporting the ratchet tree", e))
    }

    /// The MLS epoch authenticator (RFC 9420 §8.7) of an active room, for
    /// checking that members agree.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`].
    pub fn epoch_authenticator(&self, room: &str) -> Result<Vec<u8>, AgentError> {
        Ok(self.member(room)?.epoch_authenticator().to_vec())
    }

    /// The MLS epoch of an active room.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`].
    pub fn epoch(&self, room: &str) -> Result<u64, AgentError> {
        Ok(self.member(room)?.epoch())
    }

    /// How many published KeyPackages are thought unused (an estimate).
    pub fn key_packages_outstanding(&self) -> u32 {
        self.state.key_packages_outstanding
    }

    /// Publishes `n` one-time KeyPackages (KeyPackage/set).
    ///
    /// # Errors
    ///
    /// The first failure; those published before it stay published.
    pub async fn publish_key_packages(&mut self, n: u32) -> Result<(), AgentError> {
        for _ in 0..n {
            let bytes = self
                .identity
                .key_package(KeyPackageKind::OneTime)
                .map_err(|e| AgentError::mls("minting a KeyPackage", e))?;
            self.jmap.publish_key_package(&bytes).await?;
            self.state.key_packages_outstanding += 1;
            self.state.signature_key_bound = true;
            self.save()?;
        }
        Ok(())
    }

    /// Has the server host a new room (Room/create) with this user as its
    /// only participant, and returns the room URI. The room ID is the
    /// server's `roomIdPrefix` and the base32 of 16 random octets, the MLS
    /// group ID 16 more random octets (draft-atwood-jmap-chat-mimi-00
    /// §Room/create). The server accepts the room only from a signature key
    /// bound to the account, which the first KeyPackage/set does; if this
    /// identity never published one, one is published first.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] for a name of more than 255 octets, the
    /// errors of building the group, and the server's refusal.
    pub async fn host_room(&mut self, options: &HostOptions) -> Result<String, AgentError> {
        if options.name.len() > 255 {
            return Err(AgentError::Invalid(
                "a room name is at most 255 octets".to_owned(),
            ));
        }
        if !self.state.signature_key_bound {
            self.publish_key_packages(1).await?;
        }
        let room = format!("{}{}", self.jmap.room_id_prefix, base32(&random::<16>()?));
        let group_id = random::<16>()?.to_vec();
        let sender = self.jmap.hub_sender.clone();
        let mut components: Vec<(u16, Vec<u8>)> = if options.open {
            vec![
                (APP_COMPONENTS, vec![0x02, 0x00, 0x22]),
                // An open room has no roles_list: any non-zero role.
                (PARTICIPANT_LIST, participant_list(&self.me, ROLE)?),
            ]
        } else {
            let mut franking_key = vec![0x20];
            franking_key.extend_from_slice(&sender.signature_key);
            let franking_credential = [
                vec![0x00, 0x01], // CredentialType basic
                encode(&VLBytes::new(sender.identity.as_bytes().to_vec()))?,
            ]
            .concat();
            let franking_agent = encode(&FrankingAgentData {
                franking_signature_key: SignaturePublicKey::tls_deserialize_exact(
                    &franking_key[..],
                )
                .map_err(|e| AgentError::tls("the hub's signature key", e))?,
                credential: Credential::tls_deserialize_exact(&franking_credential[..])
                    .map_err(|e| AgentError::tls("the hub's credential", e))?,
            })?;
            vec![
                // app_components: franking_agent, participant_list,
                // roles_list, base_room_policy; every member's leaf must
                // list them, and frank_aad (safe_aad below).
                (
                    APP_COMPONENTS,
                    vec![0x08, 0x00, 0x21, 0x00, 0x22, 0x00, 0x25, 0x00, 0x27],
                ),
                (SAFE_AAD, vec![0x02, 0x00, 0x20]),
                (FRANKING_AGENT, franking_agent),
                // The creator is the room's admin (decision
                // mimid-1wgh.56).
                (PARTICIPANT_LIST, participant_list(&self.me, ADMIN_ROLE)?),
                (
                    ROLES_LIST,
                    encode(&options.roles.clone().unwrap_or_else(default_roles))?,
                ),
                (BASE_ROOM_POLICY, encode(&default_base_policy())?),
            ]
        };
        if options.metadata {
            let metadata = room_metadata(&room, &options.name)?;
            let at = components
                .iter()
                .position(|(id, _)| *id > ROOM_METADATA)
                .unwrap_or(components.len());
            components.insert(at, (ROOM_METADATA, metadata));
            if let Some((_, list)) = components.iter_mut().find(|(id, _)| *id == APP_COMPONENTS) {
                *list = add_component_id(list, ROOM_METADATA)?;
            }
        }
        let senders = [ExternalSender {
            signature_key: sender.signature_key.to_vec(),
            identity: sender.identity.into_bytes(),
        }];
        let mut member = Member::create(&self.identity, &group_id, &senders, &components)
            .map_err(|e| AgentError::mls("creating the MLS group", e))?;
        let bundle = member
            .commit(&self.identity, &[], &[], &[], apply_commit_op)
            .map_err(|e| AgentError::mls("the first Commit", e))?;
        member
            .merge_pending_commit(&self.identity)
            .map_err(|e| AgentError::mls("merging the first Commit", e))?;
        let tree = member
            .ratchet_tree()
            .map_err(|e| AgentError::mls("the ratchet tree", e))?;
        let hosted = self
            .jmap
            .create_room(&room, &bundle.group_info, &tree)
            .await?;
        if hosted != room {
            return Err(AgentError::malformed(
                "Room/create",
                format!("answered roomId {hosted}, not {room}"),
            ));
        }
        self.state
            .group_rooms
            .insert(hex::encode(&group_id), room.clone());
        self.members.insert(room.clone(), member);
        self.state.rooms.insert(
            room.clone(),
            Room {
                status: RoomStatus::Active,
                out_of_sync: None,
                joined_epoch: None,
            },
        );
        self.save()?;
        Ok(room)
    }

    /// Adds `user` to `room`: their KeyPackages through KeyMaterial/fetch
    /// (protocol-07 §5.2), then one Commit with the Adds and one
    /// ParticipantListUpdate (§3.2). The server fans the Commit and the
    /// Welcome out.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoKeyMaterial`] if the user has not consented or has
    /// no usable KeyPackage, [`AgentError::Refused`] if the hub refuses the
    /// Commit, and the errors of building it.
    pub async fn invite(&mut self, room: &str, user: &str) -> Result<(), AgentError> {
        if user_uri_domain(user).is_none() {
            return Err(AgentError::Invalid(format!("{user} is not a user URI")));
        }
        let before = participants(self.member(room)?)?;
        if before
            .iter()
            .any(|u| normalized_uri(u) == normalized_uri(user))
        {
            return Err(AgentError::Invalid(format!(
                "{user} is already a participant"
            )));
        }
        let did_webvh_room = self
            .member(room)?
            .did_webvh_heads(&self.identity)
            .ok()
            .flatten()
            .and(self.identity.did_webvh_code_points());
        let required = required_capabilities(did_webvh_room);
        let request_required = RequiredCapabilities::tls_deserialize_exact(&required)
            .map_err(|e| AgentError::tls("own RequiredCapabilities", e))?;
        let request = key_material_request(&self.me, user, room, &required)?;
        let response = self.jmap.key_material(&request).await?;
        match response.user_status {
            KeyMaterialUserCode::Success | KeyMaterialUserCode::PartialSuccess => {}
            code => {
                return Err(AgentError::NoKeyMaterial {
                    user: user.to_owned(),
                    code: format!("{code:?}"),
                });
            }
        }
        let mut target = user.to_owned();
        let mut key_packages = Vec::new();
        for client in &response.clients {
            if let ClientKeyMaterial::Success { key_package, .. } = client {
                let info = key_package
                    .verify(SystemTime::now())
                    .map_err(|e| AgentError::tls("a KeyPackage does not verify", e))?;
                // In a did_webvh room the KeyPackage must also list the
                // record component, which the request could not ask for
                // (decision mimid-1wgh.4.81.36); one that does not could
                // not be added, so it is not used.
                if let Some(code_points) = did_webvh_room
                    && !mimi_mls::didwebvh::key_package_lists_record(
                        &info,
                        &request_required,
                        code_points,
                    )
                {
                    tracing::info!(
                        name: "key_package_without_did_webvh_record",
                        "a KeyPackage from a did_webvh room's keyMaterial request does not list \
                         the record component; not used"
                    );
                    continue;
                }
                // A did_webvh KeyPackage names its user in its verified log
                // (decision mimid-1wgh.4.81.21).
                let did_webvh = match self.identity.did_webvh_code_points() {
                    Some(code_points) => info.did_webvh(code_points).map_err(|e| {
                        AgentError::malformed(
                            "KeyMaterial/fetch",
                            format!("a did_webvh KeyPackage does not verify: {e}"),
                        )
                    })?,
                    None => None,
                };
                // The URI as given may be another spelling of the one in
                // the credential (RFC 3986 §6.2.2; decision mimid-1wgh.52):
                // compare normal forms, then use the credential's bytes.
                let identity = match &did_webvh {
                    Some(log) => mimi_mls::didwebvh::mimi_user_uri(log),
                    None => info
                        .identity()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok()),
                }
                .ok_or_else(|| {
                    AgentError::malformed("KeyMaterial/fetch", "a KeyPackage names no user")
                })?;
                if normalized_uri(identity) != normalized_uri(user) {
                    return Err(AgentError::malformed(
                        "KeyMaterial/fetch",
                        format!("a KeyPackage for another identity ({identity})"),
                    ));
                }
                // draft-atwood-mls-didwebvh-credential-01 §Reference
                // Identifiers: the SCID pinned for this contact.
                let mut pins = self.state.pinned_scids.clone();
                if let Pin::Changed { pinned, presented } = check_pin(
                    &mut pins,
                    &normalized_uri(identity),
                    did_webvh.as_ref().map(|log| log.scid()),
                ) {
                    return Err(AgentError::Invalid(format!(
                        "{identity} is pinned to SCID {pinned}, and a KeyPackage presents {}",
                        presented.as_deref().unwrap_or("a BasicCredential")
                    )));
                }
                self.state.pinned_scids = pins;
                target = identity.to_owned();
                key_packages.push(encode(key_package)?);
            }
        }
        if key_packages.is_empty() {
            return Err(AgentError::NoKeyMaterial {
                user: user.to_owned(),
                code: "no usable KeyPackage".to_owned(),
            });
        }
        let adds: Vec<&[u8]> = key_packages.iter().map(Vec::as_slice).collect();
        let update = list_change(vec![], &[target.as_str()])?;
        self.commit(room, &adds, &[], &[update], "invite").await
    }

    /// The user URI of the member that sent pending invite `number`: the
    /// identity in the credential of the leaf that signed the Welcome's
    /// GroupInfo (RFC 9420 §12.4.3.1). Read without joining; the invite
    /// stays pending and its KeyPackage unused, so a caller can decide
    /// from it whether to [`Agent::join`].
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchInvite`], or the MLS error of staging the
    /// Welcome.
    pub fn inviter(&self, number: u64) -> Result<String, AgentError> {
        let (welcome, tree) = self.invite_material(number)?;
        let identity = Member::welcome_sender(&self.identity, &welcome, tree.as_deref())
            .map_err(|e| AgentError::mls("reading the Welcome", e))?;
        Ok(String::from_utf8_lossy(&identity).into_owned())
    }

    /// The Welcome and ratchet tree (if any) of pending invite `number`.
    fn invite_material(&self, number: u64) -> Result<(Vec<u8>, Option<Vec<u8>>), AgentError> {
        let invite = self
            .state
            .invites
            .iter()
            .find(|i| i.number == number)
            .ok_or(AgentError::NoSuchInvite(number))?;
        let bad_hex = |what: &str| AgentError::State {
            path: PathBuf::from("state.json"),
            detail: format!("{what} of invite {number} is not hex"),
            source: None,
        };
        let welcome = hex::decode(&invite.welcome).map_err(|_| bad_hex("the Welcome"))?;
        let tree = invite
            .ratchet_tree
            .as_deref()
            .map(hex::decode)
            .transpose()
            .map_err(|_| bad_hex("the ratchet tree"))?;
        Ok((welcome, tree))
    }

    /// Joins the room of pending invite `number` from its Welcome, and
    /// returns the room URI. Messages for the room that arrived before the
    /// join are processed; their events come with the next
    /// [`Agent::poll`].
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchInvite`], or the MLS error of joining.
    pub fn join(&mut self, number: u64) -> Result<String, AgentError> {
        let index = self
            .state
            .invites
            .iter()
            .position(|i| i.number == number)
            .ok_or(AgentError::NoSuchInvite(number))?;
        let (welcome, tree) = self.invite_material(number)?;
        // A group this device left before, perhaps under an earlier
        // version that kept its state: OpenMLS refuses the Welcome while
        // the state is there.
        if let Ok(group_id) = Member::welcome_group_id(&self.identity, &welcome, tree.as_deref())
            && !self.members.values().any(|m| m.group_id() == group_id)
            && let Ok(stale) = Member::load(&self.identity, &group_id)
        {
            forget_group(&self.identity, stale);
        }
        let member = Member::join_welcome(&self.identity, &welcome, tree.as_deref())
            .map_err(|e| AgentError::mls("joining from the Welcome", e))?
            .member;
        let used = self.state.invites.remove(index);
        self.state.consumed_welcomes.push(used.welcome);
        let excess = self
            .state
            .consumed_welcomes
            .len()
            .saturating_sub(MAX_CONSUMED_WELCOMES);
        self.state.consumed_welcomes.drain(..excess);
        // The room is the room metadata's room_uri when the group has one
        // (a Room/create room, whose group ID is random), else the group ID.
        let room = member
            .component(ROOM_METADATA)
            .and_then(|data| RoomMetaData::tls_deserialize_exact(data).ok())
            .map(|metadata| metadata.room_uri.as_str().to_owned())
            .or_else(|| {
                String::from_utf8(member.group_id().to_vec())
                    .ok()
                    .filter(|r| IdentifierUri::new(r).is_ok())
            })
            .ok_or_else(|| AgentError::Invalid("the group has no room URI".to_owned()))?;
        self.state
            .group_rooms
            .insert(hex::encode(member.group_id()), room.clone());
        let held_key = format!("group:{}", hex::encode(member.group_id()));
        self.members.insert(room.clone(), member);
        self.state.rooms.insert(
            room.clone(),
            Room {
                status: RoomStatus::Active,
                out_of_sync: None,
                joined_epoch: None,
            },
        );
        self.state.key_packages_outstanding = self.state.key_packages_outstanding.saturating_sub(1);
        let (replay, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.state.held)
            .into_iter()
            .partition(|held| held.room == room || held.room == held_key);
        self.state.held = keep;
        self.save()?;
        let mut events = self.check_contacts(&room);
        self.replay(&room, replay, &mut events);
        self.deliver(events);
        self.save()?;
        Ok(room)
    }

    /// Processes `held`, messages stored for `room` before this device
    /// joined it, in order.
    fn replay(&mut self, room: &str, held: Vec<Held>, events: &mut Vec<Event>) {
        for held in held {
            let frank = match held.frank.as_deref().map(|f| {
                hex::decode(f)
                    .ok()
                    .and_then(|b| Frank::tls_deserialize_exact(&b[..]).ok())
            }) {
                None => None,
                Some(Some(frank)) => Some(frank),
                Some(None) => {
                    events.push(Event::Problem {
                        room: Some(room.to_owned()),
                        description: "a held message's frank no longer decodes".to_owned(),
                    });
                    continue;
                }
            };
            match hex::decode(&held.message).map(|b| MLSMessage::tls_deserialize_exact(&b[..])) {
                Ok(Ok(message)) => {
                    self.incoming_mls(&message, held.accepted_at, frank.as_ref(), events)
                }
                _ => events.push(Event::Problem {
                    room: Some(room.to_owned()),
                    description: "a held message no longer decodes".to_owned(),
                }),
            }
        }
    }

    /// Joins, by external Commit, every room of this user that this
    /// device is not in (decision mimid-1wgh.61): a new device of a user
    /// ends up in the user's rooms (protocol-07 §3.6). The rooms are the
    /// `roomId`s of the account's Chats (draft-atwood-jmap-chat-mimi-00
    /// §Chat.roomId); each one this device does not know gets
    /// GroupInfo/fetch (protocol-07 §5.6) and an external Commit through
    /// Room/update. A room joins only if a device of the user accepted it
    /// (bead mimid-f2rn; decision mimid-1wgh.63): its Chat's
    /// `privateMetadata` holds `{"accepted": true}` in
    /// [`crate::ACCEPTED_NAMESPACE`]. Being added by another
    /// user's Add is not acceptance: the invite policy, or the user, of a
    /// device that got the Welcome decides that ([`Agent::join`]). A room
    /// also joins only if the group already holds a client of this user,
    /// so a participant whose clients were all kicked does not come back
    /// this way, and never if this device has a pending invite to it. The
    /// hub's room policy decides (room-policy-04 §8.1.1 `canAddOwnClient`).
    ///
    /// First, it records each room this device is an active member of as
    /// accepted (so a Welcome joined with [`Agent::join`], a room made
    /// with [`Agent::host_room`] and a room joined this way are all
    /// accepted, and so are rooms joined before acceptance was recorded),
    /// and removes the record of each room this device left or was
    /// removed from since the last call. Another device still in such a
    /// room records it again.
    ///
    /// A room whose GroupInfo the hub refuses, or that fails the checks,
    /// is not tried again until the agent is opened again, and the group
    /// state of a room not joined is deleted. A room with
    /// pending proposals is tried again at the next call. Each joined room
    /// gets an [`Event::MembersChanged`] at the next [`Agent::poll`];
    /// messages from before the join are skipped.
    ///
    /// # Errors
    ///
    /// The errors of reading the account's Chats, and
    /// [`AgentError::State`] if the state cannot be saved. A room that
    /// is not joined is in [`OwnRoomsJoined::failed`] or
    /// [`OwnRoomsJoined::skipped`], not an error.
    pub async fn join_own_rooms(&mut self) -> Result<OwnRoomsJoined, AgentError> {
        let mut outcome = OwnRoomsJoined::default();
        let chats = self.jmap.own_chats().await?;
        self.record_acceptance(&chats).await?;
        let mut rooms = Vec::new();
        for chat in chats {
            if self.state.rooms.contains_key(&chat.room) || self.not_joinable.contains(&chat.room) {
                continue;
            }
            // Decision mimid-1wgh.63; bead mimid-f2rn.
            if !self.jmap.chat_metadata {
                self.not_joinable.insert(chat.room.clone());
                outcome.skipped.push((
                    chat.room,
                    "the server keeps no record of the rooms this user accepted \
                     (Chat privateMetadata, draft-ietf-jmap-metadata-05)"
                        .to_owned(),
                ));
            } else if !chat.accepted {
                outcome.skipped.push((
                    chat.room,
                    "no device of this user has accepted the room's invite".to_owned(),
                ));
            } else {
                rooms.push(chat.room);
            }
        }
        if rooms.is_empty() {
            return Ok(outcome);
        }
        // The groups of this device's own pending invites: joining one of
        // them is the invite's business (Agent::join), not this.
        let invited: std::collections::BTreeSet<Vec<u8>> = self
            .state
            .invites
            .iter()
            .filter_map(|invite| {
                let (welcome, tree) = self.invite_material(invite.number).ok()?;
                Member::welcome_group_id(&self.identity, &welcome, tree.as_deref()).ok()
            })
            .collect();
        for room in rooms {
            match self.join_external(&room, &invited).await {
                Ok(()) => {
                    tracing::info!(
                        name: "own_room_joined",
                        room = room.as_str(),
                        "joined a room of this user by external Commit"
                    );
                    outcome.joined.push(room);
                }
                Err((error, why)) => {
                    tracing::info!(
                        name: "own_room_not_joined",
                        room = room.as_str(),
                        error = &error as &dyn std::error::Error,
                        why = ?why,
                        "a room of this user not joined by external Commit"
                    );
                    if why != NotJoined::Later {
                        self.not_joinable.insert(room.clone());
                    }
                    if why == NotJoined::Skip {
                        outcome.skipped.push((room, error.to_string()));
                    } else {
                        outcome.failed.push((room, error.to_string()));
                    }
                }
            }
        }
        Ok(outcome)
    }

    /// Records in the account's Chats (decision mimid-1wgh.63 item 6) that
    /// the user accepted each room this device is an active member of,
    /// and removes the record of each room in `withdrawn` this device is
    /// no longer in. A write the server refuses is logged and tried again
    /// at the next call.
    ///
    /// # Errors
    ///
    /// [`AgentError::State`] if the state cannot be saved.
    async fn record_acceptance(
        &mut self,
        chats: &[crate::client::OwnChat],
    ) -> Result<(), AgentError> {
        if !self.jmap.chat_metadata {
            return Ok(());
        }
        let withdrawn = std::mem::take(&mut self.state.withdrawn);
        let mut keep = Vec::new();
        for chat in chats {
            let active = self
                .state
                .rooms
                .get(&chat.room)
                .is_some_and(|r| r.status == RoomStatus::Active);
            let accepted = if active && !chat.accepted {
                true
            } else if !active && chat.accepted && withdrawn.contains(&chat.room) {
                false
            } else {
                continue;
            };
            match self.jmap.set_accepted(&chat.id, accepted).await {
                Ok(()) => tracing::info!(
                    name: "room_acceptance_recorded",
                    room = chat.room.as_str(),
                    accepted,
                    "recorded whether this user accepted a room"
                ),
                Err(error) => {
                    tracing::warn!(
                        name: "room_acceptance_not_recorded",
                        room = chat.room.as_str(),
                        accepted,
                        error = &error as &dyn std::error::Error,
                        "could not record whether this user accepted a room; trying again later"
                    );
                    if !accepted {
                        keep.push(chat.room.clone());
                    }
                }
            }
        }
        // A withdrawn room this device is back in, or whose Chat is
        // already unmarked, needs nothing more.
        if !withdrawn.is_empty() || !keep.is_empty() {
            self.state.withdrawn = keep;
            self.save()?;
        }
        Ok(())
    }

    /// Queues `room`'s record of the user's acceptance for removal by the
    /// next [`Agent::join_own_rooms`] (decision mimid-1wgh.63 item 6).
    fn withdraw(&mut self, room: &str) {
        if !self.state.withdrawn.iter().any(|r| r == room) {
            self.state.withdrawn.push(room.to_owned());
        }
    }

    /// One room of [`Agent::join_own_rooms`]. The error comes with what
    /// it means for the room.
    async fn join_external(
        &mut self,
        room: &str,
        invited: &std::collections::BTreeSet<Vec<u8>>,
    ) -> Result<(), (AgentError, NotJoined)> {
        let later = |e: AgentError| (e, NotJoined::Later);
        let never = |e: AgentError| (e, NotJoined::Never);
        let skip = |e: AgentError| (e, NotJoined::Skip);
        let (hpke_key, hpke_public) = mimi_mls::label::HpkePrivateKey::generate()
            .map_err(|e| later(AgentError::mls("the groupInfoPublicKey", e)))?;
        let request = group_info_request(&self.me, &hpke_public).map_err(later)?;
        let response = self.jmap.group_info(room, &request).await.map_err(later)?;
        let success = match GroupInfoResponse::tls_deserialize_exact(&response[..]) {
            Ok(GroupInfoResponse::Success(success)) => success,
            Ok(other) => {
                return Err(skip(AgentError::Refused {
                    what: format!("GroupInfo/fetch for {room}"),
                    reason: format!("{:?}", other.status()),
                }));
            }
            Err(e) => return Err(later(AgentError::tls("a GroupInfoResponse", e))),
        };
        // protocol-07 §5.6; draft-atwood-jmap-chat-mimi-00 §GroupInfo/fetch.
        success
            .verify()
            .map_err(|e| never(AgentError::encoding("the GroupInfoResponse signature", e)))?;
        if success.tbs().room_id != room.as_bytes() {
            return Err(never(AgentError::malformed(
                "GroupInfo/fetch",
                "the response is for another room",
            )));
        }
        let tbe = mimi_protocol::decrypt_group_info(
            &hpke_key,
            room.as_bytes(),
            &success.tbs().encrypted_groupinfo_and_tree,
        )
        .map_err(|e| never(AgentError::encoding("opening the GroupInfo", e)))?;
        // The hub refuses an external Commit while proposals are pending.
        if !tbe.pending_proposals.is_empty() {
            return Err(later(AgentError::Invalid(format!(
                "{room} has pending proposals; joining later"
            ))));
        }
        let group_info = encode(&tbe.group_info).map_err(never)?;
        // Checked before joining, so a pending invite's group gets no
        // state from this.
        if invited.contains(&group_info_group_id(&group_info).map_err(never)?) {
            return Err(skip(AgentError::Invalid(format!(
                "this device has a pending invite to {room}"
            ))));
        }
        let group_info = [GROUP_INFO_HEADER.as_slice(), &group_info].concat();
        let joined = Member::join_external(
            &self.identity,
            &group_info,
            tbe.ratchet_tree_option.ratchet_tree(),
        )
        .map_err(|e| never(AgentError::mls("joining by external Commit", e)))?;
        let member = joined.member;
        let sent = match self.check_external_join(room, &member, &success.tbs().hub_sender) {
            Ok(tree) => match commit_request(&joined.commit_bundle, tree.as_deref()) {
                Ok(request) => self
                    .update_ok(room, &request, "external join")
                    .await
                    .map_err(later),
                Err(e) => Err(never(e)),
            },
            Err(e) => Err(e),
        };
        if let Err(e) = sent {
            // Nothing of the group is kept, so a later join (a Welcome, or
            // this again) can be made.
            forget_group(&self.identity, member);
            return Err(e);
        }
        let epoch = member.epoch();
        let group_id = member.group_id().to_vec();
        self.state
            .group_rooms
            .insert(hex::encode(&group_id), room.to_owned());
        self.members.insert(room.to_owned(), member);
        self.state.rooms.insert(
            room.to_owned(),
            Room {
                status: RoomStatus::Active,
                out_of_sync: None,
                joined_epoch: Some(epoch),
            },
        );
        let held_key = format!("group:{}", hex::encode(&group_id));
        let (replay, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.state.held)
            .into_iter()
            .partition(|held| held.room == room || held.room == held_key);
        self.state.held = keep;
        self.save().map_err(later)?;
        let mut events = self.check_contacts(room);
        events.push(Event::MembersChanged {
            room: room.to_owned(),
            epoch,
            committer: Some(self.me.clone()),
            participants: self
                .members
                .get(room)
                .map(participants)
                .transpose()
                .ok()
                .flatten()
                .unwrap_or_default(),
        });
        self.replay(room, replay, &mut events);
        self.deliver(events);
        self.save().map_err(later)
    }

    /// The checks of decision mimid-1wgh.61 item 3 on a group joined by
    /// external Commit, before the Commit is sent; the tree to send with
    /// it, if the hub wants it.
    fn check_external_join(
        &self,
        room: &str,
        member: &Member,
        hub_sender: &mimi_mls::wire::ExternalSender,
    ) -> Result<Option<Vec<u8>>, (AgentError, NotJoined)> {
        let never = |e: AgentError| (e, NotJoined::Never);
        let skip = |e: AgentError| (e, NotJoined::Skip);
        let hub_sender = encode(hub_sender).map_err(never)?;
        if !member
            .external_senders()
            .map_err(|e| never(AgentError::mls("the external senders", e)))?
            .contains(&hub_sender)
        {
            return Err(never(AgentError::malformed(
                "GroupInfo/fetch",
                "the hub that answered is not the room's external sender",
            )));
        }
        if let Some(metadata) = member
            .component(ROOM_METADATA)
            .and_then(|data| RoomMetaData::tls_deserialize_exact(data).ok())
            && metadata.room_uri.as_str() != room
        {
            return Err(never(AgentError::malformed(
                "GroupInfo/fetch",
                "the group's room_uri is another room",
            )));
        }
        // Decision mimid-1wgh.61 item 3: another client of this user is
        // in the group.
        let me = normalized_uri(&self.me);
        let own_leaf = member.own_leaf_index();
        if !member.members().iter().any(|(leaf, user)| {
            *leaf != own_leaf && normalized_uri(&String::from_utf8_lossy(user)) == me
        }) {
            return Err(skip(AgentError::Invalid(format!(
                "no client of {} is in {room}",
                self.me
            ))));
        }
        let tree = if wants_full_tree(&self.full_tree_hubs, room) {
            Some(
                member
                    .ratchet_tree()
                    .map_err(|e| never(AgentError::mls("the external Commit's tree", e)))?,
            )
        } else {
            None
        };
        Ok(tree)
    }

    /// Sends `text` as a one-part `text/plain` message to `room`, and
    /// returns its MIMI message ID and the hub's acceptance time.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] for text over [`MAX_TEXT_LEN`] octets, and
    /// the errors of [`Agent::send_content`].
    pub async fn send_text(&mut self, room: &str, text: &str) -> Result<Sent, AgentError> {
        if text.len() > MAX_TEXT_LEN {
            return Err(AgentError::Invalid("message too long".to_owned()));
        }
        let content = MimiContent {
            salt: random()?,
            replaces: None,
            topic_id: vec![],
            expires: None,
            in_reply_to: None,
            mimi_extensions: Extensions {
                sender_uri: Some(self.me.clone()),
                room_uri: Some(room.to_owned()),
                other: BTreeMap::new(),
            },
            nested_part: NestedPart {
                disposition: Disposition::RENDER,
                language: String::new(),
                part: Part::Single {
                    content_type: TEXT_PLAIN.to_owned(),
                    content: text.as_bytes().to_vec(),
                },
            },
        };
        self.send_content(room, &content).await
    }

    /// Sends an edit of this user's message `replaces` in `room`: a
    /// message whose `replaces` is `replaces` and whose body is `text` as
    /// one `text/plain` part (mimi-content-10 §5.5). `replaces` names the
    /// first version of the message, however often it was edited. The
    /// edit has no `inReplyTo` or `topicId` (§9.3: an edit changes only
    /// the NestedPart; the caller edits only messages sent without them).
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] for text over [`MAX_TEXT_LEN`] octets, and
    /// the errors of [`Agent::send_content`].
    pub async fn send_edit(
        &mut self,
        room: &str,
        replaces: &MessageId,
        text: &str,
    ) -> Result<Sent, AgentError> {
        if text.len() > MAX_TEXT_LEN {
            return Err(AgentError::Invalid("message too long".to_owned()));
        }
        let part = Part::Single {
            content_type: TEXT_PLAIN.to_owned(),
            content: text.as_bytes().to_vec(),
        };
        let content = self.replacement(room, replaces, part)?;
        self.send_content(room, &content).await
    }

    /// Sends a retraction of this user's message `replaces` in `room`: a
    /// message whose `replaces` is `replaces` and whose body is a NullPart
    /// (mimi-content-10 §5.6). `replaces` names the first version.
    ///
    /// # Errors
    ///
    /// The errors of [`Agent::send_content`].
    pub async fn send_retraction(
        &mut self,
        room: &str,
        replaces: &MessageId,
    ) -> Result<Sent, AgentError> {
        let content = self.replacement(room, replaces, Part::Null)?;
        self.send_content(room, &content).await
    }

    /// The content replacing `replaces` in `room` with body `part`, with
    /// disposition `render`.
    fn replacement(
        &self,
        room: &str,
        replaces: &MessageId,
        part: Part,
    ) -> Result<MimiContent, AgentError> {
        Ok(MimiContent {
            salt: random()?,
            replaces: Some(*replaces),
            topic_id: vec![],
            expires: None,
            in_reply_to: None,
            mimi_extensions: Extensions {
                sender_uri: Some(self.me.clone()),
                room_uri: Some(room.to_owned()),
                other: BTreeMap::new(),
            },
            nested_part: NestedPart {
                disposition: Disposition::RENDER,
                language: String::new(),
                part,
            },
        })
    }

    /// Sends `text` with `attachments` to `room`. Each attachment is
    /// encrypted under its own key ([`crate::asset::seal`]), uploaded to
    /// this user's server, and sent as an ExternalPart with disposition
    /// `attachment`; the text and the attachments go in a `processAll`
    /// MultiPart (mimi-content-10 §4.5), or one attachment without text on
    /// its own. Each part's `expires` is the upload time plus the server's
    /// `assetLifetime`, or 0 (never) if the server states none
    /// ([`crate::asset::expiry`]). Without attachments this is [`Agent::send_text`]; empty
    /// text is left out.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] for text over [`MAX_TEXT_LEN`] or nothing to
    /// send, the upload's errors, and those of [`Agent::send_content`].
    pub async fn send_message(
        &mut self,
        room: &str,
        text: &str,
        attachments: &[OutgoingAttachment],
    ) -> Result<Sent, AgentError> {
        if attachments.is_empty() {
            return self.send_text(room, text).await;
        }
        if text.len() > MAX_TEXT_LEN {
            return Err(AgentError::Invalid("message too long".to_owned()));
        }
        // Before any upload: an unknown room uploads nothing.
        self.member(room)?;
        let mut parts = Vec::with_capacity(attachments.len() + 1);
        if !text.is_empty() {
            parts.push(NestedPart {
                disposition: Disposition::RENDER,
                language: String::new(),
                part: Part::Single {
                    content_type: TEXT_PLAIN.to_owned(),
                    content: text.as_bytes().to_vec(),
                },
            });
        }
        for attachment in attachments {
            let sealed = crate::asset::seal(&attachment.content)?;
            // The upload response has no time (RFC 8620 §6.1): the clock
            // before the upload stands for the server's (asset.rs).
            let uploaded_at = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let url = self.jmap.upload(sealed.stored.clone()).await?;
            parts.push(NestedPart {
                disposition: Disposition::ATTACHMENT,
                language: String::new(),
                part: Part::External(sealed.part(
                    url,
                    attachment.content_type.clone(),
                    attachment.filename.clone(),
                    String::new(),
                    crate::asset::expiry(uploaded_at, self.jmap.asset_lifetime),
                )),
            });
        }
        let content = MimiContent {
            salt: random()?,
            replaces: None,
            topic_id: vec![],
            expires: None,
            in_reply_to: None,
            mimi_extensions: Extensions {
                sender_uri: Some(self.me.clone()),
                room_uri: Some(room.to_owned()),
                other: BTreeMap::new(),
            },
            // A MultiPart has at least two parts (mimi-content-10 §4.5), so
            // one attachment without text is sent on its own.
            nested_part: if parts.len() == 1 {
                parts.remove(0)
            } else {
                NestedPart {
                    disposition: Disposition::RENDER,
                    language: String::new(),
                    part: Part::Multi {
                        part_semantics: PartSemantics::ProcessAll,
                        parts,
                    },
                }
            },
        };
        self.send_content(room, &content).await
    }

    /// Fetches attachment `part` of a message in `room` through this
    /// user's server, checks it against its contentHash, and decrypts it
    /// ([`crate::asset::open`]). An expired part (mimi-content-10 §4.5
    /// `expires`) is not fetched.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] for an expired part, the fetch's errors,
    /// and [`AgentError::Asset`] if the content does not open.
    pub fn fetch_attachment<'a>(
        &'a self,
        room: &'a str,
        part: &'a ExternalPart,
    ) -> impl Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a {
        // Only the JMAP client is held across the await, so the future is
        // Send (see Agent::consents).
        let jmap = &self.jmap;
        async move {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            if part.expires != 0 && u64::from(part.expires) < now {
                return Err(AgentError::Invalid("the attachment has expired".to_owned()));
            }
            let stored = jmap.fetch_asset(room, &part.url).await?;
            Ok(crate::asset::open(part, &stored)?)
        }
    }

    /// Sends `content` to `room` (Room/send), with a `frank_aad` item when
    /// the room's Safe AAD requires it (protocol-07 §5.4.1), and returns its
    /// MIMI message ID and the hub's acceptance time. The caller makes the
    /// salt random and sets
    /// `senderUri`/`roomUri` if it wants them.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`], encoding or MLS errors, and the hub's
    /// refusal.
    pub async fn send_content(
        &mut self,
        room: &str,
        content: &MimiContent,
    ) -> Result<Sent, AgentError> {
        let bytes = content
            .encode()
            .map_err(|e| AgentError::encoding("encoding mimi-content", e))?;
        let message_id = MessageId::compute(&self.me, room, &bytes, &content.salt)
            .map_err(|e| AgentError::encoding("the message ID", e))?;
        let member = self
            .members
            .get_mut(room)
            .ok_or_else(|| AgentError::NoSuchRoom(room.to_owned()))?;
        let safe_aad = frank_aad_items(member, &content.salt, &bytes);
        let ciphertext = member
            .send(&self.identity, &bytes, &safe_aad)
            .map_err(|e| AgentError::mls("encrypting", e))?;
        let message = MLSMessage::tls_deserialize_exact(&ciphertext[..])
            .map_err(|e| AgentError::tls("own message", e))?;
        let accepted_at = self.jmap.send(room, &message).await?;
        self.remember_sent()?;
        Ok(Sent {
            message_id,
            accepted_at,
        })
    }

    /// Starts leaving `room` (protocol-07 §3.5): a Remove of this client,
    /// a Remove of each other client of this user (room-policy-04 §8.1.2
    /// `canRemoveSelf`: "MUST simultaneously propose to remove all of its
    /// remaining clients"; bead mimid-pv2k), and the participant-list
    /// update removing this user, sent together as proposals. The user
    /// leaves on every device. The room is `Leaving` until another user's
    /// member commits them ([`Event::Left`]); if this user is the last
    /// participant the room is left at once.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`] if the room is not active, and the hub's
    /// refusal.
    pub async fn leave(&mut self, room: &str) -> Result<(), AgentError> {
        if self.state.rooms.get(room).map(|r| r.status) != Some(RoomStatus::Active) {
            return Err(AgentError::NoSuchRoom(room.to_owned()));
        }
        let list = participants(self.member(room)?)?;
        let index = list
            .iter()
            .position(|u| *u == self.me)
            .ok_or_else(|| AgentError::Invalid(format!("not in {room}'s participant list")))?;
        let alone = list.len() == 1;
        let index = u32::try_from(index)
            .map_err(|_| AgentError::Invalid("participant index".to_owned()))?;
        let member = self
            .members
            .get_mut(room)
            .ok_or_else(|| AgentError::NoSuchRoom(room.to_owned()))?;
        let own_leaf = member.own_leaf_index();
        let me = normalized_uri(&self.me);
        let siblings: Vec<u32> = room_clients(member, &self.identity)
            .into_iter()
            .filter(|client| client.leaf != own_leaf && normalized_uri(&client.user) == me)
            .map(|client| client.leaf)
            .collect();
        let remove = member
            .propose_self_remove(&self.identity)
            .map_err(|e| AgentError::mls("building the Remove proposal", e))?;
        let mut more = Vec::with_capacity(siblings.len() + 1);
        for leaf in siblings {
            more.push(
                member
                    .propose_remove(&self.identity, leaf)
                    .map_err(|e| AgentError::mls("building a Remove of another own client", e))?,
            );
        }
        more.push(
            member
                .propose_app_data_update(&self.identity, &list_change(vec![index], &[])?)
                .map_err(|e| AgentError::mls("building the leave proposal", e))?,
        );
        let request = UpdateRequest {
            bundle: HandshakeBundle::Proposal {
                proposal_or_commit: MLSMessage::tls_deserialize_exact(&remove[..])
                    .map_err(|e| AgentError::tls("own Remove proposal", e))?,
                more_proposals: more
                    .iter()
                    .map(|bytes| MLSMessage::tls_deserialize_exact(&bytes[..]))
                    .collect::<Result<_, _>>()
                    .map_err(|e| AgentError::tls("own proposal", e))?,
            },
        };
        self.update_ok(room, &request, "leave").await?;
        if let Some(r) = self.state.rooms.get_mut(room) {
            r.status = RoomStatus::Leaving;
        }
        self.withdraw(room);
        self.save()?;
        if alone {
            self.finish_leaving(room);
            self.deliver(vec![Event::Left {
                room: room.to_owned(),
            }]);
            self.save()?;
        }
        Ok(())
    }

    /// The participant list of an active room with each participant's
    /// role index (protocol-07 §7.5).
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`], or [`AgentError::Encoding`] if the list
    /// does not decode.
    pub fn participant_roles(&self, room: &str) -> Result<Vec<(String, u32)>, AgentError> {
        Ok(participant_list_of(self.member(room)?)?
            .participants
            .into_iter()
            .map(|p| (String::from_utf8_lossy(&p.user).into_owned(), p.role_index))
            .collect())
    }

    /// The roles of an active room's `roles_list` (room-policy-04 §3) as
    /// (`role_index`, `role_name`); empty for a room without one (an open
    /// room) or whose list does not decode.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`].
    pub fn roles(&self, room: &str) -> Result<Vec<(u32, String)>, AgentError> {
        Ok(self
            .member(room)?
            .component(ROLES_LIST)
            .and_then(|data| RoleData::tls_deserialize_exact(data).ok())
            .map(|roles| {
                roles
                    .roles
                    .into_iter()
                    .map(|r| (r.role_index, r.role_name))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Removes every client of `user` from `room` without changing the
    /// participant list: room-policy-04 §8.1.2 `canKick`. The user stays a
    /// participant (protocol-07 §7.5: "temporarily kicked").
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] for this user itself, a user not in the
    /// participant list or one with no client in the group,
    /// [`AgentError::Refused`] if the hub refuses (the room policy), and
    /// the errors of building the Commit.
    pub async fn kick(&mut self, room: &str, user: &str) -> Result<(), AgentError> {
        let target = self.moderation_target(room, user)?;
        if target.leaves.is_empty() {
            return Err(AgentError::Invalid(format!(
                "{user} has no client in {room}"
            )));
        }
        self.moderate(room, &target.leaves, &[], "kick").await
    }

    /// Removes `user` from `room`'s participant list and all its clients
    /// from the group, in one Commit: room-policy-04 §8.1.2
    /// `canRemoveParticipant`.
    ///
    /// # Errors
    ///
    /// As [`Agent::kick`], except that a user with no client can be
    /// removed.
    pub async fn remove(&mut self, room: &str, user: &str) -> Result<(), AgentError> {
        let target = self.moderation_target(room, user)?;
        let update = participant_change(vec![], vec![target.index])?;
        self.moderate(room, &target.leaves, &[update], "remove")
            .await
    }

    /// Bans `user` from `room`: its role becomes 1, "banned", and all its
    /// clients are removed, in one Commit (room-policy-04 §8.1.3
    /// `canBan`). A banned user stays in the participant list, so it
    /// cannot be invited again until it is unbanned.
    ///
    /// # Errors
    ///
    /// As [`Agent::remove`], and [`AgentError::Invalid`] if the user is
    /// banned already or the room has no role 1 named "banned".
    pub async fn ban(&mut self, room: &str, user: &str) -> Result<(), AgentError> {
        let target = self.moderation_target(room, user)?;
        if !self
            .roles(room)?
            .iter()
            .any(|(index, name)| *index == BANNED_ROLE_INDEX && name == BANNED_ROLE_NAME)
        {
            return Err(AgentError::Invalid(format!(
                "{room} has no \"banned\" role"
            )));
        }
        if target.role_index == BANNED_ROLE_INDEX {
            return Err(AgentError::Invalid(format!("{user} is banned already")));
        }
        let update = participant_change(
            vec![UserindexRolePair {
                user_index: target.index,
                role_index: BANNED_ROLE_INDEX,
            }],
            vec![],
        )?;
        self.moderate(room, &target.leaves, &[update], "ban").await
    }

    /// Unbans `user` in `room`: its role goes from 1, "banned", to 2, the
    /// role this agent gives every participant it adds (room-policy-04
    /// §8.1.3 `canUnban`; decision mimid-1wgh.62 item 4). No client is
    /// added.
    ///
    /// # Errors
    ///
    /// As [`Agent::remove`], and [`AgentError::Invalid`] if the user is
    /// not banned.
    pub async fn unban(&mut self, room: &str, user: &str) -> Result<(), AgentError> {
        let target = self.moderation_target(room, user)?;
        if target.role_index != BANNED_ROLE_INDEX {
            return Err(AgentError::Invalid(format!("{user} is not banned")));
        }
        self.set_role(room, &target, ROLE, "unban").await
    }

    /// Gives `user` role `role_index` in `room` (room-policy-04 §8.1.3
    /// `canChangeUserRole`). Banning is [`Agent::ban`], which also removes
    /// the user's clients, so role 1 is refused here, as is role 0
    /// (removal is [`Agent::remove`]).
    ///
    /// # Errors
    ///
    /// As [`Agent::remove`], and [`AgentError::Invalid`] for role 0 or 1
    /// or a user that has the role already.
    pub async fn change_role(
        &mut self,
        room: &str,
        user: &str,
        role_index: u32,
    ) -> Result<(), AgentError> {
        if role_index == 0 || role_index == BANNED_ROLE_INDEX {
            return Err(AgentError::Invalid(format!(
                "role {role_index} is not set by a role change; use remove or ban"
            )));
        }
        let target = self.moderation_target(room, user)?;
        if target.role_index == role_index {
            return Err(AgentError::Invalid(format!(
                "{user} has role {role_index} already"
            )));
        }
        self.set_role(room, &target, role_index, "role change")
            .await
    }

    async fn set_role(
        &mut self,
        room: &str,
        target: &Target,
        role_index: u32,
        what: &str,
    ) -> Result<(), AgentError> {
        let update = participant_change(
            vec![UserindexRolePair {
                user_index: target.index,
                role_index,
            }],
            vec![],
        )?;
        self.moderate(room, &[], &[update], what).await
    }

    /// A moderation Commit with `removes` and `updates`; once the hub has
    /// accepted it, an [`Event::MembersChanged`] for the next
    /// [`Agent::poll`], as for a Commit received, so the caller's view of
    /// the room follows this device's own change too.
    async fn moderate(
        &mut self,
        room: &str,
        removes: &[u32],
        updates: &[AppDataUpdate],
        what: &str,
    ) -> Result<(), AgentError> {
        self.commit(room, &[], removes, updates, what).await?;
        let member = self.member(room)?;
        let event = Event::MembersChanged {
            room: room.to_owned(),
            epoch: member.epoch(),
            participants: participants(member)?,
            committer: Some(self.me.clone()),
        };
        tracing::info!(name: "room_moderated", action = what, "moderation Commit accepted");
        self.deliver(vec![event]);
        self.save()
    }

    /// Where `user` is in `room`: its participant-list index, its role and
    /// its leaves. Moderation acts on another user only (room-policy-04
    /// §8.1.2, §8.1.3).
    fn moderation_target(&self, room: &str, user: &str) -> Result<Target, AgentError> {
        if self.state.rooms.get(room).map(|r| r.status) != Some(RoomStatus::Active) {
            return Err(AgentError::NoSuchRoom(room.to_owned()));
        }
        let wanted = normalized_uri(user);
        if wanted == normalized_uri(&self.me) {
            return Err(AgentError::Invalid(
                "moderation acts on another user, not on this one".to_owned(),
            ));
        }
        let member = self.member(room)?;
        let list = participant_list_of(member)?;
        let (index, entry) = list
            .participants
            .iter()
            .enumerate()
            .find(|(_, p)| normalized_uri(&String::from_utf8_lossy(&p.user)) == wanted)
            .ok_or_else(|| AgentError::Invalid(format!("{user} is not a participant of {room}")))?;
        let leaves = member
            .members()
            .into_iter()
            .filter(|(_, id)| normalized_uri(&String::from_utf8_lossy(id)) == wanted)
            .map(|(leaf, _)| leaf)
            .collect();
        Ok(Target {
            index: u32::try_from(index)
                .map_err(|_| AgentError::Invalid("participant index".to_owned()))?,
            role_index: entry.role_index,
            leaves,
        })
    }

    /// Lets `requester` fetch this user's KeyPackages for any room
    /// (Consent/set `grant`; the server tells the requester's provider).
    ///
    /// # Errors
    ///
    /// The server's refusal.
    pub async fn allow(&mut self, requester: &str) -> Result<(), AgentError> {
        self.decide(requester, "grant").await
    }

    /// Refuses `requester` (Consent/set `revoke`).
    ///
    /// # Errors
    ///
    /// The server's refusal.
    pub async fn deny(&mut self, requester: &str) -> Result<(), AgentError> {
        self.decide(requester, "revoke").await
    }

    /// Asks `target` for consent to fetch their KeyPackages for any room
    /// (Consent/set; the server sends protocol-07 §5.7 requestConsent).
    ///
    /// # Errors
    ///
    /// The server's refusal.
    pub async fn request_consent(&mut self, target: &str) -> Result<(), AgentError> {
        let args = match Self::consent_id(&self.jmap, &self.me, target).await? {
            Some(id) => json!({"update": {id: {"requested": true}}}),
            None => json!({"create": {"c": {"requesterUri": self.me, "targetUri": target}}}),
        };
        self.jmap.consent_set(args).await
    }

    /// Withdraws a consent request to `target`.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] if there is none, and the server's refusal.
    pub async fn cancel_consent(&mut self, target: &str) -> Result<(), AgentError> {
        let id = Self::consent_id(&self.jmap, &self.me, target)
            .await?
            .ok_or_else(|| AgentError::Invalid(format!("no consent request to {target}")))?;
        self.jmap
            .consent_set(json!({"update": {id: {"requested": false}}}))
            .await
    }

    /// The account's Consent records.
    ///
    /// The future borrows only the JMAP client, not the whole agent, so it
    /// is `Send`: an `Agent` is not `Sync` (its SQLite connection), and a
    /// future holding `&Agent` across an await is not `Send`.
    ///
    /// # Errors
    ///
    /// The server's refusal.
    pub fn consents(
        &self,
    ) -> impl Future<Output = Result<Vec<ConsentRecord>, AgentError>> + Send + '_ {
        let jmap = &self.jmap;
        async move { jmap.consents().await }
    }

    /// Reports `messages`, received in `room`, as abusive to the room's hub
    /// (protocol-07 §5.9) through the user's server (`Room/reportAbuse`,
    /// INVENTED, NOT FROM SPEC; decisions mimid-1wgh.58, mimid-1wgh.59).
    /// Take each message from [`ReceivedMessage::reported_message`], now or
    /// from where the caller kept it.
    ///
    /// The AbuseReport has this user as `reportingUser`, the one sender of
    /// the messages (their content's `senderUri`) as `allegedAbuserUri`,
    /// `reason` as `reasonCode` and `note` as `note`. Franked messages go
    /// in `messages`; unfranked ones in `abuse_extensions`, under mimid's
    /// component 0xF020, unverified (INVENTED, NOT FROM SPEC; decision
    /// mimid-1wgh.60), and the component is left out when there are none.
    /// The order between the two kinds is not kept. The franks are not
    /// checked again: the agent verified them on receipt (protocol-07
    /// §5.4.1.3) and the hub verifies them now. The hub's room policy
    /// decides whether this user may report (room-policy-04 §8.3
    /// `canReportAbuse`).
    ///
    /// The future borrows only the JMAP client, as [`Agent::consents`]
    /// does, so it is `Send`.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoSuchRoom`] for a room this agent never knew;
    /// [`AgentError::Invalid`] for no messages or more than
    /// [`MAX_REPORTED_MESSAGES`], a `note` over [`MAX_NOTE_LEN`] octets, or
    /// a message whose content does not decode, has no `senderUri`, names
    /// another sender than the first message or another room than `room`;
    /// and the server's errors. A refusal by the hub is not an error but a
    /// [`ReportOutcome`].
    pub fn report_abuse<'a>(
        &'a self,
        room: &str,
        messages: &[ReportedMessage],
        reason: AbuseType,
        note: &str,
    ) -> impl Future<Output = Result<ReportOutcome, AgentError>> + Send + 'a {
        let report = self.abuse_report(room, messages, reason, note);
        let room = room.to_owned();
        let jmap = &self.jmap;
        async move {
            let report = report?;
            jmap.report_abuse(&room, &report).await
        }
    }

    /// The encoded AbuseReport of [`Agent::report_abuse`].
    fn abuse_report(
        &self,
        room: &str,
        messages: &[ReportedMessage],
        reason: AbuseType,
        note: &str,
    ) -> Result<Vec<u8>, AgentError> {
        if !self.state.rooms.contains_key(room) {
            return Err(AgentError::NoSuchRoom(room.to_owned()));
        }
        if messages.is_empty() || messages.len() > MAX_REPORTED_MESSAGES {
            return Err(AgentError::Invalid(format!(
                "a report carries 1 to {MAX_REPORTED_MESSAGES} messages, not {}",
                messages.len()
            )));
        }
        if note.len() > MAX_NOTE_LEN {
            return Err(AgentError::Invalid(format!(
                "the note is over {MAX_NOTE_LEN} octets"
            )));
        }
        let mut alleged_abuser: Option<String> = None;
        for (index, message) in messages.iter().enumerate() {
            let content = MimiContent::decode(message.message_content()).map_err(|e| {
                AgentError::Invalid(format!("reported message {index} is not mimi-content: {e}"))
            })?;
            let extensions = content.mimi_extensions;
            if extensions.room_uri.as_deref() != Some(room) {
                return Err(AgentError::Invalid(format!(
                    "reported message {index} is not from the room {room}"
                )));
            }
            let sender = extensions.sender_uri.ok_or_else(|| {
                AgentError::Invalid(format!("reported message {index} has no senderUri"))
            })?;
            match &alleged_abuser {
                None => alleged_abuser = Some(sender),
                Some(first) if *first == sender => {}
                Some(_) => {
                    return Err(AgentError::Invalid(format!(
                        "reported message {index} has another sender than the first: \
                         a report names one alleged abuser"
                    )));
                }
            }
        }
        let uri = |value: &str, what: &str| {
            IdentifierUri::new(value)
                .map_err(|e| AgentError::Invalid(format!("{what} is not a MIMI URI: {e}")))
        };
        let alleged_abuser = alleged_abuser.unwrap_or_default();
        let mut franked = Vec::new();
        let mut unfranked = Vec::new();
        for message in messages {
            match message {
                ReportedMessage::Franked(message) => franked.push(message.clone()),
                ReportedMessage::Unfranked(message) => unfranked.push(message.clone()),
            }
        }
        // Decision mimid-1wgh.60; MAX_REPORTED_MESSAGES is below
        // MAX_UNVERIFIED_ABUSIVE_MESSAGES, so the list always encodes.
        let abuse_extensions = if unfranked.is_empty() {
            AppDataDictionary::default()
        } else {
            UnverifiedAbusiveMessages {
                messages: unfranked,
            }
            .to_extensions()
            .map_err(|e| AgentError::tls("the unverified messages", e))?
        };
        encode(&AbuseReport {
            reporting_user: uri(&self.me, "this user")?,
            alleged_abuser_uri: uri(&alleged_abuser, "the senderUri")?,
            reason_code: reason,
            note: note.as_bytes().to_vec(),
            messages: franked,
            abuse_extensions,
        })
    }

    /// Reads what the server stored since the last poll and handles it:
    /// Welcomes become invites, Commits and proposals change the groups,
    /// application messages are decrypted. A member's leave proposals are
    /// committed by the remaining member with the lowest leaf index.
    ///
    /// Returns every event not yet acknowledged, oldest first: those of
    /// earlier calls (and of [`Agent::join`] and [`Agent::leave`]) and the
    /// new ones. They are saved in the state directory before they are
    /// returned and stay there until [`Agent::acknowledge`] with the
    /// [`Receipt`], so a caller that crashes before storing them gets them
    /// again (the module `journal`); the caller must tolerate an event it
    /// has seen. [`Agent::poll`] acknowledges at once.
    ///
    /// # Errors
    ///
    /// The errors of reaching the server, and [`AgentError::State`] if the
    /// state cannot be saved. An item that cannot be handled is an
    /// [`Event::Problem`], not an error.
    pub async fn receive(&mut self) -> Result<(Vec<Event>, Receipt), AgentError> {
        let since = self.state.message_state.clone();
        let (state, messages) = self.jmap.messages_since(since.as_deref()).await?;
        for (id, body) in &messages {
            if self.state.handled.contains(id) {
                continue;
            }
            let mut events = Vec::new();
            if !self.jmap.is_own(body) {
                self.incoming(body, &mut events).await;
            }
            // One save per Message: its events and that it was handled.
            self.deliver(events);
            self.state.handled.push(id.clone());
            self.save()?;
        }
        // A leave stored outside a proposal bundle (a join's replay).
        if let Some((room, leaf)) = self.deferred_leaver.take() {
            let mut events = Vec::new();
            self.maybe_commit_leave(&room, leaf, &mut events).await;
            self.deliver(events);
        }
        self.state.message_state = Some(state);
        self.state.handled.clear();
        self.remember_sent()?;
        let events = self.state.journal.iter().map(Journaled::event).collect();
        Ok((
            events,
            Receipt {
                count: self.state.journal.len(),
            },
        ))
    }

    /// Drops the events `receipt` delivered from the journal: the caller
    /// has stored them. Events found since stay.
    ///
    /// # Errors
    ///
    /// [`AgentError::State`] if the state cannot be saved; the events then
    /// come again.
    pub fn acknowledge(&mut self, receipt: Receipt) -> Result<(), AgentError> {
        if receipt.count == 0 {
            return Ok(());
        }
        let count = receipt.count.min(self.state.journal.len());
        self.state.journal.drain(..count);
        self.save()
    }

    /// [`Agent::receive`] and [`Agent::acknowledge`] together, for a
    /// caller that keeps nothing it could lose: a crash after this returns
    /// loses the events.
    ///
    /// # Errors
    ///
    /// Those of [`Agent::receive`] and [`Agent::acknowledge`].
    pub async fn poll(&mut self) -> Result<Vec<Event>, AgentError> {
        let (events, receipt) = self.receive().await?;
        self.acknowledge(receipt)?;
        Ok(events)
    }

    // ---- internals ----

    fn member(&self, room: &str) -> Result<&Member, AgentError> {
        self.members
            .get(room)
            .ok_or_else(|| AgentError::NoSuchRoom(room.to_owned()))
    }

    fn save(&self) -> Result<(), AgentError> {
        self.dir.save(&self.state)
    }

    /// Adds `events` to the journal; the next save keeps them.
    fn deliver(&mut self, events: Vec<Event>) {
        self.state
            .journal
            .extend(events.into_iter().map(Journaled::of));
    }

    /// Saves the sent-message digests with the state.
    fn remember_sent(&mut self) -> Result<(), AgentError> {
        self.state.sent = self.jmap.sent_digests();
        self.save()
    }

    /// The id of the any-room Consent record from `requester` to `target`.
    /// It takes the JMAP client, not `&self`, so the futures of its callers
    /// stay `Send` (see [`Agent::consents`]).
    async fn consent_id(
        jmap: &Jmap,
        requester: &str,
        target: &str,
    ) -> Result<Option<String>, AgentError> {
        Ok(jmap
            .consents()
            .await?
            .into_iter()
            .find(|r| r.requester == requester && r.target == target && r.room.is_none())
            .map(|r| r.id))
    }

    async fn decide(&mut self, requester: &str, decision: &str) -> Result<(), AgentError> {
        let args = match Self::consent_id(&self.jmap, requester, &self.me).await? {
            Some(id) => json!({"update": {id: {"decision": decision}}}),
            None => json!({"create": {"c": {"requesterUri": requester, "targetUri": self.me,
                                            "decision": decision}}}),
        };
        self.jmap.consent_set(args).await
    }

    /// Room/update with `request`; anything but success is
    /// [`AgentError::Refused`].
    async fn update_ok(
        &mut self,
        room: &str,
        request: &UpdateRequest,
        what: &str,
    ) -> Result<(), AgentError> {
        let response = self.jmap.update(room, request).await?;
        self.remember_sent()?;
        match response.result {
            UpdateResult::Success { .. } => Ok(()),
            other => Err(AgentError::Refused {
                what: format!("{what} in {room}"),
                reason: format!("{other:?} {}", response.error_description.as_str())
                    .trim()
                    .to_owned(),
            }),
        }
    }

    /// A Commit with `adds`, `removes` and `updates`, sent and merged; on a
    /// refusal the pending Commit is cleared.
    async fn commit(
        &mut self,
        room: &str,
        adds: &[&[u8]],
        removes: &[u32],
        updates: &[AppDataUpdate],
        what: &str,
    ) -> Result<(), AgentError> {
        let request = self.build_commit(room, adds, removes, updates, what)?;
        self.send_commit(room, &request, what).await
    }

    /// Builds a Commit with `adds`, `removes` and `updates`, left pending,
    /// as the UpdateRequest that carries it. Nothing is pending on an
    /// error.
    fn build_commit(
        &mut self,
        room: &str,
        adds: &[&[u8]],
        removes: &[u32],
        updates: &[AppDataUpdate],
        what: &str,
    ) -> Result<UpdateRequest, AgentError> {
        let member = self
            .members
            .get_mut(room)
            .ok_or_else(|| AgentError::NoSuchRoom(room.to_owned()))?;
        let before = room_clients(member, &self.identity);
        let bundle = member
            .commit(&self.identity, adds, removes, updates, apply_commit_op)
            .map_err(|e| AgentError::mls(format!("building the {what} Commit"), e))?;
        self.pending_removed = Some((
            room.to_owned(),
            users_of(&before, &bundle.removed_without_app_data_update),
        ));
        let tree = if wants_full_tree(&self.full_tree_hubs, room) {
            match member.pending_ratchet_tree(&self.identity) {
                Ok(tree) => Some(tree),
                Err(e) => {
                    let _ = member.clear_pending_commit(&self.identity);
                    return Err(AgentError::mls(format!("the {what} Commit's tree"), e));
                }
            }
        } else {
            None
        };
        match commit_request(&bundle, tree.as_deref()) {
            Ok(request) => Ok(request),
            Err(e) => {
                let _ = member.clear_pending_commit(&self.identity);
                Err(e)
            }
        }
    }

    /// Sends the pending Commit `request` built by [`Agent::build_commit`]
    /// and merges it; on a refusal the pending Commit is cleared.
    async fn send_commit(
        &mut self,
        room: &str,
        request: &UpdateRequest,
        what: &str,
    ) -> Result<(), AgentError> {
        let removed = self
            .pending_removed
            .take()
            .filter(|(r, _)| r == room)
            .map(|(_, users)| users)
            .unwrap_or_default();
        if let Err(e) = self.update_ok(room, request, what).await {
            if let Some(member) = self.members.get_mut(room) {
                let _ = member.clear_pending_commit(&self.identity);
            }
            return Err(e);
        }
        let member = self
            .members
            .get_mut(room)
            .ok_or_else(|| AgentError::NoSuchRoom(room.to_owned()))?;
        member
            .merge_pending_commit(&self.identity)
            .map_err(|e| AgentError::mls(format!("merging the {what} Commit"), e))?;
        let epoch = member.epoch();
        let events = removed_events(room, removed, epoch);
        if !events.is_empty() {
            self.deliver(events);
            self.save()?;
        }
        Ok(())
    }

    fn finish_leaving(&mut self, room: &str) {
        // The group state is of no more use, and OpenMLS refuses a Welcome
        // back into a group it holds.
        if let Some(member) = self.members.remove(room) {
            forget_group(&self.identity, member);
        }
        if let Some(r) = self.state.rooms.get_mut(room) {
            r.status = RoomStatus::Left;
        }
        self.withdraw(room);
    }

    async fn incoming(&mut self, item: &[u8], events: &mut Vec<Event>) {
        let fanouts = match FanoutMessage::decode_all(item) {
            Ok(fanouts) if !fanouts.is_empty() => fanouts,
            _ => {
                events.push(Event::Problem {
                    room: None,
                    description: format!(
                        "a stored Message of {} octets is not a FanoutMessage",
                        item.len()
                    ),
                });
                return;
            }
        };
        for fanout in fanouts {
            match fanout.event {
                FanoutEvent::Application { message, frank } => {
                    self.incoming_mls(&message, fanout.timestamp, frank.as_ref(), events);
                }
                FanoutEvent::Commit { message, .. } => {
                    self.incoming_mls(&message, fanout.timestamp, None, events);
                }
                FanoutEvent::Proposal {
                    message,
                    more_proposals,
                } => {
                    self.incoming_mls(&message, fanout.timestamp, None, events);
                    for proposal in &more_proposals {
                        self.incoming_mls(proposal, fanout.timestamp, None, events);
                    }
                    if let Some((room, leaf)) = self.deferred_leaver.take() {
                        self.maybe_commit_leave(&room, leaf, events).await;
                    }
                }
                FanoutEvent::Welcome {
                    message,
                    ratchet_tree_option,
                } => match encode(&message) {
                    Ok(welcome) => self.add_invite(
                        welcome,
                        ratchet_tree_option.ratchet_tree().map(<[u8]>::to_vec),
                        events,
                    ),
                    Err(e) => events.push(Event::Problem {
                        room: None,
                        description: format!("a Welcome: {e}"),
                    }),
                },
            }
        }
    }

    fn add_invite(&mut self, welcome: Vec<u8>, tree: Option<Vec<u8>>, events: &mut Vec<Event>) {
        let welcome_hex = hex::encode(&welcome);
        if let Some(existing) = self
            .state
            .invites
            .iter_mut()
            .find(|i| i.welcome == welcome_hex)
        {
            if existing.ratchet_tree.is_none() {
                existing.ratchet_tree = tree.as_deref().map(hex::encode);
            }
            return;
        }
        if self.state.consumed_welcomes.contains(&welcome_hex) {
            return;
        }
        let number = self
            .state
            .push_invite(welcome_hex, tree.as_deref().map(hex::encode));
        events.push(Event::InviteArrived { number });
    }

    fn incoming_mls(
        &mut self,
        message: &MLSMessage,
        accepted_at: u64,
        frank: Option<&Frank>,
        events: &mut Vec<Event>,
    ) {
        // The room of the group; for a group not known yet whose ID is not a
        // room URI (a Room/create room still to be joined), `group:<hex>`,
        // so the message is held and replayed at the join.
        let Some(room) = message.group_id().map(|g| {
            self.state
                .room_of_group(g)
                .or_else(|| {
                    String::from_utf8(g.to_vec())
                        .ok()
                        .filter(|r| IdentifierUri::new(r).is_ok())
                })
                .unwrap_or_else(|| format!("group:{}", hex::encode(g)))
        }) else {
            events.push(Event::Problem {
                room: None,
                description: "an MLS message that is not for a group".to_owned(),
            });
            return;
        };
        let bytes = match encode(message) {
            Ok(b) => b,
            Err(e) => {
                events.push(Event::Problem {
                    room: Some(room),
                    description: e.to_string(),
                });
                return;
            }
        };
        match self.state.rooms.get(&room).map(|r| r.status) {
            None => {
                let frank = match frank.map(encode).transpose() {
                    Ok(frank) => frank.map(hex::encode),
                    Err(e) => {
                        events.push(Event::Problem {
                            room: Some(room),
                            description: e.to_string(),
                        });
                        return;
                    }
                };
                self.state.held.push(Held {
                    room,
                    message: hex::encode(&bytes),
                    accepted_at,
                    frank,
                });
                let excess = self.state.held.len().saturating_sub(MAX_HELD);
                self.state.held.drain(..excess);
                return;
            }
            Some(RoomStatus::Left) => return,
            Some(_) => {}
        }
        // Decision mimid-1wgh.61 item 6: from before this device joined.
        if let (Some(joined), Some(epoch)) = (
            self.state.rooms.get(&room).and_then(|r| r.joined_epoch),
            message.epoch(),
        ) && epoch < joined
        {
            tracing::debug!(
                name: "message_before_join_skipped",
                epoch,
                joined,
                "skipping a message from before this device joined the room"
            );
            return;
        }
        let Some(member) = self.members.get_mut(&room) else {
            return;
        };
        // The leaves before a Commit, to name the clients it removes.
        let before = if message.content_type() == Some(ContentType::Commit) {
            room_clients(member, &self.identity)
        } else {
            Vec::new()
        };
        let own_leaf = member.own_leaf_index();
        let result = member.process(&self.identity, &bytes, apply_commit_op);
        let out_of_sync = member.out_of_sync().map(|o| (o.epoch, o.reason.clone()));
        if let Some(r) = self.state.rooms.get_mut(&room) {
            r.out_of_sync = out_of_sync;
        }
        match result {
            Ok(Incoming::Application {
                sender_identity,
                data,
                safe_aad,
                ..
            }) => {
                let sender = String::from_utf8_lossy(&sender_identity).into_owned();
                let checked =
                    received(&data, &sender, &room, accepted_at).and_then(|mut message| {
                        // protocol-07 §5.4.1.3; mimi-protocol#159 (bead
                        // mimid-1wgh.13.6).
                        message.frank = frank::check(&frank::Received {
                            member,
                            room: &room,
                            sender: &sender,
                            data: &data,
                            content: &message.content,
                            safe_aad: &safe_aad,
                            frank,
                            accepted_at,
                        })?;
                        Ok(message)
                    });
                match checked {
                    Ok(message) => events.push(Event::Message(Box::new(message))),
                    Err(description) => events.push(Event::Problem {
                        room: Some(room),
                        description,
                    }),
                }
            }
            Ok(Incoming::Proposal { sender }) => {
                let name = self.leaf_user(&room, sender);
                events.push(Event::Proposal {
                    room: room.clone(),
                    sender: name,
                });
                if let Sender::Member(leaf) = sender {
                    // Taken as a §3.5 leave: the proposals a member sends
                    // here are its own Remove and participant-list update,
                    // or an Update carrying a new did_webvh credential it
                    // could not commit (bead mimid-1wgh.4.81.28); either
                    // way the lowest other leaf commits them. Committed
                    // once the FanoutMessage's proposals are all stored, or
                    // at the end of the poll.
                    self.deferred_leaver = Some((room, leaf));
                }
            }
            Ok(Incoming::Commit(summary)) => {
                // Bead mimid-4lp4.4: other clients removed for lacking
                // AppDataUpdate; this device's own removal is Event::Left.
                let removed: Vec<u32> = summary
                    .removed_without_app_data_update
                    .iter()
                    .copied()
                    .filter(|leaf| *leaf != own_leaf)
                    .collect();
                events.extend(removed_events(
                    &room,
                    users_of(&before, &removed),
                    summary.epoch,
                ));
                if summary.self_removed {
                    self.finish_leaving(&room);
                    events.push(Event::Left { room });
                } else {
                    let participants = self
                        .members
                        .get(&room)
                        .map(participants)
                        .transpose()
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let alerts = self.check_contacts(&room);
                    let committer = summary
                        .committer_identity
                        .filter(|identity| !identity.is_empty())
                        .map(|identity| String::from_utf8_lossy(&identity).into_owned());
                    events.push(Event::MembersChanged {
                        room,
                        epoch: summary.epoch,
                        participants,
                        committer,
                    });
                    events.extend(alerts);
                }
            }
            Ok(_) => {}
            Err(e) => events.push(Event::Problem {
                room: Some(room),
                description: format!("cannot process a message: {e}"),
            }),
        }
    }

    fn leaf_user(&self, room: &str, sender: Sender) -> Option<String> {
        let Sender::Member(leaf) = sender else {
            return None;
        };
        self.members.get(room).and_then(|m| {
            m.members()
                .into_iter()
                .find(|(l, _)| *l == leaf)
                .map(|(_, id)| String::from_utf8_lossy(&id).into_owned())
        })
    }

    /// The remaining member with the lowest leaf index commits a member's
    /// leave proposals by reference, adding nothing of its own (a hub may
    /// count a change of the committer's as a second change). A client of
    /// the leaver's user is not a candidate: a leave removes all of them
    /// (bead mimid-pv2k), and a Commit cannot remove its committer
    /// (RFC 9420 §12.4).
    async fn maybe_commit_leave(&mut self, room: &str, leaver: u32, events: &mut Vec<Event>) {
        let Some(member) = self.members.get(room) else {
            return;
        };
        let clients = room_clients(member, &self.identity);
        let leaving_user = clients
            .iter()
            .find(|client| client.leaf == leaver)
            .map(|client| normalized_uri(&client.user));
        let committer = clients
            .iter()
            .filter(|client| {
                client.leaf != leaver
                    && leaving_user
                        .as_ref()
                        .is_none_or(|user| *user != normalized_uri(&client.user))
            })
            .map(|client| client.leaf)
            .min();
        if committer != Some(member.own_leaf_index()) {
            return;
        }
        match self.commit(room, &[], &[], &[], "leave").await {
            Ok(()) => {
                let participants = self
                    .members
                    .get(room)
                    .map(participants)
                    .transpose()
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let epoch = self.members.get(room).map_or(0, Member::epoch);
                events.push(Event::MembersChanged {
                    room: room.to_owned(),
                    epoch,
                    participants,
                    committer: Some(self.me.clone()),
                });
            }
            Err(e) => events.push(Event::Problem {
                room: Some(room.to_owned()),
                description: format!("committing a leave: {e}"),
            }),
        }
    }
}

/// The user of each leaf in `leaves`, from `clients` (the leaves before
/// the Commit that removed them); empty for a leaf not among them.
fn users_of(clients: &[RoomClient], leaves: &[u32]) -> Vec<String> {
    leaves
        .iter()
        .map(|leaf| {
            clients
                .iter()
                .find(|c| c.leaf == *leaf)
                .map(|c| c.user.clone())
                .unwrap_or_default()
        })
        .collect()
}

/// An [`Event::RemovedWithoutAppDataUpdate`] per user in `users`.
fn removed_events(room: &str, users: Vec<String>, epoch: u64) -> Vec<Event> {
    users
        .into_iter()
        .map(|user| {
            tracing::info!(
                name: "member_removed_without_app_data_update",
                epoch,
                "a client lacking AppDataUpdate was removed by a did_webvh record update"
            );
            Event::RemovedWithoutAppDataUpdate {
                room: room.to_owned(),
                user,
                epoch,
            }
        })
        .collect()
}

/// A received application message: decoded, its `senderUri` and `roomUri`
/// checked against the authenticated sender and room (mimi-content-10
/// §3.3), and its message ID computed from the bytes as received.
fn received(
    data: &[u8],
    sender: &str,
    room: &str,
    accepted_at: u64,
) -> Result<ReceivedMessage, String> {
    let content = MimiContent::decode(data).map_err(|e| format!("not mimi-content: {e}"))?;
    if let Some(claimed) = &content.mimi_extensions.sender_uri
        && claimed != sender
    {
        return Err(format!(
            "senderUri {claimed} does not match the MLS sender {sender}"
        ));
    }
    if let Some(claimed) = &content.mimi_extensions.room_uri
        && claimed != room
    {
        return Err(format!("roomUri {claimed} does not match the room {room}"));
    }
    let message_id = MessageId::compute(sender, room, data, &content.salt)
        .map_err(|e| format!("the message ID: {e}"))?;
    // The one text part, or the first text part of a top-level processAll
    // MultiPart that is not an attachment (a message with attachments,
    // Agent::send_message).
    let text = top_level_parts(&content.nested_part).find_map(|part| match &part.part {
        Part::Single {
            content_type,
            content,
        } if content_type.to_ascii_lowercase().starts_with("text/")
            && part.disposition != Disposition::ATTACHMENT =>
        {
            Some(String::from_utf8_lossy(content).into_owned())
        }
        _ => None,
    });
    Ok(ReceivedMessage {
        room: room.to_owned(),
        sender: sender.to_owned(),
        message_id,
        accepted_at,
        content,
        application_data: data.to_vec(),
        text,
        frank: None,
    })
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AgentError> {
    value
        .tls_serialize_detached()
        .map_err(|e| AgentError::tls("encoding", e))
}

fn identifier(uri: &str) -> Result<IdentifierUri, AgentError> {
    IdentifierUri::new(uri).map_err(|e| AgentError::Invalid(format!("{uri:?} is not a URI: {e:?}")))
}

fn pairs(users: &[&str]) -> Vec<UserRolePair> {
    users
        .iter()
        .map(|u| UserRolePair {
            user: u.as_bytes().to_vec(),
            role_index: ROLE,
        })
        .collect()
}

/// A new room's participant list: its creator alone, with `role_index`.
fn participant_list(creator: &str, role_index: u32) -> Result<Vec<u8>, AgentError> {
    encode(&ParticipantListData {
        participants: vec![UserRolePair {
            user: creator.as_bytes().to_vec(),
            role_index,
        }],
    })
}

/// Deletes `member`'s group state from the MLS store
/// ([`Member::delete`]); a failure is logged, and leaves a later join of
/// the same group to fail.
fn forget_group(identity: &Identity, member: Member) {
    if let Err(error) = member.delete(identity) {
        tracing::warn!(
            name: "group_state_not_deleted",
            error = &error as &dyn std::error::Error,
            "the state of a group no longer used cannot be deleted"
        );
    }
}

/// A participant-list change (protocol-07 §7.5) that changes roles and
/// removes users, all indexing the list at the start of the epoch.
fn participant_change(
    changed_role_participants: Vec<UserindexRolePair>,
    removed_indices: Vec<u32>,
) -> Result<AppDataUpdate, AgentError> {
    Ok(AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: encode(&ParticipantListUpdate {
            changed_role_participants,
            removed_indices,
            added_participants: vec![],
        })?,
    })
}

/// The participant list (protocol-07 §7.5) of `member`'s group, empty if
/// it has none.
fn participant_list_of(member: &Member) -> Result<ParticipantListData, AgentError> {
    match member.component(PARTICIPANT_LIST) {
        None => Ok(ParticipantListData {
            participants: vec![],
        }),
        Some(data) => ParticipantListData::tls_deserialize_exact(data)
            .map_err(|e| AgentError::tls("the participant list", e)),
    }
}

fn list_change(removed_indices: Vec<u32>, added: &[&str]) -> Result<AppDataUpdate, AgentError> {
    Ok(AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: encode(&ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices,
            added_participants: pairs(added),
        })?,
    })
}

/// The participant list (protocol-07 §7.5) of `member`'s group.
/// The leaves of `member`'s group with their users and SCIDs.
fn room_clients(member: &Member, identity: &Identity) -> Vec<RoomClient> {
    let scids: BTreeMap<u32, String> = member.did_webvh_members(identity).into_iter().collect();
    let dids: BTreeMap<u32, String> = member.did_webvh_member_dids(identity).into_iter().collect();
    member
        .members()
        .into_iter()
        .map(|(leaf, user)| RoomClient {
            leaf,
            user: String::from_utf8_lossy(&user).into_owned(),
            scid: scids.get(&leaf).cloned(),
            did: dids.get(&leaf).cloned(),
        })
        .collect()
}

/// Reads a `did_webvh` credential from the controller's `did.jsonl` and,
/// if given, `did-witness.json`.
fn read_did_webvh_files(
    log: &std::path::Path,
    witness: Option<&std::path::Path>,
) -> Result<mimi_mls::mls_didwebvh::DidWebvhCredential, AgentError> {
    let read = |path: &std::path::Path| {
        std::fs::read(path).map_err(|e| AgentError::State {
            path: path.to_path_buf(),
            detail: "cannot be read".to_owned(),
            source: Some(e),
        })
    };
    let did_log = read(log)?;
    let witness_file = witness.map(read).transpose()?.unwrap_or_default();
    mimi_mls::mls_didwebvh::DidWebvhCredential::new(did_log, witness_file).map_err(|e| {
        AgentError::State {
            path: log.to_path_buf(),
            detail: format!("is not a usable did:webvh log: {e}"),
            source: None,
        }
    })
}

fn participants(member: &Member) -> Result<Vec<String>, AgentError> {
    let Some(data) = member.component(PARTICIPANT_LIST) else {
        return Ok(vec![]);
    };
    let list = ParticipantListData::tls_deserialize_exact(data)
        .map_err(|e| AgentError::tls("the participant list", e))?;
    Ok(list
        .participants
        .into_iter()
        .map(|p| String::from_utf8_lossy(&p.user).into_owned())
        .collect())
}

/// The roles a hosted room starts with (decision mimid-1wgh.56):
///
/// - 1 "banned" (room-policy-04 §8.1.3), no capabilities;
/// - 2 "member", which every added participant gets: send, receive,
///   reply, react and report abuse (§8.3), add participants and own
///   clients (§8.1.1; decision mimid-1wgh.61), leave and remove an own
///   client (§8.1.2); nothing of §8.2 or §8.6
///   (bug mimid-y2hi);
/// - 3 "admin", which the room's creator gets: everything a member holds,
///   and kick, remove, ban, unban and change other users' roles (§8.1.2,
///   §8.1.3), change the room metadata (§8.2), and change the role list,
///   the preauthorization list and the membership style (§8.6). Its
///   transitions are those of room-policy-04 Appendix A.1's
///   `group_admin` over roles 0 to 3.
fn default_roles() -> RoleData {
    let role = |role_index: u32,
                name: &str,
                role_capabilities: Vec<Capability>,
                authorized_role_changes: Vec<SingleSourceRoleChangeTargets>| Role {
        role_index,
        role_name: name.to_owned(),
        role_description: String::new(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes,
    };
    let changes = |entries: &[(u32, &[u32])]| {
        entries
            .iter()
            .map(|(from, targets)| SingleSourceRoleChangeTargets {
                from_role_index: *from,
                target_role_indexes: targets.to_vec(),
            })
            .collect::<Vec<_>>()
    };
    let ordinary = [
        Capability::CAN_ADD_PARTICIPANT,
        // A new device of a participant joins by external Commit
        // (§8.1.1; decision mimid-1wgh.61 item 8).
        Capability::CAN_ADD_OWN_CLIENT,
        Capability::CAN_REMOVE_SELF,
        // A revoked did_webvh device is removed by another
        // device of its user (decision mimid-1wgh.4.81.25).
        Capability::CAN_REMOVE_OWN_CLIENT,
        Capability::CAN_SEND_MESSAGE,
        Capability::CAN_RECEIVE_MESSAGE,
        Capability::CAN_REPLY_TO_MESSAGE,
        Capability::CAN_REACT_TO_MESSAGE,
        // Bead mimid-14bu: the hub checks it on reportAbuse.
        Capability::CAN_REPORT_ABUSE,
    ];
    // Bug mimid-y2hi: no canChangeRoleDefinitions, which would let any
    // member give the member role any capability in one Commit.
    let member = ordinary.to_vec();
    let mut admin = ordinary.to_vec();
    admin.extend([
        Capability::CAN_REMOVE_PARTICIPANT,
        Capability::CAN_KICK,
        Capability::CAN_BAN,
        Capability::CAN_UN_BAN,
        Capability::CAN_CHANGE_USER_ROLE,
        Capability::CAN_CHANGE_ROOM_NAME,
        Capability::CAN_CHANGE_ROOM_DESCRIPTION,
        Capability::CAN_CHANGE_ROOM_AVATAR,
        Capability::CAN_CHANGE_ROOM_SUBJECT,
        Capability::CAN_CHANGE_ROOM_MOOD,
        Capability::CAN_CHANGE_ROOM_MEMBERSHIP_STYLE,
        Capability::CAN_CHANGE_ROLE_DEFINITIONS,
        Capability::CAN_CHANGE_PREAUTHORIZED_USER_LIST,
    ]);
    RoleData {
        roles: vec![
            role(BANNED_ROLE_INDEX, "banned", vec![], vec![]),
            // §8.1: adding moves a user from role 0 to a member role,
            // leaving moves the leaver back to 0.
            role(
                ROLE,
                "member",
                member,
                changes(&[(0, &[ROLE]), (ROLE, &[0])]),
            ),
            // Appendix A.1 group_admin: add, remove, ban, unban, promote
            // and demote among roles 0 to 3.
            role(
                ADMIN_ROLE,
                "admin",
                admin,
                changes(&[
                    (0, &[BANNED_ROLE_INDEX, ROLE, ADMIN_ROLE]),
                    (BANNED_ROLE_INDEX, &[0, ROLE, ADMIN_ROLE]),
                    (ROLE, &[0, BANNED_ROLE_INDEX, ADMIN_ROLE]),
                    (ADMIN_ROLE, &[0, BANNED_ROLE_INDEX, ROLE]),
                ]),
            ),
        ],
    }
}

/// The base_room_policy a hosted room starts with: open membership,
/// several devices, no limits, persistent (room-policy-04 §5).
fn default_base_policy() -> BaseRoomPolicy {
    BaseRoomPolicy {
        fixed_membership: Bool::False,
        parent_dependant: Bool::False,
        parent_room: vec![],
        multi_device: Bool::True,
        max_clients: None,
        max_users: None,
        pseudonyms_allowed: Bool::False,
        persistent_room: Bool::True,
        discoverable: Bool::False,
        policy_component_ids: vec![],
    }
}

/// The Safe AAD items for a message: a `frank_aad` item with the
/// message's franking tag (protocol-07 §5.4.1) when the room's `safe_aad`
/// list requires frank_aad, and none otherwise.
fn frank_aad_items(member: &Member, salt: &[u8; 16], content: &[u8]) -> Vec<(u16, Vec<u8>)> {
    if frank::requires_frank(member) {
        vec![(FRANK_AAD, franking_tag(salt, content).to_vec())]
    } else {
        vec![]
    }
}

/// Whether Commits in `room` carry the full tree: its hub's domain is in
/// `hubs` ([`AgentConfig::full_tree_hubs`], lowercase).
fn wants_full_tree(hubs: &std::collections::BTreeSet<String>, room: &str) -> bool {
    crate::uri::room_uri_domain(room).is_some_and(|d| hubs.contains(&d.to_ascii_lowercase()))
}

/// protocol-07 §5.3 UpdateRequest around a CommitBundle. The
/// RatchetTreeOption is `full` with `tree`, the next epoch's ratchet tree,
/// when given ([`AgentConfig::full_tree_hubs`]), else `distributionService`
/// (ratchet-tree-options-02 §3; beads mimid-1wgh.13.7, mimid-1wgh.46.20.7):
/// a mimid hub rebuilds the tree from the Commits it accepts and attaches
/// its own to the Welcomes it fans out.
fn commit_request(bundle: &CommitBundle, tree: Option<&[u8]>) -> Result<UpdateRequest, AgentError> {
    let welcome = bundle
        .welcome
        .as_ref()
        .map(|w| {
            let bare = w.strip_prefix(&WELCOME_HEADER).ok_or_else(|| {
                AgentError::Invalid("the Welcome is not an mls_welcome".to_owned())
            })?;
            Welcome::tls_deserialize_exact(bare).map_err(|e| AgentError::tls("own Welcome", e))
        })
        .transpose()?;
    let group_info = bundle
        .group_info
        .strip_prefix(&GROUP_INFO_HEADER)
        .ok_or_else(|| AgentError::Invalid("the GroupInfo is not an mls_group_info".to_owned()))?;
    Ok(UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(&bundle.commit[..])
                .map_err(|e| AgentError::tls("own Commit", e))?,
            welcome,
            group_info_option: GroupInfoOption::Full {
                group_info: GroupInfo::tls_deserialize_exact(group_info)
                    .map_err(|e| AgentError::tls("own GroupInfo", e))?,
            },
            ratchet_tree_option: match tree {
                Some(tree) => RatchetTreeOption::full(tree)
                    .map_err(|e| AgentError::tls("own ratchet tree", e))?,
                None => RatchetTreeOption::distribution_service(),
            },
        },
    })
}

/// A signed protocol-07 §5.2 KeyMaterialRequest, with a fresh Ed25519 key
/// per request: [`Identity`] does not hand out the MLS signing key.
fn key_material_request(
    requester: &str,
    target: &str,
    room: &str,
    required: &[u8],
) -> Result<Vec<u8>, AgentError> {
    let pair = mimi_mls::label::SignatureKeyPair::generate()
        .map_err(|e| AgentError::mls("the request key", e))?;
    let key = encode(&VLBytes::new(pair.verification_key().to_vec()))?;
    let credential = [
        vec![0x00, 0x01], // CredentialType basic
        encode(&VLBytes::new(requester.as_bytes().to_vec()))?,
    ]
    .concat();
    let request = KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: identifier(requester)?,
        target_user: identifier(target)?,
        room_id: identifier(room)?,
        acceptable_ciphersuites: vec![
            CipherSuite::tls_deserialize_exact([0x00, 0x01])
                .map_err(|e| AgentError::tls("cipher suite", e))?,
        ],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact(required)
            .map_err(|e| AgentError::tls("required capabilities", e))?,
        requester_signature_key: SignaturePublicKey::tls_deserialize_exact(&key)
            .map_err(|e| AgentError::tls("the request key", e))?,
        requester_credential: Credential::tls_deserialize_exact(&credential)
            .map_err(|e| AgentError::tls("the request credential", e))?,
    }
    .sign(&pair)
    .map_err(|e| AgentError::encoding("signing the keyMaterial request", e))?;
    encode(&request)
}

/// A signed protocol-07 §5.6 GroupInfoRequest from `requester` asking
/// for the answer to be encrypted to `group_info_public_key`, with a fresh
/// Ed25519 key, as [`key_material_request`] (decision mimid-1wgh.61 item
/// 2), and no joining code.
fn group_info_request(
    requester: &str,
    group_info_public_key: &[u8],
) -> Result<Vec<u8>, AgentError> {
    let pair = mimi_mls::label::SignatureKeyPair::generate()
        .map_err(|e| AgentError::mls("the request key", e))?;
    let key = encode(&VLBytes::new(pair.verification_key().to_vec()))?;
    let credential = [
        vec![0x00, 0x01], // CredentialType basic
        encode(&VLBytes::new(requester.as_bytes().to_vec()))?,
    ]
    .concat();
    let hpke = encode(&VLBytes::new(group_info_public_key.to_vec()))?;
    let request = GroupInfoRequestTbs {
        protocol: Protocol::Mls10,
        cipher_suite: CipherSuite::tls_deserialize_exact([0x00, 0x01])
            .map_err(|e| AgentError::tls("cipher suite", e))?,
        requesting_signature_key: SignaturePublicKey::tls_deserialize_exact(&key)
            .map_err(|e| AgentError::tls("the request key", e))?,
        requesting_credential: Credential::tls_deserialize_exact(&credential)
            .map_err(|e| AgentError::tls("the request credential", e))?,
        group_info_public_key: HPKEPublicKey::tls_deserialize_exact(&hpke)
            .map_err(|e| AgentError::tls("the groupInfoPublicKey", e))?,
        joining_code: None,
    }
    .sign(&pair)
    .map_err(|e| AgentError::encoding("signing the GroupInfo request", e))?;
    encode(&request)
}

/// The group ID of a TLS-encoded GroupInfo: RFC 9420 §12.4.3 GroupInfo
/// starts with its GroupContext (§8.1): `ProtocolVersion version`
/// (uint16), `CipherSuite cipher_suite` (uint16), `opaque group_id<V>`.
/// The GroupInfo decoded already, so this only reads the field.
fn group_info_group_id(group_info: &[u8]) -> Result<Vec<u8>, AgentError> {
    let mut rest = group_info
        .get(4..)
        .ok_or_else(|| AgentError::malformed("GroupInfo/fetch", "a GroupInfo too short"))?;
    VLBytes::tls_deserialize(&mut rest)
        .map(|id| id.as_slice().to_vec())
        .map_err(|e| AgentError::tls("the GroupInfo's group_id", e))
}

/// Unpadded lowercase RFC 4648 §6 base32.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// `RoomMetaData` (protocol-07 §7.6) for `room` named `name`.
fn room_metadata(room: &str, name: &str) -> Result<Vec<u8>, AgentError> {
    let uri = identifier(room)?;
    let text =
        |t: &str| Utf8String::new(t.to_owned()).map_err(|e| AgentError::Invalid(format!("{e:?}")));
    encode(&RoomMetaData {
        room_uri: uri.clone(),
        room_name: text(name)?,
        room_descriptions: vec![],
        room_avatar: uri,
        room_subject: text("")?,
        room_mood: text("")?,
    })
}

/// An app_components ComponentsList (mls-extensions-11 §5) with
/// `component` added in ascending order.
fn add_component_id(list: &[u8], component: u16) -> Result<Vec<u8>, AgentError> {
    let bad = || AgentError::Invalid("unexpected app_components list".to_owned());
    let (&len, ids) = list.split_first().ok_or_else(bad)?;
    if usize::from(len) != ids.len() || len >= 0x3e || ids.len() % 2 != 0 {
        return Err(bad());
    }
    let mut ids: Vec<u16> = ids
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect();
    if !ids.contains(&component) {
        ids.push(component);
        ids.sort_unstable();
    }
    let mut out = vec![u8::try_from(ids.len() * 2).map_err(|_| bad())?];
    for id in ids {
        out.extend(id.to_be_bytes());
    }
    Ok(out)
}

fn random<const N: usize>() -> Result<[u8; N], AgentError> {
    mimi_mls::label::random_array::<N>().map_err(|e| AgentError::mls("random bytes", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bead mimid-4lp4.4: the removed leaves are named from the leaves
    // before the Commit, and each becomes one event that survives the
    // journal (a replay delivers the same event, so the JMAP notice key is
    // the same).
    #[test]
    fn removed_leaves_are_named_from_the_tree_before_the_commit() {
        let client = |leaf: u32, user: &str| RoomClient {
            leaf,
            user: user.to_owned(),
            scid: None,
            did: None,
        };
        let before = [
            client(0, "mimi://a.example/u/alice"),
            client(1, "mimi://b.example/u/erin"),
            client(3, "mimi://a.example/u/dave"),
        ];
        assert_eq!(
            users_of(&before, &[3, 1, 7]),
            ["mimi://a.example/u/dave", "mimi://b.example/u/erin", ""]
        );
        let events = removed_events("mimi://a.example/r/one", users_of(&before, &[1]), 5);
        assert_eq!(
            events,
            [Event::RemovedWithoutAppDataUpdate {
                room: "mimi://a.example/r/one".to_owned(),
                user: "mimi://b.example/u/erin".to_owned(),
                epoch: 5,
            }]
        );
        let replayed: Vec<Event> = events
            .iter()
            .cloned()
            .map(|e| Journaled::of(e).event())
            .collect();
        assert_eq!(replayed, events);
        assert!(removed_events("r", Vec::new(), 5).is_empty());
    }

    /// A daemon drives an agent from spawned tasks, which need `Send`
    /// futures; `Agent` is not `Sync`, so a future that holds `&Agent`
    /// across an await is not `Send`. A compile-time check of the public
    /// async methods.
    #[test]
    fn the_public_futures_are_send() {
        fn send<T: Send>(_: &T) {}
        async fn all(agent: &mut Agent) {
            send(&agent.consents());
            send(&agent.poll());
            send(&agent.publish_key_packages(1));
            send(&agent.host_room(&HostOptions::named("n")));
            send(&agent.invite("r", "u"));
            send(&agent.send_text("r", "t"));
            send(&agent.send_message("r", "t", &[]));
            let part = ExternalPart {
                content_type: String::new(),
                url: String::new(),
                expires: 0,
                size: 0,
                enc_alg: 0,
                key: vec![],
                nonce: vec![],
                aad: vec![],
                hash_alg: 0,
                content_hash: vec![],
                description: String::new(),
                filename: String::new(),
            };
            send(&agent.fetch_attachment("r", &part));
            send(&agent.leave("r"));
            send(&agent.allow("u"));
            send(&agent.deny("u"));
            send(&agent.request_consent("u"));
            send(&agent.cancel_consent("u"));
        }
        let _ = all;
    }

    #[test]
    fn base32_is_rfc4648_lowercase_unpadded() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "my");
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32(&[0; 16]).len(), 26);
    }

    #[test]
    fn room_metadata_is_added_to_app_components_in_order() {
        let list = vec![0x08, 0x00, 0x21, 0x00, 0x22, 0x00, 0x25, 0x00, 0x27];
        assert_eq!(
            add_component_id(&list, ROOM_METADATA).unwrap(),
            [
                0x0a, 0x00, 0x21, 0x00, 0x22, 0x00, 0x23, 0x00, 0x25, 0x00, 0x27
            ]
        );
        assert_eq!(add_component_id(&list, 0x0022).unwrap(), list);
        assert!(add_component_id(&[0x03, 0, 0, 0], 1).is_err());
    }

    /// A message from Agent::send_message: its text is the text part and
    /// its attachments the ExternalParts; an attachment-only message has no
    /// text, and a text/plain part marked as an attachment is not the text.
    #[test]
    fn received_reads_text_and_attachments_of_a_process_all_message() {
        let external = |name: &str| NestedPart {
            disposition: Disposition::ATTACHMENT,
            language: String::new(),
            part: Part::External(crate::asset::seal(name.as_bytes()).unwrap().part(
                format!("https://a.example/assets/{name}"),
                "image/png".into(),
                name.into(),
                String::new(),
                0,
            )),
        };
        let text = |body: &str, disposition| NestedPart {
            disposition,
            language: String::new(),
            part: Part::Single {
                content_type: TEXT_PLAIN.to_owned(),
                content: body.as_bytes().to_vec(),
            },
        };
        let message_of = |parts: Vec<NestedPart>| {
            let content = MimiContent {
                salt: [1; 16],
                replaces: None,
                topic_id: vec![],
                expires: None,
                in_reply_to: None,
                mimi_extensions: Extensions::default(),
                nested_part: NestedPart {
                    disposition: Disposition::RENDER,
                    language: String::new(),
                    part: Part::Multi {
                        part_semantics: PartSemantics::ProcessAll,
                        parts,
                    },
                },
            };
            received(
                &content.encode().unwrap(),
                "mimi://a.example/u/a",
                "mimi://a.example/r/x",
                0,
            )
            .unwrap()
        };
        let both = message_of(vec![
            text("look", Disposition::RENDER),
            external("a.png"),
            external("b.png"),
        ]);
        assert_eq!(both.text.as_deref(), Some("look"));
        assert_eq!(
            both.attachments()
                .iter()
                .map(|p| p.filename.as_str())
                .collect::<Vec<_>>(),
            ["a.png", "b.png"]
        );
        let only = message_of(vec![
            text("notes", Disposition::ATTACHMENT),
            external("c.png"),
        ]);
        assert_eq!(only.text, None);
        assert_eq!(only.attachments().len(), 1);
    }

    #[test]
    fn received_checks_sender_and_room_and_computes_the_id() {
        let content = MimiContent {
            salt: [7; 16],
            replaces: None,
            topic_id: vec![],
            expires: None,
            in_reply_to: None,
            mimi_extensions: Extensions {
                sender_uri: Some("mimi://a.example/u/alice".to_owned()),
                room_uri: Some("mimi://a.example/r/x".to_owned()),
                other: BTreeMap::new(),
            },
            nested_part: NestedPart {
                disposition: Disposition::RENDER,
                language: String::new(),
                part: Part::Single {
                    content_type: TEXT_PLAIN.to_owned(),
                    content: b"hi".to_vec(),
                },
            },
        };
        let bytes = content.encode().unwrap();
        let message = received(
            &bytes,
            "mimi://a.example/u/alice",
            "mimi://a.example/r/x",
            0,
        )
        .unwrap();
        assert_eq!(message.text.as_deref(), Some("hi"));
        assert_eq!(
            message.message_id,
            MessageId::compute(
                "mimi://a.example/u/alice",
                "mimi://a.example/r/x",
                &bytes,
                &[7; 16]
            )
            .unwrap()
        );
        assert!(received(&bytes, "mimi://a.example/u/eve", "mimi://a.example/r/x", 0).is_err());
        assert!(
            received(
                &bytes,
                "mimi://a.example/u/alice",
                "mimi://a.example/r/y",
                0
            )
            .is_err()
        );
    }
}

#[cfg(test)]
#[path = "agent_didwebvh_tests.rs"]
mod didwebvh_tests;

#[cfg(test)]
#[path = "agent_policy_tests.rs"]
mod policy_tests;
