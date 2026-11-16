//! [`Agent`]: one user's MIMI client, reached through the user's mimid
//! server's JMAP API.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::SystemTime;

use mimi_content::{Disposition, Extensions, MessageId, MimiContent, NestedPart, Part};
use mimi_mls::member::{
    AppDataUpdate, CommitBundle, ExternalSender, Incoming, Member, OutOfSync, Sender,
};
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::{
    CipherSuite, Credential, GroupInfo, MLSMessage, RatchetTreeOption, RequiredCapabilities,
    SignaturePublicKey, Welcome,
};
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANK_AAD, FRANKING_AGENT, PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::{
    ClientKeyMaterial, FanoutEvent, FanoutMessage, FrankingAgentData, GroupInfoOption,
    HandshakeBundle, IdentifierUri, KeyMaterialRequestTbs, KeyMaterialUserCode,
    ParticipantListData, ParticipantListUpdate, Protocol, RoomMetaData, UpdateRequest,
    UpdateResult, UserRolePair, Utf8String, franking_tag,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{
    BaseRoomPolicy, Bool, Capability, Role, RoleData, SingleSourceRoleChangeTargets,
};
use serde_json::json;

use crate::AgentError;
use crate::client::{ConsentRecord, Jmap};
use crate::components::apply_commit_op;
use crate::state::{Room, RoomStatus, State, StateDir};
use crate::uri::{normalized_uri, user_uri_domain};

/// mls-extensions-11 §5 `app_components`.
const APP_COMPONENTS: u16 = 0x0001;
/// mls-extensions-11 §5 `safe_aad` component.
const SAFE_AAD: u16 = 0x0002;
/// RFC 9420 §11.1 RequiredCapabilities for keyMaterial (protocol-07 §5.2):
/// extension `app_data_dictionary` (0x0006) and proposal `AppDataUpdate`
/// (0x0008) of mls-extensions-11, which every room this agent builds
/// needs. No credential types are required.
const REQUIRED_CAPABILITIES: [u8; 7] = [0x02, 0x00, 0x06, 0x02, 0x00, 0x08, 0x00];
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
    /// list (decision mimid-1wgh.52). A hub that requires either refuses
    /// to host it.
    pub open: bool,
}

impl HostOptions {
    /// A room named `name` with metadata, franking and the default room
    /// policy.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            metadata: true,
            open: false,
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
    /// The decoded content.
    pub content: MimiContent,
    /// The text, when the content is one `text/*` part.
    pub text: Option<String>,
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
    /// Events found outside [`Agent::poll`] (held messages replayed by a
    /// join, a leave done locally), returned by the next poll.
    pending: Vec<Event>,
    /// The room and leaf of a member whose leave proposals are stored and
    /// not yet committed.
    deferred_leaver: Option<(String, u32)>,
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
        let (identity, state) = dir.load_or_create(&config.user_uri)?;
        let jmap = Jmap::open(&config.server_url, &config.token).await?;
        jmap.restore_sent(&state.sent);
        let mut agent = Self {
            me: config.user_uri,
            identity,
            state,
            dir,
            jmap,
            members: BTreeMap::new(),
            pending: Vec::new(),
            deferred_leaver: None,
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
                Err(e) => agent.pending.push(Event::Problem {
                    room: Some(uri.clone()),
                    description: format!("cannot reload the MLS group: {e}"),
                }),
            }
        }
        Ok(agent)
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
                (PARTICIPANT_LIST, participant_list(&[self.me.as_str()])?),
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
                (PARTICIPANT_LIST, participant_list(&[self.me.as_str()])?),
                (ROLES_LIST, encode(&default_roles())?),
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
        let request = key_material_request(&self.me, user, room)?;
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
                // The URI as given may be another spelling of the one in
                // the credential (RFC 3986 §6.2.2; decision mimid-1wgh.52):
                // compare normal forms, then use the credential's bytes.
                let identity = info
                    .identity()
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .ok_or_else(|| {
                        AgentError::malformed(
                            "KeyMaterial/fetch",
                            "a KeyPackage has no UTF-8 identity",
                        )
                    })?;
                if normalized_uri(identity) != normalized_uri(user) {
                    return Err(AgentError::malformed(
                        "KeyMaterial/fetch",
                        format!("a KeyPackage for another identity ({identity})"),
                    ));
                }
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
        let invite = self.state.invites[index].clone();
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
            },
        );
        self.state.key_packages_outstanding = self.state.key_packages_outstanding.saturating_sub(1);
        let (replay, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.state.held)
            .into_iter()
            .partition(|(r, _)| *r == room || *r == held_key);
        self.state.held = keep;
        self.save()?;
        let mut events = Vec::new();
        for (_, item) in replay {
            match hex::decode(&item).map(|b| MLSMessage::tls_deserialize_exact(&b[..])) {
                Ok(Ok(message)) => self.incoming_mls(&message, &mut events),
                _ => events.push(Event::Problem {
                    room: Some(room.clone()),
                    description: "a held message no longer decodes".to_owned(),
                }),
            }
        }
        self.pending.extend(events);
        self.save()?;
        Ok(room)
    }

    /// Sends `text` as a one-part `text/plain` message to `room`, and
    /// returns its MIMI message ID.
    ///
    /// # Errors
    ///
    /// [`AgentError::Invalid`] for text over [`MAX_TEXT_LEN`] octets, and
    /// the errors of [`Agent::send_content`].
    pub async fn send_text(&mut self, room: &str, text: &str) -> Result<MessageId, AgentError> {
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

    /// Sends `content` to `room` (Room/send), with a `frank_aad` item when
    /// the room's Safe AAD requires it (protocol-07 §5.4.1), and returns its
    /// MIMI message ID. The caller makes the salt random and sets
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
    ) -> Result<MessageId, AgentError> {
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
        self.jmap.send(room, &message).await?;
        self.remember_sent()?;
        Ok(message_id)
    }

    /// Starts leaving `room` (protocol-07 §3.5): a Remove of this client
    /// and the participant-list update removing this user, sent together
    /// as proposals. The room is `Leaving` until another member's Commit
    /// covers them ([`Event::Left`]); if this user is the last participant
    /// the room is left at once.
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
        let remove = member
            .propose_self_remove(&self.identity)
            .map_err(|e| AgentError::mls("building the Remove proposal", e))?;
        let update = member
            .propose_app_data_update(&self.identity, &list_change(vec![index], &[])?)
            .map_err(|e| AgentError::mls("building the leave proposal", e))?;
        let request = UpdateRequest {
            bundle: HandshakeBundle::Proposal {
                proposal_or_commit: MLSMessage::tls_deserialize_exact(&remove[..])
                    .map_err(|e| AgentError::tls("own Remove proposal", e))?,
                more_proposals: vec![
                    MLSMessage::tls_deserialize_exact(&update[..])
                        .map_err(|e| AgentError::tls("own proposal", e))?,
                ],
            },
        };
        self.update_ok(room, &request, "leave").await?;
        if let Some(r) = self.state.rooms.get_mut(room) {
            r.status = RoomStatus::Leaving;
        }
        self.save()?;
        if alone {
            self.finish_leaving(room);
            self.pending.push(Event::Left {
                room: room.to_owned(),
            });
            self.save()?;
        }
        Ok(())
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
        let args = match self.consent_id(&self.me.clone(), target).await? {
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
        let id = self
            .consent_id(&self.me.clone(), target)
            .await?
            .ok_or_else(|| AgentError::Invalid(format!("no consent request to {target}")))?;
        self.jmap
            .consent_set(json!({"update": {id: {"requested": false}}}))
            .await
    }

    /// The account's Consent records.
    ///
    /// # Errors
    ///
    /// The server's refusal.
    pub async fn consents(&self) -> Result<Vec<ConsentRecord>, AgentError> {
        self.jmap.consents().await
    }

    /// Reads what the server stored since the last poll and handles it:
    /// Welcomes become invites, Commits and proposals change the groups,
    /// application messages are decrypted. A member's leave proposals are
    /// committed by the remaining member with the lowest leaf index.
    ///
    /// # Errors
    ///
    /// The errors of reaching the server. An item that cannot be handled is
    /// an [`Event::Problem`], not an error.
    pub async fn poll(&mut self) -> Result<Vec<Event>, AgentError> {
        let mut events = std::mem::take(&mut self.pending);
        let since = self.state.message_state.clone();
        let (state, messages) = self.jmap.messages_since(since.as_deref()).await?;
        for (_, body) in &messages {
            if !self.jmap.is_own(body) {
                self.incoming(body, &mut events).await;
            }
        }
        // A leave stored outside a proposal bundle (a join's replay).
        if let Some((room, leaf)) = self.deferred_leaver.take() {
            self.maybe_commit_leave(&room, leaf, &mut events).await;
        }
        self.state.message_state = Some(state);
        self.remember_sent()?;
        events.extend(std::mem::take(&mut self.pending));
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

    /// Saves the sent-message digests with the state.
    fn remember_sent(&mut self) -> Result<(), AgentError> {
        self.state.sent = self.jmap.sent_digests();
        self.save()
    }

    async fn consent_id(
        &self,
        requester: &str,
        target: &str,
    ) -> Result<Option<String>, AgentError> {
        Ok(self
            .jmap
            .consents()
            .await?
            .into_iter()
            .find(|r| r.requester == requester && r.target == target && r.room.is_none())
            .map(|r| r.id))
    }

    async fn decide(&mut self, requester: &str, decision: &str) -> Result<(), AgentError> {
        let args = match self.consent_id(requester, &self.me.clone()).await? {
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
        let member = self
            .members
            .get_mut(room)
            .ok_or_else(|| AgentError::NoSuchRoom(room.to_owned()))?;
        let bundle = member
            .commit(&self.identity, adds, removes, updates, apply_commit_op)
            .map_err(|e| AgentError::mls(format!("building the {what} Commit"), e))?;
        let request = commit_request(&bundle)?;
        if let Err(e) = self.update_ok(room, &request, what).await {
            if let Some(member) = self.members.get_mut(room) {
                let _ = member.clear_pending_commit(&self.identity);
            }
            return Err(e);
        }
        self.members
            .get_mut(room)
            .ok_or_else(|| AgentError::NoSuchRoom(room.to_owned()))?
            .merge_pending_commit(&self.identity)
            .map_err(|e| AgentError::mls(format!("merging the {what} Commit"), e))
    }

    fn finish_leaving(&mut self, room: &str) {
        self.members.remove(room);
        if let Some(r) = self.state.rooms.get_mut(room) {
            r.status = RoomStatus::Left;
        }
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
                FanoutEvent::Application { message, .. } | FanoutEvent::Commit { message, .. } => {
                    self.incoming_mls(&message, events);
                }
                FanoutEvent::Proposal {
                    message,
                    more_proposals,
                } => {
                    self.incoming_mls(&message, events);
                    for proposal in &more_proposals {
                        self.incoming_mls(proposal, events);
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
        if let Err(e) = self.save() {
            events.push(Event::Problem {
                room: None,
                description: format!("saving the state: {e}"),
            });
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

    fn incoming_mls(&mut self, message: &MLSMessage, events: &mut Vec<Event>) {
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
                self.state.held.push((room, hex::encode(&bytes)));
                let excess = self.state.held.len().saturating_sub(MAX_HELD);
                self.state.held.drain(..excess);
                return;
            }
            Some(RoomStatus::Left) => return,
            Some(_) => {}
        }
        let Some(member) = self.members.get_mut(&room) else {
            return;
        };
        let result = member.process(&self.identity, &bytes, apply_commit_op);
        let out_of_sync = member.out_of_sync().map(|o| (o.epoch, o.reason.clone()));
        if let Some(r) = self.state.rooms.get_mut(&room) {
            r.out_of_sync = out_of_sync;
        }
        match result {
            Ok(Incoming::Application {
                sender_identity,
                data,
                ..
            }) => {
                let sender = String::from_utf8_lossy(&sender_identity).into_owned();
                match received(&data, &sender, &room) {
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
                    // Taken as a §3.5 leave: the only proposals a member
                    // sends here are its own Remove and participant-list
                    // update. Committed once the FanoutMessage's proposals
                    // are all stored, or at the end of the poll.
                    self.deferred_leaver = Some((room, leaf));
                }
            }
            Ok(Incoming::Commit(summary)) => {
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
                    events.push(Event::MembersChanged {
                        room,
                        epoch: summary.epoch,
                        participants,
                    });
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
    /// count a change of the committer's as a second change).
    async fn maybe_commit_leave(&mut self, room: &str, leaver: u32, events: &mut Vec<Event>) {
        let Some(member) = self.members.get(room) else {
            return;
        };
        let committer = member
            .members()
            .into_iter()
            .map(|(leaf, _)| leaf)
            .filter(|&leaf| leaf != leaver)
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
                });
            }
            Err(e) => events.push(Event::Problem {
                room: Some(room.to_owned()),
                description: format!("committing a leave: {e}"),
            }),
        }
    }
}

/// A received application message: decoded, its `senderUri` and `roomUri`
/// checked against the authenticated sender and room (mimi-content-10
/// §3.3), and its message ID computed from the bytes as received.
fn received(data: &[u8], sender: &str, room: &str) -> Result<ReceivedMessage, String> {
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
    let text = match &content.nested_part.part {
        Part::Single {
            content_type,
            content,
        } if content_type.to_ascii_lowercase().starts_with("text/") => {
            Some(String::from_utf8_lossy(content).into_owned())
        }
        _ => None,
    };
    Ok(ReceivedMessage {
        room: room.to_owned(),
        sender: sender.to_owned(),
        message_id,
        content,
        text,
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

fn participant_list(users: &[&str]) -> Result<Vec<u8>, AgentError> {
    encode(&ParticipantListData {
        participants: pairs(users),
    })
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

/// The roles a hosted room starts with: 1 "banned" (room-policy-04 §8.1.3,
/// no capabilities) and 2 "member", which every added participant gets:
/// send, receive, reply and react (§8.3), add participants (§8.1.1),
/// leave (§8.1.2) and change the role list (§8.6).
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
    RoleData {
        roles: vec![
            role(1, "banned", vec![], vec![]),
            role(
                ROLE,
                "member",
                vec![
                    Capability::CAN_ADD_PARTICIPANT,
                    Capability::CAN_REMOVE_SELF,
                    Capability::CAN_SEND_MESSAGE,
                    Capability::CAN_RECEIVE_MESSAGE,
                    Capability::CAN_REPLY_TO_MESSAGE,
                    Capability::CAN_REACT_TO_MESSAGE,
                    Capability::CAN_CHANGE_ROLE_DEFINITIONS,
                ],
                // §8.1: adding moves a user from role 0 to a member role,
                // leaving moves the leaver back to 0.
                vec![
                    SingleSourceRoleChangeTargets {
                        from_role_index: 0,
                        target_role_indexes: vec![ROLE],
                    },
                    SingleSourceRoleChangeTargets {
                        from_role_index: ROLE,
                        target_role_indexes: vec![0],
                    },
                ],
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
    let required = member.component(SAFE_AAD).is_some_and(|list| {
        list.get(1..)
            .is_some_and(|ids| ids.chunks(2).any(|id| id == FRANK_AAD.to_be_bytes()))
    });
    if required {
        vec![(FRANK_AAD, franking_tag(salt, content).to_vec())]
    } else {
        vec![]
    }
}

/// protocol-07 §5.3 UpdateRequest around a CommitBundle. The
/// RatchetTreeOption is `distributionService` (ratchet-tree-options-02;
/// bead mimid-1wgh.13.7): a mimid hub rebuilds the tree from the Commits it
/// accepts and attaches its own to the Welcomes it fans out.
fn commit_request(bundle: &CommitBundle) -> Result<UpdateRequest, AgentError> {
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
            ratchet_tree_option: RatchetTreeOption::distribution_service(),
        },
    })
}

/// A signed protocol-07 §5.2 KeyMaterialRequest, with a fresh Ed25519 key
/// per request: [`Identity`] does not hand out the MLS signing key.
fn key_material_request(requester: &str, target: &str, room: &str) -> Result<Vec<u8>, AgentError> {
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
        required_capabilities: RequiredCapabilities::tls_deserialize_exact(REQUIRED_CAPABILITIES)
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
        let message = received(&bytes, "mimi://a.example/u/alice", "mimi://a.example/r/x").unwrap();
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
        assert!(received(&bytes, "mimi://a.example/u/eve", "mimi://a.example/r/x").is_err());
        assert!(received(&bytes, "mimi://a.example/u/alice", "mimi://a.example/r/y").is_err());
    }
}
