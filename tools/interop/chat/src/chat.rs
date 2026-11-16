//! The chat client: rooms as MLS groups, commands, and incoming items.
//!
//! # Delivery through a hub that never dials out
//!
//! mimi-hubd sends no `/notify` (DIV-5), fans a submitted message out only
//! to participants on its own domain, and neither stores nor relays Commits
//! (mimi-hubd/README.md). So each client pulls from its own deliver-once
//! queue on the hub's JSON lane (`GET /mimi/v1/message?user=<own URI>`),
//! and the sender of anything puts a copy in each other participant's
//! queue (`POST /mimi/v1/submitMessage?recipient=`):
//!
//! - for a participant on another domain (a mimid user), the copy is the
//!   protocol-07 §5.5 FanoutMessage the hub would have sent to that user's
//!   provider in a `/notify`: application, proposal, commit or welcome;
//! - for a participant on the hub's domain, a handshake copy is the bare
//!   MLSMessage (application messages already reach them through the
//!   hub's own fan-out of submitMessage).
//!
//! A Welcome also goes through the hub's own Welcome relay
//! (`/mimi/v1/welcome/ingest`, pulled with `GET /mimi/v1/welcome?user=`),
//! which runs the hub's suite gate. That copy carries no ratchet tree:
//! mimid's GroupInfo leaves the `ratchet_tree` extension out (protocol-07
//! §5.3), so the invitee needs the FanoutMessage copy, whose
//! RatchetTreeOption carries the full tree.
//!
//! submitMessage also queues the message under the room URI (mimi-hubd's
//! persistence key), a queue nobody reads; it holds at most 256 items, and
//! once full the hub refuses submitMessage. Every member therefore drains
//! the room's queue and discards what it finds.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail, ensure};
use mimi_content::{Disposition, Extensions, MimiContent, NestedPart, Part};
use mimi_mls::member::{
    AppDataUpdate, CommitBundle, ExternalSender, Incoming, Member, OutOfSync, Sender,
};
use mimi_mls::tls_codec::{Deserialize, VLBytes};
use mimi_mls::wire::{
    CipherSuite, Credential, GroupInfo, MLSMessage, RatchetTreeOption, RequiredCapabilities,
    SignaturePublicKey, Welcome,
};
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANK_AAD, FRANKING_AGENT, PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::{
    AbuseReport, AbuseType, AbusiveMessage, ClientKeyMaterial, ConsentEntry, ConsentOperation,
    FanoutEvent, FanoutMessage, Frank, FrankingAgentData, GroupInfoOption, HandshakeBundle,
    IdentifierUri, KeyMaterialRequestTbs, KeyMaterialResponse, KeyMaterialUserCode,
    ParticipantListData, ParticipantListUpdate, Protocol, RoomMetaData, SubmitMessageRequest,
    UpdateRequest, UserRolePair, UserindexRolePair, Utf8String, franking_tag,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{
    BaseRoomPolicy, Bool, Capability, Role, RoleData, SingleSourceRoleChangeTargets,
};
use mimid_server::hub::components::apply_commit_op;
use mimid_server::hub::normalized_uri;
use serde_json::json;

use crate::hub::{Hub, encode};
use crate::state::{Room, RoomStatus, State, StateDir};

/// mls-extensions-11 §5 `app_components`.
const APP_COMPONENTS: u16 = 0x0001;
/// mls-extensions-11 §5 `safe_aad` component: the Safe AAD components a
/// room requires.
const SAFE_AAD: u16 = 0x0002;
/// RFC 9420 §11.1 RequiredCapabilities for keyMaterial (§5.2): extension
/// `app_data_dictionary` (0x0006) and proposal `AppDataUpdate` (0x0008)
/// from mls-extensions-11, which every room this client builds needs,
/// because its GroupContext carries `participant_list`. A hub should then
/// answer `nothingCompatible` for KeyPackages without them, instead of
/// handing out one the Add will refuse. No credential types are required.
const REQUIRED_CAPABILITIES: [u8; 7] = [0x02, 0x00, 0x06, 0x02, 0x00, 0x08, 0x00];
/// RFC 9420 §6 MLSMessage headers: mls10, then wire_format.
const GROUP_INFO_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];
const WELCOME_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x03];
/// KeyPackages kept published at the hub.
const KEY_PACKAGE_TARGET: u32 = 5;
/// Joined Welcomes remembered, so the second route's copy is dropped.
const MAX_CONSUMED_WELCOMES: usize = 16;
/// Messages kept for rooms not (yet) joined.
const MAX_HELD: usize = 256;
/// Items pulled from one queue per poll.
const MAX_PULLS_PER_POLL: usize = 64;
/// The role every participant mimid-chat adds gets: 2, "member" in
/// [`default_roles`]. Not 1, which room-policy-04 §8.1.3 gives the "banned"
/// role, and which mimi-hubd requires to be named "banned". Rooms made
/// before this change hold participants with role 1.
const ROLE: u32 = 2;
/// The longest line of text sent as one message.
const MAX_TEXT_LEN: usize = 16 * 1024;
const TEXT_PLAIN: &str = "text/plain;charset=utf-8";

pub struct Client {
    pub me: String,
    identity: Identity,
    state: State,
    dir: StateDir,
    hub: Hub,
    members: BTreeMap<String, Member>,
    /// Every line printed, for `/expect`.
    pub printed: Vec<String>,
    last_poll_error: Option<String>,
    /// The line editor's printer, when reading from a terminal.
    printer: Option<Box<dyn rustyline::ExternalPrinter + Send>>,
    /// Whether KeyPackages are published at the hub without a /publish
    /// (at start-up and after a join). Off for a hub whose operator has
    /// asked visitors not to write through its JSON lane.
    pub auto_publish: bool,
    /// Set while the proposals of one FanoutMessage are processed, so a
    /// leave is committed once all of them are stored, not after the
    /// first (protocol-07 §3.5 sends a Remove and an AppDataUpdate).
    deferring_leave: bool,
    /// The room and leaf of a proposal sender seen while deferring.
    deferred_leaver: Option<(String, u32)>,
}

impl Client {
    pub fn open(dir: StateDir, me: String, hub: Hub) -> anyhow::Result<Self> {
        let (identity, state, minted) = dir.load_or_create(&me)?;
        let mut client = Self {
            me,
            identity,
            state,
            dir,
            hub,
            members: BTreeMap::new(),
            printed: Vec::new(),
            last_poll_error: None,
            printer: None,
            auto_publish: true,
            deferring_leave: false,
            deferred_leaver: None,
        };
        client.say(format!(
            "* {} {} (hub {})",
            if minted {
                "new identity"
            } else {
                "reloaded identity"
            },
            client.me,
            client.hub.domain
        ));
        let rooms: Vec<(String, Room)> = client
            .state
            .rooms
            .iter()
            .map(|(uri, room)| (uri.clone(), room.clone()))
            .collect();
        for (uri, room) in rooms {
            if room.status == RoomStatus::Left {
                continue;
            }
            // The group ID: from the group map for a Room/create room, else
            // the room URI's bytes.
            let group_id = client
                .state
                .group_rooms
                .iter()
                .find(|(_, r)| **r == uri)
                .and_then(|(hex_id, _)| hex::decode(hex_id).ok())
                .unwrap_or_else(|| uri.as_bytes().to_vec());
            match Member::load(&client.identity, &group_id) {
                Ok(mut member) => {
                    if let Some((epoch, reason)) = room.out_of_sync {
                        member.restore_out_of_sync(OutOfSync::new(epoch, reason));
                    }
                    client.members.insert(uri, member);
                }
                Err(e) => client.error(format!("cannot reload room {uri}: {}", causes(&e))),
            }
        }
        Ok(client)
    }

    // ---- output ----

    pub fn say(&mut self, line: String) {
        let unprinted = match &mut self.printer {
            // Above the prompt, leaving a half-typed line intact.
            Some(printer) => printer.print(format!("{line}\n")).err(),
            None => {
                println!("{line}");
                None
            }
        };
        if let Some(e) = unprinted {
            println!("{line}");
            tracing::warn!(error = %e, "the line editor could not print");
        }
        self.printed.push(line);
    }

    /// Prints through the line editor from now on.
    pub fn set_printer(&mut self, printer: Box<dyn rustyline::ExternalPrinter + Send>) {
        self.printer = Some(printer);
    }

    /// The current room's short name, if any.
    pub fn current_room_name(&self) -> Option<String> {
        self.state.current_room.as_deref().map(short_room)
    }

    pub fn error(&mut self, line: String) {
        self.say(format!("! {line}"));
    }

    fn save(&mut self) {
        if let Err(e) = self.dir.save(&self.state) {
            self.error(format!("cannot save state: {e:#}"));
        }
    }

    // ---- start-up ----

    /// Publishes KeyPackages until about [`KEY_PACKAGE_TARGET`] are
    /// outstanding at the hub.
    pub async fn top_up_key_packages(&mut self) {
        if !self.auto_publish {
            return;
        }
        let mut published = 0;
        while self.state.key_packages_outstanding < KEY_PACKAGE_TARGET {
            match self.publish_one_key_package().await {
                Ok(()) => {
                    self.state.key_packages_outstanding += 1;
                    published += 1;
                }
                Err(e) => {
                    self.error(format!("publishing a KeyPackage: {e:#}"));
                    break;
                }
            }
        }
        self.save();
        if published > 0 {
            self.say(format!(
                "* published {published} KeyPackage(s) at the hub ({} outstanding)",
                self.state.key_packages_outstanding
            ));
        }
    }

    async fn publish_one_key_package(&mut self) -> anyhow::Result<()> {
        let bytes = self
            .identity
            .key_package(KeyPackageKind::OneTime)
            .context("minting a KeyPackage")?;
        self.hub.publish_key_package(&self.me, bytes).await
    }

    pub fn greet(&mut self) {
        let active = self
            .state
            .rooms
            .values()
            .filter(|r| r.status != RoomStatus::Left)
            .count();
        let invites = self.state.invites.len();
        let current = self.state.current_room.clone();
        self.say(format!(
            "* {active} room(s), {invites} pending invite(s); current room: {}. /help for commands",
            current.as_deref().map_or("none".to_owned(), short_room)
        ));
    }

    // ---- commands ----

    /// Runs one input line. Returns `false` on `/quit`.
    pub async fn command(&mut self, line: &str) -> bool {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            return true;
        }
        let result = if let Some(rest) = line.strip_prefix('/') {
            let (name, arg) = match rest.split_once(char::is_whitespace) {
                Some((name, arg)) => (name, arg.trim()),
                None => (rest, ""),
            };
            match name {
                "quit" | "exit" => return false,
                "help" => {
                    self.help();
                    Ok(())
                }
                "create" => self.create(arg, true).await,
                "adopt" => self.create(arg, false).await,
                "host" => self.host(arg).await,
                "invite" => self.invite(arg).await,
                "policy" => self.policy(arg).await,
                "roles" => self.roles(arg).await,
                "ban" => self.ban(arg).await,
                "stale-commit" => self.stale_commit(arg).await,
                "allow" => self.allow(arg).await,
                "deny" => self.deny(arg).await,
                "consents" => self.consents().await,
                "request" => self.request_consent(arg, ConsentOperation::Request).await,
                "cancel" => self.request_consent(arg, ConsentOperation::Cancel).await,
                "report" => self.report(arg).await,
                "join" => self.join(arg).await,
                "rooms" => {
                    self.rooms();
                    Ok(())
                }
                "room" => self.switch(arg),
                "who" => self.who(),
                "leave" => self.leave(arg).await,
                "publish" => self.publish(arg).await,
                "poll" => {
                    self.poll().await;
                    Ok(())
                }
                // A literal leading slash: "//text" sends "/text".
                _ if rest.starts_with('/') => self.send_text(rest).await,
                _ => Err(anyhow!("unknown command /{name}; /help lists them")),
            }
        } else {
            self.send_text(line).await
        };
        if let Err(e) = result {
            self.error(format!("{e:#}"));
        }
        true
    }

    fn help(&mut self) {
        for line in [
            "/create <name>         create mimi://<hub>/r/<name> with you as its first participant",
            "/adopt <name>          as /create, for a room the hub already lists you in (no addParticipant)",
            "/host <name> [--open] [--no-meta]  have a mimid hub host mimi://<hub>/r/<name> (needs --local-url);\n                       --open: no franking and no room policy;\n                       --no-meta: over JMAP, no room metadata, so members need not support room_metadata",
            "/invite <user>         add a user (a mimi:// URI, or a bare name on your domain)",
            "  ... --policy k=v ... the same Commit also changes base_room_policy",
            "  ... --roles          the same Commit also replaces roles_list (both hubs should refuse)",
            "/roles [ban|ban-no-banned]  set roles_list: 1 \"banned\", 2 \"member\" (needed before /policy on mimi-hubd);\n                       ban: member also holds canBan 2->1; ban-no-banned: the same without role 1",
            "/ban <user>            move <user> to role 1 and remove their clients (canBan)",
            "/policy k=v ...        change base_room_policy: fixed_membership, multi_device,\n                       pseudonyms_allowed, persistent_room, discoverable (true|false),\n                       max_clients, max_users (a number or none)",
            "/stale-commit          test: send a roles_list Commit one epoch late (expect wrongEpoch)",
            "/allow <user>          let <user> fetch your KeyPackages (updateConsent grant)",
            "/deny <user>           refuse <user> consent to fetch your KeyPackages (revoke)",
            "/request <user>        ask <user> for consent to fetch their KeyPackages (requestConsent)",
            "/cancel <user>         withdraw that request (requestConsent cancel)",
            "/consents              your consent requests and decisions (JMAP mode)",
            "/report [--message] <user> [note]\n                       report <user> in the current room (reportAbuse);\n                       --message attaches one AbusiveMessage",
            "/join [n]              accept pending invite #n (default: the oldest)",
            "/rooms                 list rooms; /room <name|uri> switches the current room",
            "/who                   participants of the current room",
            "/leave [room]          leave the current (or named) room (protocol-07 §3.5)",
            "/publish [n]           publish n more KeyPackages at the hub (default 1)",
            "/poll                  pull from the hub now",
            "/sleep <s>, /expect <text> [s]   script helpers",
            "/quit                  exit; any other line is sent to the current room",
        ] {
            self.say(line.to_owned());
        }
    }

    /// `/create`, or with `register` false `/adopt`: the same MLS group, but
    /// no addParticipant, for a room whose hub already lists you as its
    /// first participant (a seeded room such as Haven's r/table).
    async fn create(&mut self, name: &str, register: bool) -> anyhow::Result<()> {
        let command = if register { "/create" } else { "/adopt" };
        ensure!(
            valid_name(name),
            "usage: {command} <name> (a-z 0-9 . _ -, up to 64)"
        );
        let room = format!("mimi://{}/r/{name}", self.hub.domain);
        ensure!(
            !self.state.rooms.contains_key(&room),
            "you already have a room {room}"
        );
        if register {
            self.hub
                .add_participant(&room, &self.me)
                .await
                .context("registering you as the room's first participant at the hub")?;
        }
        let member = Member::create(
            &self.identity,
            room.as_bytes(),
            &[],
            &[
                // mls-extensions-11 §5: a ComponentsList naming
                // participant_list (0x0022), roles_list (0x0025) and
                // base_room_policy (0x0027), so /policy and --roles can set
                // them: a component with state must be listed. Every member's
                // leaf must list them too; mimid's leaves do.
                (
                    APP_COMPONENTS,
                    vec![0x06, 0x00, 0x22, 0x00, 0x25, 0x00, 0x27],
                ),
                (PARTICIPANT_LIST, participant_list(&[self.me.as_str()])?),
            ],
        )
        .map_err(|e| anyhow!("creating the MLS group: {}", causes(&e)))?;
        self.members.insert(room.clone(), member);
        self.state.rooms.insert(
            room.clone(),
            Room {
                status: RoomStatus::Active,
                out_of_sync: None,
            },
        );
        self.state.current_room = Some(room.clone());
        self.save();
        self.say(format!("* created {room}; it is now the current room"));
        Ok(())
    }

    /// `/host <name>`: a room hosted by a mimid hub, created through its
    /// local control listener (mimid's `local` module; the narrow
    /// Room/create of bead mimid-1wgh.12.4). The group names the hub as its
    /// external sender and franking agent, requires frank_aad, and carries
    /// the participant list, [`default_roles`] and [`default_base_policy`],
    /// as `Hub::create_room` requires. A first empty Commit gives the
    /// GroupInfo the hub is handed; nothing is sent for it.
    async fn host(&mut self, arg: &str) -> anyhow::Result<()> {
        let mut words = arg.split(' ');
        let name = words.next().unwrap_or_default();
        let (mut open, mut no_meta) = (false, false);
        for flag in words {
            match flag {
                "--open" => open = true,
                "--no-meta" => no_meta = true,
                _ => bail!("usage: /host <name> [--open] [--no-meta]"),
            }
        }
        ensure!(
            valid_name(name),
            "usage: /host <name> [--open] [--no-meta] (a-z 0-9 . _ -, up to 64)"
        );
        // Over JMAP, Room/create wants roomIdPrefix and the base32 of 16
        // random octets, a 16-octet random group ID, and the name in the
        // room metadata (draft-atwood-jmap-chat-mimi-00 §Room/create rules
        // 5, 6); otherwise the room is named <name> and the group ID is the
        // room URI.
        let (room, group_id) = match &self.hub.jmap {
            Some(jmap) => (
                format!("{}{}", jmap.room_id_prefix, base32(&random::<16>()?)),
                random::<16>()?.to_vec(),
            ),
            None => {
                let room = format!("mimi://{}/r/{name}", self.hub.domain);
                let group_id = room.as_bytes().to_vec();
                (room, group_id)
            }
        };
        ensure!(
            !self.state.rooms.contains_key(&room),
            "you already have a room {room}"
        );
        let sender = self.hub.hub_sender().await?;
        let mut franking_key = vec![0x20];
        franking_key.extend_from_slice(&sender.signature_key);
        let franking_credential = [
            vec![0x00, 0x01], // CredentialType basic
            encode(&VLBytes::new(sender.identity.as_bytes().to_vec()))?,
        ]
        .concat();
        let franking_agent = encode(&FrankingAgentData {
            franking_signature_key: SignaturePublicKey::tls_deserialize_exact(&franking_key[..])
                .map_err(|e| anyhow!("hub key: {e:?}"))?,
            credential: Credential::tls_deserialize_exact(&franking_credential[..])
                .map_err(|e| anyhow!("hub credential: {e:?}"))?,
        })?;
        let senders = [ExternalSender {
            signature_key: sender.signature_key.to_vec(),
            identity: sender.identity.into_bytes(),
        }];
        // Ascending component ids (app_data_dictionary order).
        let mut components: Vec<(u16, Vec<u8>)> = if open {
            // An open room (decision mimid-1wgh.52, bead mimid-1wgh.53): no
            // franking and no room policy, so only the participant list.
            // A hub that requires either refuses to host it.
            vec![
                (APP_COMPONENTS, vec![0x02, 0x00, 0x22]),
                (PARTICIPANT_LIST, participant_list(&[self.me.as_str()])?),
            ]
        } else {
            vec![
                // mls-extensions-11 §5 app_components: franking_agent,
                // participant_list, roles_list, base_room_policy. Every member's
                // leaf must list these, and frank_aad (0x0020) below.
                (
                    APP_COMPONENTS,
                    vec![0x08, 0x00, 0x21, 0x00, 0x22, 0x00, 0x25, 0x00, 0x27],
                ),
                // safe_aad: frank_aad required (mimid hub, bead mimid-1wgh.6.74).
                (SAFE_AAD, vec![0x02, 0x00, 0x20]),
                (FRANKING_AGENT, franking_agent),
                (PARTICIPANT_LIST, participant_list(&[self.me.as_str()])?),
                (ROLES_LIST, encode(&default_roles())?),
                (BASE_ROOM_POLICY, encode(&default_base_policy())?),
            ]
        };
        if self.hub.jmap.is_some() && !no_meta {
            // room_metadata (protocol-07 §7.6), listed in app_components.
            // Optional (draft-atwood-jmap-chat-mimi Room/create rule 5); a
            // room with it requires every member to support room_metadata
            // (mls-extensions-11 §5), so --no-meta leaves it out.
            let metadata = room_metadata(&room, name)?;
            let at = components
                .iter()
                .position(|(id, _)| *id > ROOM_METADATA)
                .unwrap_or(components.len());
            components.insert(at, (ROOM_METADATA, metadata));
            if let Some((_, list)) = components.iter_mut().find(|(id, _)| *id == APP_COMPONENTS) {
                *list = add_component_id(list, ROOM_METADATA)?;
            }
        }
        let mut member = Member::create(&self.identity, &group_id, &senders, &components)
            .map_err(|e| anyhow!("creating the MLS group: {}", causes(&e)))?;
        let bundle = member
            .commit(&self.identity, &[], &[], &[], apply_commit_op)
            .map_err(|e| anyhow!("the first (empty) Commit: {}", causes(&e)))?;
        member
            .merge_pending_commit(&self.identity)
            .map_err(|e| anyhow!("merging the first Commit: {}", causes(&e)))?;
        let tree = member
            .ratchet_tree()
            .map_err(|e| anyhow!("ratchet tree: {}", causes(&e)))?;
        self.hub
            .create_room(&room, &self.me, &bundle.group_info, &tree)
            .await
            .context("having the hub host the room")?;
        if group_id != room.as_bytes() {
            self.state
                .group_rooms
                .insert(hex::encode(&group_id), room.clone());
        }
        self.members.insert(room.clone(), member);
        self.state.rooms.insert(
            room.clone(),
            Room {
                status: RoomStatus::Active,
                out_of_sync: None,
            },
        );
        self.state.current_room = Some(room.clone());
        self.save();
        self.say(format!(
            "* {room} is hosted by {}{}; it is now the current room",
            self.hub.domain,
            if open {
                ", open (no franking, no policy)"
            } else {
                ""
            }
        ));
        Ok(())
    }

    /// `/policy k=v ...`: a Commit with one base_room_policy AppDataUpdate
    /// (room-policy-04 §5), sent with update and distributed to the room.
    async fn policy(&mut self, arg: &str) -> anyhow::Result<()> {
        let settings: Vec<&str> = arg.split_whitespace().collect();
        ensure!(!settings.is_empty(), "usage: /policy k=v ... (see /help)");
        let room = self.current()?;
        let update = base_policy_update(self.member(&room)?, &settings)?;
        self.commit_one_update(&room, update, "base_room_policy")
            .await?;
        self.say(format!(
            "[{}] * base_room_policy changed: {}",
            short_room(&room),
            settings.join(" ")
        ));
        Ok(())
    }

    /// `/roles`: a Commit with one roles_list AppDataUpdate (room-policy-04
    /// §3) setting [`default_roles`]. mimi-hubd refuses a base_room_policy
    /// for a room with no roles, so this goes first.
    ///
    /// `/roles ban` also gives the member role canBan with a change from
    /// role 2 to role 1; `/roles ban-no-banned` does that without defining
    /// role 1, which room-policy-04 §8.1.3 allows in the list but not for
    /// a ban (the role-1 check with Haven, IETF 127 table).
    async fn roles(&mut self, arg: &str) -> anyhow::Result<()> {
        let (roles, described) = match arg {
            "" => (
                default_roles(),
                "1 banned, 2 member (send, receive, reply, react, add, leave)",
            ),
            "ban" => (
                ban_roles(true),
                "1 banned, 2 member (as /roles, plus canBan 2->1)",
            ),
            "ban-no-banned" => (
                ban_roles(false),
                "2 member (as /roles, plus canBan 2->1), no role 1",
            ),
            _ => bail!("usage: /roles [ban|ban-no-banned]"),
        };
        let room = self.current()?;
        let update = AppDataUpdate::Update {
            component_id: ROLES_LIST,
            update: encode(&roles)?,
        };
        self.commit_one_update(&room, update, "roles_list").await?;
        self.say(format!(
            "[{}] * roles_list set: {described}",
            short_room(&room)
        ));
        Ok(())
    }

    /// `/ban <user>`: one Commit that moves `user` to role 1 in the
    /// participant list and removes all their clients (room-policy-04
    /// §8.1.3 canBan; protocol-07 §7.6 changedRoleParticipants).
    async fn ban(&mut self, arg: &str) -> anyhow::Result<()> {
        let target = self.user_uri(arg.trim())?;
        ensure!(target != self.me, "you cannot ban yourself");
        let room = self.current()?;
        let member = self.member(&room)?;
        let list = participants(member)?;
        let user_index = list
            .iter()
            .position(|u| normalized_uri(u) == normalized_uri(&target))
            .ok_or_else(|| anyhow!("{target} is not a participant"))?;
        let removes: Vec<u32> = member
            .members()
            .into_iter()
            .filter(|(_, identity)| {
                std::str::from_utf8(identity)
                    .is_ok_and(|id| normalized_uri(id) == normalized_uri(&target))
            })
            .map(|(leaf, _)| leaf)
            .collect();
        let update = AppDataUpdate::Update {
            component_id: PARTICIPANT_LIST,
            update: encode(&ParticipantListUpdate {
                changed_role_participants: vec![UserindexRolePair {
                    user_index: u32::try_from(user_index)?,
                    role_index: 1,
                }],
                removed_indices: vec![],
                added_participants: vec![],
            })?,
        };
        self.commit_removes_and_updates(&room, &removes, &[update], "ban")
            .await?;
        self.say(format!(
            "[{}] * you banned {target} ({} client(s) removed)",
            short_room(&room),
            removes.len()
        ));
        Ok(())
    }

    /// Test of a hub's epoch check (protocol-07 §5.3): builds a roles_list
    /// Commit at the current epoch and keeps it unsent, sends the same
    /// change as a second Commit to move the room on one epoch, then sends
    /// the first. A hub should answer `wrongEpoch` and change nothing.
    /// Both carry a change, since a hub may refuse an empty Commit.
    async fn stale_commit(&mut self, arg: &str) -> anyhow::Result<()> {
        ensure!(arg.is_empty(), "usage: /stale-commit");
        let room = self.current()?;
        let update = || -> anyhow::Result<AppDataUpdate> {
            Ok(AppDataUpdate::Update {
                component_id: ROLES_LIST,
                update: encode(&default_roles())?,
            })
        };
        let member = self
            .members
            .get_mut(&room)
            .ok_or_else(|| anyhow!("no MLS group for {room}"))?;
        let stale = member
            .commit(&self.identity, &[], &[], &[update()?], apply_commit_op)
            .map_err(|e| anyhow!("building the first Commit: {}", causes(&e)))?;
        let stale_request = commit_request(&stale)?;
        member
            .clear_pending_commit(&self.identity)
            .map_err(|e| anyhow!("setting the first Commit aside: {}", causes(&e)))?;
        self.commit_one_update(&room, update()?, "roles_list, to move the epoch on")
            .await?;
        let answer = self.hub.update(&room, stale_request).await?;
        self.say(format!(
            "[{}] * the Commit from the previous epoch got {:?} ({:?})",
            short_room(&room),
            answer.result,
            answer.error_description.as_str()
        ));
        Ok(())
    }

    /// A Commit with `update` and nothing else, sent with update (§5.3),
    /// merged, and distributed to the room's other participants.
    async fn commit_one_update(
        &mut self,
        room: &str,
        update: AppDataUpdate,
        what: &str,
    ) -> anyhow::Result<()> {
        self.commit_removes_and_updates(room, &[], &[update], what)
            .await
    }

    /// A Commit removing the leaves `removes` and applying `updates`, sent
    /// to the hub, merged and distributed to the participants before it.
    async fn commit_removes_and_updates(
        &mut self,
        room: &str,
        removes: &[u32],
        updates: &[AppDataUpdate],
        what: &str,
    ) -> anyhow::Result<()> {
        let before = participants(self.member(room)?)?;
        let member = self
            .members
            .get_mut(room)
            .ok_or_else(|| anyhow!("no MLS group for {room}"))?;
        let bundle = member
            .commit(&self.identity, &[], removes, updates, apply_commit_op)
            .map_err(|e| anyhow!("building the Commit: {}", causes(&e)))?;
        let request = commit_request(&bundle)?;
        if let Err(e) = self.hub.update_ok(room, request).await {
            if let Err(clear) = member.clear_pending_commit(&self.identity) {
                self.error(format!("clearing the refused Commit: {}", causes(&clear)));
            }
            return Err(e.context(format!("update ({what})")));
        }
        member
            .merge_pending_commit(&self.identity)
            .map_err(|e| anyhow!("merging the Commit: {}", causes(&e)))?;
        let commit = MLSMessage::tls_deserialize_exact(&bundle.commit[..])
            .map_err(|e| anyhow!("own Commit: {e:?}"))?;
        let others: Vec<String> = before.into_iter().filter(|u| *u != self.me).collect();
        self.distribute(
            &others,
            FanoutEvent::Commit {
                message: commit,
                external_proposals: vec![],
            },
        )
        .await;
        Ok(())
    }

    fn current(&self) -> anyhow::Result<String> {
        let room = self
            .state
            .current_room
            .clone()
            .ok_or_else(|| anyhow!("no current room: /create, /join or /room first"))?;
        match self.state.rooms.get(&room).map(|r| r.status) {
            Some(RoomStatus::Active) => Ok(room),
            Some(RoomStatus::Leaving) => bail!("you are leaving {room}"),
            _ => bail!("you are not in {room}"),
        }
    }

    async fn invite(&mut self, arg: &str) -> anyhow::Result<()> {
        let mut words = arg.split_whitespace();
        let user = words.next().unwrap_or("");
        let mut policy: Option<Vec<&str>> = None;
        let mut roles = false;
        for word in words {
            match word {
                "--policy" => policy = Some(Vec::new()),
                "--roles" => roles = true,
                setting => match policy.as_mut() {
                    Some(settings) => settings.push(setting),
                    None => bail!("usage: /invite <user> [--policy k=v ...] [--roles]"),
                },
            }
        }
        let mut target = self.user_uri(user)?;
        ensure!(target != self.me, "you cannot invite yourself");
        let room = self.current()?;
        let before = participants(self.member(&room)?)?;
        ensure!(
            !before.contains(&target),
            "{target} is already a participant"
        );

        // §5.2 keyMaterial for the target, through the hub.
        let request = key_material_request(&self.me, &target, &room)?;
        let body = self.hub.key_material(&target, request).await?;
        let (response, divergence) = KeyMaterialResponse::decode_for_requester(&body[..])
            .map_err(|e| anyhow!("the hub's KeyMaterialResponse does not decode: {e:?}"))?;
        if let Some(divergence) = divergence {
            self.say(format!(
                "* note: the hub's keyMaterial answer departs from protocol-07 §5.2 ({divergence:?}); read as noCompatibleMaterial"
            ));
        }
        match response.user_status {
            KeyMaterialUserCode::Success | KeyMaterialUserCode::PartialSuccess => {}
            code @ (KeyMaterialUserCode::NoConsent | KeyMaterialUserCode::NoConsentForThisRoom) => {
                bail!(
                    "keyMaterial for {target}: {code:?}: they must consent to {} first",
                    self.me
                )
            }
            KeyMaterialUserCode::NoCompatibleMaterial => bail!(
                "{target} has no usable KeyPackage right now (all used up or none compatible); they can /publish more"
            ),
            other => bail!("keyMaterial for {target}: {other:?}"),
        }
        let mut key_packages = Vec::new();
        for client in &response.clients {
            if let ClientKeyMaterial::Success { key_package, .. } = client {
                let info = key_package
                    .verify(SystemTime::now())
                    .map_err(|e| anyhow!("{target}'s KeyPackage does not verify: {e:?}"))?;
                // The URI as typed may be another spelling of the one in
                // the credential (RFC 3986 §6.2.2; decision mimid-1wgh.52):
                // compare normal forms, then use the credential's bytes, so
                // the participant list names the user as their provider does.
                let identity = info
                    .identity()
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .ok_or_else(|| anyhow!("{target}'s KeyPackage has no UTF-8 identity"))?;
                ensure!(
                    normalized_uri(identity) == normalized_uri(&target),
                    "the hub served a KeyPackage for another identity ({identity})"
                );
                if identity != target {
                    self.say(format!("* note: {target} is {identity} at its provider"));
                    target = identity.to_owned();
                }
                key_packages.push(encode(key_package)?);
            }
        }
        ensure!(
            !key_packages.is_empty(),
            "the hub has no KeyPackage for {target} (they must run mimid-chat once, or /publish)"
        );
        let adds: Vec<&[u8]> = key_packages.iter().map(Vec::as_slice).collect();

        // Commit: Add beside one ParticipantListUpdate (protocol-07 §3.2;
        // mimi-hubd DIV-10 takes exactly one change per Commit). --policy
        // and --roles add a policy change to the same Commit, to test that
        // rule: room-policy-04 §5 allows base_room_policy beside a
        // participant change, §3 forbids roles_list there.
        let mut updates = vec![list_change(vec![], &[target.as_str()])?];
        if let Some(settings) = &policy {
            updates.push(base_policy_update(self.member(&room)?, settings)?);
        }
        if roles {
            updates.push(roles_update(self.member(&room)?)?);
        }
        let member = self
            .members
            .get_mut(&room)
            .ok_or_else(|| anyhow!("no MLS group for {room}"))?;
        let bundle = member
            .commit(&self.identity, &adds, &[], &updates, apply_commit_op)
            .map_err(|e| anyhow!("building the Commit: {}", causes(&e)))?;
        let request = commit_request(&bundle)?;
        if let Err(e) = self.hub.update_ok(&room, request).await {
            if let Err(clear) = member.clear_pending_commit(&self.identity) {
                self.error(format!("clearing the refused Commit: {}", causes(&clear)));
            }
            return Err(e.context("update (Add)"));
        }
        member
            .merge_pending_commit(&self.identity)
            .map_err(|e| anyhow!("merging the Commit: {}", causes(&e)))?;
        let tree = member
            .ratchet_tree()
            .map_err(|e| anyhow!("ratchet tree: {}", causes(&e)))?;

        // The Commit to everyone already in the room, the Welcome to the
        // invitee.
        let commit = MLSMessage::tls_deserialize_exact(&bundle.commit[..])
            .map_err(|e| anyhow!("own Commit: {e:?}"))?;
        let others: Vec<String> = before.into_iter().filter(|u| *u != self.me).collect();
        self.distribute(
            &others,
            FanoutEvent::Commit {
                message: commit,
                external_proposals: vec![],
            },
        )
        .await;
        let welcome = bundle
            .welcome
            .ok_or_else(|| anyhow!("the Commit produced no Welcome"))?;
        // mimi-hubd queues a Welcome for its own users under the bare user
        // name (Jason, IETF 127 table): the URI queues nothing.
        let recipient = if self.on_hub_domain(&target) {
            target
                .rsplit_once("/u/")
                .map_or(target.as_str(), |(_, name)| name)
        } else {
            target.as_str()
        };
        if let Err(e) = self.hub.relay_welcome(recipient, welcome.clone()).await {
            self.error(format!("Welcome relay to {target}: {e:#}"));
        }
        let event = FanoutEvent::Welcome {
            message: MLSMessage::tls_deserialize_exact(&welcome[..])
                .map_err(|e| anyhow!("own Welcome: {e:?}"))?,
            ratchet_tree_option: RatchetTreeOption::full(&tree)
                .map_err(|e| anyhow!("ratchet tree option: {e:?}"))?,
        };
        if self.on_hub_domain(&target) {
            self.say(format!(
                "* note: {target} is on the hub's domain and gets the Welcome without the ratchet tree"
            ));
        } else {
            self.distribute(std::slice::from_ref(&target), event).await;
        }
        self.say(format!("[{}] * you added {target}", short_room(&room)));
        Ok(())
    }

    /// The id of the account's Consent record for requester `requester`,
    /// target `target` and any room, over JMAP.
    async fn consent_id(&self, requester: &str, target: &str) -> anyhow::Result<Option<String>> {
        let Some(jmap) = &self.hub.jmap else {
            return Ok(None);
        };
        Ok(jmap
            .consents()
            .await?
            .into_iter()
            .find(|r| {
                r["requesterUri"] == requester && r["targetUri"] == target && r["roomId"].is_null()
            })
            .and_then(|r| r["id"].as_str().map(str::to_owned)))
    }

    /// In JMAP mode, records the account's decision about `requester`
    /// (draft-atwood-jmap-chat-mimi-00 §Consent/set): the server sends the
    /// grant or revoke to the requester's provider.
    async fn decide_over_jmap(&mut self, requester: &str, decision: &str) -> anyhow::Result<()> {
        let id = self.consent_id(requester, &self.me).await?;
        let args = match id {
            Some(id) => json!({"update": {id: {"decision": decision}}}),
            None => json!({"create": {"c": {"requesterUri": requester, "targetUri": self.me,
                                            "decision": decision}}}),
        };
        let jmap = self.hub.jmap.as_ref().context("JMAP mode")?;
        jmap.consent_set(args).await?;
        Ok(())
    }

    /// /deny: refuses `arg` consent to fetch your KeyPackages (JMAP mode:
    /// Consent/set `revoke`; otherwise an updateConsent `revoke`).
    async fn deny(&mut self, arg: &str) -> anyhow::Result<()> {
        let requester = self.user_uri(arg)?;
        if self.hub.jmap.is_some() {
            self.decide_over_jmap(&requester, "revoke").await?;
        } else {
            let entry = ConsentEntry {
                consent_operation: ConsentOperation::Revoke,
                requester_uri: identifier(&requester)?,
                target_uri: identifier(&self.me)?,
                room_id: None,
                client_key_packages: vec![],
                consent_extensions: mimi_mls::wire::AppDataDictionary::new(&[])
                    .map_err(|e| anyhow!("{e:?}"))?,
            };
            self.hub.update_consent(encode(&entry)?).await?;
        }
        self.say(format!("* {requester} may not fetch your KeyPackages"));
        Ok(())
    }

    /// /consents: the account's Consent records (JMAP mode only).
    async fn consents(&mut self) -> anyhow::Result<()> {
        let jmap = self
            .hub
            .jmap
            .as_ref()
            .context("/consents needs JMAP mode (--jmap-url)")?;
        let records = jmap.consents().await?;
        if records.is_empty() {
            self.say("* no consent records".to_owned());
        }
        for r in records {
            let me_target = r["targetUri"] == self.me.as_str();
            let other = if me_target {
                &r["requesterUri"]
            } else {
                &r["targetUri"]
            };
            let other = other.as_str().unwrap_or("?");
            let room = r["roomId"]
                .as_str()
                .map(|room| format!(" in {room}"))
                .unwrap_or_default();
            let pending = if r["requested"] == true {
                ", request pending"
            } else {
                ""
            };
            let decision = match r["decision"].as_str() {
                Some("grant") => "allowed",
                Some("revoke") => "refused",
                _ => "no decision",
            };
            self.say(if me_target {
                format!("  {other} fetching your KeyPackages{room}: {decision}{pending}")
            } else {
                format!("  you fetching {other}'s KeyPackages{room}: {decision}{pending}")
            });
        }
        Ok(())
    }

    async fn allow(&mut self, arg: &str) -> anyhow::Result<()> {
        let requester = self.user_uri(arg)?;
        if self.hub.jmap.is_some() {
            self.decide_over_jmap(&requester, "grant").await?;
            self.say(format!("* {requester} may now fetch your KeyPackages"));
            return Ok(());
        }
        let entry = ConsentEntry {
            consent_operation: ConsentOperation::Grant,
            requester_uri: identifier(&requester)?,
            target_uri: identifier(&self.me)?,
            room_id: None,
            client_key_packages: vec![],
            consent_extensions: mimi_mls::wire::AppDataDictionary::new(&[])
                .map_err(|e| anyhow!("{e:?}"))?,
        };
        self.hub.update_consent(encode(&entry)?).await?;
        self.say(format!("* {requester} may now fetch your KeyPackages"));
        Ok(())
    }

    /// protocol-07 §5.7 requestConsent: asks `arg` for consent to fetch
    /// their KeyPackages for any room (`request`), or withdraws that request
    /// (`cancel`). The target must be on the hub's domain, the only provider
    /// mimid-chat talks to.
    async fn request_consent(
        &mut self,
        arg: &str,
        operation: ConsentOperation,
    ) -> anyhow::Result<()> {
        let target = self.user_uri(arg)?;
        if self.hub.jmap.is_some() {
            // draft-atwood-jmap-chat-mimi-00 §Consent/set: the server sends
            // the request or cancel, to any provider.
            let id = self.consent_id(&self.me, &target).await?;
            let requested = !matches!(operation, ConsentOperation::Cancel);
            let args = match (id, requested) {
                (Some(id), _) => json!({"update": {id: {"requested": requested}}}),
                (None, true) => {
                    json!({"create": {"c": {"requesterUri": self.me, "targetUri": target}}})
                }
                (None, false) => bail!("no consent request to {target} to withdraw"),
            };
            let jmap = self.hub.jmap.as_ref().context("JMAP mode")?;
            jmap.consent_set(args).await?;
            self.say(if requested {
                format!("* asked {target} for consent")
            } else {
                format!("* consent request to {target} withdrawn")
            });
            return Ok(());
        }
        ensure!(
            self.on_hub_domain(&target),
            "{target} is not on the hub's domain, {}",
            self.hub.domain.as_str()
        );
        let entry = ConsentEntry {
            consent_operation: operation,
            requester_uri: identifier(&self.me)?,
            target_uri: identifier(&target)?,
            room_id: None,
            client_key_packages: vec![],
            consent_extensions: mimi_mls::wire::AppDataDictionary::new(&[])
                .map_err(|e| anyhow!("{e:?}"))?,
        };
        self.hub.request_consent(encode(&entry)?).await?;
        self.say(match operation {
            ConsentOperation::Cancel => format!("* consent request to {target} withdrawn"),
            _ => format!("* asked {target} for consent"),
        });
        Ok(())
    }

    /// protocol-07 §5.9 reportAbuse: reports `<user>` in the current room
    /// to its hub, with an optional note and reason code 0, the only one
    /// the draft defines.
    ///
    /// `--message` attaches one AbusiveMessage, to test whether a hub takes
    /// a report with messages. mimid-chat keeps no received messages or
    /// franks, so the attached message is a new text message naming
    /// `<user>` as its sender, with an all-zero frank and the current time:
    /// a hub that verifies franks will find it does not verify.
    async fn report(&mut self, arg: &str) -> anyhow::Result<()> {
        let (with_message, rest) = match arg.strip_prefix("--message") {
            Some(rest) => (true, rest.trim_start()),
            None => (false, arg),
        };
        let (user, note) = rest.split_once(' ').unwrap_or((rest, ""));
        ensure!(!user.is_empty(), "usage: /report [--message] <user> [note]");
        let abuser = self.user_uri(user)?;
        let room = self.current()?;
        let messages = if with_message {
            let content = MimiContent {
                salt: random()?,
                replaces: None,
                topic_id: vec![],
                expires: None,
                in_reply_to: None,
                mimi_extensions: Extensions {
                    sender_uri: Some(abuser.clone()),
                    room_uri: Some(room.clone()),
                    other: BTreeMap::new(),
                },
                nested_part: NestedPart {
                    disposition: Disposition::RENDER,
                    language: String::new(),
                    part: Part::Single {
                        content_type: TEXT_PLAIN.to_owned(),
                        content: b"reported message".to_vec(),
                    },
                },
            }
            .encode()
            .map_err(|e| anyhow!("encoding mimi-content: {e}"))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("clock before 1970")?;
            vec![AbusiveMessage {
                message_content: content,
                frank: Frank {
                    server_frank: [0; 32],
                    franking_signature_ciphersuite: CipherSuite::tls_deserialize_exact([
                        0x00, 0x01,
                    ])
                    .map_err(|e| anyhow!("{e:?}"))?,
                    franking_integrity_signature: vec![],
                },
                accepted_timestamp: u64::try_from(now.as_millis()).context("time overflow")?,
            }]
        } else {
            vec![]
        };
        let count = messages.len();
        let report = AbuseReport {
            reporting_user: identifier(&self.me)?,
            alleged_abuser_uri: identifier(&abuser)?,
            reason_code: AbuseType::RESERVED,
            note: note.as_bytes().to_vec(),
            messages,
            abuse_extensions: mimi_mls::wire::AppDataDictionary::new(&[])
                .map_err(|e| anyhow!("{e:?}"))?,
        };
        self.hub.report_abuse(&room, encode(&report)?).await?;
        self.say(format!(
            "[{}] * reported {abuser} with {count} message(s); the hub accepted it",
            short_room(&room)
        ));
        Ok(())
    }

    async fn join(&mut self, arg: &str) -> anyhow::Result<()> {
        // Pick up anything that has just arrived.
        self.poll().await;
        ensure!(!self.state.invites.is_empty(), "no pending invite");
        let index = if arg.is_empty() {
            0
        } else {
            let numbers = || {
                let list: Vec<String> = self
                    .state
                    .invites
                    .iter()
                    .map(|i| i.number.to_string())
                    .collect();
                list.join(", ")
            };
            arg.parse::<u64>()
                .ok()
                .and_then(|n| self.state.invites.iter().position(|i| i.number == n))
                .ok_or_else(|| anyhow!("no invite {arg}; pending: {}", numbers()))?
        };
        let invite = self.state.invites[index].clone();
        let welcome = hex::decode(&invite.welcome)?;
        let tree = invite
            .ratchet_tree
            .as_deref()
            .map(hex::decode)
            .transpose()?;
        let joined = Member::join_welcome(&self.identity, &welcome, tree.as_deref());
        let member = match joined {
            Ok(join) => join.member,
            Err(e) => {
                let reason = causes(&e);
                if invite.ratchet_tree.is_none() {
                    bail!("cannot join (this Welcome came without a ratchet tree): {reason}");
                }
                bail!("cannot join: {reason}");
            }
        };
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
            .ok_or_else(|| anyhow!("joined a group with no room URI"))?;
        if member.group_id() != room.as_bytes() {
            self.state
                .group_rooms
                .insert(hex::encode(member.group_id()), room.clone());
        }
        let held_key = format!("group:{}", hex::encode(member.group_id()));
        let who = participants(&member)?;
        self.members.insert(room.clone(), member);
        self.state.rooms.insert(
            room.clone(),
            Room {
                status: RoomStatus::Active,
                out_of_sync: None,
            },
        );
        self.state.current_room = Some(room.clone());
        self.state.key_packages_outstanding = self.state.key_packages_outstanding.saturating_sub(1);
        self.save();
        self.say(format!(
            "[{}] * you joined {room}; participants: {}",
            short_room(&room),
            who.iter()
                .map(|u| display_user(u))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        // Messages that arrived before the join.
        let (replay, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.state.held)
            .into_iter()
            .partition(|(r, _)| *r == room || *r == held_key);
        self.state.held = keep;
        self.save();
        for (_, item) in replay {
            match hex::decode(&item).map(|b| MLSMessage::tls_deserialize_exact(&b[..])) {
                Ok(Ok(message)) => self.incoming_mls(&message).await,
                _ => self.error("a held message no longer decodes".to_owned()),
            }
        }
        self.top_up_key_packages().await;
        Ok(())
    }

    fn rooms(&mut self) {
        let lines: Vec<String> = self
            .state
            .rooms
            .iter()
            .map(|(uri, room)| {
                let mark = if self.state.current_room.as_deref() == Some(uri.as_str()) {
                    "*"
                } else {
                    " "
                };
                let sync = if room.out_of_sync.is_some() {
                    " (out of sync)"
                } else {
                    ""
                };
                format!("{mark} {uri} [{:?}]{sync}", room.status)
            })
            .collect();
        if lines.is_empty() {
            self.say("* no rooms".to_owned());
        }
        for line in lines {
            self.say(line);
        }
        let invites = self.state.invites.len();
        if invites > 0 {
            let numbers: Vec<String> = self
                .state
                .invites
                .iter()
                .map(|i| format!("#{}", i.number))
                .collect();
            self.say(format!(
                "* {invites} pending invite(s) ({}): /join <n>",
                numbers.join(", ")
            ));
        }
    }

    fn switch(&mut self, arg: &str) -> anyhow::Result<()> {
        let room = self.find_room(arg)?;
        self.state.current_room = Some(room.clone());
        self.save();
        self.say(format!("* current room: {room}"));
        Ok(())
    }

    fn find_room(&self, arg: &str) -> anyhow::Result<String> {
        ensure!(!arg.is_empty(), "name a room");
        let found: Vec<&String> = self
            .state
            .rooms
            .keys()
            .filter(|uri| uri.as_str() == arg || short_room(uri) == arg)
            .collect();
        match found.as_slice() {
            [one] => Ok((*one).clone()),
            [] => bail!("no room {arg}"),
            _ => bail!("{arg} is ambiguous; use the full URI"),
        }
    }

    fn who(&mut self) -> anyhow::Result<()> {
        let room = self
            .state
            .current_room
            .clone()
            .ok_or_else(|| anyhow!("no current room"))?;
        let member = self.member(&room)?;
        let list = participants(member)?;
        let leaves: Vec<String> = member
            .members()
            .into_iter()
            .map(|(leaf, id)| format!("{leaf}:{}", display_user(&String::from_utf8_lossy(&id))))
            .collect();
        let epoch = member.epoch();
        self.say(format!(
            "[{}] participants: {}",
            short_room(&room),
            list.iter()
                .map(|u| display_user(u))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        self.say(format!(
            "[{}] MLS leaves (epoch {epoch}): {}",
            short_room(&room),
            leaves.join(", ")
        ));
        Ok(())
    }

    /// protocol-07 §3.5: an AppDataUpdate proposal removing this user from
    /// the participant list, sent with update; another member commits it
    /// with the Remove of this user's leaf.
    async fn leave(&mut self, arg: &str) -> anyhow::Result<()> {
        let room = if arg.is_empty() {
            self.current()?
        } else {
            self.find_room(arg)?
        };
        ensure!(
            self.state.rooms.get(&room).map(|r| r.status) == Some(RoomStatus::Active),
            "you are not an active member of {room}"
        );
        let list = participants(self.member(&room)?)?;
        let index = list
            .iter()
            .position(|u| *u == self.me)
            .ok_or_else(|| anyhow!("you are not in {room}'s participant list"))?;
        let others: Vec<String> = list.into_iter().filter(|u| *u != self.me).collect();
        let index = u32::try_from(index).context("participant index")?;
        let member = self
            .members
            .get_mut(&room)
            .ok_or_else(|| anyhow!("no MLS group for {room}"))?;
        // protocol-07 §3.5 step 1: a Remove for this client (mimid-chat
        // runs one client per user) and the participant_list update, sent
        // together so the committer adds nothing of its own.
        let remove = member
            .propose_self_remove(&self.identity)
            .map_err(|e| anyhow!("building the Remove proposal: {}", causes(&e)))?;
        let update = member
            .propose_app_data_update(&self.identity, &list_change(vec![index], &[])?)
            .map_err(|e| anyhow!("building the leave proposal: {}", causes(&e)))?;
        let message = MLSMessage::tls_deserialize_exact(&remove[..])
            .map_err(|e| anyhow!("own Remove proposal: {e:?}"))?;
        let update = MLSMessage::tls_deserialize_exact(&update[..])
            .map_err(|e| anyhow!("own proposal: {e:?}"))?;
        let request = encode(&UpdateRequest {
            bundle: HandshakeBundle::Proposal {
                proposal_or_commit: message.clone(),
                more_proposals: vec![update.clone()],
            },
        })?;
        self.hub
            .update_ok(&room, request)
            .await
            .context("update (leave)")?;
        if let Some(r) = self.state.rooms.get_mut(&room) {
            r.status = RoomStatus::Leaving;
        }
        if self.state.current_room.as_deref() == Some(room.as_str()) {
            self.state.current_room = None;
        }
        self.save();
        if others.is_empty() {
            self.finish_leaving(&room);
            return Ok(());
        }
        self.distribute(
            &others,
            FanoutEvent::Proposal {
                message,
                more_proposals: vec![update],
            },
        )
        .await;
        self.say(format!(
            "[{}] * leave proposals sent; waiting for a member to commit it",
            short_room(&room)
        ));
        Ok(())
    }

    fn finish_leaving(&mut self, room: &str) {
        self.members.remove(room);
        if let Some(r) = self.state.rooms.get_mut(room) {
            r.status = RoomStatus::Left;
        }
        if self.state.current_room.as_deref() == Some(room) {
            self.state.current_room = None;
        }
        self.save();
        self.say(format!("[{}] * you have left {room}", short_room(room)));
    }

    async fn publish(&mut self, arg: &str) -> anyhow::Result<()> {
        let n: u32 = if arg.is_empty() {
            1
        } else {
            arg.parse()
                .ok()
                .filter(|n| (1..=20).contains(n))
                .ok_or_else(|| anyhow!("usage: /publish [1..=20]"))?
        };
        for _ in 0..n {
            self.publish_one_key_package().await?;
            self.state.key_packages_outstanding += 1;
        }
        self.save();
        self.say(format!("* published {n} KeyPackage(s)"));
        Ok(())
    }

    async fn send_text(&mut self, text: &str) -> anyhow::Result<()> {
        ensure!(text.len() <= MAX_TEXT_LEN, "message too long");
        let room = self.current()?;
        let salt: [u8; 16] = random()?;
        let content = MimiContent {
            salt,
            replaces: None,
            topic_id: vec![],
            expires: None,
            in_reply_to: None,
            mimi_extensions: Extensions {
                sender_uri: Some(self.me.clone()),
                room_uri: Some(room.clone()),
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
        }
        .encode()
        .map_err(|e| anyhow!("encoding mimi-content: {e}"))?;
        let member = self
            .members
            .get_mut(&room)
            .ok_or_else(|| anyhow!("no MLS group for {room}"))?;
        let safe_aad = frank_aad_items(member, &salt, &content);
        let ciphertext = member
            .send(&self.identity, &content, &safe_aad)
            .map_err(|e| anyhow!("encrypting: {}", causes(&e)))?;
        let others: Vec<String> = participants(member)?
            .into_iter()
            .filter(|u| *u != self.me)
            .collect();
        let message = MLSMessage::tls_deserialize_exact(&ciphertext[..])
            .map_err(|e| anyhow!("own message: {e:?}"))?;
        let request = encode(&SubmitMessageRequest {
            protocol: Protocol::Mls10,
            app_message: message.clone(),
            sending_uri: identifier(&self.me)?,
        })?;
        self.hub
            .submit(&room, request)
            .await
            .context("submitMessage")?;
        // The hub fans out to its own domain's participants only.
        let foreign: Vec<String> = others
            .into_iter()
            .filter(|u| !self.on_hub_domain(u))
            .collect();
        self.distribute(
            &foreign,
            FanoutEvent::Application {
                message,
                frank: None,
            },
        )
        .await;
        self.say(format!(
            "[{}] {}: {}",
            short_room(&room),
            display_user(&self.me),
            clean(text)
        ));
        Ok(())
    }

    // ---- distribution ----

    fn on_hub_domain(&self, user: &str) -> bool {
        user_domain(user).is_some_and(|d| d.eq_ignore_ascii_case(self.hub.domain.as_str()))
    }

    /// Puts `event` in each recipient's queue at the hub: a FanoutMessage
    /// for a user on another domain, the bare MLSMessage for one on the
    /// hub's (a Welcome then goes only through the Welcome relay).
    async fn distribute(&mut self, recipients: &[String], event: FanoutEvent) {
        let bare = match &event {
            FanoutEvent::Application { message, .. }
            | FanoutEvent::Proposal { message, .. }
            | FanoutEvent::Commit { message, .. } => Some(message.clone()),
            FanoutEvent::Welcome { .. } => None,
        };
        let fanout = encode(&FanoutMessage {
            timestamp: now_ms(),
            event,
        });
        for recipient in recipients {
            let item = if self.on_hub_domain(recipient) {
                match &bare {
                    Some(message) => encode(message),
                    None => continue,
                }
            } else {
                match &fanout {
                    Ok(bytes) => Ok(bytes.clone()),
                    Err(e) => Err(anyhow!("{e:#}")),
                }
            };
            let result = match item {
                Ok(item) => self.hub.deposit(recipient, item).await,
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                self.error(format!("delivering to {recipient}: {e:#}"));
            }
        }
    }

    // ---- incoming ----

    /// Pulls this user's queues and the current rooms' discard queues.
    pub async fn poll(&mut self) {
        if self.hub.jmap.is_some() {
            self.poll_jmap().await;
            return;
        }
        let mut errors = Vec::new();
        for _ in 0..MAX_PULLS_PER_POLL {
            match self.hub.pull_message(&self.me).await {
                Ok(Some(item)) => self.incoming(&item).await,
                Ok(None) => break,
                Err(e) => {
                    errors.push(format!("{e:#}"));
                    break;
                }
            }
        }
        for _ in 0..MAX_PULLS_PER_POLL {
            match self.hub.pull_welcome(&self.me).await {
                Ok(Some(welcome)) => self.add_invite(welcome, None),
                Ok(None) => break,
                Err(e) => {
                    errors.push(format!("{e:#}"));
                    break;
                }
            }
        }
        let rooms: Vec<String> = self.members.keys().cloned().collect();
        for room in rooms {
            for _ in 0..MAX_PULLS_PER_POLL {
                match self.hub.pull_message(&room).await {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(e) => {
                        errors.push(format!("{e:#}"));
                        break;
                    }
                }
            }
        }
        let now = errors.first().cloned();
        if now != self.last_poll_error {
            match &now {
                Some(e) => self.error(format!("polling the hub: {e}")),
                None => self.say("* polling the hub works again".to_owned()),
            }
            self.last_poll_error = now;
        }
    }

    /// Hands the JMAP transport the digests of messages sent in earlier
    /// runs (bead mimid-1wgh.12.41).
    pub fn restore_jmap_sent(&self) {
        if let Some(jmap) = &self.hub.jmap {
            jmap.restore_sent(&self.state.jmap_sent);
        }
    }

    /// Polling over JMAP (bead mimid-1wgh.12.41): every Message the server
    /// stored since the last poll, each a FanoutMessage, except those
    /// carrying this process's own MLSMessages.
    async fn poll_jmap(&mut self) {
        let Some(jmap) = &self.hub.jmap else {
            return;
        };
        let since = self.state.jmap_message_state.clone();
        let result = jmap.messages_since(since.as_deref()).await;
        let error = match result {
            Ok((state, messages)) => {
                let own: Vec<bool> = messages.iter().map(|(_, body)| jmap.is_own(body)).collect();
                for ((_, body), own) in messages.iter().zip(own) {
                    if !own {
                        self.incoming(body).await;
                    }
                }
                // Incoming items may have sent more (a leave's Commit).
                let sent = self
                    .hub
                    .jmap
                    .as_ref()
                    .map(|jmap| jmap.sent_digests())
                    .unwrap_or_default();
                if self.state.jmap_message_state.as_deref() != Some(state.as_str())
                    || self.state.jmap_sent != sent
                {
                    self.state.jmap_message_state = Some(state);
                    self.state.jmap_sent = sent;
                    self.save();
                }
                None
            }
            Err(e) => Some(format!("{e:#}")),
        };
        if error != self.last_poll_error {
            match &error {
                Some(e) => self.error(format!("polling the server: {e}")),
                None => self.say("* polling the server works again".to_owned()),
            }
            self.last_poll_error = error;
        }
    }

    async fn incoming(&mut self, item: &[u8]) {
        // A bare MLSMessage (from a client on the hub's domain), or one or
        // more FanoutMessages (§5.5, from a mimid sender).
        if let Ok(message) = MLSMessage::tls_deserialize_exact(item) {
            self.incoming_mls(&message).await;
            return;
        }
        match FanoutMessage::decode_all(item) {
            Ok(messages) if !messages.is_empty() => {
                for fanout in messages {
                    match fanout.event {
                        FanoutEvent::Application { message, .. }
                        | FanoutEvent::Commit { message, .. } => {
                            self.incoming_mls(&message).await;
                        }
                        FanoutEvent::Proposal {
                            message,
                            more_proposals,
                        } => {
                            self.deferring_leave = true;
                            self.incoming_mls(&message).await;
                            for proposal in &more_proposals {
                                self.incoming_mls(proposal).await;
                            }
                            self.deferring_leave = false;
                            if let Some((room, leaf)) = self.deferred_leaver.take() {
                                self.maybe_commit_leave(&room, leaf).await;
                            }
                        }
                        FanoutEvent::Welcome {
                            message,
                            ratchet_tree_option,
                        } => match (encode(&message), ratchet_tree_option.ratchet_tree()) {
                            (Ok(welcome), tree) => {
                                self.add_invite(welcome, tree.map(<[u8]>::to_vec))
                            }
                            (Err(e), _) => self.error(format!("a Welcome: {e:#}")),
                        },
                    }
                }
            }
            _ => self.error(format!(
                "an item of {} bytes in your queue is neither an MLSMessage nor a FanoutMessage",
                item.len()
            )),
        }
    }

    fn add_invite(&mut self, welcome: Vec<u8>, tree: Option<Vec<u8>>) {
        let welcome_hex = hex::encode(&welcome);
        if let Some(existing) = self
            .state
            .invites
            .iter_mut()
            .find(|i| i.welcome == welcome_hex)
        {
            // The same Welcome through both routes: keep the tree.
            if existing.ratchet_tree.is_none() {
                existing.ratchet_tree = tree.as_deref().map(hex::encode);
                self.save();
            }
            return;
        }
        if self.state.consumed_welcomes.contains(&welcome_hex) {
            // The other route's copy of a Welcome already joined.
            return;
        }
        let n = self
            .state
            .push_invite(welcome_hex, tree.as_deref().map(hex::encode));
        self.save();
        self.say(format!("* invite #{n} arrived: /join {n} to accept"));
    }

    async fn incoming_mls(&mut self, message: &MLSMessage) {
        // The room of the group; for a group not known yet whose ID is not a
        // room URI (a Room/create room still to be joined), `group:<hex>`, so
        // the message is held and replayed at /join.
        let Some(room) = message.group_id().map(|g| {
            self.state
                .group_rooms
                .get(&hex::encode(g))
                .cloned()
                .or_else(|| {
                    String::from_utf8(g.to_vec())
                        .ok()
                        .filter(|r| IdentifierUri::new(r).is_ok())
                })
                .unwrap_or_else(|| format!("group:{}", hex::encode(g)))
        }) else {
            self.error("an MLS message that is not for a group".to_owned());
            return;
        };
        let status = self.state.rooms.get(&room).map(|r| r.status);
        let bytes = match encode(message) {
            Ok(b) => b,
            Err(e) => {
                self.error(format!("{e:#}"));
                return;
            }
        };
        if status.is_none() {
            // Perhaps for a room whose Welcome is still pending: kept, and
            // replayed after /join.
            self.state.held.push((room, hex::encode(&bytes)));
            let excess = self.state.held.len().saturating_sub(MAX_HELD);
            self.state.held.drain(..excess);
            self.save();
            return;
        }
        if status == Some(RoomStatus::Left) {
            tracing::debug!(room = %clean(&room), "message for a room this user left; dropped");
            return;
        }
        let Some(member) = self.members.get_mut(&room) else {
            return;
        };
        let result = member.process(&self.identity, &bytes, apply_commit_op);
        let out_of_sync = member.out_of_sync().map(|o| (o.epoch, o.reason.clone()));
        if let Some(r) = self.state.rooms.get_mut(&room)
            && r.out_of_sync != out_of_sync
        {
            r.out_of_sync = out_of_sync;
            self.save();
        }
        let tag = short_room(&room);
        match result {
            Ok(Incoming::Application {
                sender_identity,
                data,
                ..
            }) => {
                let sender = String::from_utf8_lossy(&sender_identity).into_owned();
                match render(&data, &sender, &room) {
                    Ok(text) => self.say(format!("[{tag}] {}: {text}", display_user(&sender))),
                    Err(e) => self.error(format!("[{tag}] from {}: {e:#}", display_user(&sender))),
                }
            }
            Ok(Incoming::Proposal { sender }) => {
                self.say(format!(
                    "[{tag}] * proposal from {}",
                    self.leaf_name(&room, sender)
                ));
                if let Sender::Member(leaf) = sender {
                    if self.deferring_leave {
                        self.deferred_leaver = Some((room.clone(), leaf));
                    } else {
                        self.maybe_commit_leave(&room, leaf).await;
                    }
                }
            }
            Ok(Incoming::Commit(summary)) => {
                let by = self.leaf_name(&room, summary.committer);
                let added: Vec<String> = summary
                    .added
                    .iter()
                    .map(|id| display_user(&String::from_utf8_lossy(id)))
                    .collect();
                self.say(format!(
                    "[{tag}] * commit by {by} (epoch {}){}{}",
                    summary.epoch,
                    if added.is_empty() {
                        String::new()
                    } else {
                        format!(", added {}", added.join(", "))
                    },
                    if summary.removed.is_empty() {
                        String::new()
                    } else {
                        format!(", removed leaves {:?}", summary.removed)
                    }
                ));
                if summary.self_removed {
                    self.finish_leaving(&room);
                }
            }
            Ok(Incoming::OwnMessage) => {}
            Ok(other) => tracing::debug!(?other, "unhandled incoming"),
            Err(e) => self.error(format!("[{tag}] cannot process a message: {}", causes(&e))),
        }
    }

    fn leaf_name(&self, room: &str, sender: Sender) -> String {
        match sender {
            Sender::Member(leaf) => self
                .members
                .get(room)
                .and_then(|m| {
                    m.members()
                        .into_iter()
                        .find(|(l, _)| *l == leaf)
                        .map(|(_, id)| display_user(&String::from_utf8_lossy(&id)))
                })
                .unwrap_or_else(|| format!("leaf {leaf}")),
            other => format!("{other:?}"),
        }
    }

    /// A member's proposals are taken as its §3.5 leave (the only proposals
    /// mimid-chat sends): its own Remove and the participant_list update.
    /// The remaining member with the lowest leaf index commits them by
    /// reference from the proposal store and adds nothing of its own, since
    /// a hub may count a change of the committer's as a second change
    /// (mimi-hubd does, DIV-10).
    async fn maybe_commit_leave(&mut self, room: &str, leaver: u32) {
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
        if let Err(e) = self.commit_leave(room, leaver).await {
            self.error(format!(
                "[{}] committing the leave: {e:#}",
                short_room(room)
            ));
        }
    }

    async fn commit_leave(&mut self, room: &str, leaver: u32) -> anyhow::Result<()> {
        let member = self
            .members
            .get_mut(room)
            .ok_or_else(|| anyhow!("no MLS group"))?;
        let before = participants(member)?;
        let leaver_uri = member
            .members()
            .into_iter()
            .find(|(leaf, _)| *leaf == leaver)
            .map(|(_, id)| String::from_utf8_lossy(&id).into_owned());
        let bundle = member
            .commit(&self.identity, &[], &[], &[], apply_commit_op)
            .map_err(|e| anyhow!("building the Commit: {}", causes(&e)))?;
        let request = commit_request(&bundle)?;
        if let Err(e) = self.hub.update_ok(room, request).await {
            if let Err(clear) = member.clear_pending_commit(&self.identity) {
                self.error(format!("clearing the refused Commit: {}", causes(&clear)));
            }
            return Err(e.context("update (Remove)"));
        }
        member
            .merge_pending_commit(&self.identity)
            .map_err(|e| anyhow!("merging the Commit: {}", causes(&e)))?;
        let commit = MLSMessage::tls_deserialize_exact(&bundle.commit[..])
            .map_err(|e| anyhow!("own Commit: {e:?}"))?;
        // Everyone before the Commit, the leaver included, so its client
        // sees it is out.
        let recipients: Vec<String> = before.into_iter().filter(|u| *u != self.me).collect();
        self.distribute(
            &recipients,
            FanoutEvent::Commit {
                message: commit,
                external_proposals: vec![],
            },
        )
        .await;
        self.say(format!(
            "[{}] * you committed the leave of {}",
            short_room(room),
            leaver_uri.as_deref().map_or("?".to_owned(), display_user)
        ));
        Ok(())
    }

    // ---- helpers ----

    fn member(&self, room: &str) -> anyhow::Result<&Member> {
        self.members
            .get(room)
            .ok_or_else(|| anyhow!("no MLS group for {room}"))
    }

    /// A full `mimi://` user URI, or a bare name on this user's domain.
    fn user_uri(&self, arg: &str) -> anyhow::Result<String> {
        ensure!(!arg.is_empty(), "name a user");
        let uri = if arg.starts_with("mimi://") {
            arg.to_owned()
        } else {
            ensure!(
                valid_name(arg),
                "{arg:?} is neither a mimi:// URI nor a user name"
            );
            let domain = user_domain(&self.me).unwrap_or_default();
            format!("mimi://{domain}/u/{arg}")
        };
        ensure!(
            user_domain(&uri).is_some() && uri.contains("/u/"),
            "{uri} is not a mimi://<domain>/u/<name> user URI"
        );
        identifier(&uri)?;
        Ok(uri)
    }
}

// ---- free helpers ----

/// The room's last path segment, for display.
pub fn short_room(room: &str) -> String {
    clean(room.rsplit_once("/r/").map_or(room, |(_, name)| name))
}

/// `mimi://domain/u/name` as `name@domain`, else the cleaned text.
fn display_user(user: &str) -> String {
    match user
        .strip_prefix("mimi://")
        .and_then(|rest| rest.split_once("/u/"))
    {
        Some((domain, name)) if !name.contains('/') => clean(&format!("{name}@{domain}")),
        _ => clean(user),
    }
}

fn user_domain(user: &str) -> Option<&str> {
    user.strip_prefix("mimi://")?
        .split('/')
        .next()
        .filter(|d| !d.is_empty())
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// Text from a peer, made safe for a terminal: control, bidi and
/// zero-width characters are shown as escapes.
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let invisible = c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{061c}' | '\u{feff}');
        if invisible {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The text of a mimi-content message from `sender` in `room`.
fn render(data: &[u8], sender: &str, room: &str) -> anyhow::Result<String> {
    let content = MimiContent::decode(data).map_err(|e| anyhow!("not mimi-content: {e}"))?;
    // mimi-content-10 §3.3: a present senderUri or roomUri must match the
    // authenticated sender and the room.
    if let Some(claimed) = &content.mimi_extensions.sender_uri {
        ensure!(
            claimed == sender,
            "senderUri {} does not match the MLS sender",
            clean(claimed)
        );
    }
    if let Some(claimed) = &content.mimi_extensions.room_uri {
        ensure!(
            claimed == room,
            "roomUri {} does not match the room",
            clean(claimed)
        );
    }
    Ok(part_text(&content.nested_part))
}

fn part_text(part: &NestedPart) -> String {
    match &part.part {
        Part::Null => "(empty)".to_owned(),
        Part::Single {
            content_type,
            content,
        } => {
            if content_type.to_ascii_lowercase().starts_with("text/") {
                clean(&String::from_utf8_lossy(content))
            } else {
                format!("({} bytes of {})", content.len(), clean(content_type))
            }
        }
        Part::External(external) => format!("(external {})", clean(&external.content_type)),
        Part::Multi { parts, .. } => parts.iter().map(part_text).collect::<Vec<_>>().join(" | "),
    }
}

fn identifier(uri: &str) -> anyhow::Result<IdentifierUri> {
    IdentifierUri::new(uri).map_err(|e| anyhow!("{uri:?} is not a URI: {e}"))
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

fn participant_list(users: &[&str]) -> anyhow::Result<Vec<u8>> {
    encode(&ParticipantListData {
        participants: pairs(users),
    })
}

fn list_change(removed_indices: Vec<u32>, added: &[&str]) -> anyhow::Result<AppDataUpdate> {
    Ok(AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: encode(&ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices,
            added_participants: pairs(added),
        })?,
    })
}

/// A base_room_policy AppDataUpdate (room-policy-04 §5): the room's current
/// policy, or an all-false one with no limits if it has none, with
/// `settings` (`k=v`) applied. The update replaces the whole policy
/// (decision mimid-1wgh.3.20), so unnamed fields keep their values.
fn base_policy_update(member: &Member, settings: &[&str]) -> anyhow::Result<AppDataUpdate> {
    let mut policy = match member.component(BASE_ROOM_POLICY) {
        Some(data) => BaseRoomPolicy::tls_deserialize_exact(data)
            .map_err(|e| anyhow!("the room's base_room_policy does not decode: {e:?}"))?,
        None => BaseRoomPolicy {
            fixed_membership: Bool::False,
            parent_dependant: Bool::False,
            parent_room: vec![],
            multi_device: Bool::False,
            max_clients: None,
            max_users: None,
            pseudonyms_allowed: Bool::False,
            persistent_room: Bool::False,
            discoverable: Bool::False,
            policy_component_ids: vec![],
        },
    };
    for setting in settings {
        let (key, value) = setting
            .split_once('=')
            .ok_or_else(|| anyhow!("{setting:?} is not k=v"))?;
        let flag = || -> anyhow::Result<Bool> {
            match value {
                "true" => Ok(Bool::True),
                "false" => Ok(Bool::False),
                _ => bail!("{key} takes true or false"),
            }
        };
        let limit = || -> anyhow::Result<Option<u32>> {
            if value == "none" {
                Ok(None)
            } else {
                Ok(Some(value.parse().with_context(|| {
                    format!("{key} takes a number or none")
                })?))
            }
        };
        match key {
            "fixed_membership" => policy.fixed_membership = flag()?,
            "multi_device" => policy.multi_device = flag()?,
            "pseudonyms_allowed" => policy.pseudonyms_allowed = flag()?,
            "persistent_room" => policy.persistent_room = flag()?,
            "discoverable" => policy.discoverable = flag()?,
            "max_clients" => policy.max_clients = limit()?,
            "max_users" => policy.max_users = limit()?,
            other => bail!("unknown base_room_policy field {other}"),
        }
    }
    Ok(AppDataUpdate::Update {
        component_id: BASE_ROOM_POLICY,
        update: encode(&policy)?,
    })
}

/// A roles_list AppDataUpdate (room-policy-04 §3) that rewrites the room's
/// current roles unchanged, or an empty list if it has none: only its
/// presence in a Commit matters for the negative test.
fn roles_update(member: &Member) -> anyhow::Result<AppDataUpdate> {
    let roles = match member.component(ROLES_LIST) {
        Some(data) => RoleData::tls_deserialize_exact(data)
            .map_err(|e| anyhow!("the room's roles_list does not decode: {e:?}"))?,
        None => default_roles(),
    };
    Ok(AppDataUpdate::Update {
        component_id: ROLES_LIST,
        update: encode(&roles)?,
    })
}

/// The role list `/roles` sets: role 1, "banned" (room-policy-04 §8.1.3,
/// with no capabilities), and [`ROLE`], "member", the role every participant
/// mimid-chat adds gets, with what a chat member needs: send, receive,
/// reply and react (§8.3), add participants (§8.1.1) and leave (§8.1.2),
/// change the role list (§8.6, so `/invite --roles` reaches a hub's §3
/// rule instead of its capability check), and no constraints. mimi-hubd enforces canSendMessage once a room has a
/// policy, so a member without it cannot send.
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
                // room-policy-04 §8.1: adding a participant moves them from
                // role 0 to a member role, and leaving moves the leaver back
                // to 0; the actor's role must authorize each change.
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

/// [`default_roles`] with canBan and a change from role 2 to role 1 on the
/// member role; with `banned` false, role 1 is left undefined.
fn ban_roles(banned: bool) -> RoleData {
    let mut roles = default_roles();
    if let Some(member) = roles.roles.iter_mut().find(|r| r.role_index == ROLE) {
        member.role_capabilities.push(Capability::CAN_BAN);
        member
            .authorized_role_changes
            .push(SingleSourceRoleChangeTargets {
                from_role_index: ROLE,
                target_role_indexes: vec![1],
            });
    }
    if !banned {
        roles.roles.retain(|r| r.role_index != 1);
    }
    roles
}

/// The base_room_policy `/host` sets: open membership, several devices,
/// no limits, persistent (room-policy-04 §5).
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

/// The Safe AAD items for a message in `member`'s room: a `frank_aad` item
/// carrying the message's franking tag (protocol-07 §5.4.1, §10.1) when the
/// room's `safe_aad` list requires frank_aad, as rooms hosted by mimid do,
/// and none otherwise (Member::send refuses items in a room without Safe
/// AAD).
fn frank_aad_items(member: &Member, salt: &[u8; 16], content: &[u8]) -> Vec<(u16, Vec<u8>)> {
    // ComponentsList: component_ids<V>, two bytes per id; one length byte
    // is enough for any list mimid-chat meets.
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

/// The participant list (protocol-07 §7.5) of `member`'s group.
fn participants(member: &Member) -> anyhow::Result<Vec<String>> {
    let Some(data) = member.component(PARTICIPANT_LIST) else {
        return Ok(vec![]);
    };
    let list = ParticipantListData::tls_deserialize_exact(data)
        .map_err(|e| anyhow!("the participant list does not decode: {e:?}"))?;
    Ok(list
        .participants
        .into_iter()
        .map(|p| String::from_utf8_lossy(&p.user).into_owned())
        .collect())
}

/// protocol-07 §5.3 UpdateRequest around a CommitBundle. The bundle's
/// RatchetTreeOption is `distributionService` (ratchet-tree-options-02): a
/// mimid hub rebuilds the tree from the Commits it accepts and attaches its
/// own to Welcomes (decision mimid-1wgh.6.12), and mimi-hubd reads no tree,
/// so a `full` tree here was uploaded on every Commit and never used. A
/// joiner still gets the full tree in the Welcome this client delivers.
fn commit_request(bundle: &CommitBundle) -> anyhow::Result<Vec<u8>> {
    let welcome = bundle
        .welcome
        .as_ref()
        .map(|w| {
            let bare = w
                .strip_prefix(&WELCOME_HEADER)
                .ok_or_else(|| anyhow!("the Welcome is not an mls_welcome MLSMessage"))?;
            Welcome::tls_deserialize_exact(bare).map_err(|e| anyhow!("own Welcome: {e:?}"))
        })
        .transpose()?;
    let group_info = bundle
        .group_info
        .strip_prefix(&GROUP_INFO_HEADER)
        .ok_or_else(|| anyhow!("the GroupInfo is not an mls_group_info MLSMessage"))?;
    encode(&UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(&bundle.commit[..])
                .map_err(|e| anyhow!("own Commit: {e:?}"))?,
            welcome,
            group_info_option: GroupInfoOption::Full {
                group_info: GroupInfo::tls_deserialize_exact(group_info)
                    .map_err(|e| anyhow!("own GroupInfo: {e:?}"))?,
            },
            ratchet_tree_option: RatchetTreeOption::distribution_service(),
        },
    })
}

/// A signed protocol-07 §5.2 KeyMaterialRequest. Its signature key is a
/// fresh Ed25519 key per request: `Identity` does not hand out the MLS
/// signing key, and the hub does not verify this signature
/// (mimi-hubd `key_material_wire`).
fn key_material_request(requester: &str, target: &str, room: &str) -> anyhow::Result<Vec<u8>> {
    let seed: [u8; 32] = random()?;
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let key = encode(&VLBytes::new(public.to_vec()))?;
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
            CipherSuite::tls_deserialize_exact([0x00, 0x01]).map_err(|e| anyhow!("{e:?}"))?,
        ],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact(REQUIRED_CAPABILITIES)
            .map_err(|e| anyhow!("{e:?}"))?,
        requester_signature_key: SignaturePublicKey::tls_deserialize_exact(&key)
            .map_err(|e| anyhow!("{e:?}"))?,
        requester_credential: Credential::tls_deserialize_exact(&credential)
            .map_err(|e| anyhow!("{e:?}"))?,
    }
    .sign(
        &mimi_mls::label::SignatureKeyPair::from_raw(&seed, &public)
            .map_err(|e| anyhow!("the request key: {e}"))?,
    )
    .map_err(|e| anyhow!("signing the keyMaterial request: {e}"))?;
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
fn room_metadata(room: &str, name: &str) -> anyhow::Result<Vec<u8>> {
    let uri = IdentifierUri::new(room).map_err(|e| anyhow!("room URI: {e:?}"))?;
    let text = |t: &str| Utf8String::new(t.to_owned()).map_err(|e| anyhow!("{e:?}"));
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
fn add_component_id(list: &[u8], component: u16) -> anyhow::Result<Vec<u8>> {
    let (&len, ids) = list
        .split_first()
        .ok_or_else(|| anyhow!("empty app_components"))?;
    ensure!(
        usize::from(len) == ids.len() && len < 0x3e,
        "unexpected app_components list"
    );
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
    let mut out = vec![u8::try_from(ids.len() * 2)?];
    for id in ids {
        out.extend(id.to_be_bytes());
    }
    Ok(out)
}

fn random<const N: usize>() -> anyhow::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness: {e}"))?;
    Ok(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// An error and its causes, as one line.
fn causes(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_escapes_terminal_controls() {
        assert_eq!(clean("hi\x1b[2J"), "hi\\u{1b}[2J");
        assert_eq!(clean("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(clean("plain text"), "plain text");
    }

    #[test]
    fn display_user_shortens_user_uris() {
        assert_eq!(display_user("mimi://d.example/u/alice"), "alice@d.example");
        assert_eq!(display_user("not a uri"), "not a uri");
    }

    #[test]
    fn short_room_is_the_name() {
        assert_eq!(short_room("mimi://hub.example/r/table"), "table");
    }

    #[test]
    fn names_are_restricted() {
        assert!(valid_name("alice-2"));
        assert!(!valid_name(""));
        assert!(!valid_name(".x"));
        assert!(!valid_name("Alice"));
        assert!(!valid_name("a/b"));
    }

    #[test]
    fn render_checks_sender_and_room() {
        let content = |sender: &str| {
            MimiContent {
                salt: [0; 16],
                replaces: None,
                topic_id: vec![],
                expires: None,
                in_reply_to: None,
                mimi_extensions: Extensions {
                    sender_uri: Some(sender.to_owned()),
                    room_uri: Some("mimi://h/r/x".to_owned()),
                    other: BTreeMap::new(),
                },
                nested_part: NestedPart {
                    disposition: Disposition::RENDER,
                    language: String::new(),
                    part: Part::Single {
                        content_type: TEXT_PLAIN.to_owned(),
                        content: b"hello".to_vec(),
                    },
                },
            }
            .encode()
            .unwrap()
        };
        assert_eq!(
            render(&content("mimi://d/u/a"), "mimi://d/u/a", "mimi://h/r/x").unwrap(),
            "hello"
        );
        assert!(render(&content("mimi://d/u/b"), "mimi://d/u/a", "mimi://h/r/x").is_err());
        assert!(render(&content("mimi://d/u/a"), "mimi://d/u/a", "mimi://h/r/y").is_err());
    }
}
