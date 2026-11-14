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
use mimi_mls::member::{AppDataUpdate, CommitBundle, Incoming, Member, OutOfSync, Sender};
use mimi_mls::tls_codec::{Deserialize, VLBytes};
use mimi_mls::wire::{
    CipherSuite, Credential, GroupInfo, MLSMessage, RatchetTreeOption, RequiredCapabilities,
    SignaturePublicKey, Welcome,
};
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::{
    ClientKeyMaterial, ConsentEntry, ConsentOperation, FanoutEvent, FanoutMessage, GroupInfoOption,
    HandshakeBundle, IdentifierUri, KeyMaterialRequestTbs, KeyMaterialResponse,
    KeyMaterialUserCode, ParticipantListData, ParticipantListUpdate, Protocol,
    SubmitMessageRequest, UpdateRequest, UserRolePair,
};
use mimid_server::hub::components::apply_commit_op;

use crate::hub::{Hub, encode};
use crate::state::{Invite, Room, RoomStatus, State, StateDir};

/// mls-extensions-10 §5 `app_components`.
const APP_COMPONENTS: u16 = 0x0001;
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
/// The role every participant gets (room-policy-04 has no default; the
/// driver and b4.sh use 1).
const ROLE: u32 = 1;
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
            match Member::load(&client.identity, uri.as_bytes()) {
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
                "invite" => self.invite(arg).await,
                "allow" => self.allow(arg).await,
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
            "/invite <user>         add a user (a mimi:// URI, or a bare name on your domain)",
            "/allow <user>          let <user> fetch your KeyPackages (updateConsent grant)",
            "/join [n]              accept pending invite n (default: the oldest)",
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
                // mls-extensions-10 §5: a ComponentsList naming participant_list.
                (APP_COMPONENTS, vec![0x02, 0x00, 0x22]),
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
        let target = self.user_uri(arg)?;
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
        let response = KeyMaterialResponse::tls_deserialize_exact(&body[..])
            .map_err(|e| anyhow!("the hub's KeyMaterialResponse does not decode: {e:?}"))?;
        match response.user_status {
            KeyMaterialUserCode::Success | KeyMaterialUserCode::PartialSuccess => {}
            KeyMaterialUserCode::NoConsent | KeyMaterialUserCode::NoConsentForThisRoom => bail!(
                "{target} has not consented to you: they must run /allow {} first",
                self.me
            ),
            other => bail!("keyMaterial for {target}: {other:?}"),
        }
        let mut key_packages = Vec::new();
        for client in &response.clients {
            if let ClientKeyMaterial::Success { key_package, .. } = client {
                let info = key_package
                    .verify(SystemTime::now())
                    .map_err(|e| anyhow!("{target}'s KeyPackage does not verify: {e:?}"))?;
                ensure!(
                    info.identity() == Some(target.as_bytes()),
                    "the hub served a KeyPackage for another identity"
                );
                key_packages.push(encode(key_package)?);
            }
        }
        ensure!(
            !key_packages.is_empty(),
            "the hub has no KeyPackage for {target} (they must run mimid-chat once, or /publish)"
        );
        let adds: Vec<&[u8]> = key_packages.iter().map(Vec::as_slice).collect();

        // Commit: Add beside one ParticipantListUpdate (protocol-07 §3.2;
        // mimi-hubd DIV-10 takes exactly one change per Commit).
        let member = self
            .members
            .get_mut(&room)
            .ok_or_else(|| anyhow!("no MLS group for {room}"))?;
        let bundle = member
            .commit(
                &self.identity,
                &adds,
                &[],
                &[list_change(vec![], &[target.as_str()])?],
                apply_commit_op,
            )
            .map_err(|e| anyhow!("building the Commit: {}", causes(&e)))?;
        let request = commit_request(member, &bundle)?;
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
        if let Err(e) = self.hub.relay_welcome(&target, welcome.clone()).await {
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

    async fn allow(&mut self, arg: &str) -> anyhow::Result<()> {
        let requester = self.user_uri(arg)?;
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

    async fn join(&mut self, arg: &str) -> anyhow::Result<()> {
        // Pick up anything that has just arrived.
        self.poll().await;
        ensure!(!self.state.invites.is_empty(), "no pending invite");
        let index = if arg.is_empty() {
            0
        } else {
            arg.parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .filter(|&n| n < self.state.invites.len())
                .ok_or_else(|| anyhow!("usage: /join [1..={}]", self.state.invites.len()))?
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
        let room = String::from_utf8(member.group_id().to_vec())
            .ok()
            .filter(|r| IdentifierUri::new(r).is_ok())
            .ok_or_else(|| anyhow!("joined a group whose ID is not a room URI"))?;
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
            .partition(|(r, _)| *r == room);
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
            self.say(format!("* {invites} pending invite(s): /join"));
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
        let proposal = member
            .propose_app_data_update(&self.identity, &list_change(vec![index], &[])?)
            .map_err(|e| anyhow!("building the leave proposal: {}", causes(&e)))?;
        let message = MLSMessage::tls_deserialize_exact(&proposal[..])
            .map_err(|e| anyhow!("own proposal: {e:?}"))?;
        let request = encode(&UpdateRequest {
            bundle: HandshakeBundle::Proposal {
                proposal_or_commit: message.clone(),
                more_proposals: vec![],
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
                more_proposals: vec![],
            },
        )
        .await;
        self.say(format!(
            "[{}] * leave proposal sent; waiting for a member to commit it",
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
        let content = MimiContent {
            salt: random()?,
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
        let ciphertext = member
            .send(&self.identity, &content, &[])
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
                        | FanoutEvent::Proposal { message, .. }
                        | FanoutEvent::Commit { message, .. } => {
                            self.incoming_mls(&message).await;
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
        self.state.invites.push(Invite {
            welcome: welcome_hex,
            ratchet_tree: tree.as_deref().map(hex::encode),
        });
        self.save();
        let n = self.state.invites.len();
        self.say(format!("* invite #{n} arrived: /join {n} to accept"));
    }

    async fn incoming_mls(&mut self, message: &MLSMessage) {
        let Some(room) = message
            .group_id()
            .and_then(|g| String::from_utf8(g.to_vec()).ok())
        else {
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
                    self.maybe_commit_leave(&room, leaf).await;
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

    /// A member's proposal is taken as its §3.5 leave (the only proposal
    /// mimid-chat sends). The remaining member with the lowest leaf index
    /// commits it, with the Remove of the leaver's leaf; the proposal goes
    /// in by reference from the proposal store.
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
            .commit(&self.identity, &[], &[leaver], &[], apply_commit_op)
            .map_err(|e| anyhow!("building the Commit: {}", causes(&e)))?;
        let request = commit_request(member, &bundle)?;
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

/// protocol-07 §5.3 UpdateRequest around a CommitBundle.
fn commit_request(member: &Member, bundle: &CommitBundle) -> anyhow::Result<Vec<u8>> {
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
    let tree = member
        .ratchet_tree()
        .map_err(|e| anyhow!("ratchet tree: {}", causes(&e)))?;
    encode(&UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(&bundle.commit[..])
                .map_err(|e| anyhow!("own Commit: {e:?}"))?,
            welcome,
            group_info_option: GroupInfoOption::Full {
                group_info: GroupInfo::tls_deserialize_exact(group_info)
                    .map_err(|e| anyhow!("own GroupInfo: {e:?}"))?,
            },
            ratchet_tree_option: RatchetTreeOption::full(&tree)
                .map_err(|e| anyhow!("ratchet tree option: {e:?}"))?,
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
        required_capabilities: RequiredCapabilities::tls_deserialize_exact([0x00, 0x00, 0x00])
            .map_err(|e| anyhow!("{e:?}"))?,
        requester_signature_key: SignaturePublicKey::tls_deserialize_exact(&key)
            .map_err(|e| anyhow!("{e:?}"))?,
        requester_credential: Credential::tls_deserialize_exact(&credential)
            .map_err(|e| anyhow!("{e:?}"))?,
    }
    .sign(&seed)
    .map_err(|e| anyhow!("signing the keyMaterial request: {e}"))?;
    encode(&request)
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
