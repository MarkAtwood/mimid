//! The `mimid` service nick (INVENTED, NOT FROM SPEC;
//! docs/design/agent-frontends.md §4, §7.5): what IRC has no command for.
//! The user sends it text (`/msg mimid <command>`) and it answers with
//! NOTICEs from `mimid!mimid@<server>`.
//!
//! The same commands also reach it as a raw verb, `MIMID <command>`
//! (`/quote MIMID ...`), which Mark asked for on 2026-11-22 for scripts
//! and muscle memory; both forms call this one handler. The service nick
//! stays the documented path, because its NOTICEs land in a query window
//! that a client renders and logs, which `password add` depends on: it
//! shows a secret once, and a raw-verb reply can land in a status window
//! a client renders oddly or discards.
//!
//! | Command | Does |
//! |---|---|
//! | `help` | lists these commands |
//! | `allow <nick, user URI or user@domain>` | consents to the user: their invites are joined from the next sync (`Store::allow`) |
//! | `deny <nick, user URI or user@domain>` | refuses the user: they may no longer fetch the user's KeyPackages to invite them, and their invites are not joined (`Store::deny`) |
//!
//! `user@domain` stands for the user URI `mimi://domain/u/user` (§7.15),
//! here and in INVITE.
//! | `invites` | lists the pending invites, each accepted by JOIN of the channel name it is shown under (§7.13) or of `&invite-<number>` |
//! | `expire <#channel> [<duration> or off]` | shows or sets the room's local expiry policy: messages older than the duration are deleted here (`Store::set_message_expiry`, §7.21) |
//! | `burn <#channel> <text>` | sends `text` to be deleted by each mimid recipient once read; the user's own copy stays (`Store::send_with`, §7.22) |
//! | `call <#channel> <url> [<description>]` | sends a call to join: `url`, which must be `https` or `wss`, as mimi-content-10 §5.10 has it (`Store::send_call`, §7.24) |
//! | `devices` | lists the user's devices, the clients the server has bound to the account (`Store::devices`; draft-atwood-jmap-chat-mimi-00 §Clients) |
//! | `forget-device <id>` | forgets another device, such as a lost one: the server unbinds it and its leaves leave every room this device shares with it (`Store::forget_device`) |
//! | `identity <user>` | what is known of a user's identity: their did:webvh DID and when it last changed, or that they have none, which means their provider's word is all there is |
//! | `rooms` | the user's rooms, by the channel name this client knows them under, with their state: in, leaving, or left |
//! | `version` | this front end's version |
//! | `passwords` | lists the credentials: names, kinds, when made and last used; never a secret (docs/design/frontend-auth.md §3.6) |
//! | `password add <name>` | makes an app password and shows it once, with a warning that the client may log the line (decision A5) |
//! | `password revoke <name>` | revokes an app password; its connections close, this one included if it used it |
//!
//! # Limitations
//!
//! - English only.
//! - Rooms are made with JOIN and left with PART (§7.1), so the service
//!   has no `create` or `leave`; reports and removing participants have
//!   no command in v1.

use crate::command::Who;
use crate::conn::{Session, VERSION, one_line};
use crate::line::Out;
use crate::names::SERVICE_NICK;
use mimid_agent_store::Binding;
use mimid_agent_store::record::{Call, Invite, MessageExpiry, RoomStatus};

/// How long a link from `link` is good for: long enough to switch to a
/// browser and open it, short enough that a line left in a log is not a
/// lasting key. INVENTED VALUE, NOT FROM SPEC.
pub const LINK_LIFETIME: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// The help text, one NOTICE a line.
const HELP: &[&str] = &[
    "mimid service commands:",
    "  allow <user>  let this user's invites in (joined at the next sync)",
    "  deny <user>   refuse this user: they can no longer invite you",
    "  invites       list pending invites; JOIN of the invite's channel accepts it",
    "  expire #channel [<duration>|off]  show or set how long messages are kept",
    "                here: 90s, 30m, 12h, 7d or 2w; off keeps them",
    "  burn #channel <text>  send text that each mimid recipient deletes once",
    "                read; your own copy stays; other software keeps it",
    "  call #channel <url> [<description>]  send a call to join; the URL",
    "                must be https:// or wss://",
    "  devices       list your devices (the clients bound to your account)",
    "  forget-device <id>  forget a lost device: it is unbound and removed from your rooms",
    "  passwords     list your app passwords and the agent token",
    "  password add <name>  make an app password for a device; shown once",
    "  password revoke <name>  revoke one; its connections close",
    "  identity <user>  show what is known of a user's identity: their",
    "                did:webvh DID if they have one, and when it last changed",
    "  rooms         list your rooms and their state, this client's channels",
    "                and the ones you have left included",
    "  version       this agent's version",
    "  whoami        which agent this is: your user, your provider, where its",
    "                state lives, and which binding it speaks",
    "  sync          sync now, and say what the last one did",
    "  report #channel <msgid>... [<reason>]  report messages to the room's hub",
    "                as abusive; <reason> is a number 0-255, then free text",
    "  link #channel <msgid> [<n>]  a link to attachment <n> (default 1) of a",
    "                message, to open in a browser; it expires",
    "A <user> is a nick, a user URI (mimi://domain/u/name) or name@domain,",
    "which stands for mimi://domain/u/name.",
    "Rooms: JOIN #name hosts a new room; PART leaves a room for good;",
    "INVITE <user> #channel invites someone; TOPIC #channel :text sets the",
    "room's subject, if your role may. No private messages.",
];

impl Session {
    /// What made a credential from here: `irc (<credential>)`.
    fn credential_label(&self) -> String {
        match &self.login {
            Some(login) => format!("irc ({})", login.name),
            None => "irc".to_owned(),
        }
    }

    /// `password add <name>` (docs/design/frontend-auth.md §3.6; decision
    /// A5): the new secret in a NOTICE, with the warning that IRC clients
    /// log what they are sent.
    fn password_add(&mut self, name: &str) {
        let by = self.credential_label();
        match self.shared.credentials.add(name, &by) {
            Ok((info, password)) => {
                self.service_says(&format!(
                    "app password {} made; it is shown once: {}",
                    info.name,
                    password.shown()
                ));
                self.service_says(
                    "warning: your IRC client may have written that line to its log on \
                     disk; delete it there, or make passwords with \
                     `mimid-agent <config> app-password add` instead",
                );
            }
            Err(error) => self.service_says(&format!("password add failed: {error}")),
        }
    }

    /// A NOTICE from the service to the user.
    fn service_says(&mut self, text: &str) {
        let me = self.me();
        let source = format!("{SERVICE_NICK}!{SERVICE_NICK}@{}", self.shared.server);
        self.send(&Out::new(&source, "NOTICE", vec![me.nick, one_line(text)]));
    }

    /// Text the user sent the service.
    pub(crate) async fn service(&mut self, text: &str) {
        let mut words = text.split_whitespace();
        let command = words.next().unwrap_or_default().to_ascii_lowercase();
        let argument = words.next();
        match (command.as_str(), argument) {
            ("help", _) | ("", _) => {
                for line in HELP {
                    self.service_says(line);
                }
            }
            ("allow" | "deny", Some(name)) => {
                let Who::User(user) = self.who_or_address(name) else {
                    self.service_says(&format!(
                        "{name} is no nick here; give the user URI (mimi://<domain>/u/<name>) or <name>@<domain>"
                    ));
                    return;
                };
                let store = self.store();
                let result = if command == "allow" {
                    store.allow(&user).await
                } else {
                    store.deny(&user).await
                };
                match result {
                    Ok(()) if command == "allow" => self.service_says(&format!(
                        "allowed {user}: their invites are joined from now on"
                    )),
                    Ok(()) => self.service_says(&format!(
                        "denied {user}: they may not fetch your keys to invite you, and their invites are not joined"
                    )),
                    Err(error) => self.service_says(&format!("{command} {user} failed: {error}")),
                }
            }
            ("allow" | "deny", None) => {
                self.service_says(&format!("usage: {command} <nick, user URI or name@domain>"));
            }
            // §7.15's forms, and the Person record's DID: nothing else in
            // IRC shows who a user is cryptographically. `did_changed_at`
            // is what an identity-change notice is about, so it is shown.
            ("identity", Some(name)) => {
                let Who::User(user) = self.who_or_address(name) else {
                    self.service_says(&format!(
                        "{name} is no nick here; give the user URI (mimi://<domain>/u/<name>) or <name>@<domain>"
                    ));
                    return;
                };
                // Yourself is the first thing anyone asks, and there is
                // no Person record for the user themself: the store makes
                // those for others it has seen.
                if user == self.shared.store.user() {
                    self.service_says(&format!("{user} is you"));
                    self.service_says("  your own devices and keys: devices");
                    return;
                }
                let person = self
                    .shared
                    .store
                    .state()
                    .people
                    .values()
                    .find(|p| p.user == user)
                    .cloned();
                match person {
                    None => {
                        self.service_says(&format!("{user}: nobody of that name is known here yet"))
                    }
                    Some(person) => {
                        self.service_says(&format!("{}:", person.user));
                        if let Some(name) = &person.display_name {
                            self.service_says(&format!("  name you gave them: {name}"));
                        }
                        match &person.did {
                            Some(did) => {
                                self.service_says(&format!("  did:webvh: {did}"));
                                match person.did_changed_at {
                                    Some(at) => self.service_says(&format!(
                                        "  that DID last changed at {}",
                                        crate::render::server_time(at)
                                    )),
                                    None => self.service_says(
                                        "  that DID has not changed since first seen",
                                    ),
                                }
                            }
                            // The default, and the weakness worth saying
                            // out loud: a BasicCredential is the
                            // provider's word for who this is.
                            None => self.service_says(
                                "  no did:webvh DID: their provider vouches for this name,                                  nothing more",
                            ),
                        }
                        self.service_says(&format!(
                            "  first seen at {}",
                            crate::render::server_time(person.first_seen)
                        ));
                    }
                }
            }
            ("identity", None) => {
                self.service_says("usage: identity <nick, user URI or name@domain>");
            }
            // A room the user has left, or is leaving, keeps its record
            // and its channel in the client, so the state is worth
            // showing: PART alone does not say which it is.
            ("rooms", _) => {
                // The channel name this client knows the room by, not the
                // room's own name: in an IRC client the user knows
                // #lobby, and the room is named "lobby".
                let rooms: Vec<(String, Option<String>, RoomStatus)> = {
                    let names = self.shared.names();
                    self.shared
                        .store
                        .state()
                        .rooms
                        .values()
                        .map(|room| {
                            (
                                room.uri.clone(),
                                names.channel(&room.key).map(str::to_owned),
                                room.status,
                            )
                        })
                        .collect()
                };
                if rooms.is_empty() {
                    self.service_says("no rooms; JOIN #name hosts one");
                }
                for (uri, name, status) in rooms {
                    let state = match status {
                        RoomStatus::Active => "in",
                        RoomStatus::Leaving => "leaving (the hub has not removed you yet)",
                        RoomStatus::Left => "left",
                        _ => "in some state this version does not know",
                    };
                    match name {
                        Some(channel) => {
                            self.service_says(&format!("{channel}  {state}  {uri}"));
                        }
                        // A room with no channel here: left, or not shown.
                        None => self.service_says(&format!("(no channel)  {state}  {uri}")),
                    }
                }
            }
            // There is no build-revision constant to show; the crate
            // version is what the CTCP VERSION reply already carries.
            ("version", _) => self.service_says(VERSION),
            // Bead mimid-i0id.10: the first thing to ask when several
            // agents run on one machine. Never the token.
            ("whoami", _) => {
                // Read everything first: service_says takes &mut self.
                let user = self.shared.store.user().to_owned();
                let state = self.shared.store.database_path().display().to_string();
                let binding = match self.shared.store.binding().await {
                    Binding::Jmap => "JMAP",
                    Binding::Stream => "mimid's live stream",
                    _ => "one this version does not name",
                };
                self.service_says(&format!("you are {user}"));
                self.service_says(&format!("  binding: {binding}"));
                self.service_says(&format!("  state: {state}"));
                self.service_says(&format!("  this front end: {VERSION}"));
            }
            // Bead mimid-i0id.8: a room can sit out of sync with nothing
            // telling the user (AGENTS.md: mark it out of sync and wait),
            // so this is the one place that state is visible.
            ("sync", _) => {
                self.service_says("syncing now");
                match self.shared.store.sync().await {
                    Ok(report) => {
                        self.service_says(&format!(
                            "synced: {} message(s), {} room(s) joined, {} edit(s)",
                            report.messages,
                            report.joined.len(),
                            report.edits
                        ));
                        if !report.pending_invites.is_empty() {
                            self.service_says(&format!(
                                "  {} invite(s) waiting; see invites",
                                report.pending_invites.len()
                            ));
                        }
                        // The problems are the whole point: a room out of
                        // sync says so here and nowhere else.
                        for problem in &report.problems {
                            self.service_says(&format!("  problem: {problem}"));
                        }
                        for skipped in &report.skipped {
                            self.service_says(&format!("  not stored: {skipped}"));
                        }
                    }
                    Err(error) => {
                        self.service_says(&format!("sync failed: {error}"));
                        self.service_says(
                            "  nothing is lost: what was not acknowledged comes again",
                        );
                    }
                }
            }
            ("invites", _) => {
                let invites: Vec<Invite> = self.shared.store.state().invites.clone();
                if invites.is_empty() {
                    self.service_says("no pending invites");
                }
                for invite in invites {
                    let number = invite.number;
                    let (from, channel) = {
                        let mut names = self.shared.names();
                        let from = match &invite.inviter {
                            Some(uri) => format!("{} ({uri})", names.nick(uri)),
                            None => "an unknown inviter".to_owned(),
                        };
                        (from, names.invite_channel(&invite))
                    };
                    let how = if channel.starts_with('#') {
                        format!("JOIN {channel} or JOIN &invite-{number} to accept")
                    } else {
                        format!("JOIN &invite-{number} to accept")
                    };
                    self.service_says(&format!("invite {number} from {from}: {how}"));
                }
            }
            ("expire", Some(channel)) => self.expire(channel, words.next()).await,
            ("burn", Some(channel)) => {
                // The text is the rest of the line as sent, spaces kept.
                let text = text
                    .trim_start()
                    .split_once(char::is_whitespace)
                    .and_then(|(_, rest)| rest.trim_start().split_once(char::is_whitespace))
                    .map_or("", |(_, text)| text.trim_start());
                self.burn(channel, text).await;
            }
            ("call", Some(channel)) => {
                let Some(url) = words.next() else {
                    self.service_says("usage: call #channel <url> [<description>]");
                    return;
                };
                // The description is the rest of the line, spaces kept.
                let description = after_words(text, 3).trim_end();
                self.call(channel, url, description).await;
            }
            ("call", None) => self.service_says("usage: call #channel <url> [<description>]"),
            ("expire", None) => {
                self.service_says("usage: expire #channel [<duration> or off]");
            }
            ("burn", None) => self.service_says("usage: burn #channel <text>"),
            // Bead mimid-i0id.7: the service's own Limitations said
            // reports had no command in v1, so abuse reporting was
            // JMAP-only.
            ("report", Some(channel)) => {
                let rest: Vec<String> = words.map(str::to_owned).collect();
                self.report(channel, &rest).await;
            }
            ("report", None) => {
                self.service_says("usage: report #channel <msgid>... [<reason 0-255>] [<note>]")
            }
            // Bead mimid-i0id.9: IRC has no attachment story, and DCC is
            // not it; the agent already serves the blob over its loopback
            // listener behind an HMAC link.
            ("link", Some(channel)) => {
                let msgid = words.next().map(str::to_owned);
                let index = words.next().and_then(|n| n.parse::<usize>().ok());
                match msgid {
                    Some(msgid) => self.attachment_link(channel, &msgid, index).await,
                    None => self.service_says("usage: link #channel <msgid> [<n>]"),
                }
            }
            ("link", None) => self.service_says("usage: link #channel <msgid> [<n>]"),
            ("devices", _) => {
                let devices = self.store().devices().await;
                match devices {
                    Ok(devices) if devices.is_empty() => self.service_says("no devices"),
                    Ok(devices) => {
                        for device in devices {
                            let this = if device.this_device {
                                " (this device)"
                            } else {
                                ""
                            };
                            self.service_says(&format!("device {}{this}", device.id));
                        }
                    }
                    Err(error) => self.service_says(&format!("devices failed: {error}")),
                }
            }
            ("forget-device", Some(id)) => {
                let forgotten = self.store().forget_device(id).await;
                match forgotten {
                    Ok(forgotten) => {
                        self.service_says(&format!(
                            "forgot device {id}: removed from {} room(s)",
                            forgotten.removed_from.len()
                        ));
                        for (room, why) in forgotten.failed {
                            self.service_says(&format!("not removed from {room}: {why}"));
                        }
                    }
                    Err(error) => self.service_says(&format!("forget-device {id} failed: {error}")),
                }
            }
            ("forget-device", None) => self.service_says("usage: forget-device <id>, from devices"),
            ("passwords", _) | ("password", Some("list")) => {
                for info in self.shared.credentials.list() {
                    self.service_says(&mimid_agent_store::credentials::describe(&info));
                }
            }
            ("password", Some("add")) => match words.next() {
                Some(name) => self.password_add(name),
                None => self.service_says("usage: password add <name>, e.g. password add phone"),
            },
            ("password", Some("revoke")) => match words.next() {
                Some(name) => {
                    let by = self.credential_label();
                    match self.shared.credentials.revoke(name, &by) {
                        Ok(info) => self.service_says(&format!(
                            "revoked {}: its connections close now",
                            info.name
                        )),
                        Err(error) => {
                            self.service_says(&format!("password revoke failed: {error}"))
                        }
                    }
                }
                None => self.service_says("usage: password revoke <name>"),
            },
            ("password", _) => {
                self.service_says("usage: passwords, password add <name>, password revoke <name>");
            }
            _ => self.service_says(&format!("unknown command {command:?}; try help")),
        }
    }

    /// `expire #channel [duration|off]` (docs/design/agent-frontends.md
    /// §7.21): shows or sets the room's local expiry policy.
    async fn expire(&mut self, channel: &str, duration: Option<&str>) {
        let Some(key) = self.shown_room(channel) else {
            self.service_says(&format!("{channel}: no such channel here"));
            return;
        };
        let store = self.store();
        let Some(duration) = duration else {
            let now = store
                .state()
                .rooms
                .get(&key)
                .and_then(|r| r.message_expiry_seconds);
            self.service_says(&match now {
                Some(seconds) => format!(
                    "{channel}: messages are deleted here {} after they arrive",
                    show_duration(seconds)
                ),
                None => format!("{channel}: messages are kept"),
            });
            return;
        };
        let Some(seconds) = parse_duration(duration) else {
            self.service_says(&format!(
                "{duration:?} is no duration; give 90s, 30m, 12h, 7d, 2w, or off"
            ));
            return;
        };
        store.set_message_expiry(&key, seconds);
        self.save().await;
        self.service_says(&match seconds {
            Some(seconds) => format!(
                "{channel}: messages are deleted here {} after they arrive;                  others in the room keep their own copies",
                show_duration(seconds)
            ),
            None => format!("{channel}: messages are kept"),
        });
    }

    /// `burn #channel text` (docs/design/agent-frontends.md §7.22): sends
    /// `text` with burnOnRead.
    /// `report #channel <msgid>... [<reason>] [<note>]`: the messages to
    /// the room's hub as abusive (bead mimid-i0id.7).
    ///
    /// The words after the ids are the reason, if the first parses as a
    /// number 0 to 255 (the protocol-07 §5.9 `AbuseType`; the draft
    /// defines no codes yet, decision mimid-1wgh.5.32), and the rest a
    /// note. A message that kept nothing cannot be reported, and says so.
    async fn report(&mut self, channel: &str, rest: &[String]) {
        let Some(room) = self.shown_room(channel) else {
            self.service_says(&format!("{channel}: no such channel here"));
            return;
        };
        // The ids come first; the first word that is not a known message
        // of this room begins the reason and note.
        let mut keys = Vec::new();
        let mut tail = rest;
        while let Some((word, more)) = tail.split_first() {
            match self.message_of_msgid(&room, word) {
                Some(key) => {
                    keys.push(key);
                    tail = more;
                }
                None => break,
            }
        }
        if keys.is_empty() {
            self.service_says(
                "give at least one message id of that channel (the msgid tag of its line)",
            );
            return;
        }
        let (reason, note) = match tail.split_first() {
            Some((first, more)) => match first.parse::<u8>() {
                Ok(code) => (code, more.join(" ")),
                Err(_) => (0, tail.join(" ")),
            },
            None => (0, String::new()),
        };

        let reason = mimid_agent_store::AbuseType(reason);
        match self.store().report(&keys, reason, &note).await {
            Ok(reported) => {
                self.service_says(&format!(
                    "reported {} message(s) to the room's hub: {reported:?}",
                    keys.len()
                ));
            }
            Err(error) => {
                self.service_says(&format!("report failed: {error}"));
                self.service_says(
                    "  a message you sent, or one stored before franks were kept,                      cannot be reported",
                );
            }
        }
    }

    /// `link #channel <msgid> [<n>]`: a link to the message's nth
    /// attachment, default the first (bead mimid-i0id.9).
    async fn attachment_link(&mut self, channel: &str, msgid: &str, index: Option<usize>) {
        let Some(room) = self.shown_room(channel) else {
            self.service_says(&format!("{channel}: no such channel here"));
            return;
        };
        let Some(key) = self.message_of_msgid(&room, msgid) else {
            self.service_says(&format!("{msgid} is no message of {channel}"));
            return;
        };
        let nth = index.unwrap_or(1).max(1);
        let attachment = {
            let state = self.shared.store.state();
            state
                .messages
                .get(&key)
                .and_then(|m| m.attachments.get(nth - 1).cloned())
        };
        let Some(attachment) = attachment else {
            self.service_says(&format!("that message has no attachment {nth}"));
            return;
        };
        match self.shared.store.attachment_link(
            &key,
            &attachment.blob_id,
            crate::service::LINK_LIFETIME,
        ) {
            Some(url) => {
                self.service_says(&format!("{}: {url}", attachment.file_name));
                self.service_says(
                    "  that link carries its own authority and expires;                      do not paste it into a room",
                );
            }
            // No links means no HTTP listener (`[jmap]` off and no
            // `listen`), which is a configuration, not a failure.
            None => self.service_says(
                "no attachment links: this agent serves no HTTP listener to hand them out",
            ),
        }
    }

    async fn burn(&mut self, channel: &str, text: &str) {
        let Some(key) = self.shown_room(channel) else {
            self.service_says(&format!("{channel}: no such channel here"));
            return;
        };
        if text.is_empty() {
            self.service_says("usage: burn #channel <text>");
            return;
        }
        let store = self.store();
        let message_key = store.new_key();
        let expiry = MessageExpiry {
            burn_on_read: true,
            ..MessageExpiry::default()
        };
        self.own_sends.insert(message_key.clone());
        match store
            .send_with(message_key.clone(), &key, text, &[], expiry)
            .await
        {
            Ok(_) => self.save().await,
            Err(error) => {
                self.own_sends.remove(&message_key);
                self.service_says(&format!("{channel}: not sent: {error}"));
            }
        }
    }
}

impl Session {
    /// `call #channel url [description]` (docs/design/agent-frontends.md
    /// §7.24): sends a call to join.
    async fn call(&mut self, channel: &str, url: &str, description: &str) {
        let Some(key) = self.shown_room(channel) else {
            self.service_says(&format!("{channel}: no such channel here"));
            return;
        };
        let store = self.store();
        let message_key = store.new_key();
        let call = Call {
            url: url.to_owned(),
            description: description.to_owned(),
            expires: None,
        };
        self.own_sends.insert(message_key.clone());
        match store
            .send_call(
                message_key.clone(),
                &key,
                "",
                &call,
                MessageExpiry::default(),
            )
            .await
        {
            Ok(_) => self.save().await,
            Err(error) => {
                self.own_sends.remove(&message_key);
                self.service_says(&format!("{channel}: not sent: {error}"));
            }
        }
    }
}

/// `text` after its first `n` words, the space after them left out.
fn after_words(text: &str, n: usize) -> &str {
    let mut rest = text.trim_start();
    for _ in 0..n {
        rest = rest
            .split_once(char::is_whitespace)
            .map_or("", |(_, tail)| tail)
            .trim_start();
    }
    rest
}

/// The largest duration `expire` takes: a year, as mimi-content-10 §9.1
/// bounds an expiry. INVENTED, NOT FROM SPEC: applying that bound to a
/// local policy.
const MAX_DURATION_SECS: u64 = mimid_agent_store::expiry::ONE_YEAR_SECS;

/// `off` or `0` as `None`; `<n>[s|m|h|d|w]` (seconds without a unit) as
/// seconds, up to [`MAX_DURATION_SECS`]; `None` inside for off, outer
/// `None` for anything else.
fn parse_duration(text: &str) -> Option<Option<u64>> {
    let text = text.to_ascii_lowercase();
    if text == "off" || text == "0" {
        return Some(None);
    }
    let (digits, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => text.split_at(i),
        None => (text.as_str(), "s"),
    };
    let unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    let seconds = digits.parse::<u64>().ok()?.checked_mul(unit)?;
    match seconds {
        0 => Some(None),
        s if s <= MAX_DURATION_SECS => Some(Some(s)),
        _ => None,
    }
}

/// `seconds` in the largest unit that divides it.
fn show_duration(seconds: u64) -> String {
    for (unit, name) in [(604_800, "w"), (86_400, "d"), (3600, "h"), (60, "m")] {
        if seconds.is_multiple_of(unit) {
            return format!("{}{name}", seconds / unit);
        }
    }
    format!("{seconds}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_description_is_the_rest_of_the_line() {
        assert_eq!(
            after_words(" call  #c\thttps://example.com/j  Join the  Foo ", 3),
            "Join the  Foo "
        );
        assert_eq!(after_words("call #c https://example.com/j", 3), "");
        assert_eq!(after_words("call", 3), "");
    }

    #[test]
    fn durations_parse_with_units_and_off() {
        assert_eq!(parse_duration("off"), Some(None));
        assert_eq!(parse_duration("OFF"), Some(None));
        assert_eq!(parse_duration("0"), Some(None));
        assert_eq!(parse_duration("0h"), Some(None));
        assert_eq!(parse_duration("90"), Some(Some(90)));
        assert_eq!(parse_duration("90s"), Some(Some(90)));
        assert_eq!(parse_duration("30m"), Some(Some(1_800)));
        assert_eq!(parse_duration("12h"), Some(Some(43_200)));
        assert_eq!(parse_duration("7d"), Some(Some(604_800)));
        assert_eq!(parse_duration("2W"), Some(Some(1_209_600)));
        assert_eq!(parse_duration("365d"), Some(Some(31_536_000)));
        for bad in [
            "",
            "m",
            "-5",
            "5x",
            "1.5h",
            "366d",
            "99999999999999999999w",
            "5 m",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
        assert_eq!(show_duration(90), "90s");
        assert_eq!(show_duration(1_800), "30m");
        assert_eq!(show_duration(1_209_600), "2w");
    }
}
