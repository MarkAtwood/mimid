//! Store records and changes as IRC lines (docs/design/agent-frontends.md
//! §4 "The mapping", §7).
//!
//! | Store | IRC |
//! |---|---|
//! | Active room | Channel: JOIN, 332 (the subject, the name and the room URI), 333 when the subject's setter and time are known (§7.14), 353/366 |
//! | Subject changed | TOPIC from the Commit's sender, or from the server if not known (§7.14) |
//! | Participants | NAMES, `@` for the role "admin"; banned users left out |
//! | Members changed | JOIN and PART of others; MODE +o/-o from the server |
//! | The user out of a room | PART from the user, with the reason the user gave on another connection of this daemon, else "no longer in this room" (§7.16) |
//! | Room deleted here | PART from the user, "deleted here" |
//! | Message | PRIVMSG from the sender's hostmask, `msgid` and `time`; `/me ` text as ACTION |
//! | Reply | `+draft/reply=<msgid>` of a stored message |
//! | Edit | PRIVMSG `(edited) <text>`, its own msgid, `+draft/reply` naming the first version |
//! | Retraction | NOTICE from the server: `<nick> retracted a message` |
//! | Notice of the agent's | NOTICE from the server, with the notice's text |
//! | Pending invite | `:<inviter> INVITE <nick> #<channel>`, the channel the room will have (§7.13); `&invite-<number>` if its Welcome could not be read |
//!
//! A front end is told of its own writes too: the user's own message comes
//! back from the feed, and is shown to the connection that sent it only
//! with echo-message, and from the user's own hostmask to every other.
//!
//! Text from peers is data: CR and LF split it into lines, NUL becomes
//! U+2400, and `\x01` U+2401, so that no peer can send CTCP.
//!
//! # Limitations
//!
//! - Messages stored before the connection registered are not shown, and
//!   neither are edits or retractions made before it (§7.6).
//! - A message whose text is empty (attachments only) is not shown (§7.4).
//! - A reply to a message not stored here carries no `+draft/reply`.

use std::collections::BTreeSet;
use std::sync::Arc;

use mimid_agent_store::Change;
use mimid_agent_store::record::{Invite, Key, Message, Reply, Room, RoomStatus, Sender};

use crate::conn::{ChannelView, Session, ShownMessage};
use crate::line::{Out, split_text};
use crate::names::Identity;

/// Milliseconds since the UNIX epoch, now.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// IRCv3 server-time's `time`: `YYYY-MM-DDThh:mm:ss.sssZ`.
pub(crate) fn server_time(ms: u64) -> String {
    let date = mimid_agent_store::convert::utc_date(ms);
    if date.contains('.') {
        date
    } else {
        date.replace('Z', ".000Z")
    }
}

/// A room's topic (§7.14): `subject | name | URI`, leaving out an empty
/// subject or name. Peer text is data, on one line.
pub(crate) fn topic_of(room: &Room) -> String {
    [room.subject.as_deref(), room.name.as_deref()]
        .into_iter()
        .flatten()
        .filter(|t| !t.trim().is_empty())
        .map(|t| data(t).replace(['\r', '\n'], " "))
        .chain(std::iter::once(room.uri.clone()))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// The members a room shows: its participants but the banned, each with
/// whether their role is "admin".
pub(crate) fn members_of(room: &Room) -> Vec<(String, bool)> {
    room.participants
        .iter()
        .filter_map(|p| {
            let role = p.role.and_then(|r| room.role_names.get(&r));
            (role.map(String::as_str) != Some("banned"))
                .then(|| (p.user.clone(), role.map(String::as_str) == Some("admin")))
        })
        .collect()
}

/// Peer text as data: NUL as U+2400, `\x01` as U+2401.
pub(crate) fn data(text: &str) -> String {
    text.replace('\0', "\u{2400}").replace('\x01', "\u{2401}")
}

/// A room as a connection shows it.
pub(crate) struct RoomShown {
    pub(crate) channel: String,
    pub(crate) topic: String,
    /// Who set the subject and when, in seconds, if both are known.
    pub(crate) topic_set: Option<(Identity, u64)>,
    pub(crate) members: Vec<(Identity, bool)>,
}

/// A message as a connection shows it.
struct MessageShown {
    record: Message,
    channel: String,
    /// The sender, `None` for the agent's notice.
    sender: Option<Identity>,
    /// The msgid of what it replies to, if stored.
    reply_to: Option<String>,
}

impl Session {
    /// Shows every room the user is in that is not shown yet, shows again
    /// those that are, and the pending invites: at registration, and after
    /// the feed's log no longer reached back.
    pub(crate) fn show_all(&mut self) {
        let mut keys: BTreeSet<Key> = self
            .shared
            .store
            .state()
            .rooms
            .values()
            .filter(|r| r.status == RoomStatus::Active)
            .map(|r| r.key.clone())
            .collect();
        keys.extend(self.channels.keys().cloned());
        for key in keys {
            self.show_room(&key);
        }
        self.show_invites();
    }

    /// Shows one change from the feed.
    pub(crate) fn apply(&mut self, change: &Change) {
        match change {
            Change::RoomAdded(key) | Change::RoomChanged(key) | Change::RoomLeft(key) => {
                self.show_room(key);
            }
            Change::RoomForgotten { key, .. } => {
                if let Some(view) = self.channels.remove(key) {
                    self.part_own(&view.name, "deleted here");
                }
            }
            Change::MessageAdded(key) => self.show_message(key),
            Change::MessageChanged(key) => self.show_change(key),
            // IRC cannot take a line back; the record is gone, so nothing
            // shows it again (docs/design/agent-frontends.md §7.20).
            Change::MessageExpired(key) | Change::MessageDeleted(key) => {
                self.shown.remove(key);
            }
            Change::InvitePending(_) => self.show_invites(),
            _ => {}
        }
    }

    /// Room `key` as this connection shows it, if the user is in it.
    pub(crate) fn room_shown(&self, key: &str) -> Option<RoomShown> {
        let mut state = self.shared.store.state();
        let room = state.rooms.get_mut(key)?;
        if room.status != RoomStatus::Active {
            return None;
        }
        let mut names = self.shared.names();
        names.note_room(room);
        let channel = names.channel(key)?.to_owned();
        let members = members_of(room)
            .into_iter()
            .map(|(uri, op)| (names.identity(&uri), op))
            .collect();
        let topic_set = room
            .subject_set
            .as_ref()
            .and_then(|set| Some((names.identity(set.by.as_deref()?), set.at / 1000)));
        Some(RoomShown {
            channel,
            topic: topic_of(room),
            topic_set,
            members,
        })
    }

    /// Brings what this connection shows of room `key` up to date: JOIN
    /// it, PART it, or the JOIN, PART and MODE lines of its members.
    pub(crate) fn show_room(&mut self, key: &str) {
        let Some(shown) = self.room_shown(key) else {
            if let Some(view) = self.channels.remove(key) {
                let reason = self.shared.part_reason(key);
                self.part_own(
                    &view.name,
                    reason.as_deref().unwrap_or("no longer in this room"),
                );
            }
            return;
        };
        let Some(view) = self.channels.get(key).cloned() else {
            self.join_burst(key, &shown);
            return;
        };
        let server = self.shared.server.clone();
        let channel = view.name.clone();
        let me = self.me();
        let mut members = view.members.clone();
        let now: Vec<(Identity, bool)> = shown.members;
        for (who, _) in &now {
            members.remove(&who.uri);
        }
        // Gone.
        for uri in members.keys() {
            if *uri == me.uri {
                continue;
            }
            let who = self.shared.names().identity(uri);
            let out = Out::new(
                &who.mask(),
                "PART",
                vec![channel.clone(), "no longer in this room".into()],
            );
            self.send(&out);
        }
        for (who, op) in &now {
            match view.members.get(&who.uri) {
                None => {
                    self.send(&Out::new(&who.mask(), "JOIN", vec![channel.clone()]));
                    if *op {
                        self.send(&Out::new(
                            &server,
                            "MODE",
                            vec![channel.clone(), "+o".into(), who.nick.clone()],
                        ));
                    }
                }
                Some(was) if was != op => {
                    let mode = if *op { "+o" } else { "-o" };
                    self.send(&Out::new(
                        &server,
                        "MODE",
                        vec![channel.clone(), mode.into(), who.nick.clone()],
                    ));
                }
                Some(_) => {}
            }
        }
        if view.topic != shown.topic {
            let source = shown
                .topic_set
                .as_ref()
                .map_or_else(|| server.clone(), |(who, _)| who.mask());
            self.send_cut(Out::new(
                &source,
                "TOPIC",
                vec![channel.clone(), shown.topic.clone()],
            ));
        }
        self.channels.insert(
            key.to_owned(),
            ChannelView {
                name: channel,
                topic: shown.topic,
                members: now.into_iter().map(|(w, op)| (w.uri, op)).collect(),
            },
        );
    }

    /// The JOIN of a channel: JOIN, 332, 333 if known, 353, 366
    /// (docs/irc-lessons.md "JOIN").
    fn join_burst(&mut self, key: &str, shown: &RoomShown) {
        let me = self.me();
        let channel = shown.channel.clone();
        // In the room again: a reason for leaving it before is spent.
        self.shared.set_part_reason(key, None);
        self.send(&Out::new(&me.mask(), "JOIN", vec![channel.clone()]));
        self.topic_reply(shown);
        let members: Vec<(String, bool)> = shown
            .members
            .iter()
            .map(|(w, op)| (w.nick.clone(), *op))
            .collect();
        self.names_reply(&channel, &members);
        self.channels.insert(
            key.to_owned(),
            ChannelView {
                name: channel,
                topic: shown.topic.clone(),
                members: shown
                    .members
                    .iter()
                    .map(|(w, op)| (w.uri.clone(), *op))
                    .collect(),
            },
        );
    }

    /// The topic of a channel (§7.14): 332, then 333 naming the subject's
    /// setter and the hub's time when both are known. Nothing else is
    /// honest: the agent knows no setter or time for a subject the room
    /// had when it joined, and a time from its own records would differ
    /// between members.
    pub(crate) fn topic_reply(&mut self, shown: &RoomShown) {
        self.numeric_cut("332", &[&shown.channel, &shown.topic]);
        if let Some((who, at)) = &shown.topic_set {
            self.numeric("333", &[&shown.channel, &who.mask(), &at.to_string()]);
        }
    }

    /// 353 lines within the line limit, then 366.
    pub(crate) fn names_reply(&mut self, channel: &str, members: &[(String, bool)]) {
        let words: Vec<String> = members
            .iter()
            .map(|(nick, op)| {
                if *op {
                    format!("@{nick}")
                } else {
                    nick.clone()
                }
            })
            .collect();
        let probe = Out::new(
            &self.shared.server,
            "353",
            vec![self.target(), "=".into(), channel.to_owned(), String::new()],
        );
        let room = probe.room_for_trailing(self.caps.message_tags);
        for list in crate::line::pack_words(&words, room) {
            self.numeric("353", &["=", channel, &list]);
        }
        self.numeric("366", &[channel, "End of /NAMES list"]);
    }

    /// PART of `channel` from the user's own hostmask.
    pub(crate) fn part_own(&mut self, channel: &str, reason: &str) {
        let me = self.me();
        self.send(&Out::new(
            &me.mask(),
            "PART",
            vec![channel.to_owned(), reason.to_owned()],
        ));
    }

    /// Message `key` with what showing it needs, if its room is shown.
    fn message_shown(&self, key: &str) -> Option<MessageShown> {
        let state = self.shared.store.state();
        let record = state.messages.get(key)?.clone();
        let channel = self.channels.get(&record.room)?.name.clone();
        let reply_to = match &record.in_reply_to {
            Some(Reply::Message(target)) => {
                state.messages.get(target).map(|m| m.sender_msg_id.clone())
            }
            _ => None,
        };
        drop(state);
        let sender = match &record.sender {
            Sender::User(uri) => Some(self.shared.names().identity(uri)),
            _ => None,
        };
        Some(MessageShown {
            record,
            channel,
            sender,
            reply_to,
        })
    }

    /// Shows a message stored now.
    fn show_message(&mut self, key: &str) {
        let own_send = self.own_sends.remove(key);
        if self.shown.contains_key(key) {
            return;
        }
        let Some(m) = self.message_shown(key) else {
            return;
        };
        self.shown.insert(
            key.to_owned(),
            ShownMessage {
                edited_at: m.record.edited_at,
                retracted: m.record.deleted.is_some(),
            },
        );
        if m.record.deleted.is_some() || (own_send && !self.caps.echo_message) {
            return;
        }
        let mut tags = vec![("msgid".to_owned(), m.record.sender_msg_id.clone())];
        if let Some(reply) = &m.reply_to {
            tags.push(("+draft/reply".to_owned(), reply.clone()));
        }
        let time = m.record.accepted_at;
        if m.record.expiry.counts_from_read() {
            self.delivered.push(key.to_owned());
        }
        match &m.sender {
            Some(sender) => {
                self.text_lines(
                    &sender.mask(),
                    "PRIVMSG",
                    &m.channel,
                    &m.record.body,
                    "",
                    tags,
                    time,
                );
            }
            None => {
                let server = self.shared.server.clone();
                self.text_lines(
                    &server,
                    "NOTICE",
                    &m.channel,
                    &m.record.body,
                    "",
                    tags,
                    time,
                );
            }
        }
    }

    /// Shows a message changed now: an edit or a retraction made since
    /// this connection last showed it, or since it registered.
    fn show_change(&mut self, key: &str) {
        let Some(m) = self.message_shown(key) else {
            return;
        };
        let since = self.shown.get(key).copied();
        let mut seen = since.unwrap_or_default();
        let after = |at: u64| at >= self.connected_at;
        if let Some(deleted) = m.record.deleted {
            if deleted.for_all && !seen.retracted && (since.is_some() || after(deleted.at)) {
                let nick = m.sender.as_ref().map_or("mimid", |s| s.nick.as_str());
                let server = self.shared.server.clone();
                let out = Out::new(
                    &server,
                    "NOTICE",
                    vec![m.channel.clone(), format!("{nick} retracted a message")],
                )
                .tag("+draft/reply", &m.record.sender_msg_id);
                self.send(&out);
            }
            seen.retracted = true;
        } else if let Some(edited_at) = m.record.edited_at
            && seen.edited_at.is_none_or(|was| edited_at > was)
            && (since.is_some() || after(edited_at))
        {
            seen.edited_at = Some(edited_at);
            let msgid = m
                .record
                .aliases
                .last()
                .map(|alias| {
                    let mut random = [0u8; 16];
                    random[6..].copy_from_slice(&alias.0);
                    ulid::Ulid::from_parts(edited_at, u128::from_be_bytes(random)).to_string()
                })
                .unwrap_or_else(|| m.record.sender_msg_id.clone());
            let tags = vec![
                ("msgid".to_owned(), msgid),
                ("+draft/reply".to_owned(), m.record.sender_msg_id.clone()),
            ];
            let source = match &m.sender {
                Some(sender) => sender.mask(),
                None => self.shared.server.clone(),
            };
            self.text_lines(
                &source,
                "PRIVMSG",
                &m.channel,
                &m.record.body,
                "(edited) ",
                tags,
                edited_at,
            );
        }
        self.shown.insert(key.to_owned(), seen);
    }

    /// `body` as `command` lines from `source` to `channel`, split on line
    /// breaks and to fit the line limit, `prefix` before the first. Only
    /// the first line carries `tags`; every line carries `time` with
    /// server-time.
    #[allow(clippy::too_many_arguments)]
    fn text_lines(
        &mut self,
        source: &str,
        command: &str,
        channel: &str,
        body: &str,
        prefix: &str,
        tags: Vec<(String, String)>,
        time: u64,
    ) {
        let text = data(body);
        let lines: Vec<&str> = text
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .flat_map(|l| l.split('\r'))
            .filter(|l| !l.is_empty())
            .collect();
        let time = self.caps.server_time.then(|| server_time(time));
        let mut first = true;
        for (i, line) in lines.iter().enumerate() {
            let (action, line) = match line.strip_prefix("/me ") {
                Some(rest) if i == 0 && command == "PRIVMSG" => (true, rest),
                _ => (false, *line),
            };
            let content = if i == 0 {
                format!("{prefix}{line}")
            } else {
                (*line).to_owned()
            };
            let mut probe = Out::new(source, command, vec![channel.to_owned(), String::new()]);
            probe.tags.clone_from(&tags);
            if let Some(time) = &time {
                probe.tags.push(("time".to_owned(), time.clone()));
            }
            let mut room = probe.room_for_trailing(self.caps.message_tags);
            if action {
                room = room.saturating_sub("\x01ACTION \x01".len());
            }
            for piece in split_text(&content, room) {
                let text = if action {
                    format!("\x01ACTION {piece}\x01")
                } else {
                    piece.to_owned()
                };
                let mut out = Out::new(source, command, vec![channel.to_owned(), text]);
                if first {
                    out.tags.clone_from(&tags);
                }
                if let Some(time) = &time {
                    out.tags.push(("time".to_owned(), time.clone()));
                }
                self.send(&out);
                first = false;
            }
        }
    }

    /// Shows the pending invites not shown yet as INVITE lines to the
    /// channel name each room will have, or to `&invite-<number>` if its
    /// Welcome could not be read (§7.13).
    pub(crate) fn show_invites(&mut self) {
        let invites: Vec<Invite> = self
            .shared
            .store
            .state()
            .invites
            .iter()
            .filter(|i| !self.invites_shown.contains(&i.number))
            .cloned()
            .collect();
        let me = self.me();
        for invite in invites {
            self.invites_shown.insert(invite.number);
            let (source, channel) = {
                let mut names = self.shared.names();
                let source = match &invite.inviter {
                    Some(uri) => names.identity(uri).mask(),
                    None => self.shared.server.clone(),
                };
                (source, names.invite_channel(&invite))
            };
            self.send(&Out::new(&source, "INVITE", vec![me.nick.clone(), channel]));
        }
    }

    /// The store, for the commands.
    pub(crate) fn store(&self) -> Arc<mimid_agent_store::Store> {
        Arc::clone(&self.shared.store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_time_always_has_milliseconds() {
        assert_eq!(server_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(server_time(1_500), "1970-01-01T00:00:01.500Z");
    }

    /// Oracle: §4 "Text from peers is data": a peer cannot send CTCP.
    #[test]
    fn peer_text_cannot_carry_ctcp_or_nul() {
        assert_eq!(data("\x01DCC SEND x\x01"), "\u{2401}DCC SEND x\u{2401}");
        assert_eq!(data("a\0b"), "a\u{2400}b");
        assert_eq!(data("\x02bold\x02"), "\x02bold\x02");
    }

    #[test]
    fn banned_participants_are_not_members() {
        let room: Room = serde_json::from_value(serde_json::json!({
            "key": "R", "uri": "mimi://a.example/r/x", "status": "active",
            "participants": [
                {"user": "mimi://a.example/u/a", "role": 1},
                {"user": "mimi://a.example/u/b", "role": 2},
                {"user": "mimi://a.example/u/c", "role": 0},
                {"user": "mimi://a.example/u/d"},
            ],
            "roleNames": {"0": "banned", "1": "admin", "2": "member"},
        }))
        .unwrap();
        assert_eq!(
            members_of(&room),
            [
                ("mimi://a.example/u/a".to_owned(), true),
                ("mimi://a.example/u/b".to_owned(), false),
                ("mimi://a.example/u/d".to_owned(), false),
            ]
        );
        assert_eq!(topic_of(&room), "mimi://a.example/r/x");
    }

    /// Oracle: §7.14: `subject | name | URI`, an empty or absent part left
    /// out, peer text on one line and without CTCP.
    #[test]
    fn topic_is_subject_name_and_uri() {
        let room = |subject: Option<&str>, name: Option<&str>| -> Room {
            serde_json::from_value(serde_json::json!({
                "key": "R", "uri": "mimi://a.example/r/x", "status": "active",
                "name": name, "subject": subject,
            }))
            .unwrap()
        };
        let uri = "mimi://a.example/r/x";
        assert_eq!(
            topic_of(&room(Some("plans"), Some("lobby"))),
            format!("plans | lobby | {uri}")
        );
        assert_eq!(
            topic_of(&room(Some(""), Some("lobby"))),
            format!("lobby | {uri}")
        );
        assert_eq!(
            topic_of(&room(Some("plans"), None)),
            format!("plans | {uri}")
        );
        assert_eq!(topic_of(&room(Some(" "), Some(""))), uri);
        assert_eq!(
            topic_of(&room(Some("a\r\nb\x01"), Some("lobby"))),
            format!("a  b\u{2401} | lobby | {uri}")
        );
    }
}
