//! The v1 commands of a registered client (docs/design/agent-frontends.md
//! §4 "Commands in v1", §7; docs/irc-lessons.md "Must do").
//!
//! A write is a store method ([`mimid_agent_store::action`]); the
//! connection then saves, and shows the result when the change comes back
//! from the feed, as every other connection does. A refused write is told
//! as a numeric where IRC has one, else as a server NOTICE.
//!
//! - `JOIN #name`: a room the user is in is shown; the name a pending
//!   invite is shown under accepts it (§7.13); any other name hosts a new
//!   room named `name` (§7.1). `JOIN &invite-<n>` accepts pending invite
//!   `n` (§7.5) and is answered with JOIN and PART of `&invite-<n>`, so
//!   the client closes that window, before the room's own JOIN. `JOIN 0`
//!   leaves every room shown, each as `PART` does (§7.12).
//! - `PART #c [reason]`: leaves the room for good (§7.1). The reason is
//!   shown to the user's other IRC connections of this daemon only: MIMI
//!   carries no reason for a leave, so other members see "no longer in
//!   this room" (§7.16). `PART <nick>` closes the private query with that
//!   user: hidden until the next message (bead mimid-2vcw, option B).
//! - `PRIVMSG #c`: sends the text; `/me` as ACTION text; with a
//!   `+draft/reply` tag naming a message of the room, as a reply to it. To
//!   a nick, a user URI or `user@domain`: the same into the one-to-one room
//!   with that user, opened if there is none (client-survey.md §10 S2); to
//!   [`crate::names::SERVICE_NICK`]: the service ([`crate::service`]).
//! - `TAGMSG #c` (or to the nick of a query) with `+draft/react` or `+draft/unreact` and
//!   `+draft/reply` reacts to a message or takes the reaction back
//!   (§7.27); any other TAGMSG is dropped.
//! - `NOTICE` is never answered with an error (docs/irc-lessons.md
//!   "NOTICE"); to a channel it is sent as a plain message.
//! - `MODE #c` and `MODE #c b|e|I` are queries, answered 324 (no 329,
//!   §7.15), 367/368, 349, 347, never 482. `+o`, `-o`, `+b`, `-b` change roles and
//!   bans; a ban mask must be `nick` or `nick!*@*`.
//! - `TOPIC #c` reads (332, and 333 when the setter is known; §7.14).
//!   `TOPIC #c :text` sets the room's subject (`Store::set_subject`); the
//!   TOPIC line comes with the room's change. A role without
//!   room-policy-04 `canChangeRoomSubject` gets 482, any other failure a
//!   NOTICE saying why.
//! - `KICK`, `INVITE` (nick, user URI or `user@domain`, §7.15), `NAMES`,
//!   `LIST`, `WHO` (always ends 315), `WHOIS` (always ends 318, 330 giving
//!   the user URI as the account), `ISON`, `USERHOST`,
//!   `AWAY` (305, 306), `MOTD` (422), `PING`, `PONG`, `QUIT`, `CAP`; every
//!   other command is 421.

use mimid_agent_store::action::{MemberChanges, Role, SendOptions};
use mimid_agent_store::convert::MessageRef;
use mimid_agent_store::record::Key;

use crate::conn::{Session, VERSION, one_line};
use crate::line::{Line, Out};
use crate::names::{Held, SERVICE_NICK, fold, is_channel_name, parse_user_address, parse_user_uri};

/// Whether CTCP `ctcp` (without its `\x01`s) is an ACTION.
fn is_action(ctcp: &str) -> bool {
    ctcp.split_once(' ')
        .is_some_and(|(verb, _)| verb.eq_ignore_ascii_case("ACTION"))
}

/// Whom a nick or user URI names.
pub(crate) enum Who {
    /// A user, by URI.
    User(String),
    /// The service.
    Service,
    /// Not a nick given here, nor a user URI.
    Unknown,
}

impl Session {
    /// The user `name` names: a nick given here, or a user URI.
    pub(crate) fn who(&self, name: &str) -> Who {
        if parse_user_uri(name).is_some() {
            return Who::User(name.to_owned());
        }
        match self.shared.names().user_of(name) {
            Some("") => Who::Service,
            Some(uri) => Who::User(uri.to_owned()),
            None => Who::Unknown,
        }
    }

    /// The user `name` names where a user may be named who has no nick
    /// yet (INVITE, the service's `allow` and `deny`; §7.15): as
    /// [`Session::who`], or `user@domain` for `mimi://domain/u/user`.
    pub(crate) fn who_or_address(&self, name: &str) -> Who {
        match parse_user_address(name) {
            Some(uri) => Who::User(uri),
            None => self.who(name),
        }
    }

    /// The key of the message of room `room` shown under `msgid`: its
    /// `senderMsgId` or that of a later version.
    pub(crate) fn message_of_msgid(&self, room: &str, msgid: &str) -> Option<Key> {
        let reference = mimid_agent_store::reference_of(msgid)?;
        self.shared
            .store
            .state()
            .message_of_ref(room, &reference)
            .cloned()
    }

    /// The version of message `key` a reply or reaction from this
    /// connection names, by its reference octets: the latest version this
    /// connection showed (docs/design/agent-frontends.md §7.26), else the
    /// one `msgid` names. The store takes octets that name no version of
    /// the message as its latest version.
    pub(crate) fn version_shown(&self, key: &str, msgid: &str) -> Option<MessageRef> {
        self.shown
            .get(key)
            .and_then(|shown| shown.version)
            .or_else(|| mimid_agent_store::reference_of(msgid))
    }

    /// The room key of `channel`, if this connection shows it.
    pub(crate) fn shown_room(&self, channel: &str) -> Option<Key> {
        let folded = fold(channel);
        self.channels
            .iter()
            .find(|(_, v)| fold(&v.name) == folded)
            .map(|(k, _)| k.clone())
    }

    /// The room `target` names: a channel this connection shows, or the
    /// one-to-one room with the user a nick, user URI or `user@domain`
    /// names, if there is one (a private query).
    pub(crate) fn target_room(&self, target: &str) -> Option<Key> {
        if target.starts_with(['#', '&']) {
            return self.shown_room(target);
        }
        match self.who_or_address(target) {
            Who::User(uri) => self.shared.store.direct_room(&uri),
            _ => None,
        }
    }

    /// A command of a registered client.
    pub(crate) async fn command(&mut self, line: &Line) {
        match line.verb().as_str() {
            "CAP" => self.cap(line),
            "PING" => self.ping(line),
            "PONG" => {}
            "PASS" | "USER" => self.numeric("462", &["You may not reregister"]),
            "NICK" => {
                let me = self.me();
                if let Some(nick) = line.param(0)
                    && nick != me.nick
                {
                    self.numeric("432", &[nick, "Nicks are given by mimid: yours is fixed"]);
                }
            }
            "QUIT" => {
                let why = line.param(0).unwrap_or("Client quit");
                self.close(&format!("Quit: {why}"));
            }
            "JOIN" => self.join(line).await,
            "PART" => self.part(line).await,
            "PRIVMSG" => self.privmsg(line, false).await,
            "NOTICE" => self.privmsg(line, true).await,
            "TAGMSG" => self.tagmsg(line).await,
            "MODE" => self.mode(line).await,
            "TOPIC" => self.topic(line).await,
            "NAMES" => self.names(line),
            "LIST" => self.list(),
            "WHO" => self.who_cmd(line),
            "WHOIS" => self.whois(line),
            "ISON" => self.ison(line),
            "USERHOST" => self.userhost(line),
            "AWAY" => {
                if line.param(0).is_some_and(|m| !m.is_empty()) {
                    self.numeric("306", &["You have been marked as being away"]);
                } else {
                    self.numeric("305", &["You are no longer marked as being away"]);
                }
            }
            "MOTD" => self.numeric("422", &["MOTD File is missing"]),
            "KICK" => self.kick(line).await,
            "INVITE" => self.invite(line).await,
            other => self.numeric("421", &[other, "Unknown command"]),
        }
    }

    async fn join(&mut self, line: &Line) {
        let Some(targets) = line.param(0) else {
            self.numeric("461", &["JOIN", "Not enough parameters"]);
            return;
        };
        if targets == "0" {
            // §7.12: leave every room this connection shows, each as PART
            // does (§7.1).
            let keys: Vec<Key> = self.channels.keys().cloned().collect();
            for key in keys {
                self.part_room(&key, "left every room").await;
            }
            return;
        }
        for target in targets.split(',').filter(|t| !t.is_empty()) {
            self.join_one(target).await;
        }
    }

    async fn join_one(&mut self, target: &str) {
        if let Some(number) = target.strip_prefix("&invite-") {
            let Ok(number) = number.parse::<u64>() else {
                self.numeric("403", &[target, "No such invite"]);
                return;
            };
            if self.accept(number, target).await {
                // irssi keeps a window for every JOIN it sent until the
                // server answers it under the same name; without this the
                // user types into a dead `&invite-<n>` (§7.13;
                // docs/irc-lessons.md "Answer a JOIN under the name it
                // asked for").
                let me = self.me();
                self.send(&Out::new(&me.mask(), "JOIN", vec![target.to_owned()]));
                self.part_own(target, "accepted");
            }
            return;
        }
        if self.shown_room(target).is_some() {
            return;
        }
        let known = self.shared.names().room_of(target).cloned();
        if let Some(key) = known {
            // Shown by another connection's change before this one's.
            self.show_room(&key);
            return;
        }
        // §7.13: the name of a pending invite accepts it, rather than
        // hosting a new room (§7.1); the room's JOIN follows when it
        // arrives.
        let held = self.shared.names().held(target);
        match held {
            Some(Held::Invite(number)) => {
                self.accept(number, target).await;
                return;
            }
            Some(Held::Joining) => return,
            None => {}
        }
        if !is_channel_name(target) {
            self.numeric(
                "403",
                &[
                    target,
                    "No such channel: a new channel's name is # and letters, digits, '_', '.' and '-'",
                ],
            );
            return;
        }
        // §7.1: JOIN of a name that is not one of the user's rooms hosts a
        // new room with that name.
        let store = self.store();
        let name = &target[1..];
        match store.create_room(store.new_key(), name, &[]).await {
            Ok(_) => self.save().await,
            Err(error) => {
                self.numeric(
                    "403",
                    &[target, &one_line(&format!("Cannot host the room: {error}"))],
                );
            }
        }
    }

    /// Accepts pending invite `number`, which the user sent JOIN for as
    /// `target`; whether it was accepted. The room's JOIN comes when the
    /// room arrives, under the name the invite held, if any (§7.13).
    async fn accept(&mut self, number: u64, target: &str) -> bool {
        self.shared.names().accepting(number, true);
        let room = self
            .shared
            .store
            .state()
            .invites
            .iter()
            .find(|i| i.number == number)
            .and_then(|i| i.room.clone());
        if let Some(room) = room
            && !target.starts_with("&invite-")
        {
            self.accepted_names.insert(room, target.to_owned());
        }
        let store = self.store();
        match store.accept_invite(number).await {
            Ok(uri) => {
                self.server_notice(&format!(
                    "mimid: joining {uri}; its channel follows once the room arrives"
                ));
                self.save().await;
                true
            }
            Err(error) => {
                self.shared.names().accepting(number, false);
                self.numeric(
                    "403",
                    &[target, &one_line(&format!("No such invite: {error}"))],
                );
                false
            }
        }
    }

    async fn part(&mut self, line: &Line) {
        let Some(targets) = line.param(0) else {
            self.numeric("461", &["PART", "Not enough parameters"]);
            return;
        };
        let reason = line.param(1).unwrap_or("left the room").to_owned();
        for target in targets.split(',').filter(|t| !t.is_empty()) {
            if !target.starts_with(['#', '&']) {
                self.close_query(target).await;
                continue;
            }
            let Some(key) = self.shown_room(target) else {
                self.numeric("442", &[target, "You're not on that channel"]);
                continue;
            };
            self.part_room(&key, &reason).await;
        }
    }

    /// `PART <nick>`: closes the private query with that user (bead
    /// mimid-2vcw, option B; docs/design/agent-frontends.md §7.32). A
    /// one-to-one room cannot be left (room-policy-04 §5), so it is only
    /// hidden here: chathistory `TARGETS` leaves it out until a message
    /// newer than the close, and the user's devices stay in it. The
    /// next message, either way, opens it again. Answered with a server
    /// NOTICE.
    async fn close_query(&mut self, target: &str) {
        let Some(key) = self.target_room(target) else {
            self.server_notice(&format!("mimid: there is no private query with {target}"));
            return;
        };
        let at = crate::render::now_ms();
        {
            let mut state = self.shared.store.state();
            if let Some(room) = state.rooms.get_mut(&key) {
                crate::names::set_hidden_at(room, at);
            }
        }
        self.save().await;
        self.server_notice(&format!(
            "mimid: the query with {target} is closed here; their next message opens it again"
        ));
    }

    /// Leaves room `key`, shown by this connection, for good (§7.1): PART
    /// from the user's own hostmask with `reason`, or a NOTICE if leaving
    /// fails.
    async fn part_room(&mut self, key: &str, reason: &str) {
        let store = self.store();
        // Before the leave, so that the other connections have it when
        // the change reaches them.
        self.shared.set_part_reason(key, Some(reason));
        match store.leave(key).await {
            Ok(()) => {
                if let Some(view) = self.channels.remove(key) {
                    self.part_own(&view.name, reason);
                }
                self.save().await;
            }
            Err(error) => {
                self.shared.set_part_reason(key, None);
                let channel = self
                    .channels
                    .get(key)
                    .map_or_else(|| key.to_owned(), |view| view.name.clone());
                self.server_notice(&format!("mimid: leaving {channel} failed: {error}"));
            }
        }
    }

    async fn privmsg(&mut self, line: &Line, notice: bool) {
        let (Some(target), Some(text)) = (line.param(0), line.param(1)) else {
            if !notice {
                if line.params.is_empty() {
                    self.numeric("411", &["No recipient given (PRIVMSG)"]);
                } else {
                    self.numeric("412", &["No text to send"]);
                }
            }
            return;
        };
        if text.is_empty() {
            if !notice {
                self.numeric("412", &["No text to send"]);
            }
            return;
        }
        if target.contains(',') {
            if !notice {
                self.numeric(
                    "407",
                    &[target, "Too many recipients: one target per message"],
                );
            }
            return;
        }
        let ctcp = text
            .strip_prefix('\x01')
            .map(|t| t.strip_suffix('\x01').unwrap_or(t));
        let room = if target.starts_with(['#', '&']) {
            let Some(key) = self.shown_room(target) else {
                if !notice {
                    self.numeric("403", &[target, "No such channel"]);
                }
                return;
            };
            Some(key)
        } else {
            None
        };
        // A private query (docs/design/client-survey.md §10 S2): the
        // one-to-one room with the user, opened if there is none.
        let room = match (room, self.who_or_address(target)) {
            (Some(key), _) => key,
            (None, Who::User(uri)) if ctcp.is_none_or(is_action) => {
                match self.direct_for(&uri).await {
                    Ok(key) => key,
                    Err(error) => {
                        if !notice {
                            self.numeric(
                                "404",
                                &[target, &one_line(&format!("Cannot send: {error}"))],
                            );
                        }
                        return;
                    }
                }
            }
            (None, Who::Service) => {
                if notice {
                    return;
                }
                match ctcp {
                    Some(ctcp) if ctcp.eq_ignore_ascii_case("VERSION") => {
                        let me = self.me();
                        let out = Out::new(
                            &format!("{SERVICE_NICK}!{SERVICE_NICK}@{}", self.shared.server),
                            "NOTICE",
                            vec![me.nick, format!("\x01VERSION {VERSION}\x01")],
                        );
                        self.send(&out);
                    }
                    Some(_) => {}
                    None => self.service(text).await,
                }
                return;
            }
            // Other CTCP to a user never reaches them (§4 "CTCP from the
            // user").
            (None, Who::User(_)) => return,
            (None, Who::Unknown) => {
                if !notice {
                    self.numeric("401", &[target, "No such nick/channel"]);
                }
                return;
            }
        };
        let key = room;
        let text = match ctcp {
            None => text.to_owned(),
            Some(ctcp) => match ctcp.split_once(' ') {
                Some((verb, rest)) if verb.eq_ignore_ascii_case("ACTION") && !notice => {
                    format!("/me {rest}")
                }
                // Other CTCP never reaches a peer (§4 "CTCP from the
                // user").
                _ => return,
            },
        };
        let store = self.store();
        let message_key = store.new_key();
        self.own_sends.insert(message_key.clone());
        let mut options = SendOptions::new();
        // +draft/reply names the msgid (senderMsgId) of a message of
        // this room; one not stored here is sent as a plain message.
        if let Some(msgid) = line.tag("+draft/reply")
            && let Some(target) = self.message_of_msgid(&key, msgid)
        {
            options.in_reply_to_version = self.version_shown(&target, msgid);
            options.in_reply_to = Some(target);
        }
        match store
            .send_message(message_key.clone(), &key, &text, &[], &options)
            .await
        {
            Ok(_) => self.save().await,
            Err(error) => {
                self.own_sends.remove(&message_key);
                if !notice {
                    self.numeric(
                        "404",
                        &[target, &one_line(&format!("Cannot send: {error}"))],
                    );
                }
            }
        }
    }

    /// The one-to-one room with `user` (a private query): the one there
    /// is ([`mimid_agent_store::Store::direct_room`]), or a new one
    /// ([`mimid_agent_store::Store::open_direct`]: their consent applies
    /// as to any invite). A query this user closed is open again once
    /// this message is stored (bead mimid-2vcw, option B).
    async fn direct_for(
        &mut self,
        user: &str,
    ) -> Result<Key, mimid_agent_store::action::ActionError> {
        let store = self.store();
        if let Some(key) = store.direct_room(user) {
            return Ok(key);
        }
        let (room, _new) = store.open_direct(store.new_key(), user).await?;
        self.save().await;
        Ok(room.key)
    }

    /// TAGMSG to a channel (§7.27): `+draft/react` with `+draft/reply`
    /// naming a message of the room reacts to it; `+draft/unreact` takes
    /// back the user's reaction of that text to it. Anything else is
    /// read and dropped; a refusal is a server NOTICE.
    async fn tagmsg(&mut self, line: &Line) {
        let Some(target) = line.param(0) else {
            return;
        };
        let Some(room) = self.target_room(target) else {
            return;
        };
        let (react, unreact) = (line.tag("+draft/react"), line.tag("+draft/unreact"));
        let Some(msgid) = line.tag("+draft/reply") else {
            return;
        };
        let Some(message) = self.message_of_msgid(&room, msgid) else {
            return;
        };
        let version = self.version_shown(&message, msgid);
        let store = self.store();
        let result = if let Some(reaction) = react {
            let key = store.new_key();
            self.own_sends.insert(key.clone());
            let result = store
                .react(key.clone(), &message, version.as_ref(), reaction)
                .await;
            if result.is_err() {
                self.own_sends.remove(&key);
            }
            result.map(|_| ())
        } else if let Some(reaction) = unreact {
            let me = self.me();
            let own = store.state().messages.get(&message).and_then(|m| {
                m.reactions
                    .iter()
                    .find(|r| r.sender == me.uri && r.reaction == reaction)
                    .map(|r| r.key.clone())
            });
            match own {
                Some(key) => store.unreact(&message, &key).await.map(|_| ()),
                None => return,
            }
        } else {
            return;
        };
        match result {
            Ok(()) => self.save().await,
            Err(error) => {
                let text = one_line(&format!("Reaction not sent: {error}"));
                let server = self.shared.server.clone();
                self.send(&Out::new(&server, "NOTICE", vec![target.to_owned(), text]));
            }
        }
    }

    async fn mode(&mut self, line: &Line) {
        let Some(target) = line.param(0) else {
            self.numeric("461", &["MODE", "Not enough parameters"]);
            return;
        };
        if !target.starts_with(['#', '&']) {
            let me = self.me();
            if fold(target) != fold(&me.nick) {
                self.numeric("502", &["Can't change mode for other users"]);
            } else if line.param(1).is_none() {
                self.numeric("221", &["+i"]);
            }
            return;
        }
        let Some(key) = self.shown_room(target) else {
            self.numeric("403", &[target, "No such channel"]);
            return;
        };
        let channel = self.channels[&key].name.clone();
        let Some(modes) = line.param(1) else {
            // No 329: the agent knows no creation time that every member
            // would agree on (§7.15).
            self.numeric("324", &[&channel, "+nt"]);
            return;
        };
        let mut args = line.params[2..].iter();
        let mut sign = None;
        for mode in modes.chars() {
            match mode {
                '+' => sign = Some(true),
                '-' => sign = Some(false),
                'b' | 'e' | 'I' => match args.next() {
                    None => self.list_query(&key, &channel, mode),
                    Some(mask) if mode == 'b' => {
                        self.ban_mode(&key, &channel, sign.unwrap_or(true), mask)
                            .await;
                    }
                    Some(_) => self.server_notice(&format!(
                        "mimid: {channel} keeps no exception or invite lists"
                    )),
                },
                'o' => match args.next() {
                    Some(nick) => {
                        self.op_mode(&key, &channel, sign.unwrap_or(true), nick)
                            .await
                    }
                    None => self.numeric("461", &["MODE", "Not enough parameters"]),
                },
                'n' | 't' => self.server_notice(&format!(
                    "mimid: {channel} is always +nt: only members send, and the room policy says who sets the topic"
                )),
                other => {
                    let other = other.to_string();
                    self.numeric("472", &[&other, "is an unknown mode char to me"]);
                }
            }
        }
    }

    /// `MODE #c b`, `e` or `I` with no argument: the lists.
    fn list_query(&mut self, key: &str, channel: &str, mode: char) {
        match mode {
            'b' => {
                let bans: Vec<String> = self
                    .shared
                    .store
                    .state()
                    .bans
                    .values()
                    .filter(|b| b.room == key)
                    .map(|b| b.user.clone())
                    .collect();
                for user in bans {
                    let who = self.shared.names().identity(&user);
                    let mask = format!("{}!*@{}", who.nick, who.host);
                    self.numeric("367", &[channel, &mask]);
                }
                self.numeric("368", &[channel, "End of channel ban list"]);
            }
            'e' => self.numeric("349", &[channel, "End of channel exception list"]),
            _ => self.numeric("347", &[channel, "End of channel invite list"]),
        }
    }

    async fn ban_mode(&mut self, key: &str, channel: &str, add: bool, mask: &str) {
        let nick = mask.strip_suffix("!*@*").unwrap_or(mask);
        let user = match (nick.contains(['!', '@', '*', '?']), self.who(nick)) {
            (false, Who::User(uri)) => uri,
            _ => {
                self.server_notice(&format!(
                    "mimid: a ban mask is nick or nick!*@*; {mask} was not changed"
                ));
                return;
            }
        };
        let store = self.store();
        let result = if add {
            store
                .ban(store.new_key(), key, &user, None, None)
                .await
                .map(|_| ())
        } else {
            let ban = store
                .state()
                .bans
                .values()
                .find(|b| b.room == key && b.user == user)
                .map(|b| b.key.clone());
            match ban {
                Some(ban) => store.unban(&ban).await.map(|_| ()),
                None => {
                    self.server_notice(&format!("mimid: {nick} is not banned in {channel}"));
                    return;
                }
            }
        };
        match result {
            Ok(()) => {
                let server = self.shared.server.clone();
                let mode = if add { "+b" } else { "-b" };
                self.send(&Out::new(
                    &server,
                    "MODE",
                    vec![channel.to_owned(), mode.into(), mask.to_owned()],
                ));
                self.save().await;
            }
            Err(error) => self.server_notice(&format!("mimid: {mask} in {channel}: {error}")),
        }
    }

    async fn op_mode(&mut self, key: &str, channel: &str, add: bool, nick: &str) {
        let Who::User(user) = self.who(nick) else {
            self.numeric("401", &[nick, "No such nick/channel"]);
            return;
        };
        let mut changes = MemberChanges::new();
        changes
            .roles
            .push((user, if add { Role::Admin } else { Role::Member }));
        let store = self.store();
        match store.change_members(key, &changes).await {
            // The MODE line comes with the room's change.
            Ok(()) => self.save().await,
            Err(error) => self.server_notice(&format!("mimid: {nick} in {channel}: {error}")),
        }
    }

    async fn topic(&mut self, line: &Line) {
        let Some(target) = line.param(0) else {
            self.numeric("461", &["TOPIC", "Not enough parameters"]);
            return;
        };
        let Some(key) = self.shown_room(target) else {
            self.numeric("403", &[target, "No such channel"]);
            return;
        };
        let channel = self.channels[&key].name.clone();
        let Some(subject) = line.param(1) else {
            match self.room_shown(&key) {
                Some(shown) => self.topic_reply(&shown),
                None => self.numeric("331", &[&channel, "No topic is set"]),
            }
            return;
        };
        // §7.14: the topic sets the room's subject; the TOPIC line comes
        // with the room's change, to every connection.
        let store = self.store();
        match store.set_subject(&key, subject).await {
            Ok(()) => self.save().await,
            Err(error) if let Some(capability) = error.missing_capability() => {
                self.numeric(
                    "482",
                    &[
                        &channel,
                        &format!(
                            "Your role in this room may not change its subject ({capability})"
                        ),
                    ],
                );
            }
            Err(error) => self.server_notice(&format!(
                "mimid: the subject of {channel} was not changed: {error}"
            )),
        }
    }

    fn names(&mut self, line: &Line) {
        let keys: Vec<Key> = match line.param(0) {
            Some(targets) => {
                let mut keys = Vec::new();
                for target in targets.split(',').filter(|t| !t.is_empty()) {
                    match self.shown_room(target) {
                        Some(key) => keys.push(key),
                        None => self.numeric("366", &[target, "End of /NAMES list"]),
                    }
                }
                keys
            }
            None => self.channels.keys().cloned().collect(),
        };
        for key in keys {
            if let Some(shown) = self.room_shown(&key) {
                let members: Vec<(String, bool)> = shown
                    .members
                    .iter()
                    .map(|(w, op)| (w.nick.clone(), *op))
                    .collect();
                self.names_reply(&shown.channel, &members);
            }
        }
    }

    fn list(&mut self) {
        let keys: Vec<Key> = self.channels.keys().cloned().collect();
        for key in keys {
            if let Some(shown) = self.room_shown(&key) {
                let count = shown.members.len().to_string();
                self.numeric_cut("322", &[&shown.channel, &count, &shown.topic]);
            }
        }
        self.numeric("323", &["End of /LIST"]);
    }

    fn who_reply(&mut self, channel: &str, who: &crate::names::Identity, op: bool) {
        let server = self.shared.server.clone();
        let flags = if op { "H@" } else { "H" };
        self.numeric(
            "352",
            &[
                channel,
                &who.user,
                &who.host,
                &server,
                &who.nick,
                flags,
                &format!("0 {}", who.uri),
            ],
        );
    }

    fn who_cmd(&mut self, line: &Line) {
        let mask = line.param(0).unwrap_or("*").to_owned();
        if let Some(key) = self.shown_room(&mask) {
            if let Some(shown) = self.room_shown(&key) {
                for (who, op) in &shown.members {
                    self.who_reply(&shown.channel, who, *op);
                }
            }
        } else if let Who::User(uri) = self.who(&mask) {
            let who = self.shared.names().identity(&uri);
            self.who_reply("*", &who, false);
        }
        self.numeric("315", &[&mask, "End of /WHO list"]);
    }

    fn whois(&mut self, line: &Line) {
        let Some(nick) = line.params.last().cloned() else {
            self.numeric("431", &["No nickname given"]);
            return;
        };
        let nick = nick.split(',').next().unwrap_or_default().to_owned();
        let server = self.shared.server.clone();
        match self.who(&nick) {
            Who::Service => {
                self.numeric(
                    "311",
                    &[
                        SERVICE_NICK,
                        SERVICE_NICK,
                        &server,
                        "*",
                        "the mimid service: /msg mimid help",
                    ],
                );
                self.numeric("312", &[SERVICE_NICK, &server, "mimid-agent"]);
            }
            Who::User(uri) => {
                let who = self.shared.names().identity(&uri);
                self.numeric("311", &[&who.nick, &who.user, &who.host, "*", &who.uri]);
                let channels: Vec<String> = self
                    .channels
                    .values()
                    .filter_map(|v| {
                        v.members
                            .get(&uri)
                            .map(|op| format!("{}{}", if *op { "@" } else { "" }, v.name))
                    })
                    .collect();
                if !channels.is_empty() {
                    self.numeric("319", &[&who.nick, &channels.join(" ")]);
                }
                self.numeric("312", &[&who.nick, &server, "mimid-agent"]);
                let did = {
                    let state = self.shared.store.state();
                    state
                        .person_of_user(&uri)
                        .and_then(|k| state.people.get(k))
                        .and_then(|p| p.did.clone())
                };
                if let Some(did) = did {
                    self.numeric("320", &[&who.nick, &format!("has the did:webvh DID {did}")]);
                }
                // §7.15: the account is the user URI.
                self.numeric("330", &[&who.nick, &who.uri, "is logged in as"]);
                self.numeric("318", &[&who.nick, "End of /WHOIS list"]);
                return;
            }
            _ => self.numeric("401", &[&nick, "No such nick/channel"]),
        }
        self.numeric("318", &[&nick, "End of /WHOIS list"]);
    }

    fn ison(&mut self, line: &Line) {
        let names = self.shared.names();
        let present: Vec<String> = line
            .params
            .iter()
            .flat_map(|p| p.split(' '))
            .filter(|n| !n.is_empty())
            .filter_map(|n| {
                names
                    .every_nick()
                    .find(|(nick, _)| fold(nick) == fold(n))
                    .map(|(nick, _)| nick.to_owned())
            })
            .collect();
        drop(names);
        self.numeric("303", &[&present.join(" ")]);
    }

    fn userhost(&mut self, line: &Line) {
        let mut replies = Vec::new();
        for nick in line.params.iter().flat_map(|p| p.split(' ')).take(5) {
            match self.who(nick) {
                Who::User(uri) if parse_user_uri(nick).is_none() => {
                    let who = self.shared.names().identity(&uri);
                    replies.push(format!("{}=+{}@{}", who.nick, who.user, who.host));
                }
                Who::Service => {
                    replies.push(format!(
                        "{SERVICE_NICK}=+{SERVICE_NICK}@{}",
                        self.shared.server
                    ));
                }
                _ => {}
            }
        }
        self.numeric("302", &[&replies.join(" ")]);
    }

    async fn kick(&mut self, line: &Line) {
        let (Some(channel), Some(nicks)) = (line.param(0), line.param(1)) else {
            self.numeric("461", &["KICK", "Not enough parameters"]);
            return;
        };
        let Some(key) = self.shown_room(channel) else {
            self.numeric("403", &[channel, "No such channel"]);
            return;
        };
        let mut users = Vec::new();
        for nick in nicks.split(',').filter(|n| !n.is_empty()) {
            match self.who(nick) {
                Who::User(uri) => users.push(uri),
                _ => {
                    self.numeric("401", &[nick, "No such nick/channel"]);
                    return;
                }
            }
        }
        let store = self.store();
        match store.kick(&key, &users).await {
            Ok(()) => {
                self.server_notice(&format!(
                    "mimid: {nicks}'s devices were removed from {channel}; they stay a participant"
                ));
                self.save().await;
            }
            Err(error) => {
                self.server_notice(&format!("mimid: kicking {nicks} from {channel}: {error}"))
            }
        }
    }

    async fn invite(&mut self, line: &Line) {
        let (Some(nick), Some(channel)) = (line.param(0), line.param(1)) else {
            self.numeric("461", &["INVITE", "Not enough parameters"]);
            return;
        };
        let Some(key) = self.shown_room(channel) else {
            self.numeric("442", &[channel, "You're not on that channel"]);
            return;
        };
        let Who::User(user) = self.who_or_address(nick) else {
            self.numeric("401", &[nick, "No such nick/channel"]);
            return;
        };
        let mut changes = MemberChanges::new();
        changes.invite.push(user.clone());
        let store = self.store();
        match store.change_members(&key, &changes).await {
            Ok(()) => {
                let who = self.shared.names().identity(&user);
                let name = self.channels[&key].name.clone();
                self.numeric("341", &[&who.nick, &name]);
                self.save().await;
            }
            Err(error) => {
                self.server_notice(&format!("mimid: inviting {nick} to {channel}: {error}"))
            }
        }
    }
}
