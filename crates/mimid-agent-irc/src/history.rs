//! IRCv3 `draft/chathistory` (docs/design/client-survey.md §10 S2;
//! docs/design/agent-frontends.md §7.33), served from the store's
//! history ([`mimid_agent_store::Store::history`], §7.31).
//!
//! - `CHATHISTORY BEFORE|AFTER|LATEST|AROUND|BETWEEN <target> ...
//!   <limit>` for a channel this connection shows or the nick of a
//!   private query (the one-to-one room with that user, hidden or not);
//!   references by `timestamp=` (the hub's time, milliseconds) or
//!   `msgid=` (the store's `senderMsgId`, or the msgid of an `(edited)`
//!   line). A timestamp excludes every message of that millisecond on the
//!   side it bounds; a msgid excludes that message.
//! - `CHATHISTORY TARGETS <timestamp> <timestamp> <limit>`: the channels
//!   and queries whose latest message falls between the two, oldest
//!   first; a query closed with `PART <nick>` is left out until a message
//!   newer than the close (bead mimid-2vcw, option B).
//! - With `batch` (and message-tags) the reply is a `chathistory` batch
//!   naming the target, or a `draft/chathistory-targets` batch, empty if
//!   there is nothing; `draft/chathistory-end` on the opening line when
//!   there is no more in the page's direction. Messages are oldest first,
//!   as the live lines would show them now (an edited message with its
//!   latest text, a retracted one as the server's NOTICE, or left out
//!   with `draft/message-redaction`), each with
//!   `msgid` and, with server-time, `time`. With `draft/event-playback`
//!   each message's reactions follow it as TAGMSG lines.
//! - Errors are `FAIL CHATHISTORY INVALID_PARAMS` or `INVALID_TARGET`.
//!
//! # Limitations
//!
//! - A page is at most [`mimid_agent_store::history::MAX_HISTORY_PAGE`]
//!   messages (ISUPPORT `CHATHISTORY`); each command reads the room's
//!   records whole, and `TARGETS` every room's.
//! - Messages shown from history count as read, as live ones do
//!   (§7.22).
//! - Attachments are not shown (§7.4), here as live.

use mimid_agent_store::Store;
use mimid_agent_store::action::ActionError;
use mimid_agent_store::history::{Direction, MAX_HISTORY_PAGE, Point};
use mimid_agent_store::record::{Key, Message, RoomStatus};

use crate::conn::Session;
use crate::line::{Line, Out};
use crate::render::{server_time, shown_now};

/// A message reference of a `CHATHISTORY` command.
#[derive(Debug, Clone)]
enum Bound {
    /// `timestamp=`: milliseconds.
    Time(u64),
    /// `msgid=`: a message of the room, by key, with its place in hub
    /// order.
    Message(Key, (u64, u64)),
}

impl Bound {
    /// Its place in hub order, a timestamp before every message of its
    /// millisecond.
    fn order(&self) -> (u64, u64) {
        match self {
            Self::Time(t) => (*t, 0),
            Self::Message(_, order) => *order,
        }
    }

    /// Whether `m` comes after it, excluding it.
    fn has_after(&self, m: &Message) -> bool {
        match self {
            Self::Time(t) => m.accepted_at > *t,
            Self::Message(_, order) => (m.accepted_at, m.seq) > *order,
        }
    }

    /// Whether `m` comes before it, excluding it.
    fn has_before(&self, m: &Message) -> bool {
        match self {
            Self::Time(t) => m.accepted_at < *t,
            Self::Message(_, order) => (m.accepted_at, m.seq) < *order,
        }
    }

    /// The store's point for a page going `direction` from it.
    fn point(&self, direction: Direction) -> Point {
        match (self, direction) {
            (Self::Time(t), Direction::Before) => Point::Time(*t),
            // Point::Time takes "at or after"; a timestamp excludes its
            // millisecond.
            (Self::Time(t), _) => Point::Time(t.saturating_add(1)),
            (Self::Message(key, _), _) => Point::Message(key.clone()),
        }
    }
}

/// A page of messages, oldest first, and whether there are more beyond it.
type Found = (Vec<Message>, bool);

/// `timestamp=<server-time>` as milliseconds.
fn timestamp(text: &str) -> Option<u64> {
    mimid_agent_store::convert::parse_utc_date(text.strip_prefix("timestamp=")?)
}

impl Session {
    /// `FAIL CHATHISTORY <code> <context...> :<description>`.
    fn history_fail(&mut self, code: &str, context: &[&str], description: &str) {
        let mut params = vec!["CHATHISTORY".to_owned(), code.to_owned()];
        params.extend(context.iter().map(|c| (*c).to_owned()));
        params.push(description.to_owned());
        let server = self.shared.server.clone();
        self.send_cut(Out::new(&server, "FAIL", params));
    }

    /// `CHATHISTORY`.
    pub(crate) fn chathistory(&mut self, line: &Line) {
        let sub = line.param(0).unwrap_or_default().to_ascii_uppercase();
        match sub.as_str() {
            "TARGETS" => self.history_targets(line),
            "BEFORE" | "AFTER" | "LATEST" | "AROUND" | "BETWEEN" => {
                self.history_messages(&sub, line);
            }
            _ => self.history_fail("INVALID_PARAMS", &[&sub], "Unknown command"),
        }
    }

    /// The reference `text` names in room `room`.
    fn bound(&self, room: &str, text: &str) -> Option<Bound> {
        if let Some(t) = timestamp(text) {
            return Some(Bound::Time(t));
        }
        let msgid = text.strip_prefix("msgid=")?;
        let key = self.message_of_msgid(room, msgid)?;
        let state = self.shared.store.state();
        let m = state.messages.get(&key)?;
        Some(Bound::Message(key, (m.accepted_at, m.seq)))
    }

    /// `CHATHISTORY BEFORE|AFTER|LATEST|AROUND|BETWEEN`.
    fn history_messages(&mut self, sub: &str, line: &Line) {
        let between = sub == "BETWEEN";
        let wanted = if between { 5 } else { 4 };
        if line.params.len() < wanted {
            self.history_fail("INVALID_PARAMS", &[sub], "Insufficient parameters");
            return;
        }
        let target = line.params[1].clone();
        let Some(room) = self.target_room(&target) else {
            self.history_fail(
                "INVALID_TARGET",
                &[sub, &target],
                "Messages could not be retrieved",
            );
            return;
        };
        let limit = line.params[wanted - 1]
            .parse::<usize>()
            .ok()
            .filter(|l| *l > 0);
        let Some(limit) = limit.map(|l| l.min(MAX_HISTORY_PAGE)) else {
            self.history_fail("INVALID_PARAMS", &[sub], "Invalid limit");
            return;
        };
        let first = &line.params[2];
        let bound_a = if sub == "LATEST" && first == "*" {
            None
        } else {
            match self.bound(&room, first) {
                Some(bound) => Some(bound),
                None => {
                    self.history_fail("INVALID_PARAMS", &[sub, first], "Invalid message reference");
                    return;
                }
            }
        };
        let bound_b = if between {
            match self.bound(&room, &line.params[3]) {
                Some(bound) => Some(bound),
                None => {
                    let second = line.params[3].clone();
                    self.history_fail(
                        "INVALID_PARAMS",
                        &[sub, &second],
                        "Invalid message reference",
                    );
                    return;
                }
            }
        } else {
            None
        };
        let store = self.store();
        let found = select(
            &store,
            &room,
            sub,
            bound_a.as_ref(),
            bound_b.as_ref(),
            limit,
        );
        match found {
            Ok((messages, more)) => self.history_batch(&target, &messages, more),
            Err(_) => self.history_fail(
                "MESSAGE_ERROR",
                &[sub, &target],
                "Messages could not be retrieved",
            ),
        }
    }

    /// A new batch reference, if the client takes batches.
    fn open_batch(&mut self, kind: &str, params: &[&str], end: bool) -> Option<String> {
        if !(self.caps.batch && self.caps.message_tags) {
            return None;
        }
        self.batches += 1;
        let id = format!("h{}", self.batches);
        let mut all = vec![format!("+{id}"), kind.to_owned()];
        all.extend(params.iter().map(|p| (*p).to_owned()));
        let server = self.shared.server.clone();
        let mut out = Out::new(&server, "BATCH", all);
        if end {
            out = out.tag("draft/chathistory-end", "");
        }
        self.send(&out);
        Some(id)
    }

    /// Ends batch `id`, if any.
    fn close_batch(&mut self, id: Option<String>) {
        if let Some(id) = id {
            let server = self.shared.server.clone();
            self.send(&Out::new(&server, "BATCH", vec![format!("-{id}")]));
        }
    }

    /// `messages` as a `chathistory` batch for `target`.
    fn history_batch(&mut self, target: &str, messages: &[Message], more: bool) {
        let id = self.open_batch("chathistory", &[target], !more);
        let every: Vec<(String, String)> = id
            .iter()
            .map(|id| ("batch".to_owned(), id.clone()))
            .collect();
        for record in messages {
            let key = record.key.clone();
            let Some(m) = self.shown_record(record.clone()) else {
                continue;
            };
            self.shown
                .entry(key.clone())
                .or_insert_with(|| shown_now(&m.record));
            let time = self
                .caps
                .server_time
                .then(|| server_time(m.record.accepted_at));
            if m.record.deleted.is_some() && self.caps.message_redaction {
                // draft/message-redaction "Chat history": left out.
                continue;
            }
            if m.record.deleted.is_some() {
                let mut out = self
                    .retraction_line(&m, &every)
                    .tag("msgid", &m.record.sender_msg_id);
                if let Some(time) = &time {
                    out = out.tag("time", time);
                }
                self.send(&out);
                continue;
            }
            if m.record.expiry.counts_from_read() {
                self.delivered.push(key);
            }
            for out in self.message_lines(&m, &every) {
                self.send(&out);
            }
            if self.caps.event_playback && self.caps.message_tags {
                for r in &m.record.reactions {
                    let who = self.shared.names().identity(&r.sender);
                    let mut out = Out::new(&who.mask(), "TAGMSG", vec![m.target.clone()])
                        .tag("+draft/react", &crate::render::one_line_data(&r.reaction))
                        .tag("+draft/reply", &m.record.sender_msg_id);
                    out.tags.extend(every.iter().cloned());
                    if self.caps.server_time {
                        out = out.tag("time", &server_time(r.accepted_at));
                    }
                    self.send_cut(out);
                }
            }
        }
        self.close_batch(id);
    }

    /// `CHATHISTORY TARGETS <timestamp> <timestamp> <limit>`.
    fn history_targets(&mut self, line: &Line) {
        if line.params.len() < 4 {
            self.history_fail("INVALID_PARAMS", &["TARGETS"], "Insufficient parameters");
            return;
        }
        let (Some(a), Some(b)) = (timestamp(&line.params[1]), timestamp(&line.params[2])) else {
            self.history_fail("INVALID_PARAMS", &["TARGETS"], "Invalid timestamp");
            return;
        };
        let Some(limit) = line.params[3].parse::<usize>().ok().filter(|l| *l > 0) else {
            self.history_fail("INVALID_PARAMS", &["TARGETS"], "Invalid limit");
            return;
        };
        let (low, high) = (a.min(b), a.max(b));
        let mut targets = self.targets();
        targets.retain(|(_, at)| *at > low && *at < high);
        targets.sort_by_key(|(_, at)| *at);
        let more = targets.len() > limit;
        if a <= b {
            targets.truncate(limit);
        } else {
            let from = targets.len().saturating_sub(limit);
            targets.drain(..from);
        }
        let id = self.open_batch("draft/chathistory-targets", &[], !more);
        let server = self.shared.server.clone();
        for (name, at) in targets {
            let mut out = Out::new(
                &server,
                "CHATHISTORY",
                vec!["TARGETS".to_owned(), name, server_time(at)],
            );
            if let Some(id) = &id {
                out = out.tag("batch", id);
            }
            self.send(&out);
        }
        self.close_batch(id);
    }

    /// Every channel this connection shows and every private query, by
    /// name, with the hub's time of its latest message; rooms with none
    /// and queries closed since their latest message are left out.
    fn targets(&self) -> Vec<(String, u64)> {
        let me = self.me();
        let rooms: Vec<(Key, Option<String>, Option<u64>)> = {
            let state = self.shared.store.state();
            state
                .rooms
                .values()
                .filter(|r| r.status == RoomStatus::Active)
                .filter_map(|r| {
                    if self.channels.contains_key(&r.key) {
                        return Some((r.key.clone(), None, None));
                    }
                    let peer = r.direct_peer(&me.uri)?;
                    Some((
                        r.key.clone(),
                        Some(peer.to_owned()),
                        crate::names::hidden_at(r),
                    ))
                })
                .collect()
        };
        let store = self.store();
        let mut targets = Vec::new();
        for (key, peer, hidden) in rooms {
            let Ok(page) = store.history(&key, &Point::Edge, Direction::Before, 1) else {
                continue;
            };
            let Some(latest) = page.messages.last() else {
                continue;
            };
            if hidden.is_some_and(|at| latest.accepted_at <= at) {
                continue;
            }
            let name = match peer {
                Some(peer) => self.shared.names().nick(&peer),
                None => match self.channels.get(&key) {
                    Some(view) => view.name.clone(),
                    None => continue,
                },
            };
            targets.push((name, latest.accepted_at));
        }
        targets
    }
}

/// The messages of room `room` that `CHATHISTORY <sub>` asks for, with
/// `a` its first reference (`None` for `LATEST *`), `b` the second of
/// `BETWEEN`: oldest first, and whether there are more beyond them.
fn select(
    store: &Store,
    room: &str,
    sub: &str,
    a: Option<&Bound>,
    b: Option<&Bound>,
    limit: usize,
) -> Result<Found, ActionError> {
    let page = |point: Point, direction| -> Result<Found, ActionError> {
        let page = store.history(room, &point, direction, limit)?;
        Ok((page.messages, page.more))
    };
    let Some(a) = a else {
        return page(Point::Edge, Direction::Before);
    };
    match sub {
        "BEFORE" => page(a.point(Direction::Before), Direction::Before),
        "AFTER" => page(a.point(Direction::After), Direction::After),
        "LATEST" => {
            let (mut messages, more) = page(Point::Edge, Direction::Before)?;
            let all = messages.len();
            messages.retain(|m| a.has_after(m));
            Ok((messages.clone(), more && messages.len() == all))
        }
        "BETWEEN" => {
            let Some(b) = b else {
                return Ok((Vec::new(), false));
            };
            if a.order() <= b.order() {
                let (mut messages, more) = page(a.point(Direction::After), Direction::After)?;
                let all = messages.len();
                messages.retain(|m| b.has_before(m));
                Ok((messages.clone(), more && messages.len() == all))
            } else {
                let (mut messages, more) = page(a.point(Direction::Before), Direction::Before)?;
                let all = messages.len();
                messages.retain(|m| b.has_after(m));
                Ok((messages.clone(), more && messages.len() == all))
            }
        }
        // AROUND: half before, the rest after, and the message itself for
        // a msgid.
        _ => {
            let half = limit / 2;
            let mut before = if half > 0 {
                store
                    .history(room, &a.point(Direction::Before), Direction::Before, half)?
                    .messages
            } else {
                Vec::new()
            };
            if let Bound::Message(key, _) = a
                && let Some(m) = store.state().messages.get(key)
                && before.len() < limit
            {
                before.push(m.clone());
            }
            let rest = limit.saturating_sub(before.len());
            if rest > 0 {
                let after =
                    store.history(room, &a.point(Direction::After), Direction::After, rest)?;
                before.extend(after.messages);
                return Ok((before, after.more));
            }
            Ok((before, true))
        }
    }
}
