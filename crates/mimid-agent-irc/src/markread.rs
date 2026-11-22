//! IRCv3 `draft/read-marker` (docs/design/agent-frontends.md §7.34) over
//! the store's read positions, the ones JMAP Chat's `ReadPosition` shows
//! ([`mimid_agent_store::record::ReadPosition`]).
//!
//! - A room's read marker is the hub's time of the message its read
//!   position names (the first position of the room by key, if there are
//!   several); `*` if it has none.
//! - `MARKREAD <target>` asks for it; `MARKREAD <target>
//!   timestamp=<time>` moves the position to the latest message of the
//!   room at or before that time, if that is past where it is: a marker
//!   only moves forward. Either way the client gets a `MARKREAD` back: the
//!   new marker comes to every connection with the capability when the
//!   change is saved, an older or unchanged one is answered with the
//!   marker as it stands.
//! - A connection with the capability gets `MARKREAD` after each JOIN,
//!   before the names, and whenever a position moves, from IRC or JMAP.
//! - A target is a channel the connection shows or a private query's
//!   nick (§7.32); a user with no query has no marker (`*`).
//!
//! Moving a position reads every message up to it, which deletes those
//! with a read rule (§7.22), as JMAP's ReadPosition does.
//!
//! # Limitations
//!
//! - The marker is a message's time, so a marker set between two
//!   messages comes back as the earlier one's time.

use mimid_agent_store::history::{Direction, Point};
use mimid_agent_store::record::Key;

use crate::conn::Session;
use crate::line::{Line, Out};
use crate::render::server_time;

impl Session {
    /// The read position of room `room` and the hub's time and place of
    /// the message it names: (position key, `(accepted_at, seq)`).
    fn read_position(&self, room: &str) -> Option<(Key, Option<(u64, u64)>)> {
        let state = self.shared.store.state();
        let position = state.read_positions.values().find(|p| p.room == room)?;
        let order = position
            .message
            .as_ref()
            .and_then(|m| state.messages.get(m))
            .map(|m| (m.accepted_at, m.seq));
        Some((position.key.clone(), order))
    }

    /// `:server MARKREAD <target> timestamp=<time>`, or `*` for none.
    pub(crate) fn marker_line(&self, target: &str, room: &str) -> Out {
        let marker = self
            .read_position(room)
            .and_then(|(_, order)| order)
            .map_or_else(
                || "*".to_owned(),
                |(at, _)| format!("timestamp={}", server_time(at)),
            );
        Out::new(
            &self.shared.server,
            "MARKREAD",
            vec![target.to_owned(), marker],
        )
    }

    /// `FAIL MARKREAD <code> <context...> :<description>`.
    fn markread_fail(&mut self, code: &str, context: &[&str], description: &str) {
        let mut params = vec!["MARKREAD".to_owned(), code.to_owned()];
        params.extend(context.iter().map(|c| (*c).to_owned()));
        params.push(description.to_owned());
        let server = self.shared.server.clone();
        self.send_cut(Out::new(&server, "FAIL", params));
    }

    /// `MARKREAD <target> [timestamp=<time>]`.
    pub(crate) async fn markread(&mut self, line: &Line) {
        let Some(target) = line.param(0).map(str::to_owned) else {
            self.markread_fail("NEED_MORE_PARAMS", &[], "Missing parameters");
            return;
        };
        let Some(room) = self.target_room(&target) else {
            if !target.starts_with(['#', '&'])
                && matches!(self.who_or_address(&target), crate::command::Who::User(_))
            {
                let server = self.shared.server.clone();
                self.send(&Out::new(&server, "MARKREAD", vec![target, "*".to_owned()]));
            } else {
                self.markread_fail("INVALID_PARAMS", &[&target], "Invalid parameters");
            }
            return;
        };
        let Some(bound) = line.param(1) else {
            let out = self.marker_line(&target, &room);
            self.send(&out);
            return;
        };
        let Some(at) = bound
            .strip_prefix("timestamp=")
            .and_then(mimid_agent_store::convert::parse_utc_date)
        else {
            self.markread_fail("INVALID_PARAMS", &[&target, bound], "Invalid parameters");
            return;
        };
        // The latest message at or before the time.
        let store = self.store();
        let read = store
            .history(
                &room,
                &Point::Time(at.saturating_add(1)),
                Direction::Before,
                1,
            )
            .ok()
            .and_then(|page| page.messages.into_iter().last());
        let current = self.read_position(&room);
        let newer = read.as_ref().is_some_and(|m| {
            current
                .as_ref()
                .and_then(|(_, order)| *order)
                .is_none_or(|order| (m.accepted_at, m.seq) > order)
        });
        if !newer {
            let out = self.marker_line(&target, &room);
            self.send(&out);
            return;
        }
        let Some(read) = read else { return };
        let key = current.map_or_else(|| store.new_key(), |(key, _)| key);
        store.set_read_position(
            key,
            room,
            Some(read.key),
            Some(mimid_agent_store::sync::now_ms()),
        );
        // The MARKREAD comes with the change, to every connection.
        self.save().await;
    }

    /// Shows read position `key`, moved, to a connection with the
    /// capability.
    pub(crate) fn show_read_position(&mut self, key: &str) {
        if !self.caps.read_marker {
            return;
        }
        let room = {
            let state = self.shared.store.state();
            let Some(position) = state.read_positions.get(key) else {
                return;
            };
            // The marker of a room is its first position's.
            match state
                .read_positions
                .values()
                .find(|p| p.room == position.room)
            {
                Some(first) if first.key == key => position.room.clone(),
                _ => return,
            }
        };
        if let Some(target) = self.target_of(&room, None) {
            let out = self.marker_line(&target, &room);
            self.send(&out);
        }
    }
}
