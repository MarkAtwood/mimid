//! Nicks and channel names (docs/design/agent-frontends.md §4 "Names",
//! §7.3): assigned once, kept in the record's `ext["irc"]`, and never
//! moved to another person or room while it is shown.
//!
//! - **Casemapping**: `CASEMAPPING=ascii`; [`fold`] folds exactly A-Z.
//! - **Nicks**: from the user URI `mimi://<domain>/u/<local>`, never from
//!   a display name: `<local>-<label>`, the label being the domain's
//!   first DNS label, for every user, the user's own provider included
//!   (§7.3). Characters outside `[A-Za-z0-9_-]` become `_`, and a nick
//!   starting with a digit or `-` gets a `_` in front. The user's own nick
//!   is reserved first, then the service nick [`SERVICE_NICK`]. On a
//!   collision, or past [`NICKLEN`], the nick is cut and `-` and 4 base32
//!   characters of SHA-256 of the URI are appended.
//! - **Hostmask**: `<nick>!<local>@<domain>`.
//! - **Channels**: `#` and the room's `room_name` without the characters
//!   outside `[A-Za-z0-9_.-]`, at most [`CHANNELLEN`]; a room with no
//!   usable name gets the id part of its URI. A collision gets `-` and 4
//!   base32 characters of SHA-256 of the room URI.
//! - **Pending invites** (§7.13): an invite whose Welcome could be read
//!   is shown under the channel name its room will have, made by the same
//!   rules from the room name and URI in the Welcome, and held from then
//!   on: no room or other invite takes it, and the room takes it when it
//!   arrives. A name is held by whichever comes first, a room or an
//!   invite; the later one gets the collision suffix. An invite whose
//!   Welcome could not be read is `&invite-<number>`.
//!
//! # Limitations
//!
//! - A user with no person record (the user themselves, someone invited
//!   but not yet seen at a sync, an inviter) has a nick in memory only
//!   until the record is made. If the daemon restarts first, a colliding
//!   nick may come out with another suffix.
//! - A room the user is no longer in gives its channel name up: it is not
//!   shown, and JOIN of the name hosts a new room (§7.1).
//! - Non-Latin room names come out as ids.
//! - The name held for a room whose invite was accepted is given up only
//!   when the room arrives; if the room never does, the name stays held
//!   until the daemon restarts.

use std::collections::BTreeMap;

use mimid_agent_store::State;
use mimid_agent_store::record::{Ext, Invite, Key, Person, Room, RoomStatus};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The longest nick (`NICKLEN` in 005).
pub const NICKLEN: usize = 30;

/// The longest channel name, `#` included (`CHANNELLEN` in 005).
pub const CHANNELLEN: usize = 64;

/// The nick of the service the user sends what IRC has no command for
/// (`/msg mimid help`). INVENTED, NOT FROM SPEC.
pub const SERVICE_NICK: &str = "mimid";

/// The key of the IRC front end's part of a record's `ext`.
pub const EXT_KEY: &str = "irc";

/// The length of a collision suffix: `-` and 4 base32 characters.
const SUFFIX_LEN: usize = 5;

/// `text` with A-Z folded to a-z and nothing else changed
/// (`CASEMAPPING=ascii`).
#[must_use]
pub fn fold(text: &str) -> String {
    text.to_ascii_lowercase()
}

/// The domain and local part of `mimi://<domain>/u/<local>`.
#[must_use]
pub fn parse_user_uri(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("mimi://")?;
    let (domain, path) = rest.split_once('/')?;
    let local = path.strip_prefix("u/")?;
    (!domain.is_empty() && !local.is_empty() && !local.contains('/')).then_some((domain, local))
}

/// The user URI `mimi://<domain>/u/<user>` that `<user>@<domain>` stands
/// for (docs/design/agent-frontends.md §7.15), the domain in lowercase:
/// `None` unless `text` is one `@` between a non-empty user part without
/// `/`, `:`, `!`, `*`, `?` or whitespace and a domain of DNS letters,
/// digits, `-` and `.` that neither starts nor ends with `.`.
#[must_use]
pub fn parse_user_address(text: &str) -> Option<String> {
    let (user, domain) = text.split_once('@')?;
    let user_ok = !user.is_empty()
        && !user
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/:@!*?".contains(c));
    let domain_ok = !domain.is_empty()
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    (user_ok && domain_ok).then(|| format!("mimi://{}/u/{user}", domain.to_ascii_lowercase()))
}

/// How IRC shows one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The user URI.
    pub uri: String,
    /// The nick.
    pub nick: String,
    /// The user part of the hostmask: the URI's local part.
    pub user: String,
    /// The host part of the hostmask: the URI's domain.
    pub host: String,
}

impl Identity {
    /// `nick!user@host`.
    #[must_use]
    pub fn mask(&self) -> String {
        format!("{}!{}@{}", self.nick, self.user, self.host)
    }
}

/// Whether `c` may be in a nick.
fn nick_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Whether `c` may be in a channel name after the `#`.
fn channel_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

/// `text` with every character outside the nick characters as `_`.
fn nick_part(text: &str) -> String {
    text.chars()
        .map(|c| if nick_char(c) { c } else { '_' })
        .collect()
}

/// Whether `nick` is one this module could have made.
fn is_nick(nick: &str) -> bool {
    !nick.is_empty()
        && nick.len() <= NICKLEN
        && nick.chars().all(nick_char)
        && !nick.starts_with(|c: char| c.is_ascii_digit() || c == '-')
}

/// Whether `name` is a channel name JOIN may create or this module could
/// have made: `#`, then 1 to [`CHANNELLEN`] - 1 of `[A-Za-z0-9_.-]`.
#[must_use]
pub fn is_channel_name(name: &str) -> bool {
    name.strip_prefix('#').is_some_and(|rest| {
        !rest.is_empty() && name.len() <= CHANNELLEN && rest.chars().all(channel_char)
    })
}

/// `-` and 4 base32 characters of SHA-256 of `seed`, and of attempt `n`
/// past the first.
fn suffix(seed: &str, n: u32) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut hash = Sha256::new();
    hash.update(seed.as_bytes());
    if n > 0 {
        hash.update(format!("#{n}").as_bytes());
    }
    let digest = hash.finalize();
    let bits = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let mut out = String::from("-");
    for i in 0..4 {
        out.push(char::from(ALPHABET[(bits >> (27 - 5 * i)) as usize & 31]));
    }
    out
}

/// `text` cut to at most `max` octets (it is ASCII).
fn cut(text: &str, max: usize) -> &str {
    &text[..text.len().min(max)]
}

/// The nick `uri` would get with nothing taken, and its hostmask parts.
fn base_identity(uri: &str) -> (String, String, String) {
    let (domain, local) = parse_user_uri(uri).unwrap_or(("unknown.invalid", "user"));
    let label = domain.split('.').next().unwrap_or(domain);
    let mut nick = format!("{}-{}", nick_part(local), nick_part(label));
    if nick.starts_with(|c: char| c.is_ascii_digit() || c == '-') {
        nick.insert(0, '_');
    }
    (nick, nick_part(local), domain.to_owned())
}

/// The nicks and channel names of one store, for every IRC connection.
#[derive(Debug)]
pub struct Names {
    own: Identity,
    /// User URI to nick.
    nicks: BTreeMap<String, String>,
    /// Folded nick to user URI; the service nick maps to "".
    users: BTreeMap<String, String>,
    /// Room key to channel name, for the rooms shown.
    channels: BTreeMap<Key, String>,
    /// Folded channel name to room key.
    rooms: BTreeMap<String, Key>,
    /// Pending invite number to the name it is shown under.
    invites: BTreeMap<u64, InviteName>,
    /// Folded channel name to the hold on it for a room not shown yet.
    held: BTreeMap<String, Hold>,
}

/// The name a pending invite is shown under.
#[derive(Debug, Clone)]
struct InviteName {
    /// `#<name>`, held; or `&invite-<number>`, which is never a channel.
    channel: String,
    /// The room URI from the Welcome, if it could be read.
    room: Option<String>,
}

/// A channel name held for a room not shown yet, which takes it when it
/// arrives.
#[derive(Debug, Clone)]
struct Hold {
    /// The name as shown.
    channel: String,
    /// The room URI.
    room: String,
    /// Whether the user accepted the invite: the room is being joined.
    accepted: bool,
}

/// What a held channel name stands for ([`Names::held`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    /// A pending invite, by number, which JOIN of the name accepts
    /// (§7.13).
    Invite(u64),
    /// The room of an accepted invite, which has not arrived yet.
    Joining,
}

impl Names {
    /// The names of `own_uri`'s store, with the user's own nick and the
    /// service nick reserved, before any other.
    #[must_use]
    pub fn new(own_uri: &str) -> Self {
        let (mut nick, user, host) = base_identity(own_uri);
        if nick.len() > NICKLEN || fold(&nick) == SERVICE_NICK {
            nick = format!("{}{}", cut(&nick, NICKLEN - SUFFIX_LEN), suffix(own_uri, 0));
        }
        let mut names = Self {
            own: Identity {
                uri: own_uri.to_owned(),
                nick: nick.clone(),
                user,
                host,
            },
            nicks: BTreeMap::new(),
            users: BTreeMap::new(),
            channels: BTreeMap::new(),
            rooms: BTreeMap::new(),
            invites: BTreeMap::new(),
            held: BTreeMap::new(),
        };
        names.users.insert(SERVICE_NICK.to_owned(), String::new());
        names.take_nick(own_uri, nick);
        names
    }

    fn take_nick(&mut self, uri: &str, nick: String) {
        self.users.insert(fold(&nick), uri.to_owned());
        self.nicks.insert(uri.to_owned(), nick);
    }

    /// The user's own identity.
    #[must_use]
    pub fn own(&self) -> &Identity {
        &self.own
    }

    /// Reads the names kept in `state`'s records, then gives every person
    /// and every active room without one a name and writes it into the
    /// record's `ext["irc"]`, in key order. A kept name that another took
    /// first, or that is malformed, is given again.
    pub fn load(&mut self, state: &mut State) {
        for person in state.people.values_mut() {
            if let Some(nick) = kept(&person.ext, "nick")
                && is_nick(&nick)
                && !self.users.contains_key(&fold(&nick))
                && !self.nicks.contains_key(&person.user)
            {
                self.take_nick(&person.user, nick);
            }
        }
        for room in state.rooms.values_mut() {
            if room.status != RoomStatus::Active {
                continue;
            }
            if let Some(channel) = kept(&room.ext, "channel")
                && is_channel_name(&channel)
                && !self.rooms.contains_key(&fold(&channel))
            {
                self.rooms.insert(fold(&channel), room.key.clone());
                self.channels.insert(room.key.clone(), channel);
            }
        }
        for person in state.people.values_mut() {
            self.note_person(person);
        }
        for room in state.rooms.values_mut() {
            self.note_room(room);
        }
        for invite in &state.invites {
            self.invite_channel(invite);
        }
    }

    /// The nick of `uri`, given now if it has none.
    pub fn nick(&mut self, uri: &str) -> String {
        if let Some(nick) = self.nicks.get(uri) {
            return nick.clone();
        }
        let (base, _, _) = base_identity(uri);
        let mut nick = base.clone();
        let mut n = 0;
        while nick.len() > NICKLEN || self.users.contains_key(&fold(&nick)) {
            nick = format!("{}{}", cut(&base, NICKLEN - SUFFIX_LEN), suffix(uri, n));
            n += 1;
        }
        self.take_nick(uri, nick.clone());
        nick
    }

    /// How IRC shows `uri`.
    pub fn identity(&mut self, uri: &str) -> Identity {
        let nick = self.nick(uri);
        let (_, user, host) = base_identity(uri);
        Identity {
            uri: uri.to_owned(),
            nick,
            user,
            host,
        }
    }

    /// The user URI of `nick`, if it is one given here; `Some("")` for the
    /// service nick.
    #[must_use]
    pub fn user_of(&self, nick: &str) -> Option<&str> {
        self.users.get(&fold(nick)).map(String::as_str)
    }

    /// Every nick given, with its URI ("" for the service).
    pub fn every_nick(&self) -> impl Iterator<Item = (&str, &str)> {
        self.nicks
            .iter()
            .map(|(uri, nick)| (nick.as_str(), uri.as_str()))
            .chain(std::iter::once((SERVICE_NICK, "")))
    }

    /// Gives `person` its nick, if it has none, and keeps it in the
    /// record's `ext["irc"]`.
    pub fn note_person(&mut self, person: &mut Person) {
        let nick = self.nick(&person.user);
        if kept(&person.ext, "nick").as_deref() != Some(nick.as_str()) {
            person
                .ext
                .insert(EXT_KEY.to_owned(), json!({ "nick": nick }));
        }
    }

    /// Gives active `room` its channel name, if it has none, and keeps it
    /// in the record's `ext["irc"]`; a room no longer active gives its
    /// name up.
    pub fn note_room(&mut self, room: &mut Room) {
        if room.status != RoomStatus::Active {
            self.forget_room(&room.key);
            room.ext.remove(EXT_KEY);
            return;
        }
        let channel = self.channel_for(room);
        if kept(&room.ext, "channel").as_deref() != Some(channel.as_str()) {
            room.ext
                .insert(EXT_KEY.to_owned(), json!({ "channel": channel }));
        }
    }

    /// The channel name of `room`, given now if it has none: the one held
    /// for its URI, if any, else a new one.
    fn channel_for(&mut self, room: &Room) -> String {
        if let Some(channel) = self.channels.get(&room.key) {
            return channel.clone();
        }
        let channel = match self.hold_of(&room.uri) {
            Some(folded) => self
                .held
                .remove(&folded)
                .map_or(folded, |hold| hold.channel),
            None => self.new_channel(room.name.as_deref(), &room.uri),
        };
        self.rooms.insert(fold(&channel), room.key.clone());
        self.channels.insert(room.key.clone(), channel.clone());
        channel
    }

    /// The folded name held for the room with URI `uri`.
    fn hold_of(&self, uri: &str) -> Option<String> {
        self.held
            .iter()
            .find(|(_, hold)| hold.room == uri)
            .map(|(folded, _)| folded.clone())
    }

    /// A channel name that no room shown has and nothing holds, for a room
    /// named `name` with URI `uri`: `#` and the name's channel characters,
    /// else the URI's id part, with the collision suffix if taken.
    fn new_channel(&self, name: Option<&str>, uri: &str) -> String {
        let clean = |text: &str| -> String { text.chars().filter(|c| channel_char(*c)).collect() };
        let mut base = name.map(clean).unwrap_or_default();
        if base.is_empty() {
            base = clean(uri.rsplit('/').next().unwrap_or_default());
        }
        if base.is_empty() {
            base = "room".to_owned();
        }
        let base = format!("#{}", cut(&base, CHANNELLEN - 1));
        let taken = |channel: &str| {
            let folded = fold(channel);
            self.rooms.contains_key(&folded) || self.held.contains_key(&folded)
        };
        let mut channel = base.clone();
        let mut n = 0;
        while taken(&channel) {
            channel = format!("{}{}", cut(&base, CHANNELLEN - SUFFIX_LEN), suffix(uri, n));
            n += 1;
        }
        channel
    }

    /// The name pending `invite` is shown under, given now if it has none
    /// (§7.13): if its Welcome could be read, the channel name its room
    /// will have, held from now on (another invite to the same room shares
    /// it); else `&invite-<number>`.
    pub fn invite_channel(&mut self, invite: &Invite) -> String {
        if let Some(name) = self.invites.get(&invite.number) {
            return name.channel.clone();
        }
        let channel = match invite.room.as_deref() {
            Some(uri) => match self.hold_of(uri) {
                Some(folded) => self.held[&folded].channel.clone(),
                None => {
                    let channel = self.new_channel(invite.room_name.as_deref(), uri);
                    self.held.insert(
                        fold(&channel),
                        Hold {
                            channel: channel.clone(),
                            room: uri.to_owned(),
                            accepted: false,
                        },
                    );
                    channel
                }
            },
            None => format!("&invite-{}", invite.number),
        };
        self.invites.insert(
            invite.number,
            InviteName {
                channel: channel.clone(),
                room: invite.room.clone(),
            },
        );
        channel
    }

    /// What held channel name `channel` stands for, if it is held: a
    /// pending invite to accept, or a room being joined.
    #[must_use]
    pub fn held(&self, channel: &str) -> Option<Held> {
        let hold = self.held.get(&fold(channel))?;
        if hold.accepted {
            return Some(Held::Joining);
        }
        self.invites
            .iter()
            .find(|(_, name)| name.room.as_deref() == Some(hold.room.as_str()))
            .map(|(number, _)| Held::Invite(*number))
    }

    /// Marks the name of pending invite `number`, if it holds one, as its
    /// room's while the user accepts it, or, with `accepted` false, as the
    /// invite's again (accepting failed). A room being joined keeps the
    /// name until it arrives, though the invite is gone.
    pub fn accepting(&mut self, number: u64, accepted: bool) {
        let Some(uri) = self.invites.get(&number).and_then(|i| i.room.clone()) else {
            return;
        };
        if let Some(folded) = self.hold_of(&uri)
            && let Some(hold) = self.held.get_mut(&folded)
        {
            hold.accepted = accepted;
        }
    }

    /// Forgets pending invite `number`, gone from the store, and gives up
    /// its held name unless its room is being joined or another pending
    /// invite to the room shares it.
    pub fn forget_invite(&mut self, number: u64) {
        let Some(gone) = self.invites.remove(&number) else {
            return;
        };
        let Some(uri) = gone.room else {
            return;
        };
        let shared = self
            .invites
            .values()
            .any(|i| i.room.as_deref() == Some(uri.as_str()));
        if let Some(folded) = self.hold_of(&uri)
            && !shared
            && !self.held[&folded].accepted
        {
            self.held.remove(&folded);
        }
    }

    /// The channel name of room `key`, if it is shown.
    #[must_use]
    pub fn channel(&self, key: &str) -> Option<&str> {
        self.channels.get(key).map(String::as_str)
    }

    /// The key of the room shown as `channel`.
    #[must_use]
    pub fn room_of(&self, channel: &str) -> Option<&Key> {
        self.rooms.get(&fold(channel))
    }

    /// Gives up room `key`'s channel name.
    pub fn forget_room(&mut self, key: &str) {
        if let Some(channel) = self.channels.remove(key) {
            self.rooms.remove(&fold(&channel));
        }
    }
}

/// The text kept under `field` in `ext["irc"]`.
fn kept(ext: &Ext, field: &str) -> Option<String> {
    ext.get(EXT_KEY)
        .and_then(|v| v.get(field))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "mimi://a.example/u/alice";

    fn room(key: &str, uri: &str, name: Option<&str>) -> Room {
        serde_json::from_value(json!({
            "key": key, "uri": uri, "name": name, "status": "active",
        }))
        .unwrap()
    }

    /// Oracle: §7.15 (Mark, 2026-11-21): `user@domain` stands for
    /// `mimi://domain/u/user`; anything else is not an address.
    #[test]
    fn user_at_domain_is_a_user_uri() {
        assert_eq!(
            parse_user_address("bob@b.example").as_deref(),
            Some("mimi://b.example/u/bob")
        );
        assert_eq!(
            parse_user_address("Bob.X@B.Example").as_deref(),
            Some("mimi://b.example/u/Bob.X")
        );
        for not in [
            "bob",
            "@b.example",
            "bob@",
            "bob@b.example.",
            "bob@.b.example",
            "bob@b_example",
            "bob@b.example/x",
            "bo/b@b.example",
            "bob@x@b.example",
            "bob smith@b.example",
            "nick!*@*",
            "mimi://b.example/u/bob",
        ] {
            assert_eq!(parse_user_address(not), None, "{not}");
        }
    }

    /// Oracle: `CASEMAPPING=ascii` folds A-Z and nothing else
    /// (docs/irc-lessons.md "Casemapping"): not the rfc1459 pairs, not
    /// Unicode.
    #[test]
    fn casemapping_folds_exactly_ascii() {
        assert_eq!(fold("AbC-XyZ_09"), "abc-xyz_09");
        assert_eq!(fold("[]\\^{}|~"), "[]\\^{}|~");
        assert_eq!(fold("ÉÀ"), "ÉÀ");
        let mut names = Names::new(ME);
        assert_eq!(names.user_of("ALICE-A"), Some(ME));
        assert_eq!(names.user_of("Alice-a"), Some(ME));
        assert_eq!(names.user_of("MIMID"), Some(""));
        let bob = names.nick("mimi://a.example/u/Bob");
        assert_eq!(bob, "Bob-a");
        // Another case of the same nick is the same nick.
        let other = names.nick("mimi://a.example/u/bob");
        assert_eq!(&other[..6], "bob-a-");
        assert_eq!(other.len(), 10);
    }

    /// Oracle: §7.3: `<local>-<label>` for every user, the own provider
    /// included; characters outside `[A-Za-z0-9_-]` are `_`.
    #[test]
    fn every_nick_carries_its_provider_label() {
        let mut names = Names::new(ME);
        assert_eq!(names.own().nick, "alice-a");
        assert_eq!(names.own().mask(), "alice-a!alice@a.example");
        assert_eq!(names.nick("mimi://a.example/u/bob"), "bob-a");
        assert_eq!(names.nick("mimi://evil.example/u/bob"), "bob-evil");
        assert_eq!(names.nick("mimi://x.y.z/u/j.r%20s"), "j_r_20s-x");
        assert_eq!(names.nick("mimi://b.example/u/9lives"), "_9lives-b");
        assert_eq!(names.nick("mimi://b.example/u/zoë"), "zo_-b");
        let id = names.identity("mimi://evil.example/u/bob");
        assert_eq!(id.mask(), "bob-evil!bob@evil.example");
        // Assigned once: the same URI keeps its nick.
        assert_eq!(names.nick("mimi://evil.example/u/bob"), "bob-evil");
    }

    /// Oracle: §4 "Names": the own nick is reserved first, so no remote
    /// user takes it (tailircd's shadowing); a collision or a nick past
    /// NICKLEN gets `-` and 4 base32 characters of SHA-256 of the URI.
    #[test]
    fn collisions_and_long_nicks_get_a_hash_suffix() {
        let mut names = Names::new(ME);
        // alice on a.example.org: same local part, same first label.
        let shadow = names.nick("mimi://a.example.org/u/alice");
        assert_ne!(shadow, "alice-a");
        assert_eq!(&shadow[..8], "alice-a-");
        assert_eq!(
            shadow,
            format!("alice-a{}", suffix("mimi://a.example.org/u/alice", 0))
        );
        let long_uri = format!("mimi://b.example/u/{}", "x".repeat(40));
        let long = names.nick(&long_uri);
        assert_eq!(long.len(), NICKLEN);
        assert_eq!(long, format!("{}{}", "x".repeat(25), suffix(&long_uri, 0)));
        // The suffix is 4 characters of the base32 alphabet.
        let s = suffix("anything", 0);
        assert_eq!(s.len(), SUFFIX_LEN);
        assert!(
            s[1..]
                .chars()
                .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        );
        // A user named like the service is not the service.
        let mut names = Names::new("mimi://mimid/u/x");
        assert_eq!(names.own().nick, "x-mimid");
        assert_eq!(names.user_of("mimid"), Some(""));
        assert_ne!(fold(&names.nick("mimi://q/u/mimid")), "mimid");
    }

    #[test]
    fn kept_names_are_read_back_and_bad_ones_given_again() {
        let mut state = State::new(ME);
        let person: Person = serde_json::from_value(json!({
            "key": "P1", "user": "mimi://b.example/u/carol", "firstSeen": 0,
            "ext": {"irc": {"nick": "carol-kept"}},
        }))
        .unwrap();
        state.insert_person(person);
        let stolen: Person = serde_json::from_value(json!({
            "key": "P2", "user": "mimi://c.example/u/dave", "firstSeen": 0,
            "ext": {"irc": {"nick": "alice-a"}},
        }))
        .unwrap();
        state.insert_person(stolen);
        let mut r = room("R1", "mimi://a.example/r/r1", Some("Lobby!"));
        r.ext.insert("irc".into(), json!({"channel": "#kept"}));
        state.insert_room(r);
        state.insert_room(room("R2", "mimi://a.example/r/r2", Some("lobby")));
        state.insert_room(room("R3", "mimi://a.example/r/r3", Some("LOBBY")));
        state.insert_room(room("R4", "mimi://a.example/r/xyz", None));
        state.insert_room(room("R5", "mimi://a.example/r/r5", Some("日本")));
        let mut left = room("R6", "mimi://a.example/r/r6", Some("gone"));
        left.status = RoomStatus::Left;
        left.ext.insert("irc".into(), json!({"channel": "#gone"}));
        state.insert_room(left);

        let mut names = Names::new(ME);
        names.load(&mut state);
        assert_eq!(names.nick("mimi://b.example/u/carol"), "carol-kept");
        assert_eq!(names.nick("mimi://c.example/u/dave"), "dave-c");
        assert_eq!(state.people["P2"].ext["irc"], json!({"nick": "dave-c"}));
        assert_eq!(names.channel("R1"), Some("#kept"));
        assert_eq!(names.channel("R2"), Some("#lobby"));
        let r3 = names.channel("R3").unwrap().to_owned();
        assert_eq!(r3, format!("#LOBBY{}", suffix("mimi://a.example/r/r3", 0)));
        assert_eq!(names.channel("R4"), Some("#xyz"));
        assert_eq!(names.channel("R5"), Some("#r5"));
        assert_eq!(names.channel("R6"), None);
        assert!(!state.rooms["R6"].ext.contains_key("irc"));
        assert_eq!(state.rooms["R3"].ext["irc"], json!({"channel": r3}));
        assert_eq!(names.room_of("#LoBbY"), Some(&"R2".to_owned()));
        names.forget_room("R2");
        assert_eq!(names.room_of("#lobby"), None);
    }

    fn invite(number: u64, uri: Option<&str>, name: Option<&str>) -> Invite {
        Invite {
            number,
            inviter: Some("mimi://b.example/u/bob".to_owned()),
            room: uri.map(str::to_owned),
            room_name: name.map(str::to_owned),
            refused: true,
        }
    }

    /// Oracle: §7.13: a pending invite is shown under the channel its
    /// room will get by the §4 "Names" rules, the name held; JOIN of it
    /// accepts; the room takes it when it arrives; `&invite-<n>` when the
    /// Welcome could not be read.
    #[test]
    fn a_pending_invite_holds_its_rooms_channel_name() {
        let mut names = Names::new(ME);
        let pending = invite(1, Some("mimi://b.example/r/q1"), Some("B side!"));
        assert_eq!(names.invite_channel(&pending), "#Bside");
        // Assigned once.
        assert_eq!(names.invite_channel(&pending), "#Bside");
        assert_eq!(names.held("#bside"), Some(Held::Invite(1)));
        assert_eq!(names.held("#other"), None);
        // No usable name: the id part of the URI, as for a room.
        assert_eq!(
            names.invite_channel(&invite(2, Some("mimi://b.example/r/q2"), Some("日本"))),
            "#q2"
        );
        // Not read: the fallback, which holds nothing.
        assert_eq!(names.invite_channel(&invite(3, None, None)), "&invite-3");
        assert_eq!(names.held("&invite-3"), None);

        // Accepted: the name stays held, for the room, after the invite
        // is gone; then the room takes it.
        names.accepting(1, true);
        assert_eq!(names.held("#Bside"), Some(Held::Joining));
        names.forget_invite(1);
        assert_eq!(names.held("#Bside"), Some(Held::Joining));
        let mut r = room("R1", "mimi://b.example/r/q1", Some("renamed since"));
        names.note_room(&mut r);
        assert_eq!(names.channel("R1"), Some("#Bside"));
        assert_eq!(names.held("#Bside"), None);
        assert_eq!(r.ext["irc"], json!({"channel": "#Bside"}));

        // Accepting failed: the invite holds it again.
        names.accepting(2, true);
        names.accepting(2, false);
        assert_eq!(names.held("#q2"), Some(Held::Invite(2)));
        // Gone without being accepted (refused elsewhere): the name is
        // free again.
        names.forget_invite(2);
        assert_eq!(names.held("#q2"), None);
        assert_eq!(
            names.invite_channel(&invite(4, Some("mimi://b.example/r/q4"), Some("q2"))),
            "#q2"
        );
    }

    /// Oracle: §7.13: whichever comes first, a room or an invite, keeps
    /// the name; the later one gets the collision suffix of its own room
    /// URI, as two rooms do.
    #[test]
    fn invite_and_room_names_collide_first_come_first_kept() {
        let mut names = Names::new(ME);
        // A room shown first: the invite gets the suffix.
        let mut mine = room("R1", "mimi://a.example/r/mine", Some("bside"));
        names.note_room(&mut mine);
        let theirs = "mimi://b.example/r/theirs";
        let shown = names.invite_channel(&invite(1, Some(theirs), Some("bside")));
        assert_eq!(shown, format!("#bside{}", suffix(theirs, 0)));
        // The room arrives under the name the invite showed.
        let mut joined = room("R2", theirs, Some("bside"));
        names.note_room(&mut joined);
        assert_eq!(names.channel("R2"), Some(shown.as_str()));

        // An invite first: a room the user hosts afterwards, before
        // accepting, gets the suffix, and the invite keeps its name.
        let mut names = Names::new(ME);
        let pending = names.invite_channel(&invite(1, Some(theirs), Some("bside")));
        assert_eq!(pending, "#bside");
        let hosted = "mimi://a.example/r/hosted";
        let mut r = room("R3", hosted, Some("bside"));
        names.note_room(&mut r);
        assert_eq!(
            names.channel("R3"),
            Some(format!("#bside{}", suffix(hosted, 0)).as_str())
        );
        assert_eq!(names.held("#bside"), Some(Held::Invite(1)));
        // A second invite to the same room shares the name.
        assert_eq!(
            names.invite_channel(&invite(2, Some(theirs), Some("bside"))),
            "#bside"
        );
        names.forget_invite(1);
        assert_eq!(names.held("#bside"), Some(Held::Invite(2)));
        // Joined by the invite policy: the room takes the name before the
        // invite is forgotten.
        let mut r = room("R4", theirs, Some("bside"));
        names.note_room(&mut r);
        assert_eq!(names.channel("R4"), Some("#bside"));
        names.forget_invite(2);
        assert_eq!(names.room_of("#bside"), Some(&"R4".to_owned()));
    }

    #[test]
    fn channel_names_are_checked() {
        assert!(is_channel_name("#a"));
        assert!(is_channel_name("#a.b-c_9"));
        assert!(is_channel_name(&format!("#{}", "x".repeat(63))));
        assert!(!is_channel_name(&format!("#{}", "x".repeat(64))));
        for bad in ["#", "a", "#a b", "#a,b", "&x", "#é", "#a:b"] {
            assert!(!is_channel_name(bad), "{bad}");
        }
    }
}
