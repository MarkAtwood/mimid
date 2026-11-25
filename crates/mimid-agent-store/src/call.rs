//! The live-call announcement: the message that tells a chat a call has
//! started, and the extension a call-capable client reads off it
//! (bead mimid-1wgh.114.1).
//!
//! A call is its own MIMI room, parent-dependent on the chat
//! ([`crate::Store::start_call`]; room-policy-04 §5, decision
//! mimid-1wgh.113). Nothing in MIMI says a call is live, which is a gap
//! in the drafts rather than in mimid (bead mimid-1wgh.37.111), so the
//! announcement is an ordinary message in the PARENT chat: its text is a
//! sentence any client renders, and a private-use mimi-content-10 §4.3
//! extension carries what a client needs to join. A client that does not
//! know the key shows the sentence, which is the point of the design --
//! the user is told a call started rather than left wondering why a room
//! appeared.
//!
//! # The extension
//!
//! [`ANNOUNCEMENT_KEY`], an `ExtensionKey::Text`, with a map value
//! (decision mimid-1wgh.128, which superseded mimid-1wgh.116 and
//! mimid-1wgh.124):
//!
//! ```text
//! "tag:reviewcommit.com,2026:mimid:live-call": {
//!   "room":    "mimi://a.example/r/<call>",   required
//!   "ended":   true,                          optional, advisory
//!   "media":   ["audio", "video"],            optional
//!   "subject": "standup"                      optional
//! }
//! ```
//!
//! in RFC 8949 §4.2.1 bytewise key order, which content-10 §6.1 requires
//! of senders. INVENTED, NOT FROM SPEC, and provisional exactly as
//! component id `0xf021` is (decision mimid-1wgh.112): a private-use
//! value used now, with the upstream ask for a registered one in bead
//! mimid-1wgh.37.111.
//!
//! The sender and the time are NOT in the map: they are already the
//! message's, and two sources for one fact tempt a client to compute
//! liveness from the timestamp ("started forty minutes ago, probably
//! over"), which decision mimid-1wgh.117 forbids. `media` and `subject`
//! are descriptive rather than temporal, so they do not reopen that: they
//! are there because the receiving side projects a call from the room and
//! the room carries neither, so without them both are empty on every side
//! but the caller's (bead mimid-1wgh.114.11).
//!
//! # Liveness
//!
//! Decision mimid-1wgh.117: the announcement is an INVITATION, not a
//! liveness indicator. A front end renders it as a chat event and never
//! as a live badge. [`Announcement::ended`] is advisory -- its presence
//! means someone said the call is over, and its ABSENCE MEANS "not
//! known", never "still going", because a sender that crashes never sends
//! it. Liveness comes from joining the call room. There is no heartbeat
//! and no presence.
//!
//! An ended announcement is a NEW message, not an edit of the first: an
//! edit is only the sender's to make, and whoever ends a call need not be
//! whoever started it.
//!
//! # Limitations
//!
//! - Only mimid reads [`ANNOUNCEMENT_KEY`]. Another implementation keeps
//!   it unchanged and acts on nothing (§4.3), so its user sees the
//!   sentence and joins the call room by hand if their client can.
//! - A call started by another implementation has no announcement at all,
//!   so mimid learns of it from the invite to the call room.
//! - `room` is taken on the sender's word that it is a room they are in.
//!   The caller checks it ([`crate::Store`]); this module only decodes.

use mimi_content::{ExtensionKey, MimiContent, RawValue};

use mimid_agent_core::ContentOptions;

/// The private-use extension key of a call announcement (decision
/// mimid-1wgh.128). INVENTED, NOT FROM SPEC.
pub const ANNOUNCEMENT_KEY: &str = "tag:reviewcommit.com,2026:mimid:live-call";

/// The longest `room` URI read or sent. Room URIs are
/// `mimi://<domain>/r/<id>` (protocol-07 §2.1); this is far above any
/// real one and bounds what a peer can make us hold.
pub const MAX_ROOM_URI_LEN: usize = 512;

/// The longest `subject` read or sent.
pub const MAX_SUBJECT_LEN: usize = 256;

/// The most `media` kinds read or sent.
pub const MAX_MEDIA_KINDS: usize = 8;

/// The longest one `media` kind read or sent.
pub const MAX_MEDIA_KIND_LEN: usize = 32;

/// What a call announcement says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Announcement {
    /// The call room's MIMI URI, which is what a client joins. Not a
    /// store key: the announcement crosses providers and a store key is
    /// local.
    pub room: String,
    /// The media kinds, as draft-atwood-jmap-vtc-00 spells them
    /// (`"audio"`, `"video"`); empty when the sender said nothing.
    pub media: Vec<String>,
    /// The call's subject; empty when there is none.
    pub subject: String,
    /// Someone said the call is over. Advisory: see the module
    /// documentation and decision mimid-1wgh.117.
    pub ended: bool,
}

impl Announcement {
    /// A call starting in `room`.
    #[must_use]
    pub fn started(room: impl Into<String>) -> Self {
        Self {
            room: room.into(),
            ..Self::default()
        }
    }

    /// The announcement that `room`'s call is over.
    #[must_use]
    pub fn ended(room: impl Into<String>) -> Self {
        Self {
            room: room.into(),
            ended: true,
            ..Self::default()
        }
    }

    /// Whether this is sendable: a `room` within [`MAX_ROOM_URI_LEN`] and
    /// fields within their own limits. The limits are the same in both
    /// directions, so mimid never sends what it would refuse to read.
    #[must_use]
    pub fn is_sendable(&self) -> bool {
        !self.room.is_empty()
            && self.room.len() <= MAX_ROOM_URI_LEN
            && self.subject.len() <= MAX_SUBJECT_LEN
            && self.media.len() <= MAX_MEDIA_KINDS
            && self
                .media
                .iter()
                .all(|kind| !kind.is_empty() && kind.len() <= MAX_MEDIA_KIND_LEN)
    }

    /// The sentence a client with no knowledge of the key renders, with
    /// `who` as the caller's name when one is known.
    ///
    /// It names the caller only when `who` is given, because the sender
    /// is already the message's: a client that shows the sender beside
    /// the text would otherwise print the name twice.
    #[must_use]
    pub fn text(&self, who: Option<&str>) -> String {
        let kind = if self.media.iter().any(|m| m == "video") {
            "video call"
        } else {
            "call"
        };
        let verb = if self.ended {
            format!("ended the {kind}")
        } else {
            format!("started a {kind}")
        };
        let mut line = match who {
            Some(name) if !name.is_empty() => format!("{name} {verb}"),
            _ => verb,
        };
        if !self.subject.is_empty() && !self.ended {
            line.push_str(": ");
            line.push_str(&self.subject);
        }
        line
    }

    /// The message options that carry this announcement, or `None` if it
    /// is not [`Announcement::is_sendable`].
    #[must_use]
    pub fn content_options(&self) -> Option<ContentOptions> {
        if !self.is_sendable() {
            return None;
        }
        let mut options = ContentOptions::new();
        // Valid deterministic CBOR by construction, and `RawValue::new`
        // is what proves it rather than a comment: a mistake here is a
        // refused value, not a bad message on the wire.
        let value = RawValue::new(&self.value()).ok()?;
        options
            .extensions
            .insert(ExtensionKey::Text(ANNOUNCEMENT_KEY.to_owned()), value);
        Some(options)
    }

    /// The map's deterministic encoding (RFC 8949 §4.2.1, content-10
    /// §6.1): keys in bytewise order, which for these four is `room`,
    /// `ended`, `media`, `subject`, and an absent field is an absent key
    /// rather than a null.
    fn value(&self) -> Vec<u8> {
        let mut entries: Vec<Vec<u8>> = Vec::with_capacity(4);
        entries.push([text(b"room"), text(self.room.as_bytes())].concat());
        if self.ended {
            entries.push([text(b"ended"), vec![0xf5]].concat());
        }
        if !self.media.is_empty() {
            let mut array = vec![0x80 | u8::try_from(self.media.len()).unwrap_or(0)];
            for kind in &self.media {
                array.extend(text(kind.as_bytes()));
            }
            entries.push([text(b"media"), array].concat());
        }
        if !self.subject.is_empty() {
            entries.push([text(b"subject"), text(self.subject.as_bytes())].concat());
        }
        let mut out = vec![0xa0 | u8::try_from(entries.len()).unwrap_or(0)];
        for entry in entries {
            out.extend(entry);
        }
        out
    }
}

/// `content`'s call announcement, or `None` if it carries none or one
/// this version cannot read.
///
/// The value's CBOR was already checked against content-10 §6.1 when the
/// message was decoded (`RawValue`), so this reads definite lengths and
/// bytewise-ordered keys without re-proving them. It still fails closed:
/// anything unexpected gives `None` rather than a partly-read
/// announcement, and an unknown key is skipped so a later field can be
/// added without a second extension key, which is why decision
/// mimid-1wgh.116 chose a map over a bare string.
#[must_use]
pub fn announcement(content: &MimiContent) -> Option<Announcement> {
    let key = ExtensionKey::Text(ANNOUNCEMENT_KEY.to_owned());
    let value = content.mimi_extensions.other.get(&key)?;
    decode(value.as_bytes())
}

/// The call announcement among a record's kept extensions
/// ([`crate::record::Message::extensions`]), or `None` if there is none.
///
/// This is the receiving side: the announcement arrives as an ordinary
/// message, so every front end already renders its text, and a front end
/// that can offer Join reads the call room off it with this. Nothing
/// else is needed to receive one.
///
/// Decision mimid-1wgh.117 governs what a front end does with it: render
/// it as a chat event, NEVER as a live badge. The absence of an
/// [`Announcement::ended`] does not mean the call is still going.
#[must_use]
pub fn in_record(extensions: &[crate::record::Extension]) -> Option<Announcement> {
    let name = crate::record::ExtensionName::Text(ANNOUNCEMENT_KEY.to_owned());
    let found = extensions.iter().find(|held| held.name == name)?;
    decode(&found.octets()?)
}

/// [`announcement`] from the extension value's bytes.
fn decode(bytes: &[u8]) -> Option<Announcement> {
    let (&head, mut rest) = bytes.split_first()?;
    // A map of at most 23 pairs, which is every shape this key defines
    // and well past the four it has.
    let pairs = match head {
        0xa0..=0xb7 => usize::from(head & 0x1f),
        _ => return None,
    };
    let mut found = Announcement::default();
    for _ in 0..pairs {
        let (name, after) = read_text(rest, MAX_KEY_LEN)?;
        rest = after;
        match name.as_str() {
            "room" => {
                let (room, after) = read_text(rest, MAX_ROOM_URI_LEN)?;
                found.room = room;
                rest = after;
            }
            "subject" => {
                let (subject, after) = read_text(rest, MAX_SUBJECT_LEN)?;
                found.subject = subject;
                rest = after;
            }
            "ended" => {
                let (&flag, after) = rest.split_first()?;
                // Only `true` means anything (decision mimid-1wgh.117:
                // its presence is the statement). `false` is read as what
                // it says and is not an error.
                found.ended = match flag {
                    0xf5 => true,
                    0xf4 => false,
                    _ => return None,
                };
                rest = after;
            }
            "media" => {
                let (&count, after) = rest.split_first()?;
                let count = match count {
                    0x80..=0x97 => usize::from(count & 0x1f),
                    _ => return None,
                };
                if count > MAX_MEDIA_KINDS {
                    return None;
                }
                rest = after;
                for _ in 0..count {
                    let (kind, after) = read_text(rest, MAX_MEDIA_KIND_LEN)?;
                    found.media.push(kind);
                    rest = after;
                }
            }
            // A field a later version added: skipped, not refused.
            _ => rest = skip(rest)?,
        }
    }
    // Trailing bytes are not one item, and `room` is the one field
    // without which there is nothing to join.
    if !rest.is_empty() || found.room.is_empty() {
        return None;
    }
    Some(found)
}

/// The longest map key read. Every key this version defines is far
/// shorter; the cap is what stops an unknown one being unbounded.
const MAX_KEY_LEN: usize = 64;

/// The deterministic encoding of the text string `value` (major type 3,
/// shortest form). Lengths past `u16` do not arise: every caller is
/// bounded by a constant of this module.
fn text(value: &[u8]) -> Vec<u8> {
    let len = value.len();
    let mut out = match len {
        0..=0x17 => vec![0x60 | u8::try_from(len).unwrap_or(0)],
        0x18..=0xff => vec![0x78, u8::try_from(len).unwrap_or(0xff)],
        _ => [
            &[0x79][..],
            &u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes(),
        ]
        .concat(),
    };
    out.extend_from_slice(value);
    out
}

/// One text string of at most `max` octets, and what follows it.
fn read_text(bytes: &[u8], max: usize) -> Option<(String, &[u8])> {
    let (&head, rest) = bytes.split_first()?;
    // Major type 3 in shortest form (RFC 8949 §4.2.1), up to `u16`.
    let (len, rest): (usize, &[u8]) = match head {
        0x60..=0x77 => (usize::from(head & 0x1f), rest),
        0x78 => {
            let (&v, rest) = rest.split_first()?;
            (v >= 24).then_some((usize::from(v), rest))?
        }
        0x79 => {
            let (v, rest) = rest.split_first_chunk::<2>()?;
            let v = u16::from_be_bytes(*v);
            (v > 0xff).then_some((usize::from(v), rest))?
        }
        _ => return None,
    };
    if len > max {
        return None;
    }
    let (value, rest) = rest.split_at_checked(len)?;
    Some((std::str::from_utf8(value).ok()?.to_owned(), rest))
}

/// Steps over one item, for a key this version does not know. Only the
/// shapes a map value can be here: a text or byte string, an unsigned or
/// negative integer, a simple value, or an array of those one deep. Maps
/// and deeper nesting are refused rather than guessed at, which costs a
/// skipped announcement and not a misread one.
fn skip(bytes: &[u8]) -> Option<&[u8]> {
    let (&head, rest) = bytes.split_first()?;
    match head {
        // Integers and strings: the argument, then that many octets for
        // a string.
        0x00..=0x3b | 0x40..=0x5b | 0x60..=0x7b => {
            let (len, rest) = argument(head, rest)?;
            if (0x40..=0x5b).contains(&head) || (0x60..=0x7b).contains(&head) {
                return rest.split_at_checked(len).map(|(_, rest)| rest);
            }
            Some(rest)
        }
        // `false`, `true`, `null`, `undefined`.
        0xf4..=0xf7 => Some(rest),
        // An array of simple items, one deep.
        0x80..=0x97 => {
            let mut rest = rest;
            for _ in 0..usize::from(head & 0x1f) {
                rest = skip_simple(rest)?;
            }
            Some(rest)
        }
        _ => None,
    }
}

/// [`skip`] for an array's element: no nesting at all.
fn skip_simple(bytes: &[u8]) -> Option<&[u8]> {
    let (&head, _) = bytes.split_first()?;
    match head {
        0x80..=0x97 | 0xa0..=0xb7 => None,
        _ => skip(bytes),
    }
}

/// The argument of `head`, in shortest form, and what follows it.
fn argument(head: u8, rest: &[u8]) -> Option<(usize, &[u8])> {
    match head & 0x1f {
        n @ 0..=23 => Some((usize::from(n), rest)),
        24 => {
            let (&v, rest) = rest.split_first()?;
            (v >= 24).then_some((usize::from(v), rest))?.into()
        }
        25 => {
            let (v, rest) = rest.split_first_chunk::<2>()?;
            let v = u16::from_be_bytes(*v);
            (v > 0xff).then_some((usize::from(v), rest))?.into()
        }
        26 => {
            let (v, rest) = rest.split_first_chunk::<4>()?;
            let v = u32::from_be_bytes(*v);
            (v > 0xffff)
                .then_some((usize::try_from(v).ok()?, rest))?
                .into()
        }
        _ => None,
    }
}
