//! Disappearing messages (docs/design/agent-frontends.md §7.20 to §7.23;
//! bead mimid-tu1g): when the store deletes a message by itself.
//!
//! A message is deleted at the earliest of its deadlines ([`deadline`]):
//!
//! - **The sender's time** ([`MessageExpiry::sender_expires_at`]): every
//!   copy goes at that time, the sender's own included. On the wire it is
//!   mimi-content-10 §4.1 `expires` with `relative` false, the time in
//!   whole seconds since the UNIX epoch; in JMAP Chat, the Message's
//!   `senderExpiresAt` (draft-atwood-jmap-chat-00 §Message).
//! - **The room's policy** ([`crate::record::Room::message_expiry_seconds`]):
//!   local, never sent (draft-atwood-jmap-chat-00 §Chat
//!   `messageExpirySeconds`); a message older than that, counted from its
//!   arrival here, goes.
//! - **The read** ([`MessageExpiry::burn_on_read`],
//!   [`MessageExpiry::expires_after_read_seconds`]): a received copy goes
//!   when the user reads it, or so many seconds after; the sender's copy
//!   stays. On the wire the rule is mimi-content-10 §4.1 `expires` with
//!   `relative` true ("a relative amount of time after the receiving
//!   client reads the message"), so other implementations honour it:
//!   `[true, N]` for delete after N seconds, `[true, 0]` for burn on
//!   read. Only a message that also has the sender's time, which then
//!   takes `expires`, carries its read rule in mimid's own extension,
//!   [`READ_EXPIRY_KEY`] (INVENTED, NOT FROM SPEC; decision
//!   mimid-1wgh.84), which only mimid honours. Both are honoured when
//!   received; the earlier deadline wins.
//!
//! The deletion ([`crate::Store::expire_due`]) is the local delete's
//! ([`crate::State::delete_message`]): the record goes, with a tombstone
//! of its versions that keeps a delivery of it again from storing it; its
//! attachments waiting for a retry go, and so do its blobs that nothing
//! else names, after the save that writes the deletion. Every front end
//! is told ([`crate::Change::MessageExpired`]). A received message whose
//! deadline has passed when it arrives is not stored
//! (draft-atwood-jmap-chat-00 §Message `senderExpiresAt`: "Servers MUST
//! reject a `senderExpiresAt` value that is already in the past at
//! delivery time").
//!
//! The deadlines are kept in the records, so a deletion due while the
//! agent was stopped happens at its next start, and one due later is
//! still kept: whatever drives the store (the daemon) waits for
//! [`crate::Store::next_expiry`] and calls [`crate::Store::expire_now`].
//!
//! # Limitations
//!
//! - [`crate::Store::next_expiry`] and [`crate::Store::expire_due`] walk
//!   every message.
//! - Deleted blobs go after the save; a crash between the two leaves them
//!   to the blob store's quota, which evicts unreferenced blobs.
//! - What a front end showed before the deletion stays on the user's
//!   screen: an IRC client keeps its lines.
//! - Only mimid honours [`READ_EXPIRY_KEY`]; another implementation
//!   keeps a message with both the sender's time and a read rule as if
//!   it had no read rule.
//! - `[true, 0]` as burn on read is mimid's reading of §4.1, which does
//!   not say what zero seconds means; the WG has been asked
//!   (draft-ietf-mimi-content issue 93).
//! - A message with both `burnOnRead` and `expiresAfterReadSeconds` and
//!   no sender's time is sent as `[true, 0]` alone: burn wins at the
//!   receiver, which sees no `expiresAfterReadSeconds`.

use std::collections::BTreeSet;

use mimi_content::{Expiration, ExtensionKey, MimiContent, RawValue};
use mimid_agent_core::ContentOptions;

use crate::change::Change;
use crate::db::FileError;
use crate::record::{Key, Message, MessageExpiry, Room, Sender};
use crate::store::Store;
use crate::sync::now_ms;

/// The mimiExtensions key under which mimid sends a message's read rule
/// (burn on read, and delete so many seconds after the read) when the
/// message also has the sender's time, which takes the standard
/// `expires` (mimi-content-10 §4.3 "private use" text key). INVENTED,
/// NOT FROM SPEC (decision mimid-1wgh.84). Its value is
///
/// ```cddl
/// readExpiry = [
///     burnOnRead: bool,
///     expiresAfterReadSeconds: null / uint .size 4,
/// ]
/// ```
///
/// in deterministic encoding (§6.1); the extension is sent only when one
/// of the two is set and `senderExpiresAt` is too. Other implementations
/// ignore it (§4.3: unknown extensions are kept, not acted on).
pub const READ_EXPIRY_KEY: &str = "mimid-read-expiry";

/// mimi-content-10 §9.1 calls an `expires` "more than a year in the past"
/// or "more than a year in the future" nonsensical, to be logged and
/// discarded; a year here is 365 days, in seconds.
pub const ONE_YEAR_SECS: u64 = 365 * 24 * 60 * 60;

/// Why a message's expiry cannot be sent ([`check_outgoing`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExpiryError {
    /// `senderExpiresAt` is not after now (draft-atwood-jmap-chat-00
    /// §Message `senderExpiresAt`: "Servers MUST reject a `senderExpiresAt`
    /// value that is already in the past").
    #[error("senderExpiresAt is not in the future")]
    InThePast,
    /// `senderExpiresAt` is more than [`ONE_YEAR_SECS`] ahead: receivers
    /// discard such a message (mimi-content-10 §9.1).
    #[error("senderExpiresAt is more than a year ahead; receivers discard such a message")]
    TooFarAhead,
    /// `expiresAfterReadSeconds` is more than [`ONE_YEAR_SECS`]: sent as a
    /// relative `expires`, receivers discard such a message
    /// (mimi-content-10 §9.1).
    #[error("expiresAfterReadSeconds is more than a year; receivers discard such a message")]
    ReadTooLong,
}

/// What a received message's `expires` and extensions ask, or why the
/// message is discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Received {
    /// Store it, with this expiry; a malformed [`READ_EXPIRY_KEY`] value
    /// is ignored, and said why.
    Expiry(MessageExpiry, Option<String>),
    /// mimi-content-10 §9.1: "nonsensical values that most likely
    /// represent malicious messages. These should be logged and
    /// discarded."
    Discard(String),
}

/// What `content`, received at `now` (milliseconds), asks
/// (see the module documentation).
pub(crate) fn received(content: &MimiContent, now: u64) -> Received {
    let now_secs = now / 1000;
    let mut expiry = MessageExpiry::default();
    match content.expires {
        None => {}
        Some(Expiration::Absolute(at)) => {
            let at = u64::from(at);
            if at.saturating_add(ONE_YEAR_SECS) < now_secs {
                return Received::Discard(
                    "its expires is more than a year in the past (mimi-content-10 §9.1)".into(),
                );
            }
            if at > now_secs.saturating_add(ONE_YEAR_SECS) {
                return Received::Discard(
                    "its expires is more than a year in the future (mimi-content-10 §9.1)".into(),
                );
            }
            expiry.sender_expires_at = Some(at * 1000);
        }
        Some(Expiration::Relative(seconds)) => {
            if u64::from(seconds) > ONE_YEAR_SECS {
                return Received::Discard(
                    "its expires is more than a year in the future (mimi-content-10 §9.1)".into(),
                );
            }
            // mimi-content-10 §4.1; decision mimid-1wgh.84: zero seconds
            // after the read is burn on read (asked of the WG in
            // draft-ietf-mimi-content issue 93).
            if seconds == 0 {
                expiry.burn_on_read = true;
            } else {
                expiry.expires_after_read_seconds = Some(seconds);
            }
        }
    }
    let key = ExtensionKey::Text(READ_EXPIRY_KEY.to_owned());
    let mut problem = None;
    if let Some(value) = content.mimi_extensions.other.get(&key) {
        match parse_read_expiry(value.as_bytes()) {
            Some((burn, after)) => {
                expiry.burn_on_read |= burn;
                // The earlier rule wins, as for every deadline.
                expiry.expires_after_read_seconds = match (expiry.expires_after_read_seconds, after)
                {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
            None => {
                problem = Some(format!(
                    "a {READ_EXPIRY_KEY} extension that is not [bool, null / uint] was ignored"
                ));
            }
        }
    }
    Received::Expiry(expiry, problem)
}

/// The value of [`READ_EXPIRY_KEY`]: `[burn, after]`, or `None` if the
/// value is anything else, in any encoding but the deterministic one.
fn parse_read_expiry(bytes: &[u8]) -> Option<(bool, Option<u32>)> {
    let (&array, rest) = bytes.split_first()?;
    if array != 0x82 {
        return None;
    }
    let (&flag, rest) = rest.split_first()?;
    let burn = match flag {
        0xf4 => false,
        0xf5 => true,
        _ => return None,
    };
    let (&head, rest) = rest.split_first()?;
    // Major type 0, shortest form (RFC 8949 §4.2.1), at most 4 octets.
    let (after, rest): (u32, &[u8]) = match head {
        0xf6 => return rest.is_empty().then_some((burn, None)),
        0x00..=0x17 => (u32::from(head), rest),
        0x18 => {
            let (&v, rest) = rest.split_first()?;
            (v >= 24).then_some((u32::from(v), rest))?
        }
        0x19 => {
            let (v, rest) = rest.split_first_chunk::<2>()?;
            let v = u16::from_be_bytes(*v);
            (v > 0xff).then_some((u32::from(v), rest))?
        }
        0x1a => {
            let (v, rest) = rest.split_first_chunk::<4>()?;
            let v = u32::from_be_bytes(*v);
            (v > 0xffff).then_some((v, rest))?
        }
        _ => return None,
    };
    rest.is_empty().then_some((burn, Some(after)))
}

/// The deterministic encoding of `[burn, after]`.
fn read_expiry_value(burn: bool, after: Option<u32>) -> Vec<u8> {
    let mut out = vec![0x82, if burn { 0xf5 } else { 0xf4 }];
    match after {
        None => out.push(0xf6),
        Some(v) => out.extend(crate::expiry::uint(v)),
    }
    out
}

/// `v` as a CBOR unsigned integer, shortest form.
fn uint(v: u32) -> Vec<u8> {
    match v {
        0..=0x17 => vec![v as u8],
        0x18..=0xff => vec![0x18, v as u8],
        0x100..=0xffff => [&[0x19][..], &(v as u16).to_be_bytes()].concat(),
        _ => [&[0x1a][..], &v.to_be_bytes()].concat(),
    }
}

/// Checks that `expiry` may be sent at `now` (milliseconds): a
/// `senderExpiresAt` after now and at most a year ahead, and an
/// `expiresAfterReadSeconds` of at most a year.
///
/// # Errors
///
/// [`ExpiryError`].
pub fn check_outgoing(expiry: &MessageExpiry, now: u64) -> Result<(), ExpiryError> {
    if let Some(at) = expiry.sender_expires_at {
        if at <= now {
            return Err(ExpiryError::InThePast);
        }
        if at / 1000 > (now / 1000).saturating_add(ONE_YEAR_SECS) {
            return Err(ExpiryError::TooFarAhead);
        }
    }
    if expiry
        .expires_after_read_seconds
        .is_some_and(|s| u64::from(s) > ONE_YEAR_SECS)
    {
        return Err(ExpiryError::ReadTooLong);
    }
    Ok(())
}

/// `expiry` with its `senderExpiresAt` cut to the whole second, as
/// `expires` carries it (`at or before this time`, draft-atwood-jmap-chat-00
/// §Message): what is sent and what the sender's copy keeps.
#[must_use]
pub fn to_whole_seconds(mut expiry: MessageExpiry) -> MessageExpiry {
    expiry.sender_expires_at = expiry.sender_expires_at.map(|at| at / 1000 * 1000);
    expiry
}

/// What a message with `expiry` carries on the wire (decision
/// mimid-1wgh.84): `expires` absolute for the sender's time; without
/// one, `expires` relative for a read rule, `[true, 0]` for burn on read
/// and `[true, N]` for N seconds after it; with one, the read rule in
/// [`READ_EXPIRY_KEY`].
pub(crate) fn content_options(expiry: &MessageExpiry) -> ContentOptions {
    let mut options = ContentOptions::new();
    let Some(at) = expiry.sender_expires_at else {
        options.expires = if expiry.burn_on_read {
            Some(Expiration::Relative(0))
        } else {
            expiry.expires_after_read_seconds.map(Expiration::Relative)
        };
        return options;
    };
    options.expires = Some(Expiration::Absolute(
        u32::try_from(at / 1000).unwrap_or(u32::MAX),
    ));
    if expiry.counts_from_read() {
        let value = read_expiry_value(expiry.burn_on_read, expiry.expires_after_read_seconds);
        // The encoding above is one valid item by construction.
        if let Ok(value) = RawValue::new(&value) {
            options
                .extensions
                .insert(ExtensionKey::Text(READ_EXPIRY_KEY.to_owned()), value);
        }
    }
    options
}

/// When `message` in `room` is to be deleted, in milliseconds, for the
/// store of `user`; `None` if never. A message is deleted once now is at
/// or past it.
#[must_use]
pub fn deadline(message: &Message, room: Option<&Room>, user: &str) -> Option<u64> {
    let mut at = message.expiry.sender_expires_at;
    let mut earliest = |t: u64| at = Some(at.map_or(t, |a| a.min(t)));
    if let Some(seconds) = room
        .and_then(|r| r.message_expiry_seconds)
        .filter(|s| *s > 0)
    {
        // "older than this many seconds": strictly more.
        earliest(
            message
                .received_at
                .saturating_add(seconds.saturating_mul(1000))
                .saturating_add(1),
        );
    }
    let received = matches!(&message.sender, Sender::User(u) if u != user);
    if received && let Some(read) = message.read_at {
        if message.expiry.burn_on_read {
            earliest(read);
        }
        if let Some(seconds) = message.expiry.expires_after_read_seconds {
            earliest(read.saturating_add(u64::from(seconds) * 1000));
        }
    }
    at
}

impl Store {
    /// Wakes whatever waits for the next deletion ([`Store::next_expiry`]):
    /// a deadline may have come nearer.
    #[must_use]
    pub fn expiry_wanted(&self) -> &std::sync::Arc<tokio::sync::Notify> {
        &self.expiry_wake
    }

    pub(crate) fn want_expiry(&self) {
        self.expiry_wake.notify_one();
    }

    /// The earliest deadline of any message, in milliseconds ([`deadline`]).
    #[must_use]
    pub fn next_expiry(&self) -> Option<u64> {
        let state = self.state();
        state
            .messages
            .values()
            .filter_map(|m| deadline(m, state.rooms.get(&m.room), &self.user))
            .min()
    }

    /// Deletes every message whose deadline is at or before `now`
    /// (milliseconds), each a [`Change::MessageExpired`], and returns their
    /// keys. The next save writes the deletions and then deletes their
    /// blobs that nothing names any more.
    pub fn expire_due(&self, now: u64) -> Vec<Key> {
        let state = self.state();
        let due: Vec<Key> = state
            .messages
            .values()
            .filter(|m| deadline(m, state.rooms.get(&m.room), &self.user).is_some_and(|d| d <= now))
            .map(|m| m.key.clone())
            .collect();
        drop(state);
        for key in &due {
            self.expire(key);
        }
        if !due.is_empty() {
            tracing::debug!(count = due.len(), "messages deleted at their expiry");
        }
        due
    }

    /// Deletes message `key` now, as at its expiry ([`Store::expire_due`]):
    /// the record, with a tombstone, and its blobs after the next save; a
    /// [`Change::MessageExpired`]. False if there is no such message.
    pub fn expire(&self, key: &str) -> bool {
        let Some(message) = self.state().expire_message(key) else {
            return false;
        };
        self.record([Change::MessageExpired(key.to_owned())]);
        let blobs: BTreeSet<String> = message.attachments.into_iter().map(|a| a.blob_id).collect();
        self.delete_blobs_of_expired(blobs);
        true
    }

    /// [`Store::expire_due`] now, and a save if anything was deleted;
    /// returns how many were.
    ///
    /// # Errors
    ///
    /// Those of [`Store::save`]; the deletions are then in memory, and
    /// the next save writes them.
    pub async fn expire_now(&self) -> Result<usize, FileError> {
        let due = self.expire_due(now_ms());
        if !due.is_empty() {
            self.save().await?;
        }
        Ok(due.len())
    }

    /// Records that the user read message `key` at `at` (milliseconds),
    /// if it is a received message with a read rule not read before: a
    /// burn-on-read message is deleted at once, as [`Store::expire_due`]
    /// deletes, and one deleted some seconds after the read gets its
    /// deadline. What a front end counts as a read is its own
    /// (docs/design/agent-frontends.md §7.22). The caller saves. Returns
    /// whether anything changed.
    pub fn mark_read(&self, key: &str, at: u64) -> bool {
        let mut state = self.state();
        let Some(message) = state.messages.get_mut(key) else {
            return false;
        };
        let received = matches!(&message.sender, Sender::User(u) if *u != self.user);
        if !received || !message.expiry.counts_from_read() || message.read_at.is_some() {
            return false;
        }
        message.read_at = Some(at);
        let burn = message.expiry.burn_on_read;
        drop(state);
        if burn {
            self.expire(key);
        } else {
            self.want_expiry();
        }
        true
    }

    /// Sets the local expiry policy of room `key`
    /// ([`Room::message_expiry_seconds`]; 0 or `None` for none), a
    /// [`Change::RoomChanged`]; messages it makes due go at the next
    /// [`Store::expire_now`]. False if there is no such room.
    pub fn set_message_expiry(&self, key: &str, seconds: Option<u64>) -> bool {
        let seconds = seconds.filter(|s| *s > 0);
        let mut state = self.state();
        let Some(room) = state.rooms.get_mut(key) else {
            return false;
        };
        if room.message_expiry_seconds != seconds {
            room.message_expiry_seconds = seconds;
            drop(state);
            self.record([Change::RoomChanged(key.to_owned())]);
            self.want_expiry();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Ext;
    use mimi_content::{Disposition, Extensions, NestedPart, Part};

    const ME: &str = "mimi://a.example/u/me";
    const PEER: &str = "mimi://a.example/u/peer";

    fn content(expires: Option<Expiration>, ext: Option<&[u8]>) -> MimiContent {
        let mut other = std::collections::BTreeMap::new();
        if let Some(bytes) = ext {
            other.insert(
                ExtensionKey::Text(READ_EXPIRY_KEY.to_owned()),
                RawValue::new(bytes).unwrap(),
            );
        }
        MimiContent {
            salt: [0; 16],
            replaces: None,
            topic_id: vec![],
            expires,
            in_reply_to: None,
            mimi_extensions: Extensions {
                sender_uri: None,
                room_uri: None,
                other,
            },
            nested_part: NestedPart {
                disposition: Disposition::RENDER,
                language: String::new(),
                part: Part::Null,
            },
        }
    }

    /// Oracle: RFC 8949 §3 and §4.2.1, the encodings written out by hand.
    #[test]
    fn the_read_expiry_value_is_deterministic_cbor() {
        assert_eq!(read_expiry_value(true, None), [0x82, 0xf5, 0xf6]);
        assert_eq!(read_expiry_value(false, Some(0)), [0x82, 0xf4, 0x00]);
        assert_eq!(read_expiry_value(false, Some(23)), [0x82, 0xf4, 0x17]);
        assert_eq!(read_expiry_value(false, Some(24)), [0x82, 0xf4, 0x18, 0x18]);
        assert_eq!(
            read_expiry_value(true, Some(300)),
            [0x82, 0xf5, 0x19, 0x01, 0x2c]
        );
        assert_eq!(
            read_expiry_value(false, Some(u32::MAX)),
            [0x82, 0xf4, 0x1a, 0xff, 0xff, 0xff, 0xff]
        );
        for (burn, after) in [(true, None), (false, Some(5)), (true, Some(70_000))] {
            let bytes = read_expiry_value(burn, after);
            assert_eq!(parse_read_expiry(&bytes), Some((burn, after)));
        }
    }

    /// Oracle: §6.1 deterministic encoding and the CDDL in
    /// [`READ_EXPIRY_KEY`]: anything else is not a read rule.
    #[test]
    fn a_read_expiry_value_in_any_other_form_is_refused() {
        for bad in [
            &[][..],
            &[0x82, 0xf5],                               // short
            &[0x83, 0xf5, 0xf6, 0xf6],                   // three items
            &[0x82, 0x01, 0xf6],                         // not a bool
            &[0x82, 0xf5, 0x18, 0x05],                   // not shortest form
            &[0x82, 0xf5, 0x19, 0x00, 0xff],             // not shortest form
            &[0x82, 0xf5, 0x1b, 0, 0, 0, 1, 0, 0, 0, 0], // past uint .size 4
            &[0x82, 0xf5, 0x20],                         // negative
            &[0x82, 0xf5, 0xf6, 0x00],                   // trailing
            &[0x9f, 0xf5, 0xf6, 0xff],                   // indefinite length
        ] {
            assert_eq!(parse_read_expiry(bad), None, "{bad:02x?}");
        }
    }

    /// Oracle: mimi-content-10 §4.1 (absolute: seconds since the epoch;
    /// relative: seconds after the read, zero being burn on read by
    /// decision mimid-1wgh.84), §9.1 (a year either way is discarded) and
    /// [`READ_EXPIRY_KEY`].
    #[test]
    fn a_received_expiry_maps_to_the_record() {
        let now = 1_800_000_000_000; // ms
        let secs = 1_800_000_000u32;
        let expiry = |c: &MimiContent| match received(c, now) {
            Received::Expiry(e, None) => e,
            other => panic!("{other:?}"),
        };
        assert_eq!(expiry(&content(None, None)), MessageExpiry::default());
        let e = expiry(&content(Some(Expiration::Absolute(secs + 600)), None));
        assert_eq!(e.sender_expires_at, Some((u64::from(secs) + 600) * 1000));
        let e = expiry(&content(Some(Expiration::Relative(30)), None));
        assert_eq!(e.expires_after_read_seconds, Some(30));
        assert!(!e.burn_on_read && e.sender_expires_at.is_none());
        let e = expiry(&content(Some(Expiration::Relative(0)), None));
        assert_eq!(
            e,
            MessageExpiry {
                burn_on_read: true,
                ..MessageExpiry::default()
            }
        );
        // The extension cannot take back a burn the relative expires asks.
        let e = expiry(&content(
            Some(Expiration::Relative(0)),
            Some(&[0x82, 0xf4, 0x0a]),
        ));
        assert!(e.burn_on_read);
        assert_eq!(e.expires_after_read_seconds, Some(10));
        // A time already past is kept, so the store can drop the message
        // as expired.
        let e = expiry(&content(Some(Expiration::Absolute(secs - 10)), None));
        assert_eq!(e.sender_expires_at, Some((u64::from(secs) - 10) * 1000));
        let e = expiry(&content(None, Some(&[0x82, 0xf5, 0xf6])));
        assert!(e.burn_on_read && e.expires_after_read_seconds.is_none());
        // Both a relative expires and the extension: the earlier.
        let e = expiry(&content(
            Some(Expiration::Relative(30)),
            Some(&[0x82, 0xf4, 0x0a]),
        ));
        assert_eq!(e.expires_after_read_seconds, Some(10));

        let year = ONE_YEAR_SECS as u32;
        for c in [
            content(Some(Expiration::Absolute(secs + year + 1)), None),
            content(Some(Expiration::Absolute(secs - year - 1)), None),
            content(Some(Expiration::Relative(year + 1)), None),
        ] {
            assert!(matches!(received(&c, now), Received::Discard(_)), "{c:?}");
        }
        assert!(matches!(
            received(&content(Some(Expiration::Absolute(secs + year)), None), now),
            Received::Expiry(..)
        ));
        // A malformed read rule is ignored, not the message.
        match received(&content(None, Some(&[0x82, 0x01, 0xf6])), now) {
            Received::Expiry(e, Some(_)) => assert!(e.is_none()),
            other => panic!("{other:?}"),
        }
    }

    /// Oracle: the sender's side of the same mapping (decision
    /// mimid-1wgh.84): absolute `expires` in whole seconds; a read rule
    /// alone as relative `expires`, `[true, 0]` for burn on read and
    /// `[true, N]` for N seconds; beside a sender's time, the read rule in
    /// [`READ_EXPIRY_KEY`]; and what is sent reads back as what was
    /// asked.
    #[test]
    fn an_outgoing_expiry_maps_to_the_content_and_back() {
        let sent = |options: &ContentOptions| {
            let mut c = content(None, None);
            c.expires = options.expires;
            c.mimi_extensions.other = options.extensions.clone();
            c
        };
        let burn = MessageExpiry {
            burn_on_read: true,
            ..MessageExpiry::default()
        };
        let after = MessageExpiry {
            expires_after_read_seconds: Some(30),
            ..MessageExpiry::default()
        };
        for (expiry, expires) in [
            (burn, Expiration::Relative(0)),
            (after, Expiration::Relative(30)),
        ] {
            let options = content_options(&expiry);
            assert_eq!(options.expires, Some(expires));
            assert!(options.extensions.is_empty(), "{expiry:?}");
            assert_eq!(
                received(&sent(&options), 1_800_000_000_000),
                Received::Expiry(expiry, None)
            );
        }
        // Burn wins, so it alone is sent.
        let both = content_options(&MessageExpiry {
            burn_on_read: true,
            expires_after_read_seconds: Some(30),
            ..MessageExpiry::default()
        });
        assert_eq!(both.expires, Some(Expiration::Relative(0)));
        assert!(both.extensions.is_empty());

        let expiry = MessageExpiry {
            sender_expires_at: Some(1_800_000_600_000),
            burn_on_read: true,
            expires_after_read_seconds: Some(60),
        };
        let options = content_options(&expiry);
        assert_eq!(options.expires, Some(Expiration::Absolute(1_800_000_600)));
        assert_eq!(
            options.extensions.keys().collect::<Vec<_>>(),
            [&ExtensionKey::Text(READ_EXPIRY_KEY.to_owned())]
        );
        assert_eq!(
            received(&sent(&options), 1_800_000_000_000),
            Received::Expiry(expiry, None)
        );
        let none = content_options(&MessageExpiry::default());
        assert!(none.expires.is_none() && none.extensions.is_empty());
        let timed = content_options(&MessageExpiry {
            sender_expires_at: Some(1_000),
            ..MessageExpiry::default()
        });
        assert!(timed.extensions.is_empty());
    }

    /// Oracle: draft-atwood-jmap-chat-00 §Message `senderExpiresAt` (a
    /// past value is rejected) and mimi-content-10 §9.1 (a year ahead,
    /// absolute or relative).
    #[test]
    fn an_outgoing_time_must_be_ahead_and_within_a_year() {
        let now = 1_800_000_000_000;
        let at = |t| MessageExpiry {
            sender_expires_at: Some(t),
            ..MessageExpiry::default()
        };
        assert_eq!(check_outgoing(&at(now), now), Err(ExpiryError::InThePast));
        assert_eq!(
            check_outgoing(&at(now - 1), now),
            Err(ExpiryError::InThePast)
        );
        assert_eq!(check_outgoing(&at(now + 1), now), Ok(()));
        let year = ONE_YEAR_SECS * 1000;
        assert_eq!(check_outgoing(&at(now + year), now), Ok(()));
        assert_eq!(
            check_outgoing(&at(now + year + 1000), now),
            Err(ExpiryError::TooFarAhead)
        );
        assert_eq!(check_outgoing(&MessageExpiry::default(), now), Ok(()));
        let read = |s| MessageExpiry {
            expires_after_read_seconds: Some(s),
            ..MessageExpiry::default()
        };
        let year = u32::try_from(ONE_YEAR_SECS).unwrap();
        assert_eq!(check_outgoing(&read(year), now), Ok(()));
        assert_eq!(
            check_outgoing(&read(year + 1), now),
            Err(ExpiryError::ReadTooLong)
        );
        assert_eq!(to_whole_seconds(at(1_999)).sender_expires_at, Some(1_000));
    }

    fn message(sender: &str) -> Message {
        Message {
            key: "M".into(),
            room: "R".into(),
            seq: 1,
            sender: Sender::User(sender.into()),
            mimi_id: None,
            aliases: Vec::new(),
            accepted_at: 1_000,
            received_at: 2_000,
            sender_msg_id: String::new(),
            body: String::new(),
            body_type: crate::content::BodyType::Plain,
            in_reply_to: None,
            in_reply_to_id: None,
            topic_id: None,
            attachments: Vec::new(),
            calls: Vec::new(),
            edit_history: Vec::new(),
            edited_at: None,
            deleted: None,
            kept_frank: None,
            notice: None,
            expiry: MessageExpiry::default(),
            read_at: None,
            ext: Ext::new(),
        }
    }

    fn room(seconds: Option<u64>) -> Room {
        serde_json::from_value(serde_json::json!({
            "key": "R", "uri": "mimi://a.example/r/x", "status": "active",
            "messageExpirySeconds": seconds,
        }))
        .unwrap()
    }

    /// Oracle: draft-atwood-jmap-chat-00 §Message (`senderExpiresAt` for
    /// every copy; `burnOnRead` and `expiresAfterReadSeconds` for the
    /// receiving mailbox only, burnOnRead first) and §Chat
    /// `messageExpirySeconds` ("older than", from the arrival); "whichever
    /// deadline arrives first takes effect".
    #[test]
    fn the_deadline_is_the_earliest_rule_that_applies() {
        let mut m = message(PEER);
        assert_eq!(deadline(&m, Some(&room(None)), ME), None);
        assert_eq!(deadline(&m, Some(&room(Some(0))), ME), None);
        assert_eq!(deadline(&m, Some(&room(Some(10))), ME), Some(12_001));
        m.expiry.sender_expires_at = Some(5_000);
        assert_eq!(deadline(&m, Some(&room(Some(10))), ME), Some(5_000));
        assert_eq!(deadline(&m, None, ME), Some(5_000));

        let mut m = message(PEER);
        m.expiry.expires_after_read_seconds = Some(3);
        assert_eq!(deadline(&m, None, ME), None, "not read yet");
        m.read_at = Some(4_000);
        assert_eq!(deadline(&m, None, ME), Some(7_000));
        m.expiry.burn_on_read = true;
        assert_eq!(deadline(&m, None, ME), Some(4_000));

        // The sender's own copy keeps its read rules out, not its time.
        let mut own = m.clone();
        own.sender = Sender::User(ME.into());
        assert_eq!(deadline(&own, None, ME), None);
        own.expiry.sender_expires_at = Some(9_000);
        assert_eq!(deadline(&own, None, ME), Some(9_000));
        // A notice has only the room's policy.
        let mut notice = m.clone();
        notice.sender = Sender::Agent;
        assert_eq!(deadline(&notice, Some(&room(Some(1))), ME), Some(3_001));
    }
}
