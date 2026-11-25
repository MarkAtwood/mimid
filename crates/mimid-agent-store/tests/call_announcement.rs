//! The live-call announcement's extension value (bead mimid-1wgh.114.1;
//! decisions mimid-1wgh.128, mimid-1wgh.117).
//!
//! Oracle: decision mimid-1wgh.128's map, and RFC 8949 §4.2.1 bytewise
//! key order, which mimi-content-10 §6.1 requires of senders. Each
//! fixture is hex written out byte by byte below, and every byte of it is
//! commented; an independent encoder (a short Python script that shares
//! no code with the parser, kept in the bead) produced the same bytes for
//! all four.
//!
//! The direction is the one AGENTS.md fixes: decode the fixture, compare
//! the result to the expected value, re-encode it, and require
//! byte-identical output. An encode-then-decode test alone would prove
//! only that the module agrees with itself.

#![forbid(unsafe_code)]

use mimi_content::{
    Disposition, ExtensionKey, Extensions, MimiContent, NestedPart, Part, RawValue,
};
use mimid_agent_store::call::{
    ANNOUNCEMENT_KEY, Announcement, MAX_MEDIA_KINDS, MAX_ROOM_URI_LEN, MAX_SUBJECT_LEN,
    announcement,
};

const ROOM: &str = "mimi://a.example/r/call1";

/// `{ "room": "mimi://a.example/r/call1" }`
///
/// ```text
/// a1                    map(1)
///   64 726f6f6d         text(4) "room"
///   78 18               text(24), one-octet length, shortest form
///      6d696d693a2f2f612e6578616d706c652f722f63616c6c31
///                       "mimi://a.example/r/call1"
/// ```
const STARTED: &str = "a164726f6f6d78186d696d693a2f2f612e6578616d706c652f722f63616c6c31";

/// `{ "room": ..., "media": ["audio", "video"], "subject": "standup" }`
///
/// Keys in bytewise order: `64 "room"` < `65 "media"` < `67 "subject"`.
///
/// ```text
/// a3                    map(3)
///   64 726f6f6d         text(4) "room"
///   78 18 6d696d69...   text(24) "mimi://a.example/r/call1"
///   65 6d65646961       text(5) "media"
///   82                  array(2)
///     65 617564696f     text(5) "audio"
///     65 766964656f     text(5) "video"
///   67 7375626a656374   text(7) "subject"
///   67 7374616e647570   text(7) "standup"
/// ```
const VIDEO: &str = "a364726f6f6d78186d696d693a2f2f612e6578616d706c652f722f63616c6c31\
656d656469618265617564696f65766964656f677375626a656374677374616e647570";

/// `{ "room": ..., "ended": true }`
///
/// `65 "ended"` sorts before `65 "media"` and after `64 "room"`.
///
/// ```text
/// a2                    map(2)
///   64 726f6f6d         text(4) "room"
///   78 18 6d696d69...   text(24) "mimi://a.example/r/call1"
///   65 656e646564       text(5) "ended"
///   f5                  true
/// ```
const ENDED: &str =
    "a264726f6f6d78186d696d693a2f2f612e6578616d706c652f722f63616c6c3165656e646564f5";

/// `{ "room": ..., "zz-later": "ignored" }`: a field a later version
/// added, which this one skips rather than refusing. Decision
/// mimid-1wgh.116 chose a map over a bare string so a field could be
/// added without a second extension key, and that is only true if an
/// older reader keeps working.
///
/// ```text
/// a2                    map(2)
///   64 726f6f6d         text(4) "room"
///   78 18 6d696d69...   text(24) "mimi://a.example/r/call1"
///   68 7a7a2d6c61746572 text(8) "zz-later"
///   67 69676e6f726564   text(7) "ignored"
/// ```
const UNKNOWN_KEY: &str = "a264726f6f6d78186d696d693a2f2f612e6578616d706c652f722f63616c6c31\
687a7a2d6c617465726769676e6f726564";

fn bytes(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// A `MimiContent` carrying `value` under [`ANNOUNCEMENT_KEY`]. Built
/// through `RawValue::new`, which is content-10 §6.1's own check, so a
/// fixture that is not deterministic CBOR fails here rather than being
/// read.
fn carrying(value: &[u8]) -> MimiContent {
    with_value(RawValue::new(value).expect("the fixture is one deterministic CBOR item"))
}

/// A `text/plain` message carrying `value` under [`ANNOUNCEMENT_KEY`].
fn with_value(value: RawValue) -> MimiContent {
    let mut content = empty();
    content
        .mimi_extensions
        .other
        .insert(ExtensionKey::Text(ANNOUNCEMENT_KEY.to_owned()), value);
    content
}

/// A `text/plain` message carrying no extension of ours.
fn empty() -> MimiContent {
    MimiContent {
        salt: [0; 16],
        replaces: None,
        topic_id: vec![],
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions::default(),
        nested_part: NestedPart {
            disposition: Disposition::RENDER,
            language: String::new(),
            part: Part::Single {
                content_type: "text/plain;charset=utf-8".to_owned(),
                content: b"started a call".to_vec(),
            },
        },
    }
}

/// Decode, compare, re-encode, require the same bytes.
fn round_trip(hex: &str, expected: &Announcement) {
    let fixture = bytes(hex);
    let content = carrying(&fixture);
    let read = announcement(&content).expect("the fixture decodes");
    assert_eq!(&read, expected);

    let options = read
        .content_options()
        .expect("what decoded is sendable again");
    let value = options
        .extensions
        .get(&ExtensionKey::Text(ANNOUNCEMENT_KEY.to_owned()))
        .expect("the key is set");
    assert_eq!(
        value.as_bytes(),
        fixture.as_slice(),
        "re-encoding must give the fixture's bytes back"
    );
}

#[test]
fn a_started_announcement_round_trips() {
    round_trip(STARTED, &Announcement::started(ROOM));
}

#[test]
fn media_kinds_and_a_subject_round_trip() {
    round_trip(
        VIDEO,
        &Announcement {
            room: ROOM.to_owned(),
            media: vec!["audio".to_owned(), "video".to_owned()],
            subject: "standup".to_owned(),
            ended: false,
        },
    );
}

#[test]
fn an_ended_announcement_round_trips() {
    round_trip(ENDED, &Announcement::ended(ROOM));
}

/// The unknown key is skipped, so what decodes is the announcement
/// without it. Re-encoding therefore does NOT give the fixture back, and
/// that is correct rather than a round-trip failure: mimid must not
/// forward a field it does not understand as though it did. The message's
/// own extension map keeps the original bytes unchanged (mimi-content-10
/// §4.3), which is where round-tripping an unknown field belongs.
#[test]
fn a_field_a_later_version_added_is_skipped_not_refused() {
    let content = carrying(&bytes(UNKNOWN_KEY));
    let read = announcement(&content).expect("an unknown field must not refuse the announcement");
    assert_eq!(read, Announcement::started(ROOM));
}

/// A message with no announcement has none, and a value of the wrong
/// shape is `None` rather than a partly-read announcement.
#[test]
fn nothing_and_nonsense_both_read_as_no_announcement() {
    assert_eq!(announcement(&empty()), None);

    for (what, value) in [
        // Not a map at all: the room URI as a bare text string, which is
        // what decision mimid-1wgh.116 chose a map over. `78 18` then 24
        // octets, so it is a valid item and the refusal is this module's.
        (
            "a bare text string",
            bytes("78186d696d693a2f2f612e6578616d706c652f722f63616c6c31"),
        ),
        // A map with no `room`: nothing to join.
        ("a map with no room", bytes("a165656e646564f5")),
        // `ended` as something other than a boolean: `00`, unsigned 0.
        (
            "a non-boolean ended",
            bytes("a264726f6f6d78186d696d693a2f2f612e6578616d706c652f722f63616c6c3165656e64656400"),
        ),
    ] {
        // Every one of these is a valid extension value, so the refusal
        // is this module's and not `RawValue`'s. Asserted rather than
        // skipped on failure: a `continue` here would let a malformed
        // fixture pass as a passing test.
        let raw = RawValue::new(&value)
            .unwrap_or_else(|e| panic!("{what} must be a valid extension value: {e}"));
        assert_eq!(
            announcement(&with_value(raw)),
            None,
            "{what} must not decode"
        );
    }
}

/// The limits are the same in both directions, so mimid never sends what
/// it would refuse to read. Values at the limit are sendable and values
/// past it are not.
#[test]
fn every_field_is_bounded_in_both_directions() {
    let at_limit = Announcement {
        room: format!("mimi://a.example/r/{}", "r".repeat(MAX_ROOM_URI_LEN - 19)),
        media: vec!["audio".to_owned(); MAX_MEDIA_KINDS],
        subject: "s".repeat(MAX_SUBJECT_LEN),
        ended: false,
    };
    assert_eq!(at_limit.room.len(), MAX_ROOM_URI_LEN);
    assert!(at_limit.is_sendable(), "a value at the limit is sendable");
    let options = at_limit.content_options().expect("and encodes");

    // And what it encodes to is readable again, which is the property
    // that makes "the same limits both ways" true rather than claimed.
    let value = options
        .extensions
        .get(&ExtensionKey::Text(ANNOUNCEMENT_KEY.to_owned()))
        .expect("the key is set");
    assert_eq!(
        announcement(&with_value(value.clone())).as_ref(),
        Some(&at_limit)
    );

    for past in [
        Announcement {
            room: "r".repeat(MAX_ROOM_URI_LEN + 1),
            ..Announcement::default()
        },
        Announcement {
            room: ROOM.to_owned(),
            subject: "s".repeat(MAX_SUBJECT_LEN + 1),
            ..Announcement::default()
        },
        Announcement {
            room: ROOM.to_owned(),
            media: vec!["audio".to_owned(); MAX_MEDIA_KINDS + 1],
            ..Announcement::default()
        },
        // No room: there is nothing to join.
        Announcement::default(),
    ] {
        assert!(!past.is_sendable(), "{past:?} must not be sendable");
        assert!(past.content_options().is_none(), "{past:?}");
    }
}

/// The sentence a client with no knowledge of the key renders. It names
/// the caller only when the caller supplies a name, because the sender is
/// already the message's.
#[test]
fn the_text_reads_as_a_sentence() {
    let plain = Announcement::started(ROOM);
    assert_eq!(plain.text(None), "started a call");
    assert_eq!(plain.text(Some("Alice")), "Alice started a call");

    let video = Announcement {
        room: ROOM.to_owned(),
        media: vec!["audio".to_owned(), "video".to_owned()],
        subject: "standup".to_owned(),
        ended: false,
    };
    assert_eq!(
        video.text(Some("Alice")),
        "Alice started a video call: standup"
    );

    // An ended announcement says so, and drops the subject: the line is
    // about the end, and decision mimid-1wgh.117 wants nothing that
    // reads as a live call.
    assert_eq!(
        Announcement::ended(ROOM).text(Some("Bob")),
        "Bob ended the call"
    );
}
