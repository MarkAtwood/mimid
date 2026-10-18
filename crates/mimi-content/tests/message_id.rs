//! T3 and T4: `MessageId::compute` (content-09 §3.3) against the WG
//! examples.
//!
//! T3 oracle: the message IDs the WG published for each example, in the
//! `# message ID` header of each vendored `.edn` file. All but
//! `mention-html` are also printed in the draft text (section noted per
//! row). Sender and room URIs are the `sender=`/`room=` arguments of the
//! WG's generate-examples.py at the tag recorded in PROVENANCE, i.e. the
//! user URI (decision mimid-1wgh.2.10).
//!
//! T4 oracle: the `inReplyTo` and `replaces` values carried in the
//! fixture bytes, which must name the ID computed from the referenced
//! fixture.
//!
//! Edge-case vectors were computed with Python `hashlib`, independently
//! of this crate, by this script run on `original.cbor`:
//!
//! ```text
//! import hashlib, struct, sys
//! msg = open(sys.argv[1], 'rb').read(); salt = msg[2:18]
//! def mid(s, r):
//!     s = s.encode('utf-8'); r = r.encode('utf-8')
//!     h = hashlib.sha256(struct.pack('!H', len(s)) + s +
//!                        struct.pack('!H', len(r)) + r + msg + salt).digest()
//!     return (b'\x01' + h[:31]).hex()
//! ```
//!
//! The script reproduces the published Original ID, which checks it.

#[allow(dead_code, reason = "each test crate uses a different subset")]
mod common;

use std::collections::BTreeMap;

use common::{ALICE, BOB, CATHY, FIXTURES, ROOM, expected, fixture, hex};
use mimi_content::{MAX_MESSAGE_ID_URI_LEN, MessageId, MessageIdError, MimiContent};

/// (fixture, authenticated sender, published message ID, where else the ID
/// is published besides `<fixture>.edn`).
const PUBLISHED: [(&str, &str, &str, &str); 14] = [
    (
        "original",
        ALICE,
        "017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4",
        "draft §5.1",
    ),
    (
        "reply",
        BOB,
        "015354973c2b65ca937bf1e035ae53a5ab80e947afa43d46920d4202e5cc0b27",
        "draft §5.2",
    ),
    (
        "reaction",
        CATHY,
        "0158c4288911e50a8f6be3f47746b6682f10fd91bc8c05557aa589a3157aff68",
        "draft §5.3",
    ),
    (
        "mention",
        CATHY,
        "018d825adf9f6be00dcafc5704c4102f5022e74219d0b603e4ba7622654042af",
        "draft §5.4",
    ),
    (
        "mention-html",
        CATHY,
        "01967ff8e9a66819738ad5cf26d2e0388a3b81d86b0f61d129c077d043ee2a4e",
        "repo .edn only",
    ),
    (
        "edit",
        BOB,
        "014028c0deddbdea56bec26172f6ede953d11024cb82b8192b5e2aea62d7fb47",
        "draft §5.5",
    ),
    (
        "delete",
        BOB,
        "011d9efc78d04d4dcf4d82b07d5199bbef37011c1f0c7e004b6111c6dda504b4",
        "draft §5.6",
    ),
    (
        "unlike",
        CATHY,
        "013aadbb8f313253c8930f4e93c6ca54b2ed06d258185bdcec3870534c8a4ec4",
        "draft §5.7",
    ),
    (
        "expiring",
        ALICE,
        "01e59db8173939facc2c8a4a0f0ae8d0c7a11a81239626630c9464a8d6717a03",
        "draft §5.8",
    ),
    (
        "attachment",
        BOB,
        "0176180c7d19a925021fe446d241134d05c38e0d999cdc0f39c391d2377ed9d1",
        "draft §5.9",
    ),
    (
        "conferencing",
        ALICE,
        "01496d15a8dba28d7397f9868b70768e4a67f765d5b5b1ae9e03848c5fdeb0ba",
        "draft §5.10",
    ),
    (
        "multipart-1",
        ALICE,
        "01da5a515ec5db42cc4dcc19b90c3c31245d8a1cfcce11318f24eb11dce0990e",
        "draft §B.1",
    ),
    (
        "multipart-2",
        ALICE,
        "01d65918c6c51c8e76546337276ae6f4bfd873d867d5cb57c76bcdca3d999dd7",
        "draft §B.2",
    ),
    (
        "multipart-3",
        ALICE,
        "01cfebeadbdb83c1eefb6403ba4852daf8bbbf9cd53bf5035a74d5d741950c9f",
        "draft §B.3",
    ),
];

fn id(s: &str) -> MessageId {
    MessageId(hex(s).try_into().expect("32-octet message ID"))
}

/// Computes the ID of fixture `name` from its bytes as stored, with the
/// salt taken from the hand-built expected value, not from the decoder.
fn compute(name: &str, sender: &str) -> MessageId {
    MessageId::compute(sender, ROOM, &fixture(name), &expected(name).salt)
        .unwrap_or_else(|e| panic!("compute {name}: {e}"))
}

/// T3: every computed ID equals the WG-published one.
#[test]
fn computed_ids_match_published_ids() {
    let names: Vec<&str> = PUBLISHED.iter().map(|row| row.0).collect();
    assert_eq!(names, FIXTURES, "every fixture has a published ID");
    for (name, sender, published, source) in PUBLISHED {
        assert_eq!(
            compute(name, sender),
            id(published),
            "{name}: computed ID differs from the one published in {name}.edn ({source})"
        );
    }
}

/// The Original message's ID under the -07 algorithm. Draft §5.2/§5.3 hex
/// dumps carry it (decision mimid-1wgh.2.17), and so does the WG's
/// `implied-original.cbor`, which was not regenerated for -09.
const ORIGINAL_ID_DRAFT_07: &str =
    "01b0084467273cc43d6f0ebeac13eb84229c4fffe8f6c3594c905f47779e5a79";

/// T3: the MessageDerivedValues example (draft §5.1) pairs the Original
/// message's ID with its senderUserUrl and roomUrl. Computing from the
/// URIs in `implied-original.cbor` and from `original.cbor` gives the ID
/// that §5.1 and `implied-original.edn` publish.
///
/// The messageId inside `implied-original.cbor` is the stale -07 value.
/// The test asserts that too, so a regenerated upstream file is noticed.
/// content-09 §5.1; decision mimid-1wgh.2.23; wg mimid-1wgh.37.20.
#[test]
fn implied_original_message_id_matches() {
    let published = id("017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4");
    let bytes = fixture("implied-original");
    let mut d = minicbor::Decoder::new(&bytes);
    assert_eq!(d.array().expect("array"), Some(7));
    let stale_message_id = id(&hex_of(d.bytes().expect("messageId")));
    assert_eq!(stale_message_id, id(ORIGINAL_ID_DRAFT_07));
    d.u64().expect("hubAcceptedTimestamp");
    d.bytes().expect("mlsGroupId");
    d.u32().expect("senderLeafIndex");
    d.str().expect("senderClientUrl");
    let sender_user_url = d.str().expect("senderUserUrl").to_owned();
    let room_url = d.str().expect("roomUrl").to_owned();
    assert_eq!(d.position(), bytes.len(), "no trailing bytes");

    let computed = MessageId::compute(
        &sender_user_url,
        &room_url,
        &fixture("original"),
        &expected("original").salt,
    )
    .expect("compute");
    assert_eq!(computed, published);
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// T4: each `inReplyTo` and `replaces` in the fixture bytes names the ID
/// computed from the fixture its `.edn` comment says it references.
#[test]
fn references_resolve_to_computed_ids() {
    let computed: BTreeMap<&str, MessageId> = PUBLISHED
        .iter()
        .map(|&(name, sender, _, _)| (name, compute(name, sender)))
        .collect();
    // (fixture, inReplyTo target, replaces target), from the `.edn`
    // annotations `# inReplyTo = <Name>` and `# replaces = <Name>`.
    let references: [(&str, Option<&str>, Option<&str>); 14] = [
        ("original", None, None),
        ("reply", Some("original"), None),
        ("reaction", Some("original"), None),
        ("mention", Some("original"), None),
        ("mention-html", Some("original"), None),
        ("edit", Some("original"), Some("reply")),
        ("delete", Some("original"), Some("reply")),
        ("unlike", Some("original"), Some("reaction")),
        ("expiring", None, None),
        ("attachment", None, None),
        ("conferencing", None, None),
        ("multipart-1", None, None),
        ("multipart-2", None, None),
        ("multipart-3", None, None),
    ];
    for (name, in_reply_to, replaces) in references {
        let decoded =
            MimiContent::decode(&fixture(name)).unwrap_or_else(|e| panic!("decode {name}: {e}"));
        assert_eq!(
            decoded.in_reply_to,
            in_reply_to.map(|t| computed[t]),
            "{name}: inReplyTo"
        );
        assert_eq!(
            decoded.replaces,
            replaces.map(|t| computed[t]),
            "{name}: replaces"
        );
    }
}

fn original_with(sender: &str, room: &str) -> Result<MessageId, MessageIdError> {
    MessageId::compute(
        sender,
        room,
        &fixture("original"),
        &expected("original").salt,
    )
}

/// Empty URIs hash as a zero length prefix and no octets.
#[test]
fn empty_uris() {
    assert_eq!(
        original_with("", "").expect("compute"),
        id("011cb1d8d8c86486657cd871d2040bd784180552f1b3474746e8cc1c016d344a")
    );
}

/// The length prefix counts octets, not characters: U+00EB is two octets,
/// so this 24-character URI is prefixed with 25.
#[test]
fn non_ascii_uri_length_is_octets() {
    let sender = "mimi://example.com/u/zo\u{eb}";
    assert_eq!(sender.chars().count(), 24);
    assert_eq!(
        original_with(sender, ROOM).expect("compute"),
        id("0193798a26a0e0364f89c0db44ff6995c5f15940e5af5b42378c948625ceef46")
    );
}

fn uri_of_len(len: usize) -> String {
    let prefix = "mimi://example.com/u/";
    format!("{prefix}{}", "a".repeat(len - prefix.len()))
}

/// URIs of exactly 65535 octets, the largest a 16-bit prefix can hold.
#[test]
fn max_length_uris() {
    let uri = uri_of_len(MAX_MESSAGE_ID_URI_LEN);
    assert_eq!(uri.len(), 65535);
    assert_eq!(
        original_with(&uri, &uri).expect("compute"),
        id("015e8cee12ec9f368a173646f94fc5bbcbb937e99aa13e053b35b69154c0a692")
    );
}

#[test]
fn sender_uri_one_octet_too_long() {
    let uri = uri_of_len(MAX_MESSAGE_ID_URI_LEN + 1);
    assert!(matches!(
        original_with(&uri, ROOM),
        Err(MessageIdError::SenderUriTooLong { len: 65536 })
    ));
}

#[test]
fn room_uri_one_octet_too_long() {
    let uri = uri_of_len(MAX_MESSAGE_ID_URI_LEN + 1);
    assert!(matches!(
        original_with(ALICE, &uri),
        Err(MessageIdError::RoomUriTooLong { len: 65536 })
    ));
}
