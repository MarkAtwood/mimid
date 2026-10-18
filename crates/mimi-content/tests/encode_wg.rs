//! T2: hand-built messages encode to the WG example bytes.
//!
//! Each message (see `common`) must encode to exactly the bytes of the
//! matching `.cbor` file. The decoder is not involved.

#[allow(dead_code, reason = "each test crate uses a different subset")]
mod common;

use common::{ALICE, PLAIN, expected, fixture, hex, message, multi, single};
use mimi_content::{
    Disposition, EncodeError, Expiration, Extensions, MAX_NESTING_DEPTH, MAX_PARTS,
    MAX_TOPIC_ID_LEN, MimiContent, NestedPart, Part, PartSemantics,
};

fn assert_encodes_to_fixture(name: &str) {
    let encoded = expected(name)
        .encode()
        .unwrap_or_else(|e| panic!("encode {name}: {e}"));
    assert_eq!(
        encoded,
        fixture(name),
        "{name}: encoding differs from fixture"
    );
}

#[test]
fn original() {
    assert_encodes_to_fixture("original");
}

#[test]
fn reply() {
    assert_encodes_to_fixture("reply");
}

#[test]
fn reaction() {
    assert_encodes_to_fixture("reaction");
}

#[test]
fn mention() {
    assert_encodes_to_fixture("mention");
}

#[test]
fn mention_html() {
    assert_encodes_to_fixture("mention-html");
}

#[test]
fn edit() {
    assert_encodes_to_fixture("edit");
}

#[test]
fn delete() {
    assert_encodes_to_fixture("delete");
}

#[test]
fn unlike() {
    assert_encodes_to_fixture("unlike");
}

#[test]
fn expiring() {
    assert_encodes_to_fixture("expiring");
}

#[test]
fn attachment() {
    assert_encodes_to_fixture("attachment");
}

#[test]
fn conferencing() {
    assert_encodes_to_fixture("conferencing");
}

#[test]
fn multipart_1() {
    assert_encodes_to_fixture("multipart-1");
}

#[test]
fn multipart_2() {
    assert_encodes_to_fixture("multipart-2");
}

/// Four levels deep, the maximum (decision mimid-1wgh.2.13).
#[test]
fn multipart_3() {
    assert_encodes_to_fixture("multipart-3");
}

// Structural rules and limits. Oracle: the spec rule cited on each test.

fn text_part() -> NestedPart {
    single(Disposition::RENDER, "", PLAIN, b"x")
}

/// A chain of `depth` levels: `depth - 1` MultiParts, then a SinglePart.
fn nested_to_depth(depth: usize) -> NestedPart {
    (1..depth).fold(text_part(), |inner, _| {
        multi(PartSemantics::ProcessAll, vec![inner, text_part()])
    })
}

fn with_body(nested_part: NestedPart) -> MimiContent {
    message("00000000000000000000000000000000", ALICE, nested_part)
}

/// `parts: [2* NestedPart]` (§4.4).
#[test]
fn multipart_with_one_part_is_rejected() {
    let content = with_body(multi(PartSemantics::ChooseOne, vec![text_part()]));
    assert!(matches!(
        content.encode(),
        Err(EncodeError::MultiPartTooFewParts { count: 1 })
    ));
}

/// §6.3, root is level 1 (decision mimid-1wgh.2.13).
#[test]
fn nesting_at_limit_is_accepted_and_past_it_rejected() {
    assert!(
        with_body(nested_to_depth(MAX_NESTING_DEPTH))
            .encode()
            .is_ok()
    );
    assert!(matches!(
        with_body(nested_to_depth(MAX_NESTING_DEPTH + 1)).encode(),
        Err(EncodeError::NestingTooDeep)
    ));
}

/// §9.1 "more than 1024" body parts; every NestedPart counts, the root
/// MultiPart included.
#[test]
fn part_count_at_limit_is_accepted_and_past_it_rejected() {
    let at_limit = multi(PartSemantics::ProcessAll, vec![text_part(); MAX_PARTS - 1]);
    assert!(with_body(at_limit).encode().is_ok());
    let past_limit = multi(PartSemantics::ProcessAll, vec![text_part(); MAX_PARTS]);
    assert!(matches!(
        with_body(past_limit).encode(),
        Err(EncodeError::TooManyParts)
    ));
}

/// §9.1 topicId "greater than 4096 octets".
#[test]
fn topic_id_at_limit_is_accepted_and_past_it_rejected() {
    let mut content = with_body(text_part());
    content.topic_id = vec![b'a'; MAX_TOPIC_ID_LEN];
    assert!(content.encode().is_ok());
    content.topic_id.push(b'a');
    assert!(matches!(
        content.encode(),
        Err(EncodeError::TopicIdTooLong { len }) if len == MAX_TOPIC_ID_LEN + 1
    ));
}

/// Absent registered extensions are omitted, leaving an empty map (0xa0).
#[test]
fn absent_extensions_encode_as_empty_map() {
    let mut content = with_body(NestedPart {
        disposition: Disposition::UNSPECIFIED,
        language: String::new(),
        part: Part::Null,
    });
    content.mimi_extensions = Extensions::default();
    // Hand-encoded per §4.1 and RFC 8949 §3:
    let expected = hex(concat!(
        "87",                                 // mimiContent: array(7)
        "5000000000000000000000000000000000", // salt: bstr(16), all zero
        "f6",                                 // replaces: null
        "40",                                 // topicId: bstr(0)
        "f6",                                 // expires: null
        "f6",                                 // inReplyTo: null
        "a0",                                 // mimiExtensions: map(0)
        "83",                                 // nestedPart: array(3)
        "00",                                 // disposition: 0 unspecified
        "60",                                 // language: tstr(0)
        "00",                                 // cardinality: 0 nullpart
    ));
    assert_eq!(content.encode().expect("encodes"), expected);
}

/// Relative expiration encodes `relative` as true (§4.1).
#[test]
fn relative_expiration_encodes_true_flag() {
    let mut content = with_body(NestedPart {
        disposition: Disposition::UNSPECIFIED,
        language: String::new(),
        part: Part::Null,
    });
    content.mimi_extensions = Extensions::default();
    content.expires = Some(Expiration::Relative(600));
    let expected = hex(concat!(
        "87",                                 // mimiContent: array(7)
        "5000000000000000000000000000000000", // salt: bstr(16), all zero
        "f6",                                 // replaces: null
        "40",                                 // topicId: bstr(0)
        "82",                                 // expires: array(2)
        "f5",                                 // relative: true
        "190258",                             // time: 600, uint16 form
        "f6",                                 // inReplyTo: null
        "a0",                                 // mimiExtensions: map(0)
        "83",                                 // nestedPart: array(3)
        "00",                                 // disposition: 0 unspecified
        "60",                                 // language: tstr(0)
        "00",                                 // cardinality: 0 nullpart
    ));
    assert_eq!(content.encode().expect("encodes"), expected);
}

/// `singleUnit = 1` (§4.4); no WG example uses it.
#[test]
fn single_unit_semantics_encodes_as_one() {
    let null = || NestedPart {
        disposition: Disposition::UNSPECIFIED,
        language: String::new(),
        part: Part::Null,
    };
    let mut content = with_body(multi(PartSemantics::SingleUnit, vec![null(), null()]));
    content.mimi_extensions = Extensions::default();
    let expected = hex(concat!(
        "87",                                 // mimiContent: array(7)
        "5000000000000000000000000000000000", // salt: bstr(16), all zero
        "f6",                                 // replaces: null
        "40",                                 // topicId: bstr(0)
        "f6",                                 // expires: null
        "f6",                                 // inReplyTo: null
        "a0",                                 // mimiExtensions: map(0)
        "85",                                 // nestedPart: array(5)
        "01",                                 // disposition: 1 render
        "60",                                 // language: tstr(0)
        "03",                                 // cardinality: 3 multi
        "01",                                 // partSemantics: 1 singleUnit
        "82",                                 // parts: array(2)
        "83006000",                           // [0, "", 0 nullpart]
        "83006000",                           // [0, "", 0 nullpart]
    ));
    assert_eq!(content.encode().expect("encodes"), expected);
}
