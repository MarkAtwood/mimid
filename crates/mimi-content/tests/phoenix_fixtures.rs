//! mimi-content messages encoded by Phoenix R&D's mimi-content crate
//! (phnx-im/mimi-content, the crate the Air app uses), decoded by mimid
//! (bead mimid-1wgh.46.2).
//!
//! Fixtures: tests/fixtures/phoenix, written by tools/interop/phoenix from
//! fixed inputs (see PROVENANCE and VALUES there). Phoenix main and PR #20
//! produce identical bytes for all of them.
//!
//! Oracle: the generator's inputs. Each fixture is decoded, compared with a
//! value written here from those inputs (never with mimid's own encoder
//! output), re-encoded, and required to be byte-identical.

use mimi_content::{
    DecodeError, Disposition, Expiration, ExtensionKey, Extensions, ExternalPart, MessageId,
    MimiContent, NestedPart, Part, PartSemantics, RawValue,
};

const ROOM: &str = "mimi://example.com/r/engineering_team";
const ALICE: &str = "mimi://example.com/u/alice-smith";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/phoenix/{name}.cbor",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A message ID: hash algorithm 1, then 31 copies of `fill`.
fn message_id(fill: u8) -> MessageId {
    let mut id = [fill; 32];
    id[0] = 0x01;
    MessageId(id)
}

fn content(salt: u8, nested_part: NestedPart) -> MimiContent {
    MimiContent {
        salt: [salt; 16],
        replaces: None,
        topic_id: Vec::new(),
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions::default(),
        nested_part,
    }
}

fn single(disposition: Disposition, language: &str, content_type: &str, body: &[u8]) -> NestedPart {
    NestedPart {
        disposition,
        language: language.to_owned(),
        part: Part::Single {
            content_type: content_type.to_owned(),
            content: body.to_vec(),
        },
    }
}

fn plain_hi() -> NestedPart {
    single(Disposition::RENDER, "en", "text/plain;charset=utf-8", b"hi")
}

/// Decode, compare with `expected`, re-encode, require identical bytes.
fn check(name: &str, expected: &MimiContent) {
    let bytes = fixture(name);
    let decoded = MimiContent::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(&decoded, expected, "{name}");
    assert_eq!(decoded.encode().expect("re-encode"), bytes, "{name}");
}

#[test]
fn markdown_message() {
    // simple_markdown_message("Hello, *world*", salt 0x11 * 16)
    check(
        "markdown",
        &content(
            0x11,
            single(Disposition::RENDER, "", "text/markdown", b"Hello, *world*"),
        ),
    );
}

#[test]
fn receipt() {
    // simple_receipt([message ID 01 aa..aa], salt 0x22 * 16, Read)
    let mut report = vec![
        0x81, // array(1): one PerMessageStatus
        0x82, // array(2)
        0x58, 0x20, // bytes(32): mimi_id
    ];
    report.extend(message_id(0xaa).0);
    report.push(0x02); // status: read(2)
    check(
        "receipt",
        &content(
            0x22,
            single(
                Disposition::UNSPECIFIED,
                "",
                "application/mimi-message-status",
                &report,
            ),
        ),
    );
}

#[test]
fn every_top_level_field_and_extensions() {
    let mut expected = content(0x33, plain_hi());
    expected.replaces = Some(message_id(0xbb));
    expected.topic_id = b"topic-1".to_vec();
    expected.expires = Some(Expiration::Relative(3600));
    expected.in_reply_to = Some(message_id(0xcc));
    expected.mimi_extensions.sender_uri = Some(ALICE.to_owned());
    expected.mimi_extensions.room_uri = Some(ROOM.to_owned());
    let map = RawValue::new(&[
        0xa2, // map(2), keys in RFC 8949 §4.2.1 order
        0x61, b'b', // "b"
        0x21, // -2
        0x62, b'a', b'a', // "aa"
        0x01, // 1
    ])
    .expect("raw value");
    expected
        .mimi_extensions
        .other
        .insert(ExtensionKey::Text("x-phx".to_owned()), map);
    check("extensions", &expected);
}

#[test]
fn multipart() {
    check(
        "multipart",
        &content(
            0x44,
            NestedPart {
                disposition: Disposition::RENDER,
                language: String::new(),
                part: Part::Multi {
                    part_semantics: PartSemantics::ChooseOne,
                    parts: vec![
                        plain_hi(),
                        single(
                            Disposition::RENDER,
                            "en",
                            "text/html;charset=utf-8",
                            b"<b>hi</b>",
                        ),
                    ],
                },
            },
        ),
    );
}

#[test]
fn external_part() {
    check(
        "external",
        &content(
            0x55,
            NestedPart {
                disposition: Disposition::ATTACHMENT,
                language: String::new(),
                part: Part::External(ExternalPart {
                    content_type: "image/png".to_owned(),
                    url: "https://example.com/f/1".to_owned(),
                    expires: 0,
                    size: 1024,
                    enc_alg: 1, // AES-128-GCM
                    key: vec![0x55; 16],
                    nonce: vec![0x66; 12],
                    aad: Vec::new(),
                    hash_alg: 1, // SHA-256
                    content_hash: vec![0x77; 32],
                    description: "a picture".to_owned(),
                    filename: "pic.png".to_owned(),
                }),
            },
        ),
    );
}

#[test]
fn float_extension_value_not_in_shortest_form_is_refused() {
    // Extension "x-float" = 1.5, which Phoenix encodes as a double
    // (fb 3ff8000000000000) instead of the shortest form (f9 3e00) that
    // content-10 §6.1 requires of senders: a Phoenix bug, bead
    // mimid-1wgh.46.5. mimid's strict decoder refuses it (decision
    // mimid-1wgh.2.9); -10 §6.1 lets receivers skip this check, which
    // decision bead mimid-1wgh.2.27 is to settle.
    let bytes = fixture("float");
    let float = [0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0];
    let offset = bytes
        .windows(float.len())
        .position(|w| w == float)
        .expect("the double is in the fixture");
    assert!(matches!(
        MimiContent::decode(&bytes),
        Err(DecodeError::NotShortestForm { offset: o }) if o == offset
    ));
}
