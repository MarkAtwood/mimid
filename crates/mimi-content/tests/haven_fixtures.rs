//! mimi-content documents encoded by Haven's `mimi_core::content`
//! (havenmessenger/interop examples/content_fixtures.rs), decoded by mimid.
//!
//! Fixtures: tests/fixtures/haven (see PROVENANCE there).
//!
//! Oracle: the generator's inputs (its salts, parts and URIs, read from
//! its source at the pinned revision) and the message IDs Haven wrote in
//! `fixtures.txt`. Each fixture is decoded, compared with a value written
//! here from those inputs (never with mimid's own encoder output),
//! re-encoded and required to be byte-identical, and its message ID, as
//! sent by Haven's sender in Haven's room, is required to equal Haven's.

use mimi_content::{
    Disposition, Extensions, ExternalPart, MessageId, MimiContent, NestedPart, Part, PartSemantics,
};
use sha2::{Digest, Sha256};

const SENDER: &str = "mimi://mimi.havenmessenger.com/u/erin";
const ROOM: &str = "mimi://mimi.havenmessenger.com/r/table";
const ATTACHMENT_BYTES: &[u8] = b"an example attachment for a MIMI content test";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/haven/{name}.cbor",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn hex_id(s: &str) -> MessageId {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    MessageId(bytes.try_into().unwrap())
}

fn text(content_type: &str, body: &str) -> NestedPart {
    NestedPart {
        disposition: Disposition::RENDER,
        language: "en".to_owned(),
        part: Part::Single {
            content_type: content_type.to_owned(),
            content: body.as_bytes().to_vec(),
        },
    }
}

fn document(salt: u8, in_reply_to: Option<MessageId>, nested_part: NestedPart) -> MimiContent {
    MimiContent {
        salt: [salt; 16],
        replaces: None,
        topic_id: Vec::new(),
        expires: None,
        in_reply_to,
        mimi_extensions: Extensions::default(),
        nested_part,
    }
}

fn multi(semantics: PartSemantics, parts: Vec<NestedPart>) -> NestedPart {
    NestedPart {
        disposition: Disposition::RENDER,
        language: "en".to_owned(),
        part: Part::Multi {
            part_semantics: semantics,
            parts,
        },
    }
}

/// Decode, compare with `expected`, re-encode to the same bytes, and
/// check the message ID against Haven's.
fn check(name: &str, expected: &MimiContent, id: &str) {
    let bytes = fixture(name);
    let decoded = MimiContent::decode(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(&decoded, expected, "{name}");
    assert_eq!(decoded.encode().expect("re-encode"), bytes, "{name}");
    let computed = MessageId::compute(SENDER, ROOM, &bytes, &decoded.salt).unwrap();
    assert_eq!(computed, hex_id(id), "{name}: message ID");
}

const ALTERNATIVE_ID: &str = "0196bc672b649aa896a4a08ce984583ff58f38ea716623792c9acec09d763bb9";

#[test]
fn alternative() {
    check(
        "alternative",
        &document(
            1,
            None,
            multi(
                PartSemantics::ChooseOne,
                vec![
                    text("text/plain;charset=utf-8", "Hello from Haven."),
                    text("text/markdown;variant=GFM-MIMI", "Hello from **Haven**."),
                ],
            ),
        ),
        ALTERNATIVE_ID,
    );
}

#[test]
fn attachment() {
    let image = NestedPart {
        disposition: Disposition::ATTACHMENT,
        language: String::new(),
        part: Part::External(ExternalPart {
            content_type: "image/png".to_owned(),
            url: "https://mimi.havenmessenger.com/files/example.png".to_owned(),
            expires: 0,
            size: ATTACHMENT_BYTES.len() as u64,
            enc_alg: 0,
            key: Vec::new(),
            nonce: Vec::new(),
            aad: Vec::new(),
            hash_alg: 1,
            content_hash: Sha256::digest(ATTACHMENT_BYTES).to_vec(),
            description: "An example image".to_owned(),
            filename: "example.png".to_owned(),
        }),
    };
    check(
        "attachment",
        &document(
            2,
            None,
            multi(
                PartSemantics::ProcessAll,
                vec![
                    text("text/plain;charset=utf-8", "The file is attached."),
                    image,
                ],
            ),
        ),
        "012b025709a0bf29df6a9f56542ebff8424e224c5bad26f83e353856d18f3c2c",
    );
}

#[test]
fn reply() {
    check(
        "reply",
        &document(
            3,
            Some(hex_id(ALTERNATIVE_ID)),
            text("text/plain;charset=utf-8", "Thanks, got it."),
        ),
        "01b2588c24d9bd7e6ef3a829e8ccdf990e7bb25e9b29da71da2e80dc5a20f953",
    );
}
