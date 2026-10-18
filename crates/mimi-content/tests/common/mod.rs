//! Expected values for the WG example fixtures, shared by the encoder (T2)
//! and decoder (T1) tests.
//!
//! Each message is built from the values annotated in the matching `.edn`
//! file. `implied-original` is a MessageDerivedValues example, not a
//! `mimiContent`, so it has no entry here.

use std::fs;

use mimi_content::{
    Disposition, Expiration, Extensions, ExternalPart, MessageId, MimiContent, NestedPart, Part,
    PartSemantics,
};

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wg-09");

const ROOM: &str = "mimi://example.com/r/engineering_team";
pub const ALICE: &str = "mimi://example.com/u/alice-smith";
const BOB: &str = "mimi://example.com/u/bob-jones";
const CATHY: &str = "mimi://example.com/u/cathy-washington";

const ORIGINAL_ID: &str = "017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4";
const REPLY_ID: &str = "015354973c2b65ca937bf1e035ae53a5ab80e947afa43d46920d4202e5cc0b27";
const REACTION_ID: &str = "0158c4288911e50a8f6be3f47746b6682f10fd91bc8c05557aa589a3157aff68";

const MARKDOWN: &str = "text/markdown;variant=GFM-MIMI";
pub const PLAIN: &str = "text/plain;charset=utf-8";
const HTML: &str = "text/html;charset=utf-8";

/// The names of the 14 `mimiContent` fixtures.
pub const FIXTURES: [&str; 14] = [
    "original",
    "reply",
    "reaction",
    "mention",
    "mention-html",
    "edit",
    "delete",
    "unlike",
    "expiring",
    "attachment",
    "conferencing",
    "multipart-1",
    "multipart-2",
    "multipart-3",
];

/// Reads `<name>.cbor` from the fixture directory.
pub fn fixture(name: &str) -> Vec<u8> {
    fs::read(format!("{FIXTURE_DIR}/{name}.cbor"))
        .unwrap_or_else(|e| panic!("read {name}.cbor: {e}"))
}

/// The hand-built message for fixture `name`.
pub fn expected(name: &str) -> MimiContent {
    match name {
        "original" => original(),
        "reply" => reply(),
        "reaction" => reaction(),
        "mention" => mention(),
        "mention-html" => mention_html(),
        "edit" => edit(),
        "delete" => delete(),
        "unlike" => unlike(),
        "expiring" => expiring(),
        "attachment" => attachment(),
        "conferencing" => conferencing(),
        "multipart-1" => multipart_1(),
        "multipart-2" => multipart_2(),
        "multipart-3" => multipart_3(),
        other => panic!("no expected value for fixture {other:?}"),
    }
}

/// Decodes a string of hex digit pairs.
pub fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn salt(s: &str) -> [u8; 16] {
    hex(s).try_into().expect("16-octet salt")
}

fn id(s: &str) -> MessageId {
    MessageId(hex(s).try_into().expect("32-octet message ID"))
}

fn extensions(sender: &str) -> Extensions {
    Extensions {
        sender_uri: Some(sender.to_owned()),
        room_uri: Some(ROOM.to_owned()),
    }
}

pub fn single(
    disposition: Disposition,
    language: &str,
    content_type: &str,
    content: &[u8],
) -> NestedPart {
    NestedPart {
        disposition,
        language: language.to_owned(),
        part: Part::Single {
            content_type: content_type.to_owned(),
            content: content.to_vec(),
        },
    }
}

pub fn multi(part_semantics: PartSemantics, parts: Vec<NestedPart>) -> NestedPart {
    NestedPart {
        disposition: Disposition::RENDER,
        language: String::new(),
        part: Part::Multi {
            part_semantics,
            parts,
        },
    }
}

/// A message with every behavior field empty except those the caller sets.
pub fn message(salt_hex: &str, sender: &str, nested_part: NestedPart) -> MimiContent {
    MimiContent {
        salt: salt(salt_hex),
        replaces: None,
        topic_id: Vec::new(),
        expires: None,
        in_reply_to: None,
        mimi_extensions: extensions(sender),
        nested_part,
    }
}

fn original() -> MimiContent {
    message(
        "5eed9406c2545547ab6f09f20a18b003",
        ALICE,
        single(
            Disposition::RENDER,
            "",
            MARKDOWN,
            b"Hi everyone, we just shipped release 2.0. __Good  work__!",
        ),
    )
}

fn reply() -> MimiContent {
    let mut content = message(
        "11a458c73b8dd2cf404db4b378b8fe4d",
        BOB,
        single(
            Disposition::RENDER,
            "",
            MARKDOWN,
            b"Right on! _Congratulations_ 'all!",
        ),
    );
    content.in_reply_to = Some(id(ORIGINAL_ID));
    content
}

fn reaction() -> MimiContent {
    // Content is U+2764 (e2 9d a4) as in the fixture bytes; the EDN comment
    // says U+2665 (decision mimid-1wgh.2.18).
    let mut content = message(
        "d37bc0e6a8b4f04e9e6382375f587bf6",
        CATHY,
        single(Disposition::REACTION, "", PLAIN, &hex("e29da4")),
    );
    content.in_reply_to = Some(id(ORIGINAL_ID));
    content
}

fn mention() -> MimiContent {
    let mut content = message(
        "04f290e215d0f82d1750bfa8b7dc089d",
        CATHY,
        single(
            Disposition::RENDER,
            "",
            MARKDOWN,
            b"Kudos to [@Alice Smith](mimi://example.com/u/alice-smith) for making the release happen!",
        ),
    );
    content.in_reply_to = Some(id(ORIGINAL_ID));
    content
}

fn mention_html() -> MimiContent {
    let mut content = message(
        "15d9705fd5bf5e02b0af47c85f8b98fe",
        CATHY,
        single(
            Disposition::RENDER,
            "",
            HTML,
            b"<p>Kudos to <a href=\"mimi://example.com/u/alice-smith\">@Alice Smith</a> for making the release happen!</p>",
        ),
    );
    content.in_reply_to = Some(id(ORIGINAL_ID));
    content
}

fn edit() -> MimiContent {
    let mut content = message(
        "b8c2e6d8800ecf45df39be6c45f4c042",
        BOB,
        single(
            Disposition::RENDER,
            "",
            MARKDOWN,
            b"Right on! _Congratulations_ y'all!",
        ),
    );
    content.replaces = Some(id(REPLY_ID));
    content.in_reply_to = Some(id(ORIGINAL_ID));
    content
}

fn delete() -> MimiContent {
    let mut content = message(
        "0a590d73b2c7761c39168be5ebf7f2e6",
        BOB,
        NestedPart {
            disposition: Disposition::RENDER,
            language: String::new(),
            part: Part::Null,
        },
    );
    content.replaces = Some(id(REPLY_ID));
    content.in_reply_to = Some(id(ORIGINAL_ID));
    content
}

fn unlike() -> MimiContent {
    let mut content = message(
        "c5ba86dc9fd272e58ca52ec805b79199",
        CATHY,
        NestedPart {
            disposition: Disposition::REACTION,
            language: String::new(),
            part: Part::Null,
        },
    );
    content.replaces = Some(id(REACTION_ID));
    content.in_reply_to = Some(id(ORIGINAL_ID));
    content
}

fn expiring() -> MimiContent {
    let mut content = message(
        "33be993eb39f418f9295afc2ae160d2d",
        ALICE,
        single(
            Disposition::RENDER,
            "",
            MARKDOWN,
            b"__*VPN GOING DOWN*__ I'm rebooting the VPN in ten minutes unless anyone objects.",
        ),
    );
    content.expires = Some(Expiration::Absolute(1_644_390_004));
    content
}

fn attachment() -> MimiContent {
    message(
        "18fac6371e4e53f1aeaf8a013155c166",
        BOB,
        NestedPart {
            disposition: Disposition::ATTACHMENT,
            language: "en".to_owned(),
            part: Part::External(ExternalPart {
                content_type: "video/mp4".to_owned(),
                url: "https://example.com/storage/8ksB4bSrrRE.mp4".to_owned(),
                expires: 0,
                size: 708_234_961,
                enc_alg: 1,
                key: hex("21399320958a6f4c745dde670d95e0d8"),
                nonce: hex("c86cf2c33f21527d1dd76f5b"),
                aad: Vec::new(),
                hash_alg: 1,
                content_hash: hex(
                    "9ab17a8cf0890baaae7ee016c7312fcc080ba46498389458ee44f0276e783163",
                ),
                description: "2 hours of key signing video".to_owned(),
                filename: "bigfile.mp4".to_owned(),
            }),
        },
    )
}

fn conferencing() -> MimiContent {
    let mut content = message(
        "678ac6cd54de049c3e9665cd212470fa",
        ALICE,
        NestedPart {
            disposition: Disposition::SESSION,
            language: String::new(),
            part: Part::External(ExternalPart {
                content_type: String::new(),
                url: "https://example.com/join/12345".to_owned(),
                expires: 0,
                size: 0,
                enc_alg: 0,
                key: Vec::new(),
                nonce: Vec::new(),
                aad: Vec::new(),
                hash_alg: 0,
                content_hash: Vec::new(),
                description: "Join the Foo 118 conference".to_owned(),
                filename: String::new(),
            }),
        },
    );
    content.topic_id = b"Foo 118".to_vec();
    content
}

fn multipart_1() -> MimiContent {
    message(
        "261c953e178af653fe3d42641b91d814",
        ALICE,
        multi(
            PartSemantics::ChooseOne,
            vec![
                single(Disposition::RENDER, "", MARKDOWN, b"# Welcome!"),
                single(
                    Disposition::RENDER,
                    "",
                    "application/vnd.examplevendor-fancy-im-message",
                    &hex("dc861ebaa718fd7c3ca159f71a2001"),
                ),
            ],
        ),
    )
}

fn multipart_2() -> MimiContent {
    let mut body = multi(
        PartSemantics::ProcessAll,
        vec![
            single(Disposition::REACTION, "", PLAIN, &hex("e29da4")),
            single(Disposition::REACTION, "", PLAIN, &hex("f09fa5b3")),
            single(Disposition::REACTION, "", PLAIN, &hex("f09fa49e")),
        ],
    );
    body.disposition = Disposition::REACTION;
    message("8528dc2d92e4f1944d62042907ab94d0", ALICE, body)
}

/// Four levels deep, the maximum (decision mimid-1wgh.2.13).
fn multipart_3() -> MimiContent {
    fn html_choice(cid: u8) -> NestedPart {
        let en = format!(
            "<html><body><h1>Welcome!</h1>\n<img src=\"cid:{cid}@local.invalid\" alt=\"Welcome image\"/>\n</body></html>"
        );
        let fr = format!(
            "<html><body><h1>Bienvenue!</h1>\n<img src=\"cid:{cid}@local.invalid\" alt=\"Image bienvenue\"/>\n</body></html>"
        );
        multi(
            PartSemantics::ChooseOne,
            vec![
                single(Disposition::RENDER, "en", HTML, en.as_bytes()),
                single(Disposition::RENDER, "fr", HTML, fr.as_bytes()),
            ],
        )
    }
    message(
        "b8362793168d18c049b882d4642a2274",
        ALICE,
        multi(
            PartSemantics::ChooseOne,
            vec![
                multi(
                    PartSemantics::ProcessAll,
                    vec![
                        html_choice(5),
                        single(
                            Disposition::INLINE,
                            "",
                            "image/gif",
                            &hex("dc861ebaa718fd7c3ca159f71a2001a7"),
                        ),
                    ],
                ),
                multi(
                    PartSemantics::ProcessAll,
                    vec![
                        html_choice(10),
                        single(
                            Disposition::INLINE,
                            "",
                            "image/png",
                            &hex("fa444237451a05a72bb0f67037cc1669"),
                        ),
                    ],
                ),
            ],
        ),
    )
}
