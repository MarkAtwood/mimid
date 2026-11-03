//! mimid <-> Phoenix mimi-content cross-check (bead mimid-1wgh.46.2).
//!
//!   mimid-phoenix-xcheck wg <dir>      Phoenix decodes each WG -10 example in
//!                                      <dir>, re-encodes it, compares bytes,
//!                                      and computes the message ID, at both
//!                                      Phoenix revisions.
//!   mimid-phoenix-xcheck write <dir>   Phoenix (main) encodes messages built
//!                                      from fixed inputs into <dir>, and
//!                                      reports whether PR #20 encodes the
//!                                      same values identically.
//!
//! The URIs and expected message IDs are copied from
//! crates/mimi-content/tests/message_id.rs and tests/common/mod.rs.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

const ROOM: &str = "mimi://example.com/r/engineering_team";
const ALICE: &str = "mimi://example.com/u/alice-smith";
const BOB: &str = "mimi://example.com/u/bob-jones";
const CATHY: &str = "mimi://example.com/u/cathy-washington";

/// (example, sender, expected message ID) for the WG -10 examples.
const EXAMPLES: [(&str, &str, &str); 14] = [
    (
        "original",
        ALICE,
        "017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4",
    ),
    (
        "reply",
        BOB,
        "015354973c2b65ca937bf1e035ae53a5ab80e947afa43d46920d4202e5cc0b27",
    ),
    (
        "reaction",
        CATHY,
        "0158c4288911e50a8f6be3f47746b6682f10fd91bc8c05557aa589a3157aff68",
    ),
    (
        "mention",
        CATHY,
        "018d825adf9f6be00dcafc5704c4102f5022e74219d0b603e4ba7622654042af",
    ),
    (
        "mention-html",
        CATHY,
        "01967ff8e9a66819738ad5cf26d2e0388a3b81d86b0f61d129c077d043ee2a4e",
    ),
    (
        "edit",
        BOB,
        "014028c0deddbdea56bec26172f6ede953d11024cb82b8192b5e2aea62d7fb47",
    ),
    (
        "delete",
        BOB,
        "011d9efc78d04d4dcf4d82b07d5199bbef37011c1f0c7e004b6111c6dda504b4",
    ),
    (
        "unlike",
        CATHY,
        "013aadbb8f313253c8930f4e93c6ca54b2ed06d258185bdcec3870534c8a4ec4",
    ),
    (
        "expiring",
        ALICE,
        "01e59db8173939facc2c8a4a0f0ae8d0c7a11a81239626630c9464a8d6717a03",
    ),
    (
        "attachment",
        BOB,
        "0176180c7d19a925021fe446d241134d05c38e0d999cdc0f39c391d2377ed9d1",
    ),
    (
        "conferencing",
        ALICE,
        "01496d15a8dba28d7397f9868b70768e4a67f765d5b5b1ae9e03848c5fdeb0ba",
    ),
    (
        "multipart-1",
        ALICE,
        "01da5a515ec5db42cc4dcc19b90c3c31245d8a1cfcce11318f24eb11dce0990e",
    ),
    (
        "multipart-2",
        ALICE,
        "01d65918c6c51c8e76546337276ae6f4bfd873d867d5cb57c76bcdca3d999dd7",
    ),
    (
        "multipart-3",
        ALICE,
        "01cfebeadbdb83c1eefb6403ba4852daf8bbbf9cd53bf5035a74d5d741950c9f",
    ),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A 32-byte message ID: hash algorithm 1 (SHA-256), then 31 copies of `fill`.
fn message_id(fill: u8) -> Vec<u8> {
    let mut id = vec![0x01];
    id.extend([fill; 31]);
    id
}

macro_rules! phoenix {
    ($module:ident, $krate:ident) => {
        mod $module {
            use std::collections::BTreeMap;

            use $krate::cbor::Value;
            use $krate::content_container::{
                EncryptionAlgorithm, Expiration, ExtensionName, HashAlgorithm, PartSemantics,
            };
            use $krate::{Disposition, MessageStatus, MimiContent, NestedPart};

            /// Decode, re-encode, compare, and compute the message ID.
            /// Returns (decoded, identical, id matches, detail).
            pub fn check(
                bytes: &[u8],
                sender: &str,
                expected_id: &str,
            ) -> (bool, bool, bool, String) {
                let content = match MimiContent::deserialize(bytes) {
                    Ok(content) => content,
                    Err(e) => return (false, false, false, format!("decode: {e}")),
                };
                let (identical, mut detail) = match content.serialize() {
                    Ok(out) if out == bytes => (true, String::new()),
                    Ok(out) => (
                        false,
                        format!("re-encoded {} bytes, input {}", out.len(), bytes.len()),
                    ),
                    Err(e) => (false, format!("encode: {e}")),
                };
                let id = content
                    .message_id(sender.as_bytes(), super::ROOM.as_bytes())
                    .map(|id| super::hex(&id))
                    .unwrap_or_else(|e| format!("error {e}"));
                let id_ok = id == expected_id;
                if !id_ok {
                    if !detail.is_empty() {
                        detail.push_str("; ");
                    }
                    detail.push_str(&format!("id {id}"));
                }
                (true, identical, id_ok, detail)
            }

            fn plain(text: &str) -> NestedPart {
                NestedPart::SinglePart {
                    disposition: Disposition::Render,
                    language: "en".to_owned(),
                    content_type: "text/plain;charset=utf-8".to_owned(),
                    content: text.as_bytes().to_vec(),
                }
            }

            fn base(salt: u8, nested_part: NestedPart) -> MimiContent {
                MimiContent {
                    salt: vec![salt; 16],
                    replaces: None,
                    topic_id: Vec::new(),
                    expires: None,
                    in_reply_to: None,
                    extensions: BTreeMap::new(),
                    nested_part,
                }
            }

            /// The messages B commits, from fixed inputs (values listed in
            /// crates/mimi-content/tests/fixtures/phoenix/VALUES).
            pub fn messages() -> Vec<(&'static str, Vec<u8>)> {
                let markdown =
                    MimiContent::simple_markdown_message("Hello, *world*".to_owned(), [0x11; 16]);
                let (_, receipt) = MimiContent::simple_receipt(
                    &[&super::message_id(0xaa)],
                    [0x22; 16],
                    MessageStatus::Read,
                )
                .expect("receipt");

                let mut extensions = base(0x33, plain("hi"));
                extensions.replaces = Some(super::message_id(0xbb));
                extensions.topic_id = b"topic-1".to_vec();
                extensions.expires = Some(Expiration {
                    relative: true,
                    time: 3600,
                });
                extensions.in_reply_to = Some(super::message_id(0xcc));
                extensions
                    .extensions
                    .insert(ExtensionName::Number(1), Value::Text(super::ALICE.into()));
                extensions
                    .extensions
                    .insert(ExtensionName::Number(2), Value::Text(super::ROOM.into()));
                let mut map = BTreeMap::new();
                map.insert(Value::Text("aa".into()), Value::Int(1));
                map.insert(Value::Text("b".into()), Value::Int(-2));
                extensions
                    .extensions
                    .insert(ExtensionName::Text("x-phx".to_owned()), Value::Map(map));

                let multipart = base(
                    0x44,
                    NestedPart::MultiPart {
                        disposition: Disposition::Render,
                        language: String::new(),
                        part_semantics: PartSemantics::ChooseOne,
                        parts: vec![
                            plain("hi"),
                            NestedPart::SinglePart {
                                disposition: Disposition::Render,
                                language: "en".to_owned(),
                                content_type: "text/html;charset=utf-8".to_owned(),
                                content: b"<b>hi</b>".to_vec(),
                            },
                        ],
                    },
                );

                let external = base(
                    0x55,
                    NestedPart::ExternalPart {
                        disposition: Disposition::Attachment,
                        language: String::new(),
                        content_type: "image/png".to_owned(),
                        url: "https://example.com/f/1".to_owned(),
                        expires: 0,
                        size: 1024,
                        enc_alg: EncryptionAlgorithm::Aes128Gcm,
                        key: vec![0x55; 16],
                        nonce: vec![0x66; 12],
                        aad: Vec::new(),
                        hash_alg: HashAlgorithm::Sha256,
                        content_hash: vec![0x77; 32],
                        description: "a picture".to_owned(),
                        filename: "pic.png".to_owned(),
                    },
                );

                let mut float = base(0x66, plain("hi"));
                float
                    .extensions
                    .insert(ExtensionName::Text("x-float".to_owned()), Value::Float(1.5));

                [
                    ("markdown", markdown),
                    ("receipt", receipt),
                    ("extensions", extensions),
                    ("multipart", multipart),
                    ("external", external),
                    ("float", float),
                ]
                .into_iter()
                .map(|(name, content)| (name, content.serialize().expect("encode")))
                .collect()
            }
        }
    };
}

phoenix!(main_rev, phx_main);
phoenix!(pr20_rev, phx_pr20);

fn wg(dir: &Path) -> ExitCode {
    for (label, check) in [
        (
            "main 31487f9",
            main_rev::check as fn(&[u8], &str, &str) -> (bool, bool, bool, String),
        ),
        ("PR #20 6378938", pr20_rev::check),
    ] {
        println!("== Phoenix {label}");
        println!(
            "{:<14} {:<7} {:<10} {:<9} detail",
            "example", "decode", "identical", "id"
        );
        for (name, sender, expected) in EXAMPLES {
            let bytes = match fs::read(dir.join(format!("{name}.cbor"))) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("{name}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let (decoded, identical, id_ok, detail) = check(&bytes, sender, expected);
            println!("{name:<14} {decoded:<7} {identical:<10} {id_ok:<9} {detail}");
        }
    }
    ExitCode::SUCCESS
}

fn write(dir: &Path) -> ExitCode {
    if let Err(e) = fs::create_dir_all(dir) {
        eprintln!("{}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
    let main = main_rev::messages();
    let pr20 = pr20_rev::messages();
    for ((name, bytes), (_, pr20_bytes)) in main.iter().zip(&pr20) {
        let same = if bytes == pr20_bytes {
            "identical"
        } else {
            "DIFFERENT"
        };
        println!("{name}: {} bytes, PR #20 output {same}", bytes.len());
        if let Err(e) = fs::write(dir.join(format!("{name}.cbor")), bytes) {
            eprintln!("{name}: {e}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_, mode, dir] if mode == "wg" => wg(Path::new(dir)),
        [_, mode, dir] if mode == "write" => write(Path::new(dir)),
        _ => {
            eprintln!("usage: mimid-phoenix-xcheck (wg|write) <dir>");
            ExitCode::FAILURE
        }
    }
}
