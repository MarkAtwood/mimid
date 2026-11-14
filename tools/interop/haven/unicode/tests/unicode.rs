//! Unicode stress (bead mimid-1wgh.54) through Haven's mimi-core, at the
//! commit pinned in Cargo.toml, cross-checked against mimid's encoders.
//!
//! Inputs: the Big List of Naughty Strings vendored in mimid
//! (crates/mimi-content/tests/fixtures/blns, PROVENANCE there), mimid's
//! hand-written cases, and every string in its four normalization forms.
//!
//! Each test collects every difference and prints them all before failing,
//! so one run gives the whole report. Run with `--nocapture` to see the
//! summaries of passing tests too.

use std::collections::BTreeMap;

use mimi_core::content::{
    from_content08_cbor, to_content08_cbor, Disposition as HDisposition, MimiContent as HContent,
    NestedPart as HNested, PartBody, PartSemantics as HSemantics,
};
use mimi_core::protocol_wire::IdentifierResponse;
use mimi_core::uri::MimiUri;
use unicode_normalization::UnicodeNormalization;

const BLNS: &str = include_str!("../../../../../crates/mimi-content/tests/fixtures/blns/blns.base64.txt");

fn naughty() -> Vec<Vec<u8>> {
    BLNS.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| base64(line.trim()))
        .collect()
}

/// Standard base64 with padding (RFC 4648 §4), enough for the fixture.
fn base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut bits, mut count, mut out) = (0u32, 0, Vec::new());
    for c in text.bytes().take_while(|&c| c != b'=') {
        let value = ALPHABET.iter().position(|&a| a == c).expect("base64");
        bits = (bits << 6) | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(((bits >> count) & 0xff) as u8);
        }
    }
    out
}

/// mimid's hand-written cases (crates/mimi-content/tests/unicode_stress.rs).
fn extra() -> Vec<String> {
    let mut cases: Vec<String> = [
        "\u{0130}stanbul \u{0131}\u{0049}\u{0069}",
        "D\u{0130}YARBAKIR",
        "caf\u{00E9}",
        "cafe\u{0301}",
        "\u{D55C}",
        "\u{1112}\u{1161}\u{11AB}",
        "Stra\u{00DF}e STRA\u{1E9E}E",
        "\u{202E}gnp.exe",
        "abc \u{2066}\u{05E9}\u{05DC}\u{05D5}\u{05DD}\u{2069} def",
        "\u{200F}\u{0645}\u{0631}\u{062D}\u{0628}\u{0627} 123",
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466} \u{1F1FA}\u{1F1F8} \u{1F44D}\u{1F3FD}",
        "\u{FEFF}hello\u{200B}wor\u{200D}ld",
        "\u{FFFE}\u{FFFF}\u{FFFD}",
        "\u{10000}\u{1D400}\u{1D7FF}",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    cases.push(format!("a{}", "\u{0301}".repeat(2047)));
    cases
}

/// Every valid naughty string and hand-written case, each in its original
/// form and its four normalization forms (duplicates removed), labelled.
fn texts() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let bases: Vec<(String, String)> = naughty()
        .into_iter()
        .enumerate()
        .filter_map(|(i, e)| String::from_utf8(e).ok().map(|t| (format!("blns[{i}]"), t)))
        .chain(extra().into_iter().enumerate().map(|(i, t)| (format!("extra[{i}]"), t)))
        .collect();
    for (label, text) in bases {
        let forms = [
            ("", text.clone()),
            (" NFC", text.nfc().collect()),
            (" NFD", text.nfd().collect()),
            (" NFKC", text.nfkc().collect()),
            (" NFKD", text.nfkd().collect()),
        ];
        for (form, t) in forms {
            if t.len() <= 4096 && seen.insert(t.clone()) {
                out.push((format!("{label}{form}"), t));
            }
        }
    }
    out
}

fn report(name: &str, checked: usize, problems: &[String]) {
    println!("{name}: {checked} checked, {} problems", problems.len());
    for p in problems.iter().take(40) {
        println!("  {p}");
    }
    if problems.len() > 40 {
        println!("  ... and {} more", problems.len() - 40);
    }
    assert!(problems.is_empty(), "{name}: {} problems", problems.len());
}

// ---- content ----

fn haven_carrying(text: &str) -> HContent {
    HContent {
        salt: [0x5a; 16],
        replaces: None,
        topic_id: text.as_bytes().to_vec(),
        expires: None,
        in_reply_to: None,
        mimi_extensions: vec![],
        nested_part: HNested {
            disposition: HDisposition::Render,
            language: String::new(),
            body: PartBody::Multi {
                semantics: HSemantics::ProcessAll,
                parts: vec![
                    HNested {
                        disposition: HDisposition::Render,
                        language: String::new(),
                        body: PartBody::Single {
                            content_type: "text/plain;charset=utf-8".to_owned(),
                            content: text.as_bytes().to_vec(),
                        },
                    },
                    HNested {
                        disposition: HDisposition::Attachment,
                        language: String::new(),
                        body: PartBody::External {
                            content_type: "application/octet-stream".to_owned(),
                            url: "https://a.example/f".to_owned(),
                            expires: 0,
                            size: 0,
                            enc_alg: 0,
                            key: vec![],
                            nonce: vec![],
                            aad: vec![],
                            hash_alg: 0,
                            content_hash: vec![],
                            description: text.to_owned(),
                            filename: text.to_owned(),
                        },
                    },
                ],
            },
        },
    }
}

fn mimid_carrying(text: &str) -> mimi_content::MimiContent {
    use mimi_content::{Disposition, Extensions, ExternalPart, MimiContent, NestedPart, Part, PartSemantics};
    MimiContent {
        salt: [0x5a; 16],
        replaces: None,
        topic_id: text.as_bytes().to_vec(),
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions { sender_uri: None, room_uri: None, other: BTreeMap::new() },
        nested_part: NestedPart {
            disposition: Disposition::RENDER,
            language: String::new(),
            part: Part::Multi {
                part_semantics: PartSemantics::ProcessAll,
                parts: vec![
                    NestedPart {
                        disposition: Disposition::RENDER,
                        language: String::new(),
                        part: Part::Single {
                            content_type: "text/plain;charset=utf-8".to_owned(),
                            content: text.as_bytes().to_vec(),
                        },
                    },
                    NestedPart {
                        disposition: Disposition::ATTACHMENT,
                        language: String::new(),
                        part: Part::External(ExternalPart {
                            content_type: "application/octet-stream".to_owned(),
                            url: "https://a.example/f".to_owned(),
                            expires: 0,
                            size: 0,
                            enc_alg: 0,
                            key: vec![],
                            nonce: vec![],
                            aad: vec![],
                            hash_alg: 0,
                            content_hash: vec![],
                            description: text.to_owned(),
                            filename: text.to_owned(),
                        }),
                    },
                ],
            },
        },
    }
}

#[test]
fn content_text_fields_round_trip_in_haven_and_match_mimid_bytes() {
    let texts = texts();
    let mut problems = Vec::new();
    for (label, text) in &texts {
        let haven = match to_content08_cbor(&haven_carrying(text)) {
            Ok(b) => b,
            Err(e) => {
                problems.push(format!("{label}: Haven refuses to encode: {e}"));
                continue;
            }
        };
        match from_content08_cbor(&haven) {
            Ok(back) if back == haven_carrying(text) => {}
            Ok(_) => problems.push(format!("{label}: Haven decodes its own encoding to something else")),
            Err(e) => problems.push(format!("{label}: Haven refuses its own encoding: {e}")),
        }
        match mimid_carrying(text).encode() {
            Ok(mimid) if mimid == haven => {}
            Ok(_) => problems.push(format!("{label}: Haven's and mimid's bytes differ")),
            Err(e) => problems.push(format!("{label}: mimid refuses to encode: {e}")),
        }
    }
    report("content text fields", texts.len(), &problems);
}

#[test]
fn every_naughty_entry_survives_as_a_haven_body() {
    let entries = naughty();
    let mut problems = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let mut message = haven_carrying("");
        message.nested_part = HNested {
            disposition: HDisposition::Render,
            language: String::new(),
            body: PartBody::Single {
                content_type: "application/octet-stream".to_owned(),
                content: entry.clone(),
            },
        };
        match to_content08_cbor(&message).map(|b| from_content08_cbor(&b)) {
            Ok(Ok(back)) if back == message => {}
            Ok(Ok(_)) => problems.push(format!("blns[{i}]: body changed")),
            Ok(Err(e)) | Err(e) => problems.push(format!("blns[{i}]: {e}")),
        }
    }
    report("opaque body", entries.len(), &problems);
}

#[test]
fn haven_refuses_invalid_utf8_in_a_text_string() {
    let invalid: Vec<Vec<u8>> = naughty()
        .into_iter()
        .filter(|e| std::str::from_utf8(e).is_err())
        .collect();
    let mut problems = Vec::new();
    for entry in &invalid {
        let placeholder = "Q".repeat(entry.len());
        let mut bytes = to_content08_cbor(&haven_carrying("")).unwrap();
        // Put the placeholder in the filename, then swap the bytes in.
        let mut message = haven_carrying("");
        if let PartBody::Multi { parts, .. } = &mut message.nested_part.body {
            if let PartBody::External { filename, .. } = &mut parts[1].body {
                *filename = placeholder.clone();
            }
        }
        bytes = to_content08_cbor(&message).unwrap_or(bytes);
        let at = bytes
            .windows(placeholder.len())
            .position(|w| w == placeholder.as_bytes())
            .unwrap();
        bytes[at..at + entry.len()].copy_from_slice(entry);
        if from_content08_cbor(&bytes).is_ok() {
            problems.push(format!("{entry:02x?} accepted as a filename"));
        }
    }
    report("invalid UTF-8 refused", invalid.len(), &problems);
}

// ---- URIs ----

/// What mimid takes as a URI: RFC 3986, so ASCII only. Haven's MimiUri is
/// a routing parser, so this test reports what it accepts that mimid's
/// IdentifierUri would refuse, without failing: the drafts don't say.
#[test]
fn haven_uri_parser_on_naughty_and_non_ascii_uris() {
    let mut accepted_non_ascii = Vec::new();
    let mut checked = 0;
    for entry in naughty() {
        let Ok(text) = String::from_utf8(entry) else { continue };
        for candidate in [text.clone(), format!("mimi://example.jp/u/{text}"), format!("mimi://{text}/u/alice")] {
            checked += 1;
            if MimiUri::parse(&candidate).is_ok() && !candidate.is_ascii() {
                accepted_non_ascii.push(candidate);
            }
        }
    }
    for candidate in [
        "mimi://example.jp/u/\u{30E6}\u{30FC}\u{30B6}\u{30FC}",
        "mimi://\u{4F8B}\u{3048}.jp/u/alice",
        "\u{FF4D}\u{FF49}\u{FF4D}\u{FF49}\u{FF1A}\u{FF0F}\u{FF0F}a.example/u/alice",
        "MIMI://a.example/u/alice",
    ] {
        checked += 1;
        println!("  {candidate:?}: {}", if MimiUri::parse(candidate).is_ok() { "accepted" } else { "refused" });
    }
    println!(
        "URI parser: {checked} checked, {} non-ASCII accepted (mimid refuses these)",
        accepted_non_ascii.len()
    );
    for c in accepted_non_ascii.iter().take(10) {
        println!("  accepted: {c:?}");
    }
}

/// IdentifierResponse carrying `uri`, hand-encoded from protocol-07 §5.8.
fn identifier_response(uri: &[u8]) -> Vec<u8> {
    fn vl(b: &[u8]) -> Vec<u8> {
        let mut out = if b.len() < 0x40 { vec![b.len() as u8] } else { ((b.len() as u16) | 0x4000).to_be_bytes().to_vec() };
        out.extend_from_slice(b);
        out
    }
    let mut out = vec![0x00];
    out.extend(vl(&vl(uri)));
    out.extend([0x00, 0x00]);
    out
}

#[test]
fn haven_identifier_uri_keeps_valid_text_and_refuses_invalid() {
    let entries = naughty();
    let mut problems = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        if entry.len() >= 0x3fff - 4 {
            continue;
        }
        let decoded = IdentifierResponse::decode(&identifier_response(entry));
        match (std::str::from_utf8(entry), decoded) {
            (Ok(text), Ok(r)) if r.uris.len() == 1 && r.uris[0].0 == text => {}
            (Ok(_), Ok(_)) => problems.push(format!("blns[{i}]: decoded to a different URI")),
            (Ok(_), Err(e)) => problems.push(format!("blns[{i}]: valid UTF-8 refused: {e}")),
            (Err(_), Ok(_)) => problems.push(format!("blns[{i}]: invalid UTF-8 accepted")),
            (Err(_), Err(_)) => {}
        }
    }
    report("IdentifierUri", entries.len(), &problems);
}

// ---- room policy ----

fn mimid_role_data(name: &str) -> Vec<u8> {
    use mimi_room_policy::tls_codec::Serialize;
    use mimi_room_policy::{Role, RoleData};
    RoleData {
        roles: vec![Role {
            role_index: 2,
            role_name: name.to_owned(),
            role_description: name.to_owned(),
            role_capabilities: vec![],
            minimum_participants_constraint: 0,
            maximum_participants_constraint: None,
            minimum_active_participants_constraint: 0,
            maximum_active_participants_constraint: None,
            authorized_role_changes: vec![],
        }],
    }
    .tls_serialize_detached()
    .unwrap()
}

#[test]
fn role_names_cross_both_ways() {
    use mimi_room_policy::tls_codec::Deserialize;
    // Haven reads a role name of at most 1024 octets (its decode budget);
    // mimid sets no limit and room-policy-04 gives none. Longer names are
    // reported, not failed.
    const HAVEN_ROLE_NAME_LIMIT: usize = 1024;
    let texts = texts();
    let mut problems = Vec::new();
    let over: Vec<&String> = texts
        .iter()
        .filter(|(_, t)| t.len() > HAVEN_ROLE_NAME_LIMIT)
        .map(|(l, _)| l)
        .collect();
    println!("role names over Haven's {HAVEN_ROLE_NAME_LIMIT}-octet limit, not checked: {over:?}");
    for (label, text) in texts.iter().filter(|(_, t)| t.len() <= HAVEN_ROLE_NAME_LIMIT) {
        match mimi_core::room_policy_wire::decode_role_data(&mimid_role_data(text)) {
            Ok(roles) if roles.len() == 1 && roles[0].role_name == *text => {}
            Ok(_) => problems.push(format!("{label}: Haven read a different role name")),
            Err(e) => problems.push(format!("{label}: Haven refuses mimid's role: {e}")),
        }
        let haven = mimi_core::room_policy_wire::encode_role_data(&[mimi_core::room_policy::Role {
            role_index: 2,
            role_name: text.clone(),
            capabilities: vec![],
            authorized_role_changes: vec![],
        }]);
        match mimi_room_policy::RoleData::tls_deserialize_exact(&haven[..]) {
            Ok(r) if r.roles.len() == 1 && r.roles[0].role_name == *text => {}
            Ok(_) => problems.push(format!("{label}: mimid read a different role name")),
            Err(e) => problems.push(format!("{label}: mimid refuses Haven's role: {e:?}")),
        }
    }
    report("role names", texts.len(), &problems);
}

#[test]
fn haven_refuses_a_role_name_that_is_not_utf8() {
    let invalid: Vec<Vec<u8>> = naughty()
        .into_iter()
        .filter(|e| std::str::from_utf8(e).is_err())
        .collect();
    let mut problems = Vec::new();
    for entry in &invalid {
        let placeholder = "Q".repeat(entry.len());
        let mut wire = mimid_role_data(&placeholder);
        let at = wire.windows(placeholder.len()).position(|w| w == placeholder.as_bytes()).unwrap();
        wire[at..at + entry.len()].copy_from_slice(entry);
        if mimi_core::room_policy_wire::decode_role_data(&wire).is_ok() {
            problems.push(format!("{entry:02x?} accepted"));
        }
    }
    report("invalid role names refused", invalid.len(), &problems);
}
