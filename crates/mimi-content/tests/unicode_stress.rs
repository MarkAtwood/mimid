//! Unicode stress (bead mimid-1wgh.54, first slice): text that breaks
//! things, through every text-carrying field of a MIMI content message.
//!
//! Oracles:
//! - the Big List of Naughty Strings (`fixtures/blns`, see its PROVENANCE):
//!   every valid UTF-8 entry must survive encode then decode unchanged, in
//!   every field, and re-encode to the same bytes; every entry, valid or
//!   not, must survive as the opaque body;
//! - hand-written cases for what the list covers thinly: the Turkish i, the
//!   same text in NFC and NFD, bidi controls, ZWJ emoji, a BOM, and a long
//!   run of combining marks;
//! - CBOR's own rule (RFC 8949 §3.1 major type 3) that a text string is
//!   UTF-8: an invalid entry spliced into a text-string field on the wire
//!   must be refused.
//!
//! mimid never normalizes or case-folds content: NFC and NFD forms of the
//! same text stay distinct, byte for byte.

use std::collections::BTreeMap;

use mimi_content::{
    DecodeError, Disposition, Extensions, ExternalPart, MimiContent, NestedPart, Part,
    PartSemantics,
};

const BLNS: &str = include_str!("fixtures/blns/blns.base64.txt");

/// Every entry of the list, as bytes: one standard base64 entry per line;
/// `#` lines are comments and blank lines separate sections.
fn naughty() -> Vec<Vec<u8>> {
    BLNS.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| base64(line.trim()))
        .collect()
}

/// Standard base64 (RFC 4648 §4) with padding, enough for the fixture;
/// mimi-content takes no base64 dependency for one test.
fn base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes().take_while(|&c| c != b'=') {
        let value = ALPHABET
            .iter()
            .position(|&a| a == c)
            .unwrap_or_else(|| panic!("not base64: {text}"));
        bits = (bits << 6) | u32::try_from(value).unwrap();
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).unwrap());
        }
    }
    out
}

/// The hand-written cases.
fn extra() -> Vec<String> {
    let mut cases: Vec<String> = [
        // Turkish i: dotted capital, dotless small, and the ASCII pair.
        "\u{0130}stanbul \u{0131}\u{0049}\u{0069}",
        "D\u{0130}YARBAKIR",
        // NFC é and NFD e + combining acute: must stay distinct.
        "caf\u{00E9}",
        "cafe\u{0301}",
        // Hangul precomposed vs conjoining jamo.
        "\u{D55C}",
        "\u{1112}\u{1161}\u{11AB}",
        // German sharp s and its capital.
        "Stra\u{00DF}e STRA\u{1E9E}E",
        // Bidi: RLO, LRI ... PDI, RLM, and Arabic with digits.
        "\u{202E}gnp.exe",
        "abc \u{2066}\u{05E9}\u{05DC}\u{05D5}\u{05DD}\u{2069} def",
        "\u{200F}\u{0645}\u{0631}\u{062D}\u{0628}\u{0627} 123",
        // ZWJ emoji family, flag, skin tone.
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466} \u{1F1FA}\u{1F1F8} \u{1F44D}\u{1F3FD}",
        // A byte order mark at the start, zero-width space and joiner inside.
        "\u{FEFF}hello\u{200B}wor\u{200D}ld",
        // Noncharacter and the replacement character.
        "\u{FFFE}\u{FFFF}\u{FFFD}",
        // Astral plane: Linear B, math bold.
        "\u{10000}\u{1D400}\u{1D7FF}",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    // 2047 combining marks on one base character (a "Zalgo" stack): 4095
    // octets, just under mimid's 4096-octet topicId cap.
    cases.push(format!("a{}", "\u{0301}".repeat(2047)));
    cases
}

fn plain(body: Vec<u8>) -> NestedPart {
    NestedPart {
        disposition: Disposition::RENDER,
        language: String::new(),
        part: Part::Single {
            content_type: "text/plain;charset=utf-8".to_owned(),
            content: body,
        },
    }
}

/// A message carrying `text` in every text field it has: the body, the
/// attachment's description and filename, and the topic id.
fn carrying(text: &str) -> MimiContent {
    MimiContent {
        salt: [0x5a; 16],
        replaces: None,
        topic_id: text.as_bytes().to_vec(),
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions {
            sender_uri: None,
            room_uri: None,
            other: BTreeMap::new(),
        },
        nested_part: NestedPart {
            disposition: Disposition::RENDER,
            language: String::new(),
            part: Part::Multi {
                part_semantics: PartSemantics::ProcessAll,
                parts: vec![
                    plain(text.as_bytes().to_vec()),
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

fn round_trip(label: &str, message: &MimiContent) {
    let bytes = message
        .encode()
        .unwrap_or_else(|e| panic!("{label}: encode: {e}"));
    let decoded = MimiContent::decode(&bytes).unwrap_or_else(|e| panic!("{label}: decode: {e}"));
    assert_eq!(&decoded, message, "{label}: changed in transit");
    assert_eq!(
        decoded.encode().unwrap(),
        bytes,
        "{label}: re-encoding differs"
    );
}

#[test]
fn every_valid_naughty_string_survives_every_text_field() {
    let mut valid = 0;
    for (index, entry) in naughty().iter().enumerate() {
        if let Ok(text) = std::str::from_utf8(entry) {
            round_trip(&format!("blns[{index}]"), &carrying(text));
            valid += 1;
        }
    }
    assert!(valid > 600, "the list shrank: {valid} valid entries");
}

#[test]
fn every_naughty_entry_survives_as_the_opaque_body() {
    for (index, entry) in naughty().into_iter().enumerate() {
        let message = MimiContent {
            nested_part: plain(entry),
            ..carrying("")
        };
        round_trip(&format!("blns[{index}] as body"), &message);
    }
}

#[test]
fn hand_written_cases_survive_every_text_field() {
    for (index, text) in extra().iter().enumerate() {
        round_trip(&format!("extra[{index}]"), &carrying(text));
    }
}

#[test]
fn nfc_and_nfd_forms_stay_distinct() {
    let nfc = carrying("caf\u{00E9}").encode().unwrap();
    let nfd = carrying("cafe\u{0301}").encode().unwrap();
    assert_ne!(nfc, nfd, "content must not be normalized");
}

#[test]
fn invalid_utf8_in_a_text_field_is_refused_on_the_wire() {
    // Encode with a placeholder filename of the same length as the invalid
    // entry, then swap the bytes in: the CBOR text-string header stays
    // right, only the content is no longer UTF-8.
    let invalid: Vec<Vec<u8>> = naughty()
        .into_iter()
        .filter(|entry| std::str::from_utf8(entry).is_err())
        .collect();
    assert!(!invalid.is_empty());
    for (index, entry) in invalid.iter().enumerate() {
        let placeholder = "Q".repeat(entry.len());
        let mut message = carrying("");
        let Part::Multi { parts, .. } = &mut message.nested_part.part else {
            unreachable!()
        };
        let Part::External(external) = &mut parts[1].part else {
            unreachable!()
        };
        external.filename = placeholder.clone();
        let mut bytes = message.encode().unwrap();
        let at = bytes
            .windows(placeholder.len())
            .position(|w| w == placeholder.as_bytes())
            .expect("placeholder present once");
        bytes[at..at + entry.len()].copy_from_slice(entry);
        assert!(
            matches!(
                MimiContent::decode(&bytes),
                Err(DecodeError::InvalidUtf8 { .. })
            ),
            "invalid[{index}] {entry:02x?} was not refused as invalid UTF-8"
        );
    }
}

#[test]
fn a_topic_id_over_the_cap_is_refused_whatever_its_text() {
    // mimid caps topicId at 4096 octets; the cap counts octets, so a stack
    // of combining marks reaches it at half the characters.
    let over = format!("a{}", "\u{0301}".repeat(2048));
    assert_eq!(over.len(), 4097);
    assert!(carrying(&over).encode().is_err());
}
