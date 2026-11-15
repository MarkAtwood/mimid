//! Unicode stress, JMAP slice (bead mimid-1wgh.54): what a JMAP client gets
//! back as a Chat's `name` and `description` when a room's `RoomMetaData`
//! (protocol-07 §7.6) holds hostile text.
//!
//! Every valid UTF-8 entry of the Big List of Naughty Strings (vendored in
//! mimi-content, see its PROVENANCE), and hand-written cases (Turkish i,
//! bidi controls, emoji ZWJ sequences, a BOM, every normalization form),
//! goes the whole way: encoded in a `RoomMetaData`, decoded, read by
//! [`RoomTexts`], written into a Chat object by [`Localized`] with and
//! without a `language` choice, serialized as the JSON a client receives,
//! and parsed back. The text must come back byte for byte: mimid neither
//! normalizes, folds, trims nor escapes display text beyond what JSON
//! requires (decision mimid-1wgh.52). End-to-end coverage through a hosted
//! room is in jmap_projection.rs.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mimi_protocol::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{IdentifierUri, RichDescription, RoomMetaData, Utf8String};
use mimid_server::hub::RoomTexts;
use mimid_server::jmap::language::Localized;
use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

const BLNS: &str = include_str!("../../mimi-content/tests/fixtures/blns/blns.base64.txt");

/// The list's valid UTF-8 entries.
fn naughty() -> Vec<String> {
    BLNS.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        // The list has one "=======" line, which is not base64; the other
        // stress tests read it as the empty string, which is in the list anyway.
        .filter_map(|line| STANDARD.decode(line).ok())
        .filter_map(|bytes| String::from_utf8(bytes).ok())
        .collect()
}

/// Hand-written cases the list lacks, each in all four normalization
/// forms.
fn hand_written() -> Vec<String> {
    let base = [
        "Iıİi",                             // Turkish dotted and dotless i
        "\u{202E}gnp.exe\u{202C}",          // RLO ... PDF
        "\u{2067}שלום\u{2069} world",       // RLI ... PDI
        "👩\u{200D}👩\u{200D}👧\u{200D}👦", // family ZWJ sequence
        "\u{FEFF}leading BOM",
        "e\u{301}cole",    // decomposed é
        "ﬁ ① ㎏ Ｆｕｌｌ", // compatibility characters
        "line\u{2028}separator\u{2029}",
    ];
    base.iter()
        .flat_map(|text| {
            [
                (*text).to_owned(),
                text.nfc().collect(),
                text.nfd().collect(),
                text.nfkc().collect(),
                text.nfkd().collect(),
            ]
        })
        .collect()
}

/// `room_metadata` naming the room `name` and describing it with
/// `descriptions` (language tag, text), through its wire encoding.
fn metadata(name: &str, descriptions: &[(&str, &str)]) -> RoomMetaData {
    let uri = IdentifierUri::new("mimi://a.example/r/one").unwrap();
    let sent = RoomMetaData {
        room_uri: uri.clone(),
        room_name: Utf8String::new(name.to_owned()).expect("no NUL"),
        room_descriptions: descriptions
            .iter()
            .map(|(tag, text)| RichDescription {
                media_type: Vec::new(),
                language_tag: tag.as_bytes().to_vec(),
                description_content: text.as_bytes().to_vec(),
            })
            .collect(),
        room_avatar: uri,
        room_subject: Utf8String::new(String::new()).unwrap(),
        room_mood: Utf8String::new(String::new()).unwrap(),
    };
    let wire = sent.tls_serialize_detached().unwrap();
    RoomMetaData::tls_deserialize_exact(&wire[..]).unwrap()
}

/// The Chat text a client receives: written, serialized, parsed back.
fn received(texts: &RoomTexts, i18n: bool, language: Option<&[String]>) -> Map<String, Value> {
    let mut object = Map::new();
    Localized::new(texts.name.clone(), &texts.descriptions).write(&mut object, i18n, language);
    let json = serde_json::to_string(&Value::Object(object)).unwrap();
    match serde_json::from_str(&json).unwrap() {
        Value::Object(object) => object,
        other => panic!("not an object: {other}"),
    }
}

#[test]
fn every_naughty_string_reaches_the_client_byte_for_byte() {
    let mut cases = naughty();
    assert!(cases.len() > 600, "the list loaded");
    cases.extend(hand_written());
    let german = vec!["de".to_owned()];
    for text in &cases {
        if text.contains('\0') {
            // UTF8String refuses NUL (decode: Utf8String::new); covered in
            // mimi-protocol's stress test.
            continue;
        }
        let texts = RoomTexts::from(&metadata(text, &[("en", "plain"), ("de", text)]));
        assert_eq!(texts.name, *text);

        let plain = received(&texts, false, None);
        assert_eq!(plain["name"], Value::String(text.clone()), "{text:?}");
        assert_eq!(plain["description"], "plain", "{text:?}");

        let stored = received(&texts, true, None);
        assert_eq!(
            stored["localizations"]["de"]["description"],
            Value::String(text.clone()),
            "{text:?}"
        );

        let view = received(&texts, true, Some(&german));
        assert_eq!(view["description"], Value::String(text.clone()), "{text:?}");
        assert_eq!(view["locale"], "de");
    }
}

#[test]
fn normalization_forms_stay_distinct_names() {
    // NFC and NFD of "école" are different bytes and stay different Chat
    // names: mimid compares and shows display text as sent.
    let nfc: String = "école".nfc().collect();
    let nfd: String = "école".nfd().collect();
    assert_ne!(nfc, nfd);
    let names: Vec<Value> = [&nfc, &nfd]
        .iter()
        .map(|name| received(&RoomTexts::from(&metadata(name, &[])), false, None)["name"].clone())
        .collect();
    assert_eq!(names, [Value::String(nfc), Value::String(nfd)]);
}

#[test]
fn a_hostile_language_tag_is_never_chosen_by_lookup() {
    // Tags come from another provider unchecked. A malformed one is not a
    // localization key, and no range selects its text.
    let texts = RoomTexts::from(&metadata(
        "room",
        &[
            ("en", "plain"),
            ("\u{202E}de", "reversed"),
            ("de\u{0}", "nul"),
        ],
    ));
    let stored = received(&texts, true, None);
    assert_eq!(
        stored["localizations"],
        serde_json::json!({"en": {"description": "plain"}})
    );
    let view = received(&texts, true, Some(&["de".to_owned()]));
    assert_eq!(view["description"], "plain");
    assert_eq!(view["locale"], Value::Null);
}
