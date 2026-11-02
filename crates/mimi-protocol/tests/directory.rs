//! Tests for the protocol-06 §5.1 directory and RFC 6570 level 1 expansion.
//!
//! The directory oracle is the §5.1 example JSON copied from
//! draft-ietf-mimi-protocol-06.txt. Expansion oracles are the RFC 6570
//! §1.2/§3.2.2 examples and cases worked by hand from RFC 6570 §3.2.1 (every
//! byte outside `ALPHA / DIGIT / "-" / "." / "_" / "~"` becomes `%XX`).

use std::collections::BTreeMap;

use mimi_protocol::serde_json::{self, Value, json};
use mimi_protocol::{Directory, Error, MAX_URL_LEN, UriTemplate};

/// draft-ietf-mimi-protocol-06 §5.1 (lines 1025-1043 of the .txt), verbatim
/// except for the colon missing after `"proxyDownload"`, restored per
/// decision mimid-1wgh.5.17. The `update{roomId}` typo is kept: it is a
/// valid template, so it parses as written.
const SPEC_EXAMPLE: &str = r#"
   {
     "keyMaterial":
        "https://mimi.example.com/v1/keyMaterial/{targetUser}",
     "update": "https://mimi.example.com/v1/update{roomId}",
     "notify": "https://mimi.example.com/v1/notify/{roomId}",
     "submitMessage":
        "https://mimi.example.com/v1/submitMessage/{roomId}",
     "groupInfo":
        "https://mimi.example.com/v1/groupInfo/{roomId}",
     "requestConsent":
        "https://mimi.example.com/v1/requestConsent/{targetUser}",
     "updateConsent":
        "https://mimi.example.com/v1/updateConsent/{requesterUser}",
     "identifierQuery":
        "https://mimi.example.com/v1/identifierQuery/{domain}",
     "reportAbuse":
        "https://mimi.example.com/v1/reportAbuse/{roomId}",
     "proxyDownload":
        "https://mimi.example.com/v1/proxyDownload/{downloadUrl}"
   }
"#;

fn template(s: &str) -> UriTemplate {
    UriTemplate::new(s).expect("valid template")
}

fn spec_example_expected() -> Directory {
    Directory {
        key_material: Some(template(
            "https://mimi.example.com/v1/keyMaterial/{targetUser}",
        )),
        update: Some(template("https://mimi.example.com/v1/update{roomId}")),
        notify: Some(template("https://mimi.example.com/v1/notify/{roomId}")),
        submit_message: Some(template(
            "https://mimi.example.com/v1/submitMessage/{roomId}",
        )),
        group_info: Some(template("https://mimi.example.com/v1/groupInfo/{roomId}")),
        request_consent: Some(template(
            "https://mimi.example.com/v1/requestConsent/{targetUser}",
        )),
        update_consent: Some(template(
            "https://mimi.example.com/v1/updateConsent/{requesterUser}",
        )),
        identifier_query: Some(template(
            "https://mimi.example.com/v1/identifierQuery/{domain}",
        )),
        report_abuse: Some(template("https://mimi.example.com/v1/reportAbuse/{roomId}")),
        proxy_download: Some(template(
            "https://mimi.example.com/v1/proxyDownload/{downloadUrl}",
        )),
        unknown: BTreeMap::new(),
    }
}

/// Decode, compare to `expected`, re-encode, require the same JSON value.
fn check_fixture(text: &str, expected: &Directory) {
    let decoded: Directory = serde_json::from_str(text).expect("fixture decodes");
    assert_eq!(&decoded, expected);
    let reencoded = serde_json::to_value(&decoded).expect("re-encodes");
    let original: Value = serde_json::from_str(text).expect("fixture is JSON");
    assert_eq!(reencoded, original);
}

fn decode_err(value: &Value) -> String {
    serde_json::from_value::<Directory>(value.clone())
        .expect_err("must be rejected")
        .to_string()
}

fn spec_value() -> Value {
    serde_json::from_str(SPEC_EXAMPLE).expect("fixture is JSON")
}

#[test]
fn spec_example_round_trips() {
    check_fixture(SPEC_EXAMPLE, &spec_example_expected());
}

#[test]
fn unknown_members_round_trip_unchanged() {
    let mut value = spec_value();
    value["meta"] = json!({"website": "https://mimi.example.com/", "n": [1, 2.5, null, true]});
    value["zzz"] = json!("x");
    let mut expected = spec_example_expected();
    expected
        .unknown
        .insert("meta".to_owned(), value["meta"].clone());
    expected.unknown.insert("zzz".to_owned(), json!("x"));
    check_fixture(&value.to_string(), &expected);
}

#[test]
fn each_member_may_be_absent() {
    // An absent key means the provider does not offer that endpoint
    // (decision mimid-1wgh.5.75).
    let keys: Vec<String> = spec_value()
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(keys.len(), 10);
    for key in keys {
        let mut value = spec_value();
        value.as_object_mut().expect("object").remove(&key);
        let decoded: Directory =
            serde_json::from_value(value.clone()).unwrap_or_else(|e| panic!("{key}: {e}"));
        let reencoded = serde_json::to_value(&decoded).expect("re-encodes");
        assert_eq!(reencoded, value, "{key}");
        let mut expected = spec_example_expected();
        match key.as_str() {
            "keyMaterial" => expected.key_material = None,
            "update" => expected.update = None,
            "notify" => expected.notify = None,
            "submitMessage" => expected.submit_message = None,
            "groupInfo" => expected.group_info = None,
            "requestConsent" => expected.request_consent = None,
            "updateConsent" => expected.update_consent = None,
            "identifierQuery" => expected.identifier_query = None,
            "reportAbuse" => expected.report_abuse = None,
            "proxyDownload" => expected.proxy_download = None,
            other => panic!("unexpected key {other}"),
        }
        assert_eq!(decoded, expected, "{key}");
    }
}

#[test]
fn duplicate_members_are_rejected() {
    let known = SPEC_EXAMPLE.replacen(
        "{\n",
        "{\n\"notify\": \"https://evil.example/{roomId}\",\n",
        1,
    );
    let err = serde_json::from_str::<Directory>(&known).expect_err("duplicate known key");
    assert!(
        err.to_string()
            .contains("duplicate directory member \"notify\"")
    );

    let unknown = SPEC_EXAMPLE.replacen("{\n", "{\n\"x\": 1, \"x\": 2,\n", 1);
    let err = serde_json::from_str::<Directory>(&unknown).expect_err("duplicate unknown key");
    assert!(err.to_string().contains("duplicate directory member \"x\""));
}

#[test]
fn non_string_and_invalid_values_are_rejected() {
    for bad in [
        json!(null),
        json!(1),
        json!(["https://a.example/{roomId}"]),
        json!({"url": "https://a.example/"}),
        json!("https://a.example/{room id}"),
        json!("https://a.example/{+roomId}"),
        json!("https://a.example/\u{0}"),
    ] {
        let mut value = spec_value();
        value["notify"] = bad.clone();
        decode_err(&value);
    }
}

#[test]
fn non_objects_and_trailing_data_are_rejected() {
    for bad in ["[]", "\"directory\"", "null", "", "{"] {
        assert!(serde_json::from_str::<Directory>(bad).is_err(), "{bad:?}");
    }
    let trailing = format!("{SPEC_EXAMPLE} {{}}");
    assert!(serde_json::from_str::<Directory>(&trailing).is_err());
}

#[test]
fn serializing_an_unknown_member_with_a_known_key_fails() {
    let mut directory = spec_example_expected();
    directory
        .unknown
        .insert("notify".to_owned(), json!("https://evil.example/"));
    let err = serde_json::to_string(&directory).expect_err("collision");
    assert!(err.to_string().contains("\"notify\""), "{err}");
}

#[test]
fn spec_example_expands_mimi_uris() {
    // The room URI of protocol-06 §3, fully percent-encoded (decision
    // mimid-1wgh.5.18): ':' %3A, '/' %2F.
    let directory = spec_example_expected();
    assert_eq!(
        directory
            .notify
            .as_ref()
            .expect("present")
            .expand("roomId", "mimi://a.example/r/clubhouse")
            .expect("expands"),
        "https://mimi.example.com/v1/notify/mimi%3A%2F%2Fa.example%2Fr%2Fclubhouse"
    );
    assert_eq!(
        directory
            .key_material
            .as_ref()
            .expect("present")
            .expand("targetUser", "mimi://b.example/u/cathy")
            .expect("expands"),
        "https://mimi.example.com/v1/keyMaterial/mimi%3A%2F%2Fb.example%2Fu%2Fcathy"
    );
    assert_eq!(
        directory
            .proxy_download
            .as_ref()
            .expect("present")
            .expand("downloadUrl", "https://c.example/f?id=1&x=%41")
            .expect("expands"),
        "https://mimi.example.com/v1/proxyDownload/\
         https%3A%2F%2Fc.example%2Ff%3Fid%3D1%26x%3D%2541"
    );
}

/// `(value, expansion of {v})`, worked by hand from RFC 6570 §3.2.1.
const EXPANSIONS: &[(&str, &str)] = &[
    // RFC 6570 §1.2 level 1 and §3.2.2 examples.
    ("value", "value"),
    ("Hello World!", "Hello%20World%21"),
    ("50%", "50%25"),
    ("", ""),
    // The whole unreserved set passes through.
    ("ABCXYZabcxyz0189-._~", "ABCXYZabcxyz0189-._~"),
    // gen-delims, then sub-delims (RFC 3986 §2.2): all encoded.
    (":/?#[]@", "%3A%2F%3F%23%5B%5D%40"),
    ("!$&'()*+,;=", "%21%24%26%27%28%29%2A%2B%2C%3B%3D"),
    // A value that already looks percent-encoded is encoded again.
    ("%41%7e", "%2541%257e"),
    // Characters that are neither reserved nor unreserved.
    ("\"<>\\^`{|} ", "%22%3C%3E%5C%5E%60%7B%7C%7D%20"),
    // Control characters, including NUL and DEL.
    ("\u{0}\u{1f}\u{7f}", "%00%1F%7F"),
    // U+00E9 (2 bytes), U+202E RIGHT-TO-LEFT OVERRIDE, U+200B ZERO WIDTH
    // SPACE, U+2066 LEFT-TO-RIGHT ISOLATE (3 bytes), U+1F600 (4 bytes).
    ("\u{e9}", "%C3%A9"),
    ("a\u{202e}b", "a%E2%80%AEb"),
    ("\u{200b}", "%E2%80%8B"),
    ("\u{2066}", "%E2%81%A6"),
    ("\u{1f600}", "%F0%9F%98%80"),
];

#[test]
fn simple_expansion_percent_encodes_per_rfc_6570() {
    let t = template("https://h.example/p/{v}");
    for (value, encoded) in EXPANSIONS {
        assert_eq!(
            t.expand("v", value).expect("expands"),
            format!("https://h.example/p/{encoded}"),
            "value {value:?}"
        );
    }
}

#[test]
fn every_occurrence_of_the_variable_expands() {
    assert_eq!(
        template("https://h.example/{a}/x/{a}{a}")
            .expand("a", "b c")
            .expect("expands"),
        "https://h.example/b%20c/x/b%20cb%20c"
    );
}

#[test]
fn template_without_expressions_expands_to_itself() {
    assert_eq!(
        template("https://h.example/v1/notify")
            .expand("roomId", "ignored")
            .expect("expands"),
        "https://h.example/v1/notify"
    );
}

#[test]
fn literals_keep_pct_encoded_and_encode_non_ascii() {
    // RFC 6570 §3.1: a pct-encoded triplet is copied as written; a ucschar
    // literal is encoded as UTF-8 (U+00E9 is C3 A9; U+202E is E2 80 AE).
    assert_eq!(
        template("https://h.example/%7e/\u{e9}\u{202e}/{v}")
            .expand("v", "x")
            .expect("expands"),
        "https://h.example/%7e/%C3%A9%E2%80%AE/x"
    );
}

#[test]
fn undefined_variable_fails_closed() {
    let err = template("https://h.example/{targetDomain}")
        .expand("targetUser", "mimi://b.example/u/cathy")
        .expect_err("undefined");
    assert!(matches!(err, Error::UndefinedVariable { ref name } if name == "targetDomain"));
}

#[test]
fn expansion_that_is_not_a_uri_is_rejected() {
    // No scheme: the result is a relative reference, not an RFC 3986 URI.
    let err = template("{v}").expand("v", "x").expect_err("not a URI");
    assert!(matches!(err, Error::InvalidUri));
    let err = template("h.example/{v}")
        .expand("v", "x")
        .expect_err("not a URI");
    assert!(matches!(err, Error::InvalidUri));
}

#[test]
fn level_1_templates_are_accepted() {
    for ok in [
        "",
        "https://h.example/",
        "{a}",
        "{A_1}",
        "{a.b.c}",
        "{%41b}",
        "x{a}y{b}z",
        "https://h.example/!$&()*+,;=:@?/[]~%20",
        "https://h.example/\u{a0}\u{d7ff}\u{f900}\u{fdcf}\u{fdf0}\u{ffef}",
        "https://h.example/\u{10000}\u{1fffd}\u{dfffd}\u{e1000}\u{efffd}",
        "https://h.example/\u{e000}\u{f8ff}\u{f0000}\u{ffffd}\u{100000}\u{10fffd}",
    ] {
        assert_eq!(template(ok).as_str(), ok);
    }
}

#[test]
fn malformed_and_higher_level_templates_are_rejected() {
    for (bad, index) in [
        ("{", 0),
        ("x{a", 1),
        ("}", 0),
        ("a}b", 1),
        ("{}", 1),
        ("{{a}}", 1),
        // Level 2 and 3 operators, level 4 modifiers, variable lists.
        ("{+a}", 1),
        ("{#a}", 1),
        ("{.a}", 1),
        ("{/a}", 1),
        ("{;a}", 1),
        ("{?a}", 1),
        ("{&a}", 1),
        ("{=a}", 1),
        ("{a,b}", 1),
        ("{a*}", 1),
        ("{a:3}", 1),
        // Bad varnames.
        ("{a.}", 1),
        ("{a..b}", 1),
        ("{a-b}", 1),
        ("{a%4}", 1),
        ("{\u{e9}}", 1),
        // Characters RFC 6570 §2.1 excludes from literals.
        ("a b", 1),
        ("a\"", 1),
        ("a'", 1),
        ("a<", 1),
        ("a>", 1),
        ("a\\", 1),
        ("a^", 1),
        ("a`", 1),
        ("a|", 1),
        ("a\u{0}", 1),
        ("a\u{1f}", 1),
        ("a\u{7f}", 1),
        ("a%", 1),
        ("a%4", 1),
        ("a%zz", 1),
        // Non-ASCII outside ucschar and iprivate.
        ("a\u{85}", 1),
        ("a\u{9f}", 1),
        ("a\u{fdd0}", 1),
        ("a\u{fffe}", 1),
        ("a\u{1fffe}", 1),
        ("a\u{e0001}", 1),
        ("a\u{10ffff}", 1),
    ] {
        let err = UriTemplate::new(bad).expect_err(bad);
        assert!(
            matches!(err, Error::InvalidUriTemplate { index: i } if i == index),
            "{bad:?}: {err:?}"
        );
    }
}

#[test]
fn template_length_limit() {
    let prefix = "https://h.example/";
    let at_limit = format!("{prefix}{}", "a".repeat(MAX_URL_LEN - prefix.len()));
    assert_eq!(at_limit.len(), MAX_URL_LEN);
    UriTemplate::new(&at_limit).expect("at the limit");

    let past = format!("{at_limit}a");
    let err = UriTemplate::new(&past).expect_err("past the limit");
    assert!(matches!(err, Error::UrlTooLong { len } if len == MAX_URL_LEN + 1));

    let mut value = spec_value();
    value["notify"] = Value::String(past);
    decode_err(&value);
}

#[test]
fn expanded_url_length_limit() {
    let t = template("https://h.example/{v}");
    let room = MAX_URL_LEN - "https://h.example/".len();

    let at_limit = t.expand("v", &"a".repeat(room)).expect("at the limit");
    assert_eq!(at_limit.len(), MAX_URL_LEN);
    let err = t.expand("v", &"a".repeat(room + 1)).expect_err("past");
    assert!(matches!(err, Error::UrlTooLong { len } if len == MAX_URL_LEN + 1));

    // Each '/' grows to three bytes: room / 3 slashes fit, one more does not.
    let slashes = t.expand("v", &"/".repeat(room / 3)).expect("fits");
    assert_eq!(slashes.len(), MAX_URL_LEN - room % 3);
    assert!(matches!(
        t.expand("v", &"/".repeat(room / 3 + 1)),
        Err(Error::UrlTooLong { len }) if len == MAX_URL_LEN - room % 3 + 3
    ));

    // A huge value is rejected, not expanded without bound.
    assert!(matches!(
        t.expand("v", &"\u{1f600}".repeat(1 << 20)),
        Err(Error::UrlTooLong { .. })
    ));
}

/// The directory Haven's mimi-hubd serves (havenmessenger/interop 2c14e62,
/// `mimi-hubd/src/lib.rs` `directory()`, with provider domain
/// `example.com`): eight of the ten §5.1 endpoints, no `groupInfo` (its
/// DIV-1) and no `proxyDownload` (DIV-3), plus non-standard members.
const HAVEN_DIRECTORY: &str = r#"{
  "provider": "example.com",
  "mls_ciphersuites": [1],
  "protocol_drafts": { "protocol": "06", "content": "09", "room-policy": "04" },
  "endpoints": {
    "keyMaterial": "/mimi/v1/keyMaterial",
    "notify": "/mimi/v1/notify",
    "welcome": "/mimi/v1/welcome",
    "submitMessage": "/mimi/v1/submitMessage",
    "message": "/mimi/v1/message",
    "identifierQuery": "/mimi/v1/identifierQuery",
    "updateConsent": "/mimi/v1/updateConsent",
    "requestConsent": "/mimi/v1/requestConsent"
  },
  "wireEndpoints": {
    "keyMaterial": "/mimi/pl/keyMaterial/{targetUser}",
    "submitMessage": "/mimi/pl/submitMessage/{recipient}",
    "notify": "/mimi/pl/notify",
    "identifierQuery": "/mimi/pl/identifierQuery",
    "requestConsent": "/mimi/pl/requestConsent/{targetDomain}",
    "updateConsent": "/mimi/pl/updateConsent/{requesterDomain}",
    "reportAbuse": "/mimi/pl/reportAbuse/{roomId}",
    "update": "/mimi/pl/update/{roomId}"
  },
  "unsupported": {
    "groupInfo_external_commit_join": "DIV-1: add-driven join only (ETK security)",
    "assets_ohttp": "DIV-3: v1 is messaging-only",
    "non_0x0001_ciphersuites": "DIV-2: rejected at ingest",
    "update_wire_endpoint_mixed_commits": "DIV-10: a Commit combining a custom proposal with a standard MLS proposal (Add, Remove, ...) in the same proposal list is refused - only a Commit whose list holds exactly one custom proposal is applied",
    "reportAbuse_with_abusive_messages": "DIV-9: a report attaching an AbusiveMessage is refused (its Frank cannot yet be verified) - metadata-only reports are accepted"
  },
  "keyMaterial": "https://example.com/mimi/pl/keyMaterial/{targetUser}",
  "submitMessage": "https://example.com/mimi/pl/submitMessage/{recipient}",
  "notify": "https://example.com/mimi/pl/notify",
  "identifierQuery": "https://example.com/mimi/pl/identifierQuery",
  "requestConsent": "https://example.com/mimi/pl/requestConsent/{targetDomain}",
  "updateConsent": "https://example.com/mimi/pl/updateConsent/{requesterDomain}",
  "reportAbuse": "https://example.com/mimi/pl/reportAbuse/{roomId}",
  "update": "https://example.com/mimi/pl/update/{roomId}"
}"#;

#[test]
fn directory_without_group_info_and_proxy_download_decodes() {
    // protocol-06 §5.1 does not require every endpoint; an absent key means
    // the provider does not offer it. Decision mimid-1wgh.5.75.
    let original: Value = serde_json::from_str(HAVEN_DIRECTORY).expect("fixture is JSON");
    let mut unknown = BTreeMap::new();
    for key in [
        "provider",
        "mls_ciphersuites",
        "protocol_drafts",
        "endpoints",
        "wireEndpoints",
        "unsupported",
    ] {
        unknown.insert(key.to_owned(), original[key].clone());
    }
    let expected = Directory {
        key_material: Some(template(
            "https://example.com/mimi/pl/keyMaterial/{targetUser}",
        )),
        update: Some(template("https://example.com/mimi/pl/update/{roomId}")),
        notify: Some(template("https://example.com/mimi/pl/notify")),
        submit_message: Some(template(
            "https://example.com/mimi/pl/submitMessage/{recipient}",
        )),
        group_info: None,
        request_consent: Some(template(
            "https://example.com/mimi/pl/requestConsent/{targetDomain}",
        )),
        update_consent: Some(template(
            "https://example.com/mimi/pl/updateConsent/{requesterDomain}",
        )),
        identifier_query: Some(template("https://example.com/mimi/pl/identifierQuery")),
        report_abuse: Some(template("https://example.com/mimi/pl/reportAbuse/{roomId}")),
        proxy_download: None,
        unknown,
    };
    check_fixture(HAVEN_DIRECTORY, &expected);
}
