//! Unicode stress, second slice (bead mimid-1wgh.54): the protocol's text
//! fields. The Big List of Naughty Strings is the one vendored for
//! mimi-content (`../../mimi-content/tests/fixtures/blns`, PROVENANCE
//! there).
//!
//! - `UTF8String` (protocol-07 §7.6, "a sequence of valid UTF8 without
//!   nulls"): every valid entry survives, unchanged and not normalized;
//!   every invalid one, and a NUL, is refused on the wire.
//! - Room metadata (§7.6) carries an entry in its name, subject, mood and
//!   description, and survives whole.
//! - `IdentifierUri` takes RFC 3986 URIs only, which are ASCII: no entry
//!   makes it panic, and a URI with a non-ASCII user or domain is refused
//!   until percent-encoded.

use mimi_protocol::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{IdentifierUri, RichDescription, RoomMetaData, Utf8String};

const BLNS: &str = include_str!("../../mimi-content/tests/fixtures/blns/blns.base64.txt");

fn naughty() -> Vec<Vec<u8>> {
    BLNS.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| base64(line.trim()))
        .collect()
}

/// Standard base64 with padding (RFC 4648 §4), enough for the fixture.
fn base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut bits, mut count, mut out) = (0u32, 0, Vec::new());
    for c in text.bytes().take_while(|&c| c != b'=') {
        let value = ALPHABET.iter().position(|&a| a == c).expect("base64");
        bits = (bits << 6) | u32::try_from(value).unwrap();
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).unwrap());
        }
    }
    out
}

/// RFC 9420 §2.1.2 variable-length vector of `bytes`.
fn vl(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();
    let mut out = if len < 0x40 {
        vec![u8::try_from(len).unwrap()]
    } else {
        let len = u16::try_from(len).unwrap() | 0x4000;
        len.to_be_bytes().to_vec()
    };
    out.extend_from_slice(bytes);
    out
}

fn valid() -> Vec<String> {
    naughty()
        .into_iter()
        .filter_map(|entry| String::from_utf8(entry).ok())
        .collect()
}

#[test]
fn utf8_string_keeps_every_valid_entry_exactly() {
    let valid = valid();
    assert!(valid.len() > 600);
    for text in &valid {
        let value = Utf8String::new(text.clone()).expect("no NUL in the list");
        let wire = value.tls_serialize_detached().unwrap();
        assert_eq!(wire, vl(text.as_bytes()), "{text:?}");
        let back = Utf8String::tls_deserialize_exact(&wire[..]).unwrap();
        assert_eq!(back.as_str(), text);
    }
}

#[test]
fn utf8_string_refuses_invalid_utf8_and_nul_on_the_wire() {
    let invalid: Vec<Vec<u8>> = naughty()
        .into_iter()
        .filter(|entry| std::str::from_utf8(entry).is_err())
        .collect();
    assert!(!invalid.is_empty());
    for entry in &invalid {
        assert!(
            Utf8String::tls_deserialize_exact(&vl(entry)[..]).is_err(),
            "{entry:02x?}"
        );
    }
    assert!(Utf8String::new("a\u{0}b").is_err());
    assert!(Utf8String::tls_deserialize_exact(&vl(b"a\0b")[..]).is_err());
}

#[test]
fn room_metadata_carries_every_valid_entry() {
    let uri = IdentifierUri::new("mimi://a.example/r/one").unwrap();
    for text in valid() {
        let text = Utf8String::new(text).unwrap();
        let metadata = RoomMetaData {
            room_uri: uri.clone(),
            room_name: text.clone(),
            room_descriptions: vec![RichDescription {
                media_type: b"text/plain".to_vec(),
                language_tag: b"tr".to_vec(),
                description_content: text.as_str().as_bytes().to_vec(),
            }],
            room_avatar: uri.clone(),
            room_subject: text.clone(),
            room_mood: text.clone(),
        };
        let wire = metadata.tls_serialize_detached().unwrap();
        let back = RoomMetaData::tls_deserialize_exact(&wire[..]).unwrap();
        assert_eq!(back, metadata, "{:?}", text.as_str());
    }
}

#[test]
fn identifier_uri_takes_ascii_uris_only_and_never_panics() {
    for entry in naughty() {
        if let Ok(text) = std::str::from_utf8(&entry)
            && let Ok(uri) = IdentifierUri::new(text)
        {
            assert_eq!(uri.as_str(), text);
            assert!(text.is_ascii(), "{text:?}");
        }
    }
    // A non-ASCII handle or domain is refused (RFC 3986 is ASCII);
    // percent-encoded and punycode forms are accepted.
    assert!(IdentifierUri::new("mimi://example.jp/u/\u{30E6}\u{30FC}\u{30B6}\u{30FC}").is_err());
    assert!(IdentifierUri::new("mimi://\u{4F8B}\u{3048}.jp/u/alice").is_err());
    assert!(IdentifierUri::new("mimi://example.jp/u/%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC").is_ok());
    assert!(IdentifierUri::new("mimi://xn--r8jz45g.jp/u/alice").is_ok());
}
