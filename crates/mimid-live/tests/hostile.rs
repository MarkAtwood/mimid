//! Hostile frames: each is refused with the right error (decision
//! mimid-1wgh.76), and nothing panics.

use mimid_live::cbor::{self, CborError, MAX_DEPTH, Value};
use mimid_live::{ClientMessage, DecodeError, OpKind, ProviderMessage};

fn text(t: &str) -> Vec<u8> {
    cbor::encode(&Value::Text(t.to_owned()))
}

/// A Subscribe {"t","v","id"} with `extra` appended as more pairs.
fn subscribe_with(pairs: usize, extra: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0 + 3 + pairs as u8];
    out.extend(text("t"));
    out.extend(text("Subscribe"));
    out.extend(text("v"));
    out.push(0x01);
    out.extend(text("id"));
    out.push(0x07);
    out.extend(extra);
    out
}

fn client_error(bytes: &[u8]) -> DecodeError {
    ClientMessage::decode(bytes).unwrap_err().error
}

#[test]
fn a_duplicate_key_is_refused() {
    let mut dup = text("id");
    dup.push(0x08);
    assert_eq!(
        client_error(&subscribe_with(1, &dup)),
        DecodeError::Cbor(CborError::DuplicateKey)
    );
}

#[test]
fn indefinite_lengths_are_refused() {
    // An indefinite map, an indefinite text, an indefinite array as a
    // member value.
    assert_eq!(
        client_error(&[0xbf, 0xff]),
        DecodeError::Cbor(CborError::Indefinite)
    );
    let mut member = text("x");
    member.extend([0x7f, 0x61, b'a', 0xff]);
    assert_eq!(
        client_error(&subscribe_with(1, &member)),
        DecodeError::Cbor(CborError::Indefinite)
    );
    let mut member = text("x");
    member.extend([0x9f, 0xff]);
    assert_eq!(
        client_error(&subscribe_with(1, &member)),
        DecodeError::Cbor(CborError::Indefinite)
    );
}

#[test]
fn a_non_shortest_id_is_refused() {
    let mut out = vec![0xa3];
    out.extend(text("t"));
    out.extend(text("Subscribe"));
    out.extend(text("v"));
    out.push(0x01);
    out.extend(text("id"));
    out.extend([0x18, 0x07]);
    assert_eq!(
        client_error(&out),
        DecodeError::Cbor(CborError::NotShortest)
    );
}

#[test]
fn trailing_bytes_are_refused() {
    let mut out = subscribe_with(0, &[]);
    out.push(0x00);
    assert_eq!(
        client_error(&out),
        DecodeError::Cbor(CborError::TrailingBytes(1))
    );
}

#[test]
fn truncated_frames_are_refused_at_every_length() {
    let whole = subscribe_with(0, &[]);
    for n in 0..whole.len() {
        assert_eq!(
            client_error(&whole[..n]),
            DecodeError::Cbor(CborError::Truncated),
            "{n}"
        );
    }
}

#[test]
fn a_huge_count_allocates_nothing() {
    // A map claiming 2^64-1 pairs, and bytes claiming 4 GiB.
    let mut out = vec![0xbb];
    out.extend([0xff; 8]);
    assert_eq!(client_error(&out), DecodeError::Cbor(CborError::Truncated));
    assert_eq!(
        client_error(&[0x5a, 0xff, 0xff, 0xff, 0xff, 0x00]),
        DecodeError::Cbor(CborError::Truncated)
    );
}

#[test]
fn nesting_past_the_limit_is_refused() {
    let at = |depth: usize| {
        let mut member = text("x");
        member.extend(std::iter::repeat_n(0x81, depth));
        member.push(0x00);
        subscribe_with(1, &member)
    };
    // The frame map is depth 0, so MAX_DEPTH - 1 arrays inside fit.
    assert!(ClientMessage::decode(&at(MAX_DEPTH - 1)).is_ok());
    assert_eq!(
        client_error(&at(MAX_DEPTH)),
        DecodeError::Cbor(CborError::TooDeep)
    );
    assert_eq!(
        client_error(&at(10_000)),
        DecodeError::Cbor(CborError::TooDeep)
    );
}

#[test]
fn invalid_utf8_is_refused() {
    let mut member = text("x");
    member.extend([0x62, 0xc3, 0x28]);
    assert_eq!(
        client_error(&subscribe_with(1, &member)),
        DecodeError::Cbor(CborError::InvalidUtf8)
    );
}

#[test]
fn null_bytes_bidi_and_zero_width_text_are_data() {
    // The codec carries them; meaning is the caller's (the server checks
    // room IDs and URIs as on JMAP).
    for odd in ["a\0b", "\u{202e}moc.elpmaxe", "a\u{200b}b"] {
        let mut member = text("since");
        member.extend(text(odd));
        let decoded = ClientMessage::decode(&subscribe_with(1, &member)).unwrap();
        let ClientMessage::Request(request) = decoded else {
            panic!("not a request")
        };
        assert_eq!(
            request.op,
            mimid_live::Op::Subscribe {
                since: Some(odd.to_owned())
            }
        );
    }
}

#[test]
fn floats_tags_and_undefined_are_refused() {
    for item in [
        &[0xf9, 0x3c, 0x00][..],               // 1.0, half
        &[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0], // 1.0, double
        &[0xc1, 0x00],                         // tag 1
        &[0xf7],                               // undefined
        &[0xf0],                               // simple 16
        &[0xf8, 0x20],                         // simple 32
    ] {
        let mut member = text("x");
        member.extend(item);
        assert!(
            matches!(
                client_error(&subscribe_with(1, &member)),
                DecodeError::Cbor(CborError::Unsupported { .. })
            ),
            "{item:02x?}"
        );
    }
    // A reserved additional information value.
    assert_eq!(
        client_error(&[0x1c]),
        DecodeError::Cbor(CborError::Reserved)
    );
}

#[test]
fn unknown_type_and_version_are_named() {
    let mut out = vec![0xa3];
    out.extend(text("t"));
    out.extend(text("Teleport"));
    out.extend(text("v"));
    out.push(0x01);
    out.extend(text("id"));
    out.push(0x05);
    let error = ClientMessage::decode(&out).unwrap_err();
    assert_eq!(error.id, Some(5), "the id is reported for the Error answer");
    assert_eq!(error.error, DecodeError::UnknownType("Teleport".to_owned()));

    let mut out = subscribe_with(0, &[]);
    let at = out.iter().position(|&b| b == 0x01).unwrap();
    out[at] = 0x02;
    assert_eq!(client_error(&out), DecodeError::UnknownVersion(2));
}

#[test]
fn a_frame_that_is_not_a_map_is_refused() {
    assert_eq!(client_error(&[0x80]), DecodeError::NotAMap);
    assert_eq!(client_error(&[]), DecodeError::Cbor(CborError::Truncated));
}

#[test]
fn wrong_member_types_are_named() {
    let mut member = text("since");
    member.push(0x01);
    assert_eq!(
        client_error(&subscribe_with(1, &member)),
        DecodeError::WrongType("since")
    );
}

#[test]
fn an_ack_of_no_outstanding_request_is_refused() {
    let mut out = vec![0xa4];
    out.extend(text("t"));
    out.extend(text("Ack"));
    out.extend(text("v"));
    out.push(0x01);
    out.extend(text("id"));
    out.push(0x05);
    out.extend(text("state"));
    out.extend(text("1.0"));
    let error = ProviderMessage::decode(&out, |_| None).unwrap_err();
    assert_eq!(error.error, DecodeError::UnknownRequest(5));
    assert!(ProviderMessage::decode(&out, |_| Some(OpKind::Subscribe)).is_ok());
}

/// Every one-byte change of a valid frame either decodes or is an error;
/// none panics.
#[test]
fn single_byte_corruptions_do_not_panic() {
    let whole = subscribe_with(0, &[]);
    for at in 0..whole.len() {
        for byte in 0..=255u8 {
            let mut bytes = whole.clone();
            bytes[at] = byte;
            let _ = ClientMessage::decode(&bytes);
            let _ = ProviderMessage::decode(&bytes, |_| Some(OpKind::Send));
        }
    }
}
