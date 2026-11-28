//! Hostile frames: each is refused with the right error (decision
//! mimid-1wgh.76), and nothing panics.

use mimid_live::cbor::{self, CborError, MAX_DEPTH, Value};
use mimid_live::keepalive::{KeepaliveError, MAX_KEEPALIVE_SECONDS};
use mimid_live::{ClientMessage, DecodeError, Keepalive, OpKind, ProviderMessage, VERSION};

fn text(t: &str) -> Vec<u8> {
    cbor::encode(&Value::Text(t.to_owned()))
}

/// A Subscribe {"t","v","id"} with `extra` appended as more pairs.
fn subscribe_with(pairs: usize, extra: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0 + 3 + pairs as u8];
    out.extend(text("t"));
    out.extend(text("Subscribe"));
    out.extend(text("v"));
    out.push(0x02);
    out.extend(text("id"));
    out.push(0x07);
    out.extend(extra);
    out
}

fn client_error(bytes: &[u8]) -> DecodeError {
    ClientMessage::decode(bytes).unwrap_err().error
}

/// A `ClientHello` carrying `pairs` besides the members every hello has.
/// [`cbor::encode`] sorts the keys, so the frame is well formed whatever
/// order they are given in.
fn client_hello_with(pairs: &[(&str, Value)]) -> Vec<u8> {
    let mut map = vec![
        (Value::Text("v".to_owned()), Value::Uint(1)),
        (
            Value::Text("t".to_owned()),
            Value::Text("ClientHello".to_owned()),
        ),
        (
            Value::Text("versions".to_owned()),
            Value::Array(vec![Value::Uint(VERSION)]),
        ),
        (
            Value::Text("token".to_owned()),
            Value::Text("tok".to_owned()),
        ),
    ];
    map.extend(
        pairs
            .iter()
            .map(|(key, value)| (Value::Text((*key).to_owned()), value.clone())),
    );
    cbor::encode(&Value::Map(map))
}

/// A hello stating `min` and `max`.
fn hello_keepalive(min: u64, max: u64) -> Vec<u8> {
    client_hello_with(&[
        ("minIntervalSeconds", Value::Uint(min)),
        ("maxIdleSeconds", Value::Uint(max)),
    ])
}

/// The pair a hello decoded to.
fn decoded_keepalive(bytes: &[u8]) -> Option<Keepalive> {
    match ClientMessage::decode(bytes) {
        Ok(ClientMessage::Hello(hello)) => hello.keepalive,
        other => panic!("not a ClientHello: {other:?}"),
    }
}

/// Bead mimid-mm42: `PROBES_PER_IDLE * minIntervalSeconds` must be under
/// `maxIdleSeconds` (draft-atwood-mimi-keepalive-00 §4.1), checked at
/// parse time, at the boundary and past it.
#[test]
fn a_hello_whose_keepalive_leaves_no_room_for_two_probes_is_refused() {
    for (min, max) in [(30, 90), (30, 30), (1, 3), (2, 6), (1, 1)] {
        assert_eq!(
            client_error(&hello_keepalive(min, max)),
            DecodeError::Keepalive(KeepaliveError::NoRoom { min, max }),
            "{min} and {max}"
        );
    }
    // One second more than the refused pair is the first accepted one.
    for (min, max) in [(30, 91), (1, 4), (2, 7)] {
        assert_eq!(
            decoded_keepalive(&hello_keepalive(min, max)),
            Some(Keepalive::new(min, max).unwrap()),
            "{min} and {max}"
        );
    }
}

/// A responder states both values as non-zero (§4.1).
#[test]
fn a_hello_whose_keepalive_is_zero_is_refused() {
    assert_eq!(
        client_error(&hello_keepalive(0, 10)),
        DecodeError::Keepalive(KeepaliveError::Zero {
            name: "minIntervalSeconds"
        })
    );
    assert_eq!(
        client_error(&hello_keepalive(10, 0)),
        DecodeError::Keepalive(KeepaliveError::Zero {
            name: "maxIdleSeconds"
        })
    );
    assert_eq!(
        client_error(&hello_keepalive(0, 0)),
        DecodeError::Keepalive(KeepaliveError::Zero {
            name: "minIntervalSeconds"
        })
    );
}

/// [`MAX_KEEPALIVE_SECONDS`] at the limit and past it, up to the largest
/// integer the wire can carry: the arithmetic of §4.1 does not overflow.
#[test]
fn a_keepalive_past_the_limit_is_refused() {
    assert_eq!(
        decoded_keepalive(&hello_keepalive(1, MAX_KEEPALIVE_SECONDS)),
        Some(Keepalive::new(1, MAX_KEEPALIVE_SECONDS).unwrap())
    );
    for (min, max, name, seconds) in [
        (
            1,
            MAX_KEEPALIVE_SECONDS + 1,
            "maxIdleSeconds",
            MAX_KEEPALIVE_SECONDS + 1,
        ),
        (
            MAX_KEEPALIVE_SECONDS + 1,
            MAX_KEEPALIVE_SECONDS,
            "minIntervalSeconds",
            MAX_KEEPALIVE_SECONDS + 1,
        ),
        (u64::MAX, u64::MAX, "minIntervalSeconds", u64::MAX),
        (1, u64::MAX, "maxIdleSeconds", u64::MAX),
    ] {
        assert_eq!(
            client_error(&hello_keepalive(min, max)),
            DecodeError::Keepalive(KeepaliveError::TooLong { name, seconds }),
            "{min} and {max}"
        );
    }
}

/// One of the pair alone states no pacing, so it is refused rather than
/// half believed (§4.1).
#[test]
fn a_hello_stating_half_the_keepalive_is_refused() {
    assert_eq!(
        client_error(&client_hello_with(&[(
            "minIntervalSeconds",
            Value::Uint(30)
        )])),
        DecodeError::Keepalive(KeepaliveError::Half {
            present: "minIntervalSeconds",
            missing: "maxIdleSeconds",
        })
    );
    assert_eq!(
        client_error(&client_hello_with(&[("maxIdleSeconds", Value::Uint(120))])),
        DecodeError::Keepalive(KeepaliveError::Half {
            present: "maxIdleSeconds",
            missing: "minIntervalSeconds",
        })
    );
}

/// A client that states neither value: the hello decodes, with no pair
/// (bead mimid-mm42's compatibility requirement).
#[test]
fn a_hello_stating_no_keepalive_decodes() {
    assert_eq!(decoded_keepalive(&client_hello_with(&[])), None);
}

#[test]
fn a_keepalive_of_the_wrong_type_is_refused() {
    for name in ["minIntervalSeconds", "maxIdleSeconds"] {
        let bytes = client_hello_with(&[
            (name, Value::Text("30".to_owned())),
            (
                if name == "maxIdleSeconds" {
                    "minIntervalSeconds"
                } else {
                    "maxIdleSeconds"
                },
                Value::Uint(120),
            ),
        ]);
        assert_eq!(client_error(&bytes), DecodeError::WrongType(name));
    }
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
    out.push(0x02);
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
                since: Some(odd.to_owned()),
                after: None,
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
    out.push(0x02);
    out.extend(text("id"));
    out.push(0x05);
    let error = ClientMessage::decode(&out).unwrap_err();
    assert_eq!(error.id, Some(5), "the id is reported for the Error answer");
    assert_eq!(error.error, DecodeError::UnknownType("Teleport".to_owned()));

    // Version 1, which this crate no longer speaks (bead mimid-mm42),
    // and a version after it.
    for (byte, version) in [(0x01, 1), (0x03, 3)] {
        let mut out = vec![0xa3];
        out.extend(text("t"));
        out.extend(text("Subscribe"));
        out.extend(text("v"));
        out.push(byte);
        out.extend(text("id"));
        out.push(0x07);
        assert_eq!(client_error(&out), DecodeError::UnknownVersion(version));
    }
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
    out.push(0x02);
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
