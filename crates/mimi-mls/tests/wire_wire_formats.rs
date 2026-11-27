//! mls-extensions-11 §6.1, §7.1.2, §7.1.3: the `WireFormats` body of the
//! `supported_wire_formats` and `required_wire_formats` extensions.
//!
//! Fixtures are hand-encoded from the TLS presentation-language text,
//! byte by byte.

#![forbid(unsafe_code)]

use mimi_mls::tls_codec::Serialize;
use mimi_mls::wire::{
    MAX_WIRE_FORMATS, REQUIRED_WIRE_FORMATS_EXTENSION, SUPPORTED_WIRE_FORMATS_EXTENSION,
    WireFormats,
};

/// Two formats: PublicMessage and the semiprivate one.
#[rustfmt::skip]
const TWO_FORMATS: &[u8] = &[
    0x04,       // wire_formats<V>: 4 bytes
    0x00, 0x01, // mls_public_message
    0x00, 0x11, // mls_semiprivate_message
];

#[test]
fn a_wire_formats_list_round_trips() {
    let formats = WireFormats::decode(TWO_FORMATS).expect("decodes");
    assert_eq!(formats.as_slice(), [0x0001, 0x0011]);
    assert!(formats.contains(0x0011), "the semiprivate format is listed");
    assert!(!formats.contains(0x0003), "PrivateMessage is not");
    assert_eq!(
        formats.tls_serialize_detached().expect("encodes"),
        TWO_FORMATS,
        "re-encoding gives the received bytes"
    );
}

/// An extension present but empty says explicitly that no non-default
/// format is required, which is not the same as being absent.
#[test]
fn an_empty_list_is_valid() {
    let formats = WireFormats::decode(&[0x00]).expect("decodes");
    assert!(formats.as_slice().is_empty());
    assert!(!formats.contains(0x0011));
    assert_eq!(formats.tls_serialize_detached().expect("encodes"), [0x00]);
}

/// A WireFormat is two octets, so an odd body is malformed rather than
/// silently truncated.
#[test]
fn an_odd_length_body_is_refused() {
    assert!(
        WireFormats::decode(&[0x03, 0x00, 0x01, 0x00]).is_err(),
        "three octets is not a whole number of formats"
    );
}

#[test]
fn trailing_bytes_are_refused() {
    let mut wire = TWO_FORMATS.to_vec();
    wire.push(0x00);
    assert!(WireFormats::decode(&wire).is_err(), "trailing data");
}

/// The invented limit is enforced at parse time and fails closed.
#[test]
fn more_than_the_limit_is_refused() {
    let body = vec![0x00; MAX_WIRE_FORMATS * 2];
    let mut at_limit = vec![0x40 | u8::try_from(body.len() >> 8).unwrap()];
    at_limit.push(u8::try_from(body.len() & 0xff).unwrap());
    at_limit.extend(&body);
    assert!(
        WireFormats::decode(&at_limit).is_ok(),
        "exactly the limit is allowed"
    );

    let over = vec![0x00; (MAX_WIRE_FORMATS + 1) * 2];
    let mut wire = vec![0x40 | u8::try_from(over.len() >> 8).unwrap()];
    wire.push(u8::try_from(over.len() & 0xff).unwrap());
    wire.extend(&over);
    assert!(
        WireFormats::decode(&wire).is_err(),
        "one over the limit is refused"
    );
}

/// The two extension types are the codepoints mls-extensions-11 §7.1.2
/// and §7.1.3 suggest, and they are not the same.
#[test]
fn the_extension_codepoints_are_the_registered_ones() {
    assert_eq!(SUPPORTED_WIRE_FORMATS_EXTENSION, 0x0007);
    assert_eq!(REQUIRED_WIRE_FORMATS_EXTENSION, 0x0008);
}
