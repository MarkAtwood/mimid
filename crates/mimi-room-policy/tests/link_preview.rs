//! Fixture and validation tests for the room-policy-04 §6.3
//! `link_preview_policy` component.
//!
//! Fixtures are hex encoded by hand from the TLS presentation-language text
//! of §6.3 (repeated in Appendix B): four one-byte `Optionality` values,
//! then, unless `link_preview_proxy_use` is `forbidden(2)`, `Uri
//! link_preview_proxy<V>`, a vector of `Uri` structs (decision
//! mimid-1wgh.3.15) with MLS varint lengths (RFC 9420 §2.1.2). Each test
//! decodes the fixture, compares it to the expected value, re-encodes it
//! and requires byte-identical output.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    LinkPreviewPolicy, LinkPreviewPolicyData, LinkPreviewPolicyUpdate, LinkPreviewProxyUse,
    Optionality, PolicyError, Uri, component_id,
};

fn check_fixture(fixture: &[u8], expected: &LinkPreviewPolicy) {
    let decoded = LinkPreviewPolicy::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

fn uri(s: &str) -> Uri {
    Uri::new(s).expect("valid URI")
}

fn rule_error(error: PolicyError) -> Result<LinkPreviewPolicy, Error> {
    Err(Error::DecodingError(error.to_string()))
}

/// No proxy: 4 bytes.
const FORBIDDEN_WIRE: [u8; 4] = [
    0x00, // autodetect_hyperlinks_in_text: optional
    0x02, // send_link_previews: forbidden
    0x02, // automatic_link_previews: forbidden
    0x02, // link_preview_proxy_use: forbidden; no link_preview_proxy
];

fn forbidden() -> LinkPreviewPolicy {
    LinkPreviewPolicy {
        autodetect_hyperlinks_in_text: Optionality::Optional,
        send_link_previews: Optionality::Forbidden,
        automatic_link_previews: Optionality::Forbidden,
        link_preview_proxy_use: LinkPreviewProxyUse::Forbidden,
    }
}

/// A required proxy: 23 bytes.
const REQUIRED_WIRE: [u8; 23] = [
    0x02, // autodetect_hyperlinks_in_text: forbidden
    0x01, // send_link_previews: required
    0x00, // automatic_link_previews: optional
    0x01, // link_preview_proxy_use: required
    0x12, // link_preview_proxy<V>: 18 bytes, 1 entry
    0x11, // Uri.uri<V>: 17
    b'h', b't', b't', b'p', b's', b':', b'/', b'/', b'p', b'.', b'e', b'x', b'a', b'm', b'p', b'l',
    b'e', // "https://p.example"
];

fn required() -> LinkPreviewPolicy {
    LinkPreviewPolicy {
        autodetect_hyperlinks_in_text: Optionality::Forbidden,
        send_link_previews: Optionality::Required,
        automatic_link_previews: Optionality::Optional,
        link_preview_proxy_use: LinkPreviewProxyUse::Required {
            link_preview_proxy: vec![uri("https://p.example")],
        },
    }
}

/// An optional proxy, followed by an empty `Uri` that is kept: 24 bytes.
const OPTIONAL_WIRE: [u8; 24] = [
    0x00, // autodetect_hyperlinks_in_text: optional
    0x00, // send_link_previews: optional
    0x00, // automatic_link_previews: optional
    0x00, // link_preview_proxy_use: optional
    0x13, // link_preview_proxy<V>: 19 bytes, 2 entries
    0x11, // Uri.uri<V>: 17
    b'h', b't', b't', b'p', b's', b':', b'/', b'/', b'p', b'.', b'e', b'x', b'a', b'm', b'p', b'l',
    b'e', // "https://p.example"
    0x00, // Uri.uri<V>: 0 (absent)
];

fn optional() -> LinkPreviewPolicy {
    LinkPreviewPolicy {
        autodetect_hyperlinks_in_text: Optionality::Optional,
        send_link_previews: Optionality::Optional,
        automatic_link_previews: Optionality::Optional,
        link_preview_proxy_use: LinkPreviewProxyUse::Optional {
            link_preview_proxy: vec![uri("https://p.example"), Uri::default()],
        },
    }
}

#[test]
fn forbidden_fixture() {
    check_fixture(&FORBIDDEN_WIRE, &forbidden());
}

#[test]
fn required_fixture() {
    check_fixture(&REQUIRED_WIRE, &required());
}

#[test]
fn optional_fixture() {
    check_fixture(&OPTIONAL_WIRE, &optional());
}

#[test]
fn data_and_update_are_the_same_struct() {
    let data: LinkPreviewPolicyData =
        LinkPreviewPolicyData::tls_deserialize_exact(REQUIRED_WIRE).expect("decodes");
    let update: LinkPreviewPolicyUpdate = data.clone();
    assert_eq!(update, required());
}

#[test]
fn component_id_is_the_suggested_value() {
    // §10.1.8 (decision mimid-1wgh.3.27).
    assert_eq!(component_id::LINK_PREVIEW_POLICY, 0x002B);
}

#[test]
fn proxy_use_accessors() {
    let proxy = [uri("https://p.example")];
    assert_eq!(
        required().link_preview_proxy_use.optionality(),
        Optionality::Required
    );
    assert_eq!(
        required().link_preview_proxy_use.link_preview_proxy(),
        Some(&proxy[..])
    );
    assert_eq!(
        optional().link_preview_proxy_use.optionality(),
        Optionality::Optional
    );
    assert_eq!(
        forbidden().link_preview_proxy_use.optionality(),
        Optionality::Forbidden
    );
    assert_eq!(
        forbidden().link_preview_proxy_use.link_preview_proxy(),
        None
    );
}

// --- Strict decoding ------------------------------------------------------

#[test]
fn every_truncation_is_rejected() {
    for wire in [&FORBIDDEN_WIRE[..], &REQUIRED_WIRE, &OPTIONAL_WIRE] {
        for len in 0..wire.len() {
            assert_eq!(
                LinkPreviewPolicy::tls_deserialize_exact(&wire[..len]),
                Err(Error::EndOfStream),
                "prefix of {len} bytes of {wire:02x?}"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    for wire in [&FORBIDDEN_WIRE[..], &REQUIRED_WIRE, &OPTIONAL_WIRE] {
        let wire = [wire, &[0x00]].concat();
        assert_eq!(
            LinkPreviewPolicy::tls_deserialize_exact(&wire),
            Err(Error::TrailingData)
        );
    }
}

#[test]
fn forbidden_proxy_use_carries_no_proxy_field() {
    // A link_preview_proxy<V> after forbidden(2) is trailing data.
    let wire = [&FORBIDDEN_WIRE[..], &REQUIRED_WIRE[4..]].concat();
    assert_eq!(
        LinkPreviewPolicy::tls_deserialize_exact(&wire),
        Err(Error::TrailingData)
    );
}

#[test]
fn invalid_optionality_values_are_rejected() {
    for offset in 0..4 {
        for bad in [0x03, 0xFF] {
            let mut wire = REQUIRED_WIRE;
            wire[offset] = bad;
            assert_eq!(
                LinkPreviewPolicy::tls_deserialize_exact(wire),
                Err(Error::UnknownValue(bad.into())),
                "offset {offset}, value {bad:#04x}"
            );
        }
    }
}

#[test]
fn non_minimal_proxy_length_is_rejected() {
    // link_preview_proxy<V> length 18 as a 2-byte varint.
    let wire = [&REQUIRED_WIRE[..4], &[0x40, 0x12], &REQUIRED_WIRE[5..]].concat();
    assert_eq!(
        LinkPreviewPolicy::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn invalid_proxy_uri_is_rejected() {
    // "p example": no scheme, and a space.
    let wire = [&REQUIRED_WIRE[..4], &[0x0A, 0x09], b"p example"].concat();
    assert!(matches!(
        LinkPreviewPolicy::tls_deserialize_exact(&wire),
        Err(Error::DecodingError(_))
    ));
}

// --- §6.3 rules -----------------------------------------------------------

#[test]
fn autodetect_hyperlinks_required_is_rejected() {
    // §6.3: "The value of autodetect_hyperlinks_in_text MUST NOT be
    // mandatory" (decision mimid-1wgh.3.13).
    let mut wire = FORBIDDEN_WIRE;
    wire[0] = 0x01; // autodetect_hyperlinks_in_text: required
    assert_eq!(
        LinkPreviewPolicy::tls_deserialize_exact(wire),
        rule_error(PolicyError::AutodetectHyperlinksRequired)
    );
}

#[test]
fn required_or_optional_proxy_use_needs_a_uri() {
    // §6.3: "The link_preview_proxy setting MUST include the URI of a link
    // preview proxy if link_preview_proxy_use is mandatory or optional."
    for proxy_use in [0x00, 0x01] {
        for proxy in [
            &[0x00][..],         // link_preview_proxy<V>: 0
            &[0x01, 0x00],       // 1 entry: Uri.uri<V>: 0 (absent)
            &[0x02, 0x00, 0x00], // 2 entries, both absent
        ] {
            let wire = [&[0x00, 0x00, 0x00, proxy_use][..], proxy].concat();
            assert_eq!(
                LinkPreviewPolicy::tls_deserialize_exact(&wire),
                rule_error(PolicyError::MissingLinkPreviewProxy),
                "proxy_use {proxy_use}, proxy {proxy:02x?}"
            );
        }
    }
}

#[test]
fn validate_applies_the_rules_to_built_values() {
    assert_eq!(forbidden().validate(), Ok(()));
    assert_eq!(required().validate(), Ok(()));
    assert_eq!(optional().validate(), Ok(()));
    let autodetect = LinkPreviewPolicy {
        autodetect_hyperlinks_in_text: Optionality::Required,
        ..forbidden()
    };
    assert_eq!(
        autodetect.validate(),
        Err(PolicyError::AutodetectHyperlinksRequired)
    );
    let no_proxy = LinkPreviewPolicy {
        link_preview_proxy_use: LinkPreviewProxyUse::Required {
            link_preview_proxy: vec![],
        },
        ..forbidden()
    };
    assert_eq!(
        no_proxy.validate(),
        Err(PolicyError::MissingLinkPreviewProxy)
    );
}
