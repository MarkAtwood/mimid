//! Fixture and validation tests for the room-policy-04 §6.4 `asset_policy`
//! component.
//!
//! Fixtures are hex encoded by hand from the TLS presentation-language text
//! of §6.4 (repeated in Appendix B), with MLS varint vector lengths (RFC
//! 9420 §2.1.2), `uint64` big-endian, `optional<T>` as a presence byte then
//! `T` (RFC 9420 §2.1.1), and `permitted_media_types` read as an optional
//! list (decision mimid-1wgh.3.17). `MediaType` and `Parameter` follow
//! mls-extensions-10 §6.2.2. Each test decodes the fixture, compares it to
//! the expected value, re-encodes it and requires byte-identical output.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    AssetPolicy, AssetPolicyData, AssetPolicyUpdate, AssetUploadLocation, DomainName,
    DownloadPrivacy, DownloadPrivacyType, MediaType, Parameter, PolicyError,
    ProviderAssetUploadDomains, component_id,
};

fn check_fixture(fixture: &[u8], expected: &AssetPolicy) {
    let decoded = AssetPolicy::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

fn rule_error(error: PolicyError) -> Result<AssetPolicy, Error> {
    Err(Error::DecodingError(error.to_string()))
}

fn domain(name: &str) -> DomainName {
    DomainName {
        domain: name.as_bytes().to_vec(),
    }
}

/// Every list empty, every size zero, `permitted_media_types` absent: 39
/// bytes.
const MINIMAL_WIRE: [u8; 39] = [
    0x00, // asset_upload_location: unspecified
    0x00, // upload_domains<V>: 0
    0x00, // download_privacy.allowed_download_types<V>: 0
    0x00, // download_privacy.forbidden_download_types<V>: 0
    0x00, // download_privacy.default_download_type: direct
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max_image: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max_audio: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max_video: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max_attachment: 0
    0x00, // forbidden_media_types<V>: 0
    0x00, // permitted_media_types: absent
];

fn minimal() -> AssetPolicy {
    AssetPolicy {
        asset_upload_location: AssetUploadLocation::Unspecified,
        upload_domains: vec![],
        download_privacy: DownloadPrivacy {
            allowed_download_types: vec![],
            forbidden_download_types: vec![],
            default_download_type: DownloadPrivacyType::Direct,
        },
        max_image: 0,
        max_audio: 0,
        max_video: 0,
        max_attachment: 0,
        forbidden_media_types: vec![],
        permitted_media_types: None,
    }
}

/// Offset of `asset_upload_location` in both fixtures.
const LOCATION: usize = 0;

/// Upload to the hub, every list populated, `permitted_media_types`
/// present.
fn hub_wire() -> Vec<u8> {
    [
        &[0x02][..], // asset_upload_location: hub
        &[0x19],     // upload_domains<V>: 25 bytes, 1 entry
        &[0x0B],     //   provider.domain<V>: 11
        b"hub.example",
        &[0x0C], //   asset_upload_destinations<V>: 12 bytes, 1 entry
        &[0x0B], //     domain<V>: 11
        b"cdn.example",
        &[0x02, 0x01, 0x02], // allowed_download_types<V>: 2: hubProxy, ohttp
        &[0x01, 0x00],       // forbidden_download_types<V>: 1: direct
        &[0x02],             // default_download_type: ohttp
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00], // max_image: 0x100000
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00], // max_audio: 0xA00000
        &[0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00], // max_video: 0x40000000
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // max_attachment: 2^64-1
        &[0x0B],             // forbidden_media_types<V>: 11 bytes
        &[0x09],             //   type<V>: 9
        b"text/html",
        &[0x00], //   parameters<V>: 0
        &[0x01], // permitted_media_types: present
        &[0x25], //   <V>: 37 bytes, 2 entries
        &[0x09], //   type<V>: 9
        b"image/png",
        &[0x00], //   parameters<V>: 0
        &[0x0A], //   type<V>: 10
        b"text/plain",
        &[0x0E], //   parameters<V>: 14 bytes, 1 entry
        &[0x07], //     parameter_name<V>: 7
        b"charset",
        &[0x05], //     parameter_value<V>: 5
        b"UTF-8",
    ]
    .concat()
}

fn hub() -> AssetPolicy {
    AssetPolicy {
        asset_upload_location: AssetUploadLocation::Hub,
        upload_domains: vec![ProviderAssetUploadDomains {
            provider: domain("hub.example"),
            asset_upload_destinations: vec![domain("cdn.example")],
        }],
        download_privacy: DownloadPrivacy {
            allowed_download_types: vec![DownloadPrivacyType::HubProxy, DownloadPrivacyType::Ohttp],
            forbidden_download_types: vec![DownloadPrivacyType::Direct],
            default_download_type: DownloadPrivacyType::Ohttp,
        },
        max_image: 0x10_0000,
        max_audio: 0xA0_0000,
        max_video: 0x4000_0000,
        max_attachment: u64::MAX,
        forbidden_media_types: vec![MediaType::new("text/html", vec![]).expect("valid")],
        permitted_media_types: Some(vec![
            MediaType::new("image/png", vec![]).expect("valid"),
            MediaType::new(
                "text/plain",
                vec![Parameter::new("charset", "UTF-8").expect("valid")],
            )
            .expect("valid"),
        ]),
    }
}

#[test]
fn minimal_fixture() {
    check_fixture(&MINIMAL_WIRE, &minimal());
}

#[test]
fn hub_fixture() {
    check_fixture(&hub_wire(), &hub());
}

#[test]
fn data_and_update_are_the_same_struct() {
    let data: AssetPolicyData =
        AssetPolicyData::tls_deserialize_exact(hub_wire()).expect("decodes");
    let update: AssetPolicyUpdate = data.clone();
    assert_eq!(update, hub());
}

#[test]
fn component_id_is_the_suggested_value() {
    // §10.1.9 (decision mimid-1wgh.3.27).
    assert_eq!(component_id::ASSET_POLICY, 0x002C);
}

#[test]
fn present_but_empty_permitted_list_differs_from_absent() {
    // permitted_media_types: present (0x01), <V>: 0.
    let mut wire = MINIMAL_WIRE.to_vec();
    wire.pop();
    wire.extend_from_slice(&[0x01, 0x00]);
    check_fixture(
        &wire,
        &AssetPolicy {
            permitted_media_types: Some(vec![]),
            ..minimal()
        },
    );
}

#[test]
fn domain_name_is_opaque() {
    // §6.4 gives DomainName no syntax: non-UTF-8 and NUL bytes round-trip.
    let wire = [
        &[0x01][..],         // asset_upload_location: localProvider
        &[0x04],             // upload_domains<V>: 4 bytes, 1 entry
        &[0x02, 0xFF, 0x00], //   provider.domain<V>: 2: 0xFF 0x00
        &[0x00],             //   asset_upload_destinations<V>: 0
        &MINIMAL_WIRE[2..],  // the rest as in MINIMAL_WIRE
    ]
    .concat();
    check_fixture(
        &wire,
        &AssetPolicy {
            asset_upload_location: AssetUploadLocation::LocalProvider,
            upload_domains: vec![ProviderAssetUploadDomains {
                provider: DomainName {
                    domain: vec![0xFF, 0x00],
                },
                asset_upload_destinations: vec![],
            }],
            ..minimal()
        },
    );
}

// --- Strict decoding ------------------------------------------------------

#[test]
fn every_truncation_is_rejected() {
    for wire in [MINIMAL_WIRE.to_vec(), hub_wire()] {
        for len in 0..wire.len() {
            assert_eq!(
                AssetPolicy::tls_deserialize_exact(&wire[..len]),
                Err(Error::EndOfStream),
                "prefix of {len} bytes of {wire:02x?}"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    for wire in [MINIMAL_WIRE.to_vec(), hub_wire()] {
        let wire = [&wire[..], &[0x00]].concat();
        assert_eq!(
            AssetPolicy::tls_deserialize_exact(&wire),
            Err(Error::TrailingData)
        );
    }
}

#[test]
fn invalid_upload_location_is_rejected() {
    for bad in [0x03, 0xFF] {
        let mut wire = MINIMAL_WIRE;
        wire[LOCATION] = bad;
        assert_eq!(
            AssetPolicy::tls_deserialize_exact(wire),
            Err(Error::UnknownValue(bad.into())),
            "value {bad:#04x}"
        );
    }
}

#[test]
fn invalid_download_privacy_type_is_rejected() {
    // Offsets in hub_wire(): allowed entries at 28 and 29, forbidden entry
    // at 31, default at 32.
    let base = hub_wire();
    assert_eq!(&base[27..33], &[0x02, 0x01, 0x02, 0x01, 0x00, 0x02]);
    for offset in [28, 29, 31, 32] {
        for bad in [0x03, 0xFF] {
            let mut wire = base.clone();
            wire[offset] = bad;
            assert_eq!(
                AssetPolicy::tls_deserialize_exact(&wire),
                Err(Error::UnknownValue(bad.into())),
                "offset {offset}, value {bad:#04x}"
            );
        }
    }
}

#[test]
fn invalid_presence_byte_is_rejected() {
    for bad in [0x02, 0xFF] {
        let mut wire = MINIMAL_WIRE;
        wire[38] = bad; // permitted_media_types presence
        assert!(
            matches!(
                AssetPolicy::tls_deserialize_exact(wire),
                Err(Error::DecodingError(_))
            ),
            "presence {bad:#04x}"
        );
    }
}

#[test]
fn non_minimal_vector_length_is_rejected() {
    // upload_domains<V> length 25 as a 2-byte varint.
    let base = hub_wire();
    let wire = [&base[..1], &[0x40, 0x19], &base[2..]].concat();
    assert_eq!(
        AssetPolicy::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn invalid_media_type_is_rejected() {
    // forbidden_media_types<V>: 1 entry, type "text" with no subtype.
    let wire = [
        &MINIMAL_WIRE[..37],
        &[0x06, 0x04],
        b"text",
        &[0x00], // parameters<V>: 0
        &[0x00], // permitted_media_types: absent
    ]
    .concat();
    assert!(matches!(
        AssetPolicy::tls_deserialize_exact(&wire),
        Err(Error::DecodingError(_))
    ));
}

// --- §6.4 rules -----------------------------------------------------------

#[test]
fn hub_location_needs_exactly_one_upload_domain() {
    // §6.4: "If the asset_upload_location is hub, only one provider
    // matching the hub domain is present in asset_upload_domains."
    let mut none = MINIMAL_WIRE;
    none[LOCATION] = 0x02; // hub, upload_domains<V>: 0
    assert_eq!(
        AssetPolicy::tls_deserialize_exact(none),
        rule_error(PolicyError::HubUploadDomainCount(0))
    );
    let two = [
        &[0x02][..],   // asset_upload_location: hub
        &[0x04],       // upload_domains<V>: 4 bytes, 2 entries
        &[0x00, 0x00], //   provider.domain<V>: 0, destinations<V>: 0
        &[0x00, 0x00], //   provider.domain<V>: 0, destinations<V>: 0
        &MINIMAL_WIRE[2..],
    ]
    .concat();
    assert_eq!(
        AssetPolicy::tls_deserialize_exact(&two),
        rule_error(PolicyError::HubUploadDomainCount(2))
    );
}

#[test]
fn other_locations_accept_any_number_of_upload_domains() {
    // The §6.4 count rule applies to hub only.
    for location in [0x00, 0x01] {
        let mut none = MINIMAL_WIRE;
        none[LOCATION] = location;
        assert!(AssetPolicy::tls_deserialize_exact(none).is_ok());
        let two = [
            &[location][..],
            &[0x04, 0x00, 0x00, 0x00, 0x00], // upload_domains<V>: 2 empty entries
            &MINIMAL_WIRE[2..],
        ]
        .concat();
        assert!(AssetPolicy::tls_deserialize_exact(&two).is_ok());
    }
}

#[test]
fn validate_applies_the_rule_to_built_values() {
    assert_eq!(minimal().validate(), Ok(()));
    assert_eq!(hub().validate(), Ok(()));
    let hub_without_domains = AssetPolicy {
        upload_domains: vec![],
        ..hub()
    };
    assert_eq!(
        hub_without_domains.validate(),
        Err(PolicyError::HubUploadDomainCount(0))
    );
}
