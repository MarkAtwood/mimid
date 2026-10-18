//! Fixture tests for the room-policy-04 §7 `mls_operational_policy`
//! component.
//!
//! Fixtures are hex encoded by hand from the TLS presentation-language text
//! of §7 (repeated in Appendix B), with the readings of decision
//! mimid-1wgh.3.22: `WireFormats x<V>` is a vector of `uint16 WireFormat`,
//! `ContentType` is the RFC 9420 §6 `uint8` enum, `unit64` is `uint64`, and
//! strategy values 3 to 255 select `case extension`. Vectors carry an
//! RFC 9420 §2.1.2 varint length (one byte below 64); integers are
//! big-endian. Each fixture is assembled from the commented pieces below in
//! field order. Each test decodes the fixture, compares it to the expected
//! value, re-encodes it and requires byte-identical output.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    AppMessagePolicy, Bool, ContentType, ExtendedCapabilities, ExtensionStrategy, MediaType,
    MinDefaultMaxTime, OperationalParameters, OperationalParametersData,
    OperationalParametersUpdate, Parameter, PendingProposalPolicy, component_id,
};

fn check_fixture(fixture: &[u8], expected: &OperationalParameters) {
    let decoded =
        OperationalParameters::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

// --- Pieces ---------------------------------------------------------------

/// `ExtendedCapabilities` with all ten vectors empty: 10 bytes.
const EMPTY_CAPABILITIES: [u8; 10] = [
    0x00, // versions<V>: 0 bytes
    0x00, // cipher_suites<V>: 0 bytes
    0x00, // extensions<V>: 0 bytes
    0x00, // proposals<V>: 0 bytes
    0x00, // credentials<V>: 0 bytes
    0x00, // wire_formats<V>: 0 bytes
    0x00, // component_ids<V>: 0 bytes
    0x00, // safe_aad_types<V>: 0 bytes
    0x00, // media_types<V>: 0 bytes
    0x00, // content_types<V>: 0 bytes
];

fn empty_capabilities() -> ExtendedCapabilities {
    ExtendedCapabilities {
        versions: vec![],
        cipher_suites: vec![],
        extensions: vec![],
        proposals: vec![],
        credentials: vec![],
        wire_formats: vec![],
        component_ids: vec![],
        safe_aad_types: vec![],
        media_types: vec![],
        content_types: vec![],
    }
}

/// `ExtendedCapabilities` with every vector but `safe_aad_types` populated:
/// 63 bytes.
const FULL_CAPABILITIES: [u8; 63] = [
    0x02, // versions<V>: 2 bytes
    0x00, 0x01, //   mls10
    0x04, // cipher_suites<V>: 4 bytes
    0x00, 0x01, //   MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    0x00, 0x03, //   MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    0x04, // extensions<V>: 4 bytes
    0x00, 0x02, //   ratchet_tree
    0xF0, 0xA1, //   a private-use value, carried unchanged
    0x02, // proposals<V>: 2 bytes
    0x00, 0x08, //   0x0008, an unregistered value, carried unchanged
    0x02, // credentials<V>: 2 bytes
    0x00, 0x01, //   basic
    0x06, // wire_formats<V>: 6 bytes
    0x00, 0x01, //   mls_public_message
    0x00, 0x02, //   mls_private_message
    0x00, 0x06, //   0x0006, not in RFC 9420 Table 8, carried unchanged
    0x04, // component_ids<V>: 4 bytes
    0x00, 0x24, //   mls_operational_policy
    0x00, 0x25, //   roles_list
    0x00, // safe_aad_types<V>: 0 bytes
    0x1A, // media_types<V>: 26 bytes
    0x0A, //   type<V>: 10 bytes
    b't', b'e', b'x', b't', b'/', b'p', b'l', b'a', b'i', b'n', //     "text/plain"
    0x0E, //   parameters<V>: 14 bytes
    0x07, //     parameter_name<V>: 7 bytes
    b'c', b'h', b'a', b'r', b's', b'e', b't', //       "charset"
    0x05, //     parameter_value<V>: 5 bytes
    b'U', b'T', b'F', b'-', b'8', //       "UTF-8"
    0x03, // content_types<V>: 3 bytes
    0x01, //   application
    0x02, //   proposal
    0x03, //   commit
];

fn full_capabilities() -> ExtendedCapabilities {
    ExtendedCapabilities {
        versions: vec![0x0001],
        cipher_suites: vec![0x0001, 0x0003],
        extensions: vec![0x0002, 0xF0A1],
        proposals: vec![0x0008],
        credentials: vec![0x0001],
        wire_formats: vec![0x0001, 0x0002, 0x0006],
        component_ids: vec![0x0024, 0x0025],
        safe_aad_types: vec![],
        media_types: vec![
            MediaType::new(
                "text/plain",
                vec![Parameter::new("charset", "UTF-8").expect("valid parameter")],
            )
            .expect("valid media type"),
        ],
        content_types: vec![
            ContentType::Application,
            ContentType::Proposal,
            ContentType::Commit,
        ],
    }
}

/// `ExtendedCapabilities` forbidding only PublicMessage: 12 bytes.
const FORBID_PUBLIC_CAPABILITIES: [u8; 12] = [
    0x00, // versions<V>: 0 bytes
    0x00, // cipher_suites<V>: 0 bytes
    0x00, // extensions<V>: 0 bytes
    0x00, // proposals<V>: 0 bytes
    0x00, // credentials<V>: 0 bytes
    0x02, // wire_formats<V>: 2 bytes
    0x00, 0x01, //   mls_public_message
    0x00, // component_ids<V>: 0 bytes
    0x00, // safe_aad_types<V>: 0 bytes
    0x00, // media_types<V>: 0 bytes
    0x00, // content_types<V>: 0 bytes
];

fn forbid_public_capabilities() -> ExtendedCapabilities {
    ExtendedCapabilities {
        wire_formats: vec![0x0001],
        ..empty_capabilities()
    }
}

/// Everything after `pending_proposal_policy`, all zero: 111 bytes.
const ZERO_TAIL: [u8; 111] = [
    // LeafNode_update_time
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   minimum_time: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   default_time: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   maximum_time: 0
    0x00, // app_message_policy.epoch_tolerance: 0
    0x00, 0x00, // app_message_policy.pad_to_size: 0
    0x00, 0x00, 0x00, 0x00, // app_message_policy.max_generations_skipahead: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max_kp_lifetime: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max_credential_lifetime: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // resumption_psk_lifetime: 0
    // sender_nonce_keypair_lifetime
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   minimum_time: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   default_time: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   maximum_time: 0
    0x00, 0x00, 0x00, 0x00, // max_keypairs: 0
    // buffer_incoming_message_time
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   minimum_time: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   default_time: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   maximum_time: 0
    0x00, 0x00, 0x00, 0x00, // max_buffered_messages: 0
];

fn zero_time() -> MinDefaultMaxTime {
    MinDefaultMaxTime {
        minimum_time: 0,
        default_time: 0,
        maximum_time: 0,
    }
}

/// Everything after `pending_proposal_policy`, with realistic values: 111
/// bytes.
const FULL_TAIL: [u8; 111] = [
    // LeafNode_update_time
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x10, //   minimum_time: 3600
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x51, 0x80, //   default_time: 86400
    0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x3A, 0x80, //   maximum_time: 604800
    0x02, // app_message_policy.epoch_tolerance: 2
    0x01, 0x00, // app_message_policy.pad_to_size: 256
    0x00, 0x00, 0x04, 0x00, // app_message_policy.max_generations_skipahead: 1024
    0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x8D, 0x00, // max_kp_lifetime: 2592000
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // max_credential_lifetime: 2^64-1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // resumption_psk_lifetime: 0
    // sender_nonce_keypair_lifetime
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, //   minimum_time: 60
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2C, //   default_time: 300
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x10, //   maximum_time: 3600
    0x00, 0x00, 0x00, 0x64, // max_keypairs: 100
    // buffer_incoming_message_time
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //   minimum_time: 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1E, //   default_time: 30
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, //   maximum_time: 120
    0xFF, 0xFF, 0xFF, 0xFF, // max_buffered_messages: 2^32-1
];

// --- Fixtures -------------------------------------------------------------

/// The smallest policy: empty lists, `unspecified` strategy, zero values.
/// 145 bytes.
fn minimal_wire() -> Vec<u8> {
    [
        &EMPTY_CAPABILITIES[..], // mandatory_capabilities
        &EMPTY_CAPABILITIES,     // default_capabilities
        &EMPTY_CAPABILITIES,     // forbidden_capabilities
        &[
            0x00, // handshake_formats<V>: 0 bytes
            0x00, // external_proposal_allowed: false
            0x01, // external_commit_allowed: true
            0x00, // pending_proposal_strategy: unspecified; no further fields
        ],
        &ZERO_TAIL,
    ]
    .concat()
}

fn minimal() -> OperationalParameters {
    OperationalParameters {
        mandatory_capabilities: empty_capabilities(),
        default_capabilities: empty_capabilities(),
        forbidden_capabilities: empty_capabilities(),
        handshake_formats: vec![],
        external_proposal_allowed: Bool::False,
        external_commit_allowed: Bool::True,
        pending_proposal_policy: PendingProposalPolicy::Unspecified,
        leaf_node_update_time: zero_time(),
        app_message_policy: AppMessagePolicy {
            epoch_tolerance: 0,
            pad_to_size: 0,
            max_generations_skipahead: 0,
        },
        max_kp_lifetime: 0,
        max_credential_lifetime: 0,
        resumption_psk_lifetime: 0,
        sender_nonce_keypair_lifetime: zero_time(),
        max_keypairs: 0,
        buffer_incoming_message_time: zero_time(),
        max_buffered_messages: 0,
    }
}

/// Every field populated, `random_delay` strategy. 218 bytes.
fn full_wire() -> Vec<u8> {
    [
        &FULL_CAPABILITIES[..],      // mandatory_capabilities
        &EMPTY_CAPABILITIES,         // default_capabilities
        &FORBID_PUBLIC_CAPABILITIES, // forbidden_capabilities
        &[
            0x02, // handshake_formats<V>: 2 bytes
            0x00, 0x02, //   mls_private_message
            0x01, // external_proposal_allowed: true
            0x00, // external_commit_allowed: false
            0x02, // pending_proposal_strategy: random_delay
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, //   minimum_delay_ms: 1000
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x88, //   maximum_delay_ms: 5000
        ],
        &FULL_TAIL,
    ]
    .concat()
}

fn full() -> OperationalParameters {
    OperationalParameters {
        mandatory_capabilities: full_capabilities(),
        default_capabilities: empty_capabilities(),
        forbidden_capabilities: forbid_public_capabilities(),
        handshake_formats: vec![0x0002],
        external_proposal_allowed: Bool::True,
        external_commit_allowed: Bool::False,
        pending_proposal_policy: PendingProposalPolicy::RandomDelay {
            minimum_delay_ms: 1000,
            maximum_delay_ms: 5000,
        },
        leaf_node_update_time: MinDefaultMaxTime {
            minimum_time: 3600,
            default_time: 86_400,
            maximum_time: 604_800,
        },
        app_message_policy: AppMessagePolicy {
            epoch_tolerance: 2,
            pad_to_size: 256,
            max_generations_skipahead: 1024,
        },
        max_kp_lifetime: 2_592_000,
        max_credential_lifetime: u64::MAX,
        resumption_psk_lifetime: 0,
        sender_nonce_keypair_lifetime: MinDefaultMaxTime {
            minimum_time: 60,
            default_time: 300,
            maximum_time: 3600,
        },
        max_keypairs: 100,
        buffer_incoming_message_time: MinDefaultMaxTime {
            minimum_time: 0,
            default_time: 30,
            maximum_time: 120,
        },
        max_buffered_messages: u32::MAX,
    }
}

/// [`minimal_wire`] with `pending_proposal_policy` replaced by `policy`.
fn with_pending(policy: &[u8]) -> Vec<u8> {
    [
        &EMPTY_CAPABILITIES[..],
        &EMPTY_CAPABILITIES,
        &EMPTY_CAPABILITIES,
        &[0x00, 0x00, 0x01], // handshake_formats, external_proposal_allowed, external_commit_allowed
        policy,
        &ZERO_TAIL,
    ]
    .concat()
}

/// Offset of `external_proposal_allowed` in [`minimal_wire`].
const EXTERNAL_PROPOSAL_OFFSET: usize = 31;
/// Offset of `external_commit_allowed` in [`minimal_wire`].
const EXTERNAL_COMMIT_OFFSET: usize = 32;
/// Offset of the first `content_types` entry in [`full_wire`].
const FIRST_CONTENT_TYPE_OFFSET: usize = 60;

#[test]
fn minimal_fixture() {
    let wire = minimal_wire();
    assert_eq!(wire.len(), 145);
    check_fixture(&wire, &minimal());
}

#[test]
fn full_fixture() {
    let wire = full_wire();
    assert_eq!(wire.len(), 218);
    check_fixture(&wire, &full());
}

#[test]
fn immediate_commit_fixture() {
    let wire = with_pending(&[
        0x01, // pending_proposal_strategy: immediate_commit; no further fields
    ]);
    let expected = OperationalParameters {
        pending_proposal_policy: PendingProposalPolicy::ImmediateCommit,
        ..minimal()
    };
    check_fixture(&wire, &expected);
}

#[test]
fn extension_strategy_fixtures() {
    // Decision mimid-1wgh.3.22: 3-255 select `case extension`.
    let wire = with_pending(&[
        0x03, // pending_proposal_strategy: 3, case extension
        0x12, 0x34, //   id_of_strategy_params: 0x1234
    ]);
    let expected = OperationalParameters {
        pending_proposal_policy: PendingProposalPolicy::Extension {
            pending_proposal_strategy: ExtensionStrategy::new(3).expect("3 is an extension"),
            id_of_strategy_params: 0x1234,
        },
        ..minimal()
    };
    check_fixture(&wire, &expected);

    let wire = with_pending(&[
        0xFF, // pending_proposal_strategy: 255, case extension
        0x00, 0x24, //   id_of_strategy_params: 0x0024
    ]);
    let expected = OperationalParameters {
        pending_proposal_policy: PendingProposalPolicy::Extension {
            pending_proposal_strategy: ExtensionStrategy::new(255).expect("255 is an extension"),
            id_of_strategy_params: 0x0024,
        },
        ..minimal()
    };
    check_fixture(&wire, &expected);
}

#[test]
fn every_extension_strategy_value_round_trips() {
    for strategy in 3..=255u8 {
        let wire = [strategy, 0xAB, 0xCD];
        let decoded = PendingProposalPolicy::tls_deserialize_exact(wire).expect("decodes");
        assert_eq!(decoded.pending_proposal_strategy(), strategy);
        assert_eq!(
            decoded,
            PendingProposalPolicy::Extension {
                pending_proposal_strategy: ExtensionStrategy::new(strategy).expect("in range"),
                id_of_strategy_params: 0xABCD,
            }
        );
        assert_eq!(decoded.tls_serialize_detached().expect("encodes"), wire);
    }
}

#[test]
fn extension_strategy_excludes_declared_values() {
    for declared in 0..=2u8 {
        assert_eq!(ExtensionStrategy::new(declared), None, "value {declared}");
    }
    assert_eq!(
        ExtensionStrategy::new(3).map(ExtensionStrategy::get),
        Some(3)
    );
    assert_eq!(ExtensionStrategy::MIN, 3);
}

#[test]
fn data_and_update_are_the_same_struct() {
    let data: OperationalParametersData =
        OperationalParametersData::tls_deserialize_exact(full_wire()).expect("decodes");
    let update: OperationalParametersUpdate = data.clone();
    assert_eq!(update, full());
}

#[test]
fn component_id_is_the_suggested_value() {
    // §10.1.1 (decision mimid-1wgh.3.27).
    assert_eq!(component_id::MLS_OPERATIONAL_POLICY, 0x0024);
}

#[test]
fn unstated_ordering_rules_are_not_enforced() {
    // §7 does not say minimum <= default <= maximum, or minimum_delay_ms <=
    // maximum_delay_ms, so a policy breaking both decodes and round-trips
    // (as decisions mimid-1wgh.3.45 and mimid-1wgh.3.64 do for §3 and §6).
    let mut wire = with_pending(&[
        0x02, // pending_proposal_strategy: random_delay
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, //   minimum_delay_ms: 9
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //   maximum_delay_ms: 1
    ]);
    // The tail starts after the 33-byte head and the 17-byte policy; byte 7
    // of the tail is the low byte of LeafNode_update_time.minimum_time.
    wire[33 + 17 + 7] = 0x05; // LeafNode_update_time.minimum_time: 5
    let expected = OperationalParameters {
        pending_proposal_policy: PendingProposalPolicy::RandomDelay {
            minimum_delay_ms: 9,
            maximum_delay_ms: 1,
        },
        leaf_node_update_time: MinDefaultMaxTime {
            minimum_time: 5,
            default_time: 0,
            maximum_time: 0,
        },
        ..minimal()
    };
    check_fixture(&wire, &expected);
}

#[test]
fn unknown_registry_values_round_trip() {
    // Values RFC 9420 has not assigned, in every open-registry list, are
    // carried unchanged. FULL_CAPABILITIES already holds some; this checks
    // the extremes.
    let wire = [
        0x02, 0xFF, 0xFF, // versions<V>: 0xFFFF
        0x02, 0xFF, 0xFF, // cipher_suites<V>: 0xFFFF
        0x02, 0x00, 0x00, // extensions<V>: 0x0000
        0x02, 0xFF, 0xFF, // proposals<V>: 0xFFFF
        0x02, 0xFF, 0xFF, // credentials<V>: 0xFFFF
        0x02, 0x00, 0x00, // wire_formats<V>: 0x0000
        0x02, 0xFF, 0xFF, // component_ids<V>: 0xFFFF
        0x02, 0x00, 0x00, // safe_aad_types<V>: 0x0000
        0x00, // media_types<V>: 0 bytes
        0x00, // content_types<V>: 0 bytes
    ];
    let decoded = ExtendedCapabilities::tls_deserialize_exact(wire).expect("decodes");
    assert_eq!(
        decoded,
        ExtendedCapabilities {
            versions: vec![0xFFFF],
            cipher_suites: vec![0xFFFF],
            extensions: vec![0x0000],
            proposals: vec![0xFFFF],
            credentials: vec![0xFFFF],
            wire_formats: vec![0x0000],
            component_ids: vec![0xFFFF],
            safe_aad_types: vec![0x0000],
            ..empty_capabilities()
        }
    );
    assert_eq!(decoded.tls_serialize_detached().expect("encodes"), wire);
}

// --- Strict decoding ------------------------------------------------------

fn all_fixtures() -> Vec<Vec<u8>> {
    vec![
        minimal_wire(),
        full_wire(),
        with_pending(&[0x01]),
        with_pending(&[0x03, 0x12, 0x34]),
    ]
}

#[test]
fn every_truncation_is_rejected() {
    for wire in all_fixtures() {
        for len in 0..wire.len() {
            assert_eq!(
                OperationalParameters::tls_deserialize_exact(&wire[..len]),
                Err(Error::EndOfStream),
                "prefix of {len} bytes of {wire:02x?}"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    for wire in all_fixtures() {
        let wire = [&wire[..], &[0x00]].concat();
        assert_eq!(
            OperationalParameters::tls_deserialize_exact(&wire),
            Err(Error::TrailingData)
        );
    }
}

#[test]
fn bare_strategies_carry_no_fields() {
    // unspecified and immediate_commit select struct {}: a following
    // ComponentID is trailing data, not parsed as an extension arm.
    for strategy in [0x00, 0x01] {
        assert_eq!(
            PendingProposalPolicy::tls_deserialize_exact([strategy, 0x00, 0x24]),
            Err(Error::TrailingData),
            "strategy {strategy}"
        );
    }
}

#[test]
fn invalid_bool_is_rejected() {
    for offset in [EXTERNAL_PROPOSAL_OFFSET, EXTERNAL_COMMIT_OFFSET] {
        for bad in [0x02, 0xFF] {
            let mut wire = minimal_wire();
            wire[offset] = bad;
            assert_eq!(
                OperationalParameters::tls_deserialize_exact(&wire),
                Err(Error::UnknownValue(bad.into())),
                "offset {offset}, value {bad:#04x}"
            );
        }
    }
}

#[test]
fn invalid_content_type_is_rejected() {
    // RFC 9420 §6 declares 1-3 besides reserved(0).
    for bad in [0x00, 0x04, 0xFF] {
        let mut wire = full_wire();
        assert_eq!(wire[FIRST_CONTENT_TYPE_OFFSET], 0x01);
        wire[FIRST_CONTENT_TYPE_OFFSET] = bad;
        assert_eq!(
            OperationalParameters::tls_deserialize_exact(&wire),
            Err(Error::UnknownValue(bad.into())),
            "value {bad:#04x}"
        );
    }
}

#[test]
fn non_minimal_vector_length_is_rejected() {
    // handshake_formats<V> empty, as a 2-byte varint (0x40 0x00).
    let mut wire = minimal_wire();
    wire.splice(30..31, [0x40, 0x00]);
    assert_eq!(
        OperationalParameters::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn odd_length_u16_vector_is_rejected() {
    // versions<V> of 1 byte cannot hold a whole uint16.
    let wire = [
        0x01, 0x00, // versions<V>: 1 byte
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert!(ExtendedCapabilities::tls_deserialize_exact(wire).is_err());
}

#[test]
fn invalid_media_type_is_rejected() {
    // The media type checks of decision mimid-1wgh.36 apply inside §7.
    let mut wire = full_wire();
    let slash = wire
        .iter()
        .position(|&b| b == b'/')
        .expect("text/plain is present");
    wire[slash] = b'_';
    assert!(matches!(
        OperationalParameters::tls_deserialize_exact(&wire),
        Err(Error::DecodingError(_))
    ));
}
