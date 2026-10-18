//! Fixture and validation tests for the room-policy-04 §6.5
//! `logging_policy` component.
//!
//! Fixtures are hex encoded by hand from the TLS presentation-language text
//! of §6.5 (repeated in Appendix B): the one-byte `Optionality logging`,
//! then, unless `forbidden(2)`, `Uri logging_clients<V>` (a vector of `Uri`
//! structs, decision mimid-1wgh.3.15) and two `Uri` structs, with MLS
//! varint lengths (RFC 9420 §2.1.2). Each test decodes the fixture,
//! compares it to the expected value, re-encodes it and requires
//! byte-identical output.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    LoggingPolicy, LoggingPolicyData, LoggingPolicyUpdate, LoggingSettings, Optionality,
    OptionalitySelect, PolicyError, Uri, component_id,
};

fn check_fixture(fixture: &[u8], expected: &LoggingPolicy) {
    let decoded = LoggingPolicy::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

fn uri(s: &str) -> Uri {
    Uri::new(s).expect("valid URI")
}

fn rule_error(error: PolicyError) -> Result<LoggingPolicy, Error> {
    Err(Error::DecodingError(error.to_string()))
}

/// Logging forbidden: 1 byte.
const FORBIDDEN_WIRE: [u8; 1] = [
    0x02, // logging: forbidden; no further fields
];

/// Logging required with one client and a machine-readable policy: 50
/// bytes.
fn required_wire() -> Vec<u8> {
    [
        &[0x01][..], // logging: required
        &[0x14],     // logging_clients<V>: 20 bytes, 1 entry
        &[0x13],     //   Uri.uri<V>: 19
        b"https://log.example",
        &[0x1A], // machine_readable_policy.uri<V>: 26
        b"https://log.example/p.json",
        &[0x00], // human_readable_policy.uri<V>: 0 (absent)
    ]
    .concat()
}

fn required() -> LoggingPolicy {
    LoggingPolicy {
        logging: OptionalitySelect::Required(LoggingSettings {
            logging_clients: vec![uri("https://log.example")],
            machine_readable_policy: uri("https://log.example/p.json"),
            human_readable_policy: Uri::default(),
        }),
    }
}

/// Logging optional with no clients and no policy pointers: 4 bytes.
const OPTIONAL_WIRE: [u8; 4] = [
    0x00, // logging: optional
    0x00, // logging_clients<V>: 0
    0x00, // machine_readable_policy.uri<V>: 0 (absent)
    0x00, // human_readable_policy.uri<V>: 0 (absent)
];

fn optional() -> LoggingPolicy {
    LoggingPolicy {
        logging: OptionalitySelect::Optional(LoggingSettings {
            logging_clients: vec![],
            machine_readable_policy: Uri::default(),
            human_readable_policy: Uri::default(),
        }),
    }
}

#[test]
fn forbidden_fixture() {
    check_fixture(
        &FORBIDDEN_WIRE,
        &LoggingPolicy {
            logging: OptionalitySelect::Forbidden,
        },
    );
}

#[test]
fn required_fixture() {
    check_fixture(&required_wire(), &required());
}

#[test]
fn optional_fixture() {
    check_fixture(&OPTIONAL_WIRE, &optional());
}

#[test]
fn data_and_update_are_the_same_struct() {
    let data: LoggingPolicyData =
        LoggingPolicyData::tls_deserialize_exact(required_wire()).expect("decodes");
    let update: LoggingPolicyUpdate = data.clone();
    assert_eq!(update, required());
}

#[test]
fn component_id_is_the_suggested_value() {
    // §10.1.10 (decision mimid-1wgh.3.27).
    assert_eq!(component_id::LOGGING_POLICY, 0x002D);
}

#[test]
fn select_accessors() {
    assert_eq!(required().logging.optionality(), Optionality::Required);
    assert_eq!(optional().logging.optionality(), Optionality::Optional);
    let forbidden = OptionalitySelect::<LoggingSettings>::Forbidden;
    assert_eq!(forbidden.optionality(), Optionality::Forbidden);
    assert_eq!(forbidden.fields(), None);
    let fields = required();
    let fields = fields.logging.fields().expect("required has fields");
    assert_eq!(fields.logging_clients, [uri("https://log.example")]);
}

// --- Strict decoding ------------------------------------------------------

#[test]
fn every_truncation_is_rejected() {
    for wire in [
        FORBIDDEN_WIRE.to_vec(),
        required_wire(),
        OPTIONAL_WIRE.to_vec(),
    ] {
        for len in 0..wire.len() {
            assert_eq!(
                LoggingPolicy::tls_deserialize_exact(&wire[..len]),
                Err(Error::EndOfStream),
                "prefix of {len} bytes of {wire:02x?}"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    for wire in [
        FORBIDDEN_WIRE.to_vec(),
        required_wire(),
        OPTIONAL_WIRE.to_vec(),
    ] {
        let wire = [&wire[..], &[0x00]].concat();
        assert_eq!(
            LoggingPolicy::tls_deserialize_exact(&wire),
            Err(Error::TrailingData)
        );
    }
}

#[test]
fn forbidden_logging_carries_no_fields() {
    // §6.5: "If logging is forbidden then the other fields are empty"; the
    // forbidden arm is struct {}, so any fields are trailing data.
    let wire = [&FORBIDDEN_WIRE[..], &OPTIONAL_WIRE[1..]].concat();
    assert_eq!(
        LoggingPolicy::tls_deserialize_exact(&wire),
        Err(Error::TrailingData)
    );
}

#[test]
fn invalid_optionality_is_rejected() {
    for bad in [0x03, 0xFF] {
        let mut wire = OPTIONAL_WIRE;
        wire[0] = bad;
        assert_eq!(
            LoggingPolicy::tls_deserialize_exact(wire),
            Err(Error::UnknownValue(bad.into())),
            "value {bad:#04x}"
        );
    }
}

#[test]
fn non_minimal_vector_length_is_rejected() {
    // logging_clients<V> length 20 as a 2-byte varint.
    let base = required_wire();
    let wire = [&base[..1], &[0x40, 0x14], &base[2..]].concat();
    assert_eq!(
        LoggingPolicy::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn invalid_uri_is_rejected() {
    // machine_readable_policy "no scheme": not an RFC 3986 URI.
    let wire = [&[0x00, 0x00, 0x09][..], b"no scheme", &[0x00]].concat();
    assert!(matches!(
        LoggingPolicy::tls_deserialize_exact(&wire),
        Err(Error::DecodingError(_))
    ));
}

// --- §6.5 rules -----------------------------------------------------------

#[test]
fn required_logging_needs_a_client_uri() {
    // §6.5: "If logging is required, the list of logging_clients needs to
    // contain at least one logging URI."
    for clients in [
        &[0x00][..],         // logging_clients<V>: 0
        &[0x01, 0x00],       // 1 entry: Uri.uri<V>: 0 (absent)
        &[0x02, 0x00, 0x00], // 2 entries, both absent
    ] {
        let wire = [&[0x01][..], clients, &[0x00, 0x00]].concat();
        assert_eq!(
            LoggingPolicy::tls_deserialize_exact(&wire),
            rule_error(PolicyError::MissingLoggingClient),
            "clients {clients:02x?}"
        );
    }
}

#[test]
fn required_logging_keeps_extra_empty_clients() {
    // An absent entry alongside a real one is kept unchanged.
    let wire = [
        &[0x01][..], // logging: required
        &[0x15],     // logging_clients<V>: 21 bytes, 2 entries
        &[0x00],     //   Uri.uri<V>: 0 (absent)
        &[0x13],     //   Uri.uri<V>: 19
        b"https://log.example",
        &[0x00, 0x00], // both policy pointers absent
    ]
    .concat();
    check_fixture(
        &wire,
        &LoggingPolicy {
            logging: OptionalitySelect::Required(LoggingSettings {
                logging_clients: vec![Uri::default(), uri("https://log.example")],
                machine_readable_policy: Uri::default(),
                human_readable_policy: Uri::default(),
            }),
        },
    );
}

#[test]
fn validate_applies_the_rule_to_built_values() {
    assert_eq!(required().validate(), Ok(()));
    assert_eq!(optional().validate(), Ok(()));
    let no_client = LoggingPolicy {
        logging: OptionalitySelect::Required(LoggingSettings {
            logging_clients: vec![],
            machine_readable_policy: Uri::default(),
            human_readable_policy: Uri::default(),
        }),
    };
    assert_eq!(no_client.validate(), Err(PolicyError::MissingLoggingClient));
}
