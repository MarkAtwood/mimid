//! Fixture and hostile-input tests for the identifierQuery bodies
//! (protocol-06 §5.8).
//!
//! Every fixture is hand-encoded from the TLS presentation-language text,
//! byte by byte, with RFC 9420 §2.1.2 variable-length prefixes written out.
//! None of the expected bytes come from this crate's encoder.

use mimi_mls::wire::AppDataDictionary;
use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{
    Error, FieldSource, IdentifierQueryCode, IdentifierRequest, IdentifierResponse, IdentifierUri,
    ProfileField, QueryElement, QuerySearch, SearchIdentifierType, UserProfile, Utf8String,
};

const GIVEN_NAME: &[u8] = b"given_name"; // 10 bytes
const XAVIER: &[u8] = b"Xavier"; // 6 bytes
const ORG: &[u8] = b"ORG"; // 3 bytes
const XYZ: &[u8] = b"XYZ"; // 3 bytes
const HANDLE: &[u8] = b"im:alice.smith@a.example"; // 24 bytes
const XAVIER_URI: &[u8] = b"mimi://xyz.example/u/xavier"; // 27 bytes

/// One unknown component (0xff00, data 01 02) in an AppDataDictionary.
const EXTENSIONS_WIRE: [u8; 6] = [
    0x05, // component_data<V>: 5 bytes
    0xff, 0x00, //   component_id: 0xff00
    0x02, //   data<V>: 2 bytes
    0x01, 0x02, //     data
];

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn uri(text: &[u8]) -> IdentifierUri {
    IdentifierUri::new(std::str::from_utf8(text).expect("ascii")).expect("valid URI")
}

fn extensions() -> AppDataDictionary {
    AppDataDictionary::new(&[(0xff00, &[0x01, 0x02])]).expect("dict")
}

fn empty_extensions() -> AppDataDictionary {
    AppDataDictionary::new(&[]).expect("dict")
}

/// Decode, compare to `expected`, re-encode, require byte-identical output.
fn check_fixture<T>(wire: &[u8], expected: &T)
where
    T: Deserialize + Serialize + Size + PartialEq + std::fmt::Debug,
{
    let decoded = T::tls_deserialize_exact(wire).expect("fixture decodes");
    assert_eq!(&decoded, expected);
    assert_eq!(decoded.tls_serialized_len(), wire.len());
    assert_eq!(decoded.tls_serialize_detached().expect("re-encodes"), wire);
}

/// Every strict prefix of a valid encoding must fail to decode, and one
/// extra byte must be reported as trailing data.
fn check_truncation_and_trailing<T: Deserialize + std::fmt::Debug>(wire: &[u8]) {
    for len in 0..wire.len() {
        assert!(
            T::tls_deserialize_exact(&wire[..len]).is_err(),
            "prefix of {len} bytes decoded"
        );
    }
    let mut long = wire.to_vec();
    long.push(0x00);
    assert!(matches!(
        T::tls_deserialize_exact(&long),
        Err(tls_codec::Error::TrailingData)
    ));
}

fn assert_decoding_error<T: Deserialize + std::fmt::Debug>(wire: &[u8], expected: &Error) {
    match T::tls_deserialize_exact(wire) {
        Err(tls_codec::Error::DecodingError(message)) => assert_eq!(message, expected.to_string()),
        other => panic!("expected {expected}, got {other:?}"),
    }
}

fn assert_encoding_error<T: Serialize + std::fmt::Debug>(value: &T, expected: &Error) {
    match value.tls_serialize_detached() {
        Err(tls_codec::Error::EncodingError(message)) => assert_eq!(message, expected.to_string()),
        other => panic!("expected {expected}, got {other:?}"),
    }
}

fn assert_unknown_value<T: Deserialize + std::fmt::Debug>(wire: &[u8]) {
    assert!(
        matches!(
            T::tls_deserialize_exact(wire),
            Err(tls_codec::Error::UnknownValue(_))
        ),
        "{wire:02x?} decoded"
    );
}

// --- SearchIdentifierType (decision mimid-1wgh.5.36) ---

#[test]
fn search_identifier_type_values() {
    check_fixture(&[0x01], &SearchIdentifierType::Handle);
    check_fixture(&[0x02], &SearchIdentifierType::Nick);
    check_fixture(&[0x03], &SearchIdentifierType::Email);
    check_fixture(&[0x04], &SearchIdentifierType::Phone);
    check_fixture(&[0x05], &SearchIdentifierType::PartialName);
    check_fixture(&[0x06], &SearchIdentifierType::WholeProfile);
    check_fixture(&[0x07], &SearchIdentifierType::OidcStdClaim);
    check_fixture(&[0x08], &SearchIdentifierType::VcardField);
}

#[test]
fn search_identifier_type_rejects_reserved_and_undefined() {
    assert_unknown_value::<SearchIdentifierType>(&[0x00]);
    for v in 9..=u8::MAX {
        assert_unknown_value::<SearchIdentifierType>(&[v]);
        // The select cannot be parsed either.
        assert_unknown_value::<QuerySearch>(&[v, 0x00]);
    }
    assert_unknown_value::<QuerySearch>(&[0x00, 0x00]);
}

// --- QueryElement and QuerySearch (decision mimid-1wgh.5.31) ---

#[test]
fn query_element_without_arm_fixtures() {
    for (byte, search) in [
        (0x01, QuerySearch::Handle),
        (0x02, QuerySearch::Nick),
        (0x03, QuerySearch::Email),
        (0x04, QuerySearch::Phone),
        (0x05, QuerySearch::PartialName),
        (0x06, QuerySearch::WholeProfile),
    ] {
        let wire = cat(&[
            &[byte], // searchType; no select arm
            &[0x03], // searchValue<V>: 3 bytes
            b"mat",
        ]);
        check_fixture(
            &wire,
            &QueryElement {
                search: search.clone(),
                search_value: b"mat".to_vec(),
            },
        );
        assert_eq!(search.search_type() as u8, byte);
    }
}

#[test]
fn query_element_oidc_claim_fixture() {
    let wire = cat(&[
        &[0x07], // searchType: oidcStdClaim
        &[0x0a], // claimName<V>: 10 bytes
        GIVEN_NAME,
        &[0x06], // searchValue<V>: 6 bytes
        XAVIER,
    ]);
    let element = QueryElement {
        search: QuerySearch::OidcStdClaim {
            claim_name: GIVEN_NAME.to_vec(),
        },
        search_value: XAVIER.to_vec(),
    };
    check_fixture(&wire, &element);
    assert_eq!(
        element.search.search_type(),
        SearchIdentifierType::OidcStdClaim
    );
    check_truncation_and_trailing::<QueryElement>(&wire);
}

#[test]
fn query_element_vcard_field_fixture() {
    let wire = cat(&[
        &[0x08], // searchType: vcardField
        &[0x03], // propertyName<V>: 3 bytes
        ORG,
        &[0x03], // searchValue<V>: 3 bytes
        XYZ,
    ]);
    check_fixture(
        &wire,
        &QueryElement {
            search: QuerySearch::VcardField {
                property_name: ORG.to_vec(),
            },
            search_value: XYZ.to_vec(),
        },
    );
    check_truncation_and_trailing::<QueryElement>(&wire);
}

#[test]
fn query_element_two_byte_length_prefix() {
    let value = [b'a'; 64];
    let wire = cat(&[
        &[0x04],       // searchType: phone
        &[0x40, 0x40], // searchValue<V>: 64 bytes, two-byte prefix (01 + 14 bits)
        &value,
    ]);
    check_fixture(
        &wire,
        &QueryElement {
            search: QuerySearch::Phone,
            search_value: value.to_vec(),
        },
    );
}

#[test]
fn query_element_rejects_non_minimal_length_prefix() {
    let wire = cat(&[
        &[0x04],       // searchType: phone
        &[0x40, 0x03], // searchValue<V>: 3 bytes in the two-byte form
        b"abc",
    ]);
    assert!(QueryElement::tls_deserialize_exact(&wire).is_err());
}

#[test]
fn query_element_search_value_is_opaque() {
    // Invalid UTF-8 and a null byte decode: searchValue is opaque<V>
    // (as decision mimid-1wgh.5.60).
    let wire = [
        0x03, // searchType: email
        0x03, // searchValue<V>: 3 bytes
        0xff, 0x00, 0xc0, // not UTF-8, contains NUL
    ];
    check_fixture(
        &wire,
        &QueryElement {
            search: QuerySearch::Email,
            search_value: vec![0xff, 0x00, 0xc0],
        },
    );
}

// --- IdentifierRequest ---

/// 61 bytes: three AND-ed elements and one unknown extension.
fn request_wire() -> Vec<u8> {
    cat(&[
        &[0x36], // query_elements<V>: 54 bytes
        &[0x07], //   searchType: oidcStdClaim
        &[0x0a], //   claimName<V>: 10 bytes
        GIVEN_NAME,
        &[0x06], //   searchValue<V>: 6 bytes
        XAVIER,
        &[0x08], //   searchType: vcardField
        &[0x03], //   propertyName<V>: 3 bytes
        ORG,
        &[0x03], //   searchValue<V>: 3 bytes
        XYZ,
        &[0x01], //   searchType: handle
        &[0x18], //   searchValue<V>: 24 bytes
        HANDLE,
        &EXTENSIONS_WIRE, // id_request_extensions
    ])
}

fn request() -> IdentifierRequest {
    IdentifierRequest {
        query_elements: vec![
            QueryElement {
                search: QuerySearch::OidcStdClaim {
                    claim_name: GIVEN_NAME.to_vec(),
                },
                search_value: XAVIER.to_vec(),
            },
            QueryElement {
                search: QuerySearch::VcardField {
                    property_name: ORG.to_vec(),
                },
                search_value: XYZ.to_vec(),
            },
            QueryElement {
                search: QuerySearch::Handle,
                search_value: HANDLE.to_vec(),
            },
        ],
        id_request_extensions: extensions(),
    }
}

#[test]
fn request_fixture() {
    let wire = request_wire();
    assert_eq!(wire.len(), 1 + 19 + 9 + 26 + 6);
    check_fixture(&wire, &request());
    let decoded = IdentifierRequest::tls_deserialize_exact(&wire).expect("decodes");
    assert_eq!(
        decoded.id_request_extensions.get(0xff00),
        Some(&[0x01, 0x02][..])
    );
}

#[test]
fn request_empty_fixture() {
    check_fixture(
        &[
            0x00, // query_elements<V>: empty
            0x00, // id_request_extensions: no components
        ],
        &IdentifierRequest {
            query_elements: Vec::new(),
            id_request_extensions: empty_extensions(),
        },
    );
}

#[test]
fn request_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<IdentifierRequest>(&request_wire());
}

#[test]
fn request_rejects_undefined_search_type_inside_list() {
    let mut wire = request_wire();
    wire[1] = 0x09; // first element's searchType
    assert_unknown_value::<IdentifierRequest>(&wire);
}

#[test]
fn request_rejects_oversized_length_claim() {
    let wire = [
        0xbf, 0xff, 0xff, 0xff, // query_elements<V>: 2^30 - 1 bytes claimed
        0x01, 0x00, // only two bytes follow
    ];
    assert!(IdentifierRequest::tls_deserialize_exact(wire).is_err());
}

// --- IdentifierQueryCode (decision mimid-1wgh.5.36) ---

#[test]
fn identifier_query_code_values() {
    check_fixture(&[0x00], &IdentifierQueryCode::Success);
    check_fixture(&[0x01], &IdentifierQueryCode::NotFound);
    check_fixture(&[0x02], &IdentifierQueryCode::Ambiguous);
    check_fixture(&[0x03], &IdentifierQueryCode::Forbidden);
    check_fixture(&[0x04], &IdentifierQueryCode::UnsupportedField);
}

#[test]
fn identifier_query_code_rejects_undefined_values() {
    for v in 5..=u8::MAX {
        assert_unknown_value::<IdentifierQueryCode>(&[v]);
        assert_unknown_value::<IdentifierResponse>(&[v, 0x00, 0x00, 0x00]);
    }
}

// --- FieldSource (decision mimid-1wgh.5.36) ---

#[test]
fn field_source_values() {
    check_fixture(&[0x07], &FieldSource::OidcStdClaim);
    check_fixture(&[0x08], &FieldSource::VcardField);
}

#[test]
fn field_source_rejects_reserved_and_undefined() {
    for v in (0..=u8::MAX).filter(|v| *v != 7 && *v != 8) {
        assert_unknown_value::<FieldSource>(&[v]);
        assert_unknown_value::<ProfileField>(&[v, 0x00, 0x00]);
    }
}

// --- ProfileField (decision mimid-1wgh.5.20) ---

fn profile_field_wire() -> Vec<u8> {
    cat(&[
        &[0x07], // fieldSource: oidcStdClaim
        &[0x0a], // fieldName<V>: 10 bytes
        GIVEN_NAME,
        &[0x06], // fieldValue<V>: 6 bytes
        XAVIER,
    ])
}

fn given_name_field() -> ProfileField {
    ProfileField {
        field_source: FieldSource::OidcStdClaim,
        field_name: Utf8String::new("given_name").expect("utf8"),
        field_value: XAVIER.to_vec(),
    }
}

#[test]
fn profile_field_fixture() {
    check_fixture(&profile_field_wire(), &given_name_field());
    check_truncation_and_trailing::<ProfileField>(&profile_field_wire());
}

#[test]
fn profile_field_name_rejects_invalid_utf8_and_null() {
    for bad in [
        &[0xff][..],         // never valid in UTF-8
        &[0xc0, 0x80][..],   // overlong NUL
        &[0xed, 0xa0, 0x80], // UTF-16 surrogate U+D800
        &[0x61, 0x00][..],   // "a" then NUL
    ] {
        let len = u8::try_from(bad.len()).expect("short");
        let wire = cat(&[
            &[0x08], // fieldSource: vcardField
            &[len],  // fieldName<V>
            bad,
            &[0x00], // fieldValue<V>: empty
        ]);
        assert!(
            matches!(
                ProfileField::tls_deserialize_exact(&wire),
                Err(tls_codec::Error::DecodingError(_))
            ),
            "{bad:02x?} decoded"
        );
    }
}

#[test]
fn profile_field_name_keeps_bidi_and_zero_width() {
    // U+202E RIGHT-TO-LEFT OVERRIDE (e2 80 ae) and U+200B ZERO WIDTH SPACE
    // (e2 80 8b) are valid UTF8String content (§7.6); they must survive
    // unchanged for the renderer to isolate.
    let wire = [
        0x08, // fieldSource: vcardField
        0x07, // fieldName<V>: 7 bytes
        0xe2, 0x80, 0xae, // U+202E
        0x4e, // "N"
        0xe2, 0x80, 0x8b, // U+200B
        0x00, // fieldValue<V>: empty
    ];
    check_fixture(
        &wire,
        &ProfileField {
            field_source: FieldSource::VcardField,
            field_name: Utf8String::new("\u{202e}N\u{200b}").expect("utf8"),
            field_value: Vec::new(),
        },
    );
}

#[test]
fn profile_field_value_is_opaque() {
    let wire = [
        0x08, // fieldSource: vcardField
        0x01, // fieldName<V>: 1 byte
        0x4e, //   "N"
        0x02, // fieldValue<V>: 2 bytes
        0xff, 0x00, // not UTF-8
    ];
    check_fixture(
        &wire,
        &ProfileField {
            field_source: FieldSource::VcardField,
            field_name: Utf8String::new("N").expect("utf8"),
            field_value: vec![0xff, 0x00],
        },
    );
}

// --- UserProfile ---

/// 57 bytes.
fn profile_wire() -> Vec<u8> {
    cat(&[
        &[0x1b], // stableUri<V>: 27 bytes
        XAVIER_URI,
        &[0x1c], // fields<V>: 28 bytes
        &profile_field_wire(),
        &[0x08], //   fieldSource: vcardField
        &[0x03], //   fieldName<V>: 3 bytes
        ORG,
        &[0x03], //   fieldValue<V>: 3 bytes
        XYZ,
    ])
}

fn profile() -> UserProfile {
    UserProfile {
        stable_uri: uri(XAVIER_URI),
        fields: vec![
            given_name_field(),
            ProfileField {
                field_source: FieldSource::VcardField,
                field_name: Utf8String::new("ORG").expect("utf8"),
                field_value: XYZ.to_vec(),
            },
        ],
    }
}

#[test]
fn profile_fixture() {
    let wire = profile_wire();
    assert_eq!(wire.len(), 28 + 1 + 19 + 9);
    check_fixture(&wire, &profile());
    check_truncation_and_trailing::<UserProfile>(&wire);
}

#[test]
fn profile_rejects_empty_stable_uri() {
    assert_decoding_error::<UserProfile>(
        &[
            0x00, // stableUri<V>: empty
            0x00, // fields<V>: empty
        ],
        &Error::EmptyIdentifierQueryUri,
    );
    assert_encoding_error(
        &UserProfile {
            stable_uri: uri(b""),
            fields: Vec::new(),
        },
        &Error::EmptyIdentifierQueryUri,
    );
}

#[test]
fn profile_rejects_invalid_stable_uri() {
    let wire = cat(&[
        &[0x09], // stableUri<V>: 9 bytes
        b"not a uri",
        &[0x00], // fields<V>: empty
    ]);
    assert_decoding_error::<UserProfile>(&wire, &Error::InvalidUri);
}

// --- IdentifierResponse ---

/// 89 bytes.
fn response_wire() -> Vec<u8> {
    cat(&[
        &[0x00], // responseCode: success
        &[0x1c], // uri<V>: 28 bytes
        &[0x1b], //   uri<V>: 27 bytes
        XAVIER_URI,
        &[0x39], // foundProfiles<V>: 57 bytes
        &profile_wire(),
        &[0x00], // id_response_extensions: no components
    ])
}

fn response() -> IdentifierResponse {
    IdentifierResponse {
        response_code: IdentifierQueryCode::Success,
        uri: vec![uri(XAVIER_URI)],
        found_profiles: vec![profile()],
        id_response_extensions: empty_extensions(),
    }
}

#[test]
fn response_fixture() {
    let wire = response_wire();
    assert_eq!(wire.len(), 1 + 29 + 58 + 1);
    check_fixture(&wire, &response());
}

#[test]
fn response_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<IdentifierResponse>(&response_wire());
}

#[test]
fn response_success_with_uri_only_or_profile_only() {
    let uri_only = cat(&[
        &[0x00], // responseCode: success
        &[0x1c], // uri<V>: 28 bytes
        &[0x1b], //   uri<V>: 27 bytes
        XAVIER_URI,
        &[0x00],          // foundProfiles<V>: empty
        &EXTENSIONS_WIRE, // id_response_extensions
    ]);
    check_fixture(
        &uri_only,
        &IdentifierResponse {
            found_profiles: Vec::new(),
            id_response_extensions: extensions(),
            ..response()
        },
    );
    let profile_only = cat(&[
        &[0x00], // responseCode: success
        &[0x00], // uri<V>: empty
        &[0x39], // foundProfiles<V>: 57 bytes
        &profile_wire(),
        &[0x00], // id_response_extensions: no components
    ]);
    check_fixture(
        &profile_only,
        &IdentifierResponse {
            uri: Vec::new(),
            ..response()
        },
    );
}

#[test]
fn response_failure_codes_without_results() {
    for (byte, code) in [
        (0x01, IdentifierQueryCode::NotFound),
        (0x02, IdentifierQueryCode::Ambiguous),
        (0x03, IdentifierQueryCode::Forbidden),
        (0x04, IdentifierQueryCode::UnsupportedField),
    ] {
        check_fixture(
            &[
                byte, // responseCode
                0x00, // uri<V>: empty
                0x00, // foundProfiles<V>: empty
                0x00, // id_response_extensions: no components
            ],
            &IdentifierResponse {
                response_code: code,
                uri: Vec::new(),
                found_profiles: Vec::new(),
                id_response_extensions: empty_extensions(),
            },
        );
    }
}

#[test]
fn response_rejects_success_without_results() {
    let expected = Error::IdentifierResultsMismatch {
        response_code: IdentifierQueryCode::Success,
    };
    assert_decoding_error::<IdentifierResponse>(
        &[
            0x00, // responseCode: success
            0x00, // uri<V>: empty
            0x00, // foundProfiles<V>: empty
            0x00, // id_response_extensions: no components
        ],
        &expected,
    );
    assert_encoding_error(
        &IdentifierResponse {
            uri: Vec::new(),
            found_profiles: Vec::new(),
            ..response()
        },
        &expected,
    );
}

#[test]
fn response_rejects_failure_codes_with_results() {
    for code in [
        IdentifierQueryCode::NotFound,
        IdentifierQueryCode::Ambiguous,
        IdentifierQueryCode::Forbidden,
        IdentifierQueryCode::UnsupportedField,
    ] {
        let expected = Error::IdentifierResultsMismatch {
            response_code: code,
        };
        let mut with_both = response_wire();
        with_both[0] = code as u8;
        assert_decoding_error::<IdentifierResponse>(&with_both, &expected);
        let uri_only = cat(&[
            &[code as u8], // responseCode
            &[0x1c],       // uri<V>: 28 bytes
            &[0x1b],       //   uri<V>: 27 bytes
            XAVIER_URI,
            &[0x00], // foundProfiles<V>: empty
            &[0x00], // id_response_extensions: no components
        ]);
        assert_decoding_error::<IdentifierResponse>(&uri_only, &expected);
        let profile_only = cat(&[
            &[code as u8], // responseCode
            &[0x00],       // uri<V>: empty
            &[0x39],       // foundProfiles<V>: 57 bytes
            &profile_wire(),
            &[0x00], // id_response_extensions: no components
        ]);
        assert_decoding_error::<IdentifierResponse>(&profile_only, &expected);
        assert_encoding_error(
            &IdentifierResponse {
                response_code: code,
                ..response()
            },
            &expected,
        );
    }
}

#[test]
fn response_rejects_empty_uri_entry() {
    let wire = [
        0x00, // responseCode: success
        0x01, // uri<V>: 1 byte
        0x00, //   uri<V>: empty
        0x00, // foundProfiles<V>: empty
        0x00, // id_response_extensions: no components
    ];
    assert_decoding_error::<IdentifierResponse>(&wire, &Error::EmptyIdentifierQueryUri);
    assert_encoding_error(
        &IdentifierResponse {
            uri: vec![uri(XAVIER_URI), uri(b"")],
            ..response()
        },
        &Error::EmptyIdentifierQueryUri,
    );
}

#[test]
fn response_rejects_empty_stable_uri_inside_list() {
    let wire = [
        0x00, // responseCode: success
        0x00, // uri<V>: empty
        0x02, // foundProfiles<V>: 2 bytes
        0x00, //   stableUri<V>: empty
        0x00, //   fields<V>: empty
        0x00, // id_response_extensions: no components
    ];
    assert_decoding_error::<IdentifierResponse>(&wire, &Error::EmptyIdentifierQueryUri);
}
