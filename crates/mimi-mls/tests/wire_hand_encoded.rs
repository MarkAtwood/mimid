//! `mimi_mls::wire` against bytes hand-encoded from the TLS presentation
//! language in mls-extensions-10 §4.6, ratchet-tree-options-02 §3-4 and
//! RFC 9420, with byte-by-byte comments. Each valid case is decoded,
//! compared, re-encoded and required to be byte-identical; each invalid one
//! must be rejected without panicking (tests run in debug, bug
//! mimid-1wgh.33).

use std::fs;

use mimi_mls::tls_codec::{Deserialize, Error, Serialize};
use mimi_mls::wire::{
    AppDataDictionary, CipherSuite, HPKEPublicKey, PartialGroupInfo, RatchetTreeOption,
    RatchetTreePresence, RatchetTreeRepresentation, RequiredCapabilities,
};

fn reencode<T: Serialize>(value: &T) -> Vec<u8> {
    value.tls_serialize_detached().expect("encode")
}

/// Requires every strict prefix, and the input plus a trailing byte, to be
/// rejected.
fn assert_rejects_truncated_and_trailing<T: Deserialize>(bytes: &[u8]) {
    for len in 0..bytes.len() {
        assert!(
            T::tls_deserialize_exact(&bytes[..len]).is_err(),
            "prefix of {len} bytes was accepted"
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(matches!(
        T::tls_deserialize_exact(&trailing),
        Err(Error::TrailingData)
    ));
}

fn decoding_error_mentions<T: std::fmt::Debug>(result: Result<T, Error>, needle: &str) -> bool {
    matches!(result, Err(Error::DecodingError(message)) if message.contains(needle))
}

// ---- mls-extensions-10 §4.6 AppDataDictionary ----

const APP_DATA_DICTIONARY: [u8; 12] = [
    0x0b, // component_data<V>: 11 bytes
    0x00, 0x01, // ComponentData.component_id = 0x0001
    0x02, // data<V>: 2 bytes
    0x61, 0x62, // "ab"
    0x00, 0x22, // ComponentData.component_id = 0x0022
    0x03, // data<V>: 3 bytes
    0x01, 0x02, 0x03,
];

#[test]
fn app_data_dictionary_round_trips() {
    let dictionary = AppDataDictionary::tls_deserialize_exact(APP_DATA_DICTIONARY).expect("decode");
    assert_eq!(dictionary.get(0x0001), Some(&b"ab"[..]));
    assert_eq!(dictionary.get(0x0022), Some(&[0x01, 0x02, 0x03][..]));
    assert_eq!(dictionary.get(0x0002), None);
    let entries: Vec<(u16, &[u8])> = dictionary.entries().collect();
    assert_eq!(
        entries,
        [(0x0001, &b"ab"[..]), (0x0022, &[0x01, 0x02, 0x03][..])]
    );
    assert_eq!(dictionary.as_bytes(), APP_DATA_DICTIONARY);
    assert_eq!(reencode(&dictionary), APP_DATA_DICTIONARY);
    assert_rejects_truncated_and_trailing::<AppDataDictionary>(&APP_DATA_DICTIONARY);

    let built =
        AppDataDictionary::new(&[(0x0001, b"ab"), (0x0022, &[0x01, 0x02, 0x03])]).expect("new");
    assert_eq!(built.as_bytes(), APP_DATA_DICTIONARY);
}

#[test]
fn empty_app_data_dictionary() {
    let empty = [
        0x00, // component_data<V>: 0 bytes
    ];
    let dictionary = AppDataDictionary::tls_deserialize_exact(empty).expect("decode");
    assert_eq!(dictionary.entries().count(), 0);
    assert_eq!(reencode(&dictionary), empty);
    assert_eq!(AppDataDictionary::new(&[]).expect("new").as_bytes(), empty);
}

#[test]
fn app_data_dictionary_rejects_unsorted_keys() {
    let unsorted = [
        0x0a, // component_data<V>: 10 bytes
        0x00, 0x22, // component_id = 0x0022
        0x02, 0x01, 0x02, // data<V>
        0x00, 0x01, // component_id = 0x0001: out of order
        0x02, 0x61, 0x62, // data<V>
    ];
    assert!(decoding_error_mentions(
        AppDataDictionary::tls_deserialize_exact(unsorted),
        "order"
    ));
    assert!(AppDataDictionary::new(&[(0x0022, &[0x01]), (0x0001, &[0x02])]).is_err());
}

#[test]
fn app_data_dictionary_rejects_duplicate_keys() {
    let duplicate = [
        0x08, // component_data<V>: 8 bytes
        0x00, 0x01, // component_id = 0x0001
        0x01, 0x61, // data<V>
        0x00, 0x01, // component_id = 0x0001 again
        0x01, 0x62, // data<V>
    ];
    assert!(decoding_error_mentions(
        AppDataDictionary::tls_deserialize_exact(duplicate),
        "duplicate"
    ));
    assert!(AppDataDictionary::new(&[(0x0001, &[0x01]), (0x0001, &[0x02])]).is_err());
}

#[test]
fn app_data_dictionary_rejects_non_minimal_length() {
    // RFC 9420 §2.1.2: lengths use the minimum number of bytes. 11 fits
    // in one byte, so the two-byte form 0x400b is invalid.
    let mut non_minimal = vec![0x40, 0x0b];
    non_minimal.extend_from_slice(&APP_DATA_DICTIONARY[1..]);
    assert!(AppDataDictionary::tls_deserialize_exact(&non_minimal).is_err());
}

#[test]
fn app_data_dictionary_rejects_oversized_length() {
    let oversized = [
        0x7f, 0xff, // component_data<V>: 16383 bytes, but only 5 follow
        0x00, 0x01, 0x01, 0x61, 0x62,
    ];
    assert!(matches!(
        AppDataDictionary::tls_deserialize_exact(oversized),
        Err(Error::EndOfStream)
    ));
}

// ---- ratchet-tree-options-02 §3 RatchetTreeOption ----

#[test]
fn https_url_ratchet_tree_option() {
    let url = b"https://example.com";
    let mut encoded = vec![
        0x02, // representation = httpsUrl(2) (decision mimid-1wgh.4.19)
        0x13, // ratchet_tree_url<V>: 19 bytes
    ];
    encoded.extend_from_slice(url);

    let option = RatchetTreeOption::tls_deserialize_exact(&encoded).expect("decode");
    assert_eq!(option.representation(), RatchetTreeRepresentation::HttpsUrl);
    assert_eq!(option.ratchet_tree_url(), Some(&url[..]));
    assert_eq!(option.ratchet_tree(), None);
    assert_eq!(reencode(&option), encoded);
    assert_rejects_truncated_and_trailing::<RatchetTreeOption>(&encoded);

    assert_eq!(
        RatchetTreeOption::https_url(url)
            .expect("https_url")
            .as_bytes(),
        &encoded[..]
    );
}

#[test]
fn ratchet_tree_options_without_payload() {
    let cases = [
        (
            [0x03], // representation = outOfBand(3), empty struct
            RatchetTreeRepresentation::OutOfBand,
            RatchetTreeOption::out_of_band(),
        ),
        (
            [0x04], // representation = distributionService(4), empty struct
            RatchetTreeRepresentation::DistributionService,
            RatchetTreeOption::distribution_service(),
        ),
    ];
    for (encoded, representation, built) in cases {
        let option = RatchetTreeOption::tls_deserialize_exact(encoded).expect("decode");
        assert_eq!(option.representation(), representation);
        assert_eq!(option.ratchet_tree(), None);
        assert_eq!(option.ratchet_tree_url(), None);
        assert_eq!(reencode(&option), encoded);
        assert_eq!(built, option);
        assert_rejects_truncated_and_trailing::<RatchetTreeOption>(&encoded);
    }
}

#[test]
fn ratchet_tree_option_rejects_undefined_representations() {
    for value in [0x00, 0x05, 0xff] {
        // reserved(0), and 5 and 255, which are undefined.
        assert!(matches!(
            RatchetTreeOption::tls_deserialize_exact([value]),
            Err(Error::UnknownValue(v)) if v == u64::from(value)
        ));
    }
}

#[test]
fn full_ratchet_tree_option_rejects_malformed_tree() {
    let bad_optional = [
        0x01, // representation = full(1)
        0x01, // ratchet_tree<V>: 1 byte
        0x02, // optional<Node> presence 2: neither 0 nor 1
    ];
    assert!(RatchetTreeOption::tls_deserialize_exact(bad_optional).is_err());
    assert!(RatchetTreeOption::full(&bad_optional[1..]).is_err());
}

// ---- ratchet-tree-options-02 §4 PartialGroupInfo ----

#[test]
fn partial_group_info_without_extensions() {
    let encoded = [
        0x01, // ratchet_tree_presence = present(1)
        0x00, // group_info_extensions<V>: 0 bytes
        0x04, // signature<V>: 4 bytes
        0x11, 0x22, 0x33, 0x44,
    ];
    let partial = PartialGroupInfo::tls_deserialize_exact(encoded).expect("decode");
    assert_eq!(
        partial.ratchet_tree_presence(),
        RatchetTreePresence::Present
    );
    assert_eq!(partial.group_info_extensions(), [0x00]);
    assert_eq!(partial.signature(), [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(reencode(&partial), encoded);
    assert_rejects_truncated_and_trailing::<PartialGroupInfo>(&encoded);

    let built = PartialGroupInfo::new(
        RatchetTreePresence::Present,
        &[0x00],
        &[0x11, 0x22, 0x33, 0x44],
    )
    .expect("new");
    assert_eq!(built.as_bytes(), encoded);
}

#[test]
fn partial_group_info_presence_values() {
    let cases = [
        (0x00, RatchetTreePresence::NoRatchetTree),
        (0x01, RatchetTreePresence::Present),
        (0x02, RatchetTreePresence::Removed),
        (0x03, RatchetTreePresence::Added),
    ];
    for (value, presence) in cases {
        // presence, empty extensions, empty signature
        let encoded = [value, 0x00, 0x00];
        let partial = PartialGroupInfo::tls_deserialize_exact(encoded).expect("decode");
        assert_eq!(partial.ratchet_tree_presence(), presence);
        assert_eq!(reencode(&partial), encoded);
    }
    for value in [0x04, 0xff] {
        assert!(matches!(
            PartialGroupInfo::tls_deserialize_exact([value, 0x00, 0x00]),
            Err(Error::UnknownValue(v)) if v == u64::from(value)
        ));
    }
}

#[test]
fn partial_group_info_keeps_known_and_unknown_extensions() {
    let encoded = [
        0x02, // ratchet_tree_presence = removed(2)
        0x0d, // group_info_extensions<V>: 13 bytes
        0x00, 0x04, // extension_type = external_pub(4)
        0x03, // extension_data<V>: 3 bytes
        0x02, 0x0a, 0x0b, // ExternalPub.external_pub: HPKEPublicKey<V>, 2 bytes
        0xff, 0x00, // extension_type = 0xff00 (private use, unknown)
        0x01, // extension_data<V>: 1 byte
        0x07, // extension_data
        0x0a, 0x0a, // extension_type = 0x0a0a (GREASE)
        0x00, // extension_data<V>: 0 bytes
        0x01, // signature<V>: 1 byte
        0x09,
    ];
    let partial = PartialGroupInfo::tls_deserialize_exact(encoded).expect("decode");
    assert_eq!(
        partial.ratchet_tree_presence(),
        RatchetTreePresence::Removed
    );
    assert_eq!(partial.group_info_extensions(), &encoded[1..15]);
    assert_eq!(partial.signature(), [0x09]);
    assert_eq!(reencode(&partial), encoded);
    assert_rejects_truncated_and_trailing::<PartialGroupInfo>(&encoded);

    let built =
        PartialGroupInfo::new(RatchetTreePresence::Removed, &encoded[1..15], &[0x09]).expect("new");
    assert_eq!(built.as_bytes(), encoded);
}

#[test]
fn partial_group_info_rejects_duplicate_extensions() {
    let encoded = [
        0x00, // ratchet_tree_presence = no_ratchet_tree(0)
        0x06, // group_info_extensions<V>: 6 bytes
        0xff, 0x00, 0x00, // extension_type 0xff00, empty extension_data
        0xff, 0x00, 0x00, // the same type again
        0x00, // signature<V>: 0 bytes
    ];
    assert!(decoding_error_mentions(
        PartialGroupInfo::tls_deserialize_exact(encoded),
        "duplicate"
    ));
}

/// RFC 9420 §2.1.2 length prefix for `len` < 2^14.
fn length_prefix(len: usize) -> Vec<u8> {
    let len = u16::try_from(len).expect("short vector");
    if len < 0x40 {
        vec![len.to_be_bytes()[1]]
    } else {
        (0x4000 | len).to_be_bytes().to_vec()
    }
}

/// An encoded Extension carrying a real ratchet tree from the mlswg
/// vectors as its extension_data.
fn extension_with_tree(extension_type: [u8; 2]) -> Vec<u8> {
    let tree = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mlswg/messages-000-ratchet_tree.bin"
    ))
    .expect("read ratchet tree fixture");
    [&extension_type[..], &length_prefix(tree.len()), &tree].concat()
}

fn partial_group_info_with_extension(extension: &[u8]) -> Vec<u8> {
    [
        &[0x01][..], // ratchet_tree_presence = present(1)
        &length_prefix(extension.len()),
        extension,
        &[0x00], // signature<V>: 0 bytes
    ]
    .concat()
}

#[test]
fn partial_group_info_rejects_ratchet_tree_extension() {
    // extension_type = ratchet_tree(2), RFC 9420 §17.3.
    let with_tree = partial_group_info_with_extension(&extension_with_tree([0x00, 0x02]));
    assert!(decoding_error_mentions(
        PartialGroupInfo::tls_deserialize_exact(&with_tree),
        "ratchet_tree"
    ));

    // Control: the same bytes under an unknown extension type decode, so
    // the rejection above is about the type alone.
    let unknown = partial_group_info_with_extension(&extension_with_tree([0xff, 0x01]));
    let partial = PartialGroupInfo::tls_deserialize_exact(&unknown).expect("decode");
    assert_eq!(reencode(&partial), unknown);
}

#[test]
fn partial_group_info_rejects_non_minimal_signature_length() {
    let encoded = [
        0x00, // ratchet_tree_presence
        0x00, // group_info_extensions<V>: 0 bytes
        0x40, 0x01, // signature<V>: 1 byte, in the non-minimal two-byte form
        0x01,
    ];
    assert!(PartialGroupInfo::tls_deserialize_exact(encoded).is_err());
    assert!(PartialGroupInfo::new(RatchetTreePresence::Present, &[0x40, 0x00], &[]).is_err());
}

// ---- RFC 9420 ----

#[test]
fn required_capabilities_round_trips() {
    let encoded = [
        0x04, // extension_types<V>: 4 bytes
        0x00, 0x06, // app_data_dictionary (mls-extensions-10 §7.1.1)
        0x0a, 0x0a, // GREASE
        0x02, // proposal_types<V>: 2 bytes
        0x00, 0x08, // app_data_update (mls-extensions-10)
        0x02, // credential_types<V>: 2 bytes
        0x00, 0x01, // basic
    ];
    let required = RequiredCapabilities::tls_deserialize_exact(encoded).expect("decode");
    assert_eq!(required.as_bytes(), encoded);
    assert_eq!(reencode(&required), encoded);
    assert_rejects_truncated_and_trailing::<RequiredCapabilities>(&encoded);
}

#[test]
fn cipher_suite_accepts_any_uint16() {
    for value in [0x0001u16, 0x0a0a, 0xffff] {
        let encoded = value.to_be_bytes();
        let suite = CipherSuite::tls_deserialize_exact(encoded).expect("decode");
        assert_eq!(u16::from(suite), value);
        assert_eq!(suite, CipherSuite::from(value));
        assert_eq!(reencode(&suite), encoded);
    }
    assert!(CipherSuite::tls_deserialize_exact([0x00]).is_err());
}

#[test]
fn opaque_vectors_reject_non_canonical_lengths() {
    // RFC 9420 §2.1.2.
    let empty = [0x00];
    assert_eq!(
        reencode(&HPKEPublicKey::tls_deserialize_exact(empty).expect("decode")),
        empty
    );
    for bad in [
        &[0x40, 0x01, 0xaa][..],         // 1 in the two-byte form
        &[0x80, 0x00, 0x00, 0x01, 0xaa], // 1 in the four-byte form
        &[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa], // prefix 0b11 is invalid
        &[0xbf, 0xff, 0xff, 0xff, 0xaa], // declares 2^30 - 1 bytes, 1 present
    ] {
        assert!(
            HPKEPublicKey::tls_deserialize_exact(bad).is_err(),
            "{bad:02x?}"
        );
    }
}
