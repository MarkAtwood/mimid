//! franking_tag and server_frank (protocol-06 §5.4.1.1, §5.4.1.2).
//!
//! Every expected value is copied from `fixtures/franking/franking_gen.out`,
//! the committed output of `fixtures/franking/franking_gen.py`: an
//! independent standard-library Python implementation with its own TLS
//! encoding (see `fixtures/franking/PROVENANCE`). Case names match the
//! generator's.

use mimi_protocol::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{
    Error, HubKey, IdentifierUri, ServerFrankingContext, franking_tag, server_frank,
    verify_franking_tag, verify_server_frank,
};

fn h(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn h32(hex: &str) -> [u8; 32] {
    h(hex).try_into().expect("32 bytes")
}

fn h16(hex: &str) -> [u8; 16] {
    h(hex).try_into().expect("16 bytes")
}

fn uri(s: &str) -> IdentifierUri {
    IdentifierUri::new(s).expect("valid URI")
}

/// The generator's `pattern(n)`: byte i is i mod 251.
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// Returns a copy of `bytes` with bit `bit` flipped.
fn flip(bytes: &[u8], bit: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[bit / 8] ^= 1 << (bit % 8);
    out
}

const SALT_A: &str = "000102030405060708090a0b0c0d0e0f";
const HUB_KEY_A: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const ALICE: &str = "mimi://b.example/u/alice";
const ROOM: &str = "mimi://hub.example/r/Rl33FWLCYWOwxHrYnpWDQg";

/// `spec_example`: CBOR `{1: ALICE, 2: ROOM}`, the §5.4.1.1 extensions map.
const SPEC_EXAMPLE_DATA: &str = "a20178186d696d693a2f2f622e6578616d706c652f752f616c69636502782b6d696d693a2f2f6875622e6578616d706c652f722f526c333346574c4359574f77784872596e7057445167";
const SPEC_EXAMPLE_TAG: &str = "079e83ae657d6516c1fe85dda2af283ffbdf171f851be568703f4f883e73694a";

/// `basic` context and frank.
const BASIC_CONTEXT: &str = "186d696d693a2f2f622e6578616d706c652f752f616c6963652b6d696d693a2f2f6875622e6578616d706c652f722f526c333346574c4359574f77784872596e70574451670000018bcfe56800";
const BASIC_FRANK: &str = "35386d8e36ca923f13ba4f4f1c10141e5c469129758363b6d6a59b840584aa66";

fn check_tag(salt: &str, data: &[u8], expected: &str) {
    let salt = h16(salt);
    let expected = h32(expected);
    assert_eq!(franking_tag(&salt, data), expected);
    verify_franking_tag(&salt, data, &expected).expect("oracle tag verifies");
}

#[test]
fn franking_tag_spec_example() {
    check_tag(SALT_A, &h(SPEC_EXAMPLE_DATA), SPEC_EXAMPLE_TAG);
}

#[test]
fn franking_tag_empty_application_data() {
    check_tag(
        SALT_A,
        b"",
        "07eff8b326b7798c9ccfcbdbe579489ac785a7995a04618b1a2813c26744777d",
    );
}

/// The room URI inside application_data is raw UTF-8 (U+00E9, U+2603,
/// U+1F600); franking_tag treats it as opaque bytes.
#[test]
fn franking_tag_non_ascii_room_uri() {
    let data = h(
        "a20178186d696d693a2f2f622e6578616d706c652f752f616c6963650278236d696d693a2f2f6875622e6578616d706c652f722f636166c3a92de298832df09f9880",
    );
    assert!(
        String::from_utf8_lossy(&data).contains("\u{e9}-\u{2603}-\u{1f600}"),
        "fixture carries the non-ASCII URI"
    );
    check_tag(
        SALT_A,
        &data,
        "0832bdc53643d731a73af4154c0cfc5c50daeb9082d2c3541970a4bd7d1540f1",
    );
}

#[test]
fn franking_tag_long_application_data() {
    check_tag(
        SALT_A,
        &pattern(100_000),
        "541e6f57c9e8a4889363aa92e50231c68293560bccf984de1bfc97adf846a428",
    );
}

#[test]
fn franking_tag_salt_ff_one_zero_byte() {
    check_tag(
        "ffffffffffffffffffffffffffffffff",
        &[0x00],
        "9588551aeb3ec8dc2f646dd0f1669523b6b7ecef284c39aac07add138bf8f0e9",
    );
}

#[test]
fn franking_tag_rejects_any_single_bit_change() {
    let salt = h16(SALT_A);
    let data = h(SPEC_EXAMPLE_DATA);
    let tag = h32(SPEC_EXAMPLE_TAG);
    for bit in 0..256 {
        let bad: [u8; 32] = flip(&tag, bit).try_into().expect("32 bytes");
        assert!(matches!(
            verify_franking_tag(&salt, &data, &bad),
            Err(Error::FrankingTagMismatch)
        ));
    }
    for bit in 0..128 {
        let bad: [u8; 16] = flip(&salt, bit).try_into().expect("16 bytes");
        assert!(matches!(
            verify_franking_tag(&bad, &data, &tag),
            Err(Error::FrankingTagMismatch)
        ));
    }
    for bit in 0..data.len() * 8 {
        assert!(matches!(
            verify_franking_tag(&salt, &flip(&data, bit), &tag),
            Err(Error::FrankingTagMismatch)
        ));
    }
    // Truncated and extended application_data.
    for bad in [&data[..data.len() - 1], &[data.as_slice(), &[0]].concat()] {
        assert!(matches!(
            verify_franking_tag(&salt, bad, &tag),
            Err(Error::FrankingTagMismatch)
        ));
    }
}

/// Decode the fixture context, compare, re-encode byte-identically, then
/// check the frank against the oracle and verify it.
fn check_frank(
    hub_key: &str,
    tag: &str,
    expected_context: &ServerFrankingContext,
    context_hex: &str,
    expected_frank: &str,
) {
    let wire = h(context_hex);
    let decoded = ServerFrankingContext::tls_deserialize_exact(&wire).expect("context decodes");
    assert_eq!(&decoded, expected_context);
    assert_eq!(decoded.tls_serialize_detached().expect("re-encodes"), wire);

    let key = HubKey::new(h32(hub_key));
    let tag = h32(tag);
    let expected = h32(expected_frank);
    assert_eq!(server_frank(&key, &tag, &decoded).expect("frank"), expected);
    verify_server_frank(&key, &tag, &decoded, &expected).expect("oracle frank verifies");
}

#[test]
fn server_frank_basic() {
    let context = ServerFrankingContext {
        sender_uri: uri(ALICE),
        room_uri: uri(ROOM),
        accepted_timestamp: 1_700_000_000_000,
    };
    check_frank(
        HUB_KEY_A,
        SPEC_EXAMPLE_TAG,
        &context,
        BASIC_CONTEXT,
        BASIC_FRANK,
    );
}

#[test]
fn server_frank_empty_uris_zero_timestamp() {
    let context = ServerFrankingContext {
        sender_uri: uri(""),
        room_uri: uri(""),
        accepted_timestamp: 0,
    };
    check_frank(
        HUB_KEY_A,
        "0000000000000000000000000000000000000000000000000000000000000000",
        &context,
        "00000000000000000000",
        "38acec8a45fbe8d80b0596f37a3ef55746026106a9a92d6e6f7500a78755a7f0",
    );
}

#[test]
fn server_frank_max_timestamp() {
    let context = ServerFrankingContext {
        sender_uri: uri(ALICE),
        room_uri: uri(ROOM),
        accepted_timestamp: u64::MAX,
    };
    check_frank(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        SPEC_EXAMPLE_TAG,
        &context,
        "186d696d693a2f2f622e6578616d706c652f752f616c6963652b6d696d693a2f2f6875622e6578616d706c652f722f526c333346574c4359574f77784872596e7057445167ffffffffffffffff",
        "ae0ed3e76df99062397b2bd328111b717cb55f7b05c32a8b16d35c7d5bba41e8",
    );
}

/// 63-byte sender URI (1-byte prefix 0x3f), 64-byte room URI (2-byte prefix
/// 0x4040).
#[test]
fn server_frank_prefix_boundary_63_64() {
    let uri_64 = format!("mimi://b.example/u/{}", "b".repeat(64 - 19));
    let context = ServerFrankingContext {
        sender_uri: uri(&uri_64[..63]),
        room_uri: uri(&uri_64),
        accepted_timestamp: 1,
    };
    check_frank(
        HUB_KEY_A,
        SPEC_EXAMPLE_TAG,
        &context,
        "3f6d696d693a2f2f622e6578616d706c652f752f626262626262626262626262626262626262626262626262626262626262626262626262626262626262626240406d696d693a2f2f622e6578616d706c652f752f6262626262626262626262626262626262626262626262626262626262626262626262626262626262626262620000000000000001",
        "11b5fbaa135ffaa311a0bcf3d5e705a156f1c6eec3eb54cc1d12446afbb18ac2",
    );
}

/// A 16384-byte room URI takes the 4-byte prefix 0x80004000. The oracle
/// prints only the context's length and head, so the frank pins the rest.
#[test]
fn server_frank_long_room_uri_4byte_prefix() {
    let prefix = "mimi://hub.example/r/";
    let room = format!("{prefix}{}", "a".repeat(16384 - prefix.len()));
    let context = ServerFrankingContext {
        sender_uri: uri(ALICE),
        room_uri: uri(&room),
        accepted_timestamp: 1_700_000_000_000,
    };
    let wire = context.tls_serialize_detached().expect("encodes");
    assert_eq!(wire.len(), 16421);
    assert_eq!(&wire[..8], h("186d696d693a2f2f").as_slice());
    assert_eq!(&wire[25..29], [0x80, 0x00, 0x40, 0x00]);
    assert_eq!(
        ServerFrankingContext::tls_deserialize_exact(&wire).expect("decodes"),
        context
    );

    let key = HubKey::new(h32(HUB_KEY_A));
    let tag = h32(SPEC_EXAMPLE_TAG);
    let expected = h32("227e10cd5e4dacf7e81ed3fca923a108ddb2a9aa8915a3755ec75da92e092b83");
    assert_eq!(server_frank(&key, &tag, &context).expect("frank"), expected);
    verify_server_frank(&key, &tag, &context, &expected).expect("oracle frank verifies");
}

#[test]
fn server_frank_percent_encoded_non_ascii_room_uri() {
    let context = ServerFrankingContext {
        sender_uri: uri(ALICE),
        room_uri: uri("mimi://hub.example/r/caf%C3%A9-%E2%98%83"),
        accepted_timestamp: 1_700_000_000_000,
    };
    check_frank(
        HUB_KEY_A,
        SPEC_EXAMPLE_TAG,
        &context,
        "186d696d693a2f2f622e6578616d706c652f752f616c696365286d696d693a2f2f6875622e6578616d706c652f722f6361662543332541392d2545322539382538330000018bcfe56800",
        "0de1778bdc5d6c4f84430bb56f2fe5b8da1b5c695db2625c5439f2221cd209a0",
    );
}

/// `IdentifierUri` is RFC 3986 (ASCII-only, decision mimid-1wgh.36), so a
/// raw non-ASCII room URI cannot enter a context, from either side.
#[test]
fn context_rejects_raw_non_ascii_room_uri() {
    assert!(matches!(
        IdentifierUri::new("mimi://hub.example/r/caf\u{e9}"),
        Err(Error::InvalidUri)
    ));
    // sender "" | room "mimi://h/caf\u{e9}" (UTF-8 c3 a9) | timestamp 0
    let wire = h("000e6d696d693a2f2f682f636166c3a90000000000000000");
    let ascii = h("000e6d696d693a2f2f682f63616665650000000000000000");
    assert!(
        ServerFrankingContext::tls_deserialize_exact(&ascii).is_ok(),
        "same framing with ASCII decodes, so only the UTF-8 is rejected"
    );
    assert!(ServerFrankingContext::tls_deserialize_exact(&wire).is_err());
}

#[test]
fn context_decode_is_strict() {
    let wire = h(BASIC_CONTEXT);
    assert!(ServerFrankingContext::tls_deserialize_exact(&wire[..wire.len() - 1]).is_err());
    assert!(
        ServerFrankingContext::tls_deserialize_exact([wire.as_slice(), &[0]].concat()).is_err()
    );
    // Non-minimal prefix: 0x4018 encodes 24, which fits in one byte.
    let non_minimal = [&[0x40], wire.as_slice()].concat();
    assert!(ServerFrankingContext::tls_deserialize_exact(&non_minimal).is_err());
}

#[test]
fn server_frank_rejects_any_single_bit_change() {
    let key_bytes = h32(HUB_KEY_A);
    let key = HubKey::new(key_bytes);
    let tag = h32(SPEC_EXAMPLE_TAG);
    let frank = h32(BASIC_FRANK);
    let wire = h(BASIC_CONTEXT);
    let context = ServerFrankingContext::tls_deserialize_exact(&wire).expect("decodes");
    let mismatch = |r: Result<(), Error>| matches!(r, Err(Error::ServerFrankMismatch));

    for bit in 0..256 {
        let bad: [u8; 32] = flip(&frank, bit).try_into().expect("32 bytes");
        assert!(mismatch(verify_server_frank(&key, &tag, &context, &bad)));

        let bad: [u8; 32] = flip(&tag, bit).try_into().expect("32 bytes");
        assert!(mismatch(verify_server_frank(&key, &bad, &context, &frank)));

        let bad = HubKey::new(flip(&key_bytes, bit).try_into().expect("32 bytes"));
        assert!(mismatch(verify_server_frank(&bad, &tag, &context, &frank)));
    }

    // Every single-bit change of the encoded context that still decodes.
    let mut decodable = 0;
    for bit in 0..wire.len() * 8 {
        if let Ok(bad) = ServerFrankingContext::tls_deserialize_exact(flip(&wire, bit)) {
            decodable += 1;
            assert!(mismatch(verify_server_frank(&key, &tag, &bad, &frank)));
        }
    }
    // The 64 timestamp bits always decode, plus many URI character flips.
    assert!(decodable > 64, "only {decodable} flipped contexts decoded");
}

#[test]
fn hub_key_debug_is_redacted() {
    let shown = format!("{:?}", HubKey::new([0xab; 32]));
    assert_eq!(shown, "HubKey(..)");
}
