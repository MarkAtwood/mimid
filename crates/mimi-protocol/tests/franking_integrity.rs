//! FrankingAgentData, the franking_integrity_signature and the receiver
//! checks (protocol-07 §5.4.1, §5.4.1.2, §5.4.1.3).
//!
//! Struct fixtures are hand-encoded from the TLS presentation-language text,
//! byte by byte. Signatures, server_franks and TBS bytes are copied from
//! `fixtures/franking/franking_gen.out`, the committed output of
//! `fixtures/franking/franking_gen.py`: an independent Python
//! implementation of SignWithLabel (pyca/cryptography Ed25519, self-checked
//! against the mlswg crypto-basics vectors) with its own TLS encoding (see
//! `fixtures/franking/PROVENANCE`). Ed25519 is deterministic, so this
//! crate's signer must reproduce the Python signatures exactly.
//!
//! None of the expected bytes come from this crate's encoder.

use mimi_mls::wire::{AppDataDictionary, CipherSuite, SignaturePublicKey};
use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{
    Error, Frank, FrankingAgentData, FrankingIntegrityTbs, HubKey, IdentifierUri, ReceivedFrank,
    ServerFrankingContext, component_id, server_frank, verify_server_frank,
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

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// Returns a copy of `bytes` with bit `bit` flipped.
fn flip(bytes: &[u8], bit: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[bit / 8] ^= 1 << (bit % 8);
    out
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

// --- Oracle values (franking_gen.out) ---

/// `franking_key`: seed 0x55 * 32 and its Ed25519 public key.
const FRANKING_SEED: [u8; 32] = [0x55; 32];
const FRANKING_PUB: &str = "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242";
/// Ed25519 public key for seed 0x22 * 32 (group_info_gen.out `hub_pub`).
const OTHER_PUB: &str = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";

const SALT_A: &str = "000102030405060708090a0b0c0d0e0f";
const HUB_KEY_A: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const ALICE: &str = "mimi://b.example/u/alice";
const ROOM: &str = "mimi://hub.example/r/Rl33FWLCYWOwxHrYnpWDQg";
const TIMESTAMP: u64 = 1_700_000_000_000;

/// `franking_tag spec_example`: CBOR `{1: ALICE, 2: ROOM}` and its tag.
const SPEC_EXAMPLE_DATA: &str = "a20178186d696d693a2f2f622e6578616d706c652f752f616c69636502782b6d696d693a2f2f6875622e6578616d706c652f722f526c333346574c4359574f77784872596e7057445167";
const SPEC_EXAMPLE_TAG: &str = "079e83ae657d6516c1fe85dda2af283ffbdf171f851be568703f4f883e73694a";

/// `server_frank basic` and `franking_integrity basic`.
const BASIC_FRANK: &str = "35386d8e36ca923f13ba4f4f1c10141e5c469129758363b6d6a59b840584aa66";
const BASIC_TBS: &str = "35386d8e36ca923f13ba4f4f1c10141e5c469129758363b6d6a59b840584aa660001186d696d693a2f2f622e6578616d706c652f752f616c6963652b6d696d693a2f2f6875622e6578616d706c652f722f526c333346574c4359574f77784872596e70574451670000018bcfe56800";
const BASIC_SIG: &str = "46ec6635d8ba0166ecfe29bcba1dd66c8009963f00d148125eb81b737c8fdcbc089976daff007642e1e66d484b86eb8fa66a2305a7cb121413a9ff7552130203";
/// `franking_integrity suite_3`: the basic TBS with ciphersuite 0x0003.
const SUITE_3_SIG: &str = "875bceb552a26c8105d9db02f9535d2e75bf2fbeb3f73bf76c22175abcc44a74890d9f277172c031cdff42dd7b68dde1cabb6ee3eefd0bcee1f29341f0c92800";

fn suite(n: u16) -> CipherSuite {
    CipherSuite::from(n)
}

fn signature_key(hex: &str) -> SignaturePublicKey {
    // opaque SignaturePublicKey<V>: 1-byte prefix 0x20, then 32 bytes.
    SignaturePublicKey::tls_deserialize_exact(cat(&[&[0x20], &h(hex)])).expect("key")
}

fn basic_context() -> ServerFrankingContext {
    ServerFrankingContext {
        sender_uri: uri(ALICE),
        room_uri: uri(ROOM),
        accepted_timestamp: TIMESTAMP,
    }
}

fn basic_frank() -> Frank {
    Frank {
        server_frank: h32(BASIC_FRANK),
        franking_signature_ciphersuite: suite(1),
        franking_integrity_signature: h(BASIC_SIG),
    }
}

// --- FrankingAgentData (§5.4.1) ---

/// `FrankingAgentData` with the oracle franking key and a BasicCredential
/// for "hub.example", 47 bytes.
fn agent_wire() -> Vec<u8> {
    cat(&[
        &[0x20],          // franking_signature_key<V>: 32 bytes
        &h(FRANKING_PUB), //   Ed25519 public key for seed 0x55 * 32
        &[0x00, 0x01],    // credential.credential_type: basic(1)
        &[0x0b],          // identity<V>: 11 bytes
        b"hub.example",   //   identity
    ])
}

fn agent() -> FrankingAgentData {
    FrankingAgentData::tls_deserialize_exact(agent_wire()).expect("agent decodes")
}

#[test]
fn franking_agent_component_id_is_0x0021() {
    // §10.2 franking_agent; decision mimid-1wgh.4.18.
    assert_eq!(component_id::FRANKING_AGENT, 0x0021);
}

#[test]
fn franking_agent_data_fixture() {
    let wire = agent_wire();
    assert_eq!(wire.len(), 47);
    let decoded = FrankingAgentData::tls_deserialize_exact(&wire).expect("decodes");
    assert_eq!(
        decoded.franking_signature_key.as_bytes(),
        cat(&[&[0x20], &h(FRANKING_PUB)])
    );
    assert_eq!(decoded.credential.as_bytes(), b"\x00\x01\x0bhub.example");
    assert_eq!(decoded.tls_serialized_len(), wire.len());
    assert_eq!(decoded.tls_serialize_detached().expect("re-encodes"), wire);
}

#[test]
fn franking_agent_data_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<FrankingAgentData>(&agent_wire());
}

#[test]
fn franking_agent_data_rejects_non_minimal_prefix() {
    // Non-minimal key prefix: 0x4020 encodes 32, which fits in one byte.
    let non_minimal = cat(&[&[0x40], &agent_wire()]);
    assert!(FrankingAgentData::tls_deserialize_exact(&non_minimal).is_err());
}

/// The component travels as GroupContext app data under 0x0021.
#[test]
fn franking_agent_data_from_app_data_dictionary() {
    let wire = agent_wire();
    let dict = AppDataDictionary::new(&[(component_id::FRANKING_AGENT, &wire)]).expect("dict");
    let data = dict.get(0x0021).expect("entry");
    assert_eq!(
        FrankingAgentData::tls_deserialize_exact(data).expect("decodes"),
        agent()
    );
}

// --- FrankingIntegrityTBS (§5.4.1.2) ---

/// Hand-encoded basic TBS, 111 bytes.
fn basic_tbs_wire() -> Vec<u8> {
    cat(&[
        &h(BASIC_FRANK), // server_frank[32], no length prefix
        &[0x00, 0x01],   // franking_signature_ciphersuite: 1
        &[0x18],         // context.sender_uri<V>: 24 bytes
        ALICE.as_bytes(),
        &[0x2b], // context.room_uri<V>: 43 bytes
        ROOM.as_bytes(),
        &[0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00], // accepted_timestamp
    ])
}

#[test]
fn integrity_tbs_fixture() {
    let wire = basic_tbs_wire();
    assert_eq!(wire, h(BASIC_TBS), "hand encoding matches the oracle");
    let expected = FrankingIntegrityTbs {
        server_frank: h32(BASIC_FRANK),
        franking_signature_ciphersuite: suite(1),
        context: basic_context(),
    };
    let decoded = FrankingIntegrityTbs::tls_deserialize_exact(&wire).expect("decodes");
    assert_eq!(decoded, expected);
    assert_eq!(decoded.tls_serialized_len(), wire.len());
    assert_eq!(decoded.tls_serialize_detached().expect("re-encodes"), wire);
}

#[test]
fn integrity_tbs_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<FrankingIntegrityTbs>(&basic_tbs_wire());
}

/// Sign with our signer, require the oracle signature, verify it.
fn check_sign(tbs: FrankingIntegrityTbs, expected_sig: &str) {
    let frank = tbs.sign(&FRANKING_SEED).expect("signs");
    assert_eq!(frank.server_frank, tbs.server_frank);
    assert_eq!(
        frank.franking_signature_ciphersuite,
        tbs.franking_signature_ciphersuite
    );
    assert_eq!(frank.franking_integrity_signature, h(expected_sig));
    frank
        .verify_integrity(&signature_key(FRANKING_PUB), &tbs.context)
        .expect("oracle signature verifies");
}

#[test]
fn integrity_signature_basic() {
    let tbs = FrankingIntegrityTbs::tls_deserialize_exact(h(BASIC_TBS)).expect("tbs");
    check_sign(tbs, BASIC_SIG);
}

#[test]
fn integrity_signature_empty_uris_zero_timestamp() {
    let tbs = FrankingIntegrityTbs {
        server_frank: h32("38acec8a45fbe8d80b0596f37a3ef55746026106a9a92d6e6f7500a78755a7f0"),
        franking_signature_ciphersuite: suite(1),
        context: ServerFrankingContext {
            sender_uri: uri(""),
            room_uri: uri(""),
            accepted_timestamp: 0,
        },
    };
    assert_eq!(
        tbs.tls_serialize_detached().expect("encodes"),
        h(
            "38acec8a45fbe8d80b0596f37a3ef55746026106a9a92d6e6f7500a78755a7f0000100000000000000000000"
        )
    );
    check_sign(
        tbs,
        "503bda9e05610a22fa71e791821a1827bfda74497cbb912788ef23b1e576f057b7e7e9c422632bb23f3a7ac675dd23f89fa775519dc2667d99122db764e65901",
    );
}

#[test]
fn integrity_signature_max_timestamp() {
    let tbs = FrankingIntegrityTbs {
        server_frank: h32("ae0ed3e76df99062397b2bd328111b717cb55f7b05c32a8b16d35c7d5bba41e8"),
        franking_signature_ciphersuite: suite(1),
        context: ServerFrankingContext {
            accepted_timestamp: u64::MAX,
            ..basic_context()
        },
    };
    check_sign(
        tbs,
        "f6a80787776afdfbb9e2b784092dac7539214a9141cb5b8b59315663ed506b38b388248c85f8d6f012ef5952416ec70b23d6d0ec711ed31cd7f1d52917fb9c05",
    );
}

/// A 16384-byte room URI (4-byte prefix). The oracle prints only the TBS
/// length and head; the signature pins the rest.
#[test]
fn integrity_signature_long_room_uri() {
    let prefix = "mimi://hub.example/r/";
    let room = format!("{prefix}{}", "a".repeat(16384 - prefix.len()));
    let tbs = FrankingIntegrityTbs {
        server_frank: h32("227e10cd5e4dacf7e81ed3fca923a108ddb2a9aa8915a3755ec75da92e092b83"),
        franking_signature_ciphersuite: suite(1),
        context: ServerFrankingContext {
            room_uri: uri(&room),
            ..basic_context()
        },
    };
    let wire = tbs.tls_serialize_detached().expect("encodes");
    assert_eq!(wire.len(), 16455);
    assert_eq!(&wire[..8], h("227e10cd5e4dacf7").as_slice());
    check_sign(
        tbs,
        "6d4b7d6ce754bdd7aefd20363a4c8fd55786e015f24a77ed8bd5805641525bc3e2e51e29a1550ba9bc73124a8e9f506eeb9f058ec330528dd8be50ed8d873007",
    );
}

/// The hub's whole job: server_frank from its key, then the signature.
#[test]
fn hub_franks_spec_example() {
    let hub_key = HubKey::new(h32(HUB_KEY_A));
    let tag = h32(SPEC_EXAMPLE_TAG);
    let context = basic_context();
    let frank_bytes = server_frank(&hub_key, &tag, &context).expect("frank");
    assert_eq!(frank_bytes, h32(BASIC_FRANK));
    let frank = FrankingIntegrityTbs {
        server_frank: frank_bytes,
        franking_signature_ciphersuite: suite(1),
        context: context.clone(),
    }
    .sign(&FRANKING_SEED)
    .expect("signs");
    assert_eq!(frank, basic_frank());
    // What the hub checks when validating an AbusiveMessage (§5.9).
    verify_server_frank(&hub_key, &tag, &context, &frank.server_frank).expect("frank");
    frank
        .verify_integrity(&signature_key(FRANKING_PUB), &context)
        .expect("signature");
}

fn is_verify_failure(r: Result<(), Error>) -> bool {
    matches!(r, Err(Error::Label(mimi_mls::label::Error::Verify)))
}

#[test]
fn integrity_rejects_any_single_bit_change() {
    let key = signature_key(FRANKING_PUB);
    let context = basic_context();
    let frank = basic_frank();

    for bit in 0..512 {
        let bad = Frank {
            franking_integrity_signature: flip(&frank.franking_integrity_signature, bit),
            ..frank.clone()
        };
        assert!(is_verify_failure(bad.verify_integrity(&key, &context)));
    }
    for bit in 0..256 {
        let bad = Frank {
            server_frank: flip(&frank.server_frank, bit).try_into().expect("32"),
            ..frank.clone()
        };
        assert!(is_verify_failure(bad.verify_integrity(&key, &context)));
        let bad_key = signature_key(&hex(&flip(&h(FRANKING_PUB), bit)));
        assert!(
            frank.verify_integrity(&bad_key, &context).is_err(),
            "flipped key bit {bit} verified"
        );
    }
    // Every single-bit change of the encoded context that still decodes.
    let wire = context.tls_serialize_detached().expect("encodes");
    let mut decodable = 0;
    for bit in 0..wire.len() * 8 {
        if let Ok(bad) = ServerFrankingContext::tls_deserialize_exact(flip(&wire, bit)) {
            decodable += 1;
            assert!(is_verify_failure(frank.verify_integrity(&key, &bad)));
        }
    }
    assert!(decodable > 64, "only {decodable} flipped contexts decoded");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn integrity_rejects_wrong_key_and_malformed_signatures() {
    let context = basic_context();
    let frank = basic_frank();
    assert!(is_verify_failure(
        frank.verify_integrity(&signature_key(OTHER_PUB), &context)
    ));
    let key = signature_key(FRANKING_PUB);
    for len in [0, 1, 63, 65, 128] {
        let mut sig = h(BASIC_SIG);
        sig.resize(len, 0);
        let bad = Frank {
            franking_integrity_signature: sig,
            ..frank.clone()
        };
        assert!(is_verify_failure(bad.verify_integrity(&key, &context)));
    }
    // A 31-byte and an empty key.
    for key_wire in [cat(&[&[0x1f], &h(FRANKING_PUB)[..31]]), vec![0x00]] {
        let bad_key = SignaturePublicKey::tls_deserialize_exact(key_wire).expect("opaque");
        assert!(is_verify_failure(
            frank.verify_integrity(&bad_key, &context)
        ));
    }
}

/// Only suite 1 is supported. Suite 3 is also Ed25519, and the oracle
/// signature is valid Ed25519, but it must be refused, not verified.
#[test]
fn integrity_refuses_unsupported_cipher_suite() {
    let frank = Frank {
        franking_signature_ciphersuite: suite(3),
        franking_integrity_signature: h(SUITE_3_SIG),
        ..basic_frank()
    };
    assert!(matches!(
        frank.verify_integrity(&signature_key(FRANKING_PUB), &basic_context()),
        Err(Error::UnsupportedCipherSuite { cipher_suite: 3 })
    ));
    let tbs = FrankingIntegrityTbs {
        server_frank: h32(BASIC_FRANK),
        franking_signature_ciphersuite: suite(3),
        context: basic_context(),
    };
    assert!(matches!(
        tbs.sign(&FRANKING_SEED),
        Err(Error::UnsupportedCipherSuite { cipher_suite: 3 })
    ));
    // The basic signature under suite 3 does not verify either way.
    let relabelled = Frank {
        franking_signature_ciphersuite: suite(3),
        ..basic_frank()
    };
    assert!(
        relabelled
            .verify_integrity(&signature_key(FRANKING_PUB), &basic_context())
            .is_err()
    );
}

// --- Receiver verification (§5.4.1.3) ---

struct Inputs {
    frank: Frank,
    accepted_timestamp: u64,
    franking_tag: [u8; 32],
    group_cipher_suite: CipherSuite,
    franking_agent: FrankingAgentData,
    salt: [u8; 16],
    application_data: Vec<u8>,
    content_sender_uri: IdentifierUri,
    content_room_uri: IdentifierUri,
    authenticated_sender_uri: IdentifierUri,
    notify_room_uri: IdentifierUri,
}

impl Inputs {
    /// The spec example end to end: content `{1: ALICE, 2: ROOM}` under
    /// salt 00..0f, franked by the oracle hub.
    fn valid() -> Self {
        Self {
            frank: basic_frank(),
            accepted_timestamp: TIMESTAMP,
            franking_tag: h32(SPEC_EXAMPLE_TAG),
            group_cipher_suite: suite(1),
            franking_agent: agent(),
            salt: h16(SALT_A),
            application_data: h(SPEC_EXAMPLE_DATA),
            content_sender_uri: uri(ALICE),
            content_room_uri: uri(ROOM),
            authenticated_sender_uri: uri(ALICE),
            notify_room_uri: uri(ROOM),
        }
    }

    fn verify(&self) -> Result<ServerFrankingContext, Error> {
        ReceivedFrank {
            frank: &self.frank,
            accepted_timestamp: self.accepted_timestamp,
            franking_tag: &self.franking_tag,
            group_cipher_suite: self.group_cipher_suite,
            franking_agent: &self.franking_agent,
            salt: &self.salt,
            application_data: &self.application_data,
            content_sender_uri: &self.content_sender_uri,
            content_room_uri: &self.content_room_uri,
            authenticated_sender_uri: &self.authenticated_sender_uri,
            notify_room_uri: &self.notify_room_uri,
        }
        .verify()
    }
}

#[test]
fn receiver_accepts_spec_example() {
    assert_eq!(Inputs::valid().verify().expect("verifies"), basic_context());
}

#[test]
fn receiver_rejects_cipher_suite_mismatch() {
    let mut inputs = Inputs::valid();
    inputs.group_cipher_suite = suite(3);
    assert!(matches!(
        inputs.verify(),
        Err(Error::FrankCipherSuiteMismatch { frank: 1, group: 3 })
    ));
    // Matching but unsupported suite.
    inputs.frank.franking_signature_ciphersuite = suite(3);
    inputs.frank.franking_integrity_signature = h(SUITE_3_SIG);
    assert!(matches!(
        inputs.verify(),
        Err(Error::UnsupportedCipherSuite { cipher_suite: 3 })
    ));
}

#[test]
fn receiver_rejects_tampered_hub_values() {
    let label_failure = |r: Result<ServerFrankingContext, Error>| matches!(r, Err(Error::Label(_)));

    let mut inputs = Inputs::valid();
    inputs.accepted_timestamp += 1;
    assert!(label_failure(inputs.verify()));

    let mut inputs = Inputs::valid();
    inputs.frank.server_frank[0] ^= 1;
    assert!(label_failure(inputs.verify()));

    let mut inputs = Inputs::valid();
    inputs.frank.franking_integrity_signature[63] ^= 0x80;
    assert!(label_failure(inputs.verify()));

    let mut inputs = Inputs::valid();
    inputs.franking_agent.franking_signature_key = signature_key(OTHER_PUB);
    assert!(label_failure(inputs.verify()));
}

/// A sender URI or room URI in the content that the hub did not sign fails
/// the signature, before the equality checks.
#[test]
fn receiver_rejects_content_uris_the_hub_did_not_sign() {
    let mut inputs = Inputs::valid();
    inputs.content_sender_uri = uri("mimi://b.example/u/mallory");
    inputs.authenticated_sender_uri = inputs.content_sender_uri.clone();
    assert!(matches!(inputs.verify(), Err(Error::Label(_))));

    let mut inputs = Inputs::valid();
    inputs.content_room_uri = uri("mimi://hub.example/r/other");
    inputs.notify_room_uri = inputs.content_room_uri.clone();
    assert!(matches!(inputs.verify(), Err(Error::Label(_))));
}

#[test]
fn receiver_rejects_franking_tag_mismatch() {
    let mut inputs = Inputs::valid();
    inputs.application_data.push(0x00);
    assert!(matches!(inputs.verify(), Err(Error::FrankingTagMismatch)));

    let mut inputs = Inputs::valid();
    inputs.salt[15] ^= 1;
    assert!(matches!(inputs.verify(), Err(Error::FrankingTagMismatch)));

    let mut inputs = Inputs::valid();
    inputs.franking_tag[31] ^= 1;
    assert!(matches!(inputs.verify(), Err(Error::FrankingTagMismatch)));
}

#[test]
fn receiver_rejects_sender_mismatch() {
    let mut inputs = Inputs::valid();
    inputs.authenticated_sender_uri = uri("mimi://b.example/u/mallory");
    assert!(matches!(inputs.verify(), Err(Error::FrankSenderMismatch)));
    // Byte comparison: a case change in the host is a mismatch.
    inputs.authenticated_sender_uri = uri("mimi://B.example/u/alice");
    assert!(matches!(inputs.verify(), Err(Error::FrankSenderMismatch)));
}

#[test]
fn receiver_rejects_room_mismatch() {
    let mut inputs = Inputs::valid();
    inputs.notify_room_uri = uri("mimi://hub.example/r/other");
    assert!(matches!(inputs.verify(), Err(Error::FrankRoomMismatch)));
    // An empty path room ID (absent) never matches.
    inputs.notify_room_uri = uri("");
    assert!(matches!(inputs.verify(), Err(Error::FrankRoomMismatch)));
}
