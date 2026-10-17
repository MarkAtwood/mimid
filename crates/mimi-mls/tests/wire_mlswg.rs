//! `mimi_mls::wire` against the mlswg interoperability test vectors
//! (`tests/fixtures/mlswg`, see its PROVENANCE).
//!
//! Each vector is decoded, its identifying fields are compared with values
//! read straight from the bytes by a small reader written from the RFC 9420
//! TLS presentation language (independent of OpenMLS), and it is
//! re-encoded and required to be byte-identical.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{
    Capabilities, CipherSuite, ContentType, Credential, ExternalSender, GroupInfo, HPKECiphertext,
    HPKEPublicKey, KeyPackage, MLSMessage, ProposalRef, RatchetTreeOption,
    RatchetTreeRepresentation, SignaturePublicKey, Welcome, WireFormat,
};
use mls_rs::{CipherSuite as MlsRsCipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mlswg");

/// The vendored messages.json entries and their ciphersuites (PROVENANCE).
const ENTRIES: [(u32, u16); 3] = [(0, 0x0001), (100, 0x0003), (200, 0x0002)];

fn fixture(name: &str) -> Vec<u8> {
    fs::read(Path::new(FIXTURE_DIR).join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn message_fixture(entry: u32, field: &str) -> Vec<u8> {
    fixture(&format!("messages-{entry:03}-{field}.bin"))
}

/// A reader for the RFC 9420 §2.1 TLS presentation language.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        head
    }

    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().unwrap())
    }

    /// RFC 9420 §2.1.2: a variable-length vector. Returns the whole
    /// encoding, length prefix included.
    fn vector(&mut self) -> &'a [u8] {
        let first = self.buf[0];
        let prefix_len = 1usize << (first >> 6);
        let mut len = usize::from(first & 0x3f);
        for &byte in &self.buf[1..prefix_len] {
            len = (len << 8) | usize::from(byte);
        }
        self.take(prefix_len + len)
    }

    fn rest(&self) -> &'a [u8] {
        self.buf
    }
}

fn content_type_from(value: u8) -> ContentType {
    match value {
        1 => ContentType::Application,
        2 => ContentType::Proposal,
        3 => ContentType::Commit,
        other => panic!("vector has content_type {other}"),
    }
}

/// Decodes `bytes` exactly as `T`, then requires the encoding, `as_bytes`
/// and the serialized length to equal the input.
fn decode_and_reencode<T>(bytes: &[u8], as_bytes: impl Fn(&T) -> &[u8]) -> T
where
    T: Deserialize + Serialize,
{
    let value = T::tls_deserialize_exact(bytes).expect("decode");
    assert_eq!(as_bytes(&value), bytes, "as_bytes differs from the input");
    assert_eq!(value.tls_serialized_len(), bytes.len());
    assert_eq!(
        value.tls_serialize_detached().expect("encode"),
        bytes,
        "re-encoding differs from the input"
    );
    value
}

/// Requires every strict prefix and the input plus one trailing byte to be
/// rejected without panicking (bug mimid-1wgh.33: tests run in debug).
fn assert_rejects_truncated_and_trailing<T: Deserialize>(bytes: &[u8]) {
    for len in 0..bytes.len() {
        assert!(
            T::tls_deserialize_exact(&bytes[..len]).is_err(),
            "prefix of {len} of {} bytes was accepted",
            bytes.len()
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(matches!(
        T::tls_deserialize_exact(&trailing),
        Err(mimi_mls::tls_codec::Error::TrailingData)
    ));
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = RustCryptoProvider::default()
        .cipher_suite_provider(MlsRsCipherSuite::CURVE25519_AES128)
        .expect("suite 1 provider")
        .hash(bytes)
        .expect("SHA-256");
    digest.iter().fold(String::new(), |mut hex, byte| {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        hex
    })
}

#[test]
fn every_fixture_matches_its_recorded_sha256() {
    let dir = Path::new(FIXTURE_DIR);
    let record = fs::read_to_string(dir.join("PROVENANCE")).expect("read PROVENANCE");
    let mut recorded = BTreeSet::new();
    for line in record
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [expected, name, _source] = fields[..] else {
            panic!("PROVENANCE row does not have 3 fields: {line:?}");
        };
        assert_eq!(sha256_hex(&fixture(name)), expected, "SHA-256 of {name}");
        assert!(recorded.insert(name.to_owned()), "{name} listed twice");
    }
    let present: BTreeSet<String> = fs::read_dir(dir)
        .expect("list fixture directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("UTF-8")
        })
        .filter(|name| name != "PROVENANCE")
        .collect();
    assert_eq!(
        present, recorded,
        "fixture files and PROVENANCE rows differ"
    );
}

#[test]
fn key_package_and_its_parts() {
    for (entry, suite) in ENTRIES {
        let message = message_fixture(entry, "mls_key_package");
        let decoded = decode_and_reencode::<MLSMessage>(&message, MLSMessage::as_bytes);
        assert_eq!(decoded.wire_format(), WireFormat::MlsKeyPackage);
        assert_eq!(decoded.content_type(), None);
        assert_rejects_truncated_and_trailing::<MLSMessage>(&message);

        // RFC 9420 §6: version, wire_format, then the KeyPackage.
        let mut r = Reader::new(&message);
        assert_eq!(r.u16(), 0x0001, "mls10");
        assert_eq!(r.u16(), 0x0005, "mls_key_package");
        let key_package = r.rest();
        decode_and_reencode::<KeyPackage>(key_package, KeyPackage::as_bytes);
        assert_rejects_truncated_and_trailing::<KeyPackage>(key_package);

        // RFC 9420 §10: version, cipher_suite, init_key, leaf_node, ...
        let mut r = Reader::new(key_package);
        assert_eq!(r.u16(), 0x0001, "KeyPackage version mls10");
        let suite_bytes = r.take(2);
        let cipher_suite = CipherSuite::tls_deserialize_exact(suite_bytes).expect("decode");
        assert_eq!(u16::from(cipher_suite), suite);
        assert_eq!(
            cipher_suite.tls_serialize_detached().expect("encode"),
            suite_bytes
        );
        let init_key = r.vector();
        decode_and_reencode::<HPKEPublicKey>(init_key, HPKEPublicKey::as_bytes);

        // RFC 9420 §7.2 LeafNode: encryption_key, signature_key,
        // credential, capabilities, ...
        let encryption_key = r.vector();
        decode_and_reencode::<HPKEPublicKey>(encryption_key, HPKEPublicKey::as_bytes);
        let signature_key = r.vector();
        decode_and_reencode::<SignaturePublicKey>(signature_key, SignaturePublicKey::as_bytes);
        assert_rejects_truncated_and_trailing::<SignaturePublicKey>(signature_key);

        // RFC 9420 §5.3: credential_type, then one vector for both basic
        // (identity<V>) and x509 (certificates<V>).
        let credential_start = r.rest();
        let credential_type = r.u16();
        assert!(matches!(credential_type, 1 | 2), "basic or x509");
        let credential_len = 2 + r.vector().len();
        let credential = &credential_start[..credential_len];
        decode_and_reencode::<Credential>(credential, Credential::as_bytes);
        assert_rejects_truncated_and_trailing::<Credential>(credential);

        // RFC 9420 §7.2 Capabilities: five vectors.
        let capabilities_start = r.rest();
        let capabilities_len: usize = (0..5).map(|_| r.vector().len()).sum();
        let capabilities = &capabilities_start[..capabilities_len];
        decode_and_reencode::<Capabilities>(capabilities, Capabilities::as_bytes);
        assert_rejects_truncated_and_trailing::<Capabilities>(capabilities);

        // RFC 9420 §12.1.8.1 ExternalSender: signature_key, credential.
        let external_sender = [signature_key, credential].concat();
        decode_and_reencode::<ExternalSender>(&external_sender, ExternalSender::as_bytes);
        assert_rejects_truncated_and_trailing::<ExternalSender>(&external_sender);
    }
}

#[test]
fn welcome_and_its_parts() {
    for (entry, suite) in ENTRIES {
        let message = message_fixture(entry, "mls_welcome");
        let decoded = decode_and_reencode::<MLSMessage>(&message, MLSMessage::as_bytes);
        assert_eq!(decoded.wire_format(), WireFormat::MlsWelcome);
        assert_eq!(decoded.content_type(), None);
        assert_rejects_truncated_and_trailing::<MLSMessage>(&message);

        let mut r = Reader::new(&message);
        assert_eq!(r.u16(), 0x0001, "mls10");
        assert_eq!(r.u16(), 0x0003, "mls_welcome");
        let welcome = r.rest();
        decode_and_reencode::<Welcome>(welcome, Welcome::as_bytes);
        assert_rejects_truncated_and_trailing::<Welcome>(welcome);

        // RFC 9420 §12.4.3.1 Welcome: cipher_suite, secrets<V>,
        // encrypted_group_info<V>.
        let mut r = Reader::new(welcome);
        assert_eq!(r.u16(), suite);
        let secrets = r.vector();
        r.vector();
        assert!(r.rest().is_empty());

        // The first EncryptedGroupSecrets: new_member (a HashReference,
        // the same type as ProposalRef), then an HPKECiphertext of
        // kem_output<V> and ciphertext<V>.
        let prefix_len = 1usize << (secrets[0] >> 6);
        let mut s = Reader::new(&secrets[prefix_len..]);
        let new_member = s.vector();
        decode_and_reencode::<ProposalRef>(new_member, ProposalRef::as_bytes);
        assert_rejects_truncated_and_trailing::<ProposalRef>(new_member);
        let ciphertext_start = s.rest();
        let ciphertext_len = s.vector().len() + s.vector().len();
        let ciphertext = &ciphertext_start[..ciphertext_len];
        decode_and_reencode::<HPKECiphertext>(ciphertext, HPKECiphertext::as_bytes);
        assert_rejects_truncated_and_trailing::<HPKECiphertext>(ciphertext);
    }
}

#[test]
fn group_info() {
    for (entry, suite) in ENTRIES {
        let message = message_fixture(entry, "mls_group_info");
        let decoded = decode_and_reencode::<MLSMessage>(&message, MLSMessage::as_bytes);
        assert_eq!(decoded.wire_format(), WireFormat::MlsGroupInfo);
        assert_eq!(decoded.content_type(), None);
        assert_rejects_truncated_and_trailing::<MLSMessage>(&message);

        let mut r = Reader::new(&message);
        assert_eq!(r.u16(), 0x0001, "mls10");
        assert_eq!(r.u16(), 0x0004, "mls_group_info");
        let group_info = r.rest();
        decode_and_reencode::<GroupInfo>(group_info, GroupInfo::as_bytes);
        assert_rejects_truncated_and_trailing::<GroupInfo>(group_info);

        // RFC 9420 §12.4.3 GroupInfo starts with the GroupContext:
        // version, cipher_suite, ...
        let mut r = Reader::new(group_info);
        assert_eq!(r.u16(), 0x0001, "GroupContext version mls10");
        assert_eq!(r.u16(), suite);
    }
}

#[test]
fn public_messages_report_their_content_type() {
    let cases = [
        ("public_message_application", ContentType::Application),
        ("public_message_proposal", ContentType::Proposal),
        ("public_message_commit", ContentType::Commit),
    ];
    for (entry, _) in ENTRIES {
        for (field, expected) in cases {
            let message = message_fixture(entry, field);
            let decoded = decode_and_reencode::<MLSMessage>(&message, MLSMessage::as_bytes);
            assert_eq!(decoded.wire_format(), WireFormat::MlsPublicMessage);
            assert_rejects_truncated_and_trailing::<MLSMessage>(&message);

            // RFC 9420 §6.2 PublicMessage, FramedContent: group_id<V>,
            // epoch, sender, authenticated_data<V>, content_type.
            let mut r = Reader::new(&message);
            assert_eq!(r.u16(), 0x0001, "mls10");
            assert_eq!(r.u16(), 0x0001, "mls_public_message");
            r.vector();
            r.u64();
            // RFC 9420 §6 Sender: member(1) and external(2) carry a
            // uint32; new_member_proposal(3) and new_member_commit(4) none.
            match r.u8() {
                1 | 2 => {
                    r.take(4);
                }
                3 | 4 => {}
                other => panic!("vector has sender_type {other}"),
            }
            r.vector();
            let wire_content_type = content_type_from(r.u8());
            assert_eq!(wire_content_type, expected);
            assert_eq!(decoded.content_type(), Some(expected), "{field}");
        }
    }
}

#[test]
fn private_message_reports_its_clear_content_type() {
    for (entry, _) in ENTRIES {
        let message = message_fixture(entry, "private_message");
        let decoded = decode_and_reencode::<MLSMessage>(&message, MLSMessage::as_bytes);
        assert_eq!(decoded.wire_format(), WireFormat::MlsPrivateMessage);
        assert_rejects_truncated_and_trailing::<MLSMessage>(&message);

        // RFC 9420 §6.3 PrivateMessage: group_id<V>, epoch, content_type.
        let mut r = Reader::new(&message);
        assert_eq!(r.u16(), 0x0001, "mls10");
        assert_eq!(r.u16(), 0x0002, "mls_private_message");
        r.vector();
        r.u64();
        let expected = content_type_from(r.u8());
        assert_eq!(decoded.content_type(), Some(expected));
    }
}

#[test]
fn mls_message_rejects_bad_version_and_wire_format() {
    let message = message_fixture(0, "mls_key_package");
    // RFC 9420 §6: bytes 0-1 are the version, 2-3 the wire_format.
    for (offset, value) in [
        (1, 0x02), // version 0x0002, not mls10
        (3, 0x00), // wire_format 0, reserved
        (3, 0x07), // wire_format 7, undefined
    ] {
        let mut mutated = message.clone();
        mutated[offset] = value;
        assert!(
            MLSMessage::tls_deserialize_exact(&mutated).is_err(),
            "byte {offset} = {value:#04x} was accepted"
        );
    }
}

#[test]
fn full_ratchet_tree_option_wraps_a_ratchet_tree_vector() {
    for (entry, _) in ENTRIES {
        let tree = message_fixture(entry, "ratchet_tree");

        // ratchet-tree-options-01 §3: representation full(1), then the
        // ratchet tree vector.
        let encoded = [&[0x01][..], &tree].concat();
        let option =
            decode_and_reencode::<RatchetTreeOption>(&encoded, RatchetTreeOption::as_bytes);
        assert_eq!(option.representation(), RatchetTreeRepresentation::Full);
        assert_eq!(option.ratchet_tree(), Some(&tree[..]));
        assert_eq!(option.ratchet_tree_url(), None);
        assert_rejects_truncated_and_trailing::<RatchetTreeOption>(&encoded);

        let built = RatchetTreeOption::full(&tree).expect("full");
        assert_eq!(built.as_bytes(), &encoded[..]);
    }
}

#[test]
fn vlbytes_headers_from_deserialization_json() {
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&fixture("deserialization.json")).expect("parse JSON");
    assert!(!cases.is_empty());
    for case in cases {
        let header_hex = case["vlbytes_header"].as_str().expect("header");
        let length = usize::try_from(case["length"].as_u64().expect("length")).expect("usize");
        let header: Vec<u8> = (0..header_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&header_hex[i..i + 2], 16).expect("hex"))
            .collect();
        if length > ROUND_TRIP_LIMIT {
            // The header alone declares far more than is present: rejected
            // without allocating the declared length.
            assert!(matches!(
                HPKEPublicKey::tls_deserialize_exact(&header),
                Err(mimi_mls::tls_codec::Error::EndOfStream)
            ));
            continue;
        }
        let encoded = [header.clone(), vec![0x5a; length]].concat();
        decode_and_reencode::<HPKEPublicKey>(&encoded, HPKEPublicKey::as_bytes);
        // One byte short of the declared length.
        assert!(HPKEPublicKey::tls_deserialize_exact(&encoded[..encoded.len() - 1]).is_err());
    }
}

/// Vectors in deserialization.json longer than this are only checked for
/// rejection of a missing payload; the largest declares 2^30 - 1 bytes.
const ROUND_TRIP_LIMIT: usize = 1 << 16;
