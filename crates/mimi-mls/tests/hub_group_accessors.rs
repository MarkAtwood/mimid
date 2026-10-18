//! `Observer::external_senders`, the `wire::ExternalSender` and
//! `wire::Credential` field accessors, and
//! `wire::GroupInfo::has_ratchet_tree_extension` (bead mimid-1wgh.6.34).
//!
//! Two independent oracles:
//!
//! - mls-rs (decision mimid-1wgh.4.13) builds the groups, with and without
//!   an external_senders extension, and exports GroupInfos with and without
//!   a ratchet_tree extension;
//! - bytes hand-encoded from the TLS presentation language of RFC 9420
//!   §5.3, §8.1, §12.1.8.1 and §12.4.3, with byte-by-byte comments. Each
//!   valid case is decoded, compared, re-encoded and required to be
//!   byte-identical; each malformed one must be rejected with an error, not
//!   a panic (tests run in debug, bug mimid-1wgh.33).

use std::fs;

use mimi_mls::Store;
use mimi_mls::observer::{Observer, ObserverStart};
use mimi_mls::tls_codec::{Deserialize, Error, Serialize};
use mimi_mls::wire::{Credential, ExternalSender, GroupInfo};
use mls_rs::extension::ExtensionType;
use mls_rs::extension::built_in::ExternalSendersExt;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// RFC 9420 §17.3: the external_senders extension type.
const EXTERNAL_SENDERS: ExtensionType = ExtensionType::new(0x0005);

const ALICE: &[u8] = b"mimi://a.example/u/alice";
/// The hub's credential identity (decision mimid-1wgh.6.35).
const HUB: &[u8] = b"mimi://hub.example";
const FOLLOWER: &[u8] = b"mimi://b.example";

trait Config: mls_rs::client_builder::MlsConfig {}
impl<C: mls_rs::client_builder::MlsConfig> Config for C {}

fn suite() -> impl CipherSuiteProvider {
    RustCryptoProvider::default()
        .cipher_suite_provider(SUITE_1)
        .expect("suite 1")
}

/// A fresh Ed25519 public key with a BasicCredential `name`.
fn signing_identity(name: &[u8]) -> SigningIdentity {
    let (_secret, public) = suite().signature_key_generate().expect("key");
    SigningIdentity::new(
        BasicCredential::new(name.to_vec()).into_credential(),
        public,
    )
}

/// An mls-rs group of one member, alice, with `senders` as its
/// external_senders extension, or with no such extension if `senders` is
/// `None`.
fn alice_group(senders: Option<Vec<SigningIdentity>>) -> Group<impl Config + use<>> {
    let (secret, public) = suite().signature_key_generate().expect("key");
    let alice = Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(RustCryptoProvider::default())
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(ALICE.to_vec()).into_credential(),
                public,
            ),
            secret,
            SUITE_1,
        )
        .build();
    let mut extensions = ExtensionList::new();
    if let Some(senders) = senders {
        extensions
            .set_from(ExternalSendersExt::new(senders))
            .expect("external_senders extension");
    }
    alice
        .create_group(extensions, Default::default(), None)
        .expect("mls-rs creates the group")
}

fn observe(group: &Group<impl Config>) -> Observer {
    let store = Store::open_in_memory().expect("store");
    let group_info = group
        .group_info_message(false)
        .expect("GroupInfo")
        .to_bytes()
        .expect("encode");
    let tree = group.export_tree().to_bytes().expect("tree");
    let ObserverStart { observer, .. } =
        Observer::from_group_info(&store, &group_info, Some(&tree)).expect("from_group_info");
    observer
}

/// RFC 9420 §12.1.8.1 ExternalSender with an Ed25519 key and a
/// BasicCredential, hand-encoded.
fn hand_encoded_sender(key: &[u8], identity: &[u8]) -> Vec<u8> {
    let mut sender = vec![u8::try_from(key.len()).expect("short key")]; // signature_key<V>
    sender.extend_from_slice(key);
    sender.extend_from_slice(&[0x00, 0x01]); // CredentialType basic
    sender.push(u8::try_from(identity.len()).expect("short identity")); // identity<V>
    sender.extend_from_slice(identity);
    sender
}

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

// ---- Observer::external_senders against mls-rs ----

#[test]
fn observer_reads_external_senders_of_an_mls_rs_group() {
    let hub = signing_identity(HUB);
    let follower = signing_identity(FOLLOWER);
    let group = alice_group(Some(vec![hub.clone(), follower.clone()]));
    let senders = observe(&group)
        .external_senders()
        .expect("external_senders");

    assert_eq!(senders.len(), 2);
    for (sender, (identity, name)) in senders.iter().zip([(&hub, HUB), (&follower, FOLLOWER)]) {
        let key = identity.signature_key.as_bytes();
        assert_eq!(sender.signature_key(), key);
        assert_eq!(sender.credential().identity(), Some(name));
        assert_eq!(sender.as_bytes(), hand_encoded_sender(key, name));
    }

    // mls-rs's own extension_data decodes to the same entries.
    let extension_data = &group
        .context()
        .extensions
        .get(EXTERNAL_SENDERS)
        .expect("external_senders")
        .extension_data;
    let decoded = Vec::<ExternalSender>::tls_deserialize_exact(extension_data).expect("decode");
    assert_eq!(decoded, senders);
    assert_eq!(&reencode(&decoded), extension_data);
}

#[test]
fn observer_reports_no_external_senders_without_the_extension() {
    let group = alice_group(None);
    assert!(
        observe(&group)
            .external_senders()
            .expect("external_senders")
            .is_empty()
    );
}

// ---- GroupInfo::has_ratchet_tree_extension against mls-rs ----

/// RFC 9420 §6: strips the 4-byte MLSMessage header from a GroupInfo
/// message and decodes the bare GroupInfo.
fn bare_group_info(message: &MlsMessage) -> GroupInfo {
    let encoded = message.to_bytes().expect("encode");
    assert_eq!(encoded[..4], [0x00, 0x01, 0x00, 0x04]);
    GroupInfo::tls_deserialize_exact(&encoded[4..]).expect("GroupInfo")
}

#[test]
fn mls_rs_group_infos_with_and_without_ratchet_tree() {
    let group = alice_group(Some(vec![signing_identity(HUB)]));
    for with_tree in [false, true] {
        let plain = bare_group_info(&group.group_info_message(with_tree).expect("GroupInfo"));
        assert_eq!(plain.has_ratchet_tree_extension(), with_tree);
        // external_pub is another GroupInfo extension; it must not be
        // mistaken for ratchet_tree, nor hide it.
        let external = bare_group_info(
            &group
                .group_info_message_allowing_ext_commit(with_tree)
                .expect("GroupInfo"),
        );
        assert_eq!(external.has_ratchet_tree_extension(), with_tree);
    }
}

// ---- RFC 9420 §12.1.8.1 external_senders, hand-encoded ----

/// `ExternalSender external_senders<V>` with two entries: a BasicCredential
/// and an x509 credential.
const TWO_SENDERS: [u8; 67] = [
    0x40, 0x41, // ExternalSender external_senders<V>: 65 bytes (2-byte length)
    // ExternalSender 1
    0x20, // SignaturePublicKey signature_key<V>: 32 bytes
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, //
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, //
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, //
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, //
    0x00, 0x01, // CredentialType basic
    0x12, // opaque identity<V>: 18 bytes
    b'm', b'i', b'm', b'i', b':', b'/', b'/', b'h', b'u', b'b', b'.', b'e', b'x', b'a', b'm', b'p',
    b'l', b'e', // "mimi://hub.example"
    // ExternalSender 2
    0x04, // SignaturePublicKey signature_key<V>: 4 bytes
    0x01, 0x02, 0x03, 0x04, //
    0x00, 0x02, // CredentialType x509
    0x03, // Certificate certificates<V>: 3 bytes
    0x02, // opaque cert_data<V>: 2 bytes
    0xca, 0xfe,
];

#[test]
fn hand_encoded_external_senders() {
    let senders = Vec::<ExternalSender>::tls_deserialize_exact(TWO_SENDERS).expect("decode");
    assert_eq!(senders.len(), 2);

    assert_eq!(senders[0].signature_key(), [0xab; 32]);
    assert_eq!(senders[0].credential().identity(), Some(HUB));
    assert_eq!(senders[0].as_bytes(), &TWO_SENDERS[2..56]);
    assert_eq!(senders[0].credential().as_bytes(), &TWO_SENDERS[35..56]);

    assert_eq!(senders[1].signature_key(), [0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        senders[1].credential().identity(),
        None,
        "x509 is not basic"
    );
    assert_eq!(senders[1].as_bytes(), &TWO_SENDERS[56..]);

    assert_eq!(reencode(&senders), TWO_SENDERS);
    assert_rejects_truncated_and_trailing::<Vec<ExternalSender>>(&TWO_SENDERS);
}

#[test]
fn hand_encoded_credentials() {
    // RFC 9420 §5.3: a basic credential with an empty identity.
    let basic_empty = [0x00, 0x01, 0x00];
    let credential = Credential::tls_deserialize_exact(basic_empty).expect("decode");
    assert_eq!(credential.identity(), Some(&[][..]));
    assert_eq!(reencode(&credential), basic_empty);

    // A GREASE credential type (RFC 9420 §13.5) with a 1-byte vector.
    let grease = [0x0a, 0x0a, 0x01, 0x07];
    let credential = Credential::tls_deserialize_exact(grease).expect("decode");
    assert_eq!(credential.identity(), None);
    assert_eq!(reencode(&credential), grease);
}

#[test]
fn empty_external_senders_list() {
    let senders = Vec::<ExternalSender>::tls_deserialize_exact([0x00]).expect("decode");
    assert!(senders.is_empty());
}

#[test]
fn malformed_external_senders_are_rejected() {
    let second = &TWO_SENDERS[56..]; // ExternalSender 2: 11 bytes
    let cases: [(&str, Vec<u8>); 6] = [
        ("empty input", Vec::new()),
        (
            "non-minimal list length",
            [&[0x40, 0x0b][..], second].concat(),
        ),
        ("list length past the end", [&[0x0c][..], second].concat()),
        (
            "list length cuts an entry",
            [&[0x0a][..], &second[..10]].concat(),
        ),
        (
            "non-minimal signature_key length",
            [
                &[0x0c, 0x40, 0x04][..], // list: 12 bytes; signature_key<V>: 4 bytes in 2
                &second[1..],
            ]
            .concat(),
        ),
        (
            "entry ends inside the credential",
            [
                &[0x08][..], // list: 8 bytes
                &second[..8],
            ]
            .concat(),
        ),
    ];
    for (case, bytes) in cases {
        assert!(
            Vec::<ExternalSender>::tls_deserialize_exact(&bytes).is_err(),
            "{case} was accepted"
        );
    }
    // A single ExternalSender with a non-minimal identity length.
    let mut sender = hand_encoded_sender(&[0x01], b"x");
    sender.splice(4..5, [0x40, 0x01]);
    assert!(ExternalSender::tls_deserialize_exact(&sender).is_err());
}

// ---- RFC 9420 §12.4.3 GroupInfo, hand-encoded ----

/// RFC 9420 §2.1.2 length prefix for `len` < 2^14.
fn length_prefix(len: usize) -> Vec<u8> {
    let len = u16::try_from(len).expect("short vector");
    if len < 0x40 {
        vec![len.to_be_bytes()[1]]
    } else {
        (0x4000 | len).to_be_bytes().to_vec()
    }
}

/// RFC 9420 §7.1 Extension with `extension_data`.
fn extension(extension_type: [u8; 2], data: &[u8]) -> Vec<u8> {
    [&extension_type[..], &length_prefix(data.len()), data].concat()
}

/// RFC 9420 §12.4.3 GroupInfo whose `extensions<V>` holds `extensions`.
/// The signature is empty: decoding does not verify it.
fn group_info(extensions: &[u8]) -> Vec<u8> {
    [
        // GroupContext (RFC 9420 §8.1)
        &[
            0x00, 0x01, // ProtocolVersion version = mls10
            0x00, 0x01, // CipherSuite cipher_suite = 1
            0x02, b'g', b'1', // opaque group_id<V>
            0, 0, 0, 0, 0, 0, 0, 7, // uint64 epoch = 7
            0x01, 0xaa, // opaque tree_hash<V>: 1 byte
            0x00, // opaque confirmed_transcript_hash<V>: empty
            0x00, // Extension extensions<V>: empty
        ][..],
        &length_prefix(extensions.len()), // Extension extensions<V>
        extensions,
        &[
            0x01, 0xbb, // MAC confirmation_tag<V>: 1 byte
            0x00, 0x00, 0x00, 0x00, // uint32 signer = 0
            0x00, // opaque signature<V>: empty
        ],
    ]
    .concat()
}

/// A real ratchet tree from the mlswg vectors.
fn mlswg_tree() -> Vec<u8> {
    fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mlswg/messages-000-ratchet_tree.bin"
    ))
    .expect("read ratchet tree fixture")
}

#[test]
fn hand_encoded_group_info_ratchet_tree_presence() {
    let tree = mlswg_tree();
    let cases = [
        ("no extensions", Vec::new(), false),
        (
            "unknown extension carrying a tree",
            extension([0xff, 0x01], &tree),
            false,
        ),
        (
            "ratchet_tree (0x0002)",
            extension([0x00, 0x02], &tree),
            true,
        ),
        (
            "unknown extension, then ratchet_tree",
            [
                extension([0xff, 0x01], &[0x00]),
                extension([0x00, 0x02], &tree),
            ]
            .concat(),
            true,
        ),
    ];
    for (case, extensions, expected) in cases {
        let encoded = group_info(&extensions);
        let decoded = GroupInfo::tls_deserialize_exact(&encoded).expect(case);
        assert_eq!(decoded.has_ratchet_tree_extension(), expected, "{case}");
        assert_eq!(reencode(&decoded), encoded, "{case}");
    }
    assert_rejects_truncated_and_trailing::<GroupInfo>(&group_info(&extension(
        [0x00, 0x02],
        &[0x00], // optional<Node> ratchet_tree<V>: empty
    )));
}

#[test]
fn malformed_ratchet_tree_extension_is_rejected() {
    let cases: [(&str, Vec<u8>); 3] = [
        (
            "invalid optional<Node> presence byte",
            extension([0x00, 0x02], &[0x01, 0x05]),
        ),
        (
            "tree vector longer than extension_data",
            extension([0x00, 0x02], &[0x05, 0x01]),
        ),
        (
            "duplicate ratchet_tree",
            [
                extension([0x00, 0x02], &mlswg_tree()),
                extension([0x00, 0x02], &mlswg_tree()),
            ]
            .concat(),
        ),
    ];
    for (case, extensions) in cases {
        assert!(
            GroupInfo::tls_deserialize_exact(group_info(&extensions)).is_err(),
            "{case} was accepted"
        );
    }
}
