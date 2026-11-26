//! draft-mahy-mls-semiprivatemessage-08 §3.1 on the wire.
//!
//! Every fixture here is hand-encoded from §3.1's presentation language,
//! byte by byte, with the field each run of bytes belongs to named in a
//! comment. None comes from the encoder under test, so a bug in the
//! encoder cannot make a fixture agree with it (AGENTS.md).
//!
//! The direction is the one AGENTS.md fixes: decode, compare to the
//! expected value, re-encode, require byte-identical output.

#![forbid(unsafe_code)]

use mimi_mls::tls_codec::{Deserialize, Serialize, Size};
use mimi_mls::wire::{
    ContentType, KeyForExternalReceiver, MAX_EXTERNAL_RECEIVERS, SemiPrivateMessage,
    SemiPrivateMessageContent,
};
use mimi_mls::wire::{
    EXTERNAL_RECEIVERS_COMPONENT, ExternalReceiver, ExternalReceivers,
    MAX_LISTED_EXTERNAL_RECEIVERS,
};

/// Decode, compare the length, re-encode, and require the bytes back.
fn round_trip<T: Deserialize + Serialize + Size>(bytes: &[u8]) -> T {
    let value = T::tls_deserialize_exact(bytes).expect("the fixture decodes");
    assert_eq!(
        value.tls_serialized_len(),
        bytes.len(),
        "tls_serialized_len disagrees with the fixture"
    );
    assert_eq!(
        value.tls_serialize_detached().expect("re-encodes"),
        bytes,
        "re-encoding is not byte-identical"
    );
    value
}

/// One `KeyForExternalReceiver`: a 4-octet ref and an HPKECiphertext of
/// two 2-octet fields.
const KEY_FOR_RECEIVER: &[u8] = &[
    0x04, 0xaa, 0xbb, 0xcc, 0xdd, // external_receiver_ref<V>: 4 octets
    0x02, 0x11, 0x22, //             HPKECiphertext.kem_output<V>: 2 octets
    0x02, 0x33, 0x44, //             HPKECiphertext.ciphertext<V>: 2 octets
];

#[test]
fn a_key_for_an_external_receiver_round_trips() {
    let key = round_trip::<KeyForExternalReceiver>(KEY_FOR_RECEIVER);
    assert_eq!(
        key.external_receiver_ref.as_slice(),
        [0xaa, 0xbb, 0xcc, 0xdd]
    );
    assert_eq!(
        key.encrypted_keys_and_nonces.as_bytes(),
        [0x02, 0x11, 0x22, 0x02, 0x33, 0x44],
        "the ciphertext keeps its own encoding, as received"
    );
}

/// A whole `SemiPrivateMessage` carrying one external receiver.
fn message_wire(content_type: u8) -> Vec<u8> {
    let mut v = vec![
        0x03,
        0x67,
        0x69,
        0x64, // group_id<V>: "gid"
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x07,         // epoch: 7
        content_type, //                                   content_type
        0x02,
        0xde,
        0xad, //                               authenticated_data<V>
        0x02,
        0xbe,
        0xef, //                               partial_context_hash<V>
    ];
    // keys_for_external_receivers<V>: one entry, so the length prefix is
    // the entry's own length.
    v.push(u8::try_from(KEY_FOR_RECEIVER.len()).expect("under 64"));
    v.extend_from_slice(KEY_FOR_RECEIVER);
    v.extend_from_slice(&[
        0x02, 0x01, 0x02, // framed_content_tbs_hash<V>
        0x02, 0x03, 0x04, // encrypted_sender_data<V>
        0x02, 0x05, 0x06, // ciphertext<V>
    ]);
    v
}

#[test]
fn a_semiprivate_message_round_trips() {
    // content_type: proposal(2).
    let wire = message_wire(0x02);
    let message = round_trip::<SemiPrivateMessage>(&wire);

    assert_eq!(message.group_id.as_slice(), b"gid");
    assert_eq!(message.epoch, 7);
    assert_eq!(message.content_type, ContentType::Proposal);
    assert_eq!(message.authenticated_data.as_slice(), [0xde, 0xad]);
    assert_eq!(message.partial_context_hash.as_slice(), [0xbe, 0xef]);
    assert_eq!(message.keys_for_external_receivers.len(), 1);
    assert_eq!(message.framed_content_tbs_hash.as_slice(), [0x01, 0x02]);
    assert_eq!(message.encrypted_sender_data.as_slice(), [0x03, 0x04]);
    assert_eq!(message.ciphertext.as_slice(), [0x05, 0x06]);

    // commit(3) decodes the same way.
    let commit = round_trip::<SemiPrivateMessage>(&message_wire(0x03));
    assert_eq!(commit.content_type, ContentType::Commit);
}

/// The AAD is the message's own fields without the two ciphertexts, so
/// it is built from a message rather than decoded beside it.
#[test]
fn the_content_aad_is_the_message_without_its_ciphertexts() {
    let wire = message_wire(0x02);
    let message = SemiPrivateMessage::decode(&wire).expect("decodes");
    let aad = message.content_aad();

    let encoded = aad.tls_serialize_detached().expect("encodes");
    assert_eq!(
        encoded.len(),
        aad.tls_serialized_len(),
        "tls_serialized_len disagrees with the encoding"
    );
    // The AAD is a prefix of the message: every field up to and including
    // framed_content_tbs_hash, and nothing after it.
    let upto = wire.len() - 6; // the two 3-octet ciphertext fields
    assert_eq!(
        encoded,
        wire[..upto],
        "the AAD is not the message's own leading fields"
    );
}

/// Oracle: §3.1 says the content is a Proposal or a Commit. An
/// application message has no reason to be readable by a non-member, so
/// `application(1)` is refused rather than decoded and ignored.
#[test]
fn an_application_content_type_is_refused() {
    assert!(
        SemiPrivateMessage::decode(&message_wire(0x01)).is_err(),
        "application(1) must not decode as a SemiPrivateMessage"
    );
}

/// RFC 9420 §6 defines `application(1)`, `proposal(2)` and `commit(3)`.
/// `reserved(0)` and anything above 3 are not this protocol.
#[test]
fn an_unknown_content_type_is_refused() {
    for byte in [0x00u8, 0x04, 0x7f, 0xff] {
        assert!(
            SemiPrivateMessage::decode(&message_wire(byte)).is_err(),
            "content_type {byte:#04x} must not decode"
        );
    }
}

/// Trailing bytes and every truncation are refused: a decoder that
/// accepted either would let a sender hide data where a reader does not
/// look.
#[test]
fn trailing_bytes_and_truncation_are_refused() {
    let wire = message_wire(0x02);

    let mut trailing = wire.clone();
    trailing.push(0x00);
    assert!(
        SemiPrivateMessage::decode(&trailing).is_err(),
        "a trailing octet must not decode"
    );

    for cut in 1..wire.len() {
        assert!(
            SemiPrivateMessage::decode(&wire[..cut]).is_err(),
            "a message truncated to {cut} octets must not decode"
        );
    }
}

/// Oracle: the count cap of [`MAX_EXTERNAL_RECEIVERS`]. The spec bounds
/// `keys_for_external_receivers` not at all, so without a cap one
/// message could ask a decoder for as many entries as a `<V>` vector
/// holds.
#[test]
fn more_external_receivers_than_the_cap_are_refused() {
    fn with_receivers(count: usize) -> Vec<u8> {
        let mut v = vec![
            0x03, 0x67, 0x69, 0x64, // group_id<V>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // epoch
            0x02, // content_type: proposal
            0x00, // authenticated_data<V>: empty
            0x00, // partial_context_hash<V>: empty
        ];
        let body: Vec<u8> = (0..count).flat_map(|_| KEY_FOR_RECEIVER.to_vec()).collect();
        // A two-octet <V> prefix: 0x40 | high, low.
        let len = body.len();
        assert!(len < 16_384, "the fixture stays inside a two-octet prefix");
        v.push(0x40 | u8::try_from(len >> 8).expect("six bits"));
        v.push(u8::try_from(len & 0xff).expect("one octet"));
        v.extend_from_slice(&body);
        v.extend_from_slice(&[0x00, 0x00, 0x00]); // the three trailing <V> fields, empty
        v
    }

    let at_cap = with_receivers(MAX_EXTERNAL_RECEIVERS);
    let message = SemiPrivateMessage::decode(&at_cap).expect("the cap itself decodes");
    assert_eq!(
        message.keys_for_external_receivers.len(),
        MAX_EXTERNAL_RECEIVERS
    );

    let over = with_receivers(MAX_EXTERNAL_RECEIVERS + 1);
    assert!(
        SemiPrivateMessage::decode(&over).is_err(),
        "one past the cap must be refused"
    );
}

/// An empty `keys_for_external_receivers` decodes. §3.1 requires no
/// entries, and a group whose `external_receivers` is empty has none to
/// encrypt to; whether such a message is useful is not the decoder's
/// question.
#[test]
fn no_external_receivers_decodes() {
    let wire = vec![
        0x03, 0x67, 0x69, 0x64, // group_id<V>: "gid"
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch: 1
        0x03, // content_type: commit
        0x00, // authenticated_data<V>: empty
        0x00, // partial_context_hash<V>: empty
        0x00, // keys_for_external_receivers<V>: empty
        0x00, // framed_content_tbs_hash<V>: empty
        0x00, // encrypted_sender_data<V>: empty
        0x00, // ciphertext<V>: empty
    ];
    let message = round_trip::<SemiPrivateMessage>(&wire);
    assert!(message.keys_for_external_receivers.is_empty());
}

// --- SemiPrivateMessageContent (§3.1), the decrypted plaintext ---

/// A `Remove` proposal and a proposal's `FramedContentAuthData`.
///
/// RFC 9420 §12.1: `Proposal` selects on a `uint16 proposal_type`, and
/// `remove(3)` carries `uint32 removed`. §6.1: a proposal's
/// `FramedContentAuthData` is a signature alone, with no confirmation
/// tag, which is why decoding it needs the content type.
const REMOVE_PROPOSAL_CONTENT: &[u8] = &[
    0x00, 0x03, //                   proposal_type: remove(3)
    0x00, 0x00, 0x00, 0x02, //       Remove.removed: leaf index 2
    0x02, 0xaa, 0xbb, //             FramedContentAuthData.signature<V>
];

#[test]
fn a_proposal_content_decodes_with_the_frame_s_content_type() {
    let content = SemiPrivateMessageContent::decode(REMOVE_PROPOSAL_CONTENT, ContentType::Proposal)
        .expect("the fixture decodes");
    assert!(
        matches!(content, SemiPrivateMessageContent::Proposal { .. }),
        "a proposal content_type gives the proposal arm"
    );
}

/// Oracle: RFC 9420 §6.3.2 requires a PrivateMessageContent's padding to
/// be zero, and §3.1 says this structure is the same but for the content.
/// A receiver that accepted anything there would let a sender pass bytes
/// nobody reads.
#[test]
fn padding_must_be_zero() {
    let mut zero = REMOVE_PROPOSAL_CONTENT.to_vec();
    zero.extend_from_slice(&[0x00, 0x00, 0x00]);
    assert!(
        SemiPrivateMessageContent::decode(&zero, ContentType::Proposal).is_ok(),
        "zero padding decodes"
    );

    let mut junk = REMOVE_PROPOSAL_CONTENT.to_vec();
    junk.extend_from_slice(&[0x00, 0x01, 0x00]);
    assert!(
        SemiPrivateMessageContent::decode(&junk, ContentType::Proposal).is_err(),
        "a non-zero padding octet must be refused"
    );
}

/// §3.1 defines no application arm for this structure, and the frame
/// refuses that content type anyway, so the content decoder refuses it
/// too rather than relying on the caller having checked.
#[test]
fn an_application_content_type_has_no_arm() {
    assert!(
        SemiPrivateMessageContent::decode(REMOVE_PROPOSAL_CONTENT, ContentType::Application)
            .is_err()
    );
}

/// The content type picks the arm, so the same bytes read as a proposal
/// do not read as a commit.
#[test]
fn the_content_type_picks_the_arm() {
    assert!(
        SemiPrivateMessageContent::decode(REMOVE_PROPOSAL_CONTENT, ContentType::Commit).is_err(),
        "proposal bytes must not decode as a commit"
    );
}

// --- external_receivers (§3), carried as a component ---

/// One `ExternalReceiver`: an HPKE public key and a BasicCredential.
///
/// RFC 9420 §5.1.1 makes `HPKEPublicKey` an `opaque<V>`, and §5.3 a
/// `Credential` a `uint16 credential_type` with the `basic(1)` arm
/// carrying `opaque identity<V>`.
const ONE_RECEIVER: &[u8] = &[
    0x04, 0x01, 0x02, 0x03, 0x04, // external_receiver_public_key<V>
    0x00, 0x01, //                   credential_type: basic(1)
    0x03, 0x68, 0x75, 0x62, //       identity<V>: "hub"
];

#[test]
fn an_external_receiver_round_trips() {
    let receiver = round_trip::<ExternalReceiver>(ONE_RECEIVER);
    assert_eq!(
        receiver.external_receiver_public_key.as_bytes(),
        [0x04, 0x01, 0x02, 0x03, 0x04],
        "the key keeps its own encoding, length prefix included"
    );
}

#[test]
fn the_component_list_round_trips() {
    let mut wire = vec![u8::try_from(ONE_RECEIVER.len()).expect("short")];
    wire.extend_from_slice(ONE_RECEIVER);
    let list = round_trip::<ExternalReceivers>(&wire);
    assert_eq!(list.as_slice().len(), 1);

    // A group with no external receivers: the list is empty, not absent.
    let empty = round_trip::<ExternalReceivers>(&[0x00]);
    assert!(empty.as_slice().is_empty());
}

/// Oracle: the component id. semiprivatemessage-08 §5.2 registers 0x0007
/// as a component type, which is the reading decision mimid-1wgh.4.79.4
/// takes; as an extension type 0x0007 is mls-extensions-11's
/// `supported_wire_formats`, so only the component reading leaves the
/// author's codepoint usable.
#[test]
fn the_component_id_is_the_registered_one() {
    assert_eq!(EXTERNAL_RECEIVERS_COMPONENT, 0x0007);
}

/// The listed-receivers cap, for the same reason as the per-message one:
/// the draft bounds the list not at all.
#[test]
fn more_listed_receivers_than_the_cap_are_refused() {
    fn list_of(count: usize) -> Vec<u8> {
        let body: Vec<u8> = (0..count).flat_map(|_| ONE_RECEIVER.to_vec()).collect();
        let mut v = Vec::new();
        assert!(body.len() < 16_384, "stays inside a two-octet prefix");
        v.push(0x40 | u8::try_from(body.len() >> 8).expect("six bits"));
        v.push(u8::try_from(body.len() & 0xff).expect("one octet"));
        v.extend_from_slice(&body);
        v
    }
    assert!(
        ExternalReceivers::decode(&list_of(MAX_LISTED_EXTERNAL_RECEIVERS)).is_ok(),
        "the cap itself decodes"
    );
    assert!(
        ExternalReceivers::decode(&list_of(MAX_LISTED_EXTERNAL_RECEIVERS + 1)).is_err(),
        "one past the cap is refused"
    );
}
