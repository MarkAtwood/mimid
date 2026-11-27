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

use mimi_mls::label::HpkePrivateKey;
use mimi_mls::tls_codec::{Deserialize, Serialize, Size, VLBytes};
use mimi_mls::wire::{
    ContentType, KeyForExternalReceiver, MAX_EXTERNAL_RECEIVERS, SemiPrivateMessage,
    SemiPrivateMessageContent, UnsealError,
};
use mimi_mls::wire::{
    EXTERNAL_RECEIVERS_COMPONENT, ExternalReceiver, ExternalReceivers,
    MAX_LISTED_EXTERNAL_RECEIVERS, PerMessageKeyAndNonces, RECEIVER_LABEL,
    SemiPrivateMessageContext,
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

// --- the external receiver's unseal (§3.1, §3.3) ---

/// A sender seals `PerMessageKeyAndNonces` to the receiver's key under
/// the `SemiPrivateMessageReceiver` label and the message's context; the
/// receiver gets the same bytes back.
///
/// This is real HPKE, not a fixture: the only way to show the context is
/// built the same way on both sides is to seal with one and open with
/// the other.
#[test]
fn an_external_receiver_unseals_the_per_message_keys() {
    let (private, public) = HpkePrivateKey::generate().expect("a key pair");

    let keys = PerMessageKeyAndNonces {
        key: vec![0x11; 32].into(),
        nonce: vec![0x22; 12].into(),
        reuse_guard: [0xaa, 0xbb, 0xcc, 0xdd],
        sender_leaf_index: 3,
    };
    let context = SemiPrivateMessageContext {
        group_id: b"gid".to_vec().into(),
        epoch: 7,
        partial_context_hash: keys.partial_context_hash().expect("hashes").into(),
    };

    let sealed = mimi_mls::label::encrypt_with_label(
        &public,
        RECEIVER_LABEL,
        &context.tls_serialize_detached().expect("context encodes"),
        &keys.tls_serialize_detached().expect("keys encode"),
    )
    .expect("seals");

    let opened = private
        .decrypt_with_label(
            RECEIVER_LABEL,
            &context.tls_serialize_detached().expect("context encodes"),
            &sealed.kem_output,
            &sealed.ciphertext,
        )
        .expect("opens");
    let recovered =
        PerMessageKeyAndNonces::tls_deserialize_exact(&opened).expect("the payload decodes");
    assert_eq!(recovered, keys, "the receiver recovers what was sealed");
}

/// Oracle: the label and the context both bind the ciphertext. A
/// receiver using either the wrong label or a context from a different
/// epoch must fail, or the seal would not be tied to this message.
#[test]
fn the_label_and_the_context_both_bind() {
    let (private, public) = HpkePrivateKey::generate().expect("a key pair");
    let keys = PerMessageKeyAndNonces {
        key: vec![0x11; 32].into(),
        nonce: vec![0x22; 12].into(),
        reuse_guard: [0; 4],
        sender_leaf_index: 1,
    };
    let context = SemiPrivateMessageContext {
        group_id: b"gid".to_vec().into(),
        epoch: 7,
        partial_context_hash: keys.partial_context_hash().expect("hashes").into(),
    };
    let encoded = context.tls_serialize_detached().expect("encodes");
    let sealed = mimi_mls::label::encrypt_with_label(
        &public,
        RECEIVER_LABEL,
        &encoded,
        &keys.tls_serialize_detached().expect("encodes"),
    )
    .expect("seals");

    assert!(
        private
            .decrypt_with_label(
                "SomeOtherLabel",
                &encoded,
                &sealed.kem_output,
                &sealed.ciphertext
            )
            .is_err(),
        "a different label must not open it"
    );

    let other_epoch = SemiPrivateMessageContext {
        epoch: 8,
        ..context
    };
    assert!(
        private
            .decrypt_with_label(
                RECEIVER_LABEL,
                &other_epoch.tls_serialize_detached().expect("encodes"),
                &sealed.kem_output,
                &sealed.ciphertext,
            )
            .is_err(),
        "a context from another epoch must not open it"
    );
}

/// The `reuse_guard` is XORed into the nonce's first four octets and the
/// rest is untouched, as RFC 9420 §6.3.2 does for a PrivateMessage.
#[test]
fn the_reuse_guard_covers_four_octets() {
    let keys = PerMessageKeyAndNonces {
        key: vec![0; 32].into(),
        nonce: vec![0xff; 12].into(),
        reuse_guard: [0x0f, 0xf0, 0x00, 0xff],
        sender_leaf_index: 0,
    };
    let guarded = keys.guarded_nonce();
    assert_eq!(
        &guarded[..4],
        &[0xf0, 0x0f, 0xff, 0x00],
        "the first four are XORed"
    );
    assert_eq!(&guarded[4..], &[0xff; 8], "the rest is unchanged");
}

/// Oracle: decision mimid-1wgh.4.79.6. The hash is over the TLS
/// encodings, so the nonce's length is part of the input and a different
/// split of the same bytes gives a different hash. Were the raw form
/// used, these two would collide.
#[test]
fn the_context_hash_includes_the_nonce_length() {
    let a = PerMessageKeyAndNonces {
        key: vec![0; 32].into(),
        nonce: vec![0x01, 0x02].into(),
        reuse_guard: [0; 4],
        sender_leaf_index: 0,
    };
    let b = PerMessageKeyAndNonces {
        nonce: vec![0x01, 0x02, 0x03].into(),
        ..a.clone()
    };
    assert_ne!(
        a.partial_context_hash().expect("hashes"),
        b.partial_context_hash().expect("hashes"),
        "a longer nonce must hash differently"
    );
}

/// A message's entry is found by the receiver's own reference, and a
/// receiver not named in it gets nothing.
#[test]
fn a_receiver_finds_only_its_own_entry() {
    let wire = message_wire(0x02);
    let message = SemiPrivateMessage::decode(&wire).expect("decodes");
    assert!(
        message.key_for(&[0xaa, 0xbb, 0xcc, 0xdd]).is_some(),
        "the named receiver finds its entry"
    );
    assert!(
        message.key_for(&[0x00, 0x00, 0x00, 0x00]).is_none(),
        "a receiver not named gets nothing"
    );
    assert_eq!(
        message.context().partial_context_hash.as_slice(),
        [0xbe, 0xef],
        "the context takes the hash from the frame"
    );
}

// --- framed_content_tbs_hash (§3.1, §3.3) ---

/// The FramedContentTBS an external receiver rebuilds, field by field
/// (RFC 9420 §6.1), with the semiprivate wire format of decision
/// mimid-1wgh.4.79.9.
#[test]
fn the_framed_content_tbs_is_rebuilt_field_by_field() {
    let message = SemiPrivateMessage::decode(&message_wire(0x02)).expect("decodes");
    let tbs = message
        .framed_content_tbs(&[0xde, 0xad], 7, &[0xc0, 0xde])
        .expect("builds");

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        0x00, 0x01,             // ProtocolVersion mls10
        0x00, 0x11,             // WireFormat mls_semiprivate_message
        0x03, b'g', b'i', b'd', // FramedContent group_id<V> = "gid"
        0, 0, 0, 0, 0, 0, 0, 7, // epoch = 7
        0x01,                   // Sender.sender_type = member
        0x00, 0x00, 0x00, 0x07, // leaf_index = 7
        0x02, 0xde, 0xad,       // authenticated_data<V>, the frame's own
        0x02,                   // ContentType proposal
        0xde, 0xad,             // the content span, verbatim
        0xc0, 0xde,             // the GroupContext
    ];
    assert_eq!(tbs, expected);
}

/// Oracle: the hash is what stops a sender encrypting one thing to the
/// members and another to the external receivers. Content that does not
/// hash to the frame's committed value is refused.
#[test]
fn content_that_does_not_match_the_hash_is_refused() {
    let message = SemiPrivateMessage::decode(&message_wire(0x02)).expect("decodes");
    // The fixture's framed_content_tbs_hash is 0xfeed, which is not the
    // hash of anything, so every input mismatches.
    let err = message
        .check_framed_content_tbs(&[0xde, 0xad], 7, &[0xc0, 0xde])
        .expect_err("must not match");
    assert!(
        matches!(err, mimi_mls::wire::UnsealError::ContentHashMismatch),
        "{err:?}"
    );
}

/// Each input to the hash changes it: the content, the sender's leaf and
/// the GroupContext. A hash that ignored any of them would let that part
/// be swapped after the fact.
#[test]
fn every_input_changes_the_hash() {
    let message = SemiPrivateMessage::decode(&message_wire(0x02)).expect("decodes");
    let base = message
        .framed_content_tbs(&[0xde, 0xad], 7, &[0xc0, 0xde])
        .expect("builds");
    for (label, other) in [
        (
            "content",
            message.framed_content_tbs(&[0xde, 0xae], 7, &[0xc0, 0xde]),
        ),
        (
            "sender leaf",
            message.framed_content_tbs(&[0xde, 0xad], 8, &[0xc0, 0xde]),
        ),
        (
            "group context",
            message.framed_content_tbs(&[0xde, 0xad], 7, &[0xc0, 0xdf]),
        ),
    ] {
        assert_ne!(base, other.expect("builds"), "{label} must change the TBS");
    }
}

/// `decode_parts` hands back the content's bytes as they arrived, not a
/// re-encoding: the hash covers the received span.
#[test]
fn decode_parts_returns_the_received_content_span() {
    let (_, spans) =
        SemiPrivateMessageContent::decode_parts(REMOVE_PROPOSAL_CONTENT, ContentType::Proposal)
            .expect("decodes");
    let content = spans.content;
    // The fixture is a Remove proposal, then the auth data, then zero
    // padding. The span stops at the proposal's last byte.
    assert_eq!(
        content,
        &REMOVE_PROPOSAL_CONTENT[..content.len()],
        "the span is a prefix of the received bytes"
    );
    assert!(
        content.len() < REMOVE_PROPOSAL_CONTENT.len(),
        "the auth data and padding are excluded"
    );
}

/// The signature span is the signature's own bytes, without the `<V>`
/// length prefix: it is handed straight to the verifier.
#[test]
fn the_signature_span_excludes_its_length_prefix() {
    let (_, spans) =
        SemiPrivateMessageContent::decode_parts(REMOVE_PROPOSAL_CONTENT, ContentType::Proposal)
            .expect("decodes");
    // The auth data follows the content, and starts with signature<V>.
    let auth = &REMOVE_PROPOSAL_CONTENT[spans.content.len()..];
    let length = usize::from(auth[0]);
    assert_eq!(
        spans.signature.len(),
        length,
        "the span is exactly the declared length"
    );
    assert_eq!(
        spans.signature,
        &auth[1..=length],
        "and starts after the prefix"
    );
}

// --- the whole external-receiver path (§3.3) ---

/// Builds a SemiPrivateMessage the way a sender would and reads it back
/// as the external receiver, with real HPKE, real AEAD, real Ed25519 and
/// the real hashes.
///
/// Nothing in mimid builds a SemiPrivateMessage yet -- that is the
/// sender side, bead mimid-1wgh.4.79.3 -- so this test stands in for the
/// sender. It is the only check that the AEAD, the two hashes and the
/// signature all agree on their inputs: each piece has its own test, but
/// a disagreement between them would pass every one of those.
#[test]
fn a_semiprivate_message_built_as_a_sender_reads_back() {
    use mimi_mls::label;
    use mimi_mls::wire::SemiPrivateContentAAD;

    let (receiver_private, receiver_public) = HpkePrivateKey::generate().expect("a key pair");
    let sender = label::SignatureKeyPair::generate().expect("a signing pair");

    // The receiver's entry, and the reference a sender names it by.
    // The receiver's entry is built from its wire form: its two fields
    // are opaque wire types with private contents.
    let mut entry_wire = VLBytes::new(receiver_public.clone())
        .tls_serialize_detached()
        .unwrap();
    entry_wire.extend([0x00, 0x01]); // credential_type: basic
    entry_wire.extend(
        VLBytes::new(b"hub".to_vec())
            .tls_serialize_detached()
            .unwrap(),
    );
    let entry = ExternalReceiver::tls_deserialize_exact(&entry_wire).expect("an ExternalReceiver");
    let reference = entry.reference().expect("hashes");

    // The handshake: the Remove proposal fixture, which is a real
    // encoded Proposal, and a signature over its FramedContentTBS.
    let group_id = b"gid".to_vec();
    let epoch = 7u64;
    let authenticated_data = vec![0xde, 0xad];
    let sender_leaf_index = 3u32;
    let group_context = b"a group context".to_vec();
    // The Remove proposal alone, without the auth data the fixture
    // appends: FramedContent's content field is the proposal.
    let proposal: &[u8] = &[
        0x00, 0x03, //             proposal_type: remove(3)
        0x00, 0x00, 0x00, 0x02, // Remove.removed: leaf index 2
    ];

    let keys = PerMessageKeyAndNonces {
        // Ciphersuite 1 is AES-128-GCM: a 16-byte key, a 12-byte nonce.
        key: vec![0x11; 16].into(),
        nonce: vec![0x22; 12].into(),
        reuse_guard: [0xaa, 0xbb, 0xcc, 0xdd],
        sender_leaf_index,
    };
    let partial_context_hash = keys.partial_context_hash().expect("hashes");

    // FramedContentTBS, as both sides build it.
    let mut tbs = vec![0x00, 0x01, 0x00, 0x11];
    tbs.extend(
        VLBytes::new(group_id.clone())
            .tls_serialize_detached()
            .unwrap(),
    );
    tbs.extend(epoch.tls_serialize_detached().unwrap());
    tbs.push(0x01);
    tbs.extend(sender_leaf_index.tls_serialize_detached().unwrap());
    tbs.extend(
        VLBytes::new(authenticated_data.clone())
            .tls_serialize_detached()
            .unwrap(),
    );
    tbs.push(0x02); // ContentType proposal
    tbs.extend(proposal);
    tbs.extend(&group_context);
    let framed_content_tbs_hash = label::hash(&tbs).expect("hashes");

    let signature = sender
        .sign_with_label("FramedContentTBS", &tbs)
        .expect("signs");

    // SemiPrivateMessageContent: the proposal, its auth data, padding.
    let mut content = proposal.to_vec();
    content.extend(VLBytes::new(signature).tls_serialize_detached().unwrap());
    content.extend([0u8; 4]); // zero padding

    // The sealed keys, then the AAD, then the ciphertext.
    let context = SemiPrivateMessageContext {
        group_id: group_id.clone().into(),
        epoch,
        partial_context_hash: partial_context_hash.clone().into(),
    };
    let sealed = label::encrypt_with_label(
        &receiver_public,
        RECEIVER_LABEL,
        &context.tls_serialize_detached().unwrap(),
        &keys.tls_serialize_detached().unwrap(),
    )
    .expect("seals");
    let mut hpke_ciphertext = VLBytes::new(sealed.kem_output.clone())
        .tls_serialize_detached()
        .unwrap();
    hpke_ciphertext.extend(
        VLBytes::new(sealed.ciphertext.clone())
            .tls_serialize_detached()
            .unwrap(),
    );
    // Built from bytes: ExternalReceiverRef wraps a private VLBytes.
    let mut key_entry_wire = VLBytes::new(reference.clone())
        .tls_serialize_detached()
        .unwrap();
    key_entry_wire.extend(&hpke_ciphertext);
    let key_entry =
        KeyForExternalReceiver::tls_deserialize_exact(&key_entry_wire).expect("an entry");

    let aad = SemiPrivateContentAAD {
        group_id: group_id.clone().into(),
        epoch,
        content_type: ContentType::Proposal,
        authenticated_data: authenticated_data.clone().into(),
        partial_context_hash: partial_context_hash.clone().into(),
        keys_for_external_receivers: vec![key_entry.clone()],
        framed_content_tbs_hash: framed_content_tbs_hash.clone().into(),
    }
    .tls_serialize_detached()
    .expect("encodes");
    let ciphertext = label::aead_seal(keys.key.as_slice(), &keys.guarded_nonce(), &aad, &content)
        .expect("seals the content");

    let message = SemiPrivateMessage {
        group_id: group_id.clone().into(),
        epoch,
        content_type: ContentType::Proposal,
        authenticated_data: authenticated_data.into(),
        partial_context_hash: partial_context_hash.into(),
        keys_for_external_receivers: vec![key_entry],
        framed_content_tbs_hash: framed_content_tbs_hash.into(),
        encrypted_sender_data: vec![0x00; 8].into(),
        ciphertext: ciphertext.into(),
    };

    // The frame survives a round trip through the wire, as a hub would
    // receive it.
    let wire = message.tls_serialize_detached().expect("encodes");
    let received = SemiPrivateMessage::decode(&wire).expect("decodes");
    assert_eq!(received, message);

    let opened = received
        .open_as_external_receiver(
            &reference,
            &receiver_private,
            &group_context,
            sender.verification_key(),
        )
        .expect("the external receiver reads the handshake");
    assert_eq!(opened.sender_leaf_index, sender_leaf_index);
    assert!(
        matches!(opened.content, SemiPrivateMessageContent::Proposal { .. }),
        "a Remove proposal came back"
    );

    // Oracle: the signature is checked against the leaf the caller
    // supplies, so another key must not verify.
    let other = label::SignatureKeyPair::generate().expect("a pair");
    let err = received
        .open_as_external_receiver(
            &reference,
            &receiver_private,
            &group_context,
            other.verification_key(),
        )
        .expect_err("a different signer must be refused");
    assert!(matches!(err, UnsealError::Signature), "{err:?}");

    // Oracle: the GroupContext is hashed in, so a receiver with the
    // wrong one refuses rather than accepting.
    let err = received
        .open_as_external_receiver(
            &reference,
            &receiver_private,
            b"another group context",
            sender.verification_key(),
        )
        .expect_err("a wrong GroupContext must be refused");
    assert!(matches!(err, UnsealError::ContentHashMismatch), "{err:?}");
}
