//! One fixture, both codecs: mimi-mls's `SemiPrivateMessage` and
//! openmls's must agree, field for field and byte for byte.
//!
//! Written before `wire::SemiPrivateMessage` becomes a wrapper over
//! openmls's (bead mimid-1wgh.4.79.11). While there are two codecs this
//! is the only thing that catches them drifting apart; once there is
//! one, it proves the wrapper did not change what the bytes mean.

#![forbid(unsafe_code)]

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::SemiPrivateMessage as MimiFrame;
use openmls::semiprivate_message::SemiPrivateMessage as OpenMlsFrame;

/// semiprivatemessage-08 §3.1, hand-encoded with one external receiver.
/// The same bytes the mimi-mls suite uses, so a change there shows up
/// here.
#[rustfmt::skip]
const FRAME: &[u8] = &[
    0x03, b'g', b'i', b'd',             // group_id<V>
    0, 0, 0, 0, 0, 0, 0, 7,             // epoch = 7
    0x02,                               // content_type: proposal(2)
    0x02, 0xde, 0xad,                   // authenticated_data<V>
    0x02, 0xbe, 0xef,                   // partial_context_hash<V>
    0x0b,                               // keys_for_external_receivers<V>: 11 bytes
      0x04, 0xaa, 0xbb, 0xcc, 0xdd,     //   external_receiver_ref<V>
      0x02, 0x11, 0x22,                 //   kem_output<V>
      0x02, 0x33, 0x44,                 //   ciphertext<V>
    0x02, 0xfe, 0xed,                   // framed_content_tbs_hash<V>
    0x01, 0x99,                         // encrypted_sender_data<V>
    0x03, 0x01, 0x02, 0x03,             // ciphertext<V>
];

#[test]
fn both_codecs_read_the_same_fields() {
    let mimi = MimiFrame::decode(FRAME).expect("mimi-mls decodes");
    let openmls = OpenMlsFrame::tls_deserialize_exact(FRAME).expect("openmls decodes");

    assert_eq!(
        mimi.group_id.as_slice(),
        openmls.group_id().as_slice(),
        "group_id"
    );
    assert_eq!(mimi.epoch, openmls.epoch().as_u64(), "epoch");
    assert_eq!(
        mimi.authenticated_data.as_slice(),
        openmls.authenticated_data(),
        "authenticated_data"
    );
    assert_eq!(
        mimi.partial_context_hash.as_slice(),
        openmls.partial_context_hash(),
        "partial_context_hash"
    );
    assert_eq!(
        mimi.framed_content_tbs_hash.as_slice(),
        openmls.framed_content_tbs_hash(),
        "framed_content_tbs_hash"
    );
    assert_eq!(
        mimi.encrypted_sender_data.as_slice(),
        openmls.encrypted_sender_data(),
        "encrypted_sender_data"
    );
    assert_eq!(
        mimi.ciphertext.as_slice(),
        openmls.ciphertext(),
        "ciphertext"
    );
    assert_eq!(
        mimi.keys_for_external_receivers.len(),
        openmls.keys_for_external_receivers().len(),
        "one entry each"
    );
    assert_eq!(
        mimi.keys_for_external_receivers[0]
            .external_receiver_ref
            .as_slice(),
        openmls.keys_for_external_receivers()[0]
            .external_receiver_ref
            .as_slice(),
        "the receiver reference"
    );
}

#[test]
fn both_codecs_re_encode_the_received_bytes() {
    let mimi = MimiFrame::decode(FRAME).expect("mimi-mls decodes");
    let openmls = OpenMlsFrame::tls_deserialize_exact(FRAME).expect("openmls decodes");
    assert_eq!(
        mimi.tls_serialize_detached().expect("mimi-mls encodes"),
        FRAME,
        "mimi-mls round trip"
    );
    assert_eq!(
        openmls.tls_serialize_detached().expect("openmls encodes"),
        FRAME,
        "openmls round trip"
    );
}

/// They differ deliberately on one input, and this records which way.
///
/// mimi-mls refuses `content_type: application` while decoding, because
/// §3.1 defines no application arm for `SemiPrivateMessageContent`.
/// openmls accepts it in the codec and refuses it in `validate`, so that
/// its codec carries no draft semantics. A caller of openmls's type must
/// therefore call `validate`; a caller of mimi-mls's need not.
#[test]
fn they_differ_only_on_an_application_content_type() {
    let mut wire = FRAME.to_vec();
    wire[12] = 0x01; // content_type: application

    assert!(
        MimiFrame::decode(&wire).is_err(),
        "mimi-mls refuses it at decode"
    );
    let openmls = OpenMlsFrame::tls_deserialize_exact(&wire).expect("openmls's codec allows it");
    assert!(
        openmls.validate().is_err(),
        "and openmls refuses it in validate"
    );
}
