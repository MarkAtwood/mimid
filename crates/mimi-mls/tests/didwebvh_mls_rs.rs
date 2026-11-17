//! The `did_webvh` credential on the wire, checked by an independent MLS
//! implementation: mls-rs (decision mimid-1wgh.4.13) decodes a mimi-mls
//! KeyPackage carrying one, re-encodes it byte for byte, and sees a custom
//! credential of type 0x0008 whose data is the draft's DIDWebVHCredential.
//! This is the encoding of decision mimid-1wgh.4.81.8: the structure
//! inside one `opaque<V>`, the only shape mls-rs (and OpenMLS) can carry.

use mimi_mls::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimi_mls::mls_didwebvh::{CodePoints, DidWebvhCredential};
use mimi_mls::{Identity, KeyPackageKind, Store};
use mls_rs::MlsMessage;
use mls_rs::identity::Credential;

#[test]
fn mls_rs_reads_the_did_webvh_credential() {
    let mut identity =
        Identity::generate(b"unset", Store::open_in_memory().expect("store")).expect("identity");
    let update = UpdateKey::from_seed(&[3; 32]);
    let log = DidLog::create(
        "example.com",
        "alice",
        "2026-11-20T11:00:00Z",
        &Parameters {
            update_keys: Some(vec![update.multikey()]),
            next_key_hashes: None,
        },
        &update,
        &[identity.signature_public_key().try_into().expect("key")],
    )
    .expect("log");
    let credential = log.credential().expect("credential");
    identity
        .set_did_webvh_credential(CodePoints::SUGGESTED, credential.clone())
        .expect("set");
    let key_package = identity
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");

    // RFC 9420 §6: an MLSMessage wrapping the KeyPackage.
    let mut wrapped = vec![0x00, 0x01, 0x00, 0x05];
    wrapped.extend_from_slice(&key_package);
    let message = MlsMessage::from_bytes(&wrapped).expect("mls-rs decodes");
    assert_eq!(message.to_bytes().expect("re-encode"), wrapped);
    let parsed = message.into_key_package().expect("a KeyPackage");
    let Credential::Custom(custom) = &parsed.signing_identity().credential else {
        panic!(
            "not a custom credential: {:?}",
            parsed.signing_identity().credential
        );
    };
    assert_eq!(custom.credential_type.raw_value(), 0x0008);
    let inner = DidWebvhCredential::decode(&custom.data).expect("DIDWebVHCredential");
    assert_eq!(inner, credential);
    assert_eq!(inner.did_log(), log.did_log().as_slice());
    assert!(inner.witness_file().is_empty());
}
