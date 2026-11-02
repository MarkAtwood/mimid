//! mimid -> Haven protocol-06 cross-check (bead mimid-1wgh.46.1.2).
//!
//! Usage: cargo run -- <vectors dir> <mlswg fixture dir>
//!
//! Each vector was encoded by mimid (mimid-dump/zz_dump_for_haven.rs).
//! For each: Haven decodes it, the decoded value is compared with the
//! value written here from the dump's inputs, and Haven re-encodes it;
//! the re-encoding must equal mimid's bytes.

use std::{env, fs, path::Path};

use mimi_core::consent::{ConsentEntry, ConsentOperation};
use mimi_core::protocol_wire::{
    decode_consent_entry, encode_consent_entry, AbuseReport, FanoutMessage, HandshakeBundle,
    IdentifierQueryCode, IdentifierRequest, IdentifierResponse, IdentifierUri,
    KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode, QueryElement,
    SearchIdentifierType, SubmitMessageRequest, SubmitMessageResponse, UpdateRoomResponse,
    PROTOCOL_MLS10,
};
use openmls::prelude::{Ciphersuite, RequiredCapabilitiesExtension};

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const ROOM: &str = "mimi://a.example/r/room1";
const TIMESTAMP: u64 = 1_700_000_000_000;
const EPOCH: u64 = 42;
const PUB: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4, 0xe6,
    0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77, 0x87, 0x37,
];
const PRIVATE_APPLICATION: &[u8] = &[
    0x00, 0x01, 0x00, 0x02, 0x04, b'r', b'o', b'o', b'm', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x07, 0x01, 0x00, 0x03, 0xa1, 0xa2, 0xa3, 0x05, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
];

fn uri(s: &str) -> IdentifierUri {
    IdentifierUri(s.to_owned())
}

/// Outcome of one vector.
struct Outcome {
    decode: Result<(), String>,
    fields: Option<Result<(), String>>,
    reencode: Option<Result<(), String>>,
}

fn same<T: PartialEq + std::fmt::Debug>(got: &T, want: &T) -> Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("got {got:?}\n      want {want:?}"))
    }
}

fn bytes_eq(got: &[u8], want: &[u8]) -> Result<(), String> {
    if got == want {
        return Ok(());
    }
    let at = got.iter().zip(want).position(|(a, b)| a != b).unwrap_or(got.len().min(want.len()));
    Err(format!(
        "Haven {} bytes vs mimid {} bytes, first difference at offset {at}: Haven {:02x?} mimid {:02x?}",
        got.len(),
        want.len(),
        &got[at..(at + 8).min(got.len())],
        &want[at..(at + 8).min(want.len())],
    ))
}

fn run<T>(
    wire: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, String>,
    fields: impl Fn(&T) -> Result<(), String>,
    encode: impl Fn(&T) -> Result<Vec<u8>, String>,
) -> Outcome {
    match decode(wire) {
        Err(e) => Outcome {
            decode: Err(e),
            fields: None,
            reencode: None,
        },
        Ok(value) => Outcome {
            decode: Ok(()),
            fields: Some(fields(&value)),
            reencode: Some(encode(&value).and_then(|b| bytes_eq(&b, wire))),
        },
    }
}

fn e<E: std::fmt::Debug>(x: E) -> String {
    format!("{x:?}")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args[1] == "make-kp-default" {
        // B4 (bead mimid-1wgh.46.1.6): a KeyPackage from openmls 0.8.1's
        // default builder (default 84-day lifetime, no KeyPackage
        // extensions), unlike test_helpers::key_package's unbounded lifetime.
        fs::write(Path::new(&args[2]).join("haven_default_key_package.bin"), default_kp(BOB.as_bytes()))
            .unwrap();
        println!("wrote haven_default_key_package.bin");
        return;
    }
    if args[1] == "decode-commit" {
        // B4: run Haven's update-lane decoder on a Commit file.
        let bytes = fs::read(&args[2]).unwrap();
        match mimi_core::commit_wire::decode_single_custom_proposal_commit(&bytes) {
            Ok(d) => println!("decode_single_custom_proposal_commit: Ok({d:?})"),
            Err(e) => println!("decode_single_custom_proposal_commit: Err({e})"),
        }
        return;
    }
    if args[1] == "make-kp" {
        // Phase 1: a KeyPackage from Haven's own openmls 0.8 stack (no
        // KeyPackage extensions, so openmls 0.8.1's GREASE bug cannot bite),
        // for mimid's dump to wrap in its messages.
        let kp = mimi_core::test_helpers::key_package(BOB.as_bytes(), 1);
        fs::write(Path::new(&args[2]).join("haven_key_package.bin"), kp).unwrap();
        println!("wrote haven_key_package.bin");
        return;
    }
    let vectors = Path::new(&args[1]);
    let mlswg = Path::new(&args[2]);
    let read = |name: &str| fs::read(vectors.join(format!("{name}.bin"))).unwrap();
    let mls = |name: &str| fs::read(mlswg.join(format!("messages-000-{name}.bin"))).unwrap();
    // Fresh mimid KeyPackage written by the dump (the mlswg one has expired).
    let key_package = read("fresh_key_package");
    let commit = mls("public_message_commit");
    let proposal = mls("public_message_proposal");
    let welcome_msg = mls("mls_welcome");

    let mut results: Vec<(&str, Outcome)> = Vec::new();

    results.push((
        "submit_message_request",
        run(
            &read("submit_message_request"),
            |b| SubmitMessageRequest::decode(b).map_err(e),
            |v| {
                same(&v.protocol, &PROTOCOL_MLS10)?;
                same(&v.app_message.as_slice(), &PRIVATE_APPLICATION)?;
                same(&v.sending_uri, &uri(ALICE))
            },
            |v| v.encode().map_err(e),
        ),
    ));
    for (name, want) in [
        (
            "submit_message_response_accepted",
            SubmitMessageResponse::Accepted {
                accepted_timestamp: TIMESTAMP,
            },
        ),
        (
            "submit_message_response_not_allowed",
            SubmitMessageResponse::NotAllowed,
        ),
        (
            "submit_message_response_epoch_too_old",
            SubmitMessageResponse::EpochTooOld {
                current_epoch: EPOCH,
            },
        ),
    ] {
        results.push((
            name,
            run(
                &read(name),
                |b| SubmitMessageResponse::decode(b).map_err(e),
                |v| same(v, &want),
                |v| Ok(v.encode()),
            ),
        ));
    }

    let consent = |operation, room: Option<&str>, kps: Vec<Vec<u8>>, ext: Vec<(u16, Vec<u8>)>| {
        ConsentEntry {
            operation,
            requester_uri: ALICE.into(),
            target_uri: BOB.into(),
            room_uri: room.map(Into::into),
            client_key_packages: kps,
            consent_extensions: ext,
        }
    };
    for (name, want) in [
        (
            "consent_request",
            consent(ConsentOperation::Request, Some(ROOM), vec![], vec![]),
        ),
        (
            "consent_grant",
            consent(
                ConsentOperation::Grant,
                None,
                vec![key_package.clone()],
                vec![(0x8001, b"ext".to_vec())],
            ),
        ),
        (
            "consent_cancel",
            consent(ConsentOperation::Cancel, Some(ROOM), vec![], vec![]),
        ),
        (
            "consent_revoke",
            consent(ConsentOperation::Revoke, None, vec![], vec![]),
        ),
    ] {
        results.push((
            name,
            run(
                &read(name),
                |b| decode_consent_entry(b).map_err(e),
                |v| same(v, &want),
                |v| encode_consent_entry(v).map_err(e),
            ),
        ));
    }

    let kmr = read("key_material_request");
    let signature_tail = kmr[kmr.len() - 64..].to_vec();
    results.push((
        "key_material_request",
        run(
            &kmr,
            |b| KeyMaterialRequest::decode(b).map_err(e),
            |v| {
                same(&v.protocol, &PROTOCOL_MLS10)?;
                same(&v.requesting_user, &uri(ALICE))?;
                same(&v.target_user, &uri(BOB))?;
                same(&v.room_id, &uri(ROOM))?;
                same(
                    &v.acceptable_ciphersuites,
                    &vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
                )?;
                same(
                    &v.required_capabilities,
                    &RequiredCapabilitiesExtension::default(),
                )?;
                same(&v.requester_signature_key.as_slice(), &PUB.as_slice())?;
                same(&v.requester_credential_identity(), &ALICE.as_bytes())?;
                same(&v.key_material_request_signature, &signature_tail)
            },
            |v| v.encode().map_err(e),
        ),
    ));

    for (name, want) in [
        (
            "key_material_response_success",
            Some(KeyMaterialResponse::Success {
                user_uri: uri(BOB),
                key_package: key_package.clone(),
            }),
        ),
        (
            "key_material_response_no_consent",
            Some(KeyMaterialResponse::Denied {
                user_uri: uri(BOB),
                code: KeyMaterialUserCode::NoConsent,
            }),
        ),
        // partialSuccess with two clients (bob-phone success, bob-laptop
        // keyMaterialExhausted). Haven's KeyMaterialResponse has no
        // variant for it; any decode result is reported as is.
        ("key_material_response_partial_success", None),
    ] {
        results.push((
            name,
            run(
                &read(name),
                |b| KeyMaterialResponse::decode(b).map_err(e),
                |v| match &want {
                    Some(w) => same(v, w),
                    None => Err(format!("no Haven value can represent it; decoded as {v:?}")),
                },
                |v| v.encode().map_err(e),
            ),
        ));
    }

    results.push((
        "handshake_bundle_proposal",
        run(
            &read("handshake_bundle_proposal"),
            |b| HandshakeBundle::decode(b).map_err(e),
            |v| {
                same(
                    v,
                    &HandshakeBundle::Proposal {
                        proposal_or_commit: proposal.clone(),
                        more_proposals: vec![],
                    },
                )
            },
            |v| v.encode().map_err(e),
        ),
    ));
    // protocol-06 §5.3: GroupInfo carried bare; Haven expects opaque<V>
    // (known divergence mimid-1wgh.46.1.8).
    results.push((
        "handshake_bundle_commit",
        run(
            &read("handshake_bundle_commit"),
            |b| HandshakeBundle::decode(b).map_err(e),
            |v| Err(format!("decoded unexpectedly: {v:?}")),
            |v| v.encode().map_err(e),
        ),
    ));

    for (name, want) in [
        (
            "update_room_response_success",
            UpdateRoomResponse::Success {
                error_description: String::new(),
                accepted_timestamp: TIMESTAMP,
            },
        ),
        (
            "update_room_response_wrong_epoch",
            UpdateRoomResponse::WrongEpoch {
                error_description: "stale".into(),
                current_epoch: EPOCH,
            },
        ),
        (
            "update_room_response_not_allowed",
            UpdateRoomResponse::NotAllowed {
                error_description: "no".into(),
            },
        ),
        (
            "update_room_response_invalid_proposal",
            UpdateRoomResponse::InvalidProposal {
                error_description: "bad".into(),
                invalid_proposals: vec![vec![0xa5; 32], vec![0x5a; 32]],
            },
        ),
    ] {
        results.push((
            name,
            run(
                &read(name),
                |b| UpdateRoomResponse::decode(b).map_err(e),
                |v| same(v, &want),
                |v| v.encode().map_err(e),
            ),
        ));
    }

    // protocol-06 §5.5 L1934-1949: message, then the wire_format tail.
    for (name, tail) in [
        (
            "fanout_message_application",
            [PRIVATE_APPLICATION, &[0x00]].concat(), // optional Frank: absent
        ),
        ("fanout_message_commit", [&commit[..], &[0x00]].concat()), // externalProposals<V>: empty
        ("fanout_message_proposal", [&proposal[..], &[0x00]].concat()), // moreProposals<V>: empty
        ("fanout_message_welcome", [&welcome_msg[..], &[0x03]].concat()), // outOfBand(3)
    ] {
        results.push((
            name,
            run(
                &read(name),
                |b| FanoutMessage::decode(b).map_err(e),
                |v| {
                    same(
                        v,
                        &FanoutMessage {
                            protocol: PROTOCOL_MLS10,
                            timestamp: TIMESTAMP,
                            message_and_tail: tail.clone(),
                        },
                    )
                },
                |v| v.encode().map_err(e),
            ),
        ));
    }

    results.push((
        "identifier_request",
        run(
            &read("identifier_request"),
            |b| IdentifierRequest::decode(b).map_err(e),
            |v| {
                same(
                    v,
                    &IdentifierRequest {
                        query_elements: vec![
                            QueryElement {
                                search_type: SearchIdentifierType::Handle,
                                qualifier: vec![],
                                search_value: b"alice".to_vec(),
                            },
                            QueryElement {
                                search_type: SearchIdentifierType::VcardField,
                                qualifier: b"EMAIL".to_vec(),
                                search_value: b"alice@a.example".to_vec(),
                            },
                        ],
                    },
                )
            },
            |v| v.encode().map_err(e),
        ),
    ));
    results.push((
        "identifier_response_success",
        run(
            &read("identifier_response_success"),
            |b| IdentifierResponse::decode(b).map_err(e),
            |v| {
                same(
                    v,
                    &IdentifierResponse {
                        response_code: IdentifierQueryCode::Success,
                        uris: vec![uri(BOB)],
                    },
                )
            },
            |v| v.encode().map_err(e),
        ),
    ));
    results.push((
        "abuse_report",
        run(
            &read("abuse_report"),
            |b| AbuseReport::decode(b).map_err(e),
            |v| {
                same(
                    v,
                    &AbuseReport {
                        reporting_user: uri(ALICE),
                        alleged_abuser_uri: uri(BOB),
                        reason_code: 1,
                        note: "spam".into(),
                    },
                )
            },
            |v| v.encode().map_err(e),
        ),
    ));

    // Diagnostic, not a pass/fail vector: rewrite mimid's spec-shaped
    // commit bundle into Haven's expected shape (Welcome wrapped in an
    // MLSMessage header, GroupInfo with a 2-byte length) to see whether
    // those are the only differences. Offsets from the mlswg inputs:
    // 428-byte Commit, presence byte, 416-byte Welcome, representation byte,
    // 420-byte GroupInfo, 1-byte RatchetTreeOption.
    {
        let wire = read("handshake_bundle_commit");
        let (c, w, r, g) = (428, 416, 1, 420);
        assert_eq!(wire.len(), c + 1 + w + r + g + 1);
        let welcome = &wire[c + 1..c + 1 + w];
        let gi_at = c + 1 + w + r;
        let group_info = &wire[gi_at..gi_at + g];
        let mut haven_shape = wire[..c + 1].to_vec();
        haven_shape.extend([0x00, 0x01, 0x00, 0x03]); // MLSMessage: mls10, mls_welcome
        haven_shape.extend(welcome);
        haven_shape.push(wire[c + 1 + w]); // representation
        haven_shape.extend([0x40 | (g >> 8) as u8, g as u8]); // opaque<V> length
        haven_shape.extend(group_info);
        haven_shape.extend(&wire[gi_at + g..]);
        match HandshakeBundle::decode(&haven_shape) {
            Ok(v) => println!(
                "DIAG handshake_bundle_commit rewritten to Haven's shape: decode ok, re-encode identical to rewrite: {}",
                v.encode().map(|b| b == haven_shape).unwrap_or(false)
            ),
            Err(err) => println!("DIAG handshake_bundle_commit rewritten: decode FAIL {err:?}"),
        }
    }

    // Diagnostic: the KeyPackage-carrying messages again, encoded by mimid
    // around Haven's own KeyPackage (phase 1), to check their framing past
    // Haven's KeyPackage gate.
    if vectors.join("consent_grant_haven_kp.bin").exists() {
        let hkp = read("haven_key_package");
        let grant = run(
            &read("consent_grant_haven_kp"),
            |b| decode_consent_entry(b).map_err(e),
            |v| {
                same(
                    v,
                    &consent(
                        ConsentOperation::Grant,
                        None,
                        vec![hkp.clone()],
                        vec![(0x8001, b"ext".to_vec())],
                    ),
                )
            },
            |v| encode_consent_entry(v).map_err(e),
        );
        let success = run(
            &read("key_material_response_success_haven_kp"),
            |b| KeyMaterialResponse::decode(b).map_err(e),
            |v| {
                same(
                    v,
                    &KeyMaterialResponse::Success {
                        user_uri: uri(BOB),
                        key_package: hkp.clone(),
                    },
                )
            },
            |v| v.encode().map_err(e),
        );
        let partial = run(
            &read("key_material_response_partial_success_haven_kp"),
            |b| KeyMaterialResponse::decode(b).map_err(e),
            |v| Err(format!("no Haven value can represent it; decoded as {v:?}")),
            |v| v.encode().map_err(e),
        );
        for (name, o) in [
            ("consent_grant_haven_kp", grant),
            ("key_material_response_success_haven_kp", success),
            ("key_material_response_partial_success_haven_kp", partial),
        ] {
            println!(
                "DIAG {name}: decode={:?} fields={:?} reencode={:?}",
                o.decode, o.fields, o.reencode
            );
        }
    }

    let mut clean = 0;
    for (name, o) in &results {
        let fmt = |r: &Option<Result<(), String>>| match r {
            None => "-".to_owned(),
            Some(Ok(())) => "ok".to_owned(),
            Some(Err(_)) => "MISMATCH".to_owned(),
        };
        let d = if o.decode.is_ok() { "ok" } else { "FAIL" };
        println!(
            "{name:42} decode={d:4} fields={:8} reencode={}",
            fmt(&o.fields),
            fmt(&o.reencode)
        );
        if let Err(msg) = &o.decode {
            println!("    decode: {msg}");
        }
        if let Some(Err(msg)) = &o.fields {
            println!("    fields: {msg}");
        }
        if let Some(Err(msg)) = &o.reencode {
            println!("    reencode: {msg}");
        }
        if o.decode.is_ok()
            && matches!(o.fields, Some(Ok(())))
            && matches!(o.reencode, Some(Ok(())))
        {
            clean += 1;
        }
    }
    println!("{clean}/{} clean", results.len());
}

/// openmls 0.8.1 KeyPackage with the builder's default lifetime (B4).
fn default_kp(identity: &[u8]) -> Vec<u8> {
    use openmls::prelude::{BasicCredential, CredentialWithKey, Extensions, KeyPackage};
    use openmls::prelude::tls_codec::Serialize as _;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::{
        crypto::OpenMlsCrypto,
        signatures::{Signer, SignerError},
        types::SignatureScheme,
        OpenMlsProvider,
    };
    struct FixtureSigner {
        key: Vec<u8>,
    }
    impl Signer for FixtureSigner {
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
            OpenMlsRustCrypto::default()
                .crypto()
                .sign(SignatureScheme::ED25519, payload, &self.key)
                .map_err(|_| SignerError::SigningError)
        }
        fn signature_scheme(&self) -> SignatureScheme {
            SignatureScheme::ED25519
        }
    }
    let provider = OpenMlsRustCrypto::default();
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity.to_vec()).into(),
        signature_key: public_key.into(),
    };
    KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            &provider,
            &FixtureSigner { key: private_key },
            credential,
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}
