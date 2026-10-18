//! Fixture and hostile-input tests for the update (protocol-06 §5.3) and
//! notify (§5.5) endpoint bodies.
//!
//! The protocol-06 framing around each MLS structure is hand-encoded from
//! the TLS presentation-language text, byte by byte, with RFC 9420 §2.1.2
//! variable-length prefixes written out. The embedded MLS structures are
//! the mlswg interoperability vectors vendored in
//! `crates/mimi-mls/tests/fixtures/mlswg` (entry 0, ciphersuite 0x0001; see
//! that directory's PROVENANCE for source, commit and SHA-256). A bare
//! Welcome or GroupInfo is the matching `MLSMessage` vector without its
//! 4-byte RFC 9420 §6 header (`version`, `wire_format`). The mlswg
//! PrivateMessages carry proposals and commits only, so the application
//! PrivateMessage is hand-encoded from RFC 9420 §6.3.
//!
//! None of the bytes come from this crate's encoder.

use mimi_mls::wire::{
    CipherSuite, GroupInfo, MLSMessage, PartialGroupInfo, ProposalRef, RatchetTreeOption,
    RatchetTreePresence, Welcome,
};
use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{
    FanoutEvent, FanoutMessage, Frank, GroupInfoOption, HandshakeBundle, IdentifierUri,
    NotifyRequest, UpdateRequest, UpdateResponseCode, UpdateResult, UpdateRoomResponse, Utf8String,
};

macro_rules! mlswg {
    ($field:literal) => {
        include_bytes!(concat!(
            "../../mimi-mls/tests/fixtures/mlswg/messages-000-",
            $field,
            ".bin"
        ))
        .as_slice()
    };
}

/// RFC 9420 §6 MLSMessage, 428 bytes: a PublicMessage commit.
const COMMIT: &[u8] = mlswg!("public_message_commit");
/// 429 bytes: a PublicMessage proposal.
const PROPOSAL: &[u8] = mlswg!("public_message_proposal");
/// 142 bytes: a PublicMessage application message.
const PUBLIC_APPLICATION: &[u8] = mlswg!("public_message_application");
/// 480 bytes: a PrivateMessage with content_type proposal (2).
const PRIVATE_PROPOSAL: &[u8] = mlswg!("private_message");
/// 420 bytes: an mls_welcome MLSMessage.
const WELCOME_MESSAGE: &[u8] = mlswg!("mls_welcome");
/// 424 bytes: an mls_group_info MLSMessage.
const GROUP_INFO_MESSAGE: &[u8] = mlswg!("mls_group_info");
/// 295 bytes: an mls_key_package MLSMessage.
const KEY_PACKAGE_MESSAGE: &[u8] = mlswg!("mls_key_package");
/// 173 bytes: `optional<Node> ratchet_tree<V>` including its prefix.
const RATCHET_TREE: &[u8] = mlswg!("ratchet_tree");

/// RFC 9420 §6 MLSMessage carrying a §6.3 PrivateMessage with an
/// application message. Ciphertext fields are arbitrary: decoding is
/// structural.
const PRIVATE_APPLICATION: &[u8] = &[
    0x00, 0x01, // version: mls10
    0x00, 0x02, // wire_format: mls_private_message
    0x04, b'r', b'o', b'o', b'm', // group_id<V>: 4 bytes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // epoch: 7
    0x01, // content_type: application
    0x00, // authenticated_data<V>: empty
    0x03, 0xa1, 0xa2, 0xa3, // encrypted_sender_data<V>: 3 bytes
    0x05, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, // ciphertext<V>: 5 bytes
];

/// RatchetTreeOption `distributionService(4)` (ratchet-tree-options-01 §3).
const TREE_DISTRIBUTION_SERVICE: &[u8] = &[0x04];

/// PartialGroupInfo (ratchet-tree-options-01 §4).
const PARTIAL_GROUP_INFO: &[u8] = &[
    0x00, // ratchet_tree_presence: no_ratchet_tree
    0x00, // group_info_extensions<V>: empty
    0x03, 0x51, 0x52, 0x53, // signature<V>: 3 bytes
];

/// Frank (protocol-06 §5.4), 39 bytes.
const FRANK: &[u8] = &[
    // server_frank[32]
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0x00, 0x01, // franking_signature_ciphersuite: 0x0001
    0x04, 0x91, 0x92, 0x93, 0x94, // franking_integrity_signature<V>: 4 bytes
];

/// uint64 timestamp 1_700_000_000_000 (0x0000018bcfe56800).
const TIMESTAMP: &[u8] = &[0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00];
const TIMESTAMP_VALUE: u64 = 1_700_000_000_000;

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn mls(bytes: &[u8]) -> MLSMessage {
    MLSMessage::tls_deserialize_exact(bytes).expect("mlswg MLSMessage decodes")
}

/// Strips the 4-byte RFC 9420 §6 MLSMessage header.
fn body(message: &[u8]) -> &[u8] {
    &message[4..]
}

fn tree_full() -> Vec<u8> {
    cat(&[&[0x01], RATCHET_TREE]) // representation: full, then ratchet_tree<V>
}

fn frank() -> Frank {
    Frank {
        server_frank: FRANK[..32].try_into().expect("32 bytes"),
        franking_signature_ciphersuite: CipherSuite::from(0x0001),
        franking_integrity_signature: vec![0x91, 0x92, 0x93, 0x94],
    }
}

/// Decode, compare to `expected`, re-encode, require byte-identical output.
fn check_fixture<T>(wire: &[u8], expected: &T)
where
    T: Deserialize + Serialize + Size + PartialEq + std::fmt::Debug,
{
    let decoded = T::tls_deserialize_exact(wire).expect("fixture decodes");
    assert_eq!(&decoded, expected);
    assert_eq!(decoded.tls_serialized_len(), wire.len());
    assert_eq!(decoded.tls_serialize_detached().expect("re-encodes"), wire);
}

fn decode_err<T: Deserialize + std::fmt::Debug>(wire: &[u8]) -> tls_codec::Error {
    T::tls_deserialize_exact(wire).expect_err("must be rejected")
}

/// Every strict prefix must fail to decode, and one extra byte must be
/// reported as trailing data.
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
        decode_err::<T>(&long),
        tls_codec::Error::TrailingData
    ));
}

fn utf8(s: &str) -> Utf8String {
    Utf8String::new(s).expect("no nulls")
}

// --- UpdateRequest / HandshakeBundle (§5.3) ---

fn commit_full_wire() -> Vec<u8> {
    cat(&[
        COMMIT,                   // proposalOrCommit: PublicMessage commit
        &[0x01],                  // optional<Welcome>: present
        body(WELCOME_MESSAGE),    // Welcome
        &[0x01],                  // GroupInfoRepresentation: full
        body(GROUP_INFO_MESSAGE), // GroupInfo
        &tree_full(),             // RatchetTreeOption: full
    ])
}

fn commit_partial_wire() -> Vec<u8> {
    cat(&[
        COMMIT,                    // proposalOrCommit: PublicMessage commit
        &[0x00],                   // optional<Welcome>: absent
        &[0x02],                   // GroupInfoRepresentation: partial
        PARTIAL_GROUP_INFO,        // PartialGroupInfo
        TREE_DISTRIBUTION_SERVICE, // RatchetTreeOption: distributionService
    ])
}

fn proposal_wire() -> Vec<u8> {
    cat(&[
        PROPOSAL,      // proposalOrCommit: PublicMessage proposal
        &[0x41, 0xad], // moreProposals<V>: 429 bytes (0x4000 | 0x01ad)
        PROPOSAL,      // one more PublicMessage proposal
    ])
}

#[test]
fn update_request_commit_with_full_group_info() {
    let expected = UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: mls(COMMIT),
            welcome: Some(Welcome::tls_deserialize_exact(body(WELCOME_MESSAGE)).expect("Welcome")),
            group_info_option: GroupInfoOption::Full {
                group_info: GroupInfo::tls_deserialize_exact(body(GROUP_INFO_MESSAGE))
                    .expect("GroupInfo"),
            },
            ratchet_tree_option: RatchetTreeOption::full(RATCHET_TREE).expect("tree"),
        },
    };
    check_fixture(&commit_full_wire(), &expected);
}

#[test]
fn update_request_commit_with_partial_group_info() {
    let expected = UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: mls(COMMIT),
            welcome: None,
            group_info_option: GroupInfoOption::Partial {
                partial_group_info: PartialGroupInfo::new(
                    RatchetTreePresence::NoRatchetTree,
                    &[0x00],
                    &[0x51, 0x52, 0x53],
                )
                .expect("PartialGroupInfo"),
            },
            ratchet_tree_option: RatchetTreeOption::distribution_service(),
        },
    };
    check_fixture(&commit_partial_wire(), &expected);
}

#[test]
fn update_request_proposals() {
    let expected = UpdateRequest {
        bundle: HandshakeBundle::Proposal {
            proposal_or_commit: mls(PROPOSAL),
            more_proposals: vec![mls(PROPOSAL)],
        },
    };
    check_fixture(&proposal_wire(), &expected);

    let lone = cat(&[PROPOSAL, &[0x00]]); // moreProposals<V>: empty
    let expected = UpdateRequest {
        bundle: HandshakeBundle::Proposal {
            proposal_or_commit: mls(PROPOSAL),
            more_proposals: vec![],
        },
    };
    check_fixture(&lone, &expected);
}

#[test]
fn update_request_truncation_and_trailing() {
    check_truncation_and_trailing::<UpdateRequest>(&commit_full_wire());
    check_truncation_and_trailing::<UpdateRequest>(&commit_partial_wire());
    check_truncation_and_trailing::<UpdateRequest>(&proposal_wire());
}

#[test]
fn update_request_rejects_wrong_handshake_wire_format() {
    // Each would-be proposalOrCommit, followed by a well-formed commit tail.
    let tail = cat(&[&[0x00, 0x02], PARTIAL_GROUP_INFO, TREE_DISTRIBUTION_SERVICE]);
    for message in [
        PRIVATE_PROPOSAL,
        PRIVATE_APPLICATION,
        PUBLIC_APPLICATION,
        WELCOME_MESSAGE,
        GROUP_INFO_MESSAGE,
        KEY_PACKAGE_MESSAGE,
    ] {
        decode_err::<UpdateRequest>(&cat(&[message, &tail]));
        decode_err::<UpdateRequest>(&cat(&[message, &[0x00]]));
    }
}

#[test]
fn update_request_rejects_non_proposals_in_more_proposals() {
    for (prefix, extra) in [
        (&[0x41, 0xac][..], COMMIT),             // 428 bytes
        (&[0x41, 0xe0][..], PRIVATE_PROPOSAL),   // 480 bytes
        (&[0x40, 0x8e][..], PUBLIC_APPLICATION), // 142 bytes
        (&[0x41, 0xa4][..], WELCOME_MESSAGE),    // 420 bytes
    ] {
        decode_err::<UpdateRequest>(&cat(&[PROPOSAL, prefix, extra]));
    }
}

#[test]
fn update_request_rejects_bad_presence_and_representation() {
    let mut wire = commit_partial_wire();
    wire[COMMIT.len()] = 0x02; // optional<Welcome> presence must be 0 or 1
    decode_err::<UpdateRequest>(&wire);

    for representation in [0x00, 0x03, 0xff] {
        let mut wire = commit_partial_wire();
        wire[COMMIT.len() + 1] = representation;
        assert!(matches!(
            decode_err::<UpdateRequest>(&wire),
            tls_codec::Error::UnknownValue(v) if v == u64::from(representation)
        ));
    }
}

#[test]
fn handshake_bundle_encoding_rejects_mismatched_arm() {
    let wrong = [
        HandshakeBundle::Commit {
            proposal_or_commit: mls(PROPOSAL),
            welcome: None,
            group_info_option: GroupInfoOption::Partial {
                partial_group_info: PartialGroupInfo::tls_deserialize_exact(PARTIAL_GROUP_INFO)
                    .expect("PartialGroupInfo"),
            },
            ratchet_tree_option: RatchetTreeOption::distribution_service(),
        },
        HandshakeBundle::Proposal {
            proposal_or_commit: mls(COMMIT),
            more_proposals: vec![],
        },
        HandshakeBundle::Proposal {
            proposal_or_commit: mls(PROPOSAL),
            more_proposals: vec![mls(COMMIT)],
        },
        HandshakeBundle::Proposal {
            proposal_or_commit: mls(PRIVATE_PROPOSAL),
            more_proposals: vec![],
        },
    ];
    for bundle in wrong {
        assert!(matches!(
            bundle.tls_serialize_detached(),
            Err(tls_codec::Error::EncodingError(_))
        ));
    }
}

// --- UpdateRoomResponse (§5.3) ---

#[test]
fn update_room_response_arms() {
    let success = [
        0x00, // responseCode: success
        0x00, // errorDescription<V>: empty
        0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00, // accepted_timestamp
    ];
    check_fixture(
        &success,
        &UpdateRoomResponse {
            error_description: utf8(""),
            result: UpdateResult::Success {
                accepted_timestamp: TIMESTAMP_VALUE,
            },
        },
    );

    let wrong_epoch = [
        0x01, // responseCode: wrongEpoch
        0x05, b's', b't', b'a', b'l', b'e', // errorDescription<V>: "stale"
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, // currentEpoch: 258
    ];
    check_fixture(
        &wrong_epoch,
        &UpdateRoomResponse {
            error_description: utf8("stale"),
            result: UpdateResult::WrongEpoch { current_epoch: 258 },
        },
    );

    let not_allowed = [
        0x02, // responseCode: notAllowed
        0x02, b'n', b'o', // errorDescription<V>: "no"
    ];
    check_fixture(
        &not_allowed,
        &UpdateRoomResponse {
            error_description: utf8("no"),
            result: UpdateResult::NotAllowed,
        },
    );

    let invalid_proposal = cat(&[
        &[0x03], // responseCode: invalidProposal
        &[0x00], // errorDescription<V>: empty
        &[0x2a], // invalidProposals<V>: 42 bytes
        &[0x20], // ProposalRef<V>: 32 bytes
        &[0xa5; 32],
        &[0x08], // ProposalRef<V>: 8 bytes
        &[0x5a; 8],
    ]);
    check_fixture(
        &invalid_proposal,
        &UpdateRoomResponse {
            error_description: utf8(""),
            result: UpdateResult::InvalidProposal {
                invalid_proposals: vec![
                    ProposalRef::tls_deserialize_exact(cat(&[&[0x20], &[0xa5; 32]])).expect("ref"),
                    ProposalRef::tls_deserialize_exact(cat(&[&[0x08], &[0x5a; 8]])).expect("ref"),
                ],
            },
        },
    );

    let empty_list = [0x03, 0x00, 0x00]; // invalidProposals<V>: empty
    check_fixture(
        &empty_list,
        &UpdateRoomResponse {
            error_description: utf8(""),
            result: UpdateResult::InvalidProposal {
                invalid_proposals: vec![],
            },
        },
    );

    for wire in [&success[..], &wrong_epoch, &not_allowed, &invalid_proposal] {
        check_truncation_and_trailing::<UpdateRoomResponse>(wire);
    }
}

#[test]
fn update_response_code_values() {
    for (code, value) in [
        (UpdateResponseCode::Success, 0u8),
        (UpdateResponseCode::WrongEpoch, 1),
        (UpdateResponseCode::NotAllowed, 2),
        (UpdateResponseCode::InvalidProposal, 3),
    ] {
        check_fixture(&[value], &code);
    }
}

#[test]
fn update_room_response_rejects_bad_codes_and_strings() {
    for code in [0x04, 0x80, 0xff] {
        assert!(matches!(
            decode_err::<UpdateRoomResponse>(&[code, 0x00]),
            tls_codec::Error::UnknownValue(v) if v == u64::from(code)
        ));
    }
    // errorDescription: invalid UTF-8, then an embedded null.
    decode_err::<UpdateRoomResponse>(&[0x02, 0x01, 0xff]);
    decode_err::<UpdateRoomResponse>(&[0x02, 0x01, 0x00]);
    // Non-minimal varint prefix (0x4001 for length 1).
    decode_err::<UpdateRoomResponse>(&[0x02, 0x40, 0x01, b'x']);
}

// --- FanoutMessage / NotifyRequest (§5.5) ---

fn fanout_application_wire() -> Vec<u8> {
    cat(&[
        TIMESTAMP,           // timestamp
        PRIVATE_APPLICATION, // message: PrivateMessage, application
        &[0x01],             // optional<Frank>: present
        FRANK,
    ])
}

fn fanout_application_unfranked_wire() -> Vec<u8> {
    cat(&[TIMESTAMP, PRIVATE_APPLICATION, &[0x00]]) // optional<Frank>: absent
}

fn fanout_welcome_wire() -> Vec<u8> {
    cat(&[TIMESTAMP, WELCOME_MESSAGE, &tree_full()])
}

fn fanout_proposal_wire() -> Vec<u8> {
    cat(&[TIMESTAMP, PROPOSAL, &[0x00]]) // moreProposals<V>: empty
}

fn fanout_commit_wire() -> Vec<u8> {
    cat(&[
        TIMESTAMP,
        COMMIT,
        &[0x41, 0xad], // externalProposals<V>: 429 bytes
        PROPOSAL,
    ])
}

fn expected_fanouts() -> Vec<(Vec<u8>, FanoutMessage)> {
    let at = |event| FanoutMessage {
        timestamp: TIMESTAMP_VALUE,
        event,
    };
    vec![
        (
            fanout_application_wire(),
            at(FanoutEvent::Application {
                message: mls(PRIVATE_APPLICATION),
                frank: Some(frank()),
            }),
        ),
        (
            fanout_application_unfranked_wire(),
            at(FanoutEvent::Application {
                message: mls(PRIVATE_APPLICATION),
                frank: None,
            }),
        ),
        (
            fanout_welcome_wire(),
            at(FanoutEvent::Welcome {
                message: mls(WELCOME_MESSAGE),
                ratchet_tree_option: RatchetTreeOption::full(RATCHET_TREE).expect("tree"),
            }),
        ),
        (
            fanout_proposal_wire(),
            at(FanoutEvent::Proposal {
                message: mls(PROPOSAL),
                more_proposals: vec![],
            }),
        ),
        (
            fanout_commit_wire(),
            at(FanoutEvent::Commit {
                message: mls(COMMIT),
                external_proposals: vec![mls(PROPOSAL)],
            }),
        ),
    ]
}

#[test]
fn fanout_message_arms() {
    check_fixture(FRANK, &frank());
    for (wire, expected) in expected_fanouts() {
        check_fixture(&wire, &expected);
        check_truncation_and_trailing::<FanoutMessage>(&wire);
    }
}

#[test]
fn fanout_rejects_message_without_an_arm() {
    // PublicMessage application, PrivateMessage proposal, GroupInfo and
    // KeyPackage select no arm (decision mimid-1wgh.5.24); each is followed
    // by a byte that any arm could start with.
    for message in [
        PUBLIC_APPLICATION,
        PRIVATE_PROPOSAL,
        GROUP_INFO_MESSAGE,
        KEY_PACKAGE_MESSAGE,
    ] {
        decode_err::<FanoutMessage>(&cat(&[TIMESTAMP, message, &[0x00]]));
    }
}

#[test]
fn fanout_rejects_non_proposals_in_lists() {
    for message in [PROPOSAL, COMMIT] {
        for (prefix, extra) in [
            (&[0x41, 0xac][..], COMMIT),             // 428 bytes
            (&[0x40, 0x8e][..], PUBLIC_APPLICATION), // 142 bytes
            (&[0x41, 0xe0][..], PRIVATE_PROPOSAL),   // 480 bytes
            (&[0x1d][..], PRIVATE_APPLICATION),      // 29 bytes
        ] {
            decode_err::<FanoutMessage>(&cat(&[TIMESTAMP, message, prefix, extra]));
        }
    }
}

#[test]
fn fanout_rejects_bad_frank_presence_and_tree_option() {
    let mut wire = fanout_application_wire();
    wire[TIMESTAMP.len() + PRIVATE_APPLICATION.len()] = 0x02;
    decode_err::<FanoutMessage>(&wire);

    for representation in [0x00, 0x05, 0xff] {
        decode_err::<FanoutMessage>(&cat(&[TIMESTAMP, WELCOME_MESSAGE, &[representation]]));
    }
}

#[test]
fn fanout_encoding_rejects_mismatched_arm() {
    let wrong = [
        FanoutEvent::Application {
            message: mls(WELCOME_MESSAGE),
            frank: None,
        },
        FanoutEvent::Application {
            message: mls(PRIVATE_PROPOSAL),
            frank: None,
        },
        FanoutEvent::Welcome {
            message: mls(PRIVATE_APPLICATION),
            ratchet_tree_option: RatchetTreeOption::distribution_service(),
        },
        FanoutEvent::Proposal {
            message: mls(COMMIT),
            more_proposals: vec![],
        },
        FanoutEvent::Commit {
            message: mls(COMMIT),
            external_proposals: vec![mls(COMMIT)],
        },
    ];
    for event in wrong {
        let message = FanoutMessage {
            timestamp: 0,
            event,
        };
        assert!(matches!(
            message.tls_serialize_detached(),
            Err(tls_codec::Error::EncodingError(_))
        ));
    }
}

#[test]
fn notify_body_is_concatenated_fanout_messages() {
    let fanouts = expected_fanouts();
    let body: Vec<u8> = fanouts.iter().flat_map(|(wire, _)| wire.clone()).collect();
    let expected: Vec<FanoutMessage> = fanouts.into_iter().map(|(_, m)| m).collect();

    let room_id = IdentifierUri::new("mimi://a.example/r/clubhouse").expect("URI");
    let request = NotifyRequest::decode(room_id.clone(), &body).expect("body decodes");
    assert_eq!(request.room_id, room_id);
    assert_eq!(request.fanout_messages, expected);
    assert_eq!(request.to_body().expect("re-encodes"), body);
    assert_eq!(FanoutMessage::decode_all(&body).expect("decodes"), expected);

    // Cutting the body at a message boundary leaves the earlier messages;
    // cutting it anywhere else fails.
    let mut boundaries = vec![0];
    for (wire, _) in expected_fanouts() {
        boundaries.push(boundaries.last().expect("non-empty") + wire.len());
    }
    for len in 0..body.len() {
        let result = FanoutMessage::decode_all(&body[..len]);
        match boundaries.iter().position(|&b| b == len) {
            Some(count) => assert_eq!(result.expect("boundary decodes"), expected[..count]),
            None => assert!(result.is_err(), "cut at {len} decoded"),
        }
    }
    let mut long = body.clone();
    long.push(0x00);
    assert!(FanoutMessage::decode_all(&long).is_err());
}

#[test]
fn notify_rejects_empty_room_id() {
    let body = fanout_proposal_wire();
    assert!(NotifyRequest::decode(IdentifierUri::default(), &body).is_err());
}
