//! Every request and every Ack shape decodes back to itself. This only
//! shows the two directions agree; fixtures.rs ties them to bytes made
//! outside the code.

use mimid_live::{
    Ack, AckResult, ClientMessage, ConsentEntry, ErrorMessage, KeyPackageEntry, Op, OpKind,
    ProviderMessage, Request, VERSION,
};

fn ops() -> Vec<Op> {
    let room = || "mimi://a.example/r/x".to_owned();
    vec![
        Op::Subscribe {
            since: None,
            after: None,
        },
        Op::Send {
            room: room(),
            message: vec![1],
            silent: None,
        },
        Op::Send {
            room: room(),
            message: vec![1],
            silent: Some(true),
        },
        Op::Update {
            room: room(),
            request: vec![2],
        },
        Op::CreateRoom {
            room: room(),
            group_info: vec![3],
            ratchet_tree: vec![4],
        },
        Op::Unbind { room: room() },
        Op::ReportAbuse {
            room: room(),
            report: vec![5],
        },
        Op::FetchGroupInfo {
            room: room(),
            request: vec![6],
        },
        Op::FetchKeyMaterial {
            room: room(),
            request: vec![7],
        },
        Op::PublishKeyPackage {
            key_package: vec![8],
            last_resort: Some(true),
        },
        Op::ListKeyPackages,
        Op::DestroyKeyPackage {
            key_package_ref: vec![9],
        },
        Op::ListClients,
        Op::DestroyClient {
            client_id: "c1".to_owned(),
        },
        Op::ListConsent,
        Op::CreateConsent {
            requester_uri: "mimi://a.example/u/a".to_owned(),
            target_uri: "mimi://b.example/u/b".to_owned(),
            room: Some(room()),
            requested: Some(true),
            decision: Some("grant".to_owned()),
        },
        Op::UpdateConsent {
            consent_id: "c".to_owned(),
            requested: Some(false),
            decision: Some(Some("revoke".to_owned())),
        },
        Op::DestroyConsent {
            consent_id: "c".to_owned(),
        },
        Op::ListChats,
        Op::SetChatAccepted {
            chat_id: "C".to_owned(),
            accepted: true,
        },
        Op::Upload {
            data: vec![10],
            media_type: Some("application/octet-stream".to_owned()),
        },
        Op::FetchAsset {
            room: room(),
            url: "https://b.example/a/1".to_owned(),
        },
    ]
}

#[test]
fn every_request_round_trips() {
    for (id, op) in ops().into_iter().enumerate() {
        let message = ClientMessage::Request(Request {
            v: VERSION,
            id: id as u64,
            op,
            extra: Vec::new(),
        });
        assert_eq!(
            ClientMessage::decode(&message.encode()).unwrap(),
            message,
            "{message:?}"
        );
    }
}

#[test]
fn every_ack_round_trips() {
    let consent = ConsentEntry {
        consent_id: "c".to_owned(),
        requester_uri: "mimi://a.example/u/a".to_owned(),
        target_uri: "mimi://b.example/u/b".to_owned(),
        room: Some("mimi://a.example/r/x".to_owned()),
        requested: false,
        decision: Some("grant".to_owned()),
        updated: 1,
        extra: Vec::new(),
    };
    for (kind, result) in [
        (
            OpKind::Update,
            AckResult::Update {
                accepted_at: 1,
                error_description: Some("x".to_owned()),
                message_ids: Some(vec!["M1".to_owned(), "M2".to_owned()]),
            },
        ),
        (
            OpKind::CreateRoom,
            AckResult::CreateRoom {
                chat_id: "C".to_owned(),
            },
        ),
        (OpKind::Unbind, AckResult::Done),
        (
            OpKind::FetchGroupInfo,
            AckResult::FetchGroupInfo {
                status: "success".to_owned(),
                response: vec![1],
            },
        ),
        (
            OpKind::FetchKeyMaterial,
            AckResult::FetchKeyMaterial { response: vec![2] },
        ),
        (
            OpKind::PublishKeyPackage,
            AckResult::PublishKeyPackage {
                key_package_ref: vec![3],
                last_resort: false,
            },
        ),
        (
            OpKind::ListKeyPackages,
            AckResult::ListKeyPackages {
                state: "k".to_owned(),
                key_packages: vec![KeyPackageEntry {
                    key_package_ref: vec![3],
                    key_package: vec![4],
                    last_resort: true,
                    extra: Vec::new(),
                }],
            },
        ),
        (
            OpKind::ListConsent,
            AckResult::ListConsent {
                state: "q".to_owned(),
                records: vec![consent],
            },
        ),
        (
            OpKind::Upload,
            AckResult::Upload {
                blob_id: "B".to_owned(),
                url: "https://a.example/assets/B".to_owned(),
                size: 5,
            },
        ),
        (OpKind::FetchAsset, AckResult::FetchAsset { data: vec![6] }),
    ] {
        let message = ProviderMessage::Ack(Ack {
            v: VERSION,
            id: 1,
            result,
            extra: Vec::new(),
        });
        assert_eq!(
            ProviderMessage::decode(&message.encode(), |_| Some(kind)).unwrap(),
            message
        );
    }
}

#[test]
fn an_error_with_every_member_round_trips() {
    let message = ProviderMessage::Error(ErrorMessage {
        detail: Some("d".to_owned()),
        current_epoch: Some(1),
        invalid_proposals: Some(vec![vec![1], vec![2]]),
        error_description: Some("e".to_owned()),
        status: Some(422),
        properties: Some(vec!["keyPackage".to_owned()]),
        existing_id: Some("x".to_owned()),
        ..ErrorMessage::new(None, "invalidProperties")
    });
    assert_eq!(
        ProviderMessage::decode(&message.encode(), |_| None).unwrap(),
        message
    );
}
