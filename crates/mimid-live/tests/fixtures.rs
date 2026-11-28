//! The hand-encoded fixtures (tests/fixtures/PROVENANCE): decode, compare
//! with the value written out here, encode again, require the same bytes.

use std::collections::BTreeMap;

use mimid_live::cbor::Value;
use mimid_live::{
    Ack, AckResult, Changed, ChatEntry, ClientEntry, ClientHello, ClientMessage, ConsentEntry,
    Deliver, ErrorMessage, Keepalive, KeepaliveError, Op, OpKind, Position, ProviderHello,
    ProviderMessage, Request,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let digits: String = text
        .lines()
        .map(|line| line.split(';').next().unwrap_or(""))
        .collect::<String>()
        .split_whitespace()
        .collect();
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap())
        .collect()
}

fn client(name: &str, expected: ClientMessage) {
    let bytes = fixture(name);
    let decoded = ClientMessage::decode(&bytes).unwrap();
    assert_eq!(decoded, expected, "{name}");
    assert_eq!(decoded.encode(), bytes, "{name} re-encoded");
}

fn provider(name: &str, kind: Option<OpKind>, expected: ProviderMessage) {
    let bytes = fixture(name);
    let decoded = ProviderMessage::decode(&bytes, |_| kind).unwrap();
    assert_eq!(decoded, expected, "{name}");
    assert_eq!(decoded.encode(), bytes, "{name} re-encoded");
}

fn request(id: u64, op: Op) -> ClientMessage {
    ClientMessage::Request(Request {
        v: 2,
        id,
        op,
        extra: Vec::new(),
    })
}

fn ack(id: u64, result: AckResult) -> ProviderMessage {
    ProviderMessage::Ack(Ack {
        v: 2,
        id,
        result,
        extra: Vec::new(),
    })
}

#[test]
fn client_hello() {
    client(
        "client-hello.hex",
        ClientMessage::Hello(ClientHello {
            versions: vec![1],
            token: "tok".to_owned(),
            keepalive: None,
            extra: Vec::new(),
        }),
    );
}

/// Bead mimid-mm42: the keepalive pair a client states as a responder
/// (draft-atwood-mimi-keepalive-00 §4.1), and a client that speaks both
/// versions.
#[test]
fn client_hello_with_a_keepalive() {
    client(
        "client-hello-keepalive.hex",
        ClientMessage::Hello(ClientHello {
            versions: vec![1, 2],
            token: "tok".to_owned(),
            keepalive: Some(Keepalive::new(30, 120).unwrap()),
            extra: Vec::new(),
        }),
    );
}

#[test]
fn subscribe() {
    client(
        "subscribe.hex",
        request(
            7,
            Op::Subscribe {
                since: Some("12.3".to_owned()),
                after: None,
            },
        ),
    );
}

/// findings log F12: the last handled Message per Chat.
#[test]
fn subscribe_after() {
    client(
        "subscribe-after.hex",
        request(
            8,
            Op::Subscribe {
                since: None,
                after: Some(BTreeMap::from([("C1".to_owned(), "M9".to_owned())])),
            },
        ),
    );
}

#[test]
fn send() {
    client(
        "send.hex",
        request(
            300,
            Op::Send {
                room: "mimi://a.example/r/x".to_owned(),
                message: vec![0, 1, 2],
                silent: None,
            },
        ),
    );
}

/// Bead mimid-e64f.20: `silent`.
#[test]
fn send_silent() {
    client(
        "send-silent.hex",
        request(
            300,
            Op::Send {
                room: "mimi://a.example/r/x".to_owned(),
                message: vec![0, 1, 2],
                silent: Some(true),
            },
        ),
    );
}

#[test]
fn update_consent_to_null() {
    client(
        "update-consent.hex",
        request(
            2,
            Op::UpdateConsent {
                consent_id: "c1".to_owned(),
                requested: None,
                decision: Some(None),
            },
        ),
    );
}

#[test]
fn provider_hello() {
    provider(
        "provider-hello.hex",
        None,
        ProviderMessage::Hello(ProviderHello {
            version: 1,
            user_uri: "mimi://a.example/u/alice".to_owned(),
            room_id_prefix: "mimi://a.example/r/".to_owned(),
            hub_sender: vec![1],
            cipher_suites: vec![1],
            max_key_packages: 100,
            max_key_package_lifetime: None,
            // The values the fixture was written with (decision
            // mimid-1wgh.78 before findings log F10), not the constants.
            max_message_bytes: 16 * 1024 * 1024 + 64 * 1024,
            max_request_bytes: 4 * 1024 * 1024 + 64 * 1024,
            max_mls_object_size: None,
            stores_assets: true,
            asset_lifetime: Some(3600),
            message_retention: None,
            max_clients: None,
            fetches_assets: true,
            accepted_rooms: true,
            keepalive: None,
            extra: Vec::new(),
        }),
    );
}

/// Bead mimid-e64f.22: `maxClients`.
#[test]
fn provider_hello_with_max_clients() {
    provider(
        "provider-hello-max-clients.hex",
        None,
        ProviderMessage::Hello(ProviderHello {
            version: 1,
            user_uri: "mimi://a.example/u/alice".to_owned(),
            room_id_prefix: "mimi://a.example/r/".to_owned(),
            hub_sender: vec![1],
            cipher_suites: vec![1],
            max_key_packages: 100,
            max_key_package_lifetime: None,
            max_clients: Some(10),
            max_message_bytes: 16 * 1024 * 1024 + 64 * 1024,
            max_request_bytes: 4 * 1024 * 1024 + 64 * 1024,
            max_mls_object_size: None,
            stores_assets: true,
            asset_lifetime: Some(3600),
            message_retention: None,
            fetches_assets: true,
            accepted_rooms: true,
            keepalive: None,
            extra: Vec::new(),
        }),
    );
}

/// Clean-room finding C4: `maxKeyPackageLifetime` in seconds.
#[test]
fn provider_hello_with_max_key_package_lifetime() {
    provider(
        "provider-hello-max-kp-lifetime.hex",
        None,
        ProviderMessage::Hello(ProviderHello {
            version: 1,
            user_uri: "mimi://a.example/u/alice".to_owned(),
            room_id_prefix: "mimi://a.example/r/".to_owned(),
            hub_sender: vec![1],
            cipher_suites: vec![1],
            max_key_packages: 100,
            max_key_package_lifetime: Some(31_539_600),
            max_message_bytes: 16 * 1024 * 1024 + 64 * 1024,
            max_request_bytes: 4 * 1024 * 1024 + 64 * 1024,
            max_mls_object_size: None,
            stores_assets: true,
            asset_lifetime: Some(3600),
            message_retention: None,
            max_clients: None,
            fetches_assets: true,
            accepted_rooms: true,
            keepalive: None,
            extra: Vec::new(),
        }),
    );
}

/// Bead mimid-mm42: version 2's hello, with the keepalive pair the
/// provider states as a responder (draft-atwood-mimi-keepalive-00 §4.1).
#[test]
fn provider_hello_with_a_keepalive() {
    provider(
        "provider-hello-keepalive.hex",
        None,
        ProviderMessage::Hello(ProviderHello {
            version: 2,
            user_uri: "mimi://a.example/u/alice".to_owned(),
            room_id_prefix: "mimi://a.example/r/".to_owned(),
            hub_sender: vec![1],
            cipher_suites: vec![1],
            max_key_packages: 100,
            max_key_package_lifetime: None,
            max_message_bytes: 16 * 1024 * 1024 + 64 * 1024,
            max_request_bytes: 4 * 1024 * 1024 + 64 * 1024,
            max_mls_object_size: None,
            stores_assets: true,
            asset_lifetime: Some(3600),
            message_retention: None,
            max_clients: None,
            fetches_assets: true,
            accepted_rooms: true,
            keepalive: Some(Keepalive::new(30, 120).unwrap()),
            extra: Vec::new(),
        }),
    );
}

/// Decision mimid-1wgh.82: `messageRetention` in seconds.
#[test]
fn provider_hello_with_message_retention() {
    provider(
        "provider-hello-retention.hex",
        None,
        ProviderMessage::Hello(ProviderHello {
            version: 1,
            user_uri: "mimi://a.example/u/alice".to_owned(),
            room_id_prefix: "mimi://a.example/r/".to_owned(),
            hub_sender: vec![1],
            cipher_suites: vec![1],
            max_key_packages: 100,
            max_key_package_lifetime: None,
            max_message_bytes: 16 * 1024 * 1024 + 64 * 1024,
            max_request_bytes: 4 * 1024 * 1024 + 64 * 1024,
            max_mls_object_size: None,
            stores_assets: true,
            asset_lifetime: Some(3600),
            message_retention: Some(604_800),
            max_clients: None,
            fetches_assets: true,
            accepted_rooms: true,
            keepalive: None,
            extra: Vec::new(),
        }),
    );
}

#[test]
fn ack_of_a_send() {
    provider(
        "ack-send.hex",
        Some(OpKind::Send),
        ack(
            300,
            AckResult::Send {
                accepted_at: 1_700_000_100_123,
                frank: Some(vec![0xaa, 0xbb]),
                message_ids: None,
            },
        ),
    );
}

/// findings log F18: the ids of the Messages stored for a sent message.
#[test]
fn ack_of_a_send_with_message_ids() {
    provider(
        "ack-send-message-ids.hex",
        Some(OpKind::Send),
        ack(
            301,
            AckResult::Send {
                accepted_at: 5,
                frank: None,
                message_ids: Some(vec!["M1".to_owned()]),
            },
        ),
    );
}

#[test]
fn ack_of_a_list_chats() {
    provider(
        "ack-list-chats.hex",
        Some(OpKind::ListChats),
        ack(
            5,
            AckResult::ListChats {
                state: "s1".to_owned(),
                chats: vec![ChatEntry {
                    chat_id: "C1".to_owned(),
                    room: "mimi://a.example/r/x".to_owned(),
                    bound: true,
                    accepted: false,
                    extra: Vec::new(),
                }],
            },
        ),
    );
}

/// Bead mimid-e64f.22.
#[test]
fn ack_of_list_clients() {
    provider(
        "ack-list-clients.hex",
        Some(OpKind::ListClients),
        ack(
            5,
            AckResult::ListClients {
                state: "s1".to_owned(),
                clients: vec![ClientEntry {
                    client_id: "c1".to_owned(),
                    signature_key: vec![1, 2],
                    extra: Vec::new(),
                }],
            },
        ),
    );
}

#[test]
fn ack_of_a_create_consent() {
    provider(
        "ack-create-consent.hex",
        Some(OpKind::CreateConsent),
        ack(
            3,
            AckResult::CreateConsent {
                record: ConsentEntry {
                    consent_id: "cs7".to_owned(),
                    requester_uri: "mimi://a.example/u/alice".to_owned(),
                    target_uri: "mimi://e.example/u/erin".to_owned(),
                    room: None,
                    requested: true,
                    decision: None,
                    updated: 1_700_000_000_000,
                    extra: Vec::new(),
                },
            },
        ),
    );
}

#[test]
fn error_epoch_too_old() {
    provider(
        "error-epoch-too-old.hex",
        None,
        ProviderMessage::Error(ErrorMessage {
            current_epoch: Some(4),
            ..ErrorMessage::new(Some(9), mimid_live::code::EPOCH_TOO_OLD)
        }),
    );
}

/// Bead mimid-e64f.21: `retryAfter`.
#[test]
fn error_rate_limited() {
    provider(
        "error-rate-limited.hex",
        None,
        ProviderMessage::Error(ErrorMessage {
            retry_after: Some(2),
            ..ErrorMessage::new(Some(7), mimid_live::code::RATE_LIMITED)
        }),
    );
}

#[test]
fn deliver() {
    provider(
        "deliver.hex",
        None,
        ProviderMessage::Deliver(Deliver {
            v: 2,
            message_id: "M1".to_owned(),
            chat_id: "C1".to_owned(),
            fanout: vec![0, 1],
            extra: Vec::new(),
        }),
    );
}

#[test]
fn position_keeps_an_unknown_member() {
    provider(
        "position-unknown-member.hex",
        None,
        ProviderMessage::Position(Position {
            v: 2,
            state: "12.3".to_owned(),
            extra: vec![(Value::Text("zz".to_owned()), Value::Uint(0))],
        }),
    );
}

#[test]
fn changed() {
    provider(
        "changed.hex",
        None,
        ProviderMessage::Changed(Changed {
            v: 2,
            types: vec!["Consent".to_owned(), "KeyPackage".to_owned()],
            extra: Vec::new(),
        }),
    );
}

/// Bead mimid-mm42: the agent refuses a provider whose pair leaves a
/// prober no legal base period (draft-atwood-mimi-keepalive-00 §4.1)
/// instead of probing on it. The fixture's `maxIdleSeconds` is lowered
/// to 112, the largest value the rule refuses beside its
/// `minIntervalSeconds` of 30: 15 x 30 is 450 and 4 x 112 is 448.
#[test]
fn a_provider_hello_whose_keepalive_leaves_no_room_is_refused() {
    let Value::Map(mut pairs) = mimid_live::cbor::decode(&fixture("provider-hello-keepalive.hex"))
        .expect("the fixture decodes")
    else {
        panic!("not a map")
    };
    for (key, value) in &mut pairs {
        if *key == Value::Text("maxIdleSeconds".to_owned()) {
            *value = Value::Uint(112);
        }
    }
    let broken = mimid_live::cbor::encode(&Value::Map(pairs));
    let error = ProviderMessage::decode(&broken, |_| None)
        .unwrap_err()
        .error;
    assert_eq!(
        error,
        mimid_live::DecodeError::Keepalive(KeepaliveError::NoRoom { min: 30, max: 112 })
    );
}

/// Key order is free on input (decision mimid-1wgh.76): the members of
/// subscribe.hex in reverse order decode to the same message, which
/// encodes in the deterministic order.
#[test]
fn any_key_order_decodes_to_the_same_message() {
    let reversed: Vec<u8> = [
        &[0xa4][..],
        &[
            0x65, b's', b'i', b'n', b'c', b'e', 0x64, b'1', b'2', b'.', b'3',
        ],
        &[0x62, b'i', b'd', 0x07],
        &[0x61, b'v', 0x02],
        &[0x61, b't', 0x69],
        b"Subscribe",
    ]
    .concat();
    let decoded = ClientMessage::decode(&reversed).unwrap();
    assert_eq!(decoded.encode(), fixture("subscribe.hex"));
}
