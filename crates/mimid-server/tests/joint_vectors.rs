//! The joint IETF 127 vector set with Haven (bead mimid-1wgh.46.17), first
//! slice: wire-level cases from the weekend's interop table that need no
//! MLS group.
//!
//! `fixtures/joint-ietf127/vectors.json` uses the schema of Haven's
//! `tests/vectors/protocol07-vectors.json` (format_version 1; vectors of
//! `{id, kind, description, hex, decode}`) so both implementations' replay
//! tests can read it, plus an `outcome` object where a hub or follower
//! decides: the operation, what the drafts say (`spec`, marked as our
//! proposal where the drafts are silent), and what `mimid` and `haven` do,
//! so a known difference is data, not a failing test. `decode` is the
//! drafts' answer and mimid's; `decode_haven`, where present, is Haven's
//! decoder's when it differs.
//!
//! This file both generates the vectors and checks them. The committed file
//! must equal what [`vectors`] builds; set `MIMID_REGEN_JOINT_VECTORS=1` to
//! rewrite it. Every vector is then decoded with mimid's codecs, and the
//! `mimid` outcome is checked against mimid itself for identifierQuery,
//! consent and role-name sizes. The abuse-report and update-response
//! outcomes are the ones seen live on 2026-11-14 and are covered by
//! hub_abuse.rs, hub_unfranked_open_rooms.rs and hub_update.rs.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::FixedClock;
use mimi_content::{Disposition, Extensions, MimiContent, NestedPart, Part};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{AppDataDictionary, CipherSuite};
use mimi_protocol::{
    AbuseReport, AbuseType, AbusiveMessage, ConsentEntry, ConsentOperation, Frank,
    IdentifierRequest, IdentifierResponse, IdentifierUri, QueryElement, QuerySearch, UpdateResult,
    UpdateRoomResponse, Utf8String,
};
use mimi_room_policy::component_id::ROLES_LIST;
use mimi_room_policy::{Role, RoleData};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::hub::Hub;
use mimid_server::limits::FieldLimits;
use mimid_server::peer::PeerClient;
use mimid_server::store::{ConsentKey, NewKeyPackage, Store};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const PATH: &str = "tests/fixtures/joint-ietf127/vectors.json";

/// The Haven-side user and provider in these vectors.
const HENRY: &str = "mimi://a.example/u/henry";
/// The mimid-side user and provider.
const ALICE: &str = "mimi://b.example/u/alice";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn uri(text: &str) -> IdentifierUri {
    IdentifierUri::new(text).unwrap()
}

fn no_extensions() -> AppDataDictionary {
    AppDataDictionary::new(&[]).unwrap()
}

fn vector(id: &str, kind: &str, description: &str, bytes: &[u8], decode: &str) -> Value {
    json!({
        "id": id,
        "kind": kind,
        "description": description,
        "hex": hex(bytes),
        "decode": decode,
    })
}

/// Records that Haven's decoder gives `haven` ("ok" or "error") where it
/// differs from `decode`, which is the drafts' answer and mimid's.
fn decode_haven(mut v: Value, haven: &str) -> Value {
    v["decode_haven"] = json!(haven);
    v
}

fn with_outcome(mut v: Value, operation: &str, spec: &str, mimid: &str, haven: &str) -> Value {
    v["outcome"] = json!({
        "operation": operation,
        "spec": spec,
        "mimid": mimid,
        "haven": haven,
    });
    v
}

fn consent(operation: ConsentOperation) -> Vec<u8> {
    ConsentEntry {
        consent_operation: operation,
        requester_uri: uri(HENRY),
        target_uri: uri(ALICE),
        room_id: None,
        client_key_packages: vec![],
        consent_extensions: no_extensions(),
    }
    .tls_serialize_detached()
    .unwrap()
}

fn abuse(messages: Vec<AbusiveMessage>) -> Vec<u8> {
    AbuseReport {
        reporting_user: uri(HENRY),
        alleged_abuser_uri: uri(ALICE),
        reason_code: AbuseType::RESERVED,
        note: b"interop test".to_vec(),
        messages,
        abuse_extensions: no_extensions(),
    }
    .tls_serialize_detached()
    .unwrap()
}

fn handle_query(value: &str) -> Vec<u8> {
    IdentifierRequest {
        query_elements: vec![QueryElement {
            search: QuerySearch::Handle,
            search_value: value.as_bytes().to_vec(),
        }],
        id_request_extensions: no_extensions(),
    }
    .tls_serialize_detached()
    .unwrap()
}

fn roles(name: &str) -> Vec<u8> {
    RoleData {
        roles: vec![Role {
            role_index: 2,
            role_name: name.to_owned(),
            role_description: String::new(),
            role_capabilities: vec![],
            minimum_participants_constraint: 0,
            maximum_participants_constraint: None,
            minimum_active_participants_constraint: 0,
            maximum_active_participants_constraint: None,
            authorized_role_changes: vec![],
        }],
    }
    .tls_serialize_detached()
    .unwrap()
}

fn content(text: &str) -> Vec<u8> {
    MimiContent {
        salt: [0x5a; 16],
        replaces: None,
        topic_id: vec![],
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions {
            sender_uri: None,
            room_uri: None,
            other: BTreeMap::new(),
        },
        nested_part: NestedPart {
            disposition: Disposition::RENDER,
            language: String::new(),
            part: Part::Single {
                content_type: "text/plain;charset=utf-8".to_owned(),
                content: text.as_bytes().to_vec(),
            },
        },
    }
    .encode()
    .unwrap()
}

/// Every vector, in order.
fn vectors() -> Value {
    let mut v = Vec::new();

    // ---- consent (protocol-07 §5.7) ----
    v.push(with_outcome(
        vector(
            "jt-consent-01",
            "ConsentEntry",
            "requestConsent request: henry (mimi://a.example/u/henry) asks alice (mimi://b.example/u/alice), any room",
            &consent(ConsentOperation::Request),
            "ok",
        ),
        "POST /requestConsent/b.example from a.example, alice has a client",
        "202, the request is held",
        "202, stored",
        "202, stored",
    ));
    v.push(with_outcome(
        vector(
            "jt-consent-02",
            "ConsentEntry",
            "requestConsent cancel of jt-consent-01's scope",
            &consent(ConsentOperation::Cancel),
            "ok",
        ),
        "the same POST, after jt-consent-01",
        "202, the held request is withdrawn",
        "202, deleted",
        "202, deleted",
    ));

    // ---- reportAbuse (protocol-07 §5.9) ----
    v.push(with_outcome(
        vector(
            "jt-abuse-01",
            "AbuseReport",
            "henry reports alice with a note and no messages",
            &abuse(vec![]),
            "ok",
        ),
        "POST /reportAbuse/{roomId} to the room's hub",
        "accepted; §5.9 names no success code",
        "200, no body",
        "201",
    ));
    let zero_frank = AbusiveMessage {
        message_content: content("reported message"),
        frank: Frank {
            server_frank: [0; 32],
            franking_signature_ciphersuite: CipherSuite::tls_deserialize_exact([0x00, 0x01])
                .unwrap(),
            franking_integrity_signature: vec![],
        },
        accepted_timestamp: 1_794_693_133_000,
    };
    v.push(decode_haven(
        with_outcome(
            vector(
                "jt-abuse-02",
                "AbuseReport",
                "as jt-abuse-01 with one AbusiveMessage whose frank is all zero",
                &abuse(vec![zero_frank]),
                "ok",
            ),
            "POST /reportAbuse/{roomId} for a franked room",
            "refused: the frank does not verify",
            "422 unverified-abusive-message; in a room without franking, 200 and logged unverified",
            "400: refuses any attached message at decode (DIV-8/9)",
        ),
        "error",
    ));

    // ---- update responses (protocol-07 §5.3) ----
    v.push(vector(
        "jt-update-01",
        "UpdateRoomResponse",
        "wrongEpoch, currentEpoch 2, empty errorDescription: a Commit one epoch late",
        &UpdateRoomResponse {
            error_description: Utf8String::new(String::new()).unwrap(),
            result: UpdateResult::WrongEpoch { current_epoch: 2 },
        }
        .tls_serialize_detached()
        .unwrap(),
        "ok",
    ));

    // ---- identifierQuery handles (protocol-07 §5.8; proposal: RFC 3986 §6.2.2) ----
    for (id, value, description, haven) in [
        (
            "jt-iq-01",
            ALICE,
            "handle query, the URI exactly",
            "success, answered as the user URI; checked on the live hub at Haven ea645b1, 2026-11-15",
        ),
        (
            "jt-iq-02",
            "MIMI://B.Example/u/alice",
            "handle query, scheme and host in other case",
            "success, answered as the user URI; checked on the live hub at Haven ea645b1, 2026-11-15",
        ),
        (
            "jt-iq-03",
            "mimi://b.example/u/%61lice",
            "handle query, an unreserved character percent-encoded",
            "success, answered as the user URI; checked on the live hub at Haven ea645b1, 2026-11-15",
        ),
    ] {
        v.push(with_outcome(
            vector(
                id,
                "IdentifierRequest",
                description,
                &handle_query(value),
                "ok",
            ),
            "POST /identifierQuery/b.example, alice has a client",
            "protocol-07 §5.8: \"the entire handle URI matches exactly (for example: im:alice.smith@a.example)\". Whether a handle is the mimi:// user URI is not said; if it is, proposed: compare by RFC 3986 §6.2.2",
            "success, answered as mimi://b.example/u/alice",
            haven,
        ));
    }
    v.push(with_outcome(
        vector(
            "jt-iq-04",
            "IdentifierRequest",
            "handle query, the user part in other case",
            &handle_query("mimi://b.example/u/ALICE"),
            "ok",
        ),
        "POST /identifierQuery/b.example, alice has a client",
        "notFound: the path is case-sensitive (RFC 3986 §6.2.2.1)",
        "notFound, HTTP 200",
        "notFound, HTTP 200; checked on the live hub at Haven ea645b1, 2026-11-15",
    ));

    // ---- identifierQuery nick (protocol-07 §5.8) ----
    v.push(with_outcome(
        vector(
            "jt-iq-05",
            "IdentifierRequest",
            "nick query, the bare user id",
            &IdentifierRequest {
                query_elements: vec![QueryElement {
                    search: QuerySearch::Nick,
                    search_value: b"alice".to_vec(),
                }],
                id_request_extensions: no_extensions(),
            }
            .tls_serialize_detached()
            .unwrap(),
            "ok",
        ),
        "POST /identifierQuery/b.example, alice has a client",
        "protocol-07 §5.8: \"nick means that the nickname or handle matches exactly\"; a bare name is a nick, not a handle",
        "success, answered as mimi://b.example/u/alice",
        "success, answered as the user URI; checked on the live hub at Haven ea645b1, 2026-11-15",
    ));
    v.push(with_outcome(
        vector(
            "jt-iq-06",
            "IdentifierRequest",
            "handle query, the bare user id",
            &handle_query("alice"),
            "ok",
        ),
        "POST /identifierQuery/b.example, alice has a client",
        "notFound: a handle is a URI (§5.8); a bare name is a nick",
        "notFound, HTTP 200",
        "notFound, HTTP 200; checked on the live hub at Haven ea645b1, 2026-11-15",
    ));

    // ---- IdentifierUri with a non-ASCII host ----
    let host = "mimi://\u{4F8B}\u{3048}.jp/u/alice".as_bytes();
    let mut raw = vec![0x00]; // responseCode success(0)
    raw.push(u8::try_from(host.len() + 1).unwrap()); // uri<V>
    raw.push(u8::try_from(host.len()).unwrap()); // IdentifierUri
    raw.extend_from_slice(host);
    raw.extend([0x00, 0x00]); // foundProfiles, id_response_extensions
    v.push(decode_haven(vector(
        "jt-uri-01",
        "IdentifierResponse",
        "success naming mimi://\u{4F8B}\u{3048}.jp/u/alice: a host outside RFC 3986, which is ASCII. mimid refuses it at decode; Haven's codec decodes it and its URI parser refuses it",
        &raw,
        "error",
    ),
        "ok",
    ));

    // ---- role names (room-policy-04 §3; proposal: a size per field) ----
    let at = "n".repeat(1024);
    let over = "n".repeat(1025);
    v.push(with_outcome(
        vector(
            "jt-role-01",
            "RoleData",
            "one role whose role_name is 1024 octets",
            &roles(&at),
            "ok",
        ),
        "a roles_list in a room's GroupContext or a Commit",
        "no limit in the draft; proposed: receivers SHOULD accept at least 1024 octets",
        "accepted",
        "accepted",
    ));
    v.push(decode_haven(
        with_outcome(
            vector(
                "jt-role-02",
                "RoleData",
                "one role whose role_name is 1025 octets",
                &roles(&over),
                "ok",
            ),
            "a roles_list in a room's GroupContext or a Commit",
            "no limit in the draft; proposed: receivers MAY refuse more than 1024 octets",
            "refused (max_name_octets 1024)",
            "refused at decode (1024-octet budget)",
        ),
        "error",
    ));
    let placeholder = "QQ";
    let mut invalid = roles(placeholder);
    let at = invalid
        .windows(2)
        .position(|w| w == placeholder.as_bytes())
        .unwrap();
    invalid[at..at + 2].copy_from_slice(&[0xc3, 0x28]);
    v.push(vector(
        "jt-role-03",
        "RoleData",
        "one role whose role_name is not UTF-8 (c3 28)",
        &invalid,
        "error",
    ));

    // ---- content text (mimi-content-10), byte for byte in both ----
    for (id, text, description) in [
        ("jt-content-01", "caf\u{00E9}", "body \"café\" in NFC"),
        (
            "jt-content-02",
            "cafe\u{0301}",
            "body \"café\" in NFD: different bytes, not normalized",
        ),
        (
            "jt-content-03",
            "\u{202E}gnp.exe",
            "body with a right-to-left override",
        ),
        (
            "jt-content-04",
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}",
            "body with a ZWJ emoji sequence",
        ),
        (
            "jt-content-05",
            "\u{0130}stanbul \u{0131}",
            "body with Turkish dotted capital I and dotless i",
        ),
    ] {
        v.push(vector(id, "MimiContent", description, &content(text), "ok"));
    }

    json!({
        "format_version": 1,
        "generator": "mimid crates/mimid-server/tests/joint_vectors.rs",
        "spec": "draft-ietf-mimi-protocol-07, draft-ietf-mimi-room-policy-04, draft-ietf-mimi-content-10",
        "description": "Joint mimid and Haven vectors from the IETF 127 hackathon MIMI table, 2026-11-14. Draft for review by both implementations.",
        "vectors": v,
    })
}

fn text() -> String {
    serde_json::to_string_pretty(&vectors()).unwrap() + "\n"
}

#[test]
fn the_committed_file_is_what_the_generator_builds() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(PATH);
    if std::env::var_os("MIMID_REGEN_JOINT_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text()).unwrap();
    }
    let committed = std::fs::read_to_string(&path).expect("run with MIMID_REGEN_JOINT_VECTORS=1");
    assert_eq!(
        committed,
        text(),
        "regenerate with MIMID_REGEN_JOINT_VECTORS=1"
    );
}

/// Decodes `bytes` as `kind` with mimid's codecs and, if that works,
/// re-encodes it: `Ok` only if it decodes and re-encodes to the same bytes.
fn decodes(kind: &str, bytes: &[u8]) -> Result<(), String> {
    fn exact<T: Deserialize + Serialize>(bytes: &[u8]) -> Result<(), String> {
        let value = T::tls_deserialize_exact(bytes).map_err(|e| format!("{e:?}"))?;
        (value.tls_serialize_detached().unwrap() == bytes)
            .then_some(())
            .ok_or_else(|| "re-encodes differently".to_owned())
    }
    match kind {
        "ConsentEntry" => exact::<ConsentEntry>(bytes),
        "AbuseReport" => exact::<AbuseReport>(bytes),
        "UpdateRoomResponse" => exact::<UpdateRoomResponse>(bytes),
        "IdentifierRequest" => exact::<IdentifierRequest>(bytes),
        "IdentifierResponse" => exact::<IdentifierResponse>(bytes),
        "RoleData" => exact::<RoleData>(bytes),
        "MimiContent" => {
            let value = MimiContent::decode(bytes).map_err(|e| e.to_string())?;
            (value.encode().unwrap() == bytes)
                .then_some(())
                .ok_or_else(|| "re-encodes differently".to_owned())
        }
        other => Err(format!("unknown kind {other}")),
    }
}

#[test]
fn every_vector_decodes_in_mimid_as_stated() {
    let file = vectors();
    for v in file["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let result = decodes(
            v["kind"].as_str().unwrap(),
            &unhex(v["hex"].as_str().unwrap()),
        );
        match v["decode"].as_str().unwrap() {
            "ok" => assert!(result.is_ok(), "{id}: {result:?}"),
            _ => assert!(result.is_err(), "{id} decodes in mimid"),
        }
    }
}

#[test]
fn role_name_outcomes_are_mimids() {
    let limits = FieldLimits::default();
    let file = vectors();
    let get = |id: &str| -> Vec<u8> {
        let v = file["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap();
        unhex(v["hex"].as_str().unwrap())
    };
    assert!(
        limits
            .component(ROLES_LIST, &get("jt-role-01"), true)
            .is_ok()
    );
    assert!(
        limits
            .component(ROLES_LIST, &get("jt-role-02"), true)
            .is_err()
    );
}

struct Provider {
    _dir: TempDir,
    store: Store,
    app: Router,
}

/// b.example with alice, peering with a.example.
async fn provider() -> Provider {
    let dir = tempfile::tempdir().unwrap();
    let domain = Domain::try_from("b.example".to_owned()).unwrap();
    let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
        .await
        .unwrap();
    store
        .insert_key_package(&NewKeyPackage {
            client_id: &format!("{ALICE}/client"),
            user_uri: ALICE,
            reference: &[0; 32],
            bytes: b"key package",
            last_resort: true,
            not_after: 4_000_000_000,
        })
        .await
        .unwrap();
    let clock = Arc::new(FixedClock(1_700_000_000_000));
    let hub = Hub::open(store.clone(), domain.clone(), clock.clone())
        .await
        .unwrap();
    let peers = BTreeMap::from([(
        Domain::try_from("a.example".to_owned()).unwrap(),
        BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap(),
    )]);
    let follower = Follower::new(domain.clone(), store.clone(), clock)
        .with_peers(PeerClient::new(&domain, peers).unwrap());
    let base = BaseUrl::try_from(format!("https://mimi.{domain}")).unwrap();
    let app = router(directory(&base), Arc::new(hub), Arc::new(follower));
    Provider {
        _dir: dir,
        store,
        app,
    }
}

async fn post(app: &Router, path: &str, body: &[u8]) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::FROM, "mimi@a.example")
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
}

fn hex_of(id: &str) -> Vec<u8> {
    let file = vectors();
    let v = file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap()
        .clone();
    unhex(v["hex"].as_str().unwrap())
}

#[tokio::test]
async fn consent_outcomes_are_mimids() {
    let b = provider().await;
    let scope = ConsentKey {
        requester_uri: HENRY,
        target_uri: ALICE,
        room_id: None,
    };
    let path = "/v1/requestConsent/b.example";
    assert_eq!(
        post(&b.app, path, &hex_of("jt-consent-01")).await.0,
        StatusCode::ACCEPTED
    );
    assert!(b.store.consent_request(&scope).await.unwrap().is_some());
    assert_eq!(
        post(&b.app, path, &hex_of("jt-consent-02")).await.0,
        StatusCode::ACCEPTED
    );
    assert!(b.store.consent_request(&scope).await.unwrap().is_none());
}

#[tokio::test]
async fn identifier_query_outcomes_are_mimids() {
    let b = provider().await;
    let path = "/v1/identifierQuery/b.example";
    for id in ["jt-iq-01", "jt-iq-02", "jt-iq-03", "jt-iq-05"] {
        let (status, body) = post(&b.app, path, &hex_of(id)).await;
        assert_eq!(status, StatusCode::OK, "{id}");
        let response = IdentifierResponse::tls_deserialize_exact(&body[..]).unwrap();
        assert_eq!(
            response.uri.iter().map(|u| u.as_str()).collect::<Vec<_>>(),
            [ALICE],
            "{id}"
        );
    }
    for id in ["jt-iq-04", "jt-iq-06"] {
        let (status, body) = post(&b.app, path, &hex_of(id)).await;
        assert_eq!(status, StatusCode::OK, "{id}");
        let response = IdentifierResponse::tls_deserialize_exact(&body[..]).unwrap();
        assert!(response.uri.is_empty(), "{id}");
    }
}
