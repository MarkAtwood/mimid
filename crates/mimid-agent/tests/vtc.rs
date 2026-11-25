//! The agent's VTC surface, switched on with `[jmap] vtc`
//! (draft-atwood-jmap-vtc-00; beads mimid-1wgh.114, mimid-1wgh.114.2).
//!
//! What this covers is the switch and what it reaches: whether the
//! capability is in the Session, and whether the methods answer at all.
//! Off is the default, by decision mimid-1wgh.119, because this surface
//! hands out key material: `VTCCall/exportMediaSecret` returns the call
//! room's per-epoch MLS exporter secret as input keying material for the
//! client's own media key schedule.
//!
//! The negotiation itself — an offer reaching the other side over the
//! JMAP WebSocket byte for byte, and both sides exporting the same
//! secret for the same epoch — is bead mimid-1wgh.114.10.
//!
//! Offline: two daemons against a test provider in this process.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, BOB, Running, config, server};
use serde_json::json;

/// alice's configuration with the VTC surface on.
fn with_vtc(dir: &std::path::Path, server: &common::Server) -> mimid_agent::Config {
    let mut config = config(server, ALICE, dir, "from-allowed");
    config.jmap.vtc = true;
    config
}

/// Oracle: decision mimid-1wgh.119, and RFC 8620 §3.3. Off by default,
/// and off means the capability is absent from the Session and refused in
/// `using`: a request naming it gets the request-level
/// `unknownCapability` and HTTP 400.
///
/// That second half is the one that matters. It tells a client the
/// surface is not there, where a method-level refusal would have made it
/// guess whether this deployment has a policy against calls or no calls
/// at all. No VTC method is registered either (`vtc_backend::register`
/// registers nothing when off), so there is nothing behind the capability
/// to refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_surface_is_off_by_default_and_its_capability_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "from-allowed")).await;
    let client = alice.client().await;

    let vtc = mimid_agent_jmap::vtc::CAPABILITY;
    assert!(
        client.session["capabilities"].get(vtc).is_none(),
        "the capability must be absent: {}",
        client.session["capabilities"]
    );

    // `call_using` asserts a 200, so the raw post is what shows the
    // request-level refusal.
    let (status, answer) = client
        .post(&json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat", vtc],
            "methodCalls": [["VTCCall/get", {"accountId": client.account, "ids": null}, "c0"]],
        }))
        .await;
    assert_eq!(status, 400, "{answer}");
    assert_eq!(
        answer["type"],
        json!("urn:ietf:params:jmap:error:unknownCapability"),
        "{answer}"
    );
    assert_eq!(
        answer["detail"],
        json!(vtc),
        "it should name which: {answer}"
    );

    // And without naming it, the method itself is not registered.
    let (status, answer) = client
        .post(&json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [["VTCCall/get", {"accountId": client.account, "ids": null}, "c0"]],
        }))
        .await;
    assert_eq!(status, 200, "{answer}");
    let response = &answer["methodResponses"][0];
    assert_eq!(response[0], json!("error"), "{answer}");
    assert_eq!(response[1]["type"], json!("unknownMethod"), "{answer}");

    alice.stop().await;
}

/// Oracle: the same decision, the other way. With `[jmap] vtc = true`
/// the Session names the capability with the properties of
/// crates/mimid-agent-jmap/src/vtc.rs, and the methods answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_switch_advertises_the_capability_and_reaches_the_methods() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_vtc(dir.path(), &server)).await;
    let client = alice.client().await;

    let vtc = mimid_agent_jmap::vtc::CAPABILITY;
    assert_eq!(client.session["capabilities"][vtc], json!({}));
    let account = &client.session["accounts"][&client.account]["accountCapabilities"][vtc];
    assert_eq!(account["supportsRoomCalls"], json!(true));
    // The two that say this agent hosts the call's own MIMI room and
    // exports its per-epoch secret.
    assert_eq!(account["supportsMimiCalls"], json!(true));
    assert_eq!(account["supportsMimiKeyedCalls"], json!(true));
    assert_eq!(account["supportsRecording"], json!(false));

    // The methods are registered: an empty account has no calls, and
    // that is an answer rather than `unknownMethod`.
    let answer = client
        .call_using(&[vtc], "VTCCall/get", json!({"ids": null}))
        .await;
    assert_eq!(answer["list"], json!([]), "{answer}");

    alice.stop().await;
}

/// A call needs a `chatId`: mimid has no media plane of its own, so a
/// call that is not a MIMI room under a chat has nothing to join and
/// nothing to key from (`VtcBackend::create_call`). The refusal is a
/// `notCreated` entry rather than a method error, as JMAP requires of a
/// `/set`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_without_a_chat_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_vtc(dir.path(), &server)).await;
    let client = alice.client().await;

    let vtc = mimid_agent_jmap::vtc::CAPABILITY;
    let answer = client
        .call_using(
            &[vtc],
            "VTCCall/set",
            // `mediaTypes` is required by the draft and checked before
            // anything of mimid's, so it is given here: what is under
            // test is the missing `chatId`, not the crate's validation.
            json!({"create": {"k": {"callType": "room", "mediaTypes": ["audio"]}}}),
        )
        .await;
    assert!(
        answer["created"].as_object().is_none_or(|m| m.is_empty()),
        "a call with no chatId must not be created: {answer}"
    );
    let refusal = &answer["notCreated"]["k"];
    assert_eq!(refusal["type"], json!("invalidProperties"), "{answer}");
    assert!(
        refusal["description"]
            .as_str()
            .is_some_and(|text| text.contains("chatId")),
        "the refusal should say what is missing: {answer}"
    );

    alice.stop().await;
}

/// A call does not survive a restart of the agent: the `VTCCall` is held
/// in the backend's memory, is not among the types `JmapExt` keeps in
/// `ext["jmap"]`, and nothing re-projects an existing call room, because
/// `project` runs on the store's changes and a restart produces none for
/// a room already in state.
///
/// This test pins TODAY'S BEHAVIOUR rather than the behaviour anyone
/// wants, and it is here because it is the blocker for the JMAP-visible
/// half of bead mimid-1wgh.129: the media-secret recovery that bead adds
/// works (crates/mimid-agent-core/tests/call_rooms.rs
/// `a_rekey_gives_the_call_a_media_secret_again`), but a client cannot
/// reach it, because after a restart it cannot name the call at all.
/// Restoring a call across a restart is bead mimid-1wgh.114.14; when that
/// lands this test is the one to rewrite, into the `epochMoved` answer
/// the surface already has the shape for.
///
/// Oracle: the five types `persist.rs` lists in `before_save`
/// (`ChatContact`, `Chat`, `ChatBan`, `Message`, `ReadPosition`), which
/// is where a sixth would have to be, and `project_call_room`'s own
/// rustdoc, which says its id "is the same at every projection and
/// across restarts" -- true, and never used, because nothing projects it
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_does_not_survive_a_restart_yet() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let config = with_vtc(dir.path(), &server);

    let alice = Running::start(&config).await;
    let client = alice.client().await;
    let vtc = mimid_agent_jmap::vtc::CAPABILITY;

    // A chat, then a call in it.
    let chat = alice
        .store
        .create_room(alice.store.new_key(), "planning", &[])
        .await
        .unwrap();
    alice.store.save().await.unwrap();
    let created = client
        .call_using(
            &[vtc],
            "VTCCall/set",
            json!({"create": {"k": {
                "callType": "room",
                "mediaTypes": ["audio"],
                "chatId": chat.key,
            }}}),
        )
        .await;
    let call = created["created"]["k"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the call should be created: {created}"))
        .to_owned();

    let first = client
        .call_using(&[vtc], "VTCCall/exportMediaSecret", json!({"callId": call}))
        .await;
    let epoch = first["epoch"].as_u64().expect("an epoch");
    let secret = first["mediaSecret"].as_str().expect("a secret").to_owned();
    alice.stop().await;

    // The same state directory, as after a crash or an upgrade. The
    // secret was in memory and is gone; §4.4's leaf is punctured in the
    // store, so it cannot be derived again for this epoch.
    let restarted = Running::start(&config).await;
    let client = restarted.client().await;

    // The call is gone. Not "under another id": gone.
    let listed = client
        .call_using(&[vtc], "VTCCall/get", json!({"ids": null}))
        .await;
    assert_eq!(
        listed["list"],
        json!([]),
        "today a restart loses every VTCCall: {listed}"
    );

    // So the id the client holds names nothing, and the media-secret
    // recovery of bead mimid-1wgh.129 is unreachable from here: the
    // refusal is "no such call" rather than anything about epochs.
    let (status, answer) = client
        .post(&json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat", vtc],
            "methodCalls": [[
                "VTCCall/exportMediaSecret",
                {"accountId": client.account, "callId": call, "epoch": epoch},
                "c0",
            ]],
        }))
        .await;
    assert_eq!(status, 200, "{answer}");
    let response = &answer["methodResponses"][0];
    assert_eq!(response[0], json!("error"), "{answer}");
    assert_eq!(response[1]["type"], json!("invalidArguments"), "{answer}");

    // The call ROOM is still there, which is why bead mimid-1wgh.114.14 is
    // a projection problem and not a loss of state: everything needed to
    // rebuild the call survived.
    let has_call_room = {
        let state = restarted.store.state();
        state.rooms.values().any(|room| room.parent.is_some())
    };
    assert!(
        has_call_room,
        "the call room persists; only its projection is gone"
    );
    // And its media secret is gone for this epoch, which is what
    // mimid-1wgh.129 recovers once a client can name the call again.
    assert!(!secret.is_empty());
    let _ = epoch;

    restarted.stop().await;
}
