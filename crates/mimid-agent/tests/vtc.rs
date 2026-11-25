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

/// A call survives a restart of the agent, under the id the client
/// holds, and the media secret the restart lost comes back at a new
/// epoch (beads mimid-1wgh.114.14 and mimid-1wgh.129).
///
/// Oracles:
///
/// - draft-atwood-jmap-vtc-00 §`VTCCall/exportMediaSecret`: a client
///   that names an epoch the call has moved past is told which one is
///   current, and asks again for that one. That is the whole of the
///   client's part in this recovery, and it is code it already has for
///   an ordinary rekey. crate-jmap's handler sends that as the
///   method-level `stateMismatch`.
/// - The id: `VTCCall/set` minted it, so it is not the call room's key
///   and cannot be re-derived from the room. The store keeps the whole
///   object in the call room's `ext["jmap"]` for exactly that reason,
///   which is also what makes the client's `mediaTypes` and `subject`
///   survive -- a projection from the room alone knows neither
///   (`Render::new_call`'s limitations).
/// - mls-extensions-11 §4.4: the restart lost the epoch's media secret
///   for good, since the Exporter Tree leaf was punctured in the store
///   while the secret itself was only ever in memory. So the secret
///   after the restart must be a different one, at a later epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_survives_a_restart_and_comes_back_at_a_new_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let config = with_vtc(dir.path(), &server);

    let alice = Running::start(&config).await;
    let client = alice.client().await;
    let vtc = mimid_agent_jmap::vtc::CAPABILITY;

    // A chat, then a call in it, with the two things the room does not
    // carry: the media kinds and the subject.
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
                "mediaTypes": ["audio", "video"],
                "subject": "standup",
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

    // The same state directory, as after a crash or an upgrade.
    let restarted = Running::start(&config).await;
    let client = restarted.client().await;

    // The call is there, under the id the client held, with what the
    // client set on it.
    let listed = client
        .call_using(&[vtc], "VTCCall/get", json!({"ids": null}))
        .await;
    let calls = listed["list"].as_array().expect("a list");
    assert_eq!(calls.len(), 1, "one call should come back: {listed}");
    let restored = &calls[0];
    assert_eq!(restored["id"], json!(call), "the same id: {listed}");
    assert_eq!(restored["state"], json!("active"), "{listed}");
    assert_eq!(restored["subject"], json!("standup"), "{listed}");
    assert_eq!(
        restored["mediaTypes"],
        json!(["audio", "video"]),
        "the client's media kinds survive, which a projection from the \
         room alone could not give: {listed}"
    );
    assert_eq!(restored["chatId"], json!(chat.key), "{listed}");

    // The epoch the client was in is gone, and it is told which one is
    // current rather than handed a secret nobody else is using.
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
    assert_eq!(response[1]["type"], json!("stateMismatch"), "{answer}");
    let told = response[1]["description"].as_str().unwrap_or_default();
    assert!(
        told.contains("the call is in epoch"),
        "the refusal should name the epoch: {answer}"
    );

    // And asking for that epoch, as a client does after a rekey, gives a
    // secret: a different one, at a later epoch.
    let again = client
        .call_using(&[vtc], "VTCCall/exportMediaSecret", json!({"callId": call}))
        .await;
    let moved = again["epoch"].as_u64().expect("an epoch");
    assert!(
        moved > epoch,
        "the epoch should have moved past {epoch}: {again}"
    );
    assert!(
        told.contains(&moved.to_string()),
        "the refusal should have named this epoch: {answer}"
    );
    assert_ne!(
        again["mediaSecret"].as_str(),
        Some(secret.as_str()),
        "mls-extensions-11 §4.4: the old epoch's secret is gone for \
         good, so this must be another one: {again}"
    );

    restarted.stop().await;
}

/// A run with the VTC surface off does not throw the call away: an
/// IRC-only run, or one where the operator turned `[jmap] vtc` off and
/// back on, leaves what the records keep alone.
///
/// Oracle: decision mimid-1wgh.119 says no `VTCCall` may be served with
/// the surface off. It does not say the records must be rewritten, and
/// rewriting them would make turning the surface off destructive -- a
/// save during such a run would drop every stored call, since the
/// backend holds none to keep.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_with_the_surface_off_does_not_lose_the_call() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let on = with_vtc(dir.path(), &server);
    let off = config(&server, ALICE, dir.path(), "from-allowed");
    let vtc = mimid_agent_jmap::vtc::CAPABILITY;

    let alice = Running::start(&on).await;
    let client = alice.client().await;
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
    {
        let st = alice.store.state();
        for r in st.rooms.values() {
            eprintln!(
                "PROBE-CREATE key={} parent={:?} ext={}",
                r.key,
                r.parent,
                serde_json::to_string(&r.ext).unwrap()
            );
        }
    }
    let early = client
        .call_using(&[vtc], "VTCCall/get", json!({"ids": null}))
        .await;
    eprintln!(
        "PROBE-LIST {}",
        early["list"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap_or("?").to_owned())
            .collect::<Vec<_>>()
            .join(",")
    );
    eprintln!("PROBE-MINTED {call}");
    let kept_store = std::sync::Arc::clone(&alice.store);
    alice.stop().await;
    {
        let st = kept_store.state();
        for r in st.rooms.values() {
            eprintln!(
                "PROBE-STOP key={} parent={:?} ext={}",
                r.key,
                r.parent,
                serde_json::to_string(&r.ext).unwrap()
            );
        }
    }

    // A run with the surface off, which saves: a message arrives in the
    // chat from this side, so the save is not a no-op.
    let without = Running::start(&off).await;
    let key = without.store.new_key();
    without
        .store
        .send(key, &chat.key, "a line while calls are off", &[])
        .await
        .unwrap();
    without.store.save().await.unwrap();
    {
        let st = without.store.state();
        for r in st.rooms.values() {
            eprintln!(
                "PROBE-OFF key={} parent={:?} ext={}",
                r.key,
                r.parent,
                serde_json::to_string(&r.ext).unwrap()
            );
        }
    }
    without.stop().await;
    // Back on, the call is still the one the client knew.
    let again = Running::start(&on).await;
    {
        let st = again.store.state();
        for r in st.rooms.values() {
            eprintln!(
                "PROBE-ON key={} parent={:?} ext={}",
                r.key,
                r.parent,
                serde_json::to_string(&r.ext).unwrap()
            );
        }
    }
    let client = again.client().await;
    let listed = client
        .call_using(&[vtc], "VTCCall/get", json!({"ids": null}))
        .await;
    assert_eq!(
        listed["list"][0]["id"],
        json!(call),
        "a run with calls off must not drop the call: {listed}"
    );
    again.stop().await;
}

/// A call room the user has left does not come back as a live call, and
/// a call they are still in does: two calls, one of them hung up on,
/// and exactly one comes back.
///
/// Oracle: `VTCCall.state` (draft-atwood-jmap-vtc-00 §State Machine)
/// says `active` means the call is running and joinable. A call whose
/// own room this agent is not in is neither, and the VTC methods say so
/// already: `AgentChat::call_room_key` refuses with `notFound`, "this
/// agent is not in the call's room". Restoring the object would make
/// `/get` and the methods disagree.
///
/// Both halves are asserted here because either alone is weak: a run
/// that restores nothing passes the first, and one that restores
/// everything passes the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_room_the_user_has_left_is_not_restored() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let config = with_vtc(dir.path(), &server);
    let vtc = mimid_agent_jmap::vtc::CAPABILITY;

    let alice = Running::start(&config).await;
    let client = alice.client().await;
    let hung_up = alice
        .store
        .create_room(alice.store.new_key(), "planning", &[])
        .await
        .unwrap();
    let still_in = alice
        .store
        .create_room(alice.store.new_key(), "standup", &[])
        .await
        .unwrap();
    alice.store.save().await.unwrap();

    let call_in = |chat: String| {
        let client = &client;
        async move {
            let created = client
                .call_using(
                    &[vtc],
                    "VTCCall/set",
                    json!({"create": {"k": {
                        "callType": "room",
                        "mediaTypes": ["audio"],
                        "chatId": chat,
                    }}}),
                )
                .await;
            created["created"]["k"]["id"]
                .as_str()
                .unwrap_or_else(|| panic!("the call should be created: {created}"))
                .to_owned()
        }
    };
    let _gone = call_in(hung_up.key.to_string()).await;
    let live = call_in(still_in.key.to_string()).await;

    // Out of the first call's own room, which is what hanging up on the
    // MIMI side is. The call's own room is the one whose parent is that
    // chat (room-policy-04 §5 `parent_room`).
    let room = {
        let state = alice.store.state();
        state
            .rooms
            .values()
            .find(|room| room.parent.as_deref() == Some(hung_up.uri.as_str()))
            .map(|room| room.key.clone())
            .expect("the call's own room")
    };
    alice.store.leave(&room).await.unwrap();
    alice.store.save().await.unwrap();
    alice.stop().await;

    let restarted = Running::start(&config).await;
    let client = restarted.client().await;
    let listed = client
        .call_using(&[vtc], "VTCCall/get", json!({"ids": null}))
        .await;
    let ids: Vec<&str> = listed["list"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|call| call["id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec![live.as_str()],
        "only the call whose room the user is still in comes back: {listed}"
    );

    // The room record of the one they left is still there: this is about
    // what is shown, not about forgetting the room.
    let kept = {
        let state = restarted.store.state();
        state.rooms.contains_key(&room)
    };
    assert!(kept, "the call room itself stays in the store");

    restarted.stop().await;
}

/// Starting a call makes one `VTCCall`, and the call room's record
/// keeps that one.
///
/// `Store::start_call` records the call's own room before it returns,
/// and any save from then until the new `VTCCall` names the room
/// projects a second call for it (`project_call_room`, which is what
/// gives the receiving side its call, bead mimid-1wgh.114.11). The save
/// that does it is the runner's, on its own task, which is why the
/// room's key is claimed rather than the writes ordered
/// (`vtc_backend::Starting`).
///
/// Oracles:
///
/// - RFC 8620 §5.1, a `/get` of all ids: one call was started, so one
///   object names it. Two would be two calls in one room to every
///   client, with only one of them the id `VTCCall/set` returned.
/// - The record is the deterministic half, and the half a restart
///   depends on (bead mimid-1wgh.114.14): whichever object won, the
///   call room's `ext["jmap"]` is what comes back, so it has to be the
///   call `/set` returned, with the `mediaTypes` the client asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn starting_a_call_makes_one_and_the_record_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_vtc(dir.path(), &server)).await;
    let client = alice.client().await;
    let vtc = mimid_agent_jmap::vtc::CAPABILITY;

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

    let listed = client
        .call_using(&[vtc], "VTCCall/get", json!({"ids": null}))
        .await;
    let ids: Vec<&str> = listed["list"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec![call.as_str()],
        "one call started, one VTCCall, under the id /set returned: {listed}"
    );

    // A save of this agent's own, so the record is written from what the
    // backend holds now.
    alice.store.save().await.unwrap();
    let kept = {
        let state = alice.store.state();
        state
            .rooms
            .values()
            .find(|room| room.parent.as_deref() == Some(chat.uri.as_str()))
            .and_then(|room| room.ext.get("jmap").cloned())
            .expect("the call room keeps a JMAP object")
    };
    assert_eq!(kept["id"], json!(call), "the record keeps the call: {kept}");
    assert_eq!(
        kept["mediaTypes"],
        json!(["audio"]),
        "with what the client asked for: {kept}"
    );

    alice.stop().await;
}

/// A call the records keep that is not a `VTCCall` does not stop the
/// agent, and a call room that keeps nothing still gives its call back.
///
/// Both halves are the upgrade path. A store written before decision
/// mimid-1wgh.120 was corrected (bead mimid-1wgh.121) gave a call room a
/// Chat, which will never be a `VTCCall`; a store written after that
/// correction and before bead mimid-1wgh.114.14 gave it nothing at all.
/// Neither may cost the user their agent, and the second should give the
/// call back as the receiving side's projection makes it
/// (`Render::new_call`), with the media kinds and subject it cannot know.
///
/// A run with `[jmap] vtc` off is what plants them: with the surface off
/// a save leaves a call room's `ext["jmap"]` exactly as it is, the same
/// property `a_run_with_the_surface_off_does_not_lose_the_call` rests on.
///
/// Oracle: `AgentChat::restore_calls`, which skips and counts a call it
/// cannot put back rather than refusing to open. One stale row of a call
/// nobody is in must not cost the user every chat they have.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stored_call_that_is_not_a_call_does_not_stop_the_agent() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let off = config(&server, ALICE, dir.path(), "from-allowed");
    let on = with_vtc(dir.path(), &server);
    let vtc = mimid_agent_jmap::vtc::CAPABILITY;

    // Two chats with a call each, made with the surface off, so no
    // VTCCall exists for either and the records keep what is put there.
    let alice = Running::start(&off).await;
    let mut chats = Vec::new();
    for name in ["planning", "standup"] {
        let chat = alice
            .store
            .create_room(alice.store.new_key(), name, &[])
            .await
            .unwrap();
        alice.store.save().await.unwrap();
        alice
            .store
            .start_call_with(
                alice.store.new_key(),
                &chat.key,
                &mimid_agent_store::action::CallOptions::default(),
            )
            .await
            .unwrap();
        chats.push(chat);
    }
    alice.store.save().await.unwrap();

    let call_room_of = |chat: &str| {
        let state = alice.store.state();
        state
            .rooms
            .values()
            .find(|room| room.parent.as_deref() == Some(chat))
            .map(|room| room.key.clone())
            .expect("each chat has a call room")
    };
    let spoiled = call_room_of(&chats[0].uri);
    let bare = call_room_of(&chats[1].uri);

    // The first keeps a Chat, as a store from before bead mimid-1wgh.121
    // does. The second keeps nothing, which is what a store from after
    // it and before mimid-1wgh.114.14 has.
    {
        let mut state = alice.store.state();
        let room = state.rooms.get_mut(&spoiled).expect("the call room");
        room.ext.insert(
            "jmap".to_owned(),
            json!({"createdAt": "2026-11-25T12:00:00Z", "members": []}),
        );
    }
    alice.store.save().await.unwrap();
    {
        let state = alice.store.state();
        assert!(
            !state.rooms[&bare].ext.contains_key("jmap"),
            "a run with calls off writes no JMAP object for a call room"
        );
    }
    alice.stop().await;

    // The agent opens, which is the first half.
    let restarted = Running::start(&on).await;
    let client = restarted.client().await;
    let listed = client
        .call_using(&[vtc], "VTCCall/get", json!({"ids": null}))
        .await;
    let ids: Vec<&str> = listed["list"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|call| call["id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec![bare.as_str()],
        "the call that is not a call is skipped, and the one projected \
         from its room comes back under the room's key: {listed}"
    );
    assert_eq!(
        listed["list"][0]["mediaTypes"],
        json!([]),
        "a call projected from the room alone knows no media kinds: {listed}"
    );
    assert_eq!(listed["list"][0]["chatId"], json!(chats[1].key), "{listed}");

    // And the room whose object was wrong is still in the store: this
    // skips showing a call, it does not forget a room.
    let kept = {
        let state = restarted.store.state();
        state.rooms.contains_key(&spoiled)
    };
    assert!(kept, "the call room itself stays in the store");

    restarted.stop().await;
}

/// The capability says a call here is between two people, and a call in
/// a chat of more than two is refused rather than created
/// (decision on bead mimid-1wgh.114.15, Mark 2026-11-25).
///
/// Oracles:
///
/// - draft-atwood-jmap-vtc-00 §`maxParticipantsPerCall`: "`null` means
///   no server-imposed limit". mimid has one, because a signal reaches
///   every member of the call's room and nothing in it says which peer
///   it is for, so three or more cannot complete negotiation. Saying
///   `null` told a client the opposite of the truth.
/// - The refusal happens BEFORE the call room is hosted, so a refused
///   create leaves no room behind and posts no announcement. An
///   announcement for a call nobody can join is worse than a refusal
///   that says why.
///
/// The chat's participant list is what the ceiling reads, and what
/// `Store::start_call` invites (`among` is `None` from here, bead
/// mimid-1wgh.131), so the test sets that list rather than standing up
/// two more daemons.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_in_a_chat_of_more_than_two_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_vtc(dir.path(), &server)).await;
    let client = alice.client().await;
    let vtc = mimid_agent_jmap::vtc::CAPABILITY;

    // Per account, as RFC 8620 §2 puts a capability's settings
    // (`the_switch_advertises_the_capability_and_reaches_the_methods`).
    let advertised = &client.session["accounts"][&client.account]["accountCapabilities"][vtc];
    assert_eq!(
        advertised["maxParticipantsPerCall"],
        json!(2),
        "the ceiling is advertised, not left as null: {advertised}"
    );

    let chat = alice
        .store
        .create_room(alice.store.new_key(), "planning", &[])
        .await
        .unwrap();
    alice.store.save().await.unwrap();

    // Two more people in the chat, so the call room would hold three.
    {
        let mut state = alice.store.state();
        let room = state.rooms.get_mut(&chat.key).expect("the chat");
        for user in ["mimi://a.example/u/carol", "mimi://a.example/u/dave"] {
            room.participants
                .push(mimid_agent_store::record::Participant {
                    user: user.to_owned(),
                    role: None,
                });
        }
    }

    let (status, answer) = client
        .post(&json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat", vtc],
            "methodCalls": [[
                "VTCCall/set",
                {"accountId": client.account, "create": {"k": {
                    "callType": "room",
                    "mediaTypes": ["audio"],
                    "chatId": chat.key,
                }}},
                "c0",
            ]],
        }))
        .await;
    assert_eq!(status, 200, "{answer}");
    let refusal = &answer["methodResponses"][0][1]["notCreated"]["k"];
    assert_eq!(refusal["type"], json!("invalidProperties"), "{answer}");
    let why = refusal["description"].as_str().unwrap_or_default();
    assert!(
        why.contains("two"),
        "the refusal should say a call here is between two: {answer}"
    );

    // Nothing was left behind: no call room, and no announcement in the
    // chat for a call that does not exist.
    let (call_rooms, messages) = {
        let state = alice.store.state();
        (
            state.rooms.values().filter(|r| r.parent.is_some()).count(),
            state
                .messages
                .values()
                .filter(|m| m.room == chat.key)
                .count(),
        )
    };
    assert_eq!(call_rooms, 0, "a refused call hosts no room");
    assert_eq!(messages, 0, "and announces nothing");

    alice.stop().await;
}
