//! The catchUp operation at the hub (docs/design/mimi-catchup.md §5;
//! INVENTED, NOT FROM SPEC, bead mimid-1wgh.37.104).
//!
//! Oracles:
//!
//! - §5: the answer is the fanouts after the sequence the follower
//!   holds, in hub order, each with its sequence, no more than it asked
//!   for, plus the highest it may know about so it can tell whether to
//!   ask again.
//! - §5.1, a MUST: a request older than the window is answered
//!   DISTINCTLY and never by returning the oldest still held, which
//!   would look complete and hide the loss.
//! - §8: a provider may be served the sequences it was a destination of.
//!   One that was never a destination is refused rather than answered
//!   emptily, because an empty answer carries a sequence number.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/submit.rs"]
mod submit;

use common::*;
use mimi_protocol::tls_codec::Serialize;
use mimi_protocol::{CatchUpRequest, CatchUpResponse, CatchUpResult};

/// The `highestSequence` of a successful answer.
fn highest(response: &CatchUpResponse) -> u64 {
    match &response.result {
        CatchUpResult::Success {
            highest_sequence, ..
        } => *highest_sequence,
        other => panic!("not a served answer: {other:?}"),
    }
}
use mimid_server::config::Domain;
use mimid_server::hub::{Hub, HubError};
use mimid_server::store::Store;
use submit::*;

const START_MS: u64 = 1_800_000_000_000;

fn from(domain: &str) -> Domain {
    Domain::try_from(domain.to_owned()).unwrap()
}

fn ask(sequence: u64, limit: u32) -> Vec<u8> {
    CatchUpRequest {
        from: sequence,
        limit,
    }
    .to_body()
    .unwrap()
}

/// A hub hosting ROOM_ID with `count` accepted messages, each fanned out
/// to a.example (alice's own, the origin) and b.example (bob's).
async fn hub_with_messages(dir: &tempfile::TempDir, count: usize) -> (Store, Hub) {
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_stepping_hub(&path, START_MS).await;
    let mut alice = create_room(&hub, ROOM_ID, b"group-catchup").await;
    for i in 0..count {
        let salt = [u8::try_from(i).unwrap(); 16];
        let (message, _) = alice.franked(format!("m{i}").as_bytes(), &salt);
        let request = submit_request(&message, ALICE);
        hub.submit_message(ROOM_ID, &from("a.example"), &request)
            .await
            .unwrap();
    }
    (store, hub)
}

fn answer(body: &[u8]) -> CatchUpResponse {
    let decoded = CatchUpResponse::decode(body).expect("the answer decodes");
    // Decode, then re-encode byte-identically, as every other body test
    // in this workspace does.
    assert_eq!(decoded.tls_serialize_detached().unwrap(), body);
    decoded
}

/// Oracle: §5. Everything after the sequence the follower holds, in
/// order, with the highest it may know about.
#[tokio::test]
async fn an_in_window_request_returns_the_range_after_what_the_follower_holds() {
    let dir = tempfile::tempdir().unwrap();
    let (_store, hub) = hub_with_messages(&dir, 3).await;

    let all = answer(
        &hub.catch_up(ROOM_ID, &from("b.example"), &ask(0, 256))
            .await
            .unwrap(),
    );
    let sequences: Vec<u64> = all.entries().iter().map(|e| e.sequence).collect();
    assert!(
        sequences.windows(2).all(|w| w[0] < w[1]),
        "in hub order: {sequences:?}"
    );
    assert_eq!(
        highest(&all),
        *sequences.last().expect("some fanout"),
        "caught up: the last entry is the highest it may know about"
    );
    assert!(all.caught_up());

    // Holding the first, it is served the rest and nothing it has.
    let held = sequences[0];
    let rest = answer(
        &hub.catch_up(ROOM_ID, &from("b.example"), &ask(held, 256))
            .await
            .unwrap(),
    );
    assert_eq!(
        rest.entries()
            .iter()
            .map(|e| e.sequence)
            .collect::<Vec<_>>(),
        sequences[1..].to_vec(),
        "after what it holds, not including it"
    );
}

/// Oracle: §5 -- a hub may return fewer than asked for, and the highest
/// is what tells the follower there is more.
#[tokio::test]
async fn the_limit_is_honoured_and_the_answer_says_there_is_more() {
    let dir = tempfile::tempdir().unwrap();
    let (_store, hub) = hub_with_messages(&dir, 3).await;

    let one = answer(
        &hub.catch_up(ROOM_ID, &from("b.example"), &ask(0, 1))
            .await
            .unwrap(),
    );
    assert_eq!(one.entries().len(), 1, "no more than asked for");
    assert!(
        !one.caught_up(),
        "and it knows to ask again: {} is below {}",
        one.entries()[0].sequence,
        highest(&one)
    );
}

/// Oracle: §5.1, the MUST. A request reaching before what the hub holds
/// is refused DISTINCTLY -- never served short, which would look
/// complete and hide the loss.
#[tokio::test]
async fn an_out_of_window_request_is_refused_and_not_served_short() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = hub_with_messages(&dir, 3).await;

    // The REAL retention sweep takes the oldest fanouts, so this holds
    // §6's coupling as well as §5.1: catch-up reaches exactly as far
    // back as the hub log, and a hand-written DELETE would not prove
    // that the sweep is what moves it.
    let (before, assigned) = store.fanout_window(ROOM_ID).await.unwrap();
    assert_eq!(before, Some(1), "the room starts at its first fanout");
    store
        .delete_expired_events(START_MS + 2_000, 1)
        .await
        .unwrap();
    let (oldest, _) = store.fanout_window(ROOM_ID).await.unwrap();
    let oldest = oldest.expect("the sweep left some fanout");
    assert!(oldest > 1, "the sweep moved the window: {oldest}");

    // A refusal is an ANSWER carrying a response code, not an error: an
    // HTTP status can be produced by something that is not the hub, and
    // this answer makes a follower tell its users history is
    // permanently missing (bead mimid-1wgh.37.104.14).
    let refused = answer(
        &hub.catch_up(ROOM_ID, &from("b.example"), &ask(0, 256))
            .await
            .expect("a refusal is an answer, not an error"),
    );
    match refused.result {
        CatchUpResult::OutOfWindow { oldest_held } => {
            assert!(
                oldest_held > 1,
                "it asked for everything after 0 and is told what the hub \
                 does hold: {oldest_held}"
            );
            assert_eq!(oldest_held, oldest, "which is the window's oldest");
        }
        other => panic!("not the distinct refusal: {other:?}"),
    }
    assert!(
        refused.entries().is_empty(),
        "and it serves nothing: a short answer would look complete"
    );

    // The same request one sequence later is in window and is served,
    // so the refusal is about the range and not the requester.
    let served = answer(
        &hub.catch_up(ROOM_ID, &from("b.example"), &ask(oldest, 256))
            .await
            .unwrap(),
    );
    assert!(!served.entries().is_empty(), "in window, so served");
    assert!(assigned > 0);
}

/// Oracle: §8. A provider that was never a destination is refused, not
/// answered emptily: an empty answer carries the highest sequence and
/// would tell a stranger how much traffic the room has (§8.2).
#[tokio::test]
async fn a_provider_that_was_never_a_destination_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (_store, hub) = hub_with_messages(&dir, 2).await;

    let refused = answer(
        &hub.catch_up(ROOM_ID, &from("z.example"), &ask(0, 256))
            .await
            .expect("a refusal is an answer, not an error"),
    );
    assert!(
        matches!(refused.result, CatchUpResult::NotAuthorized),
        "not the entitlement refusal: {:?}",
        refused.result
    );
    assert!(refused.entries().is_empty());
}

/// A room this hub does not host is refused in the body; a body that
/// does not decode is a transport-level error.
///
/// The split is the point: a request this hub cannot PARSE has no
/// response code to carry, so it stays an error, while a request it
/// parsed and declined is an answer.
#[tokio::test]
async fn an_unknown_room_is_refused_and_a_bad_body_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (_store, hub) = hub_with_messages(&dir, 1).await;

    // An unknown room is an ANSWER carrying noSuchRoom, not an error:
    // the refusal belongs in the body so that only the hub can say it
    // (bead mimid-1wgh.37.104.14). A hub that does not wish to reveal
    // whether a room exists answers notAuthorized here instead.
    let unknown = answer(
        &hub.catch_up("mimi://a.example/r/nope", &from("b.example"), &ask(0, 1))
            .await
            .expect("a refusal is an answer"),
    );
    assert!(
        matches!(unknown.result, CatchUpResult::NoSuchRoom),
        "not the no-such-room refusal: {:?}",
        unknown.result
    );
    assert!(unknown.entries().is_empty());
    assert!(matches!(
        hub.catch_up(ROOM_ID, &from("b.example"), b"short")
            .await
            .expect_err("undecodable"),
        HubError::InvalidRequest(_)
    ));
    // A limit of zero asks for nothing, which the codec refuses.
    assert!(matches!(
        hub.catch_up(ROOM_ID, &from("b.example"), &ask(0, 0))
            .await
            .expect_err("a limit of zero"),
        HubError::InvalidRequest(_)
    ));
}

/// A served fanout is byte-identical to the one that was delivered.
///
/// This is the assertion the handler's comment rests on. The stored
/// bytes are the FanoutMessage exactly as sent, and the handler decodes
/// them into a typed entry which the answer then re-encodes -- so there
/// is a round trip between what was delivered and what is served.
/// AGENTS.md says never to re-encode before verifying, because the
/// follower checks the frank over the bytes it receives, and a hub whose
/// round trip changed one byte would turn its own answer into a franking
/// failure at the other end with no way to notice here.
///
/// It holds because mimid decodes strictly and rejects non-canonical
/// encodings, so the round trip is the identity for anything it will
/// accept. If this ever becomes hard to keep true, the fix is to make
/// the entry carry opaque bytes and pass them through untouched.
#[tokio::test]
async fn a_served_fanout_is_byte_identical_to_what_was_delivered() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = hub_with_messages(&dir, 2).await;

    let served = answer(
        &hub.catch_up(ROOM_ID, &from("b.example"), &ask(0, 256))
            .await
            .unwrap(),
    );
    assert!(!served.entries().is_empty());
    for entry in served.entries() {
        let delivered = store
            .fanout_since(ROOM_ID, "b.example", entry.sequence - 1, 1)
            .await
            .unwrap();
        let (sequence, bytes) = delivered.first().expect("the stored fanout");
        assert_eq!(*sequence, entry.sequence);
        assert_eq!(
            entry.message.tls_serialize_detached().unwrap(),
            *bytes,
            "sequence {} was re-encoded differently from how it was sent",
            entry.sequence
        );
    }
}
