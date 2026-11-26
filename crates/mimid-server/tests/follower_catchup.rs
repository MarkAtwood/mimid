//! A follower asking its hub for the fanout it missed
//! (docs/design/mimi-catchup.md §5, §10; INVENTED, NOT FROM SPEC, bead
//! mimid-1wgh.37.104.4).
//!
//! The hub here is a mock serving a directory and a scripted catchUp, so
//! these hold the FOLLOWER's half: that it asks from the right place,
//! applies what comes back through the live path, stops when caught up,
//! and leaves a hub that does not offer catch-up alone. A real hub
//! answering a real follower is bead mimid-1wgh.37.104.5.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/notify.rs"]
mod common_notify;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "fixtures/notify/generate.rs"]
mod generate;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use common_notify::*;
use mimi_protocol::tls_codec::Deserialize;
use mimi_protocol::{CatchUpEntry, CatchUpRequest, CatchUpResponse, FanoutMessage};
use mimid_server::config::BaseUrl;

/// A directory with every protocol-07 §5.1 member and no `catchUp`: a
/// hub that does not support catch-up.
const WITHOUT: &str = r#"{
  "keyMaterial": "BASE/v1/keyMaterial/{targetUser}",
  "update": "BASE/v1/update/{roomId}",
  "notify": "BASE/v1/notify/{roomId}",
  "submitMessage": "BASE/v1/submitMessage/{roomId}",
  "groupInfo": "BASE/v1/groupInfo/{roomId}",
  "requestConsent": "BASE/v1/requestConsent/{targetDomain}",
  "updateConsent": "BASE/v1/updateConsent/{requesterDomain}",
  "identifierQuery": "BASE/v1/identifierQuery/{domain}",
  "reportAbuse": "BASE/v1/reportAbuse/{roomId}",
  "proxyDownload": "BASE/v1/proxyDownload/{downloadUrl}"
}"#;

#[derive(Clone, Default)]
struct HubState {
    directory: Arc<String>,
    /// One answer per catchUp request, in order.
    answers: Arc<Mutex<Vec<CatchUpResponse>>>,
    /// The `from` of each request received, in order.
    asked: Arc<Mutex<Vec<u64>>>,
    /// Answer every request with the same thing, never consuming it: a
    /// hub whose answer does not advance.
    repeat: bool,
}

/// A mock hub: a directory, and a catchUp that answers from a script.
struct MockHub {
    base: BaseUrl,
    state: HubState,
}

impl MockHub {
    async fn start(with_catch_up: bool, answers: Vec<CatchUpResponse>) -> Self {
        Self::start_inner(with_catch_up, answers, false).await
    }

    /// A hub that answers every request with `answer`, forever.
    async fn start_repeating(answer: CatchUpResponse) -> Self {
        Self::start_inner(true, vec![answer], true).await
    }

    async fn start_inner(with_catch_up: bool, answers: Vec<CatchUpResponse>, repeat: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut directory = WITHOUT.replace("BASE", &base);
        if with_catch_up {
            directory = directory.replace(
                "\n}",
                &format!(",\n  \"catchUp\": \"{base}/v1/catchUp/{{roomId}}\"\n}}"),
            );
        }
        let state = HubState {
            directory: Arc::new(directory),
            answers: Arc::new(Mutex::new(answers)),
            asked: Arc::default(),
            repeat,
        };
        let app = Router::new()
            .route(
                "/.well-known/mimi-protocol-directory",
                get(|State(s): State<HubState>| async move { s.directory.to_string() }),
            )
            .route("/v1/catchUp/{roomId}", post(serve_catch_up))
            .with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            base: BaseUrl::try_from(base).unwrap(),
            state,
        }
    }

    fn asked(&self) -> Vec<u64> {
        self.state.asked.lock().unwrap().clone()
    }
}

async fn serve_catch_up(State(state): State<HubState>, body: axum::body::Bytes) -> Response {
    let request = CatchUpRequest::decode(&body).expect("a well-formed request");
    state.asked.lock().unwrap().push(request.from);
    let answer = if state.repeat {
        state.answers.lock().unwrap().first().cloned()
    } else {
        state.answers.lock().unwrap().pop()
    };
    match answer {
        Some(answer) => answer.to_body().unwrap().into_response(),
        None => axum::http::StatusCode::GONE.into_response(),
    }
}

fn entry(sequence: u64, fanout: &[u8]) -> CatchUpEntry {
    CatchUpEntry {
        sequence,
        message: FanoutMessage::tls_deserialize_exact(fanout).expect("a fanout decodes"),
    }
}

/// A follower whose hub is `hub`, following rooms of a.example.
async fn follower_of(hub: &MockHub) -> Provider {
    Provider::start_with_peers(
        FOLLOWER_DOMAIN,
        BTreeMap::from([(domain_of("a.example"), hub.base.clone())]),
    )
    .await
}

/// Puts the follower at sequence 1 and then jumps to 3, so sequence 2 is
/// the recorded gap.
async fn with_a_gap(p: &Provider) {
    p.follower
        .accept_fanout_at(
            ROOM,
            &domain_of("a.example"),
            &application_fanout(T1, APPLICATION_1),
            1,
        )
        .await
        .unwrap();
    p.follower
        .accept_fanout_at(
            ROOM,
            &domain_of("a.example"),
            &commit_fanout(T3, COMMIT_CAROL),
            3,
        )
        .await
        .unwrap();
    let at = p.store.follower_position(ROOM).await.unwrap().unwrap();
    assert_eq!(at.gap_from, Some(2), "2 is missing");
}

/// Oracle: §5. The gap is asked for from one below the first missing
/// sequence, because `from` means "after this", and what comes back is
/// applied so the follower holds it.
#[tokio::test]
async fn a_follower_fills_its_gap_from_the_hub() {
    let answer = CatchUpResponse {
        highest_sequence: 3,
        entries: vec![entry(2, &application_fanout(T2, APPLICATION_2))],
    };
    let hub = MockHub::start(true, vec![answer]).await;
    let p = follower_of(&hub).await;
    with_a_gap(&p).await;

    let recovered = p.follower.fill_gap(ROOM).await.unwrap();
    assert_eq!(recovered, 1, "the one missing fanout");
    assert_eq!(hub.asked(), vec![1], "asked from one below the gap");

    // The gap is cleared, and the recovered fanout is held exactly as a
    // delivered one would be.
    let at = p.store.follower_position(ROOM).await.unwrap().unwrap();
    assert_eq!(at.gap_from, None, "filled, so no gap");
    assert_eq!(at.highest, 3);
}

/// Oracle: §5. A hub that publishes no `catchUp` template does not
/// support catch-up, which is the whole of the negotiation: the follower
/// asks nothing and does not treat it as an error.
#[tokio::test]
async fn a_hub_without_the_template_is_left_alone() {
    let hub = MockHub::start(false, Vec::new()).await;
    let p = follower_of(&hub).await;
    with_a_gap(&p).await;

    let recovered = p.follower.fill_gap(ROOM).await.unwrap();
    assert_eq!(recovered, 0, "nothing recovered and no error");
    assert!(
        hub.asked().is_empty(),
        "and nothing was asked: {:?}",
        hub.asked()
    );
    let at = p.store.follower_position(ROOM).await.unwrap().unwrap();
    assert_eq!(
        at.gap_from,
        Some(2),
        "the gap stays recorded: this hub cannot help, which is not the \
         same as there being nothing missing"
    );
}

/// A room with no recorded gap asks nothing, which is what keeps the
/// `/notify` path cheap: it records a gap and returns, and only a room
/// with one costs a request.
#[tokio::test]
async fn a_room_with_no_gap_asks_nothing() {
    let hub = MockHub::start(true, Vec::new()).await;
    let p = follower_of(&hub).await;
    p.follower
        .accept_fanout_at(
            ROOM,
            &domain_of("a.example"),
            &application_fanout(T1, APPLICATION_1),
            1,
        )
        .await
        .unwrap();

    assert_eq!(p.follower.fill_gap(ROOM).await.unwrap(), 0);
    assert!(
        p.follower
            .fill_gap("mimi://a.example/r/never")
            .await
            .unwrap()
            == 0
    );
    assert!(hub.asked().is_empty(), "no gap, no request");
}

/// A gap wider than one answer takes several, each asking from the last
/// sequence the one before it gave.
///
/// Oracle: §5 -- a hub may return fewer than asked for, and
/// `MAX_CATCH_UP_ENTRIES` caps an answer at 256, so a follower far
/// behind must ask again. The answers here are scripted short to make
/// that happen without 256 fixtures.
///
/// This is the shape the first version got wrong: it stopped when the
/// ANSWER said the hub had more, which asks again for sequences the
/// follower already holds above the gap. The run has to abut what it
/// already had, which is what `target` is.
#[tokio::test]
async fn a_wide_gap_takes_several_answers() {
    // The follower will hold 1 and then jump to 5, so 2, 3 and 4 are
    // missing. Answers pop from the end, so the last listed is served
    // first.
    let hub = MockHub::start(
        true,
        vec![
            CatchUpResponse {
                highest_sequence: 5,
                entries: vec![entry(4, &commit_fanout(T2, COMMIT_CAROL))],
            },
            CatchUpResponse {
                highest_sequence: 5,
                entries: vec![
                    entry(2, &application_fanout(T2, APPLICATION_2)),
                    entry(3, &application_fanout(T3, APPLICATION_1)),
                ],
            },
        ],
    )
    .await;
    let p = follower_of(&hub).await;
    p.follower
        .accept_fanout_at(
            ROOM,
            &domain_of("a.example"),
            &application_fanout(T1, APPLICATION_1),
            1,
        )
        .await
        .unwrap();
    p.follower
        .accept_fanout_at(
            ROOM,
            &domain_of("a.example"),
            &commit_fanout(T3, COMMIT_CAROL),
            5,
        )
        .await
        .unwrap();
    assert_eq!(
        p.store
            .follower_position(ROOM)
            .await
            .unwrap()
            .unwrap()
            .gap_from,
        Some(2)
    );

    let recovered = p.follower.fill_gap(ROOM).await.unwrap();
    assert_eq!(recovered, 3, "2, 3 and 4");
    assert_eq!(
        hub.asked(),
        vec![1, 3],
        "from one below the gap, then from the last it was given"
    );
    assert_eq!(
        p.store
            .follower_position(ROOM)
            .await
            .unwrap()
            .unwrap()
            .gap_from,
        None,
        "the run reached what the follower already held, so it is whole"
    );
}

/// Oracle: §5.1. A hub that no longer holds the missing range answers
/// `410`, which is an ANSWER and not a failure: the fanout is gone for
/// good, retrying cannot help, so it is recorded against the room
/// instead of returned as an error.
///
/// This is the case the whole design exists for. Before it, a follower
/// that missed a `/notify` lost that ciphertext and nobody was told.
#[tokio::test]
async fn an_unfillable_gap_is_recorded_rather_than_retried() {
    // No scripted answers, so the mock serves 410.
    let hub = MockHub::start(true, Vec::new()).await;
    let p = follower_of(&hub).await;
    with_a_gap(&p).await;

    let recovered = p.follower.fill_gap(ROOM).await.unwrap();
    assert_eq!(recovered, 0, "nothing could be recovered");
    assert_eq!(hub.asked(), vec![1], "it did ask, once");

    let at = p.store.follower_position(ROOM).await.unwrap().unwrap();
    assert!(at.unfillable, "and recorded that it cannot be filled");
    assert_eq!(
        at.gap_from,
        Some(2),
        "the gap stays recorded: it is still missing, and now known to \
         be unfillable"
    );
}

/// An unfillable gap reaches the provider's own JMAP clients, which is
/// what makes it not-silent: it counts against the room's `gone`, so a
/// `/changes` from the state before it cannot be followed and the client
/// resyncs (RFC 8620 §5.6 `cannotCalculateChanges`; decisions
/// mimid-1wgh.82, mimid-1wgh.83).
///
/// Recording it twice counts once. A gap is one fact however many times
/// anything retries, and counting per attempt would move the cursor
/// forever and make every client resync forever.
#[tokio::test]
async fn an_unfillable_gap_moves_what_clients_follow() {
    let hub = MockHub::start(true, Vec::new()).await;
    let p = follower_of(&hub).await;
    with_a_gap(&p).await;
    let before: i64 = sqlx::query_scalar("SELECT SUM(gone) FROM follower_room")
        .fetch_one(&p.db)
        .await
        .unwrap();

    p.follower.fill_gap(ROOM).await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT SUM(gone) FROM follower_room")
        .fetch_one(&p.db)
        .await
        .unwrap();
    assert_eq!(
        after,
        before + 1,
        "the count a client's state is compared against has moved, so \
         /changes refuses and the client resyncs"
    );

    // Asked again, it is already recorded: the count does not move.
    p.follower.fill_gap(ROOM).await.unwrap();
    let again: i64 = sqlx::query_scalar("SELECT SUM(gone) FROM follower_room")
        .fetch_one(&p.db)
        .await
        .unwrap();
    assert_eq!(again, after, "one gap, counted once, however often asked");
}

/// A probe finds fanout that no jump could reveal: the tail of a room
/// that then went quiet (decision mimid-1wgh.37.104.11).
///
/// Oracle: the follower holds 1 and nothing else ever arrives. Jump
/// detection cannot help -- there is no later fanout to jump -- so
/// without the probe this provider's users silently miss sequence 2
/// forever. The probe asks from what it holds and is told.
#[tokio::test]
async fn a_probe_finds_a_tail_no_jump_would_reveal() {
    let hub = MockHub::start(
        true,
        vec![CatchUpResponse {
            highest_sequence: 2,
            entries: vec![entry(2, &application_fanout(T2, APPLICATION_2))],
        }],
    )
    .await;
    let p = follower_of(&hub).await;
    p.follower
        .accept_fanout_at(
            ROOM,
            &domain_of("a.example"),
            &application_fanout(T1, APPLICATION_1),
            1,
        )
        .await
        .unwrap();
    let at = p.store.follower_position(ROOM).await.unwrap().unwrap();
    assert_eq!(
        (at.highest, at.gap_from),
        (1, None),
        "nothing looks wrong from here, which is the problem"
    );

    let recovered = p.follower.probe_all().await.unwrap();
    assert_eq!(recovered, 1, "the tail it could not have noticed");
    assert_eq!(hub.asked(), vec![1], "asked from what it holds");
    assert_eq!(
        p.store
            .follower_position(ROOM)
            .await
            .unwrap()
            .unwrap()
            .highest,
        2
    );
}

/// A probe asks nothing for a room whose highest is 0.
///
/// This is the trap in the design: 0 is what a hub that does not number
/// its fanout leaves -- every implementation but this one today -- and
/// `from` means "after this", so asking from 0 would ask for the room's
/// whole retained history, for every room, every interval.
#[tokio::test]
async fn a_probe_never_asks_from_zero() {
    let hub = MockHub::start(true, Vec::new()).await;
    let p = follower_of(&hub).await;
    // A hub that numbers nothing: the delivery is stored, the position
    // stays 0.
    p.follower
        .accept_fanout(
            ROOM,
            &domain_of("a.example"),
            &application_fanout(T1, APPLICATION_1),
        )
        .await
        .unwrap();
    assert_eq!(
        p.store
            .follower_position(ROOM)
            .await
            .unwrap()
            .unwrap()
            .highest,
        0
    );

    assert_eq!(p.follower.probe_all().await.unwrap(), 0);
    assert!(
        hub.asked().is_empty(),
        "nothing was asked: a probe from 0 would ask for everything, got {:?}",
        hub.asked()
    );
    // And asked directly, it still refuses.
    assert_eq!(p.follower.probe(ROOM, 0).await.unwrap(), 0);
    assert!(hub.asked().is_empty());
}

/// A room whose gap is known unfillable is not probed either: nothing a
/// probe could learn would change it (decision mimid-1wgh.37.104.10).
#[tokio::test]
async fn an_unfillable_room_is_not_probed_or_refilled() {
    let hub = MockHub::start(true, Vec::new()).await;
    let p = follower_of(&hub).await;
    with_a_gap(&p).await;
    p.follower.fill_gap(ROOM).await.unwrap();
    assert_eq!(hub.asked(), vec![1], "asked once, and told 410");
    assert!(
        p.store
            .follower_position(ROOM)
            .await
            .unwrap()
            .unwrap()
            .unfillable
    );

    // Neither a fill nor a probe asks again.
    assert_eq!(p.follower.fill_gap(ROOM).await.unwrap(), 0);
    assert_eq!(p.follower.probe_all().await.unwrap(), 0);
    assert_eq!(
        hub.asked(),
        vec![1],
        "still just the one request: a dropped range cannot come back"
    );
}

/// A hub whose answer does not advance past what was asked is asked
/// once more at most, never forever.
///
/// Oracle: a peer's answer is untrusted (AGENTS.md), so the loop must
/// fail closed rather than trust a hub to make progress. The hub here
/// always returns sequence 1 while claiming to hold 100, which is what
/// a buggy `from` comparison on its side would look like. Before the
/// guard, `from = last` set `from` back to 1 and the follower asked the
/// same question forever, applying the same fanout in a tight loop.
#[tokio::test]
async fn a_hub_that_does_not_advance_does_not_spin() {
    let hub = MockHub::start_repeating(CatchUpResponse {
        highest_sequence: 100,
        entries: vec![entry(1, &application_fanout(T1, APPLICATION_1))],
    })
    .await;
    let p = follower_of(&hub).await;
    // A wide gap, so neither the target nor caught_up stops the loop.
    p.follower
        .accept_fanout_at(
            ROOM,
            &domain_of("a.example"),
            &application_fanout(T1, APPLICATION_1),
            2,
        )
        .await
        .unwrap();
    p.follower
        .accept_fanout_at(
            ROOM,
            &domain_of("a.example"),
            &commit_fanout(T3, COMMIT_CAROL),
            50,
        )
        .await
        .unwrap();
    assert_eq!(
        p.store
            .follower_position(ROOM)
            .await
            .unwrap()
            .unwrap()
            .gap_from,
        Some(3)
    );

    let filled = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        p.follower.fill_gap(ROOM),
    )
    .await
    .expect("fill_gap returns instead of spinning");
    filled.unwrap();
    assert!(
        hub.asked().len() <= 2,
        "asked a bounded number of times, got {} requests",
        hub.asked().len()
    );
}
