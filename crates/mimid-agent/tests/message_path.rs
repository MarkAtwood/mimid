//! One message's path through two mimid instances, hop by hop, with the
//! time each hop took (bead mimid-604m).
//!
//! Two providers, a.example and b.example, peers of each other, and a
//! daemon on each with a JMAP Chat client of its own. alice sends bob one
//! message and it is followed from her store to his: her agent's
//! encryption, her provider's fanout, his provider's acceptance, his
//! agent's fetch and decryption, his store's record. The spans are read
//! back in process through [`mimid_telemetry::timeline`], which is what a
//! collector would have received, because a span carrying no event
//! appears in no log however long it took.
//!
//! **Neither poll can explain an arrival.** `sync_interval_ms` is an hour
//! here, so a message that arrives did so on the push, and a hop that
//! took a second took it doing something. That is the one assertion of
//! this kind that does not depend on the machine: it is a configuration,
//! not a deadline.
//!
//! The budget below is deliberately far above what the path costs, so
//! what fails is a stall and not a slow machine. When it fails, the table
//! says which hop to look at, which is the thing bead mimid-604m could
//! not find out from three runs of a test that took 349 seconds.
//!
//! Oracles: the span names the two crates open, and the `msgid` both
//! agents compute independently from the sender, the room, the content
//! and the salt -- the receiving side's span carries the same hex only if
//! the message that arrived is the one that was sent.

#![forbid(unsafe_code)]

mod common;

use std::time::Duration;

use common::{ALICE, BOB_B, Client, Running, config, two_providers};
use mimid_telemetry::timeline::{TimedSpan, Timeline};
use serde_json::{Value, json};

/// The whole path's budget. Not a wait: nothing in this test sleeps or
/// gives up, and a message that never arrives hangs the test as every
/// other wait here does. This is the assertion itself, set high enough
/// that a loaded machine passes and a stall does not.
const BUDGET: Duration = Duration::from_secs(60);

/// The poll interval the daemons are given: an hour, so no arrival can be
/// a poll's doing.
const NO_POLLING_MS: u64 = 3_600_000;

/// The Chat bound to `room` at `client`'s, once it is there.
async fn chat_of(client: &Client, store: &mimid_agent_store::Store, room: &Value) -> Value {
    common::until_probe(&format!("the Chat for {room}"), store, || async {
        client
            .get("Chat", None)
            .await
            .into_iter()
            .find(|c| c["roomId"] == *room)
    })
    .await
}

/// The first span named `name` whose fields are all `fields` and which
/// opened no earlier than `after`, or a panic naming what was opened
/// instead.
///
/// The `after` is what makes the middle of the path this message's. A
/// room's Commit and its Welcome are fanned out before any message is,
/// under the same `room_id` and with no message ID anywhere -- the hub
/// does not decrypt -- so the first fanout of the room is the room's
/// creation, not this. The hub cannot fan this message out before the
/// submit that carried it began.
fn hop(timeline: &Timeline, name: &str, fields: &[(&str, &str)], after: Duration) -> TimedSpan {
    let found = timeline.named(name).into_iter().find(|span| {
        span.opened >= after
            && fields
                .iter()
                .all(|(field, value)| span.field(field) == Some(*value))
    });
    found.unwrap_or_else(|| {
        panic!(
            "no {name} span with {fields:?} opened after {after:?}; \
             the {name} spans were {:?}",
            timeline.named(name)
        )
    })
}

/// Prints the hops in the order they opened and returns the table, so a
/// failure shows the path rather than one number.
fn table(hops: &[(&str, &TimedSpan, bool)]) -> String {
    let mut text = String::from("\n  hop                      opened      took\n");
    for (what, span, _) in hops {
        let took = span
            .took()
            .map_or_else(|| "(still open)".to_owned(), |took| format!("{took:?}"));
        text.push_str(&format!("  {:<24} {:>9?} {:>9}\n", what, span.opened, took));
    }
    text
}

/// alice's message reaches bob through every hop, and the time each hop
/// took is reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_message_crosses_two_providers_hop_by_hop() {
    // Installed before anything starts, so the first span is recorded:
    // the subscriber is global, which is why this test has its own
    // binary.
    let timeline = Timeline::install(
        "mimid_agent=debug,mimid_agent_core=debug,mimid_agent_store=debug,mimid_server=debug",
    );
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let mut alice_config = config(&a, ALICE, dir.path(), "any");
    alice_config.sync_interval_ms = NO_POLLING_MS;
    let mut bob_config = config(&b, BOB_B, dir.path(), "any");
    bob_config.sync_interval_ms = NO_POLLING_MS;
    let alice = Running::start(&alice_config).await;
    let bob = Running::start(&bob_config).await;
    let (ac, bc) = (alice.client().await, bob.client().await);

    // A direct Chat, which is itself the one-to-one room path of bead
    // mimid-604m.2, and then one message through it.
    let bob_contact = ac.create("ChatContact", json!({"identity": BOB_B})).await["id"].clone();
    let made = ac
        .create("Chat", json!({"kind": "direct", "contactId": bob_contact}))
        .await;
    let chat_id = made["id"].as_str().unwrap().to_owned();
    let room = ac.get("Chat", Some(vec![&chat_id])).await.remove(0)["roomId"].clone();
    let bob_chat = chat_of(&bc, &bob.store, &room).await;
    let bob_chat_id = bob_chat["id"].as_str().unwrap().to_owned();

    const TEXT: &str = "one message, followed";
    ac.create(
        "Message",
        json!({"chatId": chat_id, "body": TEXT, "sentAt": "2026-11-27T00:00:00Z"}),
    )
    .await;
    common::until_probe(
        &format!("the message {TEXT:?} at bob's"),
        &bob.store,
        || async {
            bc.messages(&bob_chat_id)
                .await
                .into_iter()
                .find(|m| m["body"] == json!(TEXT))
        },
    )
    .await;

    // The sender's half names the message; everything else is found from
    // it.
    let sent = hop(&timeline, "store_send", &[("user", ALICE)], Duration::ZERO);
    let msgid = sent
        .field("msgid")
        .expect("the send span names the message")
        .to_owned();
    let encrypted = timeline
        .under(&sent)
        .into_iter()
        .find(|span| span.name == "mls_encrypt_and_stage")
        .expect("the send encrypts under its own span");
    let submitted = timeline
        .under(&sent)
        .into_iter()
        .find(|span| span.name == "provider_submit")
        .expect("the send submits under its own span");
    // The receiving half: his store stored the same message id, which is
    // what makes this one message's path and not two.
    //
    // `sent_here` tells the two ends apart. The sender stores this
    // message a second time when her own copy comes back through the
    // fanout, under the same id and in the same span, so without that
    // field the first record of the message is hers and the path reads
    // as ending where it began.
    let stored = hop(
        &timeline,
        "store_received",
        &[("msgid", &msgid), ("sent_here", "false")],
        Duration::ZERO,
    );
    // The sync that stored it, and the fetch inside that same sync. Not
    // the receive the record sits inside: it does not sit inside one.
    // The store calls the agent's `receive`, is handed the events, and
    // writes the records afterwards, so the receive and the record are
    // two children of one `store_sync`.
    let sync = timeline
        .enclosing(&stored, "store_sync")
        .expect("a record is stored inside a sync");
    assert_eq!(sync.field("user"), Some(BOB_B));
    let under_sync = timeline.under(&sync);
    let received = under_sync
        .iter()
        .find(|span| span.name == "agent_receive")
        .expect("the sync that stored it also received it")
        .clone();
    let fetched = under_sync
        .iter()
        .find(|span| span.name == "provider_fetch")
        .expect("a receive fetches under its own span")
        .clone();
    // The providers: a.example hands the room's fanout to b.example, and
    // b.example stores it. Neither names the message -- a hub does not
    // decrypt -- so the room is the key.
    let room_id = room.as_str().unwrap();
    let handed = hop(
        &timeline,
        "fanout_attempt",
        &[("room_id", room_id), ("domain", "b.example")],
        submitted.opened,
    );
    let accepted = hop(
        &timeline,
        "store_fanout",
        &[("room_id", room_id)],
        submitted.opened,
    );

    // The `false` is the sync: it wraps the arrival and outlives it. The
    // record is published as it is written, which is what bob's client
    // saw and what this test waited for, while the sync goes on to the
    // attachments and the expiry pass. So it is shown and not required
    // to have finished; every other hop must have.
    let hops = [
        ("store_send", &sent, true),
        ("mls_encrypt_and_stage", &encrypted, true),
        ("provider_submit", &submitted, true),
        ("fanout_attempt", &handed, true),
        ("store_fanout", &accepted, true),
        ("store_sync", &sync, false),
        ("agent_receive", &received, true),
        ("provider_fetch", &fetched, true),
        ("store_received", &stored, true),
    ];
    let table = table(&hops);
    // Printed on every run: cargo keeps it for a failure, and
    // `--nocapture` shows it for a passing one, which is how a change in
    // the path's cost is noticed.
    eprintln!("the path of {msgid}:{table}");

    for (what, span, must_finish) in hops {
        assert!(
            !must_finish || span.closed.is_some(),
            "the {what} hop never finished:{table}"
        );
    }
    // The path's own span is the send; the arrival is the store's.
    let path = stored
        .closed
        .unwrap()
        .saturating_sub(sent.opened)
        .min(Duration::MAX);
    assert!(
        path < BUDGET,
        "the message took {path:?}, over the {BUDGET:?} budget, \
         and no poll can explain it (sync_interval_ms is an hour):{table}"
    );
}
