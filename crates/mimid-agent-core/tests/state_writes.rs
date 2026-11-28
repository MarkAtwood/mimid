//! What `Agent::in_transaction` writes to the `agent_state` row before
//! it begins a transaction (bead mimid-604m.7): nothing, when the row
//! already holds the state and the journal is empty, and the row, when
//! the state changed in memory before the call.
//!
//! The write under test has no effect on the row -- it puts back the
//! bytes already there -- so nothing read from the row afterwards can
//! show whether it ran. SQLite can: an `AFTER UPDATE` trigger fires per
//! UPDATE statement that matches the row, whatever the values, and sees
//! both `OLD.record` and `NEW.record`. That trigger, installed on a
//! second connection as a front end reaches the agent's database, is the
//! observation here; its rows commit with the agent's transaction, so a
//! rolled-back attempt leaves none.
//!
//! Oracle: SQLite's own report of each UPDATE and of whether it changed
//! the record. The counts follow from `in_transaction`'s two saves: the
//! one after the step is unconditional, so two calls of the same code
//! path write the row the same number of times after their steps, and
//! any difference between them is a difference in their pre-saves.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, BOB, device, look_again, poll_until, server};
use mimid_agent_core::mls_didwebvh::PublicKey;
use mimid_agent_core::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimid_agent_core::{Agent, Event, HostOptions};

/// Every write of an agent's `agent_state` row, as SQLite reports it.
struct StateWrites {
    database: rusqlite::Connection,
    /// The last trigger row read, so [`StateWrites::take`] returns each
    /// write once.
    read: i64,
}

impl StateWrites {
    /// Watches `agent`'s database from a second connection. The trigger
    /// and its table are made there and the agent never reads them; its
    /// own connection picks up the new trigger with its next statement.
    fn watch(agent: &Agent) -> Self {
        let database = rusqlite::Connection::open(agent.database_path()).unwrap();
        database
            .execute_batch(
                "CREATE TABLE state_write (changed INTEGER NOT NULL);
                 CREATE TRIGGER state_written AFTER UPDATE ON agent_state
                 BEGIN
                   INSERT INTO state_write (changed)
                     VALUES (OLD.record <> NEW.record);
                 END;",
            )
            .unwrap();
        Self { database, read: 0 }
    }

    /// The writes since the last call, oldest first: `true` for a write
    /// that changed the record's bytes, `false` for one that put back
    /// what the row already held.
    fn take(&mut self) -> Vec<bool> {
        let mut statement = self
            .database
            .prepare("SELECT rowid, changed FROM state_write WHERE rowid > ?1 ORDER BY rowid")
            .unwrap();
        let writes: Vec<(i64, bool)> = statement
            .query_map([self.read], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        if let Some((last, _)) = writes.last() {
            self.read = *last;
        }
        writes.into_iter().map(|(_, changed)| changed).collect()
    }
}

/// A `did_webvh` log for alice with `key` as her one device key, as
/// `didwebvh_agents.rs` builds one: her user URI in `alsoKnownAs`, one
/// update key from a fixed seed.
fn alice_log(key: PublicKey) -> DidLog {
    let signer = UpdateKey::from_seed(&[0x5a; 32]);
    DidLog::create_also_known_as(
        "a.example",
        "alice",
        "2026-11-20T12:00:01Z",
        &Parameters {
            update_keys: Some(vec![signer.multikey()]),
            next_key_hashes: None,
        },
        &signer,
        &[key],
        &[ALICE.to_owned()],
    )
    .unwrap()
}

/// A poll that takes in a message enters one transaction, and the state
/// it enters with is the state the row holds: the row is not written
/// again before the transaction begins.
///
/// The write before the transaction is the first write of the poll, so
/// the first write changing the record is the whole of the claim. The
/// writes after it are the transaction's own: `handle_message` saves the
/// Message as handled, the save after the step finds the row equal
/// again, and the poll's last save records the Message state read up to.
/// The polls that found nothing are discarded; one of those ends in a
/// save of an unchanged state as well, outside any transaction.
#[tokio::test]
async fn an_unchanged_state_is_not_written_before_a_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;
    alice.publish_key_packages(1).await.unwrap();
    bob.publish_key_packages(1).await.unwrap();
    let room = alice
        .host_room(&HostOptions::named("writes"))
        .await
        .unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let number = poll_until(&mut bob, &server, |event| match event {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    assert_eq!(bob.join(number).unwrap(), room);

    // Steady state: the room is joined and a first message has been
    // through, so the next poll has nothing to set up.
    alice.send_text(&room, "first").await.unwrap();
    poll_until(&mut bob, &server, |event| {
        matches!(event, Event::Message(_)).then_some(())
    })
    .await;

    let mut writes = StateWrites::watch(&bob);
    let mut changed = server.changed();
    alice.send_text(&room, "second").await.unwrap();
    let measured = loop {
        // Only the poll that handles the message is measured.
        writes.take();
        let events = bob.poll().await.unwrap();
        for event in &events {
            if let Event::Problem { room, description } = event {
                panic!("problem in {room:?}: {description}");
            }
        }
        if events
            .iter()
            .any(|event| matches!(event, Event::Message(_)))
        {
            break writes.take();
        }
        if events.is_empty() {
            look_again("the second message", &mut changed, None).await;
        }
    };
    assert_eq!(
        measured.first(),
        Some(&true),
        "the first state write of the poll changed the record: {measured:?}"
    );
}

/// An invite that learns the contact's SCID changes the state in memory
/// and leaves it to the next transaction's pre-save to put on disk
/// (`Agent::invite`'s KeyMaterial/fetch loop). That pre-save still runs,
/// so a failed Commit cannot lose the pin.
///
/// Two invites of the same contact, into two rooms, by the same code
/// path: the first learns alice's SCID, the second finds it pinned
/// already and changes nothing. The save after each transaction's step
/// is unconditional and both invites make the same transactions, so the
/// first invite writes the row exactly once more than the second -- the
/// pre-save that carries the pin. A guard that looked only at the
/// journal would skip it and the two counts would be equal.
#[tokio::test]
async fn a_state_changed_before_a_transaction_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;
    let log = alice_log(alice.signature_public_key().try_into().unwrap());
    alice
        .use_did_webvh_credential(log.credential().unwrap())
        .await
        .unwrap();
    alice.publish_key_packages(2).await.unwrap();
    bob.publish_key_packages(1).await.unwrap();

    let one = bob.host_room(&HostOptions::named("one")).await.unwrap();
    let mut writes = StateWrites::watch(&bob);
    bob.invite(&one, ALICE).await.unwrap();
    let first = writes.take();
    assert_eq!(
        bob.pinned_scid(ALICE),
        Some(log.verified().scid()),
        "the invite pinned alice's SCID"
    );

    let two = bob.host_room(&HostOptions::named("two")).await.unwrap();
    // The second room's own writes are not the invite's.
    writes.take();
    bob.invite(&two, ALICE).await.unwrap();
    let second = writes.take();

    assert_eq!(
        first.len(),
        second.len() + 1,
        "the invite that pinned the SCID wrote the state row once more than the invite that \
         changed nothing: {first:?} against {second:?}"
    );
}
