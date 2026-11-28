//! `Agent::host_room` builds a new room's MLS group, its first Commit
//! and the merge in one transaction of the agent's database (beads
//! mimid-604m.2, mimid-604m.6).
//!
//! OpenMLS writes each piece of a group to the store as it goes, and a
//! write with no transaction open is a transaction of its own: 28 of
//! them, four fsyncs each, with the caller holding the agent mutex
//! across all of them.
//!
//! Oracle: SQLite's own atomicity. Rows written in one transaction either
//! all survive a failure inside it or none do, so a failure between the
//! group and its first Commit that leaves no row behind is a failure
//! inside one transaction; 28 of them could not roll back together. The
//! count of rows the agent's database holds is the observation, read on a
//! second connection as a front end reads it; the failure is
//! `FailPoint::FirstCommit`.

#![forbid(unsafe_code)]
// The failure is `Agent::fail_next`, so this needs the crate's own
// `fail-points` feature, which `--all-features` turns on.
#![cfg(feature = "fail-points")]

mod common;

use common::{ALICE, BOB, device, server};
use mimid_agent_core::{Agent, FailPoint, HostOptions};

/// How many rows the agent's database holds, over every table: what a
/// rolled-back transaction must leave unchanged. Read on a second
/// connection, as a front end reads the agent's database.
fn rows(agent: &Agent) -> i64 {
    let database = rusqlite::Connection::open(agent.database_path()).unwrap();
    let tables: Vec<String> = database
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        tables.iter().any(|name| name == "openmls_group_data"),
        "the agent's database holds OpenMLS's tables: {tables:?}"
    );
    tables
        .iter()
        .map(|name| {
            database
                .query_row(&format!("SELECT count(*) FROM \"{name}\""), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        })
        .sum()
}

/// A failure between the new group and its first Commit leaves nothing of
/// the group in the agent's database, and the next attempt makes a room
/// that works: alice hosts a one-to-one room and invites bob.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_built_group_leaves_no_row_behind() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;
    bob.publish_key_packages(2).await.unwrap();
    bob.allow(ALICE).await.unwrap();
    // So that hosting does not publish alice's first KeyPackage, which
    // writes rows of its own.
    alice.publish_key_packages(1).await.unwrap();

    let before = rows(&alice);
    alice.fail_next(FailPoint::FirstCommit);
    let error = alice
        .host_room(&HostOptions::direct())
        .await
        .expect_err("the fail point makes the first Commit fail");
    assert!(format!("{error}").contains("FirstCommit"), "{error:?}");
    assert_eq!(
        rows(&alice),
        before,
        "the group rolled back with its first Commit"
    );
    assert!(alice.rooms().is_empty(), "no room was made");

    // The agent is usable afterwards: the rollback read its state and
    // groups back from the database, and the next room is a whole one.
    let room = alice.host_room(&HostOptions::direct()).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    assert!(rows(&alice) > before, "the second room was written");
    assert_eq!(
        alice.participants(&room).unwrap(),
        vec![ALICE.to_owned(), BOB.to_owned()]
    );
}
