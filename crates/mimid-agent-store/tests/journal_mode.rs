//! The agent's database runs in a write-ahead log (decision
//! mimid-1wgh.134, bead mimid-604m.4). Four connections of the agent's one
//! process write `mimid.sqlite`; in SQLite's default DELETE mode a writer
//! excludes every reader for the length of its transaction, and a
//! connection that loses the race waits out `BUSY_TIMEOUT` and then fails.
//!
//! Three of the four are this crate's, and each is opened here on a file
//! of its own, so the mode is that connection's doing and not another's:
//! `Database`, `Credentials` and `PushSubscriptions`. The fourth is the
//! MLS and state connection of mimid-agent-core, which
//! `state::tests::the_database_is_in_wal` covers in that crate.
//!
//! Oracle: SQLite's own `PRAGMA journal_mode`, read by a connection that
//! set nothing, since the mode belongs to the database and not to the
//! connection that set it.

#![forbid(unsafe_code)]

use std::path::Path;

use mimid_agent_store::credentials::Credentials;
use mimid_agent_store::db::Database;
use mimid_agent_store::push::PushSubscriptions;

/// The mode `path` reports to a connection of its own.
fn journal_mode(path: &Path) -> String {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn the_stores_connections_put_the_file_in_wal() {
    let dir = tempfile::tempdir().unwrap();

    let records = dir.path().join("records.sqlite");
    let database = Database::open(&records).unwrap();
    assert_eq!(journal_mode(&records), "wal", "{}", records.display());
    drop(database);

    let logins = dir.path().join("logins.sqlite");
    let credentials = Credentials::open(&logins).unwrap();
    assert_eq!(journal_mode(&logins), "wal", "{}", logins.display());
    drop(credentials);

    let pushes = dir.path().join("pushes.sqlite");
    let subscriptions = PushSubscriptions::open(&pushes).unwrap();
    assert_eq!(journal_mode(&pushes), "wal", "{}", pushes.display());
    drop(subscriptions);
}
