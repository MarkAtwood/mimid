//! The store's SQLite database (docs/design/agent-frontends.md §7.10):
//! every record reads back as it was written, including users and rooms
//! that are not known and tombstones; a save writes only what changed; a
//! database of another user or another schema version is refused.
//!
//! Oracle: the records written. The database is the store's own format,
//! with no outside source; what it must do is give back what it was given.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use mimid_agent_store::FileError;
use mimid_agent_store::State;
use mimid_agent_store::content::BodyType;
use mimid_agent_store::db::{Database, SCHEMA_VERSION};
use mimid_agent_store::record::{
    Attachment, Ban, Deletion, Message, NoticeKind, Octets, Participant, Person, ReadPosition,
    Reply, Revision, Room, RoomStatus, Sender, SubjectSet, Tombstone,
};
use serde_json::json;

const BOB: &str = "mimi://a.example/u/bob";
const ALICE: &str = "mimi://a.example/u/alice";
const CAROL: &str = "mimi://a.example/u/carol";

/// A ULID `senderMsgId` whose reference octets are all `n`.
fn sender_msg_id(n: u8) -> String {
    let mut random = [n; 16];
    random[..6].fill(0);
    ulid::Ulid::from_parts(
        1_700_000_000_000 + u64::from(n),
        u128::from_be_bytes(random),
    )
    .to_string()
}

fn message(key: &str, room: &str, seq: u64, sender: Sender, n: u8) -> Message {
    Message {
        key: key.to_owned(),
        room: room.to_owned(),
        seq,
        sender,
        mimi_id: Some(Octets([n; 32])),
        aliases: vec![Octets([n + 100; 10])],
        accepted_at: 1_700_000_000_000 + u64::from(n),
        received_at: 1_700_000_000_500 + u64::from(n),
        sender_msg_id: sender_msg_id(n),
        body: format!("message {n}"),
        body_type: BodyType::Plain,
        in_reply_to: None,
        topic_id: None,
        attachments: Vec::new(),
        edit_history: Vec::new(),
        edited_at: None,
        deleted: None,
        kept_frank: None,
        notice: None,
        ext: BTreeMap::new(),
    }
}

/// A store with a record of every kind, and the cases a running agent
/// makes: a sender without a person record (a ChatContact a client
/// destroyed), a participant whose role is not read yet, a message and a
/// ban naming a room that is not held, a notice, a reply to a message not stored, a retraction,
/// tombstones of both kinds, and front-end extensions.
fn state() -> State {
    let mut state = State::new(BOB);
    state
        .ext
        .insert("jmap".to_owned(), json!({"account": "bob"}));
    state.next_seq = 6;
    state.insert_room(Room {
        key: "R1".to_owned(),
        uri: "mimi://a.example/r/one".to_owned(),
        name: Some("one".to_owned()),
        subject: Some("plans".to_owned()),
        subject_set: Some(SubjectSet {
            by: Some(ALICE.to_owned()),
            at: 1_700_000_000_000,
        }),
        status: RoomStatus::Active,
        participants: vec![
            Participant {
                user: BOB.to_owned(),
                role: Some(2),
            },
            Participant {
                user: ALICE.to_owned(),
                role: None,
            },
        ],
        role_names: BTreeMap::from([(1, "banned".to_owned()), (2, "member".to_owned())]),
        ext: BTreeMap::from([("jmap".to_owned(), json!({"members": [], "unreadCount": 3}))]),
    });
    state.insert_person(Person {
        key: "P1".to_owned(),
        user: ALICE.to_owned(),
        display_name: Some("Alice A.".to_owned()),
        did: Some("did:webvh:x:a.example".to_owned()),
        did_changed_at: Some(1_700_000_000_123),
        first_seen: 1_700_000_000_000,
        ext: BTreeMap::new(),
    });
    let mut first = message("M1", "R1", 1, Sender::User(ALICE.to_owned()), 1);
    first.attachments.push(Attachment {
        blob_id: format!("s{}", "ab".repeat(32)),
        file_name: "a.txt".to_owned(),
        media_type: "text/plain".to_owned(),
        size: 3,
        sha256: "ab".repeat(32),
    });
    first.edit_history.push(Revision {
        body: "before".to_owned(),
        body_type: BodyType::Markdown,
        edited_at: 1_700_000_000_500,
    });
    first.edited_at = Some(1_700_000_000_500);
    first.kept_frank = Some(
        serde_json::from_value(json!({"room": "mimi://a.example/r/one", "message": "00",
                                      "unverified": true}))
        .unwrap(),
    );
    let mut unknown = message("M2", "R1", 2, Sender::User(CAROL.to_owned()), 2);
    unknown.in_reply_to = Some(Reply::Reference(Octets([9; 10])));
    unknown
        .ext
        .insert("jmap".to_owned(), json!({"senderId": "gone"}));
    let mut gone_room = message("M3", "GONE", 3, Sender::User(BOB.to_owned()), 3);
    gone_room.deleted = Some(Deletion {
        at: 1_700_000_001_000,
        for_all: true,
    });
    gone_room.in_reply_to = Some(Reply::Message("M1".to_owned()));
    let mut notice = message("M4", "R1", 4, Sender::Agent, 4);
    notice.mimi_id = None;
    notice.notice = Some(NoticeKind::RemovedWithoutAppDataUpdate {
        user: ALICE.to_owned(),
        epoch: 7,
    });
    for m in [first, unknown, gone_room, notice] {
        state.insert_message(m);
    }
    state.bans.insert(
        "B1".to_owned(),
        Ban {
            key: "B1".to_owned(),
            room: "GONE".to_owned(),
            user: CAROL.to_owned(),
            banned_by: BOB.to_owned(),
            reason: Some("spam".to_owned()),
            expires_at: Some(1_800_000_000_000),
            ext: BTreeMap::new(),
        },
    );
    state.read_positions.insert(
        "C1".to_owned(),
        ReadPosition {
            key: "C1".to_owned(),
            room: "R1".to_owned(),
            message: Some("M1".to_owned()),
            at: Some(1_700_000_002_000),
            ext: BTreeMap::new(),
        },
    );
    state.pending_attachments = serde_json::from_value(json!([
        {"message": "M1", "room": "mimi://a.example/r/one", "number": 1,
         "part": {"contentType": "text/plain", "url": "https://a.example/x", "expires": 0,
                  "size": 3, "encAlg": 1, "key": "00", "nonce": "00", "aad": "",
                  "hashAlg": 1, "contentHash": "00", "description": "",
                  "filename": "b.txt"},
         "attempts": 1, "nextTry": 5},
    ]))
    .unwrap();
    state.tombstones.insert(Tombstone::Message {
        room: "R1".to_owned(),
        reference: Octets([5; 10]),
    });
    state.tombstones.insert(Tombstone::Room {
        key: "R9".to_owned(),
        uri: "mimi://a.example/r/nine".to_owned(),
    });
    state.reindex();
    state
}

fn database(dir: &tempfile::TempDir) -> Database {
    Database::open(&dir.path().join("chat.sqlite")).unwrap()
}

#[test]
fn every_record_reads_back_as_written() {
    let dir = tempfile::tempdir().unwrap();
    let written = state();
    let mut db = database(&dir);
    assert_eq!(db.load(BOB).unwrap(), None, "a new database holds no store");
    db.save(&written).unwrap();
    drop(db);
    let read = database(&dir).load(BOB).unwrap().unwrap();
    assert_eq!(read, written);
    // The indexes are rebuilt too.
    let reference = mimid_agent_store::reference_of(&sender_msg_id(1)).unwrap();
    assert_eq!(
        read.message_of_ref("R1", &reference).map(String::as_str),
        Some("M1")
    );
    assert_eq!(
        read.message_of_ref("R1", &[101; 10]).map(String::as_str),
        Some("M1")
    );
    assert!(read.is_deleted("R1", &[5; 10]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.path().join("chat.sqlite");
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn a_save_writes_only_what_changed() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = state();
    let mut db = database(&dir);
    let first = db.save(&state).unwrap();
    // meta (3), one room, one person, four messages, one ban, one read
    // position, one pending attachment, two tombstones.
    assert_eq!(first, 14);
    assert_eq!(db.save(&state).unwrap(), 0, "nothing changed");

    state.messages.get_mut("M2").unwrap().body = "changed".to_owned();
    assert_eq!(db.save(&state).unwrap(), 1);
    // A local delete: the message row goes, two tombstone rows come (its
    // first version and its alias).
    state.delete_message("M1").unwrap();
    assert_eq!(db.save(&state).unwrap(), 3);
    state.clear_message_tombstones();
    assert_eq!(db.save(&state).unwrap(), 3, "three message tombstones go");
    drop(db);

    // Reopened, it reads what was saved, and writes nothing more for it.
    let mut db = database(&dir);
    let read = db.load(BOB).unwrap().unwrap();
    assert_eq!(read, state);
    assert_eq!(db.save(&read).unwrap(), 0);
}

#[test]
fn another_users_store_and_another_schema_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    database(&dir).save(&state()).unwrap();
    match database(&dir).load(ALICE) {
        Err(FileError::Malformed(why)) => assert!(why.contains("is not this one"), "{why}"),
        other => panic!("not refused: {other:?}"),
    }

    let path = dir.path().join("chat.sqlite");
    let version = |connection: &rusqlite::Connection| -> i64 {
        connection
            .query_row(
                "SELECT version FROM schema_version WHERE part = 'store'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    let connection = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(version(&connection), SCHEMA_VERSION);
    drop(connection);
    // An older store (§7.10: none is converted) and a newer one.
    for other in [SCHEMA_VERSION - 1, SCHEMA_VERSION + 1] {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE schema_version SET version = ?1 WHERE part = 'store'",
                [other],
            )
            .unwrap();
        drop(connection);
        match Database::open(&path) {
            Err(FileError::Malformed(why)) => {
                assert!(why.contains(&format!("schema version {other}")), "{why}");
            }
            other => panic!("not refused: {other:?}"),
        }
    }
}

#[test]
fn a_damaged_row_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    database(&dir).save(&state()).unwrap();
    let connection = rusqlite::Connection::open(dir.path().join("chat.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE messages SET record = '{\"extra\": 1}' WHERE key = 'M1'",
            [],
        )
        .unwrap();
    drop(connection);
    match database(&dir).load(BOB) {
        Err(FileError::Malformed(why)) => assert!(why.contains("messages M1"), "{why}"),
        other => panic!("not refused: {other:?}"),
    }
}
