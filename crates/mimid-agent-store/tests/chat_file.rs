//! The store file (docs/design/agent-frontends.md §3 step 2): format 1, as
//! mimid-agent-jmap wrote it, decodes to the expected records under the
//! same keys; format 2 decodes and re-encodes byte for byte.
//!
//! Oracles:
//!
//! - `fixtures/chat-v1/chat.json`: a chat.json written by mimid-agent-jmap
//!   at eaebf92, by a test run (see its PROVENANCE). Each record is checked
//!   against the JMAP object it came from, read from the fixture as plain
//!   JSON, and against what the generator did (its edits, retraction, ban,
//!   names, read position and pending attachment).
//! - `fixtures/chat-v2/chat.json`: format 2 of the same store (PROVENANCE
//!   there). It must decode to the same state as the format-1 fixture and
//!   re-encode to the same octets.
//! - `fixtures/chat-v1-contact-gone/chat.json`: the format-1 fixture with
//!   alice's ChatContact removed (PROVENANCE there). It must decode to the
//!   format-1 fixture's state with alice unknown wherever she was named.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use mimid_agent_store::content::BodyType;
use mimid_agent_store::file::{FileError, read, read_format_1, read_format_2, write_format_2};
use mimid_agent_store::record::{Reply, Sender};
use mimid_agent_store::{State, Store};
use serde_json::{Map, Value, json};

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";
const CAROL: &str = "mimi://a.example/u/carol";

const V1: &[u8] = include_bytes!("fixtures/chat-v1/chat.json");
const V2: &[u8] = include_bytes!("fixtures/chat-v2/chat.json");
const V1_CONTACT_GONE: &[u8] = include_bytes!("fixtures/chat-v1-contact-gone/chat.json");

/// Runs `f` with a `tracing` subscriber that writes to a buffer; returns
/// its result and what was logged.
fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
    #[derive(Clone, Default)]
    struct Buffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let out = tracing::subscriber::with_default(subscriber, f);
    let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    (out, text)
}

/// The fixture's objects of JMAP type `name`, by id.
fn objects(name: &str) -> BTreeMap<String, Map<String, Value>> {
    let file: Value = serde_json::from_slice(V1).unwrap();
    file["objects"][name]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            let o = o.as_object().unwrap().clone();
            (o["id"].as_str().unwrap().to_owned(), o)
        })
        .collect()
}

/// The fixture's side table `name` (`franks`, `mimi_ids`), by Message id.
fn side_table(name: &str) -> Map<String, Value> {
    let file: Value = serde_json::from_slice(V1).unwrap();
    file[name].as_object().cloned().unwrap_or_default()
}

fn v1() -> State {
    read_format_1(V1, BOB).unwrap()
}

/// Every property of `object` is either one the record holds (`held`) or
/// kept unchanged in its `ext["jmap"]`.
fn nothing_dropped(object: &Map<String, Value>, held: &[&str], ext: &BTreeMap<String, Value>) {
    let kept = ext.get("jmap").and_then(Value::as_object);
    for (property, value) in object {
        if held.contains(&property.as_str()) {
            continue;
        }
        assert_eq!(
            kept.and_then(|k| k.get(property)),
            Some(value),
            "{property} of {} is neither held nor kept",
            object["id"]
        );
    }
}

/// The user URI a JMAP id in the fixture names.
fn uri_of(id: &str) -> String {
    if id == "bob" {
        return BOB.to_owned();
    }
    objects("ChatContact")[id]["identity"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Milliseconds of an RFC 3339 `Z` date, by an independent route: the
/// days of each year and month counted out.
fn ms(date: &str) -> u64 {
    let n = |r: std::ops::Range<usize>| date[r].parse::<u64>().unwrap();
    let (year, month, day) = (n(0..4), n(5..7), n(8..10));
    let leap = |y: u64| (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let mut days: u64 = (1970..year).map(|y| if leap(y) { 366 } else { 365 }).sum();
    let lengths = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    days += lengths[..(month as usize - 1)].iter().sum::<u64>() + day - 1;
    let secs = days * 86_400 + n(11..13) * 3600 + n(14..16) * 60 + n(17..19);
    let millis = date
        .get(19..date.len() - 1)
        .and_then(|f| f.strip_prefix('.'))
        .map_or(0, |f| format!("{f:0<3}")[..3].parse::<u64>().unwrap());
    secs * 1000 + millis
}

/// The keys of `map`.
fn keys<R>(map: &BTreeMap<String, R>) -> BTreeSet<String> {
    map.keys().cloned().collect()
}

#[test]
fn format_1_keeps_every_jmap_id_as_the_key() {
    let state = v1();
    let ids = |name: &str| objects(name).into_keys().collect::<BTreeSet<_>>();
    assert_eq!(keys(&state.people), ids("ChatContact"));
    assert_eq!(keys(&state.rooms), ids("Chat"));
    assert_eq!(keys(&state.messages), ids("Message"));
    assert_eq!(keys(&state.bans), ids("ChatBan"));
    assert_eq!(keys(&state.read_positions), ids("ReadPosition"));
    assert_eq!(state.user, BOB);
    assert_eq!(state.ext["jmap"], json!({"account": "bob"}));
}

#[test]
fn format_1_people_and_rooms_hold_their_objects() {
    let state = v1();
    for (id, o) in objects("ChatContact") {
        let person = &state.people[&id];
        assert_eq!(person.user, o["identity"].as_str().unwrap());
        assert_eq!(
            person.display_name.as_deref(),
            o.get("displayName").and_then(Value::as_str)
        );
        assert_eq!(person.did.as_deref(), o.get("did").and_then(Value::as_str));
        assert_eq!(person.first_seen, ms(o["firstSeenAt"].as_str().unwrap()));
        assert_eq!(state.person_of_user(&person.user), Some(&id));
        nothing_dropped(
            &o,
            &[
                "id",
                "identity",
                "displayName",
                "did",
                "didChangedAt",
                "firstSeenAt",
            ],
            &person.ext,
        );
    }
    for (id, o) in objects("Chat") {
        let room = &state.rooms[&id];
        assert_eq!(room.uri, o["roomId"].as_str().unwrap());
        assert_eq!(room.name.as_deref(), o.get("name").and_then(Value::as_str));
        let users: Vec<String> = o["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| uri_of(m["id"].as_str().unwrap()))
            .collect();
        let participants: Vec<&str> = room
            .participants
            .iter()
            .map(|p| p.user.as_deref().unwrap())
            .collect();
        assert_eq!(participants, users);
        assert!(room.participants.iter().all(|p| p.role.is_none()));
        assert_eq!(state.room_of_uri(&room.uri), Some(&id));
        nothing_dropped(&o, &["id", "roomId", "name"], &room.ext);
    }
    // What the generator did: alice is "Alice A." to bob; the one room
    // has alice and bob in it, carol banned out of the members.
    let alice = state.person_of_user(ALICE).unwrap();
    assert_eq!(
        state.people[alice].display_name.as_deref(),
        Some("Alice A.")
    );
    let [room] = state.rooms.values().collect::<Vec<_>>()[..] else {
        panic!("one room");
    };
    assert_eq!(room.name.as_deref(), Some("kept"));
    let mut users: Vec<&str> = room
        .participants
        .iter()
        .map(|p| p.user.as_deref().unwrap())
        .collect();
    users.sort_unstable();
    assert_eq!(users, [ALICE, BOB]);
}

#[test]
fn format_1_messages_hold_their_objects_and_side_tables() {
    let state = v1();
    let franks = side_table("franks");
    let mimi_ids = side_table("mimi_ids");
    for (id, o) in objects("Message") {
        let m = &state.messages[&id];
        assert_eq!(m.room, o["chatId"].as_str().unwrap());
        assert_eq!(m.body, o["body"].as_str().unwrap());
        let body_type = match o["bodyType"].as_str().unwrap() {
            "text/plain" => BodyType::Plain,
            other => panic!("{other}"),
        };
        assert_eq!(m.body_type, body_type);
        let sender_msg_id = o["senderMsgId"].as_str().unwrap();
        assert_eq!(m.sender_msg_id, sender_msg_id);
        // The ULID's first 10 characters are its 48-bit time.
        let time = sender_msg_id[..10].chars().fold(0u64, |n, c| {
            n * 32 + "0123456789ABCDEFGHJKMNPQRSTVWXYZ".find(c).unwrap() as u64
        });
        assert_eq!(m.accepted_at, time);
        assert_eq!(
            m.sender,
            Sender::User(uri_of(o["senderId"].as_str().unwrap()))
        );
        assert_eq!(
            m.in_reply_to,
            o.get("replyTo")
                .and_then(Value::as_str)
                .map(|r| Reply::Message(r.to_owned()))
        );
        assert_eq!(
            m.topic_id.as_deref(),
            o.get("topicId").and_then(Value::as_str)
        );
        assert_eq!(
            m.edited_at,
            o.get("editedAt").and_then(Value::as_str).map(ms)
        );
        assert_eq!(
            m.deleted.map(|d| d.at),
            o.get("deletedAt").and_then(Value::as_str).map(ms)
        );
        assert_eq!(
            m.deleted.is_some_and(|d| d.for_all),
            o.get("deletedForAll") == Some(&json!(true))
        );
        let history = o
            .get("editHistory")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(m.edit_history.len(), history.len());
        for (revision, entry) in m.edit_history.iter().zip(&history) {
            assert_eq!(revision.body, entry["body"].as_str().unwrap());
            assert_eq!(revision.edited_at, ms(entry["editedAt"].as_str().unwrap()));
        }
        let attachments = o
            .get("attachments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(m.attachments.len(), attachments.len());
        assert_eq!(
            m.kept_frank
                .as_ref()
                .map(|f| serde_json::to_value(f).unwrap()),
            franks.get(&id).cloned()
        );
        let ids = mimi_ids.get(&id);
        assert_eq!(
            m.mimi_id.map(|i| hex::encode(i.0)),
            ids.and_then(|i| i.get("first"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        );
        let aliases: Vec<String> = m.aliases.iter().map(|a| hex::encode(a.0)).collect();
        let expected: Vec<String> = ids
            .and_then(|i| i.get("aliases"))
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|a| a.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default();
        assert_eq!(aliases, expected);
        assert_eq!(m.notice, None);
        let reference = mimid_agent_store::reference_of(&m.sender_msg_id).unwrap();
        assert_eq!(state.message_of_ref(&m.room, &reference), Some(&id));
        nothing_dropped(
            &o,
            &[
                "id",
                "chatId",
                "body",
                "bodyType",
                "senderMsgId",
                "senderId",
                "replyTo",
                "topicId",
                "attachments",
                "editHistory",
                "editedAt",
                "deletedAt",
                "deletedForAll",
            ],
            &m.ext,
        );
    }

    // Sequence numbers follow (acceptance time, key) from 1.
    let mut order: Vec<_> = state.messages.values().collect();
    order.sort_by_key(|m| m.seq);
    let seqs: Vec<u64> = order.iter().map(|m| m.seq).collect();
    assert_eq!(seqs, (1..=order.len() as u64).collect::<Vec<_>>());
    assert!(
        order
            .windows(2)
            .all(|w| (w[0].accepted_at, &w[0].key) < (w[1].accepted_at, &w[1].key))
    );
    assert_eq!(state.next_seq, order.len() as u64 + 1);

    // What the generator did.
    let by_body = |body: &str| {
        state
            .messages
            .values()
            .find(|m| m.body == body)
            .unwrap_or_else(|| panic!("no message {body:?}"))
    };
    let edited = by_body("before, edited");
    assert_eq!(edited.sender, Sender::User(ALICE.to_owned()));
    assert_eq!(edited.edit_history.len(), 1);
    assert_eq!(edited.edit_history[0].body, "before");
    assert!(edited.edited_at.is_some());
    assert_eq!(edited.aliases.len(), 1);
    assert!(edited.mimi_id.is_some() && edited.kept_frank.is_some());
    let alias = edited.aliases[0].0;
    assert_eq!(
        state.message_of_ref(&edited.room, &alias),
        Some(&edited.key)
    );
    let retracted: Vec<_> = state
        .messages
        .values()
        .filter(|m| m.deleted.is_some_and(|d| d.for_all))
        .collect();
    assert_eq!(retracted.len(), 1);
    assert_eq!(retracted[0].body, "");
    assert_eq!(retracted[0].aliases.len(), 1);
    let own = by_body("from bob");
    assert_eq!(own.sender, Sender::User(BOB.to_owned()));
    assert!(own.mimi_id.is_some());
    assert_eq!(own.kept_frank, None);
    let file = by_body("file.txt");
    assert!(file.attachments.is_empty());
    let [pending] = &state.pending_attachments[..] else {
        panic!("one pending attachment: {:?}", state.pending_attachments);
    };
    assert_eq!(pending.message, file.key);
    assert_eq!(pending.room, state.rooms[&file.room].uri);
    assert!(by_body("after").kept_frank.is_some());
}

#[test]
fn format_1_bans_and_read_positions_hold_their_objects() {
    let state = v1();
    for (id, o) in objects("ChatBan") {
        let ban = &state.bans[&id];
        assert_eq!(ban.room, o["chatId"].as_str().unwrap());
        assert_eq!(ban.user, Some(uri_of(o["userId"].as_str().unwrap())));
        assert_eq!(ban.banned_by, Some(uri_of(o["bannedBy"].as_str().unwrap())));
        assert_eq!(
            ban.reason.as_deref(),
            o.get("reason").and_then(Value::as_str)
        );
        assert_eq!(
            ban.expires_at,
            o.get("expiresAt").and_then(Value::as_str).map(ms)
        );
        nothing_dropped(
            &o,
            &["id", "chatId", "userId", "bannedBy", "reason", "expiresAt"],
            &ban.ext,
        );
    }
    for (id, o) in objects("ReadPosition") {
        let position = &state.read_positions[&id];
        assert_eq!(position.room, o["chatId"].as_str().unwrap());
        assert_eq!(
            position.message.as_deref(),
            o.get("lastReadMessageId").and_then(Value::as_str)
        );
        assert_eq!(
            position.at,
            o.get("lastReadAt").and_then(Value::as_str).map(ms)
        );
        nothing_dropped(
            &o,
            &["id", "chatId", "lastReadMessageId", "lastReadAt"],
            &position.ext,
        );
    }
    // What the generator did: alice banned carol and bob mirrored it; bob
    // read up to his own message.
    let [ban] = state.bans.values().collect::<Vec<_>>()[..] else {
        panic!("one ban");
    };
    assert_eq!(
        (ban.user.as_deref(), ban.banned_by.as_deref()),
        (Some(CAROL), Some(ALICE))
    );
    let [position] = state.read_positions.values().collect::<Vec<_>>()[..] else {
        panic!("one read position");
    };
    let read = &state.messages[position.message.as_ref().unwrap()];
    assert_eq!(read.body, "from bob");
}

/// Mark's decision (docs/design/agent-frontends.md §7.7): a Message,
/// Chat member or ChatBan naming a ChatContact that is gone is kept with
/// the user unknown, and one warning gives the count.
#[test]
fn format_1_keeps_items_naming_a_contact_that_is_gone() {
    let (state, log) = logged(|| read_format_1(V1_CONTACT_GONE, BOB).unwrap());

    // The oracle: the source fixture's state, with alice unknown wherever
    // she was named and her JMAP id kept in ext["jmap"].
    let mut expected = v1();
    let alice = expected.person_of_user(ALICE).unwrap().clone();
    expected.people.remove(&alice);
    let keep_id = |ext: &mut BTreeMap<String, Value>, property: &str| {
        ext.entry("jmap".to_owned())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .unwrap()
            .insert(property.to_owned(), json!(alice));
    };
    let mut senders = 0;
    for m in expected.messages.values_mut() {
        if m.sender == Sender::User(ALICE.to_owned()) {
            m.sender = Sender::Unknown;
            keep_id(&mut m.ext, "senderId");
            senders += 1;
        }
    }
    let mut members = 0;
    for room in expected.rooms.values_mut() {
        for p in &mut room.participants {
            if p.user.as_deref() == Some(ALICE) {
                p.user = None;
                members += 1;
            }
        }
    }
    let mut bans = 0;
    for ban in expected.bans.values_mut() {
        if ban.banned_by.as_deref() == Some(ALICE) {
            ban.banned_by = None;
            keep_id(&mut ban.ext, "bannedBy");
            bans += 1;
        }
    }
    // What the generator did: alice sent four messages, was a member of
    // the one room and banned carol (PROVENANCE).
    assert_eq!((senders, members, bans), (4, 1, 1));
    expected.reindex();
    assert_eq!(state, expected);

    let warnings: Vec<&str> = log.lines().filter(|l| l.contains("WARN")).collect();
    assert_eq!(warnings.len(), 1, "{log}");
    assert!(warnings[0].contains("unknown=6"), "{log}");
    // The source fixture names no one unknown and warns of nothing.
    let (_, log) = logged(v1);
    assert!(!log.contains("WARN"), "{log}");
}

#[test]
fn format_2_round_trips_byte_for_byte() {
    let state = read_format_2(V2, BOB).unwrap();
    assert_eq!(state, v1());
    assert_eq!(write_format_2(&state).unwrap(), V2);
    // read() picks the format.
    assert_eq!(read(V1, BOB).unwrap(), state);
    assert_eq!(read(V2, BOB).unwrap(), state);
}

#[test]
fn a_store_saves_format_2_and_opens_it_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chat.json");
    std::fs::write(&path, V1).unwrap();
    let store = Store::open(&path, BOB).unwrap();
    assert_eq!(*store.state(), v1());
    store.save().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), V2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert_eq!(*Store::open(&path, BOB).unwrap().state(), v1());
    assert!(
        Store::open(dir.path().join("none.json"), BOB)
            .unwrap()
            .state()
            .messages
            .is_empty()
    );
}

/// `V1` or `V2` as JSON, changed by `change`, re-encoded.
fn altered(bytes: &[u8], change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    change(&mut value);
    serde_json::to_vec(&value).unwrap()
}

fn refused(result: Result<State, FileError>, why: &str) {
    match result {
        Err(FileError::Malformed(reason)) => assert!(reason.contains(why), "{reason}"),
        other => panic!("not refused ({why}): {other:?}"),
    }
}

#[test]
fn malformed_format_1_files_are_refused() {
    refused(read_format_1(b"", BOB), "EOF");
    refused(
        read_format_1(&altered(V1, |v| v["format"] = json!(2)), BOB),
        "format 2",
    );
    refused(
        read_format_1(&altered(V1, |v| v["objects"]["Space"] = json!([])), BOB),
        "unknown type Space",
    );
    refused(
        read_format_1(&altered(V1, |v| v["extra"] = json!(1)), BOB),
        "unknown field",
    );
    refused(
        read_format_1(
            &altered(V1, |v| {
                v["objects"]["Message"][0]["senderMsgId"] = json!("x")
            }),
            BOB,
        ),
        "is not a ULID",
    );
    refused(
        read_format_1(
            &altered(V1, |v| {
                v["objects"]["Message"][0]["chatId"] = json!("nowhere")
            }),
            BOB,
        ),
        "names no Chat",
    );
    refused(
        read_format_1(
            &altered(V1, |v| {
                v["objects"]["Message"][0]["bodyType"] = json!("text/html")
            }),
            BOB,
        ),
        "bodyType",
    );
    refused(
        read_format_1(
            &altered(V1, |v| {
                v["objects"]["ChatContact"][0]["firstSeenAt"] = json!("yesterday")
            }),
            BOB,
        ),
        "UTCDate",
    );
    refused(
        read_format_1(
            &altered(V1, |v| {
                let m = v["objects"]["Message"][0].clone();
                v["objects"]["Message"].as_array_mut().unwrap().push(m);
            }),
            BOB,
        ),
        "twice",
    );
    refused(
        read_format_1(
            &altered(V1, |v| {
                v["objects"]["Message"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("id");
            }),
            BOB,
        ),
        "without an id",
    );
}

#[test]
fn malformed_format_2_files_are_refused() {
    refused(read_format_2(V2, ALICE), "is not this one");
    refused(
        read_format_2(&altered(V2, |v| v["format"] = json!(3)), BOB),
        "format 3",
    );
    refused(
        read(&altered(V2, |v| v["format"] = json!(3)), BOB),
        "format 3",
    );
    refused(
        read_format_2(&altered(V2, |v| v["extra"] = json!(1)), BOB),
        "unknown field",
    );
    refused(
        read_format_2(&altered(V2, |v| v["messages"][0]["extra"] = json!(1)), BOB),
        "unknown field",
    );
    refused(
        read_format_2(
            &altered(V2, |v| v["messages"][0]["room"] = json!("nowhere")),
            BOB,
        ),
        "no room nowhere",
    );
    refused(
        read_format_2(
            &altered(V2, |v| v["messages"][0]["mimiId"] = json!("AB")),
            BOB,
        ),
        "hex",
    );
    refused(
        read_format_2(
            &altered(V2, |v| {
                let r = v["rooms"][0].clone();
                v["rooms"].as_array_mut().unwrap().push(r);
            }),
            BOB,
        ),
        "twice",
    );
}

/// Writes `fixtures/chat-v2/chat.json` from the format-1 fixture; see its
/// PROVENANCE.
#[test]
#[ignore = "a fixture generator"]
fn write_the_format_2_fixture() {
    let out = std::env::var("MIMID_CHAT_V2_OUT").expect("MIMID_CHAT_V2_OUT");
    std::fs::write(out, write_format_2(&v1()).unwrap()).unwrap();
}
