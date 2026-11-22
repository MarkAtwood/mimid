# Agent front ends: one plaintext store, JMAP and IRC over it

Design note for epic mimid-1vul. Written 2026-11-19 against main at
e4e91cd. Status: steps 1 to 8 of §3 are built (2026-11-20). Each step
notes the changes it made to this design.

Mark decided on 2026-11-19 that the IRC front end is native. It is built
into the agent and calls mimid-agent-core directly. It is not a JMAP
client of the agent. The plaintext layer that mimid-agent-jmap owns today
moves into a shared crate. JMAP and IRC become two thin front ends over
it, and one agent can serve both at once.

Line references are to e4e91cd. At that commit `cargo test -p
mimid-agent-jmap -p mimid-agent` passes: 29 unit and 15 integration tests
in mimid-agent-jmap, 18 unit and 8 integration tests in mimid-agent.

## 1. Today

### What mimid-agent-jmap does beyond JMAP translation

`AgentChat` (crates/mimid-agent-jmap/src/backend.rs:126-150) is a
crate-jmap `ChatBackend`. Most of its code is not JMAP translation. It is
the agent's whole plaintext layer, written in JMAP terms.

- **Journal consumer.** `AgentChat::sync`
  (crates/mimid-agent-jmap/src/sync.rs:128-201) is the only caller of
  `Agent::receive` and `Agent::acknowledge`
  (crates/mimid-agent-core/src/agent.rs:2471-2519). It stores every event,
  saves the store file, then acknowledges (sync.rs:187-192). It runs two
  rounds when it joined a room, because a join's held messages come with
  the next poll (sync.rs:132-134).
- **Invites and consent.** The invite policy (backend.rs:51-64) decides
  which Welcomes to join, reading consent records from the agent
  (sync.rs:204-253). Refused invites stay pending in the agent, with no
  JMAP object (crates/mimid-agent-jmap/src/lib.rs:177-178). Consent
  decisions have no JMAP method at all
  (crates/mimid-agent/src/lib.rs:97-100).
- **New devices.** `Agent::join_own_rooms` runs at each sync
  (sync.rs:141-154).
- **Rooms.** Every active room gets a Chat (sync.rs:256-295). Members and
  roles are mirrored from the room: "admin" or member, banned left out
  (sync.rs:303-343).
- **People.** A ChatContact per user URI, made when first seen
  (sync.rs:347-384). Each contact's did:webvh DID is refreshed when any
  room's epoch moves (sync.rs:169-186, sync.rs:563-626).
- **Message history.** Received messages are stored once, deduplicated by
  (Chat, the 10 reference octets of the MIMI message ID)
  (sync.rs:658-723; the `Links` map, backend.rs:110-118). The stable id is
  `senderMsgId`, a ULID of the hub's acceptance time and the reference
  octets (crates/mimid-agent-jmap/src/convert.rs:25-29). Replies resolve
  within the Chat (sync.rs:696-701).
- **Notices.** The identity-change notice and the
  removed-without-AppDataUpdate notice are stored as Messages from the
  accountId, once per key (sync.rs:460-545). Keys and texts are at
  sync.rs:942-1015.
- **Attachments.** Received ExternalParts are fetched, decrypted and put in
  the blob store (sync.rs:733-809). Fetches that may succeed later are
  kept and retried with backoff (crates/mimid-agent-jmap/src/retry.rs;
  sync.rs:846-916). Sent attachments are read from the blob store and
  passed to `Agent::send_message` (backend.rs:514-588).
- **Edits and retractions.** Received ones are checked against the
  original sender and applied (crates/mimid-agent-jmap/src/edits.rs:137-242).
  The owner's edits and retractions are sent first and then stored
  (edits.rs:253-317). Each Message keeps its first MIMI message ID and
  its aliases in a `MimiIds` side record (edits.rs:54-65).
- **Moderation.** Ban, unban, kick and expiry go to the agent
  (crates/mimid-agent-jmap/src/moderate.rs:137-356). Bans made elsewhere
  are mirrored at each sync, with `bannedBy` guessed from the sync's
  committers (moderate.rs:104-128, moderate.rs:270-326).
- **Abuse reports.** Each received Message keeps its frank or its
  unverified content (crates/mimid-agent-jmap/src/report.rs:72-85,
  report.rs:110). `Message/reportAbuse` sends them through the agent.
- **Outbound room changes.** Chat create hosts a room and invites
  (backend.rs:360-407). Member and role changes go to the room
  (backend.rs:416-507). Destroying a Chat leaves the room
  (backend.rs:837-858).
- **Read positions and local state.** ReadPosition and ChatContact writes,
  `readAt`, `privateMetadata` and Message destroy are local
  (backend.rs:716-718, backend.rs:859-867).

The JMAP-only parts are small: the `ChatStore` hooks and their error
mapping (backend.rs:654-702, backend.rs:749-876), the restrictions
(backend.rs:886-949), limits (backend.rs:1021-1063), the report method's
argument parsing, UTCDate rendering (convert.rs:44) and the delegation to
`MemoryBackend` (backend.rs:1091-1123).

### Where the state lives

| State | Where | Persisted |
|---|---|---|
| Chats, Messages, ChatContacts, ChatBans, ReadPositions | crate-jmap `MemoryBackend` inside `AgentChat` (backend.rs:127) | `<state_dir>/chat.json`, the JMAP objects as JSON (crates/mimid-agent-jmap/src/persist.rs:69-98) |
| Room, contact and message links | `Links` (backend.rs:110-118) | No; rebuilt from the objects at start (persist.rs:178-219) |
| First MIMI IDs and aliases | `mimi_ids` (backend.rs:149) | In chat.json beside the objects (persist.rs:84-88) |
| Kept franks | `franks` (backend.rs:147) | In chat.json (persist.rs:79-83) |
| Attachments waiting for retry, with their keys | `pending` (backend.rs:140) | In chat.json (persist.rs:75-78) |
| Epochs at the last DID refresh | `did_epochs` (backend.rs:143) | No |
| Attachment plaintext | `<state_dir>/blobs`, content-addressed, 0700/0600 (crates/mimid-agent-jmap/src/blobs.rs:1-41) | Yes |
| MLS keys, groups, rooms, invites, the delivery journal | mimid-agent-core: `mls.sqlite`, `state.json` (crates/mimid-agent-core/src/lib.rs:45-51); since §3 step 9 one file, `mimid.sqlite`, with the store's records | Yes |
| The local token | `<state_dir>/agent-token`, 0600 (crates/mimid-agent/src/token.rs:1-7) | Yes |

chat.json is rewritten whole, 0600, through a temporary file and a rename
(persist.rs:319-336). JMAP state strings are `MemoryBackend` counters and
start again after a restart, so clients resync (persist.rs:19-20).

Two couplings matter for the split:

1. The plaintext store's schema is JMAP objects. Store keys are JMAP ids
   minted by `MemoryBackend`. Message links are rebuilt from
   `senderMsgId` (persist.rs:192-216).
2. The blob quota's "referenced" set is found by scanning JMAP object JSON
   for `blobId` keys (backend.rs:203-230).

## 2. The shared layer

A new crate, `mimid-agent-store`. It depends on mimid-agent-core,
mimi-content, serde, sha2, ulid, tokio (sync) and tracing. It does not
depend on crate-jmap or any IRC code. Its root type is `Store`.

`Store` owns the `Arc<tokio::sync::Mutex<Agent>>`, the store file, the
blob store and the change feed. It is the only journal consumer. Front
ends never call `Agent::receive`.

### Data model

All keys are store keys: ULIDs minted by the store, the same form as
`MemoryBackend`'s ids, so they are valid RFC 8620 Ids. A record a JMAP
write made keeps its JMAP id as its key.

- **Room**: key; room URI; `room_name`; status (active, leaving, left);
  participants with role index; role names; `direct` (local flag, see
  question 2); bans (below). Rooms come from `Agent::rooms` as today.
- **Message**: key; room key; sender (a user URI, or `Agent` for a
  notice); the first version's MIMI message ID, all 32 octets; aliases
  (reference octets of later versions); `accepted_at` in ms; `received_at`, its arrival here, in ms (§7.18); the stable
  id `senderMsgId` (convert.rs:25-29); body and body type (plain or
  markdown); `in_reply_to` resolved to a message key, or kept as raw
  reference octets when not stored; `topic_id`; attachments; edit history
  (at most `MAX_EDIT_HISTORY`, edits.rs:47) and `edited_at`; retracted
  (`deleted_at`, `deleted_for_all`); locally deleted; the kept report
  record (`KeptFrank`); a notice kind with its key when it is a notice.
- **Order**: a store sequence number on every message, given when stored.
  History is ordered by (`accepted_at`, sequence). `senderMsgId` gives the
  same id to sender and receivers; the sequence is local only.
- **Person**: key; user URI; display name (local, set by the user);
  did:webvh DID and `did_changed_at`; first seen.
- **Attachment**: blob id (`s` + SHA-256 hex); file name (made safe,
  sync.rs:1017-1034); media type; size; SHA-256. Pending retries keep the
  ExternalPart, its attempt count and next try, as `PendingAttachment`
  does now (retry.rs:81-94).
- **Notice**: a Message with sender `Agent` and kind `IdentityChanged
  {user, pinned, presented}` or `RemovedWithoutAppDataUpdate {user,
  epoch}`, keyed by `notice_ref` or `removal_notice_ref` (sync.rs:942-985).
  The store keeps the kind, so each front end renders it its own way.
- **Invite**: pending invite number, inviter (`Agent::inviter`), whether
  the policy refused it. The policy moves with it (backend.rs:51-64).
- **Ban**: room, user, `banned_by` (person key or the owner), local
  `reason` and `expires_at`, as the ChatBan holds them now.
- **Read position**: per room, the last read message key and when.
- **Front-end extensions**: every Room, Message, Person and Ban record has
  `ext: BTreeMap<String, serde_json::Value>`, keyed by front end
  (`"jmap"`, `"irc"`). The store keeps and saves it and never reads it.
  JMAP keeps `privateMetadata`, `readAt` and other JMAP-only properties
  there. IRC keeps assigned nicks and channel names, and its playback
  mark. One file, one writer, one atomic rename.

`MimiIds`, `franks`, `pending` and `Links` stop being side tables: they
are fields of the records, or indexes the store rebuilds at load.

A local delete (JMAP Message destroy) is a store delete, so it hides the
message in every front end. The store keeps a tombstone with the message's
reference octets, so a journal replay after a crash does not bring it
back. Today the link is dropped with the object (backend.rs:864), so that
replay would restore it.

### Storage

Superseded by §7.10 (step 4): the store is an SQLite database, not a JSON
file, and nothing reads the old `chat.json`. The write order stays: store,
save, then acknowledge (sync.rs:187-192).

The blob store moves unchanged (blobs.rs). The referenced set comes from
the store's attachment records, not from JMAP JSON.

### The JMAP projection

The JMAP front end keeps a `MemoryBackend`, as a projection of the store.
At start it seeds every object from the store under its key
(`seed_object`, as persist.rs:170-171 does now). Then it applies each
change from the feed as an insert, update or destroy. `MemoryBackend`
bumps its own state counters and change log on each write, so `/changes`,
`CHANGE_LOG_LIMIT` (backend.rs:44) and `cannotCalculateChanges` behave as
now. State strings still start again after a restart, as now
(persist.rs:19-20).

Conversion is one pure function per type, record to JMAP object. A JMAP
write hook calls the store, builds the object from the returned record
with that function, and inserts it, so the `/set` response carries it.
When the same change then comes through the feed, the projector finds an
equal object and writes nothing.

Later, not in this work: a `JmapReads` implementation over the store, with
state strings from the store's sequence numbers. `/changes` would then
survive a restart, and the second in-memory copy would go. `JmapReads` is
a trait, so this needs no write to crate-jmap.

### The change feed

```text
            Agent::receive / acknowledge
                       |
                 Store::sync  (the only journal consumer)
                       |
     records + change log (seq, Change) + save, then acknowledge
                       |
          broadcast<u64> "seq N committed"
              /                    \
   JMAP projector             IRC sessions (one per connection)
   MemoryBackend, EventSource  changes_since(last_seen)
```

- `Store::sync` does what `AgentChat::sync` does now. It holds the agent
  lock for the whole sync, as now (sync.rs:129).
- Every committed change gets a sequence number. The store keeps a bounded
  log of `(seq, Change)` in memory. `Change` names what moved: room
  added, changed or gone; message added or changed (edit, retraction,
  attachment added by a retry); members changed, with joined, left and
  role changes; person changed; ban added or lifted; invite pending or
  gone; read position moved.
- After a save the store sends the new sequence number on a
  `tokio::sync::broadcast`. The value only wakes consumers. Each consumer
  keeps the last sequence number it applied and calls
  `Store::changes_since(seq)`. A consumer that fell behind the log gets
  `TooOld` and reloads what it needs: the JMAP projector reseeds; an IRC
  session resends NAMES for its channels and plays back from its mark.
- Any number of consumers can subscribe: the projector, each IRC
  connection, and later front ends. None of them acknowledges anything to
  the agent. The store acknowledges once, after its own save, so the
  journal's count-based `Receipt`
  (crates/mimid-agent-core/src/journal.rs:247-253) has one owner.
- Writes from a front end (send, edit, retract, ban, kick, invite, leave)
  are `Store` methods that take store keys and user URIs. Each locks the
  agent, sends, records the result, saves, and publishes a change. The
  caller gets the record back. Other front ends learn of it from the
  feed. The method also wakes the sync loop, as `sync_now` does now
  (crates/mimid-agent/src/http.rs:744-756). Changed by step 5: the
  method does not save; the caller shows the record, then calls
  `Store::save`, and every save runs each registered front end's
  `before_save` first (§3 step 5). Changed by step 6: the method records
  its changes and the save publishes them (§3 step 6).
- Lock order: the agent lock first, then the store's state lock. The state
  lock is a `std::sync::Mutex` and is never held across an await.

## 3. The migration

The oracle is the existing test suite, unchanged:

- the 15 integration tests in crates/mimid-agent-jmap/tests:
  `two_accounts.rs` (6, including `a_restart_keeps_chats_and_messages`
  and `the_store_keeps_a_bounded_change_log_and_records_no_events`),
  `edits.rs`, `moderation.rs`, `didwebvh_contacts.rs`,
  `removal_notice.rs` (2), `report_abuse.rs` (2) and `blob_quota.rs` (2);
- the 8 integration tests in crates/mimid-agent/tests, among them
  `stock_rust_client.rs`, `two_daemons.rs`, `attachments.rs` and
  `no_token_in_logs.rs`;
- the 29 unit tests in crates/mimid-agent-jmap/src and 18 in
  crates/mimid-agent/src. Unit tests move with their code and keep their
  fixed values (for example `REMOVAL_KEY`, sync.rs:1048).

No integration test file changes in steps 1 to 6. They use
`AgentChat::new`, `persisted_at`, `with_blobs`, `sync`, `agent`,
`chat_of_room`, `room_of_chat`, `referenced_blobs`, `blobs`,
`account_id`, `register` and `drain_store_events_for_test`. Those stay as
a facade: `AgentChat::new` builds its own `Store` around the agent. Every
step runs the full check list in AGENTS.md before its commit.

1. **Move the pure pieces.** Create mimid-agent-store with `BlobStore`
   (blobs.rs), the retry policy and `PendingAttachment` (retry.rs),
   `MessageRef`, `message_ref`, `sender_msg_id` and `topic_id`
   (convert.rs:12-39), the date arithmetic behind `utc_date` returning a
   `String` (convert.rs:44-77), `safe_filename`, `body_type`, the notice
   keys and texts (sync.rs:919-1034) and `KeptFrank` (report.rs:72-85).
   `BlobInfo::id` becomes a `BlobId` (it is a `jmap_server::Id` at
   blobs.rs:124). mimid-agent-jmap re-exports the public names it exports
   now (lib.rs:205-213). Oracle: all of the above; no behaviour changes.

   Changed while doing it (2026-11-20): `BlobId` is a newtype over the
   id's `String` with `AsRef<str>`, `Display` and a transparent
   `Serialize`, not a bare `String`. The integration tests call
   `blob.id.as_ref()` and pass the result to `Path::join` and
   `BTreeSet<String>::contains`; with a `String` that call is ambiguous
   (`String` is `AsRef` of `str`, `[u8]`, `OsStr` and `Path`) and the
   tests would have to change. `body_type` returns the store's own
   `BodyType` (plain or markdown); mimid-agent-jmap maps it to JMAP's, and
   `sender_msg_id` and `utc_date` return `String`s that it wraps as `Id`
   and `UTCDate`.
2. **The model and the file, not wired.** Add the records, `Store`'s
   in-memory state, the format-2 file and the format-1 reader. Add a
   fixture: a chat.json written by the e4e91cd code (a test run of
   `a_restart_keeps_chats_and_messages` with edits, a ban, a kept frank
   and a pending attachment), committed with a PROVENANCE file. New
   tests: format 1 decodes to the expected records with the same keys;
   format 2 round-trips byte for byte. Oracle: the new tests; nothing
   else is touched.

   Changed while doing it (2026-11-20), against the data model above:

   - The fixture was written at eaebf92 (step 1), not e4e91cd. Step 1
     changed only an import path in persist.rs, so the writer is the
     same. Its generator is committed beside it
     (crates/mimid-agent-store/tests/fixtures/chat-v1). It also promotes
     bob to admin before the ban, because crate-jmap shows ChatBans only
     to a Chat's admins.
   - Room has no `direct` flag: §7.2 drops 1:1 rooms. Nothing keeps an
     IRC playback mark: §7.6 drops playback.
   - Users are named by user URI everywhere in the records: a
     participant, a sender, a banned user, and `banned_by` (the user's
     own URI for a ban made here). There are no person keys in other
     records, so a record never needs another record to say who it means.
   - A participant's role index is optional. Format 1 kept only JMAP's
     "admin" or "member", so rooms read from it have no index until the
     first sync sets them.
   - A notice keeps its text in `body` as well as its kind. A notice read
     from format 1 has no kind, because format 1 kept only the text. It is
     told apart from the user's own message by the three things a notice
     has: the accountId as sender, no kept MIMI ID, and a notice text.
   - "Locally deleted" and "retracted" are one field,
     `deleted: {at, for_all}`, as JMAP's `deletedAt` and `deletedForAll`
     are.
   - Invites are held in memory and not saved, because the agent holds
     them.
   - In the format-1 reader, every JMAP property that a record does not
     hold goes unchanged into that record's `ext["jmap"]`. The accountId
     goes into the state's own `ext["jmap"]`. Chat `members` is kept
     there in full, because its roles and times are JMAP's. Step 4 does
     not need to recover anything from elsewhere.
   - Format 2 is `{format: 2, user, ext, nextSeq, rooms, people, messages,
     bans, readPositions, pendingAttachments}`, records in key order,
     camelCase. Decoding is strict: unknown members are refused.
   - A ChatContact that a Message, member or ChatBan names but that is
     not in the file made the file malformed. Format 1 lets a client
     destroy a ChatContact (a local write), and the record would then
     name nobody. Mark decided this on 2026-11-20 (§7.7): the item is
     kept with the user unknown.
3. **Inbound through the store.** Move `sync`, `apply`, `store_message`,
   the notices, `refresh_contact_dids`, `apply_replacement`,
   `mirror_bans`, `expire_bans`, `accept_invites` and the retries into
   `Store::sync`, working on records. `AgentChat::sync` calls it, then
   projects the changes into `MemoryBackend`. On disk the file stays
   format 1 in this step: `save` writes the projection as today, and
   load uses step 2's reader. Oracle: every mimid-agent-jmap integration
   test; most of all `two_accounts_chat_through_jmap`,
   `a_failed_attachment_fetch_is_retried_until_it_arrives`,
   `edits_and_retractions_reach_jmap_and_only_from_the_sender`,
   `a_contact_s_did_is_shown_and_a_changed_scid_posts_one_notice`, both
   removal-notice tests and the moderation test (mirrored bans and
   `bannedBy`).

   Changed while doing it (2026-11-20):

   - The format-1 reader keeps a Message, ChatBan or ReadPosition that
     names a Chat not in the file, with its room key naming a room the
     state does not hold, and logs one warning per file with the count.
     crate-jmap's Chat/set destroy keeps the Chat's Messages and ChatBans
     (it destroys only its ReadPositions), and chat.json keeps them too.
     Step 2's reader refused such a file, so once load uses it the agent
     would not start after a client destroyed a Chat. This applies §7.7
     to Chats, which Mark confirmed on 2026-11-20 (§7.8). Format 2's
     reader still refuses a record naming a room it does not hold; step 4
     makes it keep them the same way.
   - The front end saves, so `Store::sync` takes a `Commit`: each round
     hands the front end its list of `Change`s (person, room, message
     and ban, added or changed; room left; ban lifted), the front end
     projects and saves, and only then does the store acknowledge. The
     change log and the broadcast are still step 6. The projection writes
     only the properties the store owns, and only where they differ, over
     the object the backend holds, so `unreadCount`, `readAt` and the
     other JMAP-only properties stay the backend's. A
     `MembersChanged` is always a `RoomChanged`, and the projection
     recomputes `members` against the backend's, exactly as before.
   - At load the `MemoryBackend` is seeded from the format-1 file's own
     objects, and the store's records are read from the same bytes. They
     are not rebuilt from the records: the records keep dates in
     milliseconds, and format 1 holds date texts that `utc_date` does
     not reproduce (crate-jmap's `now_utc_string` writes `.000Z`; a
     client's `deletedAt`, `expiresAt` or `lastReadAt` can carry any
     number of digits). Rebuilding would change what clients read after a
     restart. Step 4, which seeds from the records, must keep such a text
     in `ext["jmap"]` when `utc_date` would not write it, or accept the
     change.
   - The JMAP front end's own writes still go straight to the agent and
     the backend (step 5 moves them). After each one, it writes the
     object into the records (`file::merge_object`, built on the
     format-1 reader; `file::forget_object` for a destroy). For a record
     that exists it takes only what a client may change: a ChatContact's
     `displayName`, a ChatBan's `reason` and `expiresAt`, a Message's
     local deletion, or its content after an own edit or retraction, and
     every ReadPosition; the rest stays the store's. The indexes are
     rebuilt after a destroy, a whole pass, as `save` already is.
   - A ChatContact a client destroys loses its person record, so the
     user gets a new ChatContact when next seen. Before, the link to the
     destroyed id stayed until a restart: new Messages and members named
     the destroyed id, and for a user with did:webvh leaves the next DID
     refresh failed the sync.
   - A room record that lacks role indexes or role names (read from
     format 1, or made by a JMAP Chat/set create) gets them from the
     agent at the next sync, as no change: the members shown are the
     same.
   - Received replies to a message not stored keep its reference octets
     (`Reply::Reference`), and notices keep their kind. A notice is
     edited only by the user, as before, when it was the account's
     Message.
   - The unit test `kept_ids_read_back_and_damaged_ones_are_ignored`
     went with the code it tested: the MIMI IDs are read by step 2's
     reader, which refuses damaged ones as malformed.
4. **The store owns the file.** As rewritten by §7.10: the records live
   in the store's SQLite database, which starts empty; there is no
   conversion from `chat.json`. JMAP-only properties go into
   `ext["jmap"]`. The referenced blob set comes from the store. Add the
   tombstone and a regression test for a replayed message after a local
   delete (it fails before the change). Oracle:
   `a_restart_keeps_chats_and_messages`, both `blob_quota.rs` tests, both
   `report_abuse.rs` tests (franks across a restart).

   Built (2026-11-20):

   - `mimid-agent-store::db`: one table per record type (`meta`, `rooms`,
     `people`, `messages`, `bans`, `read_positions`,
     `pending_attachments`, `tombstones`), each row a record by key, the
     record as JSON in `record`, and beside it the column naming its room
     (or URI, or user). The store holds every record in memory with its
     own lookups, so the database is read whole at start and written by
     key: no index beyond the primary keys. `PRAGMA user_version` is the
     schema version (1); another version is refused. The file is created
     0600 before SQLite opens it. rusqlite =0.37.0, the version
     openmls_sqlite_storage brings for mimi-mls.
   - A save encodes every record, compares it with what was last read or
     written, and writes only the rows that differ, in one transaction.
     `Store::save` is called by the front end's `Commit::commit` after it
     has shown the changes, as before; the JMAP front end's own writes
     save the same way.
   - The JSON format 2, its fixture, the format-1 reader, its fixtures
     and their tests are gone. `AgentChat::persisted_at(path)` opens the
     database at `path`; the daemon passes `<state_dir>/chat.sqlite`.
   - `ext["jmap"]` is rebuilt from the backend's objects at each save,
     not kept current: the backend changes JMAP-only properties itself
     (`unreadCount`, `members`), and the save is the one place that sees
     every object. It holds every property of the object that the
     record's rendering as JMAP (`mimid-agent-jmap`'s `render`) does not
     give exactly, null for one the object lacks. At start the backend is
     seeded from the records: rendering plus `ext["jmap"]` gives each
     object back as it was. This keeps date texts too (`.000Z`, a
     client's six digits), so a restart changes no date a client reads;
     within one run dates never changed, since the backend keeps its own
     objects. A record without `ext["jmap"]` had no JMAP object; §7.11
     (bead mimid-1vul.12) makes one for it from the record.
   - The tombstone: `State::delete_message` (a JMAP Message destroy)
     keeps a `Tombstone::Message {room, reference}` per version, and
     `Store::sync` skips a received message or notice whose reference has
     one. Tombstones are saved, and message tombstones are dropped after
     each acknowledgement: `Agent::receive` returns every event not yet
     acknowledged, so after an acknowledgement no event that stored a
     deleted message comes again. `Tombstone::Room {key, uri}` is for
     a deleted chat (§7.9). A notice destroyed by a client is not made
     again by the same event either.
   - `merge_object` and `forget_object` (`mimid-agent-store::merge`) stay
     until step 5: they write the JMAP front end's own writes into the
     records. They keep one rule of §7.7 and §7.8 at run time: a JMAP
     object naming a ChatContact or Chat a client destroyed is written
     with the user unknown (`Sender::Unknown`, `None`) or the Chat's id as
     its room key, since crate-jmap keeps such objects.
   - The records and the MLS state are in two databases, so they do not
     commit together. openmls_sqlite_storage runs its statements on any
     `Borrow<rusqlite::Connection>` without transactions of its own, so
     one transaction is possible, but needs the agent to own one
     connection, the journal to move from `state.json` into it, and new
     APIs in mimi-mls and mimid-agent-core: bead mimid-1vul.10, built as
     step 9 (one file, `mimid.sqlite`; `persisted_at(path)` became
     `persisted()`; `schema_version` replaces `user_version`).
5. **Outbound through the store.** Move room create, member and role
   changes, leave, send with attachments, edit, retraction, ban, unban,
   kick and report into `Store` methods. The JMAP hooks translate JMAP
   ids to store keys and SetErrors from the results; the error mapping
   (backend.rs:685-702) stays in mimid-agent-jmap. Oracle:
   `two_accounts_chat_through_jmap`,
   `attachments_are_checked_against_the_blob_store_and_limits`,
   `attachments_travel_sealed_and_arrive_whole`, the edits, moderation
   and report tests.
   Built (2026-11-20):

   - `mimid-agent-store::action`: one `Store` method per action of the
     user's: `create_room`, `change_members` (invites, removals, role
     changes and leaving, in that order, under one agent lock), `leave`,
     `forget_room`, `send` (it reads the attachments from the blob store
     and touches them), `edit`, `retract`, `mark_deleted` (a local
     deletion), `delete_message` (with the tombstone), `ban`,
     `set_ban_terms`, `unban`, `kick`, `report`, `add_person`,
     `rename_person`, `forget_person`, `set_read_position`,
     `forget_read_position`, and for the IRC front end `allow`, `deny`
     and `accept_invite`. They take store keys and user URIs and fail
     with `ActionError`; mimid-agent-jmap maps that to SetErrors with the
     same types and texts as before. A method that makes a record takes
     its key (`Store::new_key`, or a JMAP id, which a JMAP write keeps).
     Reactions are no action: the agent sends none.
   - The JMAP hooks translate ids, call the method, then write the JMAP
     object as before (the client's object, with `senderMsgId`,
     `deliveredAt`, the edit or retraction patch), so what a client reads
     is unchanged. Local objects (ChatContact, ReadPosition, a Message's
     `deletedAt`) are written by crate-jmap first and then into the
     records from the object.
   - The methods do not save. The front end that called one shows the
     result and then calls `Store::save`, so the record and what that
     front end shows of it are saved together. `Store::save` runs every
     registered `Frontend`'s `before_save` before it copies the records:
     the JMAP front end registers one (`JmapExt`, holding a clone of the
     `MemoryBackend`, which shares its state) that rebuilds `ext["jmap"]`
     from the backend's objects. Every save, whoever asks for it, thus
     carries every front end's current `ext`. `Store::sync` saves after
     each round's `Commit`, which now only shows the changes; a failed
     save is `SyncError::Save` and the round is not acknowledged. Saves
     are one at a time (an async lock in the store).
   - `merge_object`, `forget_object` and `reflect` are gone. A JMAP
     object without a record is no longer made into one at save; it is
     not saved, and logged (`agent_chat_object_without_record`). The test
     suite makes none.
   - The run-time rule of §7.7 and §7.8 keeps only what is still
     reachable: a ReadPosition may name a Chat the store does not hold,
     and a Message or ChatBan of a destroyed Chat keeps its room key
     (until §7.9, which deletes them).
     Records name users by URI and no longer come from JMAP objects, so
     an unknown user (`Sender::Unknown`, `None` as a participant, banned
     user or banner) is no longer made. Bead mimid-1vul.11 then removed
     the forms: every participant, sender, banned user and banner is a
     URI, and the database's schema version is 2 (a version-1 database
     is refused, §7.10).
     A JMAP object naming a ChatContact a client destroyed renders the
     user as `UNKNOWN_ID`, and `ext["jmap"]` keeps the object's id, as in
     step 4.
   - A write makes no person record; the next sync makes one for each
     participant it sees, as before. A room `create_room` records gets
     its participants and roles from the agent at once, not at the next
     sync. `leave` marks the room record leaving; nothing reads that yet.
   - A local deletion (`deletedAt` alone) keeps the record's content and
     kept report record, as `merge_object` did; the JMAP object is
     emptied by crate-jmap and `ext["jmap"]` keeps that.
   - `Message/reportAbuse` reads only the records, not the backend, to
     find what each Message kept: a Message has a record exactly when it
     has an object, so the answers are the same.
   - The unit test `every_object_renders_back_exactly` built its records
     with `merge_object`; it now writes them out by hand, with the same
     objects, and M1's sender is a user without a person record instead
     of `Sender::Unknown`.
6. **The feed.** The store publishes changes. The projector applies them
   from the feed instead of inline. The daemon builds the `Store` first,
   then `AgentChat::over(store)`; its sync loop calls `Store::sync`
   (crates/mimid-agent/src/daemon.rs:273-301), the projector feeds the
   EventSource `changes` broadcast (http.rs:229), and KeyPackage top-up
   takes the store's agent. Oracle: every mimid-agent integration test,
   most of all `stock_rust_client_chats_through_two_daemons` and
   `two_daemons_chat_over_http` (EventSource state changes), and
   `the_store_keeps_a_bounded_change_log_and_records_no_events`.

   Built (2026-11-20):

   - `mimid-agent-store::feed`. A sync round and every write method
     record their `Change`s in the store; the next `Store::save`
     publishes them. In order, one save at a time: every registered
     `Frontend`'s `before_save(store, changes)` is handed the batch; the
     records are written; the batch gets sequence numbers in a bounded
     in-memory log (`MAX_LOGGED_CHANGES`, 4096, INVENTED) and the last
     number goes out on a `tokio::sync::broadcast<u64>`
     (`Store::subscribe`, `Store::changes_since(seq)`, `TooOld`,
     `Store::last_seq`). A batch is published whether or not the write
     succeeded: memory holds it, and the next save that succeeds writes
     it. Sequence numbers start again at each start. Nothing new is
     saved, so the schema version stays 2.
   - `Change` gains `PersonForgotten`, `RoomForgotten {key, messages,
     bans}`, `MessageDeleted`, `BanChanged`, `InvitePending(n)`,
     `InviteGone(n)`, `ReadPositionMoved` and `ReadPositionForgotten`.
     A local deletion (`mark_deleted`) is a `MessageChanged`; the record
     keeps `deleted`. Kick records nothing: the agent's member change
     comes with the next sync.
   - The JMAP projector takes the batch in `before_save`, not from the
     broadcast, and before `ext["jmap"]` is rebuilt. This closes the
     crash window: a record that a sync or another front end made is
     saved with its JMAP object, so step 4's load rule (no `ext["jmap"]`
     means no object) loses nothing. Rendering records without `ext` at
     load was the other choice. It cannot give a Chat's `members` or
     other JMAP-only properties exactly, so it was not taken here; §7.11
     takes it for records made while JMAP was off, with those properties
     made as a first sync makes them. The projector does
     not use the bounded log, so a large sync round never makes it
     `TooOld`. `Commit` is gone, and `Store::sync()` takes no argument.
   - JMAP's own writes reach the feed too, so other front ends learn of
     them. An added record whose object exists (made by a JMAP hook)
     writes nothing. A changed record writes only what differs. The
     exception is `RoomChanged` after a member change: it shows
     `members` again from the room's participants, as the sync that
     follows would. A locally deleted message is shown emptied, as
     crate-jmap empties it. A save may come between a store write and
     the hook's insert, and project the record first. The hooks therefore
     insert with `insert_shown`, which overwrites the projected object
     instead of failing with `alreadyExists`.
   - Deleting a chat: the hook leaves, destroys the Chat, calls
     `forget_room` and saves. The projector destroys the Messages and
     ChatBans of the `RoomForgotten`. `Store::save` deletes the blobs
     itself after the next save that writes (or with no database):
     `forget_room` queues the room, and `Store::blobs_in_use` adds each
     front end's `Frontend::named_blobs` (JMAP: blob ids in
     `ext["jmap"]`). A failed save keeps the room queued for the next
     one; a restart loses the queue, and the quota cleans up later.
     Destroying a Chat still writes one Message change per Message. A
     long history can push a JMAP client's state out of
     `CHANGE_LOG_LIMIT`, and the client then resyncs. Not fixed.
   - Wake-ups: `Store::sync_wanted()` is a `Notify`. `create_room`,
     `change_members`, `leave`, `send`, `edit`, `retract`, `ban`, `unban`,
     `kick`, `allow`, `deny` and `accept_invite` notify it. The daemon
     uses it as its `sync_now`.
   - `AgentChat::over(Arc<Store>, account, options)` registers `JmapExt`
     with a clone of its own `MemoryBackend` and seeds from the records.
     `AgentChat::new` builds its own store and goes through the same
     path. `Store::open_database` and `Store::set_blobs` take `&self`
     (the blob store is a `OnceLock`). `AgentChat::store()` exposes the
     store.
   - The daemon opens the blob store, builds the `Store`, opens its
     database, then calls `AgentChat::over`. Its sync loop calls
     `Store::sync`, and KeyPackage top-up takes `Store::agent`. A task
     forwards the store's broadcast to the EventSource `changes`
     broadcast, replacing the sync loop's tick after each sync.
     `StartError::Records` carries a `FileError` from opening the
     database. Nothing but `Store::sync` calls `Agent::receive` or
     `Agent::acknowledge`; the tombstones depend on that, and
     `Store::agent` says so.
   - The unit test `the_sync_future_is_send` in mimid-agent-store lost
     its `Commit` argument. New tests: `feed`'s unit test of numbering,
     the bounded log and `TooOld`; mimid-agent-jmap `tests/feed.rs`
     (another front end's write reaches JMAP and the feed, and survives
     a crash right after its save; JMAP writes and a Chat deletion on the
     feed; writes wake the sync).
7. **Configuration.** Parse `[jmap]` and `[irc]` (section 5) with no IRC
   listener yet. Oracle: the config unit tests, plus new ones for the new
   keys and for refusing a non-loopback IRC address.

   Built (2026-11-20):

   - `Config` gains `jmap: JmapSetting {enabled}` (default true) and
     `irc: Option<IrcSetting {listen, server_name}>`, both
     `deny_unknown_fields`. `[irc].listen` defaults to `127.0.0.1:6667`
     (`DEFAULT_IRC_LISTEN`) and must be loopback
     (`ConfigError::IrcNotLoopback`); `server_name` defaults to
     `mimid.invalid` and must be 1 to 63 (RFC 2812 §1.1) letters, digits,
     `-` and `.` with a dot and no empty label
     (`ConfigError::IrcServerName`). JMAP off with no `[irc]` is
     `ConfigError::NothingServed`. There is no token key: the IRC client's
     PASS is the local token in `<state_dir>/agent-token`, as §4 says.
   - `listen` stays required. §5 lets it be left out when `[irc]` is set,
     but until step 8 a daemon without it would serve nothing; step 8
     makes it optional with the IRC listener (and `Daemon::local_addr`
     then becomes optional).
   - `[irc]` does not stop the daemon: `Daemon::start` logs
     `agent_irc_not_built` (WARN) and goes on without IRC. Refusing to
     start would leave no way to run with JMAP off, which needs `[irc]`.
   - `Daemon::start` runs the config checks again (`StartError::Config`),
     since `Config`'s fields are public and tests change them in code.
   - With JMAP off the daemon makes no `AgentChat`, so no `JmapExt` is
     registered on the store; the sync loop and KeyPackage top-up need
     only the store. `Endpoint` holds the store and `jmap:
     Option<Jmap {chat, dispatcher, session, session_state}>`; the
     did:webvh log is applied through `Store::agent`. Every JMAP route
     stays registered and answers `404` with an RFC 7807 body when `jmap`
     is `None`, after the Host check and the token, as an unknown path
     does. The store's broadcast is forwarded to the EventSource ticks
     only with JMAP on.
   - §5 said the HTTP listener still serves attachment links with JMAP
     off. The only attachment route is JMAP's download, and §7.4 drops
     IRC attachment links, so with JMAP off it serves the did:webvh log
     endpoint alone.
   - `Daemon::store()` exposes the `Arc<Store>`; the new test reads the
     records through it.
   - Found: records stored while JMAP is off carry no `ext["jmap"]`, so
     turning JMAP on again showed none of them (step 4's load rule).
     Mark chose to render them from the records (§7.11, bead
     mimid-1vul.12).
   - Tests: config unit tests for the defaults, every new key, refusing a
     non-loopback `[irc].listen`, bad server names, unknown keys in both
     tables and JMAP off without `[irc]`; `tests/jmap_off.rs`, a daemon
     with JMAP off that syncs alice's room and message into its store and
     answers 401 then 404 on each JMAP path and still serves the
     did:webvh log endpoint.
8. **The IRC front end** (section 4), off unless configured. New tests
   drive it over raw TCP. One of them runs a JMAP client and an IRC
   client on one daemon and checks that each sees the other's messages
   with the same `senderMsgId` and msgid.

   Built (2026-11-20), with §7's decisions:

   - `crates/mimid-agent-irc`: `IrcFrontEnd::bind(store, IrcOptions,
     PasswordCheck)` and `serve(stop)`. The crate cannot depend on
     mimid-agent, so the daemon hands it the `PASS` check as a closure
     over `LocalToken::matches`; the check stays the daemon's. Modules as
     in §4, except that `names.rs` holds the casemapping and `conn.rs`
     the keepalive.
   - Names: the front end registers a `Frontend` whose `before_save`
     gives each person a nick and each active room a channel, kept in
     `ext["irc"]` (`{"nick"}`, `{"channel"}`). The user's own nick is not
     stored: it is reserved first and comes out the same every time. A
     user with no person record (an inviter, a user invited by URI) has a
     nick in memory until the record is made. A room no longer active
     gives its channel name up, so JOIN after PART of `#lobby` hosts a new
     room shown as `#lobby` (§7.1) rather than `#lobby-xxxx`.
   - `JOIN 0` leaves every room the connection shows, each as PART does
     (§7.1): a PART line per channel from the user's own mask, reason
     `left every room`, and each room's record leaving, then left
     (§7.12). It was refused at first.
   - PRIVMSG to a nick is 404 naming the nick ("JOIN a new channel and
     INVITE them", §7.2); to an unknown nick 401.
   - The service has `help`, `allow`, `deny` and `invites`, and since
     bead mimid-e64f.23 `devices` and `forget-device <id>`
     (draft-atwood-jmap-chat-mimi-00 §Clients: list the clients bound to
     the account, and forget a lost one, which removes its leaves from
     the rooms this device shares with it). JOIN and PART
     make and leave rooms (§7.1), and JOIN of a pending invite's name
     accepts it (§7.13), so
     `create`, `leave` and `join` are gone; `remove` and `report` are not
     in v1. `deny` revokes the consent record, so the inviter can no
     longer fetch the user's KeyPackages: their INVITE fails at their own
     agent (`NoConsent`), and no invite reaches the user at all.
   - Every line written is at most 512 octets with its tags, the stricter
     reading of irc-lessons.md. The topic is `<name> | <room URI>`. 329
     and 333 give the time in the room record's key (when this store
     made the record), since the store keeps no room creation time. 004
     lists user mode `i`; `MODE <own nick>` answers 221 `+i`.
   - An edit's msgid is the ULID of its `edited_at` and its reference
     octets, the way `senderMsgId` is made. Edits and retractions of
     messages from before the connection are shown only if made after it
     registered.
   - `TooOld`: the connection tells the user with a NOTICE that messages
     in between are not shown, then brings every channel up to date from
     the records: JOIN for new rooms, PART for rooms gone, JOIN, PART and
     MODE for member changes. Channels still shown are not joined again.
   - KICK removes the user's devices and tells the sender so in a NOTICE;
     the nick stays in the channel, since the user stays a participant.
   - The daemon: `listen` is optional (`ConfigError::NoListen` with JMAP
     on), `Daemon::local_addr()` is an `Option`, `Daemon::irc_addr()` is
     new, the sync loop and the did:webvh log watch take the store, and
     one watch signal stops the HTTP server, the sync loop and every IRC
     connection (each gets `ERROR`). `agent_listening` gains `irc` and
     `irc_listen`. `agent_irc_not_built` is gone.
   - Tests: crates/mimid-agent/tests/irc.rs (registration burst, PASS,
     CAP, PING, 417, NOTICE, queries, two daemons over IRC and JMAP with
     the same msgid and `senderMsgId`, edits and retractions, MODE,
     invites and consent, `TooOld` and split 353), and an IRC connection
     in `no_token_in_logs.rs`; unit tests for the parser, tag escaping,
     casemapping, nicks, channels and CAP LS splitting. Not tested: the
     server's own PING and the ping timeout (the daemon has no knob for
     them).

9. **One database for the agent and the store** (bead mimid-1vul.10).
   The records, the agent's state, the delivery journal and OpenMLS's
   state share one SQLite file, so that receiving a message cannot lose
   it and storing it cannot repeat it.

   Built (2026-11-20):

   - One file, `<state_dir>/mimid.sqlite` (0600, in the 0700 state
     directory; `mimid_agent_core::DATABASE_FILE`; built as
     `agent.sqlite` and renamed by §7.17), replaces `mls.sqlite`,
     `state.json` and `chat.sqlite`. It holds OpenMLS's tables, the
     agent's state (`agent_state`, one row: what `state.json` held, as
     JSON), the journal (`journal`, one row per undelivered event, by
     sequence number) and the store's tables of step 4. A
     `schema_version (part, version)` table replaces `PRAGMA
     user_version`, which is one per file: the agent's tables are part
     `agent` version 1, the store's part `store` version 3 (2 was
     `chat.sqlite`). Another version is refused; nothing is converted. A
     state directory that holds `state.json`, `mls.sqlite` or
     `chat.sqlite` and no `mimid.sqlite` is refused with a message naming
     the file, rather than minting a second identity beside it; nothing
     runs in production, so there is no migration.
   - Connections. `mimi_mls::Store` owns its `rusqlite::Connection` by
     value and builds the OpenMLS provider for each call around
     `&Connection` (`SqliteStorageProvider<_, &Connection>`), and
     `Store::connection` lends it out. openmls_sqlite_storage opens no
     transaction of its own, so OpenMLS's writes join whatever
     transaction the agent has open on that connection. No `Rc`, `Arc`,
     `Mutex` or unsafe: the connection is `Send` and lives inside the
     `Agent`, which the store already keeps behind its async mutex; the
     borrowed provider is not `Send`, but never outlives the synchronous
     mimi-mls call that made it. The store reaches the same file through
     a second connection of its own (`Store::open_database`, which takes
     no path now: the agent names it, `Agent::database_path`). One shared
     connection would have made every save wait for the agent's lock,
     which a sync holds through network calls and attachment fetches;
     with two, SQLite keeps writers one at a time (both connections wait
     up to 10 s for the other's lock), and no transaction is ever open
     across an await, so the wait is short.
   - Two transactions per delivery. (a) `Agent::receive` handles each
     server Message in one transaction on the agent's connection: the
     secrets OpenMLS consumes, the group state, the agent state with the
     Message marked handled, and its events appended to the journal
     commit together, or none of them does and the Message is handled
     again. On an error the agent rolls back and rereads its state and
     groups, since what is in memory went past the database. `Agent::join`
     is one transaction too, since it decrypts held messages. (b)
     `Store::sync` writes the round's records and removes the delivered
     events from the journal in one transaction on the store's connection
     (`Agent::acknowledge_in`, which checks that the transaction is on the
     agent's database). A crash before (a) commits decrypts again; between
     (a) and (b) the journal delivers again; before (b) commits both roll
     back and the journal delivers again; after it nothing comes again.
     Receive, store and acknowledge in a single transaction was not done:
     the store's part runs front ends' `before_save`, attachment fetches
     and joins, all async, and front ends save on their own, so it would
     hold a write transaction across awaits and mix front-end saves into
     the agent's commit. The journal stays, as the hand-off between the
     two transactions.
   - A leave this agent commits from inside a Message (the lowest
     remaining leaf commits a member's leave proposals) is sent between
     two transactions: the first ends with the Message's position
     (`in_progress`: the Message and how many of its FanoutMessages are
     handled), the Commit goes to the server and merges, and a restart
     goes on from the position. A crash after the merge and before the
     next transaction loses that Commit's own `MembersChanged` event; the
     membership the agent reports is still right (journal.rs
     Limitations).
   - API: `mimi_mls::Store::connection`, `Identity::store`;
     `Agent::database_path`, `Agent::acknowledge_in`,
     `AgentError::Database`, `mimid_agent_core::{DATABASE_FILE,
     SCHEMA_VERSION}`; `Receipt` names a journal sequence number, not a
     count. `Store::open_database()` (no path), `Store::database_path`,
     `Database::save_with`, `FileError::Acknowledge`;
     `AgentChat::persisted()` replaces `persisted_at(path)`;
     mimid-agent's `CHAT_STORE_FILE` is gone and it re-exports
     `DATABASE_FILE`. The feature `fail-points` (tests only) adds
     `Agent::fail_next`.
   - Tests: mimid-agent-store `tests/crash.rs` fails each boundary once
     (inside (a) after decrypting, between (a) and (b), inside (b) before
     the acknowledgement, after (b)), with a restart and in the same run,
     and checks every message is stored once and the journal holds what
     the failed step committed; replacing the rollback with a commit makes
     it fail. mimi-mls `store::tests` shows a caller's rollback undoes
     OpenMLS's writes; agent-core's state tests refuse another schema
     version and the older layout. Changed: mimid-agent-jmap
     `store_file.rs` and `chat_delete.rs` failed a save by making the
     store's directory unwritable, which would now stop the agent's
     writes too; a front end whose `before_save` fails does it instead.
     `chat_delete.rs` no longer requires the room URI to be absent from
     the whole file, since the agent's own state (formerly `state.json`)
     names the rooms it left; it checks the store's tables for it. The
     tests that passed `persisted_at(path)` or `open_database(path)` call
     `persisted()` and `open_database()`; mimid-agent-store
     `tests/database.rs` reads the version from `schema_version`, and
     mimid-agent `tests/jmap_off.rs` looks for `DATABASE_FILE`.

10. **Sending survives a crash** (bead mimid-e64f.16; Mark approved
    2026-11-20). Step 9 made receiving safe; sending was not. The agent
    encrypted a message (consuming a ratchet generation), sent it, and only
    on the answer did the store record it; the digest that marks the
    stored copy as the agent's own was saved after the network call too,
    and a Commit was merged only after the answer. A crash after the hub
    accepted lost the message for good, since MLS cannot decrypt the
    sender's own message, and left the group at the old epoch with its own
    Commit coming back as something it could not process.

    Built (2026-11-20):

    - The outbox (`outbox` table in `mimid.sqlite`, part `agent` version
      2; crates/mimid-agent-core/src/outbox.rs). `Agent::send_content`
      encrypts, saves the MLSMessage's digest and writes an outbox entry
      (room, the MLSMessage bytes, the mimi-content as encrypted) in one
      transaction with OpenMLS's writes, before anything leaves. A member
      Commit (`Agent::build_commit`: invite, moderation, a leave this
      device commits, a credential update) is made pending and written as
      an entry (the UpdateRequest bytes and the users it removes for lacking
      AppDataUpdate) in one transaction.
    - The answer, in one transaction. Accepted message: its plaintext goes
      to the journal as `Event::Sent` (this user's own message), the
      `messageIds` the provider named (findings log F18) are kept so the
      stored copies are skipped, and the entry is removed. Accepted
      Commit: merged, its events journaled, entry removed. Refused: the
      entry is removed (a Commit cleared) and the refusal returned. No
      answer (an error reaching the server): the entry stays, and with it
      a Commit's pending state.
    - Restart, or a lost answer. `Agent::receive` first sends every entry
      again, oldest first, with the same bytes; it never encrypts again,
      which would use a ratchet generation twice or skip one. The provider
      answers a request its hub already accepted from its record, with the
      earlier answer and the stored copies' ids (findings log F11;
      mimid-server keeps the record 30 days, `ACCEPTED_RETENTION_MS`,
      INVENTED, NOT FROM SPEC), so the hub sees it once. The entry then
      ends as above; a Commit finished this way also journals a
      `MembersChanged`, since no caller is left to report it. A refusal
      now (the room moved on meanwhile) drops the entry with an
      `Event::Problem`.
    - The store. `Store::sync` stores an `Event::Sent` like a received
      message, and a message it already has (by MIMI message ID or
      alias) is not stored again. `Store::send`, `edit` and `retract`
      keep the agent locked until their record or alias is in, so a sync
      cannot store the journal's copy first.
    - Proposals and external Commits did not go through the outbox at
      first: their digests were saved before they left, and what the agent
      did next (a room marked as being left, a room joined) could be lost.
      §7.19 puts them in the outbox too.
    - Receiving: a Message is skipped if its id is among the kept
      `messageIds`, if its digest is the agent's, or if its Chat's last
      handled Message (`State::last_handled`) has an id that does not sort
      before it (findings log F2). On `cannotCalculateChanges` (JMAP) the
      agent reads, per Chat, `Message/query` sorted by `id` with that
      Message as `anchor` and `anchorOffset` 1; on `cannotResume` (the
      stream) it subscribes again with `after`, the same per Chat (findings
      log F12).
    - Tests: mimid-agent-store `tests/send_crash.rs` fails a send after
      the outbox entry and before sending (`FailPoint::BeforeSend`), after
      the hub accepted and before the answer is handled
      (`FailPoint::AfterAccepted`), and after the answer and before the
      store saved its record (a restart without a save), with a restart and
      in the same run, and a Commit (an invite) at the first two; it
      checks each message is stored once by alice's store, received once
      by bob's agent with no Problem, and that the Commit ends merged at
      the next epoch with bob at the same one. mimid-server
      `jmap_room_create.rs` sends a message and a Commit twice and
      requires the same answer and no second stored copy; `store::accepted`
      tests the retention.

Steps 3 and 5 are the large ones. Step 3 cannot be cut much smaller: the
store has to be the only copy of inbound state before it can save it.
Keeping format 1 on disk through step 3 is what keeps it reversible.

## 4. The IRC front end

### Crate

`crates/mimid-agent-irc`, a library over `Arc<Store>`, with tokio (net,
io-util, sync, time), tracing and thiserror. No IRC library: the parser is
small, and docs/irc-lessons.md lists exact behaviour that a library would
hide.

```text
src/lib.rs       IrcFrontEnd::over(store, config); # Limitations
src/listen.rs    accept loop; loopback check
src/conn.rs      one task per connection: reader, writer queue, keepalive
src/line.rs      parse and write lines; tag escaping; 512-octet splitting
src/register.rs  CAP, PASS, NICK, USER, the burst
src/names.rs     nick and channel assignment, ASCII casemapping
src/command.rs   the v1 commands
src/render.rs    store records and changes to IRC lines
src/service.rs   the `mimid` service nick
```

### Loopback and authentication

- The listen address must be loopback, or the daemon refuses to start, as
  for the HTTP endpoint (crates/mimid-agent/src/config.rs:60-63).
- The default port is 6667. Browsers refuse to connect to it (it is on the
  Fetch standard's bad-port list), which shuts out the old HTTP-to-IRC
  cross-protocol trick from web pages.
- The client presents the agent's local token with `PASS <token>`, before
  registration ends. The check is `LocalToken::matches`, constant time
  (crates/mimid-agent/src/token.rs:99-101). A wrong or missing token gets
  464, then `ERROR :Closing Link`, and the connection closes. Before a good
  PASS only CAP, PASS, NICK, USER, PING and QUIT are read. A first line
  that looks like HTTP (`GET `, `POST `) closes the connection.
- The PASS line is never logged. The `no_token_in_logs.rs` canary gains an
  IRC connection.
- No SASL. docs/irc-lessons.md ("No SASL", "Skip") says clients that see
  `sasl` try it, and the user is already authenticated out of band. SASL
  PLAIN would only carry the same token in a form fewer clients set up.
  Every client has a server password field: irssi `/connect -password`,
  WeeChat `irc.server.<name>.password`, HexChat's server password. The
  token is 43 base64url characters with no spaces, so it fits one PASS
  parameter.
- After registration send 900 with the user's nick as the account name
  and the user URI in the text, and 330 in WHOIS, which gives the user
  URI as the account (§7.15).
- AGENTS.md's boundary table gains a row: Agent (loopback IRC), the local
  token by PASS. That is one check at the IRC boundary, with a test that a
  wrong token is refused.

Several IRC connections at once are fine. Each is the same user, as with a
bouncer, and each sees every change.

### Names

All names are assigned once, stored in the record's `ext["irc"]`, and
never change, so logs and scripts keep working.

- **Casemapping**: `CASEMAPPING=ascii`, folding exactly ASCII.
- **Nicks**: from the user URI `mimi://<domain>/u/<local>`, never from a
  display name, so a peer cannot pick its own nick or claim another
  user's. Characters are `[A-Za-z0-9_-]`, not starting with a digit or
  `-`; anything else becomes `_`. `NICKLEN=30`.
  - The user's own nick is its local part. It is reserved first, so no
    remote user can take it (tailircd's shadowing, irc-lessons.md).
  - A user on the user's own provider gets the bare local part.
  - A user on another provider gets `<local>-<label>`, where the label is
    the first DNS label of the domain: `bob-evil` for
    `mimi://evil.example/u/bob` (question 3).
  - On a remaining collision, or past NICKLEN, cut and append `-` and 4
    base32 characters of SHA-256 of the URI.
- **Hostmask**: `<nick>!<local>@<domain>`, the provider domain from the
  URI. It is stable, truthful and needs no cloak. WHOIS 311 carries the
  full URI as the real name, and 320 the did:webvh DID if there is one.
- **Server name**: `mimid.invalid` by default. It has a dot, so clients do
  not read the prefix as a nick.
- **Channels**: `#` and the room's `room_name`, with characters outside
  `[A-Za-z0-9_.-]` dropped, `CHANNELLEN=64`. A room with no usable name
  gets `#` and the id part of its room URI. A collision gets `-` and 4
  base32 characters of SHA-256 of the room URI. Non-Latin room names come
  out as ids; that is a known limit.
- **1:1 rooms** (question 2): a room flagged `direct` with exactly one
  other participant is a query with that user's nick, not a channel. If a
  third participant joins, it becomes a channel and the client gets a
  JOIN for it.

### The mapping

| Store | IRC |
|---|---|
| Active room | Channel. After 422 the server JOINs the client to every active room it has not hidden, then sends 332/333 and 353/366 for each. |
| Room subject and name | TOPIC: `subject \| name \| URI`, an empty part left out; 333 only when the subject's setter and time are known. `TOPIC #c :text` sets the room's subject; 482 only for a role without `canChangeRoomSubject` (§7.14). |
| Participants | 353 NAMES, WHO and WHOIS 319 list every participant, remote or not (irc-lessons.md "Virtual users"). Banned users are left out. |
| Members changed | JOIN and PART lines for others, a PART with "no longer in this room" (MIMI carries no reason, §7.16); MODE +o/-o for role changes. |
| This user left (`Event::Left`) | PART from the user's own nick, reason "no longer in this room", or the reason the user gave with PART on another IRC connection of the same daemon (§7.16). |
| Role "admin" | `@`. `PREFIX=(o)@`. `MODE #c +o nick` and `-o` are `Store::change_role`. |
| Bans | `MODE #c b` lists the room's banned users as 367 `nick!*@domain`, then 368. `MODE #c +b nick` (or `nick!*@*`) is `Store::ban`, `-b` is `unban`. Other masks are refused with a NOTICE and change nothing. |
| Kick | `KICK #c nick :reason` is `Store::kick` (the user's clients leave; they stay a participant). |
| Channel modes | `CHANMODES=b,,,nt`; 324 answers `+nt`, which is true: only members send, and the room policy says who sets the topic (§7.14). No 329 (§7.15). 004 lists the same modes. |
| Message | PRIVMSG from the sender's hostmask, with `time` (`accepted_at`) and `msgid` (`senderMsgId`). A body with newlines, or longer than one line, is split on line breaks and UTF-8 boundaries; only the first line carries `msgid`. |
| Own message sent elsewhere (JMAP, another IRC connection) | PRIVMSG from the user's own hostmask. Whether every client shows those well without echo-message is *unverified*. |
| Reply | The text addressed `<nick>: ` to the replied-to sender, unless it starts so already, and `+draft/reply=<msgid of the target>` when message-tags is on (§7.26). |
| Edit | A new PRIVMSG from the original sender, text `(edited) <new text>`, with its own msgid and `+draft/reply` naming the first version. |
| Retraction | NOTICE to the channel from the server: `<nick> retracted a message`. With message-tags, `+draft/reply` names it. The text is not repeated. |
| Reactions | TAGMSG from the reacting user with `+draft/react` and `+draft/reply`, without message-tags an ACTION line; a client's `+draft/react` TAGMSG reacts (§7.27). |
| Notices | NOTICE to the channel from the server name, with the store's notice text. IRC has a system sender, so the JMAP rule that the account sends them (sync.rs:446-452) does not apply. |
| Attachments | One NOTICE line per attachment from the sender: file name, size, media type and an agent URL (question 4). Without the HTTP endpoint, no URL. |
| Pending invite | `:<inviter> INVITE <nick> #<channel>`, the channel name the room will have, read from the Welcome before joining (§7.13). JOIN of that name accepts it (`Agent::join` through the store); the client then gets JOIN of the same name. Only when the Welcome cannot be read is it `&invite-<number>`, whose JOIN is answered with JOIN and PART of it before the room's JOIN. The `&` channel never exists. |
| Invite someone | `INVITE <nick> #c` is `Store::invite`. A user URI or `user@domain` (for `mimi://domain/u/user`, §7.15) in place of the nick is also taken, since a user never seen has no nick. |

**Text from peers is data.** CR, LF and NUL in peer text are split or
replaced. A peer's `\x01` is replaced with U+2401, so a peer cannot send
CTCP (a DCC request, say) to the user's IRC client. irc-lessons.md says to
pass CTCP through, but that is for traffic between IRC clients; here the
far side is a MIMI peer. Other IRC formatting codes pass as they are:
rendering is the client's job (AGENTS.md).

**CTCP from the user.** `ACTION` is sent as text starting `/me `, and text
from peers that starts with `/me ` is shown as ACTION. Other CTCP to a
nick is answered by the server (`VERSION`) or dropped; it never reaches a
peer, so the client's version is not sent to strangers.

**Sending.** PRIVMSG to a channel or query is `Store::send` with
`text/plain`. One line is far under `MAX_TEXT_LEN`
(crates/mimid-agent-core/src/agent.rs:67), and each PRIVMSG is one MIMI
message. A `+draft/reply` tag on a PRIVMSG naming a message of the room
sends it as a reply (§7.26; before that it was dropped, since
`Agent::send_message` took no `inReplyTo`). IRC has no upload, so v1 sends no
attachments. Edits and retractions are not sent from IRC in v1.

**Echo.** With echo-message the sender's connection gets the same PRIVMSG
as the others, with the same `msgid` and `time`, both from the stored
record (irc-lessons.md "echo-message").

**Playback.** No chathistory in v1 (question 6). After the autojoin, each
channel gets the messages stored since the IRC front end's mark for that
room, at most 200, each with `time` and `msgid`. The mark moves when a
message has been written to any IRC connection, and is kept in the room's
`ext["irc"]`.

### Capabilities in v1

Only caps that are wired up (irc-lessons.md):

- `message-tags` (and with it `msgid`; there is no separate cap);
- `server-time`;
- `echo-message`.

Not in v1: `sasl`, `labeled-response`, `batch`, `draft/chathistory`,
`draft/message-redaction`, `account-notify`, `invite-notify`, `chghost`,
`setname`, `away-notify`, `multi-prefix`, `draft/read-marker`. Each needs
work the lessons list, and none is needed to chat.

ISUPPORT (005): `CASEMAPPING=ascii`, `CHANTYPES=#&`, `PREFIX=(o)@`,
`CHANMODES=b,,,nt`, `NICKLEN=30`, `CHANNELLEN=64`, `TARGMAX=PRIVMSG:1,NOTICE:1,JOIN:,PART:,KICK:1,WHOIS:1`,
`LINELEN=512`, `UTF8ONLY`, `NETWORK=mimid`. Invalid UTF-8 from the client
is refused with a NOTICE saying the line was not sent.

### Commands in v1

From docs/irc-lessons.md "Must do":

- **Registration**: `CAP` (LS 302 after the client's first line, REQ
  acked or refused as a whole, continuation lines for a long LS, the nick
  as target once registered), `PASS`, `NICK`, `USER`. The client's NICK is
  accepted, 001 targets the real nick, and a NICK change follows if they
  differ. A later NICK gets 432, never 462. Burst: 001 (`Welcome to the
  mimid IRC Network nick!user@host`), 002 to 004, 005, 900, then 422.
- **Keepalive**: `PING` and `PONG`. The server pings after 90 s idle and
  closes 90 s after an unanswered ping. It answers `:server PONG server
  :token`. INVENTED VALUES.
- **Lines**: read up to 8191 octets of tags plus 512 once message-tags is
  on; a longer line gets 417, not a disconnect. Write lines of at most 512
  octets with prefix and tags; split 353; unescape tags per the spec.
- **Channels**: `JOIN`, `PART` (question 1), `TOPIC` (read; set is the
  room's subject, §7.14),
  `NAMES`, `MODE` (queries answer 324, no 329 (§7.15), then 367/368,
  348/349 empty, 346/347 empty; never 482 for a query; `+o -o +b -b`),
  `KICK`,
  `INVITE`, `LIST` (322 per room, then 323).
- **Users**: `WHO` (always ends 315), `WHOIS` (always ends 318, with 401
  first for an unknown nick), `ISON`, `USERHOST`, `AWAY` (305 and 306; no
  301, since MIMI carries no presence).
- **Messages**: `PRIVMSG` (412 for no text), `NOTICE` (never an error
  answer; to a peer it is sent as a plain message), `TAGMSG` (read and
  dropped).
- **Other**: `QUIT` (`ERROR :Closing Link` first). Anything else gets 421.
- **Flood control**: none on loopback.
- **The `mimid` service nick** (INVENTED, NOT FROM SPEC, documented in the
  crate): `allow <nick|uri|user@domain>`, `deny <nick|uri|user@domain>`,
  `invites`, `join
  <number>`, `create <name>`, `leave #c`, `remove #c <nick>` (the user
  leaves the participant list), `report <msgid> [reason]`, `help`. These
  are what IRC has no command for (question 5).

## 5. The daemon

One daemon, one `Store`, any mix of front ends.

```toml
listen = "127.0.0.1:8484"     # HTTP: JMAP, attachment links, the did:webvh log
                              # endpoint. Loopback only. As today.

[jmap]                        # optional
enabled = true                # the default

[irc]                         # optional; absent means no IRC
listen = "127.0.0.1:6667"     # loopback only
server_name = "mimid.invalid" # optional
```

- With `[jmap] enabled = false` the HTTP listener still serves the
  did:webvh log endpoint, and answers 404 on the JMAP paths (step 7: with
  no IRC attachment links, §7.4, there are no attachment links outside
  JMAP).
- `listen` may be left out when `[irc]` is set. IRC then has no
  attachment links.
- With JMAP off and no `[irc]`, the daemon refuses to start: it would
  serve nothing.
- Every address is checked for loopback, and unknown keys are refused, as
  now (config.rs:60-63, config.rs:87-129).
- The sync loop (daemon.rs:273-301) calls `Store::sync`. A send from
  either front end wakes it, and so does the provider's EventSource
  (§8); the interval is only a fallback.

The crate docs and AGENTS.md change with this: mimid-agent stops being
only "the JMAP Chat ↔ MIMI bridge" in the crate map, and the crate map
gains mimid-agent-store and mimid-agent-irc. That edit comes with the
code, not with this note.

## 6. Open questions for Mark

1. **What PART and JOIN mean.** Leaving a MIMI room removes every device
   of the user, and only a new invite brings them back
   (crates/mimid-agent-core/src/lib.rs:71-78). Many IRC clients send PART
   when the user closes a window. If PART means leave, closing a window
   leaves the room for good. Likewise, if JOIN of an unknown name hosts a
   new room, a typo makes a room on the hub. Recommendation: PART only
   hides the channel from IRC (kept in `ext["irc"]`, undone by JOIN);
   leaving is `/msg mimid leave #c`. JOIN of an unknown channel is 403;
   a new room is `/msg mimid create <name>`.

2. **1:1 rooms as queries.** MIMI has no marker for a one-to-one room,
   and the JMAP front end refuses direct Chats today
   (crates/mimid-agent-jmap/src/lib.rs:133). IRC users expect `/msg bob`
   to just work. Recommendation: a local `direct` flag on the room. It is
   set when the user sends a PRIVMSG to a nick with no direct room yet:
   the store hosts an unnamed room and invites that user, which the hub
   sees as a new room. A room joined from an invite is direct when it is
   unnamed and has exactly two participants. JMAP keeps showing all of
   them as group Chats for now.

3. **Domain suffix on other providers' nicks.** With bare local parts for
   everyone, whoever is seen first gets `bob`, so a stranger on another
   provider can take the nick of a contact the user meets later.
   Recommendation: bare nicks only for users on the user's own provider;
   everyone else is always `<local>-<label>`. Nicks are longer, but a
   nick never moves between people.

4. **Attachment links for IRC.** IRC clients cannot send the bearer
   header the download route needs (http.rs:31-33). Putting the token in
   the URL would put full access in every chat log. The other way is a
   link per blob, `/irc/blob/<HMAC of the blob id>/<name>`, keyed by a
   second 0600 secret, read only, behind the same Host check and download
   headers (http.rs:660-676). That is a second way to authorize at the
   agent boundary, which AGENTS.md says has one. Anyone who can read the
   chat log can fetch the file while the daemon runs, but the log already
   holds the plaintext. Recommendation: allow these links, downloads only,
   and add the row to the AGENTS.md table. If not: v1 shows file name and
   size only.

5. **Consent and invites from IRC.** Today consent decisions are made
   outside JMAP, and which invites are joined is fixed in the config
   (crates/mimid-agent/src/lib.rs:97-100). IRC can do better: show
   refused invites as INVITE lines, accept one by JOIN, and allow or deny
   users through the `mimid` service nick. Recommendation: yes. The IRC
   user holds the same token as a JMAP client, so this gives no one new
   power, and it is the only way an IRC-only user can accept anyone.

6. **chathistory in v1.** draft/chathistory needs `batch` and a complete
   `labeled-response` (irc-lessons.md). The store has the history, so the
   work is all on the IRC side. Recommendation: not in v1. v1 plays back
   up to 200 unseen messages per channel on connect, with server-time and
   msgid. Add chathistory in a second step, keyed by room and account,
   not by nick.

## 7. Mark's decisions (2026-11-20)

These answer §6 and override the recommendations there and anything in
§4 that disagrees.

1. **PART and JOIN.** PART leaves the room for real: every device of the
   user leaves, and only a new invite brings them back. JOIN of a channel
   name that is not one of the user's rooms hosts a new room with that
   name. The IRC front end does what IRC users expect; closing a window in
   a client that sends PART has the same effect.
2. **No queries in v1.** v1 has channels only. A PRIVMSG to a nick
   answers with an error that tells the user to make a room and invite
   them. No `direct` flag. (Lifted for IRC v2 by S2, §7.25; the store's
   `direct` flag is §7.29; IRC v2's queries are §7.32.)
3. **Every nick carries its provider.** `<local>-<label>` for everyone,
   the user's own provider included. A nick never moves between people.
4. **No attachments in v1.** Neither links nor a placeholder line are
   required; no `/irc/blob` route and no new authorization at the agent
   boundary. A message's text is shown; its attachments are not. (For IRC v2 and the other front ends the store
   now makes attachment links, §7.30.)
5. **Invites and consent from IRC: yes.** A pending invite shows as an
   INVITE line and JOIN accepts it; `/msg mimid allow <nick>` and
   `/msg mimid deny <nick>` set consent.
6. **No history in v1.** No replay on connect and no chathistory; the IRC
   client sees what arrives while it is connected.

Added on 2026-11-20:

7. **A ChatContact that is gone.** Superseded by §7.10: there is no
   format-1 reader; what remains is the run-time rule in §3 step 4.

   When the format-1 reader meets a
   Message, a Chat member or a ChatBan naming a ChatContact that is not
   in the file (JMAP clients may destroy ChatContacts), it keeps the item
   with the user marked unknown and logs a warning, instead of refusing
   the whole file. The warning is one per file conversion and gives the
   count, not one per item. In the records an unknown user is
   `Sender::Unknown`, or `None` as a participant, a banned user or a
   banner; the JMAP id the item named stays in its `ext["jmap"]`.
8. **A Chat that is gone.** Superseded by §7.10: there is no format-1
   reader or format-2 file; what remains is the run-time rule in §3
   step 4.

   The same rule for Chats. crate-jmap's
   Chat/set destroy keeps the Chat's Messages and ChatBans, so the
   format-1 reader keeps a Message, ChatBan or ReadPosition naming a Chat
   not in the file, with its room marked unknown, and logs one warning per
   file with the count. Format 2 must keep them the same way (step 4).

9. **Deleting a chat deletes its local data (Mark, 2026-11-20).** When a
   front end deletes a chat, the store deletes everything it keeps of
   the room, not only the room record: its messages, bans and read
   positions, the attachments of its messages waiting for a retry, and
   the blobs of its attachments. draft-atwood-jmap-chat-00 "Destroying a
   Chat" removes the Chat from the caller's view and forbids deleting
   the other participants' history; it does not ask the caller's own
   copy to be kept, and crate-jmap kept a destroyed Chat's Messages and
   ChatBans, plaintext no client could reach. Bead mimid-1vul.9 built it:

   - `State::remove_room` (through `Store::forget_room`) takes every
     record of the room and leaves a `Tombstone::Room {key, uri}`. It
     returns what it took: the message and ban keys, and the blob ids no
     remaining message names, marking those of the user's own messages.
   - While the tombstone is kept, `Store::sync` makes no record for the
     room and drops its events, so the agent delivering them again (an
     unacknowledged round, a restart) brings nothing back. The tombstone
     is settled right after each `Agent::receive`: if the agent is out of
     the room, or does not know it, no event of it can come after this
     delivery, so the tombstone goes once the round is acknowledged; if
     the agent is in the room again (a new invite was joined, or a room
     was forgotten without leaving), it goes at once, and the room gets a
     new record with a new key; while the agent is still leaving it
     stays. Rejoining the same room URI thus starts an empty chat.
   - The JMAP front end's `Chat/set` destroy leaves the room, destroys
     the Chat (crate-jmap destroys its ReadPositions), forgets the room,
     then destroys its Messages and ChatBans in the backend, each a
     change of its type, and saves. After a successful save it deletes
     the blobs that nothing names any more (`Store::delete_blobs`): at
     once for received attachments; for the user's own, which were
     uploads, only if stored or sent at least an hour before (RFC 8620
     §6 keeps an unreferenced upload for an hour), else the quota takes
     them later. A blob stored again after the deletion is kept.
   - The database sets `PRAGMA secure_delete`, so a deleted row's text is
     overwritten in the file instead of staying in a free page.
   - People are not the room's: a person first seen in a deleted room
     keeps their record (a ChatContact), as before.


10. **Store in SQLite, no migration from chat.json (Mark, 2026-11-20).**
    The store's on-disk form is an SQLite database in the agent's state
    directory (`chat.sqlite`, 0600), with a table per record type, a
    schema version, and saves that write only what changed, in one
    transaction. JSON rewrote the whole history on every save, could not
    shrink, had no index, and could not share a transaction with the MLS
    state. Nothing runs in production, so there are no old files: the
    store starts from an empty database, and the agent neither reads nor
    writes `chat.json`. There is no format-1 reader and no conversion; a
    later schema change refuses an older database clearly rather than
    converting it. The SQLite crate is the one mimi-mls already uses.
    Whether the records can share `mls.sqlite` and one transaction with
    the MLS state is bead mimid-1vul.10. They can: §3 step 9 puts them, the
    MLS state, the agent's state and the journal in one file,
    `mimid.sqlite`, which replaces `chat.sqlite`.

11. **JMAP built from the store (Mark, 2026-11-20).** When the JMAP front
    end starts over a store, a record without `ext["jmap"]` (made while
    JMAP was off, for example in an IRC-only run) is shown as a JMAP
    object made new from the record alone, so a JMAP client sees every
    room, message, person and ban the store holds. Records with
    `ext["jmap"]` keep their exact rendering. The store stays the only
    source of truth: nothing of JMAP's is kept while JMAP is off. Bead
    mimid-1vul.12 built it:

    - The new object is the one the projection makes when a sync brings
      the record, built by the same functions (`Render::new_chat`,
      `new_message`, `new_ban` in mimid-agent-jmap's `render`; a person
      and a read position as they render): a group Chat named by the
      room's name, `members` from the room's participants and roles (the
      user left out of a room they are leaving or have left; a banned
      participant and a user with no person are not members),
      `unreadCount` 0 (crate-jmap computes it from the Messages and
      ReadPositions at each `Chat/get`, so clients read the real count),
      no pins, not muted; a Message delivered, with its content as the
      projection shows it (one deleted here alone emptied); a ChatBan
      with the record's reason and expiry; a ChatContact's `firstSeenAt`
      and `lastSeenAt` the person's first sight.
    - The dates the record does not hold: a Chat's `createdAt`, its
      members' `joinedAt` and a ChatBan's `createdAt` are the start, as
      they are the time of the sync that makes them when JMAP is on. A
      Message's `receivedAt` is the record's `received_at`, its arrival
      here (§7.18), with JMAP on or off. Until §7.18 the store kept no
      time of receipt and `sentAt` (the hub's acceptance time) stood in
      for it, since the start would date every old Message alike.
    - The objects are seeded like the others, so they are no change: a
      client's `/changes` from the states read after the start names only
      what comes after. State strings restart at each start anyway. The
      next save keeps the objects in `ext["jmap"]`, so a later start shows
      them exactly; a crash before that save makes them again, with the
      next start's dates. An INFO event,
      `agent_chat_objects_made_from_records`, counts them.
    - Nothing on disk changed for this: no migration, and the schema
      version stayed 2 (§7.18 later bumped it for `received_at`).
    - Test: mimid-agent `tests/jmap_seed.rs` runs one scenario (a room
      with bob an admin, two messages, an edit, a ban) twice, once with
      bob's JMAP on and once with it off and then on, and compares what
      bob's client reads property by property, ids and dates named
      alike. They agree. Ids are minted per run and dates are each run's
      own, so the test checks what the dates say: the ones above are not
      before the start, and `receivedAt` is the record's arrival time,
      before the restart (§7.18). A second start shows every object as the
      first did, and `/changes` names only a new Message.

12. **JOIN 0 leaves every room (Mark, 2026-11-20).** `JOIN 0` is honoured
    as IRC defines it: the user leaves every room, for real, as §7.1 makes
    PART leave. The first v1 front end refused it with a NOTICE; bead
    mimid-1vul.13 changed that:

    - `JOIN 0` (the whole parameter; a `0` inside a list is a channel name
      and refused as one) leaves each room the connection shows through
      `Store::leave`, the same path as PART: every device of the user
      leaves, and only a new invite brings them back.
    - Each room gives a PART line from the user's own mask with the reason
      `left every room`; the record goes leaving at once and left when the
      hub has removed the user. With no channel shown it says nothing.
    - Test: mimid-agent `tests/irc.rs` `join_0_leaves_every_room`.

13. **A pending invite under its room's channel name (Mark,
    2026-11-21).** irssi 1.4.3 keeps a window for every JOIN it sends
    until the server answers it under the same name. The first front end
    showed a pending invite as `INVITE <nick> &invite-<n>` and answered
    `JOIN &invite-<n>` with `JOIN #<room>`, so irssi kept a dead
    `&invite-<n>` window active and the user's next line went to
    `PRIVMSG &invite-<n>`, which got 403 (bead mimid-br6m). Of the two
    ways out, Mark chose to show the invite under the room's real
    channel name, with `&invite-<n>` only as a fallback:

    - The store reads each pending invite's Welcome at the sync by
      staging it without joining (`Agent::invite_details`, through
      mimi-mls `Member::welcome_details`): the inviter, and from the
      verified GroupContext the room URI and the RoomMetaData
      `room_name`. Staging stores nothing; OpenMLS consumes the
      KeyPackage only when a staged Welcome becomes a group
      (`StagedWelcome::into_group`), so the later join still has it.
      The inviter was already read this way for the invite policy; the
      same staging now gives all three.
    - The invite is shown as `INVITE <nick> #<channel>`, the channel
      made from the name and URI by the §4 "Names" rules, against the
      channels already shown and the names other invites hold. The name
      is held from then on and the room takes it when it arrives.
    - JOIN of that name accepts the invite. §7.1 says JOIN of an unknown
      name hosts a new room; a name shown in a pending INVITE is not
      unknown. While the accepted room has not arrived, JOIN of its name
      does nothing; the room's JOIN, under that name, follows at the
      next sync.
    - Collisions: whichever comes first, a room shown or an invite,
      keeps the name, and the later one gets `-` and 4 base32
      characters of SHA-256 of its room URI, as two rooms do. A room the
      user hosts by another front end while the invite waits is shown
      as `#<name>-xxxx`, and JOIN `#<name>` still accepts the invite;
      from IRC the user cannot host that name meanwhile, since JOIN of
      it accepts. A second invite to the same room shares the name.
    - Fallback: when the Welcome cannot be read, the invite is
      `&invite-<n>`. JOIN of it accepts, and is answered with
      `:<me> JOIN &invite-<n>` and `:<me> PART &invite-<n> :accepted`
      before the room's `JOIN #<channel>`, so the client closes the
      window it opened. `JOIN &invite-<n>` also accepts an invite shown
      under a channel name, answered the same way.
    - `/msg mimid invites` lists both forms: `JOIN #<channel> or JOIN
      &invite-<n> to accept`, or only `&invite-<n>` in the fallback.
    - Names held for an accepted invite are given up when the room
      arrives; if it never does, the name stays held until the daemon
      restarts.
    - Tests: mimid-agent `tests/irc.rs`
      `pending_invites_are_shown_under_their_rooms_channels` and
      `tests/irc_two_providers.rs`
      `pending_invites_across_providers_are_shown_under_their_rooms_channels`
      (both through tests/common/irc.rs `invite_names`: the name, a
      collision with a channel shown, a room hosted while the invite
      waits, and the fallback); mimid-agent-irc `names` unit tests;
      mimid-agent-core `two_agents`; mimi-mls `welcome_sender`.

14. **TOPIC is the room's subject (Mark, 2026-11-21; bead mimid-uxmf).**
    irssi showed an op's TOPIC answered with 482 "not channel operator".
    `TOPIC #c :text` now sets the MIMI room subject: the `room_subject`
    of RoomMetaData (protocol-07 §7.6), in a Commit carrying that one
    `room_metadata` update with every other field unchanged
    (`Agent::set_room_subject`, `Store::set_subject`). The hub checks
    room-policy-04 §8.2 `canChangeRoomSubject`; the default roles give
    it to "admin" (`@`) and not to "member".
    - The topic every IRC connection shows is `subject | name | URI`,
      an empty subject or name left out, cut to fit one IRC line.
    - 482 only for a rights problem: the agent checks the user's role
      against the room's own `roles_list` before it builds the Commit,
      since the hub's refusal (`notAllowed`) does not say which check
      failed. Any other failure (no room metadata, a subject that is no
      MIMI `Utf8String`, the hub's refusal) is a NOTICE saying why.
    - A change by any member, from any front end, is
      `Event::RoomMetadataChanged`, for a Commit received and for this
      device's own; the store reads the name and subject again and
      records the Commit's sender and the hub's acceptance time
      (`Room::subject_set`). Every IRC connection then gets
      `:<setter> TOPIC #c :<topic>`, from the server when the sender is
      not known.
    - `TOPIC #c` alone answers 332, and 333 only with what is honestly
      known: the setter and the hub's time of a change the agent saw.
      A subject the room had when the agent joined has neither, so no
      333; the server is never named as setter, and a per-device time
      (the room record's key) is never used.
    - JMAP shows no subject: draft-atwood-jmap-chat-00 `topic` is for
      channel Chats only, and a MIMI room is a group Chat.
    - Tests: mimid-agent `tests/irc.rs`
      `registration_queries_and_refusals` (set by the creator, 333, a
      NUL refused with a NOTICE) and
      `topic_sets_the_subject_for_every_member` (seen by the other
      member and the user's other connections, 482 for a member, TOPIC
      from another member once an op, 333 in a new connection's JOIN).
15. **No 329; 330 is the user URI; `user@domain` (Mark, 2026-11-21;
    bead mimid-4sg8).**
    - No 329 at all: the only creation time the agent had was its own
      room record's key, which differs between members. Showing
      nothing beats a per-device time. 333 had the same flaw and now
      follows §7.14.
    - WHOIS 330 gives the user URI as the account name.
    - INVITE and the service's `allow` and `deny` also take
      `user@domain`, mapped to `mimi://domain/u/user` (the domain in
      lowercase), for a user who has no nick here yet. The service's
      help says so.
    - Tests: mimid-agent `tests/irc.rs`
      `registration_queries_and_refusals` (no 329, 330, the help),
      `invites_and_consent_from_irc` (`allow alice@A.Example`, INVITE
      by `bob@a.example`), `topic_sets_the_subject_for_every_member`
      (INVITE of a user never seen); mimid-agent-irc `names` unit
      tests.
16. **PART reasons; the invitee's JOIN (Mark, 2026-11-21; bead
    mimid-zo20).**
    - A PART reason cannot reach other members: a MIMI leave is
      Remove proposals for all of the user's devices and an
      AppDataUpdate of the participant list (protocol-07 §3.5), and none
      carries text. Other members therefore see the honest
      fixed text `no longer in this room`. The reason is shown on the
      leaver's connection and on the user's other IRC connections of
      the same daemon (kept in memory until the room is joined again or
      the daemon stops).
    - Decided, no change: the invitee's JOIN is shown to the other
      members at once, when the Commit adds her to the MLS group. That
      is accurate to MLS, and MIMI has no "accepted" signal to wait for.
    - Tests: mimid-agent `tests/irc.rs`
      `topic_sets_the_subject_for_every_member` (the user's other
      connections see the reason, bob the fixed text),
      `two_daemons_chat_over_irc_and_jmap` (the fixed text).
17. **The database is `mimid.sqlite` (Mark, 2026-11-21).** The agent's
    one database (§3 step 9) is `<state_dir>/mimid.sqlite`
    (`mimid_agent_core::DATABASE_FILE`), not `agent.sqlite`. Nothing runs
    in production, so there is no migration and no rename on start: a
    state directory that has no `mimid.sqlite` and holds `agent.sqlite`
    is refused, as one holding `state.json`, `mls.sqlite` or
    `chat.sqlite` already was, with a message saying it is the database
    under its earlier name and that this agent does not convert or rename
    it. Test: mimid-agent-core `state::tests::the_older_layout_is_refused`.

18. **A message's real arrival time (Mark, 2026-11-21).** The store
    records when each message arrived, and JMAP's `receivedAt` is that
    time, for objects the projection makes as a sync brings the record
    and for those made from records without `ext["jmap"]` (§7.11, which
    used `sentAt` as a stand-in):

    - `record::Message::received_at` (milliseconds). A message received
      from the hub: when this store stored it (`Store::sync`). A message
      this device sent: the hub's acceptance time, `accepted_at`, whether
      `Store::send` stores it or the journal's `Event::Sent` does after a
      crash (§3 step 10). The acceptance time is when the provider got
      it, so it is the honest arrival time of one's own message, and it
      does not move when the outbox finishes a send hours later; the
      time of the store's write would. A message of this user sent from
      another device arrives from the hub like anyone's. A notice: when
      it was made.
    - mimid-agent-jmap renders `receivedAt` from it (`Render::message`,
      `Render::new_message`), so `ext["jmap"]` no longer keeps it unless
      a client's object differs.
    - The store's schema is part `store` version 4; a version 3 database
      is refused, not converted (nothing runs in production).
    - Test: mimid-agent `tests/jmap_seed.rs` receives the messages with
      bob's JMAP off, turns it on, and requires each Message's
      `receivedAt` to be the record's `received_at`, after the scenario
      began, before the restart and not before `sentAt`.

19. **Proposals and external Commits survive a crash (Mark,
    2026-11-21).** The send-side fix of §3 step 10 covers every
    Room/update of the agent, not only member Commits:

    - The outbox has two more kinds (`outbox` table, part `agent`
      version 3; nothing is converted): `proposals` (a leave: the Remove
      of this client, the Removes of the user's other clients and the
      participant-list update; or a credential Update proposal) and
      `external_commit` (a device joining one of its user's rooms,
      decision mimid-1wgh.61). Beside the UpdateRequest bytes an entry
      keeps what the agent records once the hub has them, `finish`: a
      leave and whether the user was the last participant, or the group
      ID of the room an external Commit joins.
    - Before anything leaves, one transaction holds OpenMLS's writes (the
      proposals it stores in the group; the group the external Commit
      makes, which OpenMLS has already merged), the digests, and the
      entry. An external join that fails its checks rolls back, so no
      group is left behind.
    - On the answer, one transaction ends the entry. Accepted: a leave
      marks the room `Leaving` (left at once if the user was alone) and
      withdraws the acceptance record; an external Commit loads the group,
      makes the room active from its epoch, replays the messages held for
      it and journals the membership. Refused: a Commit is cleared, an
      external Commit's group deleted, proposals leave nothing to undo.
      No answer: the entry stays, and the room stays as it was (active,
      or not joined).
    - On restart or a lost answer `Agent::receive` sends the same bytes
      first, and the provider answers one its hub already accepted from
      its record (findings log F11); nothing is built or encrypted again.
      A second external Commit would put a second leaf of this device in
      the group, and a second set of proposals would reach the other
      members twice. `Agent::join_own_rooms` skips a room whose external
      Commit waits in the outbox, and `Agent::leave` of a room whose
      leave waits sends that one again.
    - The store follows the agent: a room the agent is leaving is shown
      as leaving at the next sync even when `Store::leave` returned an
      error.
    - Tests: mimid-agent-store `tests/send_crash.rs`
      `a_crash_around_leaving_loses_and_repeats_nothing` and
      `a_crash_around_an_external_join_loses_and_repeats_nothing` fail a
      leave and an external join at `FailPoint::BeforeSend` and
      `FailPoint::AfterAccepted`, each with a restart and in the same run.
      They check that nothing is recorded before the answer; that the
      leaving room is leaving, then left after bob's Commit, in the agent
      and the store, with bob alone and no Problem; and that the joining
      device is in the room at the epoch and epoch authenticator of alice's
      other device and bob, with two leaves of alice and one of bob, and
      that messages pass both ways.

20. **Disappearing messages: the sender's time (Mark, 2026-11-21; bead
    mimid-tu1g).** A message can carry a time at which every copy is
    deleted, the sender's own included.

    - **Mapping.** JMAP Chat `senderExpiresAt` (draft-atwood-jmap-chat-00
      §Message) is mimi-content-10 §4.1 `expires` with `relative` false:
      seconds since the UNIX epoch, `uint .size 4`. A `Message/set` create
      sends the time cut to the whole second (the draft deletes "at or
      before this time"), and the sender's record keeps that second. A
      received absolute `expires` becomes the record's
      `expiry.senderExpiresAt`, shown as the Message's `senderExpiresAt`.
      A received `expires` with `relative` true is the read rule of §7.22,
      not a time.
    - **Refused.** A create whose `senderExpiresAt` is not after now is
      `invalidProperties` naming `senderExpiresAt`, as the draft requires;
      so is one more than a year ahead, which mimi-content-10 §9.1 tells
      receivers to discard. A received message whose `expires` is more
      than a year in the past or the future is discarded and reported
      (§9.1; decision mimid-1wgh.2.19 gives that check to the agent). A
      received message whose time has passed when it arrives is not
      stored ("Servers MUST reject a `senderExpiresAt` value that is
      already in the past at delivery time").
    - **The deletion** (`Store::expire_due`, `mimid_agent_store::expiry`)
      is the local delete's: the record goes, with a tombstone of its
      versions, so a delivery of it again (an acknowledgement that failed,
      the sender's own `Event::Sent` read back after a crash) stores
      nothing; its attachments waiting for a retry go; after the save that
      writes the deletion its blobs go unless another message names them,
      the sender's own upload included. Every front end is told
      (`Change::MessageExpired`): JMAP hard-deletes the Message
      (crate-jmap `expire_message`: `destroyed` in `Message/changes`, and
      unpinned); IRC has nothing to take back and never shows it again,
      since it plays nothing back (§7.6).
    - **Edits and retractions.** The expiry belongs to the message and an
      edit cannot change it (mimi-content-10 §9.3: the sender changes only
      the NestedPart). mimid sends an edit with the `expires` and
      extension of the message it edits, so a receiver that keeps versions
      deletes them alike; a received edit's own `expires` is ignored. A
      retraction carries none, and a retracted message keeps its expiry:
      its emptied record goes at the same time. An edit or retraction that
      arrives after the message is gone here is dropped as one of a
      message not stored.
    - Tests: mimid-agent-store `tests/expiry.rs`
      `the_senders_time_deletes_every_copy_and_its_blobs`,
      `edits_and_retractions_keep_the_expiry`,
      `a_message_past_its_time_is_not_stored_or_restored`;
      `expiry::tests`; mimid-agent `tests/disappearing.rs`
      `senders_time_read_rules_and_policy_over_jmap` and
      `across_two_providers`.

21. **A room's own expiry policy (Mark, 2026-11-21).** JMAP Chat
    `messageExpirySeconds` is local, as the draft says ("This is a local
    setting, not a bilateral negotiated commitment"): the room record
    keeps it (`Room::message_expiry_seconds`) and nothing is sent. A
    message older than that many seconds, counted from its arrival here
    (`receivedAt`, §7.18), is deleted by the same path as §7.20,
    notices included; the sender's time still applies, and whichever comes
    first wins. It is set by `Chat/set` create or update of a room-bound
    Chat (null or 0 clears it), and from IRC by `/msg mimid expire #c
    <duration>` (`90s`, `30m`, `12h`, `7d`, `2w`, at most a year; `off`
    clears it; without a duration it is shown). A change made from one
    front end shows in the other (the Chat's `messageExpirySeconds`).
    Tests: mimid-agent-store `tests/expiry.rs`
    `a_rooms_policy_deletes_older_messages_here_only`; mimid-agent
    `tests/disappearing.rs`, `tests/irc.rs` `burn_and_expire_from_irc`.

22. **Burn on read and delete after read (Mark, 2026-11-21).**
    - **On the wire (Mark, 2026-11-21; decision mimid-1wgh.84).** A read
      rule goes in the standard field, so other implementations honour
      it: mimi-content-10 §4.1 `expires` with `relative` true ("a
      relative amount of time after the receiving client reads the
      message"). `expiresAfterReadSeconds` N is `[true, N]`;
      `burnOnRead` is `[true, 0]`, and with both set only `[true, 0]` is
      sent, since burn wins. Whether 0 means burn on read is mimid's
      reading; the WG has been asked
      (github.com/ietf-wg-mimi/draft-ietf-mimi-content/issues/93). Only a
      message that also has a `senderExpiresAt`, which then takes
      `expires`, carries its read rule in a mimiExtensions entry of
      mimid's own: text key `mimid-read-expiry`, value `[burnOnRead:
      bool, expiresAfterReadSeconds: null / uint .size 4]` in
      deterministic CBOR. INVENTED, NOT FROM SPEC. Only mimid receivers
      honour that entry; any other implementation keeps the unknown
      extension and the message, without the read rule.
    - **Received.** A relative `expires` `[true, 0]` is `burnOnRead`;
      `[true, N]` with N > 0 is `expiresAfterReadSeconds` N; more than a
      year is discarded (§9.1). The `mimid-read-expiry` entry is honoured
      too; with both, the earlier deadline wins. An entry of any other
      form is ignored, with a sync problem; the message is stored.
    - **Whose copy.** The receiver's only; the sender's copy, on any of
      the sender's devices, is not affected (draft-atwood-jmap-chat-00
      §Message). `burnOnRead` deletes at the read,
      `expiresAfterReadSeconds` so many seconds after it; burn wins.
    - **What a read is.** The store keeps the first read
      (`Message::read_at`, only for a received message with a read rule;
      `Store::mark_read`). On JMAP: the owner's `readAt` on the Message
      (a burn-on-read Message goes in the same `Message/set`, through
      crate-jmap's `read_and_burn_message`), or a `ReadPosition` whose
      `lastReadMessageId` is the Message or a later one in history order.
      On IRC: the message's lines were written to at least one connected
      IRC client of the user's (`Session::read_delivered`). A message that
      arrived while no IRC client was connected is not read on IRC, since
      IRC plays nothing back (§7.6).
    - **Sending.** JMAP: `burnOnRead` and `expiresAfterReadSeconds` on
      `Message/set` create (an `expiresAfterReadSeconds` of more than a
      year, which receivers would discard, is `invalidProperties`). IRC: `/msg mimid burn #c <text>` sends a
      burn-on-read message; IRC has no way to send delete-after-read or a
      sender's time.
    - Tests: mimid-agent-store `tests/expiry.rs`
      `read_rules_delete_the_receivers_copy_only`,
      `read_rules_go_in_the_standard_expires_on_the_wire`; `expiry::tests`;
      mimid-agent `tests/disappearing.rs`, `tests/irc.rs`
      `burn_and_expire_from_irc`, `tests/irc_two_providers.rs`
      `a_burn_on_read_line_across_providers`.

23. **Expiry across restarts and crashes (Mark, 2026-11-21).** The
    deadlines are fields of the records (`expiry`, `readAt`, the room's
    policy) and are saved with them; no timer state exists outside the
    database. The daemon's expiry loop (`expiry_loop`) runs
    `Store::expire_now` at start, so what fell due while the agent was
    stopped goes then, and again at each next deadline
    (`Store::next_expiry`), when one may have come nearer
    (`Store::expiry_wanted`: a message stored, a read, a policy set), and
    at least every minute. A deletion is a store write like any other: the
    record and its tombstone are written in one transaction by the next
    save; if that save fails or the agent crashes first, the record is
    still in the database at the next start, its deadline has passed, and
    it is deleted again. Blobs go only after the save that wrote the
    deletion; a crash between leaves them to the blob store's quota. The
    store's schema is part `store` version 5; a version 4 database is
    refused, not converted (nothing runs in production). Tests:
    mimid-agent-store `tests/expiry.rs`
    `deletions_survive_a_restart_and_a_failed_save`; mimid-agent
    `tests/disappearing.rs` `a_deletion_due_while_stopped_happens_at_start`.

24. **Calls to join (Mark, 2026-11-21; bead mimid-0p8s).** mimi-content-10
    §5.10 carries a conference join URL as a part of disposition
    `session` (7), the example an unencrypted ExternalPart with the URL
    and a description. Before this, the agent took every ExternalPart for
    an attachment: it asked its provider to fetch the join URL (mimid's
    hub refuses a host that is no peer provider's; another provider might
    fetch it), stored the message with an empty body, and IRC showed
    nothing.
    - **Received.** A session part, external or inline, at the top level
      or in a top-level `processAll` MultiPart, is never fetched
      (`ReceivedMessage::attachments` leaves it out;
      `ReceivedMessage::session_parts`). It becomes a `Call` on the
      message record: `url`, `description`, and the ExternalPart's
      `expires` if not 0. An inline part is a call only if it is text,
      its first line that is not empty or a `#` comment the URL
      (`text/uri-list`, RFC 2483); SDP and other descriptions are left
      out with a sync problem. At most 4 calls a message, a URL cut to
      2048 octets, a description to 256 characters (INVENTED, NOT FROM
      SPEC). A message with only a call is stored, its body empty.
    - **Link or text.** Only a URL whose scheme is `https` or `wss`, with
      a host, in printable ASCII without spaces (`content::is_call_link`)
      is shown as a link. Anything else (`http`, `sip`, `tel`,
      `javascript`, non-ASCII hosts) is shown as text, and the agent never
      opens or fetches any call URL.
    - **JMAP Chat.** draft-atwood-jmap-chat-00 has the representation: a
      MessageAction (§MessageAction) of `type`
      `urn:ietf:params:jmap:chat:cap:vtc` (§Endpoint), `uri` the URL,
      `label` the description if any, `expiresAt` the part's `expires` if
      any, in the Message's `actions`. A call that is no link is not an
      action: it is a line of the `body`, after any text,
      `call: <description> (not a web link: <url>)`. A deleted or
      retracted Message has no actions. Sending: `Message/set` create
      with one such MessageAction (and optionally `body`) sends the
      §5.10 shape: the session ExternalPart alone, or after a
      `text/plain` part in a `processAll` MultiPart; `expiresAt` goes as
      the part's `expires`. Another action type, more than one action,
      `metadata` (MIMI has no place for it), attachments beside it, or a
      URL that is no link is `invalidProperties` on `actions`.
    - **IRC.** Each call is an ACTION from the sender after the text, the
      message's tags on its first line: `* alice-a call: Join the Foo
      118 conference <https://example.com/join/12345>` as a client shows
      it; a call that is no link reads `call: <description> (not a web
      link: <url>)`. Control characters in either become spaces. IRC
      clients make links of URLs themselves; the front end cannot stop
      that for the text form. Sending: `/msg mimid call #channel <url>
      [<description>]`, the URL `https` or `wss`.
    - **Store.** `Store::send_call` sends one call with optional text and
      expiry (`Agent::send_session_link`), checks the URL and description
      first, and records the call. An edit does not change a message's
      calls; a retraction removes them.
    - Tests: mimid-agent `tests/calls.rs` `calls_on_one_provider`,
      `calls_across_two_providers` (the §5.10 example from raw content,
      JMAP and IRC, both ways; the body sent equals the example's);
      mimid-agent-core `tests/session_parts.rs`; mimid-agent-store
      `content::tests`.

25. **Front ends after v1 (Mark, 2026-11-21).** docs/design/client-survey.md
    §10, "Decisions (Mark, 2026-11-21)", S1 to S7. For this note: S2
    lifts §7.2 and §7.6 for IRC v2 (queries are one-to-one rooms with a
    store-level `direct` flag; chathistory comes from the store), and S3
    lifts "No SASL" in §4 for IRC v2 (SASL PLAIN with the agent token,
    PASS kept). v1 stays as decided above until IRC v2 is built
    (epic mimid-i0id); the store groundwork for it is epic mimid-qqtk.
    The SASL part is built (epic mimid-e13m, docs/design/frontend-auth.md
    §4.1): SASL PLAIN and SCRAM-SHA-256 (decision A3) and PASS, against
    app passwords and the agent token, on loopback and on the TLS
    listener; "No SASL" in §4 no longer holds.

26. **Replies (epic mimid-qqtk, bead mimid-qqtk.1; marmot-bridge.md §5
    P1).** mimi-content-10 §5.2: a reply's `inReplyTo` is the message ID
    replied to.
    - **Store.** `Store::send_message` takes `SendOptions`, whose
      `in_reply_to` names a message of the same room by key; the agent
      sends it as `inReplyTo` (`ContentOptions::in_reply_to`). The record
      keeps the reply resolved (`in_reply_to`, as before) and the
      `inReplyTo` exactly (`in_reply_to_id`, all 32 octets), sent or
      received. A message not stored here stays a reference. An edit of a
      reply carries the same `inReplyTo` (§9.3: an edit changes only the
      NestedPart; the §5.5 example keeps it). A notice, which has no MIMI
      message ID, or a message of another room cannot be replied to
      (`ActionError::NotReferable`).
    - **Which version (Mark, 2026-11-21; bead mimid-y5or; decision
      mimid-1wgh.85 as revised).** mimi-content-10 §4.1: "Note that a
      inReplyTo always references a specific message ID. Even if the
      original message was edited several times, a reply always refers
      to a specific version of that message, and SHOULD refer to the
      most current version at the time the reply is sent." A reply
      names the latest version the user saw. The record keeps every
      version's whole message ID: the first in `mimi_id`, each later one
      (an edit, a retraction) in `aliases`, oldest first
      (`Message::latest_mimi_id`). `SendOptions::in_reply_to_version`
      names the version the user saw by its reference octets; without it,
      or if the octets name no version of the target, the reply names the
      latest. JMAP Chat: the Message's current version, that is the
      latest. IRC: the latest version this connection showed (the message
      line, or its last `(edited)` line), else the one the
      `+draft/reply` msgid names.
    - **Receiving.** Any version resolves: the first, a later one, or
      any by its reference octets (draft-atwood-jmap-chat-mimi-00
      §Message Identifiers), through the room's index of every version's
      reference octets. A receiver that missed the edit a reply names
      cannot know that version; it keeps the reply's `inReplyTo` exactly
      and its reference octets, as for any message not stored here.
      Schema version 10.
    - **JMAP Chat.** `replyTo` on `Message/set` create is sent; one that
      names no Message of the Chat, or a notice, is `invalidProperties`
      on `replyTo`. `replyTo` beside a call to join stays `forbidden`.
    - **IRC.** A received reply is shown `<nick>: <text>`, the usual way
      to address someone on IRC, unless the text already starts with
      `<nick>:` or `<nick>,`; with message-tags it carries
      `+draft/reply` too. A PRIVMSG with `+draft/reply` naming a message
      of the room is sent as a reply to it; one naming nothing stored
      here is sent as a plain message.
    - Tests: mimid-agent-store `tests/groundwork.rs`
      `replies_are_sent_kept_and_edited_with_their_target`,
      `replies_and_reactions_name_the_latest_version` (a reply and a
      reaction to an edited message, received by a store that missed the
      edit); mimid-agent `tests/groundwork.rs`
      `replies_through_jmap_and_irc`.

27. **Reactions (epic mimid-qqtk, bead mimid-qqtk.2; marmot-bridge.md
    §5 P2).** mimi-content-10 §5.3 (a reaction is a message of
    disposition `reaction`, `inReplyTo` the message reacted to), §5.7
    (an unlike replaces the reaction message with a NullPart of that
    disposition), Appendix B.2 (several in a `processAll` MultiPart).
    - **Agent.** `Agent::send_reaction` sends the §5.3 shape, one
      `text/plain;charset=utf-8` part; `Agent::send_unreaction` the §5.7
      shape. `ReceivedMessage::reactions` reads a received one: top
      disposition `reaction`, an `inReplyTo`, no `replaces`, and one
      `text/*` part or a `processAll` MultiPart of them, each of
      disposition `reaction` and at most `MAX_REACTION_LEN` (64,
      INVENTED) octets. Anything else, a media reaction included, stays
      a message (draft-atwood-jmap-chat-mimi-00 §Reactions carries those
      as replies). The B.2 example names no message in `inReplyTo`, so
      as written it is no reaction to anything; it is kept as a message.
    - **Store.** A reaction is not a message: it is kept on the message
      it names (`Message::reactions`), keyed by the reaction message's
      `senderMsgId` (`-<n>` after it for part `n` past the first), with
      the reacting user, the text, the reaction message's ID and the
      hub's time. `Message::reaction_counts` adds them up per reaction
      text, each user once. An unlike from the reaction's sender takes
      every part of that reaction message back; one from anyone else is
      refused (§9.3); an edit of a reaction is not applied. A reaction to
      a message not stored here is skipped. At most
      `MAX_REACTIONS_PER_MESSAGE` (1024, INVENTED) per message. A
      retraction of the message drops its reactions. `Store::react`
      sends one, naming the version the user saw or else the latest, as
      a reply does (§7.26); the kept reaction keeps the version it names
      (`Reaction::in_reply_to`), and `Store::unreact` takes back one of
      the user's naming that same version (§9.3: a replacement changes
      only the NestedPart), silent as edits are. Schema version 7;
      `Reaction::in_reply_to` version 10.
    - **JMAP Chat.** Each kept reaction is in the Message's `reactions`
      under its key: `emoji` the text, `senderId` the accountId or the
      reactor's ChatContact, `sentAt` the hub's time. The owner's patch
      `reactions/<senderReactionId>` with an object reacts, the
      `senderReactionId` kept as the store key, `sentAt` set to the hub's
      time; `null` takes it back; a changed `emoji` takes the old one back
      and sends the new. `customEmojiId` is `invalidProperties`.
    - **IRC.** With message-tags: TAGMSG from the reacting user with
      `+draft/react=<text>` and `+draft/reply=<msgid>`; taken back,
      `+draft/unreact=<text>` (the unreact tag is *unverified* against
      the IRCv3 react draft, which was not read for this). Without:
      `ACTION reacted <text> to <nick>`, and `ACTION took back <text>
      from <nick>`. A client's TAGMSG with `+draft/react` (or
      `+draft/unreact`) and `+draft/reply` naming a message of the room
      reacts (or takes back the user's reaction of that text). A
      reaction made before the connection registered, to a message it
      has not shown, is not shown.
    - Tests: mimid-agent-core `agent::tests::reactions_are_read_from_the_wg_examples`
      (the WG examples); mimid-agent-store `tests/groundwork.rs`
      `reactions_are_sent_kept_added_up_and_taken_back`; mimid-agent
      `tests/groundwork.rs` `reactions_through_jmap_and_irc`.

28. **A received message's extensions (epic mimid-qqtk, bead
    mimid-qqtk.3; marmot-bridge.md §3.2, §5 P3, §6.3).** mimi-content-10
    §4.3: extensions other than `senderUri` (1) and `roomUri` (2).
    - **Store.** A message keeps its extensions as received or sent
      (`Message::extensions`: the key, int or text, and the value's CBOR
      as hex, in key order), at most `MAX_KEPT_EXTENSION_LEN` (4096,
      INVENTED) octets of values; past it the rest are left out with a
      sync problem. `SendOptions::extensions` sends more with a message,
      and the record keeps them; an edit sends the record's again (§9.3).
      `Message::on_behalf_of` reads the bridge's `mimid-on-behalf-of`
      (`ON_BEHALF_OF_KEY`, INVENTED, NOT FROM SPEC): a CBOR map whose
      text `uri` is required and text `name` and `src` are kept. It is
      what the sender says, never authenticated. Schema version 8.
    - **JMAP Chat.** The entry is the Message's vendor property
      `mimid.invalid:onBehalfOf` (RFC 8620 §1.8 names an extension's
      property with a domain and a colon), `{"uri", "name", "src"}`,
      for a client to show as "name (via sender)". INVENTED, NOT FROM
      SPEC: the property.
    - **IRC.** A message with the entry is shown `<name> (via <nick>):
      <text>`, the name the entry's name or else its URI, unless the
      text already starts with that name, as the bridge's own prefix
      does (marmot-bridge.md §3.2). The sender stays the MLS sender.
    - Tests: mimid-agent-store `content::tests::on_behalf_of_reads_the_bridge_map`,
      `tests/groundwork.rs` `extensions_are_kept_sent_and_edited`;
      mimid-agent `tests/groundwork.rs` `on_behalf_of_through_jmap_and_irc`.

29. **One-to-one rooms (epic mimid-qqtk, bead mimid-qqtk.4; Mark's
    S2, docs/design/client-survey.md §10; decision mimid-1wgh.87 as
    revised by Mark on 2026-11-21, bead mimid-qrbe; decision
    mimid-1wgh.89).** A one-to-one room is a room-policy-04 §5
    `fixed_membership` room with `max_users` 2. This replaces the
    ordinary unnamed room of two that c9d76e9f built.
    - **What §5 says.** room-policy-04 §5, quoted whole for the rules
      used here:

      > Rooms with fixed_membership set to true (fixed-membership rooms)
      > have the list of participants specified when they are created.
      > While clients of existing participants can be added, other users
      > cannot be added, so none of its non-zero, non-banned roles can
      > contain the canAddParticipant capability. Ordinary users cannot
      > leave or be removed, however a user can remove all its clients
      > from the associated MLS group. The most common case of a
      > fixed-membership room is a 1:1 conversation. This room membership
      > style is used to implement Direct Message (DM) and Group DM
      > features. Only a single fixed-membership room can exist for any
      > unique set of participants.

      > When max_clients has a value, the room's associated MLS group
      > MUST NOT have more clients than the provided value. Likewise when
      > max_users has a value, the room MUST NOT have more non-banned
      > entries in the participant list than that value.

      > If persistent_room is false, the room will be automatically
      > inaccsessible when the corresponding MLS group is destroyed (when
      > there are no clients in the group). If persistent_room is true,
      > the room policy will remain and a client whose user has
      > appropriate authorization can create a new MLS group for the same
      > room.

      §8.1.2 gives the client-level actions §5 leaves open:
      `canRemoveOwnClient` "can propose to remove its own client using an
      MLS Remove or SelfRemove proposal without changing the Participant
      list", which "cannot be committed by the leaving user"; and
      `canRemoveSelf`, leaving the participant list, which §5 rules out
      in a fixed room.
    - **The room.** `HostOptions::direct` (mimid-agent-core):
      `fixed_membership` true, `max_users` 2, `multi_device` true, no
      `max_clients`, `persistent_room` true (mimid never makes a new MLS
      group for a room, so a room whose last client leaves stays as it
      is), not discoverable, no name. Its roles (`direct_roles`): 1
      "banned"; 2 "member" for both users, creator included, holding
      `canAddOwnClient`, `canRemoveOwnClient`, send, receive, reply,
      react and report abuse, no `canAddParticipant`, no `canRemoveSelf`,
      no role changes and no metadata or policy capability.
    - **Creation.** draft-atwood-jmap-chat-mimi-00 §Room/create makes a
      room whose group and participant list hold the creator alone
      (rules 2 and 4), so "specified when they are created" is read as:
      Room/create, then the creator's first Commit, which adds the other
      user's clients and the participant-list entry and sends them a
      Welcome (`Agent::invite`, as for any invite). The KeyMaterial
      request of that Commit goes through the target's provider as
      always, so the other user's consent applies unchanged
      (`noConsent` refuses the room, which the creator then abandons).
      On the other side the Welcome is an invite like any other, joined
      or held by the invite policy (§7.5). A room whose add failed is
      abandoned: the creator leaves it, which the hub allows only while
      the creator is the only participant (decision mimid-1wgh.89,
      INVENTED).
    - **The hub's rules** (mimid-server `hub::policy`, decision
      mimid-1wgh.89, which replaces decision mimid-1wgh.3.50's "not
      enforced"):
      - "other users cannot be added": no participant-list addition, by
        add or by join (open join, preauthorization, external Commit of a
        new user), except in a Commit by the creator while it is the
        list's only entry, which may add users in a defined role other
        than 0 and 1 with no capability (no role can hold
        `canAddParticipant`). `max_users` 2 then caps it. KeyMaterial
        requests through the hub, and GroupInfo requests from users not
        listed, follow the same rule.
      - "Ordinary users cannot leave or be removed": "ordinary" is read
        as every user, since §5 defines no other kind. No entry leaves
        the participant list, by leave, removal or the hub operator's own
        removal, inline or by reference; a ban (a role change) is left to
        the roles, and `direct_roles` grants none.
      - "a user can remove all its clients": Remove and SelfRemove of the
        proposer's own clients stay allowed (`canRemoveOwnClient`), as do
        a participant's new clients (`canAddOwnClient`).
      - "Only a single fixed-membership room can exist for any unique set
        of participants": the Commit that specifies a fixed room's
        participants is refused if another fixed room this hub hosts has
        the same set. A hub cannot see rooms other hubs host; two users
        who open a room with each other at once on two providers can end
        up with two (the agent shows both, and `direct_room` picks the
        oldest).
    - **The agent and the store.** `Agent::is_fixed_membership` and
      `Agent::is_direct` read the room's policy; `Agent::leave` refuses a
      fixed room (§5) unless the user is its only participant.
      `Room::direct` is set from the policy when a room is first seen
      (`Agent::is_direct`), no longer from a name and a count;
      `Store::set_direct` is gone. `Store::direct_room` finds the active
      one-to-one room with a user (the oldest by key if several);
      `Store::open_direct` returns it, or hosts a new one
      (`HostOptions::direct`) and adds the user in its first Commit.
    - **PART and destroy: open for Mark.** §5 lets a user "remove all
      its clients from the associated MLS group" but not leave the
      participant list, so §7.1 ("PART leaves the room for real: every
      device of the user leaves, and only a new invite brings them back")
      cannot hold as written: no one can invite them back (they are still
      a participant, and nobody can add a user), and they can come back
      on their own (`canAddOwnClient`). Until Mark decides, `Agent::leave`
      refuses a fixed room, so IRC PART and JMAP Chat destroy of a direct
      Chat fail with that error and change nothing.
      Mark decided on 2026-11-22 (bead mimid-2vcw): option B. PART and
      JMAP Chat destroy on a direct room hide it locally, the devices
      stay, and the next message brings it back; option A (remove all
      the user's own devices, staying a participant) may come later as a
      separate explicit action. IRC's half is built (§7.32); JMAP Chat
      destroy still fails as above.
    - **JMAP Chat.** A direct room is a Chat of kind `direct` whose
      `contactId` is the other participant's ChatContact, with no
      `name` and no `members` (draft-atwood-jmap-chat-00 §Chat: "Group
      chats only"). `Chat/set` create with `kind: "direct"` and
      `contactId` is `Store::open_direct`; with a one-to-one room already
      there it is `alreadyExists` with its `existingId`.
    - Schema version 9 (the `direct` flag); version 11 (`direct` read
      from the policy).
    - Tests: mimid-server `tests/hub_policy.rs` `fixed_membership_rooms`;
      mimid-agent-store `tests/groundwork.rs`
      `one_to_one_rooms_are_made_once_and_recognised`; mimid-agent
      `tests/groundwork.rs` `direct_chats_over_jmap`, and
      `tests/direct_two_providers.rs` (a.example and b.example).

30. **Attachment links (epic mimid-qqtk, bead mimid-qqtk.5; decision
    mimid-1wgh.88).** For front ends whose clients cannot send the
    bearer header JMAP download needs (IRC v2, Matrix, XMPP): a URL on
    the agent's HTTP listener that gives one attachment's plaintext.
    This is §6 question 4's per-blob link, with an expiry; it adds the
    route and the second authorization at the agent boundary that §7.4
    left out of IRC v1. IRC v1 still shows no attachments.
    - **Form.** `GET /attachment/<blobId>/<expires>/<mac>/<name>`:
      `expires` in seconds since the UNIX epoch; `mac` the first 16
      octets, in hex, of HMAC-SHA256 under the link key over
      `"mimid-attachment-link-v1" 0x00 blobId 0x00 expires`; `name`
      percent-encoded, outside the MAC (it only names the download). The
      link key is HMAC-SHA256 under the local token of
      `"mimid-attachment-link-key-v1"` (`LocalToken::link_key`), so a
      link shows nothing of the token, and a new token revokes every
      link. INVENTED, NOT FROM SPEC.
    - **Making one.** `Store::attachment_link(message, blob, lifetime)`,
      for an attachment of a message that is not deleted; the lifetime
      is at most `MAX_LINK_LIFETIME` (one day), `DEFAULT_LINK_LIFETIME`
      one hour (both INVENTED; Mark, 2026-11-21). The daemon sets the links
      (`Store::set_attachment_links`) once its HTTP listener is bound;
      without `listen` there are none.
    - **Serving.** The Host check first, as for every request. Then the
      link is its own authorization, on GET of this path only
      (AGENTS.md's table gains the row): `AttachmentLinks::check`, the
      one place, compares the MAC (the hmac crate's check) and the
      expiry. A message that is not deleted must still name the blob
      (`Store::live_attachment`). The answer is the octets, with the
      attachment's media type if valid, `Content-Disposition` from the
      name, `nosniff`, `sandbox` and `no-store`. Every failure is the
      same 404.
    - **What it gives away.** Whoever reads a link (a chat log, a
      client's link preview) can fetch the file from a loopback address
      until it expires; the log holds the plaintext of the message
      anyway (§6 question 4). docs/agent.md says so.
    - Tests: mimid-agent-store `links::tests`; mimid-agent
      `tests/groundwork.rs` `attachment_links_give_one_file_until_they_expire`.

31. **History (epic mimid-qqtk, bead mimid-qqtk.6).** For IRCv3
    `draft/chathistory` (S2) and Matrix `/messages`: `Store::history(room,
    point, direction, limit)` returns a page of a room's messages, oldest
    first, and whether there are more beyond it.
    - **Order.** Hub order: the hub's acceptance time, then the store's
      sequence number for messages stored in the same millisecond. A
      notice is at the time it was made.
    - **Points.** `Point::Edge` (with `Before`, the newest messages; with
      `After`, the oldest), `Point::Message(key)` (the page leaves the
      message out), `Point::Time(ms)` (before: accepted strictly before
      it; after: at or after it). chathistory's `BEFORE`, `AFTER` and
      `LATEST` map onto these directly; `AROUND` and `BETWEEN` are two
      calls. At most `MAX_HISTORY_PAGE` (1000, INVENTED) a page.
    - **What a page holds.** What a front end may show: a message deleted
      here (record gone, or deleted for this user only) is left out, and
      so is one whose expiry has come (`expiry::deadline`) though the
      store has not deleted it yet. A retracted message stays, emptied,
      for the placeholder front ends show.
    - Tests: mimid-agent-store `tests/groundwork.rs`
      `history_pages_in_hub_order`. IRC v2's chathistory uses it
      (§7.33); the Matrix front end will.

32. **Private queries in IRC v2 (epic mimid-i0id; Mark's S2; bead
    mimid-2vcw option B).** A one-to-one room (§7.29) is a private
    query, not a channel.
    - **Showing.** It gets no channel name, and a name its invite held
      is given up when it arrives. A message from the other user is a
      PRIVMSG to the user's nick, one from the user (echo, or sent from
      another front end) a PRIVMSG to the other user's nick; edits,
      retractions and reactions go to the same target. A one-to-one room
      whose other user has not been added yet is not shown.
    - **Opening.** PRIVMSG (or NOTICE, TAGMSG, `/me`) to a nick, a user
      URI or `user@domain` writes into `Store::direct_room` with that
      user, or opens one with `Store::open_direct`, so consent and the
      invite policy apply as for any invite (§7.5). A user never seen
      has no nick yet (§4 "Names"), so a first message to them names
      them by URI or `user@domain`. PRIVMSG to oneself is 404.
    - **A pending invite to a one-to-one room** is shown as any pending
      invite (§7.13), under the channel name its room would have had.
      JOIN of that name accepts it; the room then arrives as a query, so
      the JOIN is answered with JOIN and PART of the name (reason "a
      private query with <nick>"), as for `&invite-<n>`, and the client
      keeps no dead window. INVENTED, NOT FROM SPEC.
    - **Closing** (option B). `PART <nick>` hides the query: the room
      and the user's devices stay, nothing is sent, and the time is kept
      in the room's `ext["irc"]["hiddenAt"]` (INVENTED, NOT FROM SPEC).
      chathistory `TARGETS` (§7.33) leaves a hidden query out until a
      message newer than that; live messages are shown as always, which
      is what "the next message brings it back" means on IRC. Goguma's
      own "close" sends only `MONITOR -` and archives the buffer locally;
      its `/part` sends `PART <nick>` (goguma 5aa7baa5
      `page/buffer.dart:645-652`, `commands.dart:128-139`). Answered with
      a server NOTICE.
    - Tests: mimid-agent `tests/irc_v2.rs`
      `private_queries_are_one_to_one_rooms`,
      `a_query_from_a_stranger_waits_as_an_invite`,
      `private_queries_across_two_providers`.

33. **chathistory in IRC v2 (epic mimid-i0id; Mark's S2, which lifts
    §7.6).** IRCv3 `draft/chathistory` (work in progress, read from
    github.com/ircv3/ircv3-specifications `extensions/chathistory.md`)
    over `Store::history` (§7.31), with `batch` and
    `draft/event-playback`.
    - **Commands.** BEFORE, AFTER, LATEST, AROUND, BETWEEN and TARGETS,
      references by `timestamp=` and `msgid=` (`MSGREFTYPES=timestamp,msgid`),
      at most 1000 a page (`CHATHISTORY=1000`, the store's
      `MAX_HISTORY_PAGE`). A target is a channel the connection shows or
      the nick of a private query (§7.32); anything else is `FAIL
      CHATHISTORY INVALID_TARGET`. Goguma uses only TARGETS, BETWEEN,
      BEFORE and `LATEST *`, all by timestamp (goguma 5aa7baa5
      `lib/client.dart:881-920`).
    - **Choices the draft leaves open** (INVENTED, NOT FROM SPEC):
      a timestamp excludes every message of its millisecond on the side
      it bounds, the store's hub order (time, then sequence) breaking
      ties; AROUND takes half the limit before, the msgid's message
      itself, and the rest after; TARGETS lists oldest latest message
      first, the first `limit` from the first timestamp's side; a query
      closed with `PART <nick>` is not a target until a message newer
      than the close (§7.32). `draft/chathistory-end` is set when the
      store says there is no more in the page's direction.
    - **What a page shows.** The lines a live connection would show now,
      batch-tagged: an edited message once, with its latest text and its
      first msgid; a retracted one as the server's NOTICE "<nick>
      retracted a message" with its msgid; with event-playback, each
      reaction as a TAGMSG after its message. What the store leaves out
      of history (deleted here, expired) is not shown. A message shown
      from history counts as read, as a live one does (§7.22).
    - **No automatic playback.** Without chathistory nothing is replayed
      on connect, as in v1; the draft asks a server not to replay to a
      client that negotiated it, and the others keep §7.6's behaviour.
    - Tests: mimid-agent `tests/irc_v2.rs`
      `chathistory_pages_channels_and_queries`,
      `goguma_catches_up_after_a_reconnect` (Goguma's CAP set, SASL PLAIN,
      TARGETS then BETWEEN over the time it was away),
      `private_queries_across_two_providers`.

## 8. The sync trigger: the provider's EventSource (bead mimid-ak29)

Mark decided on 2026-11-20 that JMAP (draft-atwood-jmap-chat-mimi) is
the standard client-provider protocol and the agent's default, so the
agent's live delivery comes from JMAP push. Until then the daemon polled
every 2 s and never listened to the EventSource mimid-server serves
(crates/mimid-server/src/jmap/eventsource.rs).

- **What wakes the sync.** `Store::sync_wanted()` stays the one trigger.
  A task of the daemon (crates/mimid-agent/src/push.rs) follows the
  Session's `eventSourceUrl` and notifies it for each StateChange that
  names `Message`, `Chat`, `Consent` or `KeyPackage` for the account
  (`mimid_agent_core::push::SYNC_TYPES`: what `Agent::receive`,
  `Agent::join_own_rooms`, `Agent::consents` and, after the sync,
  `Agent::refresh_key_packages` read; `KeyPackage` added for findings log
  F17, so a KeyPackage handed out leads to a top-up), and once each time
  a stream opens. The stream says only when; `Store::sync` alone reads
  what, so it is still the only caller of `Agent::receive` and
  `Agent::acknowledge`.
- **The client.** `mimid_agent_core::push`: `Agent::push_source()` hands
  out a `PushSource` (template, account, token, its own reqwest client)
  that holds no agent state, so the task never takes the agent lock.
  `PushSource::open` asks for `types=Message,Chat,Consent,KeyPackage`,
  `closeafter=no`, `ping=30` and sends `Last-Event-ID` when the last
  stream set an ID. The client has no overall timeout but a 75 s read
  timeout, two pings and slack, so a silent dead connection is dropped.
  The parser follows the WHATWG event-stream rules (CRLF, LF and CR line
  ends, comments, a leading BOM), caps an event at 64 KiB, skips events
  other than `state` and `ping`, and refuses a `state` event that is not
  a StateChange, which drops the stream. The bearer token travels only in
  the `Authorization` header; `PushSource`'s `Debug` redacts it.
- **crate-jmap.** jmap-base-client at the pinned revision has
  `subscribe_events` and `subscribe_events_reconnecting`. They are not
  used: they bring reqwest 0.12 into the agent beside mimid-agent-core's
  0.13 (two HTTP and TLS stacks in the shipped binary, where the core
  insists on one), and the reconnecting stream hides reconnections, which
  the agent must see to sync after each one.
- **Reconnection.** A stream that cannot be opened or ends is opened
  again after a delay that doubles from 1 s to 60 s, with equal jitter,
  and goes back to 1 s once a stream has delivered an event. mimid-server
  sets no event IDs, so nothing is replayed; the sync at each opening
  covers what changed while the stream was down. Logs: INFO
  `agent_push_connected`, INFO `agent_push_closed`, WARN
  `agent_push_failed` on the first failure after a stream was up or at
  start (later ones at DEBUG), WARN `agent_push_unavailable` once if the
  Session has no `eventSourceUrl`.
- **Fallback.** `sync_interval_ms` stays and now means "sync after this
  long without one". Its default went from 2000 to 30000 (INVENTED, NOT
  FROM SPEC), documented in the config module. While the stream is down,
  delivery waits up to that long. There is no switch to turn the push
  off.
- **Server change.** mimid-server's EventSource subscribed to its change
  bus and read the baseline states in the spawned stream task, after the
  answer had gone out. A change between the client's next read and that
  subscription was never announced. The handler now subscribes and reads
  the baseline before it answers, and answers 500 if it cannot read
  them.
- **Later.** The binary live stream (docs/design/binary-live-stream.md)
  would add a second path that delivers the FanoutMessages themselves.
  This change touches only the trigger, so that path can replace or sit
  beside the push task.
- Tests: mimid-agent-core `push` unit tests (line ends, chunk splits, the
  BOM, `id`, the size cap, StateChange parsing, the URL); mimid-agent
  `tests/push.rs` with the provider behind a layer that refuses or cuts
  its EventSource: with an hour's poll interval a Welcome and messages
  both ways still arrive; streams the server ends are opened again and
  carry the next message; a message sent while the EventSource is
  refused arrives (not before) once it opens again; with the EventSource
  refused, a 100 ms poll carries messages and no stream opens.
  `tests/no_token_in_logs.rs` now opens, loses, is refused and reopens
  the stream, and neither token appears in the log.
