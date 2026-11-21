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
| MLS keys, groups, rooms, invites, the delivery journal | mimid-agent-core: `mls.sqlite`, `state.json` (crates/mimid-agent-core/src/lib.rs:45-51); since §3 step 9 one file, `agent.sqlite`, with the store's records | Yes |
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
  (reference octets of later versions); `accepted_at` in ms; the stable
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
     step 9 (one file, `agent.sqlite`; `persisted_at(path)` became
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
   - The service has `help`, `allow`, `deny` and `invites`. JOIN and PART
     make and leave rooms (§7.1), and `JOIN &invite-<n>` accepts, so
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

   - One file, `<state_dir>/agent.sqlite` (0600, in the 0700 state
     directory; `mimid_agent_core::DATABASE_FILE`), replaces `mls.sqlite`,
     `state.json` and `chat.sqlite`. It holds OpenMLS's tables, the
     agent's state (`agent_state`, one row: what `state.json` held, as
     JSON), the journal (`journal`, one row per undelivered event, by
     sequence number) and the store's tables of step 4. A
     `schema_version (part, version)` table replaces `PRAGMA
     user_version`, which is one per file: the agent's tables are part
     `agent` version 1, the store's part `store` version 3 (2 was
     `chat.sqlite`). Another version is refused; nothing is converted. A
     state directory that holds `state.json`, `mls.sqlite` or
     `chat.sqlite` and no `agent.sqlite` is refused with a message naming
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

    - The outbox (`outbox` table in `agent.sqlite`, part `agent` version
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
    - Proposals and external Commits do not go through the outbox: their
      digests are saved before they leave (so their stored copies are
      skipped after a crash), and what the agent does next (a room
      marked as being left, a room joined) can still be lost; listed in
      outbox.rs Limitations.
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
  and the user URI in the text, and 330 in WHOIS.
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
| Room name | TOPIC: the name and the room URI, with 333 naming the server as setter. Setting TOPIC is refused with 482: the agent changes no room metadata (crates/mimid-agent-core/src/lib.rs:93-95). |
| Participants | 353 NAMES, WHO and WHOIS 319 list every participant, remote or not (irc-lessons.md "Virtual users"). Banned users are left out. |
| Members changed | JOIN and PART lines for others; MODE +o/-o for role changes. |
| This user left (`Event::Left`) | PART from the user's own nick, reason "no longer in this room". |
| Role "admin" | `@`. `PREFIX=(o)@`. `MODE #c +o nick` and `-o` are `Store::change_role`. |
| Bans | `MODE #c b` lists the room's banned users as 367 `nick!*@domain`, then 368. `MODE #c +b nick` (or `nick!*@*`) is `Store::ban`, `-b` is `unban`. Other masks are refused with a NOTICE and change nothing. |
| Kick | `KICK #c nick :reason` is `Store::kick` (the user's clients leave; they stay a participant). |
| Channel modes | `CHANMODES=b,,,nt`; 324 answers `+nt`, which is true: only members send, and nobody sets the topic. 004 lists the same modes. |
| Message | PRIVMSG from the sender's hostmask, with `time` (`accepted_at`) and `msgid` (`senderMsgId`). A body with newlines, or longer than one line, is split on line breaks and UTF-8 boundaries; only the first line carries `msgid`. |
| Own message sent elsewhere (JMAP, another IRC connection) | PRIVMSG from the user's own hostmask. Whether every client shows those well without echo-message is *unverified*. |
| Reply | `+draft/reply=<msgid of the target>` when message-tags is on; the text is unchanged. |
| Edit | A new PRIVMSG from the original sender, text `(edited) <new text>`, with its own msgid and `+draft/reply` naming the first version. |
| Retraction | NOTICE to the channel from the server: `<nick> retracted a message`. With message-tags, `+draft/reply` names it. The text is not repeated. |
| Reactions | mimid sends none and models none (crates/mimid-agent-jmap/src/lib.rs:165-168); a received one is a message like any other. A client's `+draft/react` TAGMSG is dropped. |
| Notices | NOTICE to the channel from the server name, with the store's notice text. IRC has a system sender, so the JMAP rule that the account sends them (sync.rs:446-452) does not apply. |
| Attachments | One NOTICE line per attachment from the sender: file name, size, media type and an agent URL (question 4). Without the HTTP endpoint, no URL. |
| Pending invite | `:<inviter> INVITE <nick> &invite-<number>`. JOIN of that name accepts it (`Agent::join` through the store); the client then gets JOIN for the real channel. The `&` channel never exists. |
| Invite someone | `INVITE <nick> #c` is `Store::invite`. A user URI in place of the nick is also taken, since a user never seen has no nick. |

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
message. A `+draft/reply` tag on a PRIVMSG is dropped in v1: `Agent::send_message`
takes no `inReplyTo` (agent.rs:1815-1820), and JMAP refuses `replyTo` for
the same reason (backend.rs:635). IRC has no upload, so v1 sends no
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
- **Channels**: `JOIN`, `PART` (question 1), `TOPIC` (read; set refused),
  `NAMES`, `MODE` (queries answer 324 and 329, then 367/368, 348/349
  empty, 346/347 empty; never 482 for a query; `+o -o +b -b`), `KICK`,
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
  crate): `allow <nick|uri>`, `deny <nick|uri>`, `invites`, `join
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
   them. No `direct` flag.
3. **Every nick carries its provider.** `<local>-<label>` for everyone,
   the user's own provider included. A nick never moves between people.
4. **No attachments in v1.** Neither links nor a placeholder line are
   required; no `/irc/blob` route and no new authorization at the agent
   boundary. A message's text is shown; its attachments are not.
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
    `agent.sqlite`, which replaces `chat.sqlite`.

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
      Message's `receivedAt` is its `sentAt` (the hub's acceptance time),
      not the start: the store keeps no time of receipt, and the start
      would date every old Message alike.
    - The objects are seeded like the others, so they are no change: a
      client's `/changes` from the states read after the start names only
      what comes after. State strings restart at each start anyway. The
      next save keeps the objects in `ext["jmap"]`, so a later start shows
      them exactly; a crash before that save makes them again, with the
      next start's dates. An INFO event,
      `agent_chat_objects_made_from_records`, counts them.
    - Nothing on disk changes: no migration, and the schema version
      stays 2.
    - Test: mimid-agent `tests/jmap_seed.rs` runs one scenario (a room
      with bob an admin, two messages, an edit, a ban) twice, once with
      bob's JMAP on and once with it off and then on, and compares what
      bob's client reads property by property, ids and dates named
      alike. They agree. Ids are minted per run and dates are each run's
      own, so the test checks what the dates say: the ones above are not
      before the start, and `receivedAt` equals `sentAt` (with JMAP on it
      is the time of the sync). A second start shows every object as the
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
