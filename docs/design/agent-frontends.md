# Agent front ends: one plaintext store, JMAP and IRC over it

Design note for epic mimid-1vul. Written 2026-11-19 against main at
e4e91cd. Status: steps 1 to 3 of §3 are built (2026-11-20). Each step
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
| MLS keys, groups, rooms, invites, the delivery journal | mimid-agent-core: `mls.sqlite`, `state.json` (crates/mimid-agent-core/src/lib.rs:45-51) | Yes |
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
`MemoryBackend`'s ids, so they are valid RFC 8620 Ids. A record migrated
from chat.json keeps its JMAP id as its key.

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

Keep one 0600 JSON file, rewritten whole through a temporary file and a
rename, with the same write order as now: store, save, then acknowledge
(sync.rs:187-192). The file becomes format 2 of `chat.json`, in neutral
records. The store reads format 1 (today's file) once, converts it, keeps
every JMAP id as the record key, and writes format 2. It renames the old
file to `chat.json.v1` before the first write, so a failed conversion
loses nothing.

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
  (crates/mimid-agent/src/http.rs:744-756).
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
4. **The store owns the file.** Switch to format 2, with the one-time
   format-1 conversion and the `chat.json.v1` copy. JMAP-only properties
   go into `ext["jmap"]`. The referenced blob set comes from the store.
   Add the tombstone and a regression test for a replayed message after a
   local delete (it fails before the change). Oracle:
   `a_restart_keeps_chats_and_messages`, both `blob_quota.rs` tests, both
   `report_abuse.rs` tests (franks across a restart), step 2's fixture
   test.
5. **Outbound through the store.** Move room create, member and role
   changes, leave, send with attachments, edit, retraction, ban, unban,
   kick and report into `Store` methods. The JMAP hooks translate JMAP
   ids to store keys and SetErrors from the results; the error mapping
   (backend.rs:685-702) stays in mimid-agent-jmap. Oracle:
   `two_accounts_chat_through_jmap`,
   `attachments_are_checked_against_the_blob_store_and_limits`,
   `attachments_travel_sealed_and_arrive_whole`, the edits, moderation
   and report tests.
6. **The feed.** The store publishes changes. The projector applies them
   from the feed instead of inline. The daemon builds the `Store` first,
   then `AgentChat::over(store)`; its sync loop calls `Store::sync`
   (crates/mimid-agent/src/daemon.rs:273-301), the projector feeds the
   EventSource `changes` broadcast (http.rs:229), and KeyPackage top-up
   takes the store's agent. Oracle: every mimid-agent integration test,
   most of all `stock_rust_client_chats_through_two_daemons` and
   `two_daemons_chat_over_http` (EventSource state changes), and
   `the_store_keeps_a_bounded_change_log_and_records_no_events`.
7. **Configuration.** Parse `[jmap]` and `[irc]` (section 5) with no IRC
   listener yet. Oracle: the config unit tests, plus new ones for the new
   keys and for refusing a non-loopback IRC address.
8. **The IRC front end** (section 4), off unless configured. New tests
   drive it over raw TCP. One of them runs a JMAP client and an IRC
   client on one daemon and checks that each sees the other's messages
   with the same `senderMsgId` and msgid.

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

- With `[jmap] enabled = false` the HTTP listener still serves attachment
  links and the did:webvh log endpoint, and answers 404 on the JMAP paths.
- `listen` may be left out when `[irc]` is set. IRC then has no
  attachment links.
- With JMAP off and no `[irc]`, the daemon refuses to start: it would
  serve nothing.
- Every address is checked for loopback, and unknown keys are refused, as
  now (config.rs:60-63, config.rs:87-129).
- The sync loop (daemon.rs:273-301) calls `Store::sync`. A send from
  either front end wakes it.

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

7. **A ChatContact that is gone.** When the format-1 reader meets a
   Message, a Chat member or a ChatBan naming a ChatContact that is not
   in the file (JMAP clients may destroy ChatContacts), it keeps the item
   with the user marked unknown and logs a warning, instead of refusing
   the whole file. The warning is one per file conversion and gives the
   count, not one per item. In the records an unknown user is
   `Sender::Unknown`, or `None` as a participant, a banned user or a
   banner; the JMAP id the item named stays in its `ext["jmap"]`.
8. **A Chat that is gone.** The same rule for Chats. crate-jmap's
   Chat/set destroy keeps the Chat's Messages and ChatBans, so the
   format-1 reader keeps a Message, ChatBan or ReadPosition naming a Chat
   not in the file, with its room marked unknown, and logs one warning per
   file with the count. Format 2 must keep them the same way (step 4).
