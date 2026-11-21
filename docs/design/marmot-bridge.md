# A MIMI room to Marmot group bridge in mimid-agent

Design note, 2026-11-21, for Mark's review. No code is written until he
has read it. It works out option (b) of nostr-comparison.md: a bridge
between a MIMI room and a Marmot group (the protocol behind the White
Noise app), driving MDK's `wn-agent` over its control socket.

Sources read, with the version of each:

| Source | Version read |
|---|---|
| mimid | main at `4f1821a` |
| github.com/marmot-protocol/mdk | `ff5320a8765d` (2026-11-21): `integrations/custom-client.md`, `crates/agent-control/src/lib.rs` and `README.md`, `crates/agent-connector/README.md`, `src/messaging.rs`, `src/event_projection.rs`, `src/send_idempotency.rs`, `crates/marmot-app/src/messages/intents.rs`, `src/client/mod.rs` (delete authorization), `crates/traits/src/app_event.rs` |
| github.com/marmot-protocol/marmot (the spec) | `36757fed3c50` (2026-11-21): `foundation/application-messages.md`, `features/encrypted-media.md`, `app-components/message-retention-v1.md`, `protocol-core/convergence.md`, `ideas/agents-in-chats.md` |
| github.com/nostr-protocol/nips | `bec0fc89e756` (2026-11-16): NIP-05 |
| draft-ietf-mimi-room-policy | -04, §6.7, §6.8, §8 |
| draft-ietf-mimi-content | -10, §4.1, §4.3, §5.4, §8.2.1 |

These are the same mdk, marmot and nips commits nostr-comparison.md
read, so the two notes describe the same snapshot. Paths below such as
`crates/agent-control/src/lib.rs` are in the mdk repo; `features/...`,
`foundation/...` and the like are in the marmot repo. Nothing here has
gone to the Marmot authors, to #mimi or to any other list.

Values marked INVENTED are mine, not from any spec or from MDK.

## 0. What the comparison left open, now checked

nostr-comparison.md §7 listed what it had not traced. Against the code:

**wn-agent's control API** (`marmot.agent-control.v2`,
`crates/agent-control/src/lib.rs`). It is newline-delimited JSON over a
Unix socket, one request per connection, at most 1 MiB a frame. The
`v2` schema is declared stable: a later breaking change gets a new
label (`crates/agent-control/README.md`, "Compatibility").

| Need | wn-agent | Notes |
|---|---|---|
| Create a group | yes, `group_create`, `group_create_with_admins` | Not idempotent: a retry can make a second group |
| Join a group | only by invite policy | No join request. A Welcome is accepted when the account's policy allows its authenticated welcomer: `deny`, `allowlist` (the default), `any-authenticated-direct`, `any-authenticated`. A `group_invite` event reports it |
| Leave | yes, `group_leave` | |
| Add or remove members | yes, `group_admin` with `add` / `remove` / `promote` | Only if the bridge's account is a Marmot admin. With no flags it reads one member's `is_member` and `is_admin` |
| List members | no | `group_info` gives `member_count`, `is_direct` and the name only. Events never name the member: "the subject member's pubkey is never surfaced" (`GroupStateChanged`) |
| Send text | yes, `send_final`, with `reply_to_message_id_hex` and an `idempotency_key` | No way to add tags. Text is scanned for npub mentions, which become `p` tags (`mention_p_tags`, `intents.rs`) |
| Edit | yes, `edit_message` | Own messages only (`invalid_edit_target`). No idempotency key |
| Delete | yes, `delete_message` | Own messages; another account's only as an admin removal of a reported message (`client/mod.rs`, the `Delete` intent). No idempotency key |
| React, unreact | yes, `send_reaction`, `remove_reaction` | `remove_reaction` with an emoji removes all of the account's reactions with that emoji on the target |
| Send attachments | yes, `send_media` | Reads files by path, only under a `--media-allowed-root` directory; at most 10 files, 512 MiB each (`MAX_MEDIA_UPLOAD_*`). Has an idempotency key |
| Receive attachments | yes, `download_media` (to a temp file), or `attachment_get` / `download_attachment` / `release_attachment` (leased handoff) | The content key never leaves wn-agent |
| Receive | `subscribe_inbound`: `inbound_message` (text, sender hex and display name, `recorded_at`, media refs, `reply_to`, `mentions_self`), `message_edited`, `message_deleted`, `reaction_added`, `reaction_removed`, `group_state_changed`, `group_invite`, `resync_required` | Own messages are not delivered back. Polls, reports, kind 4891 removals and unknown kinds are not delivered (`event_projection.rs`, the final `_ => Ok(None)`) |
| Fill gaps | `timeline_list` (cursor `(recorded_at, message_id_hex)`), `timeline_message_get` | A row has `availability`: `available`, `deleted` or `invalidated` |
| Convergence rollback | not pushed as an event | A withdrawn message shows only as `invalidated` in the timeline |
| Read receipts | none | Not in the API, and not in the Marmot spec at `36757fe` either |
| Disappearing messages | observed only | `group_state_changed` with `disappearing_timer_changed`, with no value. Nothing reads or sets the group's retention, and an inbound message carries no expiry |
| Rename the group | `group_profile_update`, admins only | |
| Look up another account's profile or NIP-05 | no | `account_profile_lookup` is for the account itself |

**Identities and keys.** wn-agent holds the Nostr secret key, the MLS
state and the relay connections. The client never sees keys or
ciphertext. An identity is made by `wn-agent bootstrap` or brought in
by `import-identity`, and the guide says it "should belong to the
connector alone and not also be signed in on another client"
(`integrations/custom-client.md`, "Choose an identity").

**How it runs.** One `wn-agent` process per home directory, as a
systemd user unit or a launchd agent. The socket is mode 0600 and
accepts only the owner's UID. A bearer token file can replace the UID
check, and then any holder of the token has full control of every
account, with no narrower scope (`crates/agent-connector/README.md`,
"Control plane security"). `send_final` idempotency keys are kept for
the last 1,024 sends in `dev/send-idempotency.json`, written to disk
after the send returns (`send_idempotency.rs`).

**Marmot content rules** that matter here:

- An app event's `pubkey` must equal the MLS sender's account, or the
  receiver drops it (`foundation/application-messages.md`, "Receiver
  authentication"). The bridge can speak only as itself.
- Unknown kinds are delivered, not rejected (same file, "Message
  kinds"), but wn-agent's stream drops them anyway.
- An edit (kind 1009) is honoured only from the original author.
- Media: the file key is derived from the epoch's exporter secret and
  the file's hash, type and name; a client "MUST NOT send it anywhere
  else" than its own account's devices (`features/encrypted-media.md`,
  "Key Derivation"). The bridge must decrypt and re-encrypt.
- Disappearing messages are a group setting, not a per-message one:
  `marmot.group.message-retention.v1` (0x8005) holds one
  `disappearing_message_secs`, set by admins, and each message expires
  at its own `created_at` plus that. The spec calls it advisory
  (`app-components/message-retention-v1.md`).

**NIP-05.** `GET https://<domain>/.well-known/nostr.json?name=<local>`
returns `{"names": {"<local>": "<hex key>"}, "relays": {...}}`. Local
parts are only `a-z0-9-_.`. The endpoint "MUST NOT return any HTTP
redirects" and fetchers "MUST ignore" them. It is "Identification, not
verification", and clients "must always follow public keys, not NIP-05
addresses": if the mapping changes later, the key stays and the name
stops being shown.

## 1. Goal and non-goals

**Goal.** People in a MIMI room and people in a Marmot group (White
Noise users) talk to each other. Each room stays what it is: a MIMI
room on its hub, a Marmot group on its relays. A bridge is a member of
both, reads one, and writes the other.

**Non-goals.**

- **One shared MLS group.** nostr-comparison.md §2.3 shows why not.
  A Marmot client rejects any leaf whose credential is not a 32-byte
  Nostr key with a valid 0x8009 proof, and MIMI leaves hold a MIMI URI;
  each side's `required_capabilities` shut out the other's clients;
  Marmot allows Commits only from admins and has no external sender or
  external commit, while a MIMI hub proposes Removes and mimid rejoins
  by external Commit; and the two sides order Commits differently (hub
  order against relay convergence), so a shared group would fork. That
  is a new protocol, not a bridge.
- **End-to-end encryption across the two sides.** It cannot survive a
  bridge. §4 says what this costs.
- **Puppets** (one bridge identity per remote user) in the first
  version. §3.3.
- **Linking MDK into mimid-agent.** MDK pins OpenMLS git rev `6100df3`;
  mimid pins the MarkAtwood fork at `f1680d9`. Two OpenMLS copies in
  one binary is not worth it when wn-agent already exists
  (nostr-comparison.md §4 (b), point 2).
- **Moderation across the bridge.** Reports, franks, bans and removals
  stay on their own side.

## 2. Architecture

### 2.1 Where the bridge runs

```text
 MIMI hub                                                Nostr relays
    |                                                          |
 mimid-server (the bridge user's provider)                     |
    |  JMAP / live stream                                      |
 mimid-agent  (user mimi://a.example/u/marmot-bridge)          |
    Store  ── front ends: bridge, IRC (operator)               |
       |                                                       |
       |  Unix socket, marmot.agent-control.v2                 |
       └──────────────────────────────►  wn-agent  ────────────┘
                                         (Nostr key, MLS, media)
```

The bridge is **a front end inside mimid-agent**, a new crate
`mimid-agent-marmot` (INVENTED name) over `Arc<Store>`, beside
`mimid-agent-irc`. It runs in a mimid-agent instance of its own, whose
user is the bridge's MIMI account, not in any person's agent. It drives
a separate `wn-agent` process over the control socket.

Why a front end and not a separate process that is a JMAP client of a
mimid-agent:

- **The store is the only journal consumer, and the bridge needs
  exactly what front ends get.** Every received message, edit,
  retraction and membership change reaches front ends as a `Change` in
  `Frontend::before_save` (crates/mimid-agent-store/src/store.rs), and
  every write is a `Store` method. A JMAP client would see the same
  through a projection and lose the store's keys and MIMI message IDs
  on the way.
- **Crash safety comes for free from the same save.** A front end's
  `ext` map and its own rows are written in the transaction that writes
  the records it reacted to (agent-frontends.md §2, §7.10). The bridge's
  id map and its outbound queue live there (§6), so a crash cannot leave
  a message recorded but not queued, or queued twice.
- **Mark already chose native over client-of-the-agent for IRC**
  (agent-frontends.md, opening paragraph). The same reasons apply.
- **It keeps the Marmot code out of mimid.** wn-agent is a separate
  binary with its own OpenMLS, Nostr and Blossom code. mimid talks JSON
  to it and links none of it.

The cost: a bridge instance is a whole mimid-agent with its own state
directory, server token and KeyPackages. That is the honest shape
anyway: the bridge is a MIMI user, and its rooms are its own.

### 2.2 Process lifecycle

- **wn-agent** runs as its own supervised service, installed with its
  own installer (`install-wn-agent.sh`, `--bootstrap`, `--relay` for
  each relay the White Noise users use) under the same Unix user as the
  bridge's mimid-agent. mimid-agent does not start it. (Open question
  2.)
- **The bridge** starts with the daemon when `[marmot]` is in the
  configuration. On start it sends `account_list` and checks that the
  configured account is listed with `local_signing: true`, and refuses
  to run the bridge (the daemon's other front ends keep running) if not.
- It opens one long-lived `subscribe_inbound` connection, filtered to
  its account, and a new connection per request. When the stream ends
  or sends `resync_required`, it reconnects with a backoff of 1 s
  doubling to 60 s (INVENTED VALUES, the same as the EventSource retry
  in docs/agent.md) and fills the gap per linked group with
  `timeline_list` from the last cursor it saved (§6).
- While wn-agent is unreachable, MIMI-to-Marmot items wait in the
  queue and Marmot-to-MIMI simply stops; neither side loses anything,
  since both queues are durable (§8).
- SIGINT and SIGTERM stop the bridge with the daemon. In-flight
  requests are abandoned; their queue rows stay and are sent again with
  the same idempotency key on the next start.

### 2.3 Keys

- **MIMI side:** the bridge user's MLS keys, in its own `mimid.sqlite`,
  as for any agent.
- **Marmot side:** a Nostr key made for the bridge with `wn-agent
  bootstrap`, held by wn-agent in its home (mode 0700). The bridge
  process never holds it.
- **Never a person's own Nostr key.** wn-agent's `import-identity`
  would let an operator use their personal npub. The bridge would then
  post other people's words as that person, to every group the key is
  in, and two clients on one identity break each other (the guide's
  troubleshooting table: "state goes wrong"). The bridge's
  configuration takes the expected account id and refuses to start if
  wn-agent's account is not it; it cannot tell a personal key from a
  new one, so the rule is in the operator guide, not in code. **Flag
  for Mark:** whether to allow a personal key at all (open question 1).

### 2.4 Configuration

A new optional table in the agent's TOML (INVENTED names, strict
parsing as for the other tables):

```toml
[marmot]
socket = "/home/bridge/.marmot-agents/standalone/dev/wn-agent.sock"
account_id_hex = "<the bridge's Nostr public key, hex>"
token_file = "/home/bridge/.marmot-agents/standalone/control.token"  # optional
media_dir = "/home/bridge/.marmot-agents/standalone/dev/outbound-media"
nip05_domains = ["a.example"]   # optional; §7
```

- `socket` must be a path to a Unix socket owned by the same user, mode
  0600 in a 0700 directory; otherwise the bridge refuses to start.
- `media_dir` must be the directory wn-agent was started with as
  `--media-allowed-root`, mode 0700. Without it, attachments are not
  bridged in either direction, and each such message says so (§5).
- Links are not in the configuration. They are made at run time (§4)
  and kept in the store, so a link cannot be made by editing a file
  without the consents.

## 3. Relay mode

### 3.1 One identity per side

- **MIMI side:** one user, for example `mimi://a.example/u/marmot-bridge`
  (INVENTED). Every Marmot user's message arrives in the MIMI room as a
  message from that user.
- **Marmot side:** one npub. Every MIMI user's message arrives in the
  Marmot group as a message from it.

**Room policy.** room-policy-04 §6.7 has `bot_policy`, a list of
`allowed_bots`, each with `bot_role_index` naming the role it acts in.
A bridge fits it: `local_client_bot` false, `bot_role_index` > 0,
`can_target_message_in_group` false, `per_user_content` false. The role
needs `canSendMessage`, `canEditOwnMessage`, `canDeleteOwnMessage`,
`canReactToMessage`, `canDeleteOwnReaction`, and nothing that changes
membership or policy. Two gaps:

- The `Bot` struct has `name`, `description` and `homepage`, and no
  field naming the participant that is the bot. Nothing ties an
  `allowed_bots` entry to the bridge's user URI. The bridge could put
  its user URI in `homepage` (a `Uri`); that is a mimid convention,
  INVENTED, and other implementations will not read it that way. Worth
  a `wg` bead (open question 5).
- mimid has the `bot_policy` codec (crates/mimi-room-policy/src/bot.rs)
  but neither the hub nor the agent acts on it today. Listing the
  bridge there is informative only until that changes.

So in practice the bridge is a participant whose role the room's admins
choose, and the bot entry is how the room says what it is.

### 3.2 How each side sees bridged speakers

The real author goes into the content. Neither side can authenticate
it: it is the bridge's claim.

- **On Marmot:** each bridged message's text starts with the speaker,
  then the text:

  ```text
  alice@a.example (via bridge): the build is green
  ```

  The label is `user@domain` from the MIMI URI `mimi://domain/u/user`,
  or the person's local display name when the bridge has one (INVENTED
  format). A body over one line keeps the prefix on the first line
  only. White Noise renders markdown (MDK has `marmot-markdown`); the
  prefix is plain text so it shows the same everywhere. wn-agent
  cannot attach tags to `send_final`, so there is no structured field.
- **On MIMI:** the body starts with the same kind of prefix, built from
  the Marmot sender's display name (wn-agent's `display_name`, from the
  sender's kind 0 profile, or none) and a short npub:

  ```text
  Bob (npub1x7k…q3, via bridge): sounds good
  ```

  and the message carries a mimiExtensions entry, text key
  `mimid-on-behalf-of` (INVENTED, NOT FROM SPEC; N7 in
  nostr-comparison.md), value a CBOR map in deterministic encoding:
  `{"uri": "nostr:npub1...", "name": "Bob" / null, "src": "<Marmot event id hex>"}`.
  The prefix is for every client; the entry is for mimid's own front
  ends and for loop prevention (§6). mimid's front ends MAY show the
  entry, but only as "Bob (via marmot-bridge)", never as a sender in
  its own right: AGENTS.md says the sender is always the authenticated
  MLS sender, and here that is the bridge.

  Later, if Mark agrees, the entry becomes a registration request for
  `onBehalfOf` in the MIMI Content Extension Keys registry
  (mimi-content-10 §8.2.1), with the rule that receivers MAY show it
  and MUST NOT treat it as authenticated (N7). Not before the bridge
  has been used.

### 3.3 Puppet mode, later or never

The alternative: one Nostr key per MIMI user, each a leaf in the Marmot
group, and one MIMI user URI per Marmot npub (mimid-server can host
`mimi://a.example/u/npub1...`), each a leaf in the MIMI room.

| | Relay mode | Puppet mode |
|---|---|---|
| What members see | one bridge member, names in the text | a member per remote person |
| Honesty | plain: the bridge holds the plaintext and says so | each puppet looks like a person who is not there; the bridge still holds all plaintext |
| Marmot adds | one admin add, once | an admin add per new MIMI speaker; wn-agent has no batch add and the bridge would need to be admin |
| MIMI adds | one invite | one per Marmot speaker, each through room policy and consent |
| Keys | two | one Nostr key and one MIMI account per remote person, each with KeyPackages to keep fresh |
| wn-agent | one account | many accounts in one wn-agent (it supports several, per `account_list`) |
| Reactions, edits | the bridge's own, with the ref-counting of §5 | per person, exact |
| Room size | +1 each side | +N each side |

Relay mode first. Puppets only if users ask for per-person reactions
or mentions, and then as a separate design.

## 4. Linking and consent

### 4.1 Getting the bridge into both rooms

- **MIMI:** a member whose role has `canAddParticipant` invites the
  bridge user. The bridge's agent joins by its `invites` setting:
  `from-allowed` with the users the operator allowed (`/msg mimid allow
  <user>` over the IRC front end), or `any`. Joining a room does not
  link it.
- **Marmot:** a Marmot admin adds the bridge's npub. wn-agent accepts by
  its invite policy: `allowlist` with that admin's npub, or
  `any-authenticated`. The operator manages it through the control API
  (`allowlist_add`, `invite_policy_set`), which the bridge exposes as
  service commands (§4.3). Joining a group does not link it either.

Being in both is not consent to copy one into the other.

### 4.2 Linking

A link is made only when an admin of each side has asked for it.

1. **MIMI side asks.** In the MIMI room, a member sends `!bridge link`
   (INVENTED). The bridge accepts it only from a participant whose role
   has `canChangeOtherPolicyAttribute` (room-policy-04 §8; the
   capability that would edit `bot_policy`). Recommendation and
   alternatives: open question 3. The bridge answers in the room with a
   one-time code: 8 characters of base32, valid for 10 minutes
   (INVENTED VALUES).
2. **Marmot side confirms.** In the Marmot group, someone sends
   `!bridge link <code>`. The bridge checks with `group_admin` (no
   flags) that the sender's account is an admin of that group, and
   that the code is live and unused.
3. **The link exists** when both are done: the store keeps a link
   record (room key, group id, who asked on each side, when). The
   bridge posts the notice of §4.4 on both sides, then starts copying.
   Nothing sent before the link is copied.

The order can be reversed (code from the Marmot side, confirmed on the
MIMI side) with the same checks. A room links to at most one group and
a group to at most one room (INVENTED limit; it keeps the id map and
the notices simple).

**From the operator.** The bridge's agent can run the IRC front end
for its operator. `/msg mimid bridge` commands (INVENTED, documented
with the crate) list links and invites, set wn-agent's allowlist and
invite policy, and unlink. The operator cannot link a pair alone: the
two admin steps above are required. The operator can always unlink,
since they can switch the bridge off anyway.

**From JMAP.** Nothing in v1. A JMAP method would need a JMAP Chat
extension, and any write to crate-jmap or jmap-chat-spec needs Mark's
OK. The in-room commands work from any client.

### 4.3 Unlinking

Any of these ends a link: `!bridge unlink` from a MIMI participant with
the linking capability or from a Marmot admin; the operator's command;
the bridge being removed from either side, or the room or group
disbanded; the bridge's MIMI role losing `canSendMessage`. The bridge
posts a notice on whatever side it can still reach, stops copying,
keeps the id map for 30 days (INVENTED) so late edits and deletes of
copied messages still reach the copies, and then drops it. It does not
leave either side by itself; an admin removes it if they want.

### 4.4 What members are told

On link, on each side, from the bridge, and again to anyone who joins
later (as a notice in their first sync after joining, on MIMI; on
Marmot, as a message after each `member_added` change, since wn-agent
does not say who joined):

> This room is bridged to a White Noise (Marmot) group by
> marmot-bridge, run by <operator, from configuration>. Messages are
> decrypted by the bridge and encrypted again for the other side, so
> the bridge and whoever runs it can read everything said here. Names
> shown as "(via bridge)" are the bridge's claim, not proven by the
> other side. The other side has <n> members. Unlink with
> `!bridge unlink`.

`<n>` on the MIMI side is wn-agent's `member_count`; the bridge cannot
list the Marmot members (§0). On the Marmot side it lists the MIMI
participants' URIs, which the bridge can see.

**The security consequence, stated plainly.** Once linked, the
end-to-end encryption of both rooms ends at the bridge's host: the
bridge's mimid-agent holds every message in plaintext in its store and
blob directory, and wn-agent holds the Marmot side's plaintext and
keys, so the operator, anyone who controls that machine, and any
process that can use wn-agent's socket or token can read both rooms
and can post in either one under any name in the "(via bridge)"
prefix. MIMI members also cannot see who the Marmot members are, only
how many. Members of each room should treat the bridge's host as one
more device that reads all their messages.

## 5. Message mapping

"M→N" is MIMI to Marmot (Nostr side), "N→M" the reverse. "Bridge
copy" means the message the bridge sent; the id map (§6) links it to
its source.

| What | M→N | N→M | Dropped or changed, and how it shows |
|---|---|---|---|
| Text | `send_final`, prefix of §3.2, idempotency key from the store record (§6). `text/markdown` passes as is; Marmot renders markdown (dialect not compared with GFM-MIMI) | `inbound_message` → `Store::send_with` with prefix and `mimid-on-behalf-of` | Body over `MAX_TEXT_LEN` (16 KiB, crates/mimid-agent-core/src/agent.rs) after the prefix: cut, ending `[…cut by bridge]` |
| Edit | `Change::MessageChanged` with a new version → `edit_message` on the bridge copy, text with prefix | `message_edited` → `Store::edit` of the bridge copy | Edits of messages from before the link: dropped. Marmot honours edits only from the author, and the bridge is the author of its copies, so this works both ways |
| Delete, retraction | retraction → `delete_message` of the bridge copy | `message_deleted` (author or admin removal) → `Store::retract` of the bridge copy | None |
| Reaction | mimid stores no reactions today (prerequisite P2). Then: `send_reaction` on the mapped target. The bridge reacts once per emoji per target and keeps a count; the reaction is removed (`remove_reaction` with that emoji) when the last MIMI reactor of that emoji unreacts | `reaction_added` → a MIMI reaction (disposition `reaction`, `inReplyTo` the bridge copy or the MIMI original) from the bridge, with `mimid-on-behalf-of`; `reaction_removed` → retract that one | M→N loses who reacted; Marmot members see the bridge's single reaction. N→M keeps one reaction per person |
| Reply | `inReplyTo` resolved to a store key → `reply_to_message_id_hex` of the mapped Marmot id | `reply_to` → `inReplyTo` of the mapped MIMI message | Target not in the map (before the link, or expired): sent as a plain message, with `↪ <first 80 chars of the quoted text>` on the first line (INVENTED) when wn-agent gave an excerpt. mimid cannot send `inReplyTo` today (prerequisite P1) |
| Mention | markdown link to `mimi://d/u/x` → `nostr:npub1…` when §7 maps that user to a key, else `@x@d` as text | `nostr:npub1…` or an npub in text → markdown link `[@name](mimi://…)` only when §7 maps the key back; else the npub as text | wn-agent turns npubs in sent text into `p` tags, so a mapped mention notifies the White Noise user |
| Attachments | blob from the store → copy into `media_dir` (mode 0600) → `send_media` with the caption, key `<store key>:media` → remove the copy after the answer | media refs → `download_media` → plaintext temp file → into the store's blob store → `Store::send_with` with the files; mimid encrypts and uploads to its provider | Re-encrypted on each side; no file key crosses (`features/encrypted-media.md`). Over the receiving side's limits (wn-agent: 10 files, 512 MiB each; the bridge agent's `blob_quota_bytes`): text sent, with `[attachment not bridged: <name>, <size>]` |
| Calls to join (`session` parts) | URL as text, `Call: <url>` | n/a | Not a call on the Marmot side, just a link |
| Absolute expiry (`expires`, `relative` false) | sent, then the bridge deletes its copy with `delete_message` at the expiry time (a scheduled row in the store, kept across restarts like §7.23 of agent-frontends.md) | see "Disappearing" below | Best effort: deletion hides the copy in clients that honour kind 5, and the encrypted event stays on relays until the group's retention, if any. Said once per room in a notice when the first such message is bridged |
| Read rule (`expires`, `relative` true: burn on read, delete after read) | **not bridged** (recommendation; open question 4). The sender's side gets a notice: "not sent to the White Noise side: it cannot honour burn-on-read" | n/a | The bridge "reads" everything at once, so the rule would fire on its own copy and protect nothing on the other side |
| Disappearing (Marmot group retention) | n/a | wn-agent does not expose the value (§0). Until it does: the link takes a retention in seconds from the Marmot admin's `!bridge link <code> [retention]` (INVENTED), and each N→M copy gets `expires` = `recorded_at` + that | On `disappearing_timer_changed`, the bridge posts a notice on MIMI asking an admin to restate it, and stops adding `expires` until they do (INVENTED behaviour; open question 4) |
| Read receipts | none | none | Neither side carries them through the bridge. mimid's read positions are local; Marmot has no read receipts in its spec |
| Joins, leaves, role changes | `Change::RoomChanged` membership → a message from the bridge, `bob@b.example joined the MIMI room` | `group_state_changed` `member_added` / `member_removed` / `member_left` / `admin_*` → a store notice, "a member joined the White Noise group (now n members)" | N→M has no names: wn-agent does not give them |
| Room name, subject | a message from the bridge, `room renamed to "x"` | `group_renamed` (with the name) → a store notice | Not applied to the other side: the bridge would need to be a Marmot admin, or `canChangeRoomName` on MIMI. Recommendation: never |
| Topics (`topicId`) | dropped | n/a | |
| Polls, reports, kind 4891 removals, unknown kinds | n/a | not delivered by wn-agent | Silent. Reports stay on their side by design |
| Abuse reports, franks | not bridged | not bridged | A MIMI report about a bridge copy names the bridge as sender; its `mimid-on-behalf-of` says whom it was relayed for |

**Prerequisites in mimid** found while mapping, each its own bead
before the bridge:

- **P1:** `Agent::send_message` takes no `inReplyTo`
  (agent-frontends.md §4, "Sending"); add it and a `Store` method.
- **P2:** reactions are not an action and not modelled
  (crates/mimid-agent-store/src/action.rs, "Limitations"); add
  receive, send and unreact.
- **P3:** the store does not keep a received message's mimiExtensions;
  keep the `mimid-on-behalf-of` entry (needed for §6 loop checks and
  for front ends that show it).

## 6. Loop prevention and idempotency

### 6.1 The id map

A table in `mimid.sqlite`, owned by the bridge crate, written in the
same transaction as the store's save (the bridge's `before_save` writes
it; INVENTED layout):

| Column | Meaning |
|---|---|
| `link` | link key |
| `direction` | `m2n` or `n2m` |
| `store_key` | the store message on the MIMI side (source or copy) |
| `version` | for M→N, which version of the store message was last sent (0 = first, then each edit) |
| `marmot_id` | the Marmot event id on the other side (source or copy) |
| `state` | `queued`, `sent`, `failed` |
| `idem_key` | for M→N, the `send_final` / `send_media` key: `<link>:<store_key>:<version>` |
| `expires_at` | scheduled delete, for §5's absolute expiry |

Reactions get rows of the same form, with the reaction's ids and the
emoji count for M→N.

### 6.2 MIMI to Marmot

1. A save brings `Change::MessageAdded`, `MessageChanged` or
   `MessageDeleted` for a room that is linked. The bridge's
   `before_save` writes a `queued` row. It does no network I/O there:
   `before_save` runs inside the save, and a failure there aborts the
   save (crates/mimid-agent-store/src/store.rs).
2. A sender task takes queued rows in store order per link, sends, and
   on the answer marks the row `sent` with the Marmot ids, through the
   next save.
3. After a crash it sends `queued` rows again. `send_final` and
   `send_media` reuse the same `idem_key`, so wn-agent answers with the
   first send's ids instead of posting again. Two holes, both narrow:
   wn-agent writes its idempotency file after the send returns, so a
   wn-agent crash in that window forgets the key; and it keeps only the
   last 1,024 keys. Either gives one duplicate message, not a loss.
4. Edits, deletes and reactions have no idempotency key in wn-agent.
   Before sending one again after a restart, the bridge reads the
   target with `timeline_message_get`: an edit whose text is already
   there, a delete of a message already `deleted`, or a reaction the
   bridge already has on the target, is marked `sent` without sending.

### 6.3 Marmot to MIMI

1. An event arrives on the stream (or from `timeline_list` after a
   gap). If its `message_id_hex` is in the map, it is skipped. If the
   sender is the bridge's own account it is skipped (wn-agent already
   does not deliver those).
2. The bridge calls `Store::send_with`, which goes through the agent's
   outbox: encrypted and written before it leaves, sent again with the
   same bytes after a crash, never encrypted twice (agent-frontends.md
   §3 step 10). The bridge writes the map row and the record's
   `ext["marmot"]` before the save that follows.
3. The gap: the agent's outbox transaction and the store's save are two
   transactions. A crash between them leaves a MIMI message on its way
   with no map row, and the bridge would send it again. The message
   carries the Marmot event id in `mimid-on-behalf-of` `src`, so when
   the agent's `Event::Sent` copy is stored on the next sync (it is,
   §3 step 10), the bridge finds the `src`, writes the row, and does
   not send again. This needs P3.
4. The stream cursor: the `(recorded_at, message_id_hex)` of the last
   event handled, per link, saved with the map. On reconnect,
   `timeline_list` with `after` that cursor.

### 6.4 Loops

- The bridge never copies a message whose MIMI sender is the bridge
  user, nor a Marmot event from its own account.
- Two bridges on one pair would copy each other's copies. On MIMI, a
  message with a `mimid-on-behalf-of` entry is never copied again.
  On Marmot there is no structured marker (no tags), so the bridge
  skips messages from npubs listed in a `peer_bridges` setting
  (INVENTED), and on its own matches nothing by text: a text rule
  could be spoofed by any member. Stated as a limit: two bridges on one
  pair, not configured to know each other, loop. The link rule of one
  group per room per bridge does not stop a second operator.

### 6.5 Convergence withdrawals

Marmot can withdraw a message after it was delivered, when a later
convergence pass picks another branch (`protocol-core/convergence.md`,
"invalidated, and their app payloads are withdrawn"). wn-agent does not
push this; the timeline shows `invalidated`. The bridge rechecks every
N→M source it copied in the last hour with `timeline_message_get` once
a minute (INVENTED VALUES), and retracts the MIMI copy of any that is
now `invalidated`, with a notice ("a White Noise message was withdrawn
by its group"). The other choice, holding each message for a settling
time before copying, adds seconds to every message for a rare event.
Open question 7.

## 7. Identity: NIP-05

`alice@a.example` (NIP-05) and `mimi://a.example/u/alice` have the same
shape. The bridge uses that in three ways:

1. **Naming MIMI users to Marmot.** For a MIMI user on a domain in
   `nip05_domains`, the bridge fetches
   `https://<domain>/.well-known/nostr.json?name=<local>`. If it names a
   key, a mention of that user becomes `nostr:npub1…` (§5), and the
   prefix may show the npub. The domain in the list is the bridge's
   choice to trust; NIP-05 is "identification, not verification".
2. **Naming Marmot users to MIMI.** A Marmot sender's key that appears
   in a fetched `nostr.json` of a listed domain is shown as
   `user@domain` in the prefix and mapped to `mimi://domain/u/user` for
   mentions. The bridge cannot check the sender's kind 0 `nip05` claim
   (wn-agent offers no profile lookup for other accounts), so this is
   the domain's word only, and it is only a display name: the key
   remains the identity, as NIP-05 says.
3. **Inviting by name**, for the operator: `/msg mimid bridge invite
   <group> alice@a.example` resolves the key and asks wn-agent to add
   it, if the bridge is a Marmot admin of that group (it should not be;
   §3.1). Low value; maybe never.

Rules for the fetch: `https` only; no redirects followed (NIP-05
"MUST"); destination addresses in loopback, link-local, private and
other special ranges refused after resolution (the SSRF concern of N3);
a body cap of 64 KiB and a 5 s timeout; positive answers cached for an
hour and negative ones for 5 minutes (INVENTED VALUES); a key that
changes for a name is shown as changed, never silently swapped.

**Server side.** mimid-server serving `/.well-known/nostr.json` for its
own users who register an npub (nostr-comparison.md option (d)) makes
1 and 2 work for that provider's users without any other host. It is
separate from the bridge: a configuration table or an admin command,
a few hundred lines. Recommendation: after the bridge works (open
question 9).

## 8. Failure modes

| Failure | What happens | What members see |
|---|---|---|
| wn-agent down or socket missing | M→N rows stay `queued`; N→M stops. Reconnect with backoff; on return, queued rows go out in order and `timeline_list` fills N→M | A delay. After 5 minutes down (INVENTED), one notice on the MIMI side: "the White Noise side is not reachable; messages will follow" |
| wn-agent answers `retryable: true` | retry with the same key | nothing |
| wn-agent answers a non-retryable error | row `failed`, logged with the code | on the sender's side: "not delivered to White Noise: <code>" (once per message) |
| Relays down | wn-agent's problem: it owns relay I/O and durable sends, and `final_sent` means it published the message (the guide: "does not prove a member received it"). What it answers with every relay down was not traced; a retryable error or a timeout leaves the row queued, and a later send reuses the key | delay on the Marmot side only |
| Marmot Commit races | invisible to the bridge except as withdrawals (§6.5) and possibly `post_join_rotation_pending_retryable` after a join, which still means sent | a withdrawn message is retracted on MIMI with a notice |
| The bridge removed from the Marmot group | `group_state_changed` does not say who was removed; the next send fails, and `group_admin` (read) shows `is_member: false` | unlink (§4.3), notice on MIMI |
| MIMI hub refuses (room policy: the bridge's role lacks the capability; `wrongEpoch` handled by the agent; a size limit) | the agent returns the refusal; row `failed` | on the Marmot side: "not delivered to MIMI: <reason>", at most one per minute per link (INVENTED) |
| The bridge's MIMI agent cannot reach its server | the agent's outbox keeps the message; N→M copies wait | delay on MIMI |
| MLS version skew | none between the two sides: each MLS group is run by its own implementation (mimid's OpenMLS fork `f1680d9`; MDK's OpenMLS `6100df3`), in separate processes, and no MLS message crosses the bridge. Skew matters only within each side, as now | nothing |
| Marmot spec churn | the spec changes daily (`changes.md`). The bridge depends on the control protocol, not on the spec, and `v2` is declared stable. Pin: the bridge records the wn-agent release it was tested with and the marmot and mdk commits read (this note: `36757fe`, `ff5320a`); `account_list` failing to parse, or an unknown `marmot_agent_control` label, stops the bridge with an error. Tracking: a recurring bead to read mdk's CHANGELOG and marmot's `changes.md` at each wn-agent release and bump the pin | nothing, until the pin moves |
| wn-agent's stream lags | `resync_required`; fill from `timeline_list` | nothing |
| Two bridges on one pair | loops on the Marmot side unless configured (§6.4) | duplicates |
| The bridge's host compromised | both rooms readable, any "(via bridge)" name forgeable | nothing; this is the §4.4 consequence |

## 9. Size and steps

Sizes compare with mimid-agent-irc, about 4,200 lines of Rust.

| Step | What | Rough size |
|---|---|---|
| 1 | P1: `inReplyTo` on send, in agent-core and the store; then JMAP `replyTo`, refused today, and IRC `+draft/reply`, dropped today | 300 to 500 lines, 1 to 2 commits |
| 2 | P2: reactions in the store: receive, send, unreact; JMAP and IRC rendering | 600 to 900 lines, 2 to 3 commits |
| 3 | P3: keep `mimid-on-behalf-of` on received messages; show it in JMAP and IRC as "(via …)" | 200 to 300 lines, 1 commit |
| 4 | Control-socket client: own serde types for the requests and events used, framing, the stream with reconnect; a fake wn-agent for tests that replays JSON fixtures captured from agent-control's own serde output at the pinned commit, with `PROVENANCE` | 1,000 to 1,400 lines with tests, 2 commits |
| 5 | The crate and `[marmot]` config; link records; in-room commands and codes; IRC service commands; notices | 900 to 1,200 lines, 2 to 3 commits |
| 6 | Text both ways: id map, queue, idempotency, crash tests at each failure point as in `tests/send_crash.rs` | 1,200 to 1,600 lines, 2 to 3 commits |
| 7 | Edits, deletes, replies, reactions, membership and rename notices | 700 to 1,000 lines, 2 commits |
| 8 | Attachments both ways; expiry (scheduled deletes, retention from the link) | 600 to 900 lines, 2 commits |
| 9 | NIP-05 lookups and mention mapping | 400 to 600 lines, 1 to 2 commits |
| 10 | docs/agent.md `[marmot]`, an operator guide, AGENTS.md crate map; a manual round trip with a real wn-agent and a White Noise phone | 300 lines of docs, 1 commit |

About 6,000 to 8,500 lines with tests, 16 to 21 commits. Steps 1 to 3
are useful without the bridge and can go first. Each step is one bead
under the epic; none is filed until Mark approves this note.

Tests stay offline (AGENTS.md): the fake wn-agent answers on a Unix
socket in a temp directory. The only live check is step 10, by hand.

## 10. Open questions for Mark

1. **Whose Nostr key.** The bridge's own key made by `wn-agent
   bootstrap`, or may an operator import a personal one?
   Recommendation: the bridge's own only, said in the operator guide;
   the config pins the account id so a swapped key is noticed. A
   personal key would post other people's words as that person.

2. **Who starts wn-agent.** A separate service installed by MDK's
   installer, or a child process mimid-agent starts and stops?
   Recommendation: separate. It keeps MDK's install, upgrade and
   `doctor` tools working as documented, and mimid-agent carries no
   process supervision code.

3. **Which MIMI capability may link a room.** `canChangeOtherPolicyAttribute`,
   `canAddParticipant`, or a mimid-specific rule such as "role named
   admin"? Recommendation: `canChangeOtherPolicyAttribute`. Linking
   exposes the room to people its members cannot see, which is closer
   to a policy change than to adding one known person.

4. **Expiring messages.** Bridge absolute expiry with a scheduled
   delete of the copy, refuse read rules (burn on read, delete after
   read) with a notice, and take the Marmot group's retention from the
   linking admin because wn-agent does not report it? Recommendation:
   yes to all three. The alternative, refusing to link any room with
   expiry, makes the bridge useless for the people most likely to want
   White Noise.

5. **The bot policy gap.** room-policy-04's `Bot` has no field for the
   bot's user URI. Use `homepage` for it as a mimid convention, and
   file a `wg` bead? Recommendation: yes to both; nothing posted to
   #mimi without your OK.

6. **On-behalf-of.** A private text key `mimid-on-behalf-of` now, and
   an `onBehalfOf` registration request (N7) only after the bridge has
   been used? Recommendation: yes. The request text would go past you
   first.

7. **Withdrawn Marmot messages.** Copy at once and retract on MIMI if
   the message is later `invalidated` (with a once-a-minute recheck for
   an hour), or hold each message a few seconds before copying?
   Recommendation: copy at once and retract. Rollbacks need concurrent
   Commits, which are rare; a delay on every message is not.

8. **wn-agent's DTOs.** Write mimid's own serde types for the few
   requests and events used, or depend on MDK's `agent-control` crate
   (MIT, serde and tokio only) by git? Recommendation: own types,
   tested against fixtures captured from `agent-control`'s serde output
   with a `PROVENANCE` file. That keeps the fixture rule (outside the
   code under test) and no git dependency on a repo that changes daily.

9. **NIP-05 on mimid-server.** Serve `/.well-known/nostr.json` for
   users who register an npub? Recommendation: yes, but as its own bead
   after the bridge, since the bridge works with other domains'
   `nostr.json` without it.

10. **Marmot member list.** MIMI members can see only how many people
    are on the Marmot side. Accept that and say it in the link notice,
    or refuse to link until wn-agent can list members? Recommendation:
    accept and say it. Marmot hides member keys from its own event
    stream on purpose; asking upstream for a list is a separate
    conversation, and would go through you.

11. **Personal bridges.** Should a person be able to run the bridge in
    their own agent, as themselves, for their own rooms? Then every
    Marmot message would appear on MIMI as sent by that person.
    Recommendation: no. The bridge is always its own MIMI user.

12. **Puppet mode.** Leave it out unless users ask? Recommendation:
    yes, leave it out (§3.3).

## 11. Uncertainties

- wn-agent's behaviour was read from code and docs, not run. Whether
  `final_sent` comes before or after the convergence pass settles, and
  how often `invalidated` really happens, are not measured.
- Whether White Noise shows several identical reactions from one
  account, or only one, is not checked; §5 assumes one per emoji.
- Which `wn-agent-v*` release tag matches `ff5320a` is not checked; the
  workspace version there is `0.19.0-dev`.
- The markdown dialects of Marmot (`marmot-markdown`) and GFM-MIMI were
  not compared; text may render differently on each side.
- `display_name` in wn-agent's events comes from a profile it has
  cached; how stale it can be was not traced.
- The sizes in §9 are estimates from the IRC front end's size, not from
  a prototype.
