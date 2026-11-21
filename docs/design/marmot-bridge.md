# A MIMI room to Marmot group bridge in mimid-agent

Design note, 2026-11-21. It works out option (b) of
nostr-comparison.md: a bridge between a MIMI room and a Marmot group
(the protocol behind the White Noise app), driving MDK's `wn-agent`
over its control socket. Mark answered its twelve open questions the
same day; his decisions are in §10, and the body follows them where
they differ from what the first version of this note recommended.
The step plan of §9 is filed as beads under epic mimid-kiy1.

Sources read, with the version of each:

| Source | Version read |
|---|---|
| mimid | main at `4f1821a`; decisions applied on main at `2fb014f` |
| github.com/marmot-protocol/mdk | `ff5320a8765d` (2026-11-21): `integrations/custom-client.md`, `crates/agent-control/src/lib.rs` and `README.md`, `crates/agent-connector/README.md`, `src/messaging.rs`, `src/event_projection.rs`, `src/send_idempotency.rs`, `crates/marmot-app/src/messages/intents.rs`, `src/client/mod.rs` (delete authorization), `crates/traits/src/app_event.rs` |
| github.com/marmot-protocol/marmot (the spec) | `36757fed3c50` (2026-11-21): `foundation/application-messages.md`, `features/encrypted-media.md`, `app-components/message-retention-v1.md`, `protocol-core/convergence.md`, `ideas/agents-in-chats.md` |
| github.com/nostr-protocol/nips | `bec0fc89e756` (2026-11-16): NIP-05, NIP-98 |
| draft-ietf-mimi-room-policy | -04, §6.7, §6.8, §8 (still the latest in the IETF archive on 2026-11-21) |
| draft-ietf-mimi-content | -10, §4.1, §4.3, §5.4, §8.2.1 (still the latest on 2026-11-21) |
| draft-ietf-mimi-protocol | -07, §7.5 (for §7.3 only; still the latest on 2026-11-21) |
| draft-ietf-mimi-arch | -03 (for §7.3 only) |

These are the same mdk, marmot and nips commits nostr-comparison.md
read, so the two notes describe the same snapshot. Paths below such as
`crates/agent-control/src/lib.rs` are in the mdk repo; `features/...`,
`foundation/...` and the like are in the marmot repo. Nothing here has
gone to the Marmot authors, to #mimi or to any other list. Two WG
issues are drafted (§3.1, §3.2) and wait for Mark's OK.

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
| Create an account | yes, `account_create` with `label` and `publish_key_package` | No idempotency key. `account_list` returns each account's `label`, so a retry can be checked against it. No request removes an account |
| Publish a profile | yes, `account_publish_profile`: `name`, `display_name`, `about`, `picture`, `nip05`, `lud16` | For the account itself. Absent fields keep their published value |
| Create a group | yes, `group_create`, `group_create_with_admins` | Not idempotent: a retry can make a second group |
| Join a group | only by invite policy | No join request. A Welcome is accepted when the account's policy allows its authenticated welcomer: `deny`, `allowlist` (the default), `any-authenticated-direct`, `any-authenticated`. A `group_invite` event reports it |
| Leave | yes, `group_leave` | |
| Add or remove members | yes, `group_admin` with `add` / `remove` / `promote` | Only if the account is a Marmot admin. With no flags it reads one member's `is_member` and `is_admin` |
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
ciphertext. An identity is made by `wn-agent bootstrap`, by
`account_create`, or brought in by `import-identity`, and the guide
says it "should belong to the connector alone and not also be signed
in on another client" (`integrations/custom-client.md`, "Choose an
identity").

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
- Convergence: a new Commit opens a pass that closes after 1 s with no
  new input or 5 s in all; a later pass can still roll back to a fork
  up to 5 Commits back and withdraw the loser's messages
  (`protocol-core/convergence.md`; nostr-comparison.md §2.1).

**NIP-05.** `GET https://<domain>/.well-known/nostr.json?name=<local>`
returns `{"names": {"<local>": "<hex key>"}, "relays": {...}}`. Local
parts are only `a-z0-9-_.`. Keys are lowercase hex. The endpoint "MUST
NOT return any HTTP redirects" and fetchers "MUST ignore" them. Servers
that answer per `name` "SHOULD also serve the relays data", and the
file should carry `Access-Control-Allow-Origin: *`. It is
"Identification, not verification", and clients "must always follow
public keys, not NIP-05 addresses": if the mapping changes later, the
key stays and the name stops being shown.

**NIP-98** defines a signed kind 27235 event with a `u` tag (the exact
URL) and a `method` tag, whose `created_at` must be within "a
reasonable time window (suggestion 60 seconds)". §7.2 borrows its shape
as a proof that a person holds a Nostr key.

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
- **Puppets in the first release.** Relay mode ships and is used
  first. Puppet mode is designed now (§3.3, decision 12) so the relay
  code does not have to be rewritten for it, and it is built after
  relay mode, on a multi-user host that gateways will share.
- **Linking MDK into mimid-agent.** MDK pins OpenMLS git rev `6100df3`;
  mimid pins the MarkAtwood fork at `f1680d9`. Two OpenMLS copies in
  one binary is not worth it when wn-agent already exists
  (nostr-comparison.md §4 (b), point 2).
- **Moderation across the bridge.** Reports, franks, bans and removals
  stay on their own side.
- **A person's own Nostr key.** The bridge never uses one, in any mode
  (decision 1).

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
`mimid-agent-irc`. In the usual, **dedicated** mode it runs in a
mimid-agent instance of its own, whose user is the bridge's MIMI
account. In **personal** mode (decision 11, §2.5) it runs in a
person's own agent, for that person's rooms. Either way it drives a
separate `wn-agent` process over the control socket.

Why a front end and not a separate process that is a JMAP client of a
mimid-agent:

- **The store is the only journal consumer, and the bridge needs
  exactly what front ends get.** Every received message, edit,
  retraction and membership change reaches front ends as a `Change` in
  `Frontend::before_save` (crates/mimid-agent-store/src/store.rs), and
  every write is a `Store` method. A JMAP client would see the same
  through a projection and lose the store's keys and MIMI message IDs
  on the way.
- **Crash safety comes from the same save.** A front end's `ext` map
  and its own rows are written in the transaction that writes the
  records it reacted to (agent-frontends.md §2, §7.10). The bridge's id
  map and its MIMI-to-Marmot queue live there (§6), so a crash cannot
  leave a message recorded but not queued, or queued twice. The
  Marmot-to-MIMI hold queue is written in a transaction of its own
  with the stream cursor (§6.3).
- **Mark already chose native over client-of-the-agent for IRC**
  (agent-frontends.md, opening paragraph). The same reasons apply.
- **It keeps the Marmot code out of mimid.** wn-agent is a separate
  binary with its own OpenMLS, Nostr and Blossom code. mimid talks JSON
  to it and links none of it.

The cost: a dedicated bridge is a whole mimid-agent with its own state
directory, server token and KeyPackages. That is the honest shape
anyway: the bridge is a MIMI user, and its rooms are its own.

**One seam for puppet mode.** Every send to either side goes through a
*speaker resolver* (INVENTED name) that answers "which identity sends
this person's words on that side". In relay mode it always answers the
bridge's own identity (or, in personal mode, the person's account on
MIMI). Puppet mode (§3.3) supplies a resolver that answers the person's
puppet where one exists and the relay identity otherwise. The id map
records which identity sent each copy (§6.1). Nothing else in the
bridge assumes one identity per side.

### 2.2 Process lifecycle

- **wn-agent** runs as its own supervised service, installed with its
  own installer (`install-wn-agent.sh`, `--bootstrap`, `--relay` for
  each relay the White Noise users use) under the same Unix user as the
  bridge's mimid-agent. mimid-agent does not start it (decision 2).
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
  the same idempotency key on the next start. Held Marmot messages stay
  held and are released on the next start once their hold time has
  passed (§6.3).

### 2.3 Keys

- **MIMI side:** the bridge user's MLS keys, in its own `mimid.sqlite`,
  as for any agent. In personal mode, the person's own agent keys.
- **Marmot side:** a Nostr key made for the bridge with `wn-agent
  bootstrap`, held by wn-agent in its home (mode 0700). The bridge
  process never holds it.
- **Never a person's own Nostr key** (decision 1). wn-agent's
  `import-identity` would let an operator use their personal npub. The
  bridge would then post other people's words as that person, to every
  group the key is in, and two clients on one identity break each other
  (the guide's troubleshooting table: "state goes wrong"). The bridge's
  configuration pins the expected account id and refuses to start if
  wn-agent's account is not it. The bridge cannot tell a personal key
  from a new one, so the rule is stated in the operator guide and in
  the personal-mode setup (§2.5), not enforced in code.

### 2.4 Configuration

A new optional table in the agent's TOML (INVENTED names, strict
parsing as for the other tables):

```toml
[marmot]
mode = "dedicated"              # or "personal" (§2.5); default "dedicated"
socket = "/home/bridge/.marmot-agents/standalone/dev/wn-agent.sock"
account_id_hex = "<the bridge's Nostr public key, hex>"
token_file = "/home/bridge/.marmot-agents/standalone/control.token"  # optional
media_dir = "/home/bridge/.marmot-agents/standalone/dev/outbound-media"
operator = "Example Org chat admins"   # shown in the link notice (§4.4)
hold_secs = 6                   # §6.3; 0 to 30
nip05_domains = ["a.example"]   # optional; §7.1
peer_bridges = []               # optional; npubs of other bridges (§6.4)
```

- `socket` must be a path to a Unix socket owned by the same user, mode
  0600 in a 0700 directory; otherwise the bridge refuses to start.
- `media_dir` must be the directory wn-agent was started with as
  `--media-allowed-root`, mode 0700. Without it, attachments are not
  bridged in either direction, and each such message says so (§5).
- `operator` is required in dedicated mode. In personal mode it is
  ignored: the operator is the agent's own user.
- Links are not in the configuration. They are made at run time (§4)
  and kept in the store, so a link cannot be made by editing a file
  without the consents.

### 2.5 Personal bridges (decision 11)

A person may run the bridge in their own mimid-agent, for their own
rooms. The MIMI side is then their own account: every White Noise
message in a linked room appears on MIMI as sent by that person,
marked "(via bridge)". The Nostr side still uses a key made for the
bridge, never the person's own npub (decision 1): the person runs
their own wn-agent, bootstraps a new account for it, and puts that
account's id in `account_id_hex`.

What differs from a dedicated bridge:

| | Dedicated (`mode = "dedicated"`) | Personal (`mode = "personal"`) |
|---|---|---|
| MIMI identity | the bridge's own account, e.g. `mimi://a.example/u/marmot-bridge` | the person's account, e.g. `mimi://a.example/u/alice` |
| Nostr identity | a key made for the bridge | a key made for the bridge, in the person's own wn-agent; its profile name says whose bridge it is ("alice's bridge", set with `account_publish_profile` on first start) |
| Who runs it | an operator, for any room that invites and links it | the person, for themselves |
| Which rooms can be linked | any room where the bridge user is a participant | only rooms where the person's own role has `canChangeOtherPolicyAttribute` (the linking capability, decision 3): "their own rooms" in policy terms |
| Who asks on the MIMI side (§4.2 step 1) | any participant whose role has the linking capability | the person only, with `!bridge link` from one of their own clients, or `/msg mimid bridge link <room>` over the IRC front end |
| Marmot side (§4.2 step 2) | a Marmot admin confirms the code | the same: a Marmot admin confirms the code. The person alone cannot link a group they do not administer |
| `bot_policy` entry | listed, with the `homepage` convention (§3.1) | not listed: the person is not a bot, and an entry would mark their own account as one |
| Copies on MIMI | sent by the bridge user, with the prefix and `mimid-on-behalf-of` (§3.2) | sent by the person, with the same prefix and `mimid-on-behalf-of` |
| Loop rule on MIMI (§6.4) | skip messages sent by the bridge user | skip messages that carry `mimid-on-behalf-of`; the person's own messages, which carry none, are copied to Marmot like anyone's |
| The person's own clients | n/a | show copies as "Bob (via bridge)" from the stored entry (P3). The store refuses an edit or retraction of a copy from any front end but the bridge, so the person cannot change a White Noise member's words by accident |
| Link notice (§4.4) | the common text | the common text plus the personal sentence below |
| Unlink | an admin of either side, or the operator | also the person, alone, at any time |

The personal-mode notice adds, on both sides:

> This bridge is run by alice@a.example in her own chat client. On
> the MIMI side, messages from the White Noise group appear under her
> name, marked "(via bridge)". She did not write them.

and on the Marmot side the bridge account's profile name is "alice's
bridge", so White Noise users see whose it is.

Two personal bridges by different members on one pair are two
bridges: §6.4 applies, and the on-behalf-of rule keeps the MIMI side
from looping.

## 3. Relay mode

### 3.1 One identity per side

- **MIMI side:** one user, for example `mimi://a.example/u/marmot-bridge`
  (INVENTED), or the person's own account in personal mode. Every
  Marmot user's message arrives in the MIMI room as a message from that
  user.
- **Marmot side:** one npub. Every MIMI user's message arrives in the
  Marmot group as a message from it.

**Room policy.** room-policy-04 §6.7 has `bot_policy`, a list of
`allowed_bots`, each with `bot_role_index` naming the role it acts in.
A dedicated bridge fits it: `local_client_bot` false, `bot_role_index`
> 0, `can_target_message_in_group` false, `per_user_content` false.
The role needs `canSendMessage`, `canEditOwnMessage`,
`canDeleteOwnMessage`, `canReactToMessage`, `canDeleteOwnReaction`, and
nothing that changes membership or policy. (Puppet mode adds
`canAddParticipant` to the relay identity's role if the room wants the
bridge to invite puppets itself; §3.3.4.) Two gaps:

- The `Bot` struct has `name`, `description` and `homepage` ("merely
  descriptive", §6.7), and no field naming the participant that is the
  bot. Nothing ties an `allowed_bots` entry to the bridge's user URI.
  **Decision 5:** mimid puts the bot's user URI in `homepage` (a
  `Uri`). mimid writes the bridge's MIMI user URI there, and reads an
  entry whose `homepage` has the `mimi` scheme and a `/u/` path as
  naming the participant that is the bot; any other `homepage` is only
  a homepage. This is a mimid convention, INVENTED, and other
  implementations will not read it that way. A room-policy issue
  proposing a real field is drafted, not posted; it says mimid uses
  `homepage` until then. When the WG adds a field, mimid writes both
  for one release and then only the field.
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
  mimi-content-10 §4.3 and §8.2.1 keep text keys for private use, so
  this needs no registration. The prefix is for every client; the
  entry is for mimid's own front ends and for loop prevention (§6).
  mimid's front ends MAY show the entry, but only as "Bob (via
  marmot-bridge)", never as a sender in its own right: AGENTS.md says
  the sender is always the authenticated MLS sender, and here that is
  the bridge (or, in personal mode, the person running it).

  **Decision 6:** ask the WG now, not after the bridge has been used.
  A mimi-content issue proposing an `onBehalfOf` field (or a
  registered extension key) is drafted alongside the bot-field issue,
  and waits for Mark's OK. mimid keeps the private
  `mimid-on-behalf-of` key until a registered `onBehalfOf` exists.
  Then it sends the registered key, keeps reading both for one release,
  and drops the private key. The proposed rule is the one in N7:
  receivers MAY show it and MUST NOT treat it as authenticated. Since
  the WG may choose another shape (a field in the message rather than
  an extension key), the entry's value stays a map that can carry
  `uri`, `name` and `src` whatever the outer shape becomes.

### 3.3 Puppet mode, on a multi-user host (decision 12)

In puppet mode each remote person gets an identity of their own on the
other side: one MIMI user per Marmot person, and one Nostr key per
MIMI person. The design is fixed now, so relay mode is built with the
seams it needs (§2.1, the speaker resolver; §6.1, the `speaker`
column). It is built after relay mode has been used, on a multi-user
host in mimid that the gateways of client-survey.md §8 reuse.

| | Relay mode | Puppet mode |
|---|---|---|
| What members see | one bridge member, names in the text | a member per remote person who opted in; relay mode for the rest |
| Honesty | plain: the bridge holds the plaintext and says so | each puppet is marked in its name and domain (§3.3.2), but looks more like a person who is there; the bridge still holds all plaintext |
| Marmot adds | one admin add, once | an admin add per MIMI puppet (wn-agent has no batch add), by an admin or by the bridge if the admins made it one (§3.3.4) |
| MIMI adds | one invite | one per Marmot puppet, through room policy and consent |
| Keys | two | one Nostr key and one MIMI account per puppet, each with KeyPackages to keep fresh |
| wn-agent | one account | many accounts in one wn-agent (`account_create`, `account_list`) |
| Reactions, edits | the bridge's own, with the ref-counting of §5 | per person, exact |
| Mentions | text, or an npub when NIP-05 maps it (§7.1) | the puppet's own npub or MIMI URI, so they notify |
| Room size | +1 each side | +N each side |

#### 3.3.1 Shape

```text
 mimid-server for the puppet domain (nostr.a.example)       Nostr relays
    |  JMAP / live stream, one account per virtual user          |
 mimid-host (one process)                                        |
    relay identity  mimi://a.example/u/marmot-bridge  ── Store, bridge
    MIMI puppets    mimi://nostr.a.example/u/npub1…  ── send-only agents
       |                                                         |
       |  marmot.agent-control.v2                                |
       └─────────────────────────►  wn-agent  ───────────────────┘
                                    accounts: the relay key, and one
                                    puppet key per MIMI person
```

- The **relay identity** is the relay-mode bridge, unchanged: it reads
  the MIMI room through its Store, holds the link records, the id map
  and the queues, answers commands and posts notices. It stays in every
  linked room and group, and carries the words of everyone who has not
  opted in to a puppet.
- **MIMI puppets** are virtual users on a puppet domain: one per
  Marmot person who opted in (§3.3.4). Each is an agent-core `Agent`
  that keeps its MLS state current and sends; none has a Store or front
  ends, and none keeps plaintext: application messages it decrypts are
  dropped once acknowledged, since the relay identity already has them.
- **Nostr puppets** are accounts in the same wn-agent: one per MIMI
  person who opted in. The bridge subscribes to the relay account's
  stream only; puppet accounts are used to send.

#### 3.3.2 Identity binding

- **A Marmot person to MIMI.** npub `P` gets
  `mimi://nostr.a.example/u/<P as npub1… bech32>` (INVENTED form),
  on a domain the operator runs for puppets only. A separate domain
  means a puppet never collides with a real user of `a.example`, and
  any MIMI client can see from the domain that the member is a bridged
  one. Its display name is "<kind 0 name> (via bridge)". Every message
  it sends carries `mimid-on-behalf-of` with `uri` = `nostr:<P>`, so
  mimid front ends mark it "(via bridge)" too (§3.2).
- **A MIMI person to Nostr.** `mimi://a.example/u/alice` gets a Nostr
  account made with `account_create`, label
  `mimid-puppet:<first 16 hex of SHA-256 of the MIMI URI>` (INVENTED),
  and a profile from `account_publish_profile`: name
  "alice@a.example (via bridge)", `about` "Messages from
  mimi://a.example/u/alice, copied into this group by <operator>'s
  bridge. Not end-to-end encrypted past the bridge." (INVENTED text),
  and `nip05` only when §7.2's opt-in applies.
- **One puppet per person per host**, reused for every link the host
  serves, so a person has one identity on the other side, not one per
  room.
- **The binding table** in the host's database (INVENTED layout):
  `person` (MIMI URI or npub hex), `side` (`mimi` or `nostr`, the side
  the puppet lives on), `puppet` (the npub hex or MIMI URI),
  `state` (`creating`, `active`, `retiring`, `retired`), `consent_at`,
  `consent_where` (the room or group and the message id of the
  opt-in), `last_used`. A binding is never moved to another person; a
  retired puppet is never reused.

#### 3.3.3 Keys

- **Nostr puppet keys** live only in wn-agent, as the relay key does.
  `account_create` has no idempotency key, so the host writes the
  binding as `creating` with its label first, then calls; after a
  crash it lists accounts and adopts the one with that label, or calls
  again if there is none.
- **MIMI puppet keys** live in each puppet's own state directory under
  the host's (mode 0700), one `mimid.sqlite` each, as agent-core
  already lays them out. agent-core is not changed for this.
- **Accounts on the puppet domain** are made through mimid-server's
  local control listener (`POST /local/v1/users`,
  `POST /local/v1/users/{user}/tokens`), which exists today. The host
  runs beside the puppet domain's server and reaches the listener on
  loopback with `local_token`. Retiring needs a new route,
  `DELETE /local/v1/users/{user}`, which removes the account and its
  tokens.
- **Retirement.** A puppet unused for 90 days (INVENTED) is retired:
  it leaves its rooms or groups, a Nostr puppet's profile is updated to
  say it is retired, and a MIMI puppet's account is deleted. wn-agent
  has no request to remove an account, so a retired Nostr key stays in
  wn-agent's home, unused, until the operator removes it by hand; the
  operator guide says how. Nostr keys cannot rotate: a puppet key that
  leaks is retired and the person gets a new puppet on their next
  opt-in.
- **Never a person's own key**, in either direction (decision 1): a
  puppet speaks for a person with a key the bridge made and the person
  never held.

#### 3.3.4 Consent

Puppet mode is off for every link until both sides turn it on, and
off for every person until they ask for it.

1. **Per link.** In the MIMI room, a participant with the linking
   capability (decision 3) sends `!bridge puppets on`; a Marmot admin
   confirms with the code the bridge answers, as for linking (§4.2).
   Either side can turn it off alone with `!bridge puppets off`; the
   puppets of that pair leave, and everyone falls back to relay mode.
2. **Per person.** A person opts in with `!bridge puppet me` (INVENTED)
   in a linked room or group, and out with `!bridge puppet off`. The
   bridge knows who asked: on MIMI the authenticated sender, on Marmot
   the sender's account in the `inbound_message`. Until a person opts
   in, their words go through the relay identity with the prefix of
   §3.2. A person who never uses the other network is not given an
   identity there by someone else's choice.
3. **Admission on MIMI.** If the relay identity's role has
   `canAddParticipant`, the bridge invites the person's MIMI puppet
   itself. If not, it posts "please add <puppet URI> for Bob" in the
   room and waits for an admin. Either way MIMI consent applies as for
   any user (protocol-07 §5.7); the host accepts a puppet's invite only
   to a room linked with puppets on.
4. **Admission on Marmot.** A Marmot admin adds each MIMI puppet's
   npub. By default the bridge posts "please add <npub> for
   alice@a.example" in the group. If the group's admins have promoted
   the relay account (`group_admin` `promote`), the bridge adds puppets
   itself and uses those rights for nothing else: no removals but its
   own puppets', no renames, no changes to retention. Marmot cannot
   enforce that limit, so the notice says so.
5. **Removal.** A puppet removed from a room or group is not added
   again without a new opt-in; its person falls back to relay mode in
   that pair.
6. **The link notice** (§4.4) gains a sentence while puppets are on:
   "People who asked for it appear on the other side as their own
   member, named '(via bridge)'. Their messages are still copied by
   the bridge, which can read everything." For the Marmot side, when
   the bridge is a Marmot admin: "The bridge is a group admin so it can
   add these members. It uses that only to add and remove its own
   members."

#### 3.3.5 Mapping in puppet mode

§5's table holds, with the speaker resolver picking the sender:

- Text, edits, deletes: sent by the speaker's puppet if it is active in
  that room or group, otherwise by the relay identity with the prefix.
  A puppet's text carries no prefix: its name says who it is. An edit
  or delete goes from whichever identity sent the copy (the id map's
  `speaker`), since both sides honour edits only from the author.
- Reactions: per person, exact; the ref-counting of §5 is used only for
  relay-mode reactors.
- Mentions: a mention of a person with an active puppet maps to the
  puppet (`nostr:npub1…` on Marmot, a MIMI URI link on MIMI), so it
  notifies.
- Joins and leaves: a puppet's own membership is not announced twice;
  the bridge's notices name it once.
- Loops (§6.4): the bridge skips any MIMI message sent by a user on the
  puppet domain or by the relay identity, and any Marmot event from an
  account in its own wn-agent.

#### 3.3.6 The multi-user host

A new crate, `mimid-host` (INVENTED name), and a binary mode of
mimid-agent or its own binary (decided in its bead). It is the piece
client-survey.md §8 calls "a multi-user host". It is designed once,
here, and shaped so the XMPP gateway of client-survey.md §4 and §8
reuses it without change; it is built only after relay mode works
(Mark, 2026-11-21, on the client survey).

- **Many agents in one process.** One agent-core `Agent` per virtual
  user, each with its own state directory, sharing the tokio runtime,
  one HTTP client pool, one KeyPackage refresh scheduler and one
  supervisor. One full agent with a Store for each identity that reads
  (the relay identity; a gateway's own bot); send-only agents for
  puppets.
- **Connections.** At first each virtual user keeps its own
  EventSource or live stream to the puppet domain's server, with a cap
  of 500 virtual users per host (INVENTED). A multiplexed stream for
  many users on one connection needs a server change and a new
  binding, and is later work with its own design and Mark's OK.
- **Provisioning and retirement** as in §3.3.3, through the local
  control listener.
- **A remote-network adapter** (INVENTED trait name `RemoteNetwork`):
  map a remote id to a display name and a puppet URI; deliver an event
  to the remote side as a given identity; a stream of inbound events;
  ask a remote person for consent; add or remove a remote member. The
  Marmot bridge over wn-agent is the first adapter. The gateways of
  client-survey.md reuse the host unchanged and bring their own
  adapter: an XMPP component behind Prosody (§4 there; consent is a
  presence subscription or a MUC invite), a Matrix appservice (§3;
  consent is a Matrix invite), per-user IRC connections (§2). Each
  gateway has the same marking problem (§7.3), which the `onBehalfOf`
  issue (§3.2) and the puppet domain address only in part.
- **What the XMPP gateway needs from it, checked against the design.**
  The component (client-survey.md §4) has the same parts as Marmot
  puppet mode, in larger numbers: one virtual MIMI user per XMPP JID
  that takes part (`mimi://<gateway>/u/<escaped jid>`), one JID per MIMI
  user on the component, MIMI rooms as MUCs. So the host's interfaces
  are fixed with XMPP in mind, not only Marmot:
  - virtual users are keyed by an opaque remote id (an npub, a JID),
    with the escaping to a MIMI user part done by the adapter;
  - a virtual user may be in many rooms, and a room may hold many
    virtual users of one adapter (an XMPP MUC brings dozens at once);
    the 500-user cap is per host, not per room;
  - consent is asked by the adapter and answered asynchronously (an
    XMPP presence subscription can take days), so the host keeps a
    pending-consent state per virtual user and room;
  - the host owns the relay identity per adapter, so an XMPP gateway can
    also run in relay mode for people who do not opt in;
  - the binding table, retirement and the `DELETE` route are the same
    for every adapter.
  Matrix (client-survey.md §3) fits the same interfaces, with the
  appservice's ghost users as the remote side.
- **What the host does not do:** speak any remote protocol itself, or
  run front ends for people. A person's own agent stays a separate
  mimid-agent.

#### 3.3.7 Order of work

1. Relay mode in mimid-agent, steps 1 to 12 of §9, including personal
   bridges and NIP-05 on the server. Used in real rooms before step 13.
2. The multi-user host (step 13), designed once in §3.3.6 for both
   Marmot puppets and the XMPP gateway, and built only after relay mode
   works, with the relay bridge moved onto it as the host's first full
   identity. A dedicated bridge then runs
   either as a mimid-agent front end or on the host; personal bridges
   stay in the person's agent.
3. Puppet identities and keys (step 14), then puppet consent and
   mapping (step 15), then docs and a manual round trip (step 16).
4. Gateways from client-survey.md, each its own design, on the same
   host.

## 4. Linking and consent

### 4.1 Getting the bridge into both rooms

- **MIMI:** a member whose role has `canAddParticipant` invites the
  bridge user. The bridge's agent joins by its `invites` setting:
  `from-allowed` with the users the operator allowed (`/msg mimid allow
  <user>` over the IRC front end), or `any`. Joining a room does not
  link it. (In personal mode the person is already in the room.)
- **Marmot:** a Marmot admin adds the bridge's npub. wn-agent accepts by
  its invite policy: `allowlist` with that admin's npub, or
  `any-authenticated`. The operator manages it through the control API
  (`allowlist_add`, `invite_policy_set`), which the bridge exposes as
  service commands (§4.2). Joining a group does not link it either.

Being in both is not consent to copy one into the other.

### 4.2 Linking

A link is made only when an admin of each side has asked for it.

1. **MIMI side asks.** In the MIMI room, a member sends `!bridge link`
   (INVENTED). The bridge accepts it only from a participant whose role
   has `canChangeOtherPolicyAttribute` (room-policy-04 §8; the
   capability that would edit `bot_policy`; decision 3). In personal
   mode only from the person running the bridge (§2.5). The bridge
   answers in the room with a one-time code: 8 characters of base32,
   valid for 10 minutes (INVENTED VALUES).
2. **Marmot side confirms.** In the Marmot group, someone sends
   `!bridge link <code> [retention]`. The bridge checks with
   `group_admin` (no flags) that the sender's account is an admin of
   that group, and that the code is live and unused. `retention` is the
   group's disappearing-message time in seconds, if it has one
   (decision 4; §5).
3. **The link exists** when both are done: the store keeps a link
   record (room key, group id, who asked on each side, when, the
   retention, the mode). The bridge posts the notice of §4.4 on both
   sides, then starts copying. Nothing sent before the link is copied.

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
the linking capability or from a Marmot admin; the operator's command
(in personal mode, the person); the bridge being removed from either
side, or the room or group disbanded; the bridge's MIMI role losing
`canSendMessage`. The bridge posts a notice on whatever side it can
still reach, stops copying, drops held messages for that link, keeps
the id map for 30 days (INVENTED) so late edits and deletes of copied
messages still reach the copies, and then drops it. It does not leave
either side by itself; an admin removes it if they want.

### 4.4 What members are told

On link, on each side, from the bridge, and again to anyone who joins
later (as a notice in their first sync after joining, on MIMI; on
Marmot, as a message after each `member_added` change, since wn-agent
does not say who joined):

> This room is bridged to a White Noise (Marmot) group by
> marmot-bridge, run by <operator>. Messages are decrypted by the
> bridge and encrypted again for the other side, so the bridge and
> whoever runs it can read everything said here. Names shown as "(via
> bridge)" are the bridge's claim, not proven by the other side. The
> White Noise group has <n> members; the bridge cannot see who they
> are. Messages from White Noise arrive here about <hold_secs> seconds
> late. Unlink with `!bridge unlink`.

On the Marmot side the same text with the sides swapped, listing the
MIMI participants' URIs, which the bridge can see, and without the
delay sentence (MIMI to Marmot is not held).

**Decision 10:** MIMI members can see only how many people are on the
Marmot side (wn-agent's `member_count`), and the notice says so in
those words. The bridge links anyway; it does not wait for wn-agent to
list members.

Personal mode adds the sentence of §2.5; puppet mode the sentences of
§3.3.4.

**The security consequence, stated plainly.** Once linked, the
end-to-end encryption of both rooms ends at the bridge's host: the
bridge's mimid-agent holds every message in plaintext in its store and
blob directory, and wn-agent holds the Marmot side's plaintext and
keys, so the operator, anyone who controls that machine, and any
process that can use wn-agent's socket or token can read both rooms
and can post in either one under any name in the "(via bridge)"
prefix. With a personal bridge that machine is the person's own, and
they can post in the MIMI room under their own name text that seems to
come from a White Noise member. MIMI members also cannot see who the
Marmot members are, only how many. Members of each room should treat
the bridge's host as one more device that reads all their messages.

## 5. Message mapping

"M→N" is MIMI to Marmot (Nostr side), "N→M" the reverse. "Bridge
copy" means the message the bridge sent; the id map (§6) links it to
its source. Every N→M event passes the hold of §6.3 before it is
copied.

| What | M→N | N→M | Dropped or changed, and how it shows |
|---|---|---|---|
| Text | `send_final`, prefix of §3.2, idempotency key from the store record (§6). `text/markdown` passes as is; Marmot renders markdown (dialect not compared with GFM-MIMI) | `inbound_message` → held → `Store::send_with` with prefix and `mimid-on-behalf-of` | Body over `MAX_TEXT_LEN` (16 KiB, crates/mimid-agent-core/src/agent.rs) after the prefix: cut, ending `[…cut by bridge]` |
| Edit | `Change::MessageChanged` with a new version → `edit_message` on the bridge copy, text with prefix | `message_edited` → held → `Store::edit` of the bridge copy; if the source is still held, the held text is replaced instead | Edits of messages from before the link: dropped. Marmot honours edits only from the author, and the bridge is the author of its copies, so this works both ways |
| Delete, retraction | retraction → `delete_message` of the bridge copy | `message_deleted` (author or admin removal) → `Store::retract` of the bridge copy; if the source is still held, it is dropped and never shown | None |
| Reaction | mimid stores no reactions today (prerequisite P2). Then: `send_reaction` on the mapped target. The bridge reacts once per emoji per target and keeps a count; the reaction is removed (`remove_reaction` with that emoji) when the last MIMI reactor of that emoji unreacts | `reaction_added` → held → a MIMI reaction (disposition `reaction`, `inReplyTo` the bridge copy or the MIMI original) from the bridge, with `mimid-on-behalf-of`; `reaction_removed` → retract that one | M→N loses who reacted; Marmot members see the bridge's single reaction. N→M keeps one reaction per person. Puppet mode: per person both ways (§3.3.5) |
| Reply | `inReplyTo` resolved to a store key → `reply_to_message_id_hex` of the mapped Marmot id | `reply_to` → `inReplyTo` of the mapped MIMI message | Target not in the map (before the link, or expired): sent as a plain message, with `↪ <first 80 chars of the quoted text>` on the first line (INVENTED) when wn-agent gave an excerpt. mimid cannot send `inReplyTo` today (prerequisite P1) |
| Mention | markdown link to `mimi://d/u/x` → `nostr:npub1…` when §7.1 maps that user to a key, else `@x@d` as text | `nostr:npub1…` or an npub in text → markdown link `[@name](mimi://…)` only when §7.1 maps the key back; else the npub as text | wn-agent turns npubs in sent text into `p` tags, so a mapped mention notifies the White Noise user |
| Attachments | blob from the store → copy into `media_dir` (mode 0600) → `send_media` with the caption, key `<store key>:media` → remove the copy after the answer | media refs → held → `download_media` → plaintext temp file → into the store's blob store → `Store::send_with` with the files; mimid encrypts and uploads to its provider | Re-encrypted on each side; no file key crosses (`features/encrypted-media.md`). Over the receiving side's limits (wn-agent: 10 files, 512 MiB each; the bridge agent's `blob_quota_bytes`): text sent, with `[attachment not bridged: <name>, <size>]`. The download starts at release, not on arrival, so a withdrawn message's media is never fetched |
| Calls to join (`session` parts) | URL as text, `Call: <url>` | n/a | Not a call on the Marmot side, just a link |
| Absolute expiry (`expires`, `relative` false) | sent, then the bridge deletes its copy with `delete_message` at the expiry time (a scheduled row in the store, kept across restarts like §7.23 of agent-frontends.md) | see "Disappearing" below | Best effort: deletion hides the copy in clients that honour kind 5, and the encrypted event stays on relays until the group's retention, if any. Said once per room in a notice when the first such message is bridged (decision 4) |
| Read rule (`expires`, `relative` true: burn on read, delete after read) | **not bridged** (decision 4). The sender's side gets a notice: "not sent to the White Noise side: it cannot honour burn-on-read" | n/a | The bridge "reads" everything at once, so the rule would fire on its own copy and protect nothing on the other side |
| Disappearing (Marmot group retention) | n/a | wn-agent does not expose the value (§0). The link takes a retention in seconds from the Marmot admin's `!bridge link <code> [retention]` (INVENTED; decision 4), and each N→M copy gets `expires` = `recorded_at` + that, so the hold does not lengthen a message's life | On `disappearing_timer_changed`, the bridge posts a notice on MIMI asking a Marmot admin to restate it with `!bridge retention <secs>`, and stops adding `expires` until they do (INVENTED behaviour) |
| Read receipts | none | none | Neither side carries them through the bridge. mimid's read positions are local; Marmot has no read receipts in its spec |
| Joins, leaves, role changes | `Change::RoomChanged` membership → a message from the bridge, `bob@b.example joined the MIMI room` | `group_state_changed` `member_added` / `member_removed` / `member_left` / `admin_*` → a store notice, "a member joined the White Noise group (now n members)" | N→M has no names: wn-agent does not give them (decision 10) |
| Room name, subject | a message from the bridge, `room renamed to "x"` | `group_renamed` (with the name) → a store notice | Not applied to the other side: the bridge would need to be a Marmot admin, or `canChangeRoomName` on MIMI. Never, even when puppet mode makes the bridge a Marmot admin (§3.3.4) |
| Topics (`topicId`) | dropped | n/a | |
| Polls, reports, kind 4891 removals, unknown kinds | n/a | not delivered by wn-agent | Silent. Reports stay on their side by design |
| Abuse reports, franks | not bridged | not bridged | A MIMI report about a bridge copy names the bridge (or, in personal mode, the person) as sender; its `mimid-on-behalf-of` says whom it was relayed for |

**Prerequisites in mimid** found while mapping, each its own bead
before the bridge:

- **P1:** `Agent::send_message` takes no `inReplyTo`
  (agent-frontends.md §4, "Sending"); add it and a `Store` method.
- **P2:** reactions are not an action and not modelled
  (crates/mimid-agent-store/src/action.rs, "Limitations"); add
  receive, send and unreact.
- **P3:** the store does not keep a received message's mimiExtensions;
  keep the `mimid-on-behalf-of` entry (needed for §6 loop checks, for
  personal mode's copy protection, and for front ends that show it).

## 6. Loop prevention and idempotency

### 6.1 The id map

A table in `mimid.sqlite`, owned by the bridge crate (INVENTED
layout). M→N rows are written by the bridge's `before_save`, in the
store's save; N→M rows by the bridge in its own transaction (§6.3).

| Column | Meaning |
|---|---|
| `link` | link key |
| `direction` | `m2n` or `n2m` |
| `store_key` | the store message on the MIMI side (source or copy); empty while an N→M row is held |
| `version` | for M→N, which version of the store message was last sent (0 = first, then each edit) |
| `marmot_id` | the Marmot event id on the other side (source or copy); unique per link and direction |
| `speaker` | the identity that sent the copy: `relay`, or a puppet's npub or MIMI URI (§3.3) |
| `state` | M→N: `queued`, `sent`, `failed`. N→M: `held`, `releasing`, `sent`, `dropped`, `failed` |
| `idem_key` | for M→N, the `send_final` / `send_media` key: `<link>:<store_key>:<version>` |
| `event` | for a held N→M row, the event as wn-agent sent it (JSON, at most one 1 MiB frame); cleared once the row leaves `held` |
| `hold_until` | for N→M, when the row may be released (Unix milliseconds) |
| `recheck_until` | for N→M, until when the copy is checked for withdrawal (§6.5) |
| `expires_at` | scheduled delete, for §5's absolute expiry |

Reactions get rows of the same form, with the reaction's ids and the
emoji count for M→N. The stream cursor per link,
`(recorded_at, message_id_hex)` of the last event taken, is kept in a
second small table.

### 6.2 MIMI to Marmot

Not held: a MIMI message is final once the hub accepts it.

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

### 6.3 Marmot to MIMI, through the hold queue (decision 7)

Every N→M event waits `hold_secs` before it is copied. **Default 6 s
(INVENTED).** Why 6: a Commit opens a Marmot convergence pass that
closes after at most 5 s (1 s with no new input, or 5 s in all;
`protocol-core/convergence.md`). A message that a race decided in that
pass is withdrawn by the time it closes, and 1 s more covers wn-agent
writing the result to its timeline and the bridge's own scheduling. A
shorter hold would miss withdrawals from passes that run to their 5 s
limit, which are the contested ones; a longer one adds delay to every
message for withdrawals the hold cannot catch anyway (a rival Commit
that reaches wn-agent late opens a later pass, which can still roll
back up to 5 Commits). The range is 0 to 30 s; 0 turns the hold off
and leaves only the recheck of §6.5. MIMI to Marmot is not held.

1. **Take.** An event arrives on the stream (or from `timeline_list`
   after a gap). If its `marmot_id` is already in the map for this
   link, it is skipped. If the sender is the bridge's own account, or
   another account in its wn-agent, or in `peer_bridges`, it is
   skipped. Otherwise the bridge writes a `held` row with the event and
   `hold_until` = now + `hold_secs`, and advances the link's cursor, in
   one transaction on the agent's database (the store's connection; a
   small `Store` hook for a front end's own transaction if none fits,
   part of step 6). A crash before that transaction commits loses
   nothing: the cursor did not move, so `timeline_list` brings the
   event back. A crash after it leaves the row held.
2. **Fold.** An edit of a message still held replaces the held text;
   a delete of a message still held turns both rows `dropped`; a
   reaction removal whose reaction is still held drops both. Nothing
   reaches MIMI for them.
3. **Release.** Rows are released in arrival order per link, each when
   its `hold_until` has passed. The bridge first reads the source with
   `timeline_message_get`:
   - `available`: the row becomes `releasing` (its own transaction),
     then the bridge calls `Store::send_with` (or edit, retract, react)
     and, through the save that follows, marks it `sent` with the store
     key and clears `event`.
   - `invalidated` or `deleted`: the row becomes `dropped`, logged at
     INFO with the link and the Marmot id. MIMI members never saw it,
     so there is no notice.
   - wn-agent unreachable: the row stays `held` and waits. The bridge
     never copies an event it could not check.
   Reactions and edits are checked through their target message; a
   withdrawn reaction on a message that stays `available` is not
   visible through the timeline (§11), so it is copied.
4. **After a crash.** On start, `held` rows whose time has passed are
   released as above. A `releasing` row may or may not have reached the
   agent's outbox: the bridge waits until the outbox is empty and one
   sync has run, then looks for a stored message whose
   `mimid-on-behalf-of` `src` is the row's Marmot id. Found: the row is
   `sent` with that key. Not found: it is released again. The outbox
   sends a message again with the same bytes and never encrypts it
   twice (agent-frontends.md §3 step 10), and the delivered copy comes
   back in the sync, so after both the answer is certain. This also
   closes the gap the first version of this note left between the
   outbox's transaction and the store's save. It needs P3.
5. **Clocks.** `hold_until` is wall-clock time, so it survives a
   restart. A row whose `hold_until` is more than `hold_secs` in the
   future (the clock went back) is reset to now + `hold_secs`.
6. **Order.** All rows of a link wait the same time, so arrival order
   is kept. Rows from `timeline_list` that are already older than
   `hold_secs` by `recorded_at` are released at once after the check.

### 6.4 Loops

- The bridge never copies a Marmot event from its own account or any
  other account in its wn-agent (puppets).
- **Dedicated mode:** it never copies a MIMI message whose sender is the
  bridge user, or, with puppets, a user on the puppet domain.
- **Personal mode:** the bridge user is a person who also speaks, so the
  sender cannot be the rule. It never copies a MIMI message that
  carries a `mimid-on-behalf-of` entry, and copies the person's other
  messages like anyone's.
- **Two bridges on one pair** would copy each other's copies. On MIMI,
  a message with a `mimid-on-behalf-of` entry is never copied again,
  in either mode. On Marmot there is no structured marker (no tags), so
  the bridge skips messages from npubs listed in `peer_bridges`, and
  on its own matches nothing by text: a text rule could be spoofed by
  any member. Stated as a limit: two bridges on one pair, not
  configured to know each other, loop on the Marmot side. The link rule
  of one group per room per bridge does not stop a second operator.

### 6.5 Convergence withdrawals after the copy

The hold (§6.3) catches withdrawals decided within `hold_secs`. A
later convergence pass can still withdraw a message that was already
copied (`protocol-core/convergence.md`, "invalidated, and their app
payloads are withdrawn"), and wn-agent does not push this; the
timeline shows `invalidated`. So the bridge still rechecks every
copied N→M source with `timeline_message_get` once a minute until its
`recheck_until`, one hour after the copy (INVENTED VALUES), and
retracts the MIMI copy of any that is now `invalidated`, with a notice
("a White Noise message was withdrawn by its group"). Decision 7: hold
and retract, both.

## 7. Identity: NIP-05

### 7.1 Lookups by the bridge

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
   remains the identity, as NIP-05 says. Since the bridge asks by name,
   it learns a key only for names it already has, the MIMI room's
   participants; it cannot list a domain.
3. **Inviting by name**, for the operator: `/msg mimid bridge invite
   <group> alice@a.example` resolves the key and asks wn-agent to add
   it, if the bridge is a Marmot admin of that group. Low value; maybe
   never.

Rules for the fetch: `https` only; no redirects followed (NIP-05
"MUST"); destination addresses in loopback, link-local, private and
other special ranges refused after resolution (the SSRF concern of N3);
a body cap of 64 KiB and a 5 s timeout; positive answers cached for an
hour and negative ones for 5 minutes (INVENTED VALUES); a key that
changes for a name is shown as changed, never silently swapped.

### 7.2 mimid-server serves `/.well-known/nostr.json` (decision 9)

Part of the bridge work, not after it. With it, 7.1 works for a mimid
provider's users without any other host.

**Switch.** A server setting, off by default (INVENTED name):

```toml
[nostr]
nip05 = true
```

Off, the route answers 404 like any unknown path.

**Who is listed.** Only users who registered a key. Nobody is listed
by default, and a user's MIMI account alone never puts them in the
file. The mapping is public once published: anyone can then tie
`alice@a.example` on MIMI to everything npub X has posted on Nostr.
Both the registration path and the operator path say so before they
publish.

**Registering a key.** Two paths, both INVENTED, NOT FROM SPEC:

- **The user, over JMAP.** A capability
  `tag:reviewcommit.com,2026:mimid:nostr` (named like mimid's
  `…:mimid:live`) with two methods on the user's own account:
  - `NostrIdentity/get`: the account's registration, or null:
    `{"name", "publicKey", "relays", "createdAt"}`.
  - `NostrIdentity/set`: `{"proof": <a signed Nostr event, JSON>,
    "relays": [<wss URL>, ...]}` to register or replace, or
    `{"destroy": true}` to remove. The proof borrows NIP-98's shape: a
    kind 27235 event signed by the key being registered, with a `u` tag
    exactly `https://<domain>/.well-known/nostr.json?name=<local>`, a
    `method` tag `PUT`, and `created_at` within 10 minutes of the
    server's clock (longer than NIP-98's suggested 60 s, because a
    person may sign on one device and paste on another). The server
    checks the event id and the BIP-340 signature, the kind, both tags,
    the time, and that `<local>` is the account's own user part. It
    keeps the event id of each proof used and refuses one seen before.
    This is not NIP-98 authentication: the request itself is
    authenticated by the JMAP bearer token, and the event only proves
    that the person holds the key they are publishing.
  The user's JMAP client talks to their agent, not to the server, so
  mimid-agent passes these two methods through: its JMAP front end
  forwards calls naming this capability to the provider unchanged, and
  its IRC front end has `/msg mimid nostr show`, `/msg mimid nostr set
  <proof>` and `/msg mimid nostr clear`.
- **The operator, over the local control listener.**
  `GET`, `PUT` and `DELETE /local/v1/users/{user}/nostr`, and
  `mimid admin <config> nostr <userUri>`, `nostr-set <userUri> <hex>
  [relay...]` and `nostr-clear <userUri>`. No proof: the operator
  vouches, as a provider already does for its users' MIMI identities.
  Each set and clear logs at INFO with the user and the key. The
  operator path is how a bridge host publishes a puppet's name (below).

**Contents.** `GET /.well-known/nostr.json?name=alice` answers 200
with:

```json
{"names": {"alice": "<64 lowercase hex>"},
 "relays": {"<64 lowercase hex>": ["wss://relay.example"]}}
```

`relays` only when the user gave some: at most 8 URLs (INVENTED),
`wss` only, each at most 256 bytes. Any name that is not registered,
not a local user, not lowercase `a-z0-9-_.` (NIP-05), or longer than 64
bytes, and a request with no `name`, all get the same 200 with
`{"names": {}}`: the file never lists all names, and a miss does not
say whether the account exists. `_` (NIP-05's root name) is not
served. Headers: `Content-Type: application/json`,
`Access-Control-Allow-Origin: *` (NIP-05's "Showcase" section), and
`Cache-Control: max-age=300` (INVENTED), so a cleared key is gone from
well-behaved caches within 5 minutes. The route never redirects: not
for a trailing slash, not to another host, not from HTTP to HTTPS
(that redirect, if any, belongs to whatever fronts the plain-HTTP
port, and NIP-05 fetchers ignore it). It shares the JMAP rate limiter
per client address.

**Puppet names.** A Nostr puppet (§3.3) may be published as
`<local>.bridge` (INVENTED), never as the bare `<local>`, which stays
the person's own key, and only when the person opted in to it with
`!bridge puppet me nip05` and the puppet host runs beside the person's
provider. The server refuses to create a user whose local part ends in
`.bridge`, so the two cannot collide.

**Storage.** A table in mimid-server's store: `user` (the account),
`name`, `public_key`, `relays`, `proof_event_id`, `created_at`;
`name` unique. Removed with the account.

**Tests** (all offline, in-process):

- a registered name answers its key and relays, byte for byte against
  a fixture; an unregistered user, an unknown name, a name with
  uppercase or other characters, an overlong name and no `name` all
  answer the same empty body;
- the CORS and cache headers are present; `/.well-known/nostr.json/`
  and other variants answer without a redirect;
- with `nip05` off, 404;
- proofs: a valid event registers; a wrong kind, `u`, `method`,
  `created_at` outside the window, a bad id, a bad signature, a key
  other than the signer, another user's name and a replayed event are
  each refused. The signed events are fixtures made by an independent
  implementation (a Nostr CLI or the BIP-340 reference code in Python)
  with a `PROVENANCE` file, decoded and checked, never signed by the
  code under test;
- a user's token cannot read or set another user's registration;
- `destroy` and the operator's clear remove the name from the next
  answer; deleting the account removes it;
- relay limits at and past 8 URLs and 256 bytes, non-`wss` URLs,
  bidi and zero-width characters, invalid UTF-8;
- the agent's pass-through forwards only this capability's two
  methods, and the IRC commands reach them;
- a log canary: the proof event and the bearer token never appear in
  `tracing` output.

### 7.3 No marker for a leaf held on someone else's behalf

A puppet's leaf, a gateway's virtual user and (in relay mode) the
bridge itself are all MLS members whose client is not run by the person
named. Nothing in MIMI says so. Checked on 2026-11-21:

- protocol-07 §7.5: a participant is a `UserRolePair` (`user`,
  `role_index`) and nothing else; the credential in the leaf names the
  user, and the protocol has no field for who runs the client.
- room-policy-04: `bot_policy` (§6.7) describes bots, but its entries
  name no participant (the gap of §3.1), and a puppet is not a bot.
  `LoggingPolicy` (§6.5) is the nearest precedent: a room-level list of
  `logging_clients` URIs that tells members which clients keep copies.
  Nothing similar exists for clients that relay to another network.
- mimi-arch-03 does not mention gateways or bridges.

`onBehalfOf` (§3.2) marks a message; it does not mark a member, so a
puppet that has not spoken yet, or a member list in a client, shows no
sign of it. The marker belongs in room state, not in content: most
likely room-policy (a list beside `logging_clients`, or a field on the
bot entry), possibly protocol-07's participant list. mimid's stopgap
is the puppet domain and the "(via bridge)" display name (§3.3.2).
Mark wants a WG question on it, paired with `onBehalfOf`: it is a
paragraph in the drafted mimi-content issue, which says it belongs in
room-policy and asks the WG where.

## 8. Failure modes

| Failure | What happens | What members see |
|---|---|---|
| wn-agent down or socket missing | M→N rows stay `queued`; N→M stops, and held rows are not released unchecked. Reconnect with backoff; on return, queued rows go out in order, held rows are checked and released, and `timeline_list` fills N→M | A delay. After 5 minutes down (INVENTED), one notice on the MIMI side: "the White Noise side is not reachable; messages will follow" |
| wn-agent answers `retryable: true` | retry with the same key | nothing |
| wn-agent answers a non-retryable error | row `failed`, logged with the code | on the sender's side: "not delivered to White Noise: <code>" (once per message) |
| Relays down | wn-agent's problem: it owns relay I/O and durable sends, and `final_sent` means it published the message (the guide: "does not prove a member received it"). What it answers with every relay down was not traced; a retryable error or a timeout leaves the row queued, and a later send reuses the key | delay on the Marmot side only |
| Marmot Commit races | withdrawals within `hold_secs` are dropped before anyone on MIMI sees them (§6.3); later ones are retracted (§6.5). `post_join_rotation_pending_retryable` after a join still means sent | normally nothing; a late withdrawal is retracted on MIMI with a notice |
| The bridge crashes with rows held | held and releasing rows are resolved on start (§6.3 step 4) | a longer delay, no duplicate |
| The clock jumps | `hold_until` is reset when it is too far ahead (§6.3 step 5) | at most `hold_secs` more delay |
| The bridge removed from the Marmot group | `group_state_changed` does not say who was removed; the next send fails, and `group_admin` (read) shows `is_member: false` | unlink (§4.3), notice on MIMI |
| MIMI hub refuses (room policy: the bridge's role lacks the capability; `wrongEpoch` handled by the agent; a size limit) | the agent returns the refusal; row `failed` | on the Marmot side: "not delivered to MIMI: <reason>", at most one per minute per link (INVENTED) |
| The bridge's MIMI agent cannot reach its server | the agent's outbox keeps the message; N→M copies wait | delay on MIMI |
| A personal bridge's owner goes offline | their agent stops, so the bridge stops; both queues wait | a delay until they are back; the link notice said whose bridge it is |
| A personal bridge's owner leaves the room or loses the linking capability | the link ends (§4.3) | an unlink notice |
| MLS version skew | none between the two sides: each MLS group is run by its own implementation (mimid's OpenMLS fork `f1680d9`; MDK's OpenMLS `6100df3`), in separate processes, and no MLS message crosses the bridge. Skew matters only within each side, as now | nothing |
| Marmot spec churn | the spec changes daily (`changes.md`). The bridge depends on the control protocol, not on the spec, and `v2` is declared stable. Pin: the bridge records the wn-agent release it was tested with and the marmot and mdk commits read (this note: `36757fe`, `ff5320a`); `account_list` failing to parse, or an unknown `marmot_agent_control` label, stops the bridge with an error. Tracking: a recurring bead to read mdk's CHANGELOG and marmot's `changes.md` at each wn-agent release and bump the pin | nothing, until the pin moves |
| wn-agent's stream lags | `resync_required`; fill from `timeline_list` | nothing |
| Two bridges on one pair | loops on the Marmot side unless configured (§6.4) | duplicates |
| A NIP-05 registration with a stale or reused proof | refused; nothing published | the user's client gets the error |
| A puppet's `account_create` interrupted | adopted by label on restart, or created again (§3.3.3) | nothing |
| The bridge's host compromised | both rooms readable, any "(via bridge)" name forgeable; with puppets, every puppet key with them | nothing; this is the §4.4 consequence |

## 9. Size and steps

Sizes compare with mimid-agent-irc, about 4,200 lines of Rust. Each
step is one bead under epic mimid-kiy1.

| Step | What | Rough size |
|---|---|---|
| 1 | P1: `inReplyTo` on send, in agent-core and the store; then JMAP `replyTo`, refused today, and IRC `+draft/reply`, dropped today | 300 to 500 lines, 1 to 2 commits |
| 2 | P2: reactions in the store: receive, send, unreact; JMAP and IRC rendering | 600 to 900 lines, 2 to 3 commits |
| 3 | P3: keep `mimid-on-behalf-of` on received messages; show it in JMAP and IRC as "(via …)" | 200 to 300 lines, 1 commit |
| 4 | Control-socket client: own serde types for the requests and events used (decision 8), framing, the stream with reconnect; a fake wn-agent for tests that replays JSON fixtures captured from agent-control's own serde output at the pinned commit, with `PROVENANCE` | 1,000 to 1,400 lines with tests, 2 commits |
| 5 | The crate and `[marmot]` config (both modes parsed, dedicated mode run); the speaker resolver seam (relay only); link records; in-room commands and codes; IRC service commands; notices; the `homepage` convention for the `bot_policy` entry (decision 5) | 900 to 1,300 lines, 2 to 3 commits |
| 6 | Text both ways: id map with `speaker`, the M→N queue, the N→M hold queue (§6.3) with folding, release checks and the releasing recovery, idempotency, crash tests at each failure point as in `tests/send_crash.rs` | 1,500 to 2,000 lines, 3 commits |
| 7 | Edits, deletes, replies, reactions, membership and rename notices; the withdrawal recheck (§6.5) | 700 to 1,000 lines, 2 commits |
| 8 | Attachments both ways; expiry (scheduled deletes, retention from the link, refused read rules) | 600 to 900 lines, 2 commits |
| 9 | mimid-server `/.well-known/nostr.json` (§7.2): the switch, the table, JMAP `NostrIdentity/get` and `/set` with proof checks, the local routes and `mimid admin` commands, the `.bridge` reservation, tests and fixtures | 900 to 1,300 lines with tests, 2 to 3 commits |
| 10 | NIP-05 in the bridge and the agent: lookups and mention mapping (§7.1); the agent's JMAP pass-through and IRC `nostr` commands for §7.2 | 600 to 900 lines, 2 commits |
| 11 | Personal mode (§2.5): run in a person's agent, the linking rules, the on-behalf-of loop rule, copy protection in the store, the personal notice and profile name | 400 to 600 lines, 1 to 2 commits |
| 12 | docs/agent.md `[marmot]`, server docs for `[nostr]`, an operator guide (dedicated and personal), AGENTS.md crate map; a manual round trip with a real wn-agent and a White Noise phone, both modes | 400 lines of docs, 1 to 2 commits |
| 13 | The multi-user host `mimid-host` (§3.3.6), designed once for Marmot puppets and the XMPP gateway of client-survey.md, started only after step 12's round trip: many agents in one process, send-only agents, shared pool and scheduler, the cap, the `RemoteNetwork` trait; the relay bridge running on it; `DELETE /local/v1/users/{user}` on mimid-server | 2,000 to 3,000 lines, 4 to 6 commits |
| 14 | Puppet identities and keys (§3.3.2, §3.3.3): the binding table, `account_create` with label recovery, profiles, puppet-domain accounts through the local listener, retirement | 1,000 to 1,500 lines, 2 to 3 commits |
| 15 | Puppet consent and mapping (§3.3.4, §3.3.5): the per-link switch, per-person opt-in, admission on both sides, the puppet resolver, per-person reactions and mentions, loop rules, notices, puppet NIP-05 names | 1,000 to 1,500 lines, 2 to 3 commits |
| 16 | Puppet mode docs and a manual round trip with a real wn-agent and a White Noise phone | 300 lines of docs, 1 commit |

Relay mode with personal bridges and NIP-05 (steps 1 to 12): about
8,000 to 11,500 lines with tests, 21 to 27 commits. The host and puppet
mode (steps 13 to 16): about 4,300 to 6,300 lines, 9 to 13 commits.
In all about 12,300 to 17,800 lines and 30 to 40 commits. Steps 1 to 3
are useful without the bridge and can go first; step 9 is independent
of the bridge crate and can run beside steps 4 to 8.

Tests stay offline (AGENTS.md): the fake wn-agent answers on a Unix
socket in a temp directory, and the host's tests run mimid-server in
process. The only live checks are steps 12 and 16, by hand.

## 10. Decisions (Mark, 2026-11-21)

Mark's answers to the twelve open questions of the first version. Where
the answer differs from what that version recommended, the body above
has been changed to match.

1. **Whose Nostr key.** The bridge's own key only; the config pins the
   account id. Applies in every mode, including personal bridges and
   puppets (§2.3, §2.5, §3.3.3). As recommended.
2. **Who starts wn-agent.** A separate service, installed with MDK's
   installer (§2.2). As recommended.
3. **Which MIMI capability may link a room.**
   `canChangeOtherPolicyAttribute` (§4.2); also used to turn puppets on
   (§3.3.4) and to define a personal bridge's "own rooms" (§2.5). As
   recommended.
4. **Expiring messages.** The bridge carries absolute expiry with a
   timed delete of its copy, refuses read rules with a notice, and takes
   the Marmot group's timer from the linking admin (§5). As recommended.
5. **The bot policy gap.** mimid uses `homepage` for the bot's user URI
   (§3.1), and a room-policy issue for a real field is drafted; it is
   posted only with Mark's OK. As recommended.
6. **On-behalf-of.** Ask the WG now: an `onBehalfOf` issue is drafted
   alongside the bot-field issue. mimid uses the private key
   `mimid-on-behalf-of` until a registered `onBehalfOf` exists (§3.2).
   *Differs:* the first version waited until the bridge had been used.
7. **Withdrawn Marmot messages.** Hold each Marmot message a few seconds
   before copying (6 s by default, INVENTED, justified in §6.3), and
   still retract a copy whose source is later invalidated (§6.5).
   *Differs:* the first version copied at once and only retracted. The
   hold queue changes the id map (§6.1), crash safety (§6.3 steps 1
   and 4), the notice (§4.4) and the failure table (§8).
8. **wn-agent's DTOs.** mimid's own serde types, tested against
   fixtures from `agent-control` with a `PROVENANCE` file (§9 step 4).
   As recommended.
9. **NIP-05 on mimid-server.** mimid-server serves
   `/.well-known/nostr.json` as part of the bridge work (§7.2, §9 step
   9). *Differs:* the first version put it after the bridge.
10. **Marmot member list.** Accept the member count only, and say so
    plainly in the link notice (§4.4). As recommended.
11. **Personal bridges.** Allowed: a person may run the bridge in their
    own agent, for their own rooms, with a clear notice (§2.5).
    *Differs:* the first version said no.
12. **Puppet mode.** Plan it now, designed into the bridge together
    with a multi-user host (§3.3, §9 steps 13 to 16). Relay mode is
    built first; puppet mode follows on the host. *Differs:* the first
    version left it out unless users asked.

Two related decisions Mark made the same day on client-survey.md apply
here: the multi-user host is designed once, in §3.3.6, shaped for the
XMPP gateway to reuse, and built after relay mode works (§3.3.7, §9
step 13); and the missing marker for a leaf held on someone else's
behalf (§7.3) goes to the WG as a question paired with `onBehalfOf`.

## 11. Uncertainties

- wn-agent's behaviour was read from code and docs, not run. Whether
  `final_sent` and `inbound_message` come before or after the
  convergence pass settles, and how often `invalidated` really happens,
  are not measured. If wn-agent delivers only settled messages, the
  hold of §6.3 catches less than its reasoning assumes and costs the
  same; the step 12 round trip should measure it, and `hold_secs` can
  then move.
- Whether a withdrawn reaction or edit shows in the timeline is not
  traced; §6.3 checks them through their target message only.
- Whether White Noise shows several identical reactions from one
  account, or only one, is not checked; §5 assumes one per emoji.
- Which `wn-agent-v*` release tag matches `ff5320a` is not checked; the
  workspace version there is `0.19.0-dev`.
- The markdown dialects of Marmot (`marmot-markdown`) and GFM-MIMI were
  not compared; text may render differently on each side.
- `display_name` in wn-agent's events comes from a profile it has
  cached; how stale it can be was not traced.
- Whether common Nostr signers (browser extensions, Amber, command-line
  tools) let a person sign an arbitrary kind 27235 event for §7.2's
  proof is not checked. If few do, the operator path is the fallback.
- How wn-agent behaves with hundreds of accounts (puppets) in one
  process, and whether accounts the bridge does not subscribe to still
  keep their MLS state current, is not traced. Step 14 must check it
  before relying on it.
- wn-agent has no request to remove an account at `ff5320a`; retired
  puppet keys stay on disk until removed by hand (§3.3.3).
- The sizes in §9 are estimates from the IRC front end's size, not from
  a prototype.
