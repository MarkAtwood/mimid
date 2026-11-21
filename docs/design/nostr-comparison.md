# Nostr's MLS messaging (Marmot, White Noise) and MIMI

Design note, 2026-11-21. Compares Marmot, the MLS-over-Nostr protocol
behind the White Noise app, with MIMI and with mimid, and lists what
mimid could do about it. Same style as air-api-comparison.md.

Sources read, with the version of each:

| Source | Version read |
|---|---|
| github.com/nostr-protocol/nips | `bec0fc89e756` (2026-11-16): NIP-01, 05, 09, 17, 29, 40, 44, 59, 65, C7, EE |
| github.com/marmot-protocol/marmot (the spec) | `36757fed3c50` (2026-11-21) |
| github.com/marmot-protocol/mdk (the Rust implementation) | `ff5320a8765d` (2026-11-21) |
| marmot-protocol/whitenoise-android, whitenoise-ios | READMEs only, at `3df7e4b4f671` and `1cf3ec2958f6` |
| draft-ietf-mimi-protocol | -07 |
| draft-ietf-mimi-content | -10 |
| draft-ietf-mimi-room-policy | -04 |
| draft-atwood-jmap-chat-mimi-00 | jmap-chat-spec `735503c` |
| agora-spec | `050fd35` (for option (c) only) |
| mimid | main at `e5c4396` |

Paths like `transports/nostr.md` are in the marmot repo at that
commit; `crates/...` under "MDK" are in the mdk repo; `NIP-xx` means
`xx.md` in the nips repo. Nothing here has gone to the Marmot authors,
to #mimi or to jmap-chat-spec. Proposed draft text needs Mark's OK, as
for the F- and A-findings.

A note on names. NIP-EE ("E2EE Messaging using MLS") is the first
public form of this work. It is now marked `final` `unrecommended` and
says at the top that it is "superseded by the Marmot Protocol". The
Marmot repo in turn calls its own older MIP-numbered documents "a
deprecated version of the protocol" (`README.md`). The current Marmot
text has no version number (`changes.md`: "The specification has no
version number"); it is a set of documents marked "Status: adopted",
with a change log from 2026-07-05. This note describes that current
text. Where NIP-EE differs in a way that matters, it says so.

## 1. Nostr and Marmot in brief

### 1.1 Nostr

- **Events** (NIP-01). Everything is a signed JSON event: `id` (SHA-256
  of the serialized `[0, pubkey, created_at, kind, tags, content]`),
  `pubkey` (32-byte x-only secp256k1 key, hex), `created_at` (sender's
  clock, seconds), `kind` (integer), `tags` (arrays of strings),
  `content` (string), `sig` (BIP-340 Schnorr). The kind range says how
  relays store it: regular (stored), replaceable (10000-19999: last per
  pubkey and kind), ephemeral (20000-29999: not stored), addressable
  (30000-39999: last per pubkey, kind and `d` tag).
- **Relays** (NIP-01). WebSocket servers. A client sends `EVENT` to
  publish (answer `OK`), `REQ` with filters (ids, authors, kinds, `#x`
  tag values, since/until, limit) to subscribe, and gets stored events
  then `EOSE`, then live ones. Relays do not talk to each other in the
  protocol; a client picks several and publishes to each.
- **Identity.** A user is a key pair. There is no account and no
  server that owns the name. `npub` is a bech32 display form.
- **Names** (NIP-05). A kind 0 profile may claim `alice@example.com`;
  a client checks it with `GET https://example.com/.well-known/nostr.json?name=alice`,
  which maps names to hex keys, optionally with relay hints. This is a
  label the domain vouches for, not an identity: the key is the
  identity, and the domain can change or drop the mapping.
- **Relay lists.** NIP-65 kind 10002 lists the relays a user writes to
  and reads from; NIP-17 kind 10050 lists the relays where the user
  wants direct messages (its inbox).
- **Encryption.** NIP-44 v2 is secp256k1 ECDH, HKDF, ChaCha20,
  HMAC-SHA256 and a padding scheme. NIP-59 gift wrap nests an unsigned
  "rumor" inside a "seal" (kind 13, signed by the sender, NIP-44
  encrypted to the recipient) inside a "gift wrap" (kind 1059, signed
  by a throwaway key, NIP-44 encrypted, with a `p` tag naming the
  recipient and a randomized `created_at`).

### 1.2 Marmot

Marmot fixes three things and leaves the rest open (`README.md`,
`principles.md`): identity is a Nostr key, application payloads are
unsigned Nostr-shaped events inside MLS, and MLS (RFC 9420) is the key
agreement. The transport is meant to be replaceable; today the only
binding is Nostr relays (`transports/nostr.md`; a QUIC binding for
streamed agent text was retired on 2026-11-21, `changes.md`).

**MLS profile** (`foundation/mls-protocol.md`, `protocol-core/group-setup.md`):

- Ciphersuite 1 (X25519, AES-128-GCM, SHA-256, Ed25519) required,
  others optional. The same suite mimid uses.
- `BasicCredential` whose identity is exactly the 32-byte Nostr public
  key (`foundation/identity.md`). The MLS signature key is a separate
  key per leaf.
- Every leaf carries the LeafNode component
  `marmot.member.account-identity-proof.v2` (0x8009): a BIP-340
  signature by the Nostr key over a local, never-published kind 450
  event naming the ciphersuite and the leaf's MLS signature key
  (`app-components/account-identity-proof-v2.md`). This binds the leaf
  to the account key, so a relay or other member cannot make a leaf for
  someone else's npub.
- Group state lives in `app_data_dictionary` components and changes by
  `AppDataUpdate`, from draft-ietf-mls-extensions. Marmot targets
  draft-10 code points (`app-components/README.md`); mimid targets
  -11. The code points both use agree: extension 0x0006, proposals
  0x0008 to 0x000a, components 0x0001, 0x0002, 0x0004
  (`foundation/registries.md`). I did not compare -10 and -11 for wire
  changes.
- Marmot's own components are in the private-use range 0x8001 to
  0x800f: profile, admin policy (0x8003, a list of admin npubs),
  Nostr routing (0x8004), retention, media, lifecycle (disband),
  account devices, device roster, device tag. None collides with
  mimid's 0xF013 and 0xF020, but both sides use the private range, so a
  collision is possible later.
- Handshake messages are `PublicMessage`, so that every member derives
  the same bytes and the same hash for a Commit. The transport must hide
  them from relays (`foundation/mls-protocol.md`, "Handshake wire
  format").
- Implementation: MDK, in Rust, on OpenMLS (git rev `6100df3` with
  `extensions-draft`, MDK `Cargo.toml`), with SQLCipher storage. White
  Noise for Android and iOS is now a thin native UI over MDK's UniFFI
  bindings ("MarmotKit"); the older Flutter app and `whitenoise-rs` are
  archived. MDK also ships `wn` (CLI and TUI), `wnd` (daemon) and
  `wn-agent`, a daemon that puts an AI agent or a bot into Marmot
  chats through a local JSON control socket
  (`integrations/custom-client.md`). MDK is MIT licensed.

**Event kinds on relays** (`transports/nostr.md`):

| Kind | What | Signed by | Relays see |
|---|---|---|---|
| 30443 | KeyPackage (addressable; one `d` slot per device) | the account key | the account, that it is reachable, roughly how many devices, optional client name, ciphersuite and capability ids |
| 5 | NIP-09 deletion of a KeyPackage slot | the account key | that a device stopped publishing |
| 1059 > 13 > 444 | Welcome: gift wrap, seal, unsigned rumor with the MLS Welcome, the `e` id of the KeyPackage used and the group's relays | throwaway key / inviter / none | that someone sent the account something, its size, and the time (randomized) |
| 445 | group message: Commit, Proposal or application message | a fresh key per event | the group's random `nostr_group_id` (`h` tag), size, time, and the retention policy if the group has one (NIP-40 `expiration` tag) |
| 1059 > 13 > 446 | push trigger to a notification server | throwaway keys | that the server got something |
| 1059 > 13 > 452-456 | pairing a new device, from an account to itself | account key in the seal | a burst of gift wraps to the account |
| 30078 | encrypted backup pointer (NIP-78) | the account key | an opaque event about once a day |
| 10002, 10050 | relay lists (standard) | the account key | where the account publishes and reads |

The kind 445 content is `base64(nonce || ChaCha20-Poly1305(k, MLSMessage))`
with `k = MLS-Exporter("marmot", "group-event", 32)` for the epoch and
an empty AAD. So relays see neither the MLS framing (epoch, sender
leaf, content type) nor the Commit, and a reader must try the key of
each epoch it keeps until one works ("Outer decryption and epoch
selection"). NIP-EE used NIP-44 with an exporter-derived key pair
instead; the current text uses the AEAD directly.

**Application payloads** (`foundation/application-messages.md`): an
unsigned Nostr event (`id`, `pubkey`, `created_at`, `kind`, `tags`,
`content`, no `sig`), JSON, inside an MLS application message. The
receiver drops it unless `pubkey` equals the account in the sender's
MLS credential. It is left unsigned on purpose, so a leaked copy cannot
be posted to a public relay as the author's. Kinds in use: 9 chat
(NIP-C7; replies by a `q` tag), 7 reaction (NIP-25), 5 own deletion
(NIP-09 shape), 1009 edit (`e` names the original; latest
`created_at` wins), 1210 group system row (made locally from
authenticated state, not sent), 1984 report and 1985 dismissal (seen
by all members), 4891 admin deletion, 1068/1018 polls (NIP-88),
447-449 push token gossip, 457-477 device-group traffic. Unknown kinds
are delivered, not rejected. Kind constants: MDK
`crates/traits/src/app_event.rs`.

**Routing and discovery.** Group traffic goes to the relay list in the
signed routing component (at most 16 relays, at least 2 advised;
`app-components/nostr-routing-v1.md`). Admins can rotate the
`nostr_group_id`, and doing it in a second Commit after a removal
keeps later traffic from the removed member. KeyPackages are fetched
from the invitee's NIP-65 write relays; Welcomes go to the invitee's
NIP-17 inbox relays. A user with no published relay lists cannot be
invited reliably.

**Media** (`features/encrypted-media.md`): files go to Blossom servers
encrypted with ChaCha20-Poly1305 under a key derived from
`MLS-Exporter("marmot", "encrypted-media", 32)` of the source epoch, the
file's hash, type and name. A client "MUST NOT send" a file key outside
its own account's devices.

**Authority** (`app-components/admin-policy-v1.md`,
`protocol-core/group-messaging.md`): admins are a list of npubs in
group state. Only an admin may add, remove others, or change any
component. A non-admin may only update its own leaf, SelfRemove, or
(in groups that allow it) add and remove its own devices. There is no
external commit. If every admin loses their keys, the group's settings
and membership are frozen for good; the members make a new group.

**Metadata exposed to relays**, in summary: the account behind every
KeyPackage and relay list; that an account received gift wraps; per
group, a stable random id, the timing and sizes of its traffic, and
which relays it uses. Not the members, not the sender of a group
message, not the group's size except by traffic volume. A relay can
still drop or withhold events, and a group whose relays all refuse a
Commit has no way out except a new group
(`app-components/nostr-routing-v1.md`, "Validation").

## 2. Ordering and consistency

### 2.1 Marmot: convergence without a hub

Two members can commit for the same epoch at the same time, and each
member may see the two Commits from different relays in a different
order. Marmot resolves this on every client by the same deterministic
rule (`protocol-core/convergence.md`):

1. **Publish before apply.** A client does not merge its own Commit
   until at least one relay has acknowledged it (`OK`, or the event
   returned to a REQ), then it keeps publishing to the rest
   (`protocol-core/publish-lifecycle.md`). Welcomes go out after that.
2. **Collect, then decide.** A new Commit opens a convergence pass. The
   client waits until 1 s passes with no new relevant input, or 5 s in
   all, then freezes the batch. Even a Commit with no rival is applied
   only when its pass closes.
3. **Score the branches.** Branches may fork at most 5 Commits back.
   They are compared by: commit depth, plus at most 1 if at least two
   distinct senders sent application messages on that branch
   ("witnesses"); then witness count; then privileged (admin) tip
   before ordinary; then the lower committer npub; then the lower
   SHA-256 of the tip Commit bytes. Transport facts (event id,
   `created_at`, relay, arrival order) MUST NOT take part. NIP-EE used
   the lowest `created_at`, then the lowest event id; the current text
   rejects that because both are sender-controlled transport metadata.
4. **Roll back if needed.** If a later pass picks another branch, the
   client rolls back to the fork point, replays the winner, and
   withdraws from the application every message and state change that
   existed only on the loser, including its own Commit that it had
   already applied. Each client keeps old epoch states for this.

The guarantee is stated carefully: clients that see the same inputs
pick the same branch, and if inputs stop arriving and everyone keeps
running they end in the same state. There is no global finality;
"Settled" is local. MDK has a convergence simulator and formal models
(`formal/`, `crates/cgka-conformance-simulator`), which I did not read.

### 2.2 MIMI: the hub orders

In MIMI the hub provider orders and authorizes every handshake and
application message for its rooms (protocol-07 §1, §5.3 to §5.5). A
client sends a Commit to the hub (`UpdateRequest`); the hub accepts one
per epoch and answers others with `wrongEpoch`; it then fans the
accepted message out to followers in order, with its acceptance time.
A `success` is a commitment that the message will be delivered. The
client does not have to wait, keep old epochs, or roll back. The cost
is trust: the hub sees handshake messages (unless SemiPrivateMessage)
and the participant list, and could send different providers different
Commits for one epoch, which nothing in MIMI detects (N1 below).

Agora (agora-spec `spec/05-messaging.md` §5.1.1) sits between them: a
Space may name a sequencer that stamps Commits into a log, which then
decides like a hub; without one, members take the Commit with the
lowest envelope id among those seen within 5 s, which can split the
group. Marmot's rule is the most worked-out of the three for the
no-orderer case.

### 2.3 Can a MIMI room and a Marmot group be one MLS group?

No, not without changing one of the two specs. The cryptography is not
the obstacle: both use RFC 9420, ciphersuite 1, OpenMLS, and the same
mls-extensions code points. The rules around it conflict:

- **Credentials.** A Marmot client rejects any leaf whose credential
  identity is not a 32-byte secp256k1 key with a valid 0x8009 proof
  (`account-identity-proof-v2.md`, "Validation"), and rejects a group
  that does not require 0x8009. MIMI's participant list holds user URIs
  (protocol-07 §7.5), and mimid's credentials hold the user's MIMI URI.
  A BasicCredential has one identity, so no leaf satisfies both.
- **Required components.** A Marmot group must require 0x8003 (admin
  policy), 0x8009 and, over Nostr, 0x8004; a MIMI room requires
  `participant_list`, `room_metadata` and the room-policy components.
  Each side's `required_capabilities` keeps out the other's clients
  unless every client implements both sets.
- **Who may commit.** Marmot allows Commits only from admins, plus a
  few self-service shapes, and has no external commit and no external
  sender. MIMI's hub is an external sender that proposes Removes
  (`hubSender`), and mimid uses external Commits to join and rejoin.
  Marmot clients would find those Commits invalid and stop following
  the group.
- **Ordering.** Marmot clients take Commits from relays and pick by
  their rule; a MIMI hub accepts the first that reaches it. If both
  paths carried Commits, the two sets of clients could pick different
  branches and fork. Only if Marmot clients submitted to the hub and
  read only its fanout would the views agree, and then they are no
  longer using the Nostr transport.
- **Threat model.** Marmot requires handshake bytes to be hidden from
  delivery infrastructure; MIMI hands them to the hub on purpose so it
  can enforce policy.

A "dual-profile" group would need a credential that carries both a
MIMI URI and a Nostr key with its proof, a policy that reconciles
admin lists with room-policy roles, and a single orderer. That is a new
protocol, not interop. The practical route is a bridge between two
groups (option (b)).

## 3. Mapping

| MIMI / mimid | Marmot / Nostr |
|---|---|
| Provider (a domain, protocol-07 §2.1) | none. Relays carry events but own no users or groups |
| Hub (orders, authorizes, keeps room state) | none. Each client runs convergence (§2.1); admins in group state authorize |
| Follower provider | none. Each client reads the group's relays itself |
| Room URI `mimi://a.example/r/x` | none public. The MLS group id is private; `nostr_group_id` is a random, rotatable delivery address, not a name |
| User URI `mimi://a.example/u/alice` | the npub (32-byte key). NIP-05 `alice@a.example` is a display label |
| Client URI `mimi://a.example/d/...` | none. A device is a leaf; device tag component 0x800f says which leaf is which device |
| KeyPackage publish (`KeyPackage/set` in the draft) | kind 30443 on the account's NIP-65 write relays, one slot per device |
| KeyPackage claim (`KeyMaterial/fetch`, §5.2) | read kind 30443 from a relay; nothing is consumed or handed out. Last-resort KeyPackages are normal |
| Welcome via hub fanout | NIP-59 gift wrap (kind 1059/13/444) to the invitee's NIP-17 inbox relays |
| Fanout (`/notify`) | the sender publishes kind 445 to every relay in the group's routing list |
| Hub acceptance time | none. Inner `created_at` is the sender's clock; ordering of application messages is by MLS and local receipt |
| Consent (§5.7, the draft's Consent objects) | none in the protocol. Anyone can fetch a KeyPackage and send a Welcome; a client decides locally whether to show or join it (wn-agent: `--allow-welcomer` allowlist) |
| Franking (§5.4.1) and AbuseReport to the hub (§5.9) | none. Reports are kind 1984 inside the group, seen by every member including the reported one; admins delete with kind 4891 |
| Room policy (roles, capabilities, preauthorization) | admin list (0x8003), plus fixed rules for non-admins. No roles |
| Room metadata component | group profile 0x8001, avatar 0x8002/0x8007 |
| Message expiration policy (room-policy §6.8) | retention component 0x8005, and NIP-40 `expiration` on application events so relays delete them |
| mimi-content CBOR, message ID over sender URI, room URI and content | unsigned Nostr event JSON; id over pubkey, time, kind, tags, content (no group binding) |
| mimi-content `replaces` (edit, delete, unlike) | kind 1009 edit, kind 5 delete, kind 5 of a kind 7 to unlike |
| mimi-content `inReplyTo` | `q` tag on kind 9 (NIP-C7); `e` tag on reactions |
| Reaction (disposition `reaction`) | kind 7 (NIP-25) |
| `topicId` | none in Marmot; NIP-C7 has none |
| ExternalPart (URL, key, nonce, hash) | `imeta` reference to a Blossom blob; key derived from the epoch exporter |
| Message status (`application/mimi-message-status`) | none found in the spec; White Noise shows "read state" (not traced) |
| External join, rejoin after a gap | none. A member that falls past the 5-Commit rollback horizon or relay retention needs a new invite |
| Minimal metadata rooms (§6) | the default stance: relays see no members |
| New device | device group: a hidden MLS group of the account's own devices, pairing over gift wraps, history bundles to new devices (`features/device-group.md`, draft) |
| Provider authentication (mTLS, draft-atwood-mimi-provider-auth) | none needed; every event is signed by its key, and relays are untrusted |
| Push | sender-triggered: encrypted tokens gossiped in the group (447-449), triggers gift-wrapped to a notification server (446) |
| Disband a group | lifecycle component 0x800c, terminal |

## 4. Options for mimid

Sizes are rough and compare with what exists: mimid-agent-irc is about
4,200 lines of Rust, mimid-agent-jmap about 4,400, mls-didwebvh about
2,700.

### (a) A Nostr front end on mimid-agent

**What.** A third front end over `mimid-agent-store`, next to JMAP and
IRC: the agent runs a loopback Nostr relay (NIP-01 WebSocket, NIP-11
info document, NIP-42 AUTH) and shows each of the user's MIMI rooms as
a NIP-29 relay-based group. NIP-29 fits well: there a relay owns the
group, checks who may post, orders it, and signs the group's metadata
(kinds 39000 to 39003), which is what the agent does for its own view
of a MIMI room.

**What it takes.**

- Crate `mimid-agent-nostr` (INVENTED name): WebSocket server, REQ
  filter matching over store records, `OK`/`EOSE`/`CLOSED`, NIP-42 AUTH
  that accepts only the owner's configured key.
- Mapping: room to group id (`h` tag); message to kind 9 with `h`;
  reply to `q`; retraction to kind 5 from the author, or 9005
  `delete-event` from an admin; ban, kick, invite and role changes to
  9000/9001 and the role events; participants to 39002, admins
  (room-policy "admin") to 39001.
- Signatures. Every event a Nostr client receives must carry a valid
  BIP-340 signature by its `pubkey`. Remote MIMI users have no Nostr
  key, so the agent would make one per user URI (for example HKDF of a
  local secret and the URI) and sign their events itself. Those keys
  and events must never leave the loopback relay. Kind 0 profiles would
  carry the MIMI URI as the name.
- The owner's key. Use a key made for this purpose, not the owner's
  real npub: a Nostr client that rebroadcasts the owner's events to
  public relays would otherwise publish private room messages as signed
  events attributable to the owner. Marmot keeps its inner events
  unsigned for the same reason.
- Size: about the IRC front end, 4,000 to 6,000 lines, plus a
  secp256k1 Schnorr dependency (`k256` with `schnorr`).

**What breaks.** Edits: NIP-29 has none; Marmot's kind 1009 is not a
general Nostr kind, so most clients would show nothing or a new
message. Nostr clients expect to reach other relays (outbox model,
profile lookups); a client set up for this relay only would be needed.
Which NIP-29 clients handle a private loopback relay well I did not
check (Chachi, Flotilla and 0xchat are said to support NIP-29;
unverified).

**Value.** Low to medium. It is a client choice for people who already
use a Nostr client, like IRC is for people who use IRC. It connects
mimid to no Nostr user.

### (b) A MIMI room to Marmot group bridge in the agent

**What.** The agent is a member of a MIMI room and of a Marmot group at
once, decrypts from one, and re-encrypts into the other. Two MLS
groups, two orderings; nothing crosses at the MLS level.

**How the agent speaks Marmot.** Two ways:

1. Run MDK's `wn-agent` next to mimid-agent and use its control socket
   (`marmot.agent-control.v2`, newline-delimited JSON:
   `group_create`, `send_final` with an idempotency key,
   `subscribe_inbound` with `inbound_message`, `message_edited`,
   `message_deleted`, `reaction_added`, `group_invite`, and
   `timeline_list` to fill gaps; `integrations/custom-client.md`).
   wn-agent keeps the Nostr key, MLS state, relays and media. The
   bridge is then glue between `Store` and the socket. Medium: 3,000
   to 5,000 lines. Whether the control API covers sending edits,
   reactions and attachments I did not trace (it has
   `invalid_edit_target` and attachment calls in
   `crates/agent-control/src/lib.rs`).
2. Link MDK into mimid-agent. Large, and awkward: MDK pins OpenMLS git
   rev `6100df3`, mimid pins the MarkAtwood fork at `f1680d9`, and the
   two target mls-extensions -10 and -11. Two OpenMLS copies in one
   binary may build but double the MLS code. Not advised.

**What the bridge looks like to each side.**

- *Relay mode (one bridge identity).* On the MIMI side the bridge is
  one user, for example `mimi://a.example/u/nostr-bridge`, listed in
  the room's bot policy (room-policy-04 §6.7, `bot_role_index` > 0);
  every Nostr user's message comes from that user. On the Marmot side
  it is one npub; every MIMI user's message comes from it. The real
  author has to go in the content: a line prefix, or a field. Marmot
  checks that inner `pubkey` equals the MLS sender, so the bridge
  cannot post as anyone else. mimi-content has no "on behalf of" field
  (N7). Simple, and honest about who holds plaintext.
- *Puppet mode (one identity per remote user).* The bridge makes a
  Nostr key per MIMI user and a MIMI user URI per npub (mimid-server
  can host those, say `mimi://a.example/u/npub1...`), each with its own
  leaf. Each puppet's leaf proof (0x8009) is honest, since the bridge
  does hold the key, but users on each side see a person who is not
  there. In Marmot every puppet add needs an admin; in MIMI it depends
  on room policy and consent. Groups grow by one leaf per remote user.
  More work (key and leaf management for every puppet), and a step
  further from what members think they see.

Relay mode first; puppets only if someone asks.

**Consent.**

- The bridge enters a Marmot group only when invited (wn-agent's
  allowlist decides whose Welcomes it accepts) and a MIMI room only
  when invited, with MIMI consent as for any user.
- It joins a pair only on an explicit link made by someone who is in
  both, for example an IRC-style service command `bridge
  <room> <group>` (INVENTED). Being invited to both is not consent to
  copying one into the other.
- Each side's members must be told: a notice on link, and the bridge's
  display name and profile saying what it is. The draft already asks a
  converting party to be a visible member (draft §Security
  Considerations, first paragraph).
- Retention and expiry do not survive the crossing unless the bridge
  carries them: a MIMI message with `expires` must become a kind 9
  with NIP-40 `expiration` at least as early, and the reverse. Neither
  side can enforce it on the other's clients.

**Loops.** The bridge keeps a map from each message it wrote to its
source (Nostr event id to MIMI message ID and back). It never bridges
a message sent by its own leaves, nor one whose id is already in the
map. Two bridges on the same pair would still loop each other's
copies; a marker in the content (a `bridged` tag in the Nostr event, a
mimi-content extension key on the MIMI side) lets a second bridge
skip them. The map also drives edits, replies and deletes.

**Content mapping.**

| mimi-content | Marmot |
|---|---|
| text body `text/plain` or `text/markdown` | kind 9 `content`. Marmot renders markdown (MDK has `marmot-markdown` crates; dialect not compared with GFM-MIMI) |
| `inReplyTo` | `q` tag with the mapped event id |
| `replaces` with new body (edit) | kind 1009 with `e` = mapped id of the first version (both name the first version) |
| `replaces` with empty body (delete) | kind 5 with `e` |
| reaction (disposition `reaction`, `inReplyTo`) | kind 7, `e` = target, `content` = the emoji |
| unlike (`replaces` the reaction, empty) | kind 5 naming the kind 7 |
| ExternalPart | download, decrypt, re-encrypt and upload to the other side's store: Marmot's file key may not be sent outside the account (`features/encrypted-media.md`, "Key Derivation"), and mimid's `assetUrl` expects encrypted blobs the bridge uploads |
| `topicId` | dropped |
| `expires` | NIP-40 `expiration` (see consent) |
| message status | none; drop |
| none | kind 4891 admin deletion: becomes a deletion by the bridge if room policy gives it `canDeleteOtherMessage`, otherwise a notice |
| none | kind 1984 report: not bridged; reports stay on their side |
| none | polls (1068/1018): a text rendering, one way |

Timestamps: a MIMI message has the hub's acceptance time; a Nostr event
has the sender's `created_at`. The bridge sets each outgoing message's
time to the time it sends it, and keeps the source time only in the
map.

**What breaks.** End-to-end encryption between the two sides; the
bridge holds plaintext, as any converting party does. Edits and
deletes of messages sent before the link. Marmot convergence can
withdraw a message the bridge already passed on (§2.1, step 4); the
bridge must then send a delete on the MIMI side, and users there see a
message vanish. Abuse reports cannot cross: a frank proves a message to
a MIMI hub, and a Marmot report is just an event.

**Value.** High, if anyone wants to talk across. It is the only option
that puts MIMI users and White Noise users in one conversation, and it
tests mimi-content against a second content model.

### (c) Nostr relays as a blind transport for mimid

**What.** Carry MIMI provider-to-provider traffic, or wake-ups, over
Nostr relays: as a fallback when a follower is unreachable, or as a
store-and-forward mailbox for providers behind NAT.

**What it takes.** Providers would need Nostr keys published in DNS
next to their provider-auth keys. Every MIMI request body
(`KeyMaterialRequest`, `UpdateRequest`, `FanoutMessage`) would go in a
gift wrap or an AEAD envelope to the target provider's key, since the
bodies carry room IDs, user URIs and PublicMessage handshakes. Request
signatures (RFC 9421, draft-atwood-mimi-provider-auth) cover HTTP
components and would not survive; a new signature over the body would.
Responses (`success`, `wrongEpoch`) would need their own events. Large,
and spec work before code.

**What breaks.** MIMI's synchronous answers; the hub's commitment on
`success` would rest on a relay's `OK`. Relays would see which
providers talk, how much and when, which TLS between them also shows,
so little is gained. Provider authentication through DNS and TLS
(protocol-07 §4.1) has no equivalent.

**Against Agora's model.** Agora's relays (agora-spec §10.4) are built
to be blind: they route by `channelToken`, derived from an admission
key they never hold, keep no accounts, and must be able to testify
that they cannot map a token to a group or a member. Marmot's relays
are close to that for group traffic (random `nostr_group_id`, fresh
key per event, encrypted framing) but not for accounts: KeyPackages,
relay lists, deletion requests and backup pointers are signed by the
account key, so a relay knows every Marmot user that publishes there.
Agora keeps KeyPackages off relays entirely (agora-spec §2.5.4, step
6). A MIMI provider is not blind and does not try to be: the hub
enforces policy on user URIs, so it must see them (A9 in
air-api-comparison.md). Putting relays under MIMI would add a blind
hop to a protocol whose ends are not blind.

**Value.** Low. MIMI providers are servers that are online, and the
hub already retries fanout. If mimid ever needs push, the provider
already knows its own users and can push directly. Not advised.

### (d) Identity

**NIP-05 names and MIMI user URIs.** `alice@a.example` and
`mimi://a.example/u/alice` have the same shape. A mimid server could
serve `/.well-known/nostr.json` for its users who have a Nostr key, and
a MIMI client could show a NIP-05 name it has checked against the
domain. That only says the domain vouches for both, which is what a
MIMI provider already says about its users; it adds no protection
against the provider. Small: a few hundred lines in mimid-server and
a configuration table. Useful mainly as a lookup for the bridge
("which npub is alice?").

**Nostr keys in MLS credentials.** Marmot's 0x8009 proof is a good
pattern: a key the user holds signs a statement naming the leaf's MLS
signature key, and every member checks it. mimid could accept a
LeafNode component of the same form beside a BasicCredential that
still holds the MIMI URI: "the holder of npub X authorizes this leaf
for `mimi://a.example/u/alice`". Members would pin the npub on first
sight and flag a change, as mimid already does for did:webvh DIDs
(README, "Known weaknesses"). Medium: 1,000 to 2,000 lines, a
component in the private range.

**Against did:webvh.** did:webvh is the stronger identity: its log has
key rotation, pre-rotation and an audit trail, and a device can be
revoked by the user. A Nostr key cannot rotate. If the key leaks the
identity is lost, and there is no adopted NIP for migrating to a new
key. What a Nostr key has is reach: many people already have one, and
Marmot users are identified by nothing else. So: did:webvh stays the
primary user-held identity; a Nostr key proof is worth adding only
together with the bridge, so a MIMI user can say "I am also npub X"
and the bridge can map them. Not on its own.

## 5. Findings for the drafts

Numbered N1 onward, in the style of F1 to F18 and A1 to A12. "No
change" items are kept so the list is complete.

### N1. Nothing detects a hub that forks a room

**Gap.** Marmot clients see every Commit for a group on the relays,
detect two Commits for one epoch, and resolve them the same way
(§2.1). In MIMI a client sees only what its provider receives from the
hub. A hub that sends different Commits for one epoch to different
providers splits the group, and the members only notice when messages
stop decrypting. mimi-content-10 §4.2 points at AppAck and message
status reports for detecting reordering, but neither MIMI draft says
how to detect a split.

**Draft.** protocol-07 §9 has nothing on it. Not a matter for
draft-atwood-jmap-chat-mimi.

**Proposed text** (for #mimi, protocol §9):

> A hub can send different Commits for the same epoch to different
> providers, so that clients on those providers end up in different
> MLS groups. Clients MAY detect this by comparing the epoch
> authenticator ({{RFC9420, Section 8.7}}) or the hash of the Commit
> that started each epoch with other members, for example in an AppAck
> ({{I-D.ietf-mls-extensions}}) or a message status report.

### N2. Commits can be lost to retention while application messages are not needed

**Gap.** Marmot never puts a relay expiry on a Commit or Proposal, "so
group-state history stays fetchable for members catching up"
(`transports/nostr.md`, "Message expiration"), while application
messages may expire. The draft's `messageRetention` treats all
Messages alike. A client away longer than the retention misses Commits
and must rejoin by external Commit, which room policy may refuse; then
it needs a new invite (draft §capability, `messageRetention`). If the
server kept handshake messages longer, such a client could follow the
group and lose only the application messages, as it does now anyway.
The server can tell them apart: a FanoutMessage's MLS wire format says
whether it carries an application message (protocol-07 §5.5).

**Proposed text.** In §capability, after `messageRetention`:

> `handshakeRetention` (UnsignedInt, optional):
> : The number of seconds the server keeps a Message in a Chat with a
> `roomId` whose MLS message is a proposal or commit, after storing it.
> When present it is not less than `messageRetention`. Absent if the
> server keeps such Messages for `messageRetention` only.

Uncertain whether this is worth the storage: Commits carry UpdatePaths
and can be large in big rooms. mimid would need to measure it.

### N3. A server that fetches a URL from a message can be aimed at its own network

**Gap.** Marmot's implementation model says a URL in authenticated
group state or a payload "does not authorize a client to contact that
destination", and lists loopback, link-local, private and metadata
addresses to refuse, with DNS rebinding in mind
(`implementation-model.md`, "Network destination safety"). The draft's
`assetDownloadUrl` has the server fetch a `url` taken from a message,
directly for its own assets and through the hub for others; the hub's
`proxyDownload` (protocol-07 §5.10.2) does the same. The base draft
has one SSRF sentence for blob URIs (draft-atwood-jmap-chat-00, line
1857 at 735503c); this draft has none.

**Proposed text.** In §Security Considerations:

> A `url` given to `assetDownloadUrl` comes from a message, which any
> member of the room can write. A server that fetches it, or asks the
> hub to, SHOULD refuse destinations in loopback, link-local, private,
> multicast and other special-purpose address ranges, after name
> resolution and after each redirect, unless it is configured to allow
> a specific one.

(SHOULD, not MAY: this protects the server's own network.)

### N4. No user-held key binds a leaf to its user

**Gap.** Every Marmot leaf carries a signature by the user's own key
over the leaf's MLS signature key (0x8009). In MIMI the provider
vouches for its users' leaves, and a malicious provider can add a leaf
for any of them (mimid README, "BasicCredential by default"). mimid's
did:webvh credential closes this from first contact on. MIMI's
identity work (draft-barnes-mimi-identity-arch) lists the problem; no
MIMI draft has a mechanism.

**Proposed text.** None for draft-atwood-jmap-chat-mimi. For the
identity discussion in #mimi: Marmot is a deployed example of a
LeafNode component that carries a user-key signature over the leaf key,
independent of the credential type. It may be worth citing as a pattern
next to did:webvh.

### N5. A joiner does not check who added it

**Gap.** A Marmot joiner rejects a Welcome unless the GroupInfo signer
is an admin in the joined state (`app-components/admin-policy-v1.md`,
`protocol-core/joining.md`). Marmot also says plainly that this check
is weak, because a forked group's state is written by its author
("Welcome-bootstrap trust"). In MIMI the hub checks the add against
room policy and the joiner trusts the hub; the draft's consent records
cover whether the user wanted to be reachable, not whether the adder
was allowed.

**Proposed text.** No change. With a hub that enforces policy the
check adds little, and Marmot's own text shows its limits. Listed
because it is the one place Marmot puts an authorization check on the
joiner.

### N6. History for a user's new device

**Gap.** Marmot's draft device group lets an existing device hand a
new device of the same account the history of a chat ("history
bundles", kind 473, `features/account-sync.md`, `features/device-group.md`,
both "Status: draft"). mimid's new device joins only rooms another
device accepted, and sees only messages after it joins (README, "Known
gaps"). The draft has `privateMetadata` (F6) for small shared state
and nothing for history.

**Proposed text.** None now. Copying history between a user's devices
is a client matter that could ride on the self-group idea in Air and
Agora as well. Worth a bead when multi-device work resumes; Marmot's
documents are the most detailed public design I know of.

### N7. mimi-content cannot say "sent on behalf of"

**Gap.** A bridge in relay mode (option (b)) sends other people's
messages as itself. Marmot has no field for it either (the inner
`pubkey` must equal the MLS sender), but Nostr clients can carry an
extra tag. mimi-content-10 §4.3 allows extension keys; none is
registered for an original author.

**Proposed text.** None yet. If mimid builds the bridge, a private
extension key first, then a registration request for an
`onBehalfOf` (text, a URI such as `nostr:npub1...` or a MIMI URI) in
the MIMI Content Extension Keys registry (mimi-content-10 §8.2.1), with
the rule that receivers MAY show it and MUST NOT treat it as
authenticated.

### N8. Publish before apply

**Gap.** Marmot requires a relay's acknowledgement before a client
merges its own Commit. MIMI's equivalent is the hub's `success`, and
the draft returns it (`responseCode`).

**Proposed text.** No change.

### N9. Group disband, admin succession, polls

Marmot has a terminal disband (0x800c), states that a group with no
reachable admin is frozen, and carries NIP-88 polls. MIMI has no room
deletion (A12 in air-api-comparison.md), room-policy-04 does not say
what happens when no one holds a role that can change roles (not
checked closely), and mimi-content has no polls. No change proposed
here; the first two are room-policy questions.

### What MIMI has that Marmot lacks

- One orderer per room: no rollback, no withdrawn messages, no 1 to 5
  s wait before a Commit takes effect.
- Consent before key material is handed out; Marmot has only local
  allowlists.
- Franking and abuse reports a third party can verify; Marmot's
  reports are ordinary events visible to every member.
- Roles and capabilities (room-policy-04 §3, §8); Marmot has admin or
  not.
- External joins and rejoins; a Marmot member that falls behind
  needs a new invite.
- Identities qualified by domain, and provider authentication; Marmot
  has keys only.
- Ratchet tree options for large rooms; Marmot puts the whole tree in
  each gift-wrapped Welcome, about 1,900 members at relays' 2 MiB
  (`transports/nostr.md`, "NIP-44 and event size").
- Proxy download of assets through the hub, so a client never contacts
  another provider; Marmot clients fetch from Blossom servers directly.
- Message status reports.

## 6. Recommendation

Build (b), the bridge, first, in relay mode, by driving MDK's
`wn-agent` over its control socket rather than linking MDK: it is the
only option that lets MIMI users and White Noise users talk, it costs
about one front end's worth of code, and it keeps OpenMLS versions and
Marmot's convergence rules in the code that already implements them.
Do the NIP-05 lookup from (d) as part of it, since the bridge needs a
way to name npubs, and leave the Nostr-key leaf proof until a user asks
to be the same person on both sides. Skip (a) unless someone wants a
Nostr client as a UI, and skip (c). Take N2 and N3 to the draft, and
N1 to #mimi, independently of any of this.

## 7. Uncertainties

- The NIP-29 client landscape in option (a) is from memory, not
  checked.
- wn-agent's control API was read from its client guide and one
  source file; whether it sends edits, reactions and attachments was
  not traced.
- mls-extensions -10 against -11 was not compared for wire changes
  that would matter to a mixed implementation.
- MDK's formal models and simulator were not read; §2.1 is from the
  spec text only.
- White Noise's read receipts (iOS README: "read state") were not
  traced to a wire format.
- The Marmot spec changes daily (`changes.md` has entries on
  2026-11-19 and 2026-11-21); this note is a snapshot at `36757fe`.
