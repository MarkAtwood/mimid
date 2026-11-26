# Existing chat clients mimid could serve: front ends and gateways

Design note, 2026-11-21, for Mark's review. It asks which deployed chat
clients, mobile and desktop, mimid could serve without changing them,
and in which of two shapes:

- **Front end.** One mimid user's own client talks to that user's
  mimid-agent in the client's own protocol. The agent holds the MLS keys
  and decrypts, and the client sees plaintext. This is what the JMAP and
  IRC front ends do now (agent-frontends.md).
- **Gateway.** Another network joins MIMI as a provider. Its users show
  up in MIMI rooms as users of a gateway domain, and MIMI users show up
  on its side. For any client that does not speak MLS the gateway holds
  the MLS leaves of that network's users, so **end-to-end encryption
  ends at the gateway**. That is stated once here and holds for every
  gateway below unless the section says otherwise.

The Nostr and White Noise case is covered by nostr-comparison.md and by
marmot-bridge.md. This note does not redo it. Its relay-mode bridge is the nearest thing in
mimid to a gateway, and §8 builds on it.

Values and sizes marked *estimate* are mine. Sizes compare with what
exists: mimid-agent-irc is about 4,200 lines of Rust, mimid-agent-jmap
about 4,400 (nostr-comparison.md §4). Nothing in this note is measured
by building or running a client. Nothing here was posted anywhere.

## Sources

Client and server source was shallow-cloned and read on 2026-11-21. The
commits:

| Source | Version read |
|---|---|
| Goguma (codeberg emersion/goguma) | 0.9.1+1365, `5aa7baa` |
| soju (codeberg emersion/soju) | `de8690c` |
| Palaver capability spec, znc-palaver (github cocodelabs) | `57b5927`; znc-palaver 1.2.2 `917f970` |
| irssi | `43f1727` |
| WeeChat | `30e63f1` (after 4.10.4) |
| HexChat | `b544ac3` (repository archived) |
| Textual (blendbyte/Textual) | `9f6219f`, the v8 branch; v7 as shipped not read |
| Halloy | 2026.10, `a39117d` |
| The Lounge | 4.6.0-pre.2, `70db8bc` |
| Conversations | 2.21.4, `513a741` |
| Cheogram Android | `11643f2` |
| Monal | `0bde570` |
| Siskin IM, Martin | `d77818f` (7.4.0; the store has 7.4.1), Martin `6daa5f871bbbb4022d7c99f3108ae7345e8b46c1` |
| Gajim, python-nbxmpp | 2.7.0 `760de28`, nbxmpp 7.5.0 |
| Dino | `9f3a973` |
| Profanity, libstrophe | 0.20.0 `a739c34`, libstrophe `f549850` |
| Slidge | `96bd180` |
| Element X Android, matrix-rust-sdk | 26.11.1 `2d8d6cba`, sdk `f4a94ad` |
| Element Web, matrix-js-sdk | 1.12.32 `a593205`, js-sdk 45.1.0 `ebbc952` |
| FluffyChat, matrix-dart-sdk | 2.11.6 `afe2da6e52c1d5b7063c2bb736c78aaabef45696`, dart sdk 17.0.0 `26016bc` |
| Cinny | 4.12.8 `24d8926` |
| Nheko | `b15dcd1` |
| iamb | 0.14.0-alpha.1 `fbc4700` |
| continuwuity, tuwunel, Conduit | `95392cc`, `2f05870`, `66d9066` |
| chatmail/core (Delta Chat core), chatmail/relay | 2.70.0-dev `3027da4` (last release 2.69.0), relay `16d4df3` |
| mattermost-mobile, Rocket.Chat.ReactNative, tindroid, stoat for-android | default branches on 2026-11-21 (commits not recorded) |
| mimid | main at `ed10100` |

Web sources are cited where they are used. File paths like
`lib/client.dart:100` are in the client named in that paragraph, at the
commit above. Reach figures are Google Play install tiers, App Store
rating counts and repository stars, each a weak signal; F-Droid
publishes no install counts.

## At a glance

"Front end" sizes are for a first useful version over today's store.
"Push" is how a phone is woken in bouncer mode (agent on the user's
always-on host); embedded mode needs no push. "Verdict" covers both
shapes.

| Family | Clients worth serving | Front end: can stock clients be served? | Front-end size (*estimate*) | Mobile push in bouncer mode | Gateway shape and prior art | Reach (rough) | Verdict |
|---|---|---|---|---|---|---|---|
| IRC (IRCv3) | Goguma (Android, iOS); irssi, WeeChat, Halloy, HexChat, Textual, The Lounge | Yes; desktop clients already work | +2,500 to 4,000 lines on top of mimid-agent-irc for Goguma | `soju.im/webpush` (RFC 8291 Web Push); payload encrypted to the phone | One IRC client connection per MIMI user to the IRC network (heisenbridge, biboumi), or a services link to a network one runs | Goguma 10K+ Play, small on iOS; desktop clients have large old user bases | **Front end: do first.** Gateway: low value, policy-heavy |
| Matrix C-S | FluffyChat, Element X, Element Web/Desktop, Cinny, Nheko, iamb | Yes; Element X needs sliding sync and a crypto key store | 4,000 to 6,000 for `/v3/sync` clients; 7,000 to 9,000 with Element X | HTTP POST to the client's pusher URL (matrix.org, push.fluffychat.im, UnifiedPush) | Appservice beside a homeserver (mautrix bridgev2), puppets; E2EE ends at the gateway, as in mautrix today | Element 1M+, Element X 500K+, FluffyChat 100K+ (Play) | **Front end: second.** Gateway: worth it, largest network reachable |
| XMPP C2S | Conversations, Cheogram, Monal, Siskin, Gajim, Dino, Profanity | Yes, with OMEMO turned off by the user; Monal needs SASL2 | 9,000 to 10,000; +1,500 to 2,500 for push | XEP-0357 publish over **s2s** to p2.siacs.eu, Monal's or Tigase's app server | XEP-0114 component behind Prosody or ejabberd (Slidge, biboumi, Spectrum2) | Conversations ~200K Play; Monal 142 ratings | Front end: third, costly. **Gateway: good**, the component shape is cheap |
| Delta Chat (IMAP/SMTP) | Delta Chat on all platforms | Only by giving it OpenPGP mail: plaintext is refused by default since core 2.50.0 | 5,000 to 6,000, OpenPGP included | Token by IMAP METADATA, POST to notifications.delta.chat (acceptance from a non-relay host unverified) | An email domain with MX, DKIM and Autocrypt, peers as gateway-held keys | 1M+ Play | Front end: weak fit. Gateway: plausible later |
| Zulip | Zulip Flutter (Android, iOS), desktop | Yes, any server URL | 10,000 to 13,000 | Zulip push bouncer; server must register (free for 10 users or fewer) | Bot or integration API beside a real Zulip server; Matterbridge | Server 26K stars | Servable, large API, push needs Zulip's permission |
| Mattermost | Mattermost mobile, desktop | Yes; server must claim at least 10.11 | 12,000 to 14,000 | Mattermost TPNS or HPNS only | Bot or webhook API; Matterbridge | Server 40K stars | Servable, largest API, vendor push |
| Rocket.Chat | Rocket.Chat mobile | Yes, but the app checks a signed "supported versions" token | about 12,000 | Rocket.Chat Cloud gateway, registration required | Bot or REST API; Matterbridge | Server 46K stars | Weak fit |
| Tinode | Tindroid, Tinode iOS | Yes, host-name setting | 4,000 to 6,000 | TNPG token from Tinode's console | Bot over its gRPC plugin API | Tindroid ~400 stars | Cheap, small reach |
| Nextcloud Talk | Talk Android and iOS | Yes, but the app expects a whole Nextcloud | about 12,000 | Free Nextcloud push proxy; UnifiedPush | Bot API | Talk Android ~750 stars | Weak fit |
| Wire | Wire on all platforms | In theory, via the custom-backend deep link | very large: wire-server API plus Proteus or Wire's MLS | AWS SNS set up by Wire | Federation peer or user bot; MLS on both sides does not make it end to end | small | Not worth it now |
| Telegram, Signal, Stoat mobile, Discord | stock apps | No: servers and keys are built in | n/a | n/a | User bot or linked device (mautrix-telegram, mautrix-signal); E2EE ends at the gateway | very large | **Gateway only** |
| SimpleX, Session, Briar, Cwtch, Jami, Tox, Status, Berty, Quiet, Keet, Ricochet Refresh, Retroshare | stock apps | No: peer to peer, onion or blind relays; there is no server to stand in for | n/a | n/a | A peer node or bot on the user's host (simplex-chat CLI API, Tox bots) | varies; SimpleX 20K stars | **Gateway peer only**, one user at a time |
| Threema, Wickr, Hush Line | n/a | No | n/a | n/a | Threema's paid Gateway API only; Wickr consumer is gone; Hush Line is a tip line, not chat | n/a | Not servable |

## 1. What every front end shares

Three things decide most of the cost, whatever the protocol.

### 1.1 Embedded on the phone or a bouncer

The agent's plain HTTP listener is loopback only; its plain IRC
listener takes any address (decision mimid-1wgh.92), and both front ends
have a TLS listener (`listen_tls`). There are two ways a phone can use it.

- **Embedded.** The agent runs on the phone and the chat app connects
  to `127.0.0.1`. On **iOS this is not realistic**: a second app cannot
  keep a localhost server alive in the background, so the chat app
  would see the agent only while the agent app is in front. On Android
  it works as a foreground service, with two limits from the client
  side. Some apps refuse cleartext to localhost or untrusted
  certificates: Tindroid allows cleartext only to the emulator's
  `10.0.2.2` and trusts only system CAs (its
  `res/xml/network_security_config.xml`); Conversations requires TLS
  and a certificate that names the account's domain, though it lets the
  user accept an unknown CA (`XmppConnection.java:1610-1630`,
  `MemorizingTrustManager.java`). Element X, Mattermost, Rocket.Chat
  and Nextcloud Talk allow cleartext to localhost (their
  `network_security_config.xml`). Goguma has an `irc+insecure://`
  scheme (`page/connect.dart:85`). Embedded mode needs no push: the
  agent itself is woken by the provider's EventSource or live stream
  and posts a local notification, or the app keeps its own connection.
- **Bouncer.** The agent runs on the user's own always-on host and the
  app connects over the network, the way Goguma connects to soju. This
  works on both platforms, and it is the only way to serve iOS. It
  needs three things the agent does not have:
  1. A listener that is not loopback, with TLS. That reverses a rule
     the agent states in agent.md and AGENTS.md (open question 1).
  2. Authentication fit for a network: today's 43-character token
     over TLS is enough strength, but each protocol wants it in its own
     form (SASL PLAIN for Goguma, SCRAM or SASL2 for Monal, a password
     login for Matrix).
  3. Push to wake the app, through whatever relay the app's vendor
     runs (§1.2).

A middle path keeps the loopback rule: the user runs WireGuard or
Tailscale on host and phone, and the agent binds to the tunnel address
only. That is still not loopback, so it is the same decision, with a
smaller exposure.

### 1.2 Push goes through the app vendor's relay

Every iOS app and every Play-store Android app can be woken only
through a relay its vendor runs, because only the vendor holds the
APNs or FCM credentials. What the relay sees differs a lot:

| App | Relay | What the relay sees | Who may send |
|---|---|---|---|
| Goguma | pushgarden.emersion.fr to FCM or APNs; any UnifiedPush distributor | Ciphertext (RFC 8291; the payload is one IRC line encrypted to keys the phone made) | Anyone holding the subscription; not tested with a non-soju sender |
| Element X | matrix.org `/_matrix/push/v1/notify`; UnifiedPush | Room and event IDs and counts (`event_id_only`) | Any homeserver: the pusher URL is chosen by the client |
| FluffyChat | push.fluffychat.im; UnifiedPush | Event content unless the homeserver sends ids only | Any homeserver |
| Conversations (Play) | p2.siacs.eu, reached by XMPP s2s | Sender and a count | Any server that can do s2s (unverified for dialback-only peers) |
| Monal | eu.prod.push.monal-im.org, by s2s | Same | Same, unverified |
| Delta Chat | notifications.delta.chat | An opaque token, encrypted to the notifier | Chatmail relays; a non-relay sender unverified (no check found in `chatmaild/notifier.py`) |
| Palaver | api.palaverapp.com | Message text unless preview is off | The server holding the token |
| Zulip | Zulip's push bouncer | Encrypted payloads from server 12 on | Registered servers only |
| Mattermost | TPNS or HPNS | Message preview unless set to ids only | TPNS free, HPNS licensed |

Two consequences. First, a front end whose push relay checks who the
sender is (Zulip, Mattermost, Rocket.Chat, Tinode) needs the vendor's
consent to register a server that is not theirs, and that is a terms of
service question before it is a code question. Second, for mimid's
privacy story the relay must never see message text: Goguma's Web Push
is the best case, Matrix with `event_id_only` is next, Palaver with
previews on is the worst.

### 1.3 What the store lacked, and where each was closed

Every richer client wants things the store did not model when this note
was written. All five are now built; the list is kept because it is why
they were built, and because the client families named are the reason
each took the shape it did.

- **Replies on send.** Every family below has replies. Built: a
  message's `in_reply_to` through the store and both front ends.
- **Reactions.** Goguma, Halloy, Matrix, XMPP, Delta Chat, Zulip and
  Mattermost all show them. Built: reaction records in the store.
- **One-to-one rooms.** MIMI has no marker for them. Goguma's DM list,
  Matrix's `m.direct`, XMPP 1:1 chats and Delta Chat's 1:1 chats all
  assume them. Built: a `fixed_membership` room, agent-frontends.md
  §7.29.
- **Attachments outside JMAP.** Goguma uploads through
  `soju.im/FILEHOST`; Matrix and XMPP need upload and download URLs.
  Built: HMAC-signed attachment links (`mimid-agent-store`'s `links`),
  agent-frontends.md §7.30.
- **History for clients that ask.** Goguma needs `draft/chathistory`;
  Matrix and XMPP are built on history queries (`/messages`, MAM).
  Built: `chathistory` in the IRC front end.

## 2. IRC and IRCv3

### What the clients use

| Client | Platform | Caps it asks for (from source) | Needs for a decent experience | Push | Auth and TLS | Reach |
|---|---|---|---|---|---|---|
| Goguma | Android, iOS, Linux | batch, echo-message, labeled-response, message-tags, server-time, sasl, draft/chathistory, draft/event-playback, draft/read-marker, draft/message-redaction, draft/metadata-2, draft/pre-away, soju.im/bouncer-networks(-notify), soju.im/no-implicit-names, soju.im/webpush, and more (`lib/client.dart:100-131`); ISUPPORT `soju.im/FILEHOST`, `VAPID` | Nothing is required. Without bouncer-networks it is a plain IRC client (`client_controller.dart:514-524`); without chathistory there is no backlog on reconnect, Android falls back to a persistent service, and iOS has no background sync (`client_controller.dart:156-175,1242`) | soju.im/webpush only (§1.2) | **The password field shows only if the server offers SASL PLAIN** (`page/connect.dart:223,255,365`). PASS is in the code but the UI never sets it. TLS by default; a self-signed certificate can be accepted and pinned (`connect.dart:401-414`) | Play 10K+; iOS 10 ratings; Codeberg 159 stars |
| Palaver | iOS, closed | `palaverapp.com`, server-time, sasl, multi-prefix (capability spec README); ircv3.net lists more | Push needs the `palaverapp.com` cap and the PALAVER command set | The server POSTs JSON to api.palaverapp.com with the app's bearer token (znc-palaver `palaver.cpp:803-848`) | SASL; mechanisms unknown | **Possibly gone**: the iTunes lookup for id 538073623 returned no result in three stores, the store page 404s and palaverapp.com has an expired certificate. Last version seen 2.10.3, 2024. Unverified |
| irssi | terminal | message-tags, sasl, server-time, extended-join, and older caps (`src/irc/core/irc-servers.h:18-30`) | Works today | none | PASS or SASL (PLAIN, EXTERNAL, SCRAM) | 3.2K stars |
| WeeChat | terminal | batch, echo-message, message-tags, server-time, draft/multiline, account-tag, and others (`src/plugins/irc/irc-command.h:49-52`) | Works today | none (its phone app uses WeeChat's own relay protocol) | PASS or SASL | 3.4K stars |
| HexChat | desktop | server-time, account-tag, and older caps; no message-tags (`src/common/inbound.c:1731-1757`) | Works today | none | PASS or SASL | 3.2K stars, archived |
| Textual | macOS | v8 branch: chathistory, read-marker, redaction, react, multiline, soju caps; v7 per ircv3.net: sasl, batch, echo-message, server-time | Works today | none | PASS or SASL | 1.9K stars |
| Halloy | desktop | batch, draft/chathistory, labeled-response, echo-message, draft/read-marker, draft/multiline, soju.im/bouncer-networks, draft/react, draft/reply, draft/message-redaction (`data/src/capabilities.rs:420-520`) | Works today; chathistory and read-marker make it much better | none | PASS or SASL; an option to accept invalid certificates | 4.6K stars |
| The Lounge | web, self-hosted | its own set plus znc.in/playback (`server/models/network.ts:323-327`) | Works today | Its own Web Push from its own server; nothing needed from mimid | PASS or SASL | 6.4K stars |

The ircv3.net client table disagrees with the source in places (irssi
echo-message, Halloy chathistory); the table above follows the source.
Sources: ircv3.net/software/clients; github.com/cocodelabs;
itunes.apple.com/lookup?id=538073623 and id=6470394620;
play.google.com/store/apps/details?id=fr.emersion.goguma.play.

**Goguma is the one mobile IRC client that matters**, and it now has an
iOS build from the same code (App Store id 6470394620, version 1.6).
One front end serves both phones.

### What the agent would add for Goguma, in order

| Step | What | Size (*estimate*) |
|---|---|---|
| 1 | TLS listener (rustls, self-signed is fine since Goguma pins it) and SASL PLAIN taking the agent token as the password; advertise `soju.im/account-required` so the field is mandatory. Keep PASS for desktop clients | 300 to 500 |
| 2 | One-to-one rooms as queries (§1.3), against decision §7.2 | 400 to 700 |
| 3 | `batch` and `draft/chathistory` (BEFORE, AFTER, LATEST, AROUND, BETWEEN, TARGETS) over the store, keyed by room; replay on JOIN for clients without it, as soju does (`downstream.go:1841,1888`); against decision §7.6 | 800 to 1,200 |
| 4 | `soju.im/webpush`: a stored VAPID P-256 key in ISUPPORT, `WEBPUSH REGISTER` and `UNREGISTER` with FAIL replies, subscriptions in the store, RFC 8291 encryption and RFC 8292 signing, a POST on a DM or mention while no client is attached. soju's rules: TTL 7 days, high urgency for PRIVMSG, 404 drops the subscription (`server.go:339-380`, `doc/ext/webpush.md`) | 600 to 900 |
| 5 | `draft/read-marker` over the store's read positions | 150 to 250 |
| 6 | `+draft/reply`, `+draft/react` and `draft/message-redaction` both ways, once the store has replies and reactions (§1.3) | 300 to 500 |
| 7 | `soju.im/FILEHOST` upload, mapped to MIMI attachments, and download URLs (§1.3) | 500 to 800 |
| 8 | Palaver: the `palaverapp.com` cap, per-device preferences, mention matching, the POST with `private: true` forced so no text leaves; plus `znc.in/playback`. Only if Palaver is still sold | 400 to 600 |

Do not advertise `soju.im/bouncer-networks`: MIMI has one "network".
Edits have no IRCv3 form that I found; keep the `(edited)` line.

**Mapping.** As in agent-frontends.md §4. Push maps cleanly: the agent
already knows when no IRC connection is attached.

**Effort and reach.** Steps 1 to 5 are about 2,500 to 3,500 lines and
give a real phone client on both platforms with end-to-end encrypted
push. It is the cheapest phone story in this note by a wide margin.
Reach is small (Goguma's 10K+ installs) but the users are exactly the
people likely to run a personal always-on host.

**Risks.** Bouncer mode needs the non-loopback listener (question 1).
pushgarden.emersion.fr is one person's service; it was not tested with
a sender other than soju.

### IRC as a gateway

Prior art: matrix-appservice-irc (one IRC connection per bridged user,
which needs the network's consent for connection limits; the large
Libera bridge was shut down, from memory), heisenbridge (one user's own
connections, bouncer style), biboumi (an XMPP component, one IRC
connection per XMPP user), Matterbridge (one relay bot with `<nick>`
prefixes), and services links (TS6, P10, InspIRCd and UnrealIRCd
server protocols, as Anope and Atheme use), which give the best
fidelity but need a network that trusts the gateway as a server.

For MIMI the cheap shape is per-user connections: an IRC user `nick` on
network N appears as `mimi://<gateway>/u/<nick>-<network>`. Reach is
every IRC network; the cost is mostly policy (bridging rules,
connection limits) and the plain fact that every IRC member of a MIMI
room is unencrypted. **Low value**: IRC people who want MIMI rooms
can use the front end.

## 3. Matrix client-server API

### What the clients need

| Client | Login | Sync | Encryption behaviour | Push |
|---|---|---|---|---|
| Element X (Android, iOS) | OAuth if advertised, else `m.login.password` (`LoginModePresenter.kt:89-98`) | **Simplified sliding sync (MSC4186) only**; without `org.matrix.simplified_msc3575` in `/versions` it shows a hard error (`SlidingSyncNotSupportedDialog.kt`) | Bootstraps cross-signing and key backup after login (`RustMatrixClientFactory.kt:169-170`), then blocks on "verify this session" if unverified (`DefaultFtueService.kt:91,118-123`). No switch turns encryption off | matrix.org gateway via FCM or APNs; UnifiedPush on Android |
| Element Web, Desktop | password, SSO, OIDC | `/v3/sync` | `.well-known` `io.element.e2ee.force_disable` skips setup (`shouldSkipSetupEncryption.ts:20-29`) | none |
| FluffyChat | password, SSO, OIDC | `/v3/sync` | Offers key backup after login; skippable (`bootstrap_page.dart:56-78`) | push.fluffychat.im via FCM; UnifiedPush |
| Cinny, Nheko, iamb | password | `/v3/sync` | Upload device keys; failures likely non-fatal (unverified for Nheko and iamb) | none |

Unencrypted rooms are labelled ("Not encrypted", "Send an unencrypted
message…"), not refused. Clients do not check server signatures on
events, so room and event IDs can be opaque.

### What the agent would implement

| Step | What | Size (*estimate*; continuwuity's equivalent) |
|---|---|---|
| 1 | `.well-known` (with `force_disable`), `/versions`, password `/login`, `/logout`, `/whoami`, `/capabilities`, push rules, profiles | 300 |
| 2 | `/v3/sync` with invite, join and leave sections, state, timeline, receipts, account data (`m.direct`); `/messages`, `/context`, `/event`, `/state`, `/members`, `/relations` | 2,000 (its v3 sync is 2,140) |
| 3 | Sending: messages, edits (`m.replace`), replies, reactions (`m.annotation`), redactions, receipts, typing, invite, join, leave, kick, ban, `createRoom`, name, topic and power levels | 800 |
| 4 | Media: authenticated upload, download, thumbnail, over the blob store | 300 |
| 5 | Pushers and a POST to the pusher URL with `event_id_only` | 400 (its push.rs is 575) |
| 6 | For Element X: a store-and-return key service (`/keys/*`, `/keys/device_signing/upload` without interactive auth, `/room_keys/*`, `/sendToDevice`, secret storage account data) and simplified sliding sync with its `e2ee`, `to_device`, `account_data`, `receipts` and `typing` extensions | 2,500 to 3,000 (its keys and backup are 1,100, sliding sync 1,870) |

Steps 1 to 5 are about 4,000 to 6,000 lines and serve FluffyChat on
both phones, Element Web and Desktop, Cinny, Nheko and iamb. Step 6
adds Element X.

**Mapping.** A user `mimi://d/u/x` is `@x:d`, with characters outside
`[a-z0-9._=/+-]` escaped. The fake server never federates, so the
domain need not resolve. MIMI roles are power levels; invites are
`m.room.member` invites and consent is accept or decline; read
positions are `m.read` receipts and `m.fully_read`; attachments are
`mxc://` URIs over blob ids. Every room is unencrypted on the client
side: the agent is the encryption end.

**Push.** The easiest of any family: a plain HTTPS POST to a URL the
client chose, no registration and no s2s. With `event_id_only` the
gateway sees ids and counts only; the phone then fetches the event from
the agent, so the agent must be reachable from the phone (bouncer mode).

**Embedded.** Element X allows cleartext to `127.0.0.1` on Android
(`app/src/main/res/xml/network_security_config.xml`), so embedded works
there; FluffyChat not checked.

**Risks.** Element X's verification screen: the fake key service must
make the new session count as verified by its own cross-signing keys,
and whether every recovery banner then goes away is unverified. The
client SDKs move fast (Element X is on a nightly rust SDK), so the
front end will need upkeep. Beeper's closed hungryserv is the only
"partial homeserver over another store" I found; no open one exists.

### Matrix as a gateway

The shape that works is an **appservice beside a real homeserver**:
MIMI users appear as ghost users in an appservice namespace, Matrix
users get MLS leaves held by the gateway under
`mimi://<gateway>/u/<escaped mxid>`, and each MIMI room is a portal
room. mautrix bridges already decrypt Megolm at the bridge
("end-to-bridge encryption", docs.mau.fi/bridges/general/end-to-bridge-encryption.html),
so the trust model is the one Matrix users of bridges already accept.
The mautrix-go bridgev2 framework does the Matrix half; the MIMI half
is the multi-user host of §8. A gateway as its own federating
homeserver (state resolution, room versions) is far larger and not
worth it.

Reach: every Matrix user, no client changes. **Worth it**, after the
host of §8 exists. The expired draft-ralston-mimi-linearized-matrix is
the earlier, protocol-level version of this idea.

## 4. XMPP client-to-server

### What the clients need

| | Conversations | Cheogram | Monal | Siskin | Gajim | Dino | Profanity |
|---|---|---|---|---|---|---|---|
| Platform | Android | Android | iOS, macOS | iOS | desktop | desktop | terminal |
| SASL | SCRAM (and -PLUS), PLAIN, SASL2, FAST; pins the mechanism | same | **SASL2 with SCRAM by default**; PLAIN only after the user allows "MITM-prone PLAIN" (`xmpp.m:3290-3400`) | SCRAM, PLAIN | SCRAM, PLAIN | SCRAM-SHA-1, PLAIN | SCRAM, PLAIN |
| TLS | Required; an unknown CA can be accepted, a name mismatch cannot | same | System trust only; self-signed probably fails (unverified) | User can accept | Can skip errors | Unknown CA refused | Prompt |
| OMEMO default | **On** for 1:1 and private MUCs | off | **On** | off | off | **On** | off |
| With no OMEMO keys | Blocks the send and opens the trust screen (`ConversationFragment.java:1079-1103`) | n/a | Alert with "Disable Encryption" | n/a | n/a | Input disabled (`encryption_list_entry.vala:44-75`) | n/a |
| Push | XEP-0357 to p2.siacs.eu (Play build) | Play build has push | XEP-0357 to Monal's app server, APNs | XEP-0357 plus Tigase extensions | none | none | none |

Monal also flags a server without MAM, stream management, push or HTTP
upload as a severe problem ("you could frequently miss messages!!").
If -PLUS is offered, Monal needs XEP-0440 channel-binding types too or
it disables the account (`xmpp.m:2755-2775`).

**OMEMO is the sharpest problem.** Since the agent is the encryption
end there are no OMEMO keys, and Conversations, Monal and Dino default
to OMEMO and then refuse to send until the user turns it off per chat
or per account. Rooms advertised as semi-anonymous avoid it in MUCs but
hide real JIDs. In practice the user turns OMEMO off once; that is a
setup step to document, not a bug to fix.

### What the agent would implement

| Step | What | Size (*estimate*) |
|---|---|---|
| 1 | Stream core: XML stream, STARTTLS and direct TLS, bind, iq routing, ping | 1,200 |
| 2 | SASL1 SCRAM and PLAIN; SASL2 with SCRAM for Monal | 600 |
| 3 | Disco and entity caps | 400 |
| 4 | Roster from the user's contacts; synthetic presence | 500 |
| 5 | 1:1 messages, stanza and origin ids, receipts, carbons | 500 |
| 6 | MUC (XEP-0045): join, occupants, affiliations, subject, invites (mediated and XEP-0249), occupant-id, self-ping | 1,500 |
| 7 | MAM (XEP-0313) on the account and per room, over the store | 700 |
| 8 | Stream management (XEP-0198) | 500 |
| 9 | Enough PEP for bookmarks (XEP-0402 with `#compat`, or 0048), avatars and nick; answer item-not-found for the OMEMO device list | 950 |
| 10 | HTTP upload (XEP-0363) over the blob store | 400 |
| 11 | Corrections 0308, retraction 0424, reactions 0444, replies 0461, markers 0333 | 600 |
| 12 | CSI, blocking | 250 |
| 13 | Push (XEP-0357), which needs **outbound s2s** to the app server: TLS, a certificate for the agent's domain, dialback or SASL EXTERNAL | 1,500 to 2,500 |

Steps 1 to 12 are about 9,000 to 10,000 lines, two to two and a half
times the IRC front end; push adds s2s on top. No mature Rust XMPP
server exists to borrow from (xmpp-proxy only terminates TLS).

**Mapping.** Users as JIDs under a synthetic domain with XEP-0106
escaping, the way Slidge names puppets; rooms as
`room-<id>@conference.<agentdomain>`; roles as affiliations; a MIMI
invite as a mediated invite (Conversations auto-joins only if the
inviter is on the roster, `MultiUserChatManager.java:650-790`, so the
agent puts inviters there); consent as presence subscription; history
as MAM with the store key as stanza-id; read positions as displayed
markers to the own bare JID.

**Effort against reach.** Conversations has about 200K Play installs
(chrome-stats.com estimate) and Monal 142 ratings. That is more than
Goguma and less than Matrix, at more than twice Goguma's cost, plus s2s
for push. **Third** as a front end.

### XMPP as a gateway

This is where XMPP pays. The prior art is mature and all of it uses
the same shape: a **XEP-0114 component behind an existing Prosody or
ejabberd**, which handles s2s, certificates and dialback. Slidge (about
22.5K lines of Python; puppets as `contact-<id>@gw`, rooms as
`group-<id>@gw` with per-room MAM, roster and bookmarks pushed through
XEP-0356), biboumi (IRC channels as MUCs) and Spectrum2 (libpurple)
all deploy this way, and matrix-bifrost does Matrix to XMPP.

For MIMI: MIMI rooms are MUCs on the component, MIMI users are JIDs on
it, and XMPP users are `mimi://<gateway>/u/<escaped jid>` with leaves
the gateway holds. OMEMO could end at the gateway too, but the keys
would be the gateway's, so that is cosmetic and best left off. The
component needs MUC, MAM, disco and avatars but no c2s, SASL, stream
management or push, so it is about 60 to 70 percent of the front end's
size (*estimate*), and it reaches every federated XMPP user with no
setup on their side. **The best gateway in this note for effort
against reach.**

## 5. Delta Chat over IMAP and SMTP

**Plaintext is refused by default.** Since core 2.50.0 (2026-05-22)
`force_encryption` defaults to on (`src/config.rs:465-470`):
unencrypted messages are not downloaded (`src/imap.rs:1584-1588`), are
trashed if fetched (`src/receive_imf.rs:526-532`), and cannot be sent
(`src/chat.rs:2838-2843`). Chatmail relays reject unencrypted mail
(`chatmail/relay/README.md:10-16`). So a front end must give Delta Chat
OpenPGP mail.

That is possible: the agent would mint one OpenPGP key per MIMI peer,
held only by the agent, and sign and encrypt each message to the user
with it, carrying `Autocrypt` and `Autocrypt-Gossip` headers. Delta
Chat treats each new key as a key-contact (CHANGELOG 2.0.0), encrypts
its replies to those agent-held keys, and the agent decrypts them at
SMTP submission. Delta Chat removed verified status in 2.61.0, so
there is no green check to fake.

What the agent would implement (*estimates*): a single-folder IMAP
subset with IDLE and METADATA (1,500 to 2,000 lines); SMTP submission
(500); Delta Chat's MIME dialect for groups (`Chat-Group-ID`,
`Chat-Group-Member-*`), edits (`Chat-Edit`), deletes (`Chat-Delete`),
reactions (RFC 9078), attachments and read receipts (2,000); the
per-peer key store with rPGP (1,000). About 5,000 to 6,000 lines.

Push: Delta Chat stores an encrypted device token by `SETMETADATA
/private/devicetoken`, and the relay POSTs it to
notifications.delta.chat; push is on only if the server answers one of
the vendor METADATA keys (`src/imap.rs:1185-1321`). Whether the
notifier accepts posts from a host that is not a chatmail relay is
unverified.

**Fit.** Weak as a front end: a fake mail server and a fake OpenPGP
identity per peer, to show the user plaintext the agent already has. As
a **gateway** it is more natural: a real email domain with MX, DKIM and
Autocrypt, each MIMI user an address with a gateway-held key, MIMI
rooms as encrypted Delta Chat groups. Delta Chat users would see MIMI
users as ordinary contacts, and mail between Delta Chat and the gateway
stays encrypted on the wire; it is still decrypted at the gateway.
Prior art is bots on real relays (matterdelta, deltabot-cli), not
domain gateways. Reach is 1M+ Play installs.

## 6. Other servable systems: Zulip, Mattermost, Rocket.Chat, Tinode, Nextcloud Talk

These have open APIs, stock apps that take any server URL, and no
client-side encryption, so a front end is possible. Two things make
them weaker than §§2 to 4: the APIs are large, and push goes through a
vendor relay that wants the server registered.

- **Zulip.** Zulip Flutter (Apache-2.0) needs server 9.0 or later. The
  hard part is `POST /register`, whose initial state is large, then the
  `/events` long poll and the message, reaction, flags and upload
  endpoints (zulip.com/api). Streams and topics fit MIMI rooms
  awkwardly: one topic per room, or topics as threads. Push needs the
  server registered with Zulip's bouncer (free for 10 users or fewer;
  zulip.readthedocs.io, "Mobile push notifications"). 10,000 to 13,000
  lines.
- **Mattermost.** The app calls about 206 REST functions and knows
  about 86 WebSocket events (mattermost-mobile `app/client/rest`,
  `app/constants/websocket.ts`); perhaps 15 events and 40 endpoints are
  needed. The app refuses servers below 10.11 from October 2026
  (forum.mattermost.com). Push only through TPNS (free) or HPNS
  (licensed). 12,000 to 14,000 lines.
- **Rocket.Chat.** REST plus DDP. The app verifies an RS256-signed
  "supported versions" token against a built-in key, fetching one from
  Rocket.Chat Cloud if the server sends none
  (`app/lib/methods/getServerInfo.ts`), so a fake server lives on
  Rocket.Chat's goodwill. Push through the Cloud gateway with
  registration. Weak fit.
- **Tinode.** The smallest protocol here (hi, acc, login, sub, pub,
  get, set, del, note over WebSocket; github.com/tinode/chat
  `docs/API.md`), topics with access modes close to MIMI roles, 4,000
  to 6,000 lines. Push needs a TNPG token from Tinode's console.
  Tindroid refuses cleartext except to the emulator and trusts only
  system CAs. Reach is small.
- **Nextcloud Talk.** The chat API is documented and push goes through
  a free proxy (or UnifiedPush), but the app expects a whole Nextcloud
  (capabilities, user status, WebDAV shares for files). Weak fit.

As gateways, all five have bot or integration APIs, and Matterbridge
(7.6K stars, last push December 2024) bridges all but Tinode. A gateway
there is a bot beside a real server, posting as one account with name
prefixes, like marmot-bridge.md's relay mode. Cheap, low fidelity, and
useful only to a team that already runs one of them.

## 7. Systems that cannot be served

- **Stock apps with built-in servers or keys.** Telegram (data centres
  and RSA keys built in; teamgram needs patched clients), Signal and
  Molly (server fixed; Molly's server choice is planned under NLnet's
  Flatline, not delivered), Stoat (formerly Revolt; the Android app
  hard-codes `api.stoat.chat` in `Constants.kt`), Discord (and so
  Spacebar for its official apps). **Gateway only**: as a user bot or
  linked device (mautrix-telegram, mautrix-signal), with E2EE ending at
  the gateway and the network's terms of service against it.
- **Peer to peer, onion or blind relays.** SimpleX (relays are
  configurable but see only ciphertext; encryption is between clients),
  Session (onion swarms), Briar and Cwtch (Tor peer to peer), Jami
  (OpenDHT), Tox (DHT), Status (Waku), Berty (IPFS), Quiet (Tor), Keet
  (Holepunch), Ricochet Refresh (onion), Retroshare (friend to
  friend). There is no server to stand in for. The only shape is a
  peer node or bot on the user's host that relays into MIMI: SimpleX
  has a CLI WebSocket API for bots (AGPL), Tox has bot libraries. Each
  is a one-user bridge at best.
- **Wire.** Stock apps accept a custom backend by deep link
  (docs.wire.com, "deeplink"), but the clients do Proteus or Wire's
  MLS themselves, so the agent would have to be a whole wire-server
  and terminate that encryption, and push needs AWS SNS set up by
  Wire. Wire speaking MLS does not make a gateway end to end: Wire's
  delivery service, credentials and epochs are its own, so a gateway
  still holds leaves on both sides (inference).
- **Not servable at all.** Threema and Threema Libre (fixed servers;
  OnPrem is a separate product for organisations; the paid Threema
  Gateway API is the only door), Wickr (the consumer app ended in 2023;
  AWS Wickr is enterprise), Hush Line (a whistleblower tip line, not a
  chat).

## 8. How mimid would host a gateway

A gateway is a MIMI provider whose users are virtual: the server hosts
`mimi://<gateway>/u/<name>` for each remote person, and something holds
an MLS leaf, KeyPackages and consent for each of them.

**Reused as it is.**

- mimid-server for the gateway domain: it already hosts many users,
  issues their tokens (`mimid admin ... add-user`, `token`), runs hub
  and follower roles and talks to peers.
- mimid-agent-core: everything one user does (KeyPackages, join, send,
  edit, retract, consent, moderation). The crate has no runtime of its
  own and is meant to be embedded (lib.rs, "The crate has no UI ...").
- mimid-agent-store's records, change feed and front-end extension
  maps, as marmot-bridge.md §2.1 uses them.

**New.**

- **A multi-user host.** `Agent` is one user on one device, with its
  own state directory and database (agent-core lib.rs, "# State"). A
  gateway with thousands of virtual users needs either many `Agent`s in
  one process sharing a connection pool and one sync loop, or an
  `Agent` that holds several identities. Either way it is a new crate,
  about 2,000 to 3,000 lines (*estimate*), and it is the piece every
  gateway in this note and marmot-bridge.md's puppet mode (its §3.3)
  would share.
- **Provisioning.** Creating a virtual user the first time a remote
  person speaks or is invited, keeping its KeyPackages fresh, and
  retiring it.
- **Consent on behalf of others.** A MIMI user inviting
  `alice@xmpp.example` reaches the gateway's virtual user; the gateway
  has to ask Alice on her side (a presence subscription, a Matrix
  invite) before it accepts, or MIMI's consent means nothing.
- **Saying what it is.** Every member of a room sees a gatewayed user
  as an ordinary MIMI participant. Nothing in MIMI marks a leaf as
  held by a gateway for someone else. marmot-bridge.md's relay mode
  sidesteps this with one visible bridge member and names in the text
  (its §3.2); puppets need a marker, which is the same gap as N7 in
  nostr-comparison.md and the `bot_policy` gap in marmot-bridge.md
  §3.1. That is draft work, not just code.

**Relay or puppets.** Relay mode (one bridge user per side, names in
the text) is cheap, honest and already designed for Marmot; it suits
the bot-API systems of §6 and the peer bridges of §7. Puppets (one
virtual MIMI user per remote person) need the multi-user host and suit
the federated networks: XMPP and Matrix.

## 9. Recommendation

Build the IRC front end out for Goguma first: TLS and SASL PLAIN,
queries, chathistory, Web Push and read markers are about 2,500 to
3,500 lines over code that exists, and give one client on both Android
and iOS with push that no relay can read. Second, a Matrix front end
for `/v3/sync` clients (FluffyChat, Element Web, Cinny, Nheko, iamb),
with Element X's sliding sync and key service after it; it reaches the
largest set of good clients and has the simplest push. Do the store
work of §1.3 (replies, reactions, one-to-one rooms, attachment URLs,
history) before either, since every front end and the Marmot bridge
need it. For gateways, an XMPP component behind Prosody is the best
reach for the effort and a Matrix appservice the largest network, and
both wait on a multi-user host in mimid that marmot-bridge.md's puppet
mode would share. Skip XMPP and Delta Chat as front ends, the
vendor-push systems of §6, and everything in §7 except as one-user
bridges someone asks for.

## 10. Decisions (Mark, 2026-11-21)

Epics: mimid-i0id (IRC v2),
mimid-rvqk (Matrix), mimid-wmdj (XMPP), mimid-qqtk (store groundwork).

- **S1. A listener that is not loopback: yes.** The agent may open a TLS
  listener on an address the user names, off by default, with the same
  token, and it refuses to start without TLS. The docs suggest binding it
  to a WireGuard or Tailscale address.

  Amended for IRC by decision mimid-1wgh.92 (Mark, 2026-11-22): the plain
  `[irc] listen` takes any address and does not refuse to start without
  TLS, because the operator controls exposure with a firewall or a proxy.
  Authentication is unchanged and still required. S1 stands as written for
  every other listener, including the agent's HTTP endpoint for JMAP
  Chat.
- **S2. Queries and history in IRC: lift agent-frontends.md §7.2 and
  §7.6 for IRC v2.** Queries are one-to-one rooms, marked by a
  store-level `direct` flag; chathistory is served from the store.
- **S3. SASL in the IRC front end: yes.** Offer SASL PLAIN, carrying the
  agent token, and keep PASS. Update docs/irc-lessons.md to match.
- **S4. Push through vendor relays: on by default, minimal payloads.**
  Matrix pushes `event_id_only`, Palaver `private`, Goguma encrypted Web
  Push. The docs say what each relay sees. Each front end has its own
  off switch.
- **S5. Both second front ends:** Matrix first (without Element X at
  first), then XMPP.
- **S6. The multi-user host:** design it once now, in the bridge's
  puppet-mode section (marmot-bridge.md §3.3.6, shaped so an XMPP
  gateway fits), and build it after the bridge's relay mode works.
- **S7. Marking gatewayed members:** raise gateway-held leaves with the
  working group together with onBehalfOf. The draft goes to Mark first.

## 11. Uncertainties

- Palaver's status: the store lookup and page were empty on
  2026-11-21, which could be a regional or API artefact.
- Whether pushgarden.emersion.fr, p2.siacs.eu, Monal's app server,
  matrix.org's gateway and notifications.delta.chat accept senders they
  have not seen; none was tested.
- Whether Element X shows any recovery banner once its own
  cross-signing keys are stored, and the stable path of MSC4186.
- Monal and Siskin with a self-signed certificate or a `127.0.0.1`
  host; Siskin's source on GitHub is older than the store build.
- Zulip Flutter's handling of cleartext to localhost; FluffyChat's
  network security config.
- Textual v7 as shipped; The Lounge's full cap list (irc-framework not
  read).
- Install counts: Play tiers fetched once; Conversations' figure is a
  third-party estimate; most others are repository stars.
- Every line count is an estimate, compared with mimid-agent-irc and,
  for Matrix, continuwuity's files at `95392cc`.
- Peer-to-peer systems in §7 were described from their project pages,
  not their source.
