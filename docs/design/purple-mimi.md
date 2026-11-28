# purple-mimi: a libpurple protocol plugin for MIMI through mimid

Design note, 2026-11-21 and 2026-11-22, for Mark's review. Epic
mimid-s4oy: step 1 (bead mimid-s4oy.1, §1), step 2 (bead mimid-s4oy.2,
§2, decided by Mark in §3) and step 3 (bead mimid-s4oy.3, the design,
§5 to §13). Mark answered the design's open questions on 2026-11-22
(§3, decisions PQ1 to PQ12).

The plugin lets Pidgin, and the other programs built on libpurple
(BitlBee, Spectrum2), use MIMI rooms through mimid. It embeds the
agent's engine and is itself an MLS client of the user (decision P1,
§3), so it holds keys and plaintext in its own process, as the mobile
app of decision mimid-1wgh.39 does (§12.1).
frontend-auth.md §2.4 and §6.5 assumed JMAP Chat to the agent, which
does not apply here (§12.2).

- The CBOR live stream (binary-live-stream.md) is between the agent and
  its provider. It is not a local client protocol. The agent's local
  protocols today are JMAP Chat and IRC (agent.md), both over one
  plaintext store (agent-frontends.md).
- The agent is the MLS end and the only component that sees keys and
  plaintext (AGENTS.md crate map; decisions mimid-1wgh.38 and .39).
  client-survey.md S1 lets it listen on a non-loopback address with TLS,
  and frontend-auth.md gives each device an app password.

Values marked INVENTED are mine. Line counts marked *estimate* are
guesses against mimid-agent-irc (about 4,500 lines of Rust today) and
the plugins in §1.4. Nothing here was built or run against Pidgin.
Nothing was posted, starred, forked or commented on.

## Sources

Read on 2026-11-21.

| Source | Version read |
|---|---|
| Pidgin 3 | tarball `pidgin3-2.98.0.tar.xz` ("Alpha 4", 2026-10-30) from fastly.imfreedom.org/Pidgin3/; headers, meson files and `protocols/` read |
| libpurple 2 | `libpurple-dev` 2.14.12 (Debian 12), `prpl.h` and the other headers; 2.14.14 is the current release |
| keep.imfreedom.org (Mercurial) | **not read**: every request got HTTP 418, "site is in lockdown!". The hg HEAD hash is unknown; AUR `pidgin-hg` was at r43379 `30cf01b12439` on 2025-10-24 |
| github.com/pidgin/pidgin | `6cde379` (2026-09-27): a README pointing at keep.imfreedom.org; no code, no tags |
| IMF Discourse | announcements of 2.14.14 and each 2.9x release; "Pidgin 3 Development Phases" (#369, 2026-03-05); "Pidgin 3 MVP requirements" (#418, 2026-08-25); Alpha 4 notes (#445) |
| Repology, AUR, Flathub, Homebrew | 2026-11-21 |
| purple-discord | `d1a7f60`, 2026-11-19 |
| purple-gowhatsapp (branch `whatsmeow`) | `d655719`, 2026-11-21 |
| purple-signald | `aa48b7e`, 2024-07-21, archived |
| purple-presage | `eb332c1`, 2026-11-18 |
| purple-teams | `095fbe5`, 2026-11-19 |
| purple-googlechat | `e268cb3`, 2026-11-10 |
| purple-matrix | `2792d4d`, 2023-04-24 |
| slack-libpurple | `1115ec1`, 2025-07-26 |
| purple-mattermost | last commit 2022-06-27 |
| lurch (OMEMO); carbons | `f4a886c` 2024-10-27; `2fa542d` 2020-12-25 |
| bitlbee-discord | `607f988`, 2021-09-28 |
| Spectrum2 | `d07c06c`, pushed 2026-10-24 |
| mimid | main at `7b0d496a` (§1, §2); at `c060c22e` for §5 to §13 |
| libpurple 2 source | 2.14.12-1 `libpurple/account.c` and `libpurple/connection.c` from sources.debian.org, read 2026-11-22 |
| Debian 12 packages | `finch` 2.14.12-1, `libpurple0` 2.14.12-1 and `bitlbee-libpurple` 3.6-1.3, downloaded with `apt-get download` 2026-11-22, not installed |

Statements marked *from memory* were not checked against a source
today.

## Summary

- **libpurple 2** is what everyone has: 2.14.14 (2025-01-23) in Debian
  13, Ubuntu 25.04 and later, Fedora, Homebrew, MSYS2 and Flathub;
  Windows Pidgin is a 32-bit GTK2 build. Its protocol API has no message
  ids, edits, reactions, replies or read receipts. No 2.x release in 22
  months.
- **libpurple 3** is not released. Pidgin 3 is at Alpha 4 (2.98.0,
  2026-10-30), monthly snapshots "not for end users", packaged only in
  AUR, Flathub Beta and a Gentoo overlay. Its protocol API is a
  `PurpleProtocol` GObject with interfaces, and messages have ids,
  `edited`, `replying_to` and attachments, but there are no reactions or
  read receipts. The protocol API is meant to settle during alpha and
  freezes only at 3.0.0.
- **Decision (Mark, 2026-11-22, §3):** option (b). The plugin embeds
  mimid-agent-core and is the MLS client, a new device per Pidgin
  profile; it reaches the provider over mimid's live stream. One Rust
  library with a C ABI, under thin C glue for libpurple 2.14 and for
  libpurple 3, both from the start. Separate repository
  MarkAtwood/purple-mimi under GPL-3.0-or-later. Linux and Homebrew
  macOS first, Windows later.
- **Design (§5 to §13):** the library embeds mimid-agent-core and
  mimid-agent-store and runs tokio on its own threads; the glue drains
  one event queue on the GLib main loop. About 50 C functions, no
  callbacks into C. A state lock per account with a takeover handshake
  (§6).

## 1. libpurple 2 and 3 today

### 1.1 Releases

- **2.x.** The last release is 2.14.14, 2025-01-23 (Discourse
  announcement; Windows `pidgin-2.14.14-offline.exe`). None since. I
  found no stated end-of-life policy (UNVERIFIED either way). The lead
  developer wrote in "Pidgin 3 MVP requirements" (2026-08-25) that
  "Pidgin 2's days on Wayland are getting shorter and shorter."
- **3.x.** Every release so far is a pre-release, numbered 2.9x:

| Version | Name | Date |
|---|---|---|
| 2.90.0 | Experimental 1 | 2024-12-31 |
| 2.90.1 | bug fix | shortly after (date UNVERIFIED) |
| 2.91.0 | Experimental 2 | 2025-04-01 |
| 2.92.0, 2.92.1 | Experimental 3 | 2025-07-01 |
| 2.93.0 | Experimental 4 | 2025-09-30 |
| 2.94.0 | Experimental 5 | 2026-01-01 |
| 2.95.0 | Alpha 1 | 2026-03-31 |
| 2.96.0 | Alpha 2 | 2026-07-01 |
| 2.97.0 | Alpha 3 | 2026-10-01 |
| 2.98.0 | Alpha 4 | 2026-10-30 |
| 2.99.0 | Alpha 5 | scheduled 2026-11-26 |

  Releases are now monthly, on the last Thursday. Alpha 4's notes call
  it a "timed development snapshot, not for end users… Most things are
  not implemented", and ask packagers not to package it.
- **API stability** ("Pidgin 3 Development Phases"): the experimental
  releases promised nothing. Alpha aims to settle the protocol-plugin
  API ("minor tweaks", no rewrites), though history and logging are
  still open. Beta settles the UI API. Only 3.0.0 freezes API and ABI
  until 4.0. No date is given for beta or 3.0.0.
- **Pidgin 3 build** (2.98.0 `meson.build`): meson 1.1 or later, C17,
  GLib 2.82, GTK 4.10, libadwaita 1.8, libsoup 3, json-glib, GPlugin
  0.44.x, and IMF's own birb, seagull (storage), hasl (SASL) and, for
  IRCv3, ibis 0.20. In-tree protocols: bonjour, demo, ircv3, sip (off by
  default), soju (new in Alpha 4), xmpp, zulip. Finch is dropped from
  Pidgin 3 for now.

### 1.2 Who ships what

| Where | libpurple |
|---|---|
| Debian 12 | 2.14.12 |
| Debian 13 (trixie), testing, sid | 2.14.14 |
| Ubuntu 24.04 | 2.14.13 |
| Ubuntu 25.04, 25.10, 26.04, 26.10 | 2.14.14 |
| Fedora 43, 44, 45, rawhide | 2.14.14 |
| Arch | no longer in the official repositories (archlinux.org finds nothing; when it moved is UNVERIFIED, about late 2025); AUR has `pidgin` 2.14.14, `libpurple-minimal` and `pidgin-hg` (Pidgin 3) |
| Homebrew | formula `pidgin` 2.14.14, libpurple inside it, no separate formula |
| MacPorts, FreeBSD, Gentoo, Alpine edge, openSUSE Tumbleweed | 2.14.14 |
| Flathub | `im.pidgin.Pidgin` 2.14.14; Pidgin 3 on Flathub Beta only |
| Windows | the pidgin.im installer, 2.14.14, 32-bit (i686) GTK2; MSYS2 `mingw-w64-pidgin` (ucrt64, clang64, clangarm64); Chocolatey, Scoop |

libpurple 3 is packaged only in AUR `pidgin-hg`, Flathub Beta and a
Gentoo overlay. On 2026-06-13 several AUR Pidgin plugin packages
(pidgin-cmds, pidgin-kwallet and others) were found to carry malware
(Discourse), so Arch users of a plugin we ship would get it from AUR or
from our own releases.

### 1.3 The plugin APIs

**libpurple 2** (`prpl.h`, 2.14.12):

- A plugin is a `PurplePluginInfo` registered by
  `PURPLE_INIT_PLUGIN(name, init, info)`, whose `extra_info` points at a
  `PurplePluginProtocolInfo`: a struct of function pointers.
- The ones a chat protocol fills in: `status_types`, `login`, `close`,
  `send_im(gc, who, msg, flags)`, `send_typing(gc, name,
  PurpleTypingState)` (`PURPLE_NOT_TYPING`, `PURPLE_TYPING`,
  `PURPLE_TYPED`), `set_status`, `chat_info` and `chat_info_defaults`
  (the fields of the join dialog), `join_chat(gc, GHashTable *)`,
  `chat_invite`, `chat_leave`, `chat_send(gc, id, msg, flags)`,
  `roomlist_get_list`, `send_file` and `new_xfer` (PurpleXfer).
- A message is an HTML string with `PurpleMessageFlags` (send, receive,
  system, no-log, delayed, images, remote-send and so on). It has no
  id, so there is no edit, reaction, reply, retraction or read receipt,
  and no way to change a line once written. Inline images go through
  imgstore (`<img id="N">`).
- Plugins write what is missing as text. purple-discord writes
  `EDIT: <text>` as a new line and `<name> reacted with "<emoji>"`
  (libdiscord.c, near lines 2826 and 3344). purple-gowhatsapp prefixes
  `[EDIT] ` and writes "removed their reaction to <quote>".
  purple-presage shows quotes and reactions as text, and sends a reply
  when a line starts with `@<search string>:`.
- A protocol must have a buddy list and status types; Pidgin shows the
  account offline without them.

**libpurple 3** (2.98.0 headers):

- A plugin is a GPlugin native plugin (`GPLUGIN_NATIVE_PLUGIN_DECLARE`,
  returning `purple_plugin_info_new(...)`; see
  `protocols/zulip/purplezulipplugin.c`) that registers a
  `PurpleProtocol` subclass with `get_default_account_settings`,
  `validate_account`, `can_connect_async` and `create_connection`.
- Behaviour comes from GObject interfaces: `PurpleProtocolConversation`,
  `PurpleProtocolContacts`, `PurpleProtocolRoster`,
  `PurpleProtocolFileTransfer`, `PurpleProtocolDirectory`,
  `PurpleProtocolWhiteboard`. The older 3.0 development API
  (`PurpleProtocolIM`, `PurpleProtocolChat`, `PurpleProtocolServer`) is
  gone.
- `PurpleProtocolConversation` is async/finish pairs:
  `create_conversation`, `leave_conversation`,
  `send_message(conversation, PurpleMessage *)`, `set_topic`,
  `get_channel_join_details` and `join_channel`, `set_avatar`,
  `refresh`, `set_title`, `set_description`, and `send_typing` with
  `PURPLE_TYPING_STATE_NONE`, `TYPING` and `PAUSED`.
- `PurpleConversation` has a type (`DM`, `GROUP_DM`, `CHANNEL`,
  `THREAD`, `COLLECTION`, `SPACE`), members with per-member typing
  state, topic, title and description each with an `editable` flag,
  badges, tags, `archived` and `federated`. A
  `PurpleConversationManager` holds them, stored through seagull.
- `PurpleMessage` has `id`, `author`, `contents`, `timestamp`, **`edited`
  and `edited_at`**, **`replying_to`** (a message id), `delivered` and
  `delivered_at`, **`attachments`** (`PurpleAttachment`: content type,
  file name, local and remote URI, size, inline), and action, notice,
  system, event and error flags. I found no call that replaces a
  message by id; `edited` is a property of the message object.
- **No reactions and no read receipts** in 2.98.0. The Zulip plugin has
  `/* GList *reactions; */` commented out
  (`protocols/zulip/purplezuliptypes.h:82`). The MVP list puts reactions
  at "not super high importance"; threads are "work started".
- Accounts use `PurpleAccountSettings` instead of option lists. Alpha 4
  added `managed` and `managed-by` account properties.
- The Pidgin 3 UI today shows an "(edited)" label and typing state, and
  has a file transfer window. I found no UI use of `replying_to`,
  `attachments` or `delivered` (grep of `pidgin/` in 2.98.0).

### 1.4 How third-party protocol plugins live

All of them target libpurple 2. Some of EionRobb's plugins (discord,
teams, googlechat, mattermost) have a `purple-3` build path, but it uses
the removed `PurpleProtocolIMIface` and its siblings, so they will not
build against 2.98.0 (my inference from the headers; not built).

| Plugin | Language | Last commit | Built and shipped | State |
|---|---|---|---|---|
| purple-discord | C | 2026-11-19 | Makefile; daily GitHub releases (.so, arm64 .so, .dll); Debian 13, sid, Ubuntu 26.04; AUR | active |
| purple-gowhatsapp | Go and C | 2026-11-21 | CMake or Makefile; nightly .dll and amd64/arm64 .deb | active; `go build -buildmode=c-archive` makes a static library that the C glue links into the plugin |
| purple-signald | C | 2024-07-21 | | archived; its README sends users to purple-presage because signald loses messages |
| purple-presage | Rust and C | 2026-11-18 | CMake; nightly .dll and .pdb | active; the Rust crate `purple-presage-backend` is a `staticlib` with hand-written `extern "C"` functions, presage pinned by git revision; the C side makes every libpurple call |
| purple-teams | C | 2026-11-19 | daily .so and .dll; AUR | active |
| purple-googlechat | C | 2026-11-10 | daily .so, .dll, .msi; Fedora 43; AUR | active |
| purple-matrix | C | 2023-04-24 | | not archived; README says "essentially unmaintained" |
| slack-libpurple | C | 2025-07-26 | AUR; has `debian/` | slow |
| purple-mattermost | C | 2022-06-27 | | idle |
| lurch (OMEMO) | C | 2024-10-27 | Debian sid, Ubuntu 0.7.0 | slow |
| carbons | C | 2020-12-25 | | idle |
| bitlbee-discord | C | 2021-09-28 | AUR | a native BitlBee plugin, not libpurple; idle |

The live ones each have one maintainer and CI that publishes a daily or
nightly .so and .dll on GitHub. They get a distro package only when a
Debian or Fedora packager picks them up. Windows users download the DLL
by hand into `%APPDATA%\.purple\plugins`.

### 1.5 Languages

- **C.** What libpurple and almost every plugin use. JSON through
  json-glib (purple-discord, purple-teams); HTTP and TLS through
  libpurple's own connection and SSL calls (*from memory*: several of
  EionRobb's plugins carry a copy of libpurple 3's `purple_http.c`,
  because 2.x has no general HTTP client).
- **Rust.** No maintained bindings. `purple-sys` 0.1.0 (2017),
  `libpurple-rust` 0.0.1 (2017), `purple-sys-flared` 0.0.7 (2021) and
  `purple-rs` 0.2.0 (2021) all target libpurple 2 and are idle; the one
  Rust protocol built on them (purple-icq) was last pushed in 2022. The
  pattern in use is purple-presage's: a C plugin over a Rust `staticlib`
  behind a hand-written C ABI. libpurple 3 generates `Purple-3.0`
  GObject introspection data, so gtk-rs style bindings could be
  generated, but none exist (crates.io search).
- **Go.** cgo `c-archive`, then the C glue is compiled into the plugin.
  On Windows this needs i686 MinGW gcc, because cgo does not use MSVC.
- **Threads.** Both bridges keep their own runtime (Go's, or tokio) on
  other threads and hand each event to the GLib main thread with
  `purple_timeout_add(0, ...)` on a heap copy (purple-gowhatsapp
  `bridge.c` near line 42, purple-presage `src/c/bridge.c` near line
  186). libpurple is called from the main thread only.
- **Windows builds.** Pidgin 2 on Windows is 32-bit, so plugins are i686
  DLLs: purple-gowhatsapp with MinGW gcc, purple-presage with MSVC 19.30
  x86, vcpkg static libraries and Rust (no Windows 7).

### 1.6 Programs that use libpurple, and what each shows

| Program | State | Rooms, invites | Edits, reactions, replies | Files | Typing | Read receipts |
|---|---|---|---|---|---|---|
| Pidgin 2 (GTK2) | maintained, no release since 2025-01 | yes | text only | PurpleXfer; inline images | IMs only | no |
| Pidgin 3 (GTK4) | Alpha 4 | yes | "(edited)" label; replies and reactions not shown | transfer window; attachments not shown | yes, per member | no |
| Finch | 2.x only; dropped from Pidgin 3 for now | yes | text only | PurpleXfer | IMs | no |
| BitlBee (libpurple mode) | last release 3.6 (about 2019, UNVERIFIED); repository pushed 2026-11-08; Debian, Ubuntu, Fedora, Homebrew | rooms as IRC channels | text only | limited (*from memory*) | IMs | no |
| Spectrum2 (XMPP gateway) | last release 2.2.1, 2023-06-12; pushed 2026-10-24; Debian sid and AUR only | rooms as MUCs | text only | | | no |
| Adium (macOS) | last release 1.5.10.4, 2017; 1.5.11 never shipped | | | | | |
| Instantbird, Thunderbird chat | Instantbird discontinued; Thunderbird dropped libpurple about 2018 (*from memory*) | | | | | |

In practice the audience is Pidgin 2 on Linux and Windows, plus BitlBee
users who want MIMI beside their other networks. On libpurple 2
everything beyond rooms, plain text, files and invites becomes text,
which is what mimid's IRC front end already does: `(edited)` lines,
reactions as ACTION lines, replies addressed `nick: `.

## 2. How the plugin talks to mimid

### 2.1 What the plugin needs from the other end

Whatever the protocol, the plugin needs: the list of rooms and their
members; history on join; new messages, edits, retractions and
reactions as they happen; send, reply, react, edit, retract; invites to
accept or refuse, and consent (allow, deny); attachments up and down;
read positions; and the agent's notices. The store already has each of
these as a record or a `Store` method
(crates/mimid-agent-store/src/action.rs: `send`, `edit`, `retract`,
`react`, `unreact`, `accept_invite`, `allow`, `deny`, `open_direct`,
`set_read_position` and the rest) and a change feed with sequence
numbers (agent-frontends.md §2). MIMI has no presence or typing, and
the JMAP front end sends neither; the plugin shows every contact as
available and sends no typing.

### 2.2 The options

**(a) JMAP Chat to the user's agent.** The plugin is one more JMAP Chat
client of mimid-agent: `Chat/get`, `Message/changes`, `Message/set`,
blob upload and download, and the agent's EventSource for changes. The
agent needs nothing new. On loopback the plugin uses the agent token;
from another machine it uses S1's TLS listener and an app password
(frontend-auth.md §4.2). The plugin sends Bearer itself, so it does not
need the agent to accept Basic, though Pidgin's username and password
fields suit Basic. Written in C: an HTTP/1.1 client and an EventSource
reader over libpurple's connection and SSL calls, and json-glib. A
variant, (a2), writes the JMAP side in Rust over crate-jmapchat-client as
a `staticlib`, the purple-presage pattern.

**(b) The plugin embeds mimid-agent-core.** A Rust `staticlib` with a C
ABI over mimid-agent-core and mimid-agent-store. The plugin is an MLS
device of the user, holds the keys in its own `mimid.sqlite`, runs the
journal and outbox, and reaches the provider over JMAP-MIMI or the live
stream. No daemon. This is the in-process shape decision mimid-1wgh.39
foresaw for mobile.

**(c) A new local agent protocol.** A small protocol of the agent's
own, JSON or CBOR frames over a unix socket or TCP, that serialises
store records and the change feed directly: a third front end beside
JMAP and IRC. All of it INVENTED, NOT FROM SPEC.

**(d) No plugin.** Document Pidgin's built-in IRC against the agent's
IRC front end (works today with PASS), and later its built-in XMPP
against the XMPP front end once mimid-wmdj exists.

**(e) The plugin speaks IRC to the agent.** A purple protocol of our own
that is an IRC client tuned to mimid's IRC front end: it reads `msgid`,
`+draft/reply` and `+draft/react` tags and drives `/msg mimid` commands
from purple's invite and consent dialogs.

### 2.3 Effort

| Option | Agent side | Plugin side | Total (*estimate*) |
|---|---|---|---|
| (a) JMAP, C | nothing | purple glue 2,000; HTTP, EventSource, JMAP calls and state 1,500 to 2,000 | 3,500 to 4,000 lines of C |
| (a2) JMAP, Rust backend | nothing | purple glue 2,000 C; Rust backend and C ABI 1,000 to 1,500 over crate-jmapchat-client | 3,000 to 3,500, in two languages |
| (b) embedded core | a C ABI crate over `Store` and `Agent`, 2,000 to 3,000 Rust, with `unsafe` (AGENTS.md forbids it at every crate root, so this crate needs an exception); the start-up the daemon does (KeyPackages, joining own rooms, the did:webvh log) moved behind the ABI | purple glue 2,000 C | 4,000 to 5,000, growing with every agent-core change |
| (c) new protocol | a front end like mimid-agent-irc without IRC's naming and line rules: 1,500 to 2,500 Rust, plus its spec | purple glue 2,000; framing and calls 700 C | 4,000 to 5,000 |
| (d) none | a section in agent.md, about 100 lines; XMPP waits for mimid-wmdj (9,000 to 10,000, client-survey.md §4) | none | about 100 now |
| (e) IRC inside | the IRC v2 items it relies on (mimid-i0id: queries, chathistory), plus tags for what IRC lacks (attachments, sending edits and retractions) | purple glue 2,000; IRC client 1,000 to 1,500 | 3,000 to 3,500, plus the agent work; each new feature done twice |

The purple glue is about the same in every option: account settings,
connect and disconnect, room list, chats, buddy list, invites, files,
and the text forms of edits, reactions and replies. Its size is a guess
against purple-discord, which does much more.

### 2.4 Crash safety

The store, journal and outbox belong to the agent (AGENTS.md,
mimid-agent row; agent-frontends.md §3 step 10). The question is which
process runs them.

- **(a), (c), (d), (e):** the agent, in its own process. If Pidgin
  crashes nothing is lost: an unsent message is either still in the
  plugin (the user sees it fail) or already in the agent's outbox. After
  a restart the plugin catches up from the agent. With (a), the JMAP
  state strings start again when the agent restarts (agent-frontends.md
  §2, "The JMAP projection"), so the plugin must handle
  `cannotCalculateChanges` by reloading; (c) can resume from the store's
  sequence number; (e) has no replay until IRC v2's chathistory.
- **(b):** the same journal and outbox code, run inside Pidgin. It is
  correct on a crash, since it is the code the daemon runs. But Pidgin
  itself, GTK or a third-party plugin can now abort the process in the
  middle of an MLS step, so the recovery paths run far more often; and
  messages are received only while Pidgin is open, so KeyPackages run
  out and Commits pile up while it is closed (the provider keeps them,
  but a long backlog takes longer to work through).

### 2.5 Several devices and clients at once

- **(a), (c), (d), (e):** one agent is one MLS device, and any number of
  clients follow the same store's change feed (agent-frontends.md §2,
  "The change feed"). Pidgin, an IRC client and a JMAP client can be
  open at once and agree, because they read one store. Pidgin on a
  second machine reaches the same agent over S1's TLS listener with its
  own app password.
- **(b):** every Pidgin profile is a new MLS device: a new leaf in every
  room, joined by external Commit (`Agent::join_own_rooms`), each with
  its own history from the moment it joined. Beside the daemon on the
  same machine, that is two devices for one user. Two Pidgin processes
  on one state directory would corrupt it, so the plugin needs a lock
  file. BitlBee and Spectrum2 load one plugin for many users, so each
  account there is a device too, with its keys on the BitlBee or
  Spectrum2 host.

### 2.6 Packaging

- **(a) in C, (c), (e):** a small `.so` or `.dll` that needs only
  libpurple, GLib and json-glib, built with meson or a Makefile,
  GPL-2.0-or-later like libpurple. It fits Debian's and Fedora's rules
  as purple-discord does, and builds as a 32-bit MinGW DLL as EionRobb's
  CI does. The agent is packaged separately and must be running.
- **(a2):** the plugin carries a Rust `staticlib` with tokio, reqwest and
  rustls: a few megabytes (*estimate*), cargo vendoring for distro
  packages, and an i686 Rust target for Windows (`i686-pc-windows-gnu`
  or `-msvc`, as purple-presage does). Whether crate-jmapchat-client is
  on crates.io, which distros need, I did not check.
- **(b):** as (a2), with all of mimid's agent side inside: OpenMLS,
  rusqlite with bundled SQLite, the crypto providers; 10 to 20 MB per
  platform (*estimate*). The mimid crates are `publish = false` and
  depend on crate-jmap by path, so no distro could package the plugin
  before those are published. mimid is Apache-2.0, which can be combined
  with GPL-3.0 but not with GPL-2.0-only; libpurple is GPL-2.0-or-later,
  so the plugin binary would go out under GPL-3.0 (not legal advice;
  Mark owns the mimid side). No daemon to install.
- **(d):** nothing to package.

### 2.7 Security, features, libpurple 3

**Where keys live and where end-to-end encryption ends.** In (a), (c),
(d) and (e) the keys stay in the agent and encryption ends at the
agent, as for every front end; the plugin sees plaintext over loopback,
or over TLS from another machine. In (b) the keys live in Pidgin's
process and in a database under Pidgin's profile: readable by every
other plugin Pidgin loads, written into any core dump, and on Windows
in a 32-bit process with whatever DLLs the user dropped into the plugins
folder. On a single-user desktop that is not much worse than the agent's
state directory, but it is a second place for keys, and AGENTS.md says
the agent is the only component that holds them. In (a), (c) and (e)
the agent token or app password is stored by libpurple 2 in
`accounts.xml` in plain text unless a keyring plugin is installed (*from
memory*); libpurple 3 has credential providers (libsecret, KWallet and
others). A stolen app password can be revoked (frontend-auth.md §3.7); a
stolen MLS key in (b) needs that device removed from every room.

**Features.** The JMAP front end carries everything the store has:
rooms, direct rooms, members, invites and consent, edits, retractions,
reactions, replies, attachments, read positions, notices. (b) and (c)
would have the same, (e) has what IRC v2 grows, and (d) has what each
stock plugin understands. libpurple 2 limits all of them the same way:
edits, reactions and replies become text, read positions are not shown,
typing and presence are absent. So on libpurple 2 the options differ
less in what the user sees than in cost, and (d) with Pidgin's IRC
already gives most of it: rooms, invites, text, `(edited)` lines,
reactions as ACTION lines, replies addressed `nick: `. What (a) adds
over (d): attachments as file transfers, history on join, invites and
consent through Pidgin's own dialogs instead of `/msg mimid`, direct
rooms as IMs, room names instead of channel names, and on libpurple 3
real edits, replies and attachments.

What Pidgin's own IRC does with the agent (*from memory*, not run):
libpurple 2's IRC asks for no IRCv3 capability except SASL, so it gets
no tags and sees the agent's text forms; its SASL needs a build with
Cyrus SASL, so PASS is the way in. Pidgin 3's `ircv3` protocol (on the
ibis library) and its new `soju` protocol may do better; I did not
check which capabilities they request.

**libpurple 3.** The purple glue is rewritten for libpurple 3 in every
option: the 2.x struct of callbacks and the 3.x GObject interfaces share
almost nothing. What survives the port is the layer below the glue: the
JMAP client in (a), the C ABI in (b), the framing in (c), the IRC client
in (e). The API is alpha and may still change in small ways each month;
waiting for beta to port costs nothing, since no distro ships 3. (b)
carries the most risk, because it moves with both libpurple and mimid's
agent internals; (a) and (c) move with libpurple and a wire protocol
that changes slowly; (d) moves with nothing of ours.

### 2.8 The options side by side

| | (a) JMAP to agent | (b) embedded core | (c) new local protocol | (d) no plugin | (e) IRC inside |
|---|---|---|---|---|---|
| Effort (*estimate*) | 3,500 to 4,000 lines of C | 4,000 to 5,000, C and Rust, with `unsafe` | 4,000 to 5,000, half in the agent | about 100 (docs) | 3,000 to 3,500, plus IRC v2 work |
| Crash safety | the agent keeps outbox and journal; plugin reloads after an agent restart | same code inside Pidgin; receives only while Pidgin runs | as (a), resumes by sequence number | as (a) | as (a); no replay before IRC v2 |
| Several clients | yes, one store | each Pidgin is a new device; needs a lock | yes | yes | yes |
| Packaging | small C plugin; agent separate | 10 to 20 MB of Rust inside; unpublished crates; GPL-3.0 binary | small C plugin; agent separate | none | small C plugin |
| Keys and end of E2EE | agent | Pidgin's process | agent | agent | agent |
| Features on libpurple 2 | all the store has, as far as purple shows it | same | same | IRC text forms; no files, no history | IRC's set |
| libpurple 3 port | glue only | glue and ABI | glue only | none | glue only |
| New interface to maintain | none | a C ABI | a protocol | none | mimid IRC tags |

### 2.9 Recommendation

**Not taken: Mark chose (b) (decision P1, §3).** Step 2's
recommendation is kept as the record of what was weighed. The costs it
names for (b) (keys inside Pidgin, a device per Pidgin, the binary
size, the `unsafe` code, a plugin that moves with agent-core) are the
costs §5 to §13 design for.

The recommendation was **(a), in C, against libpurple 2.14, with (d)
documented now.**

- (a) needs nothing new in the agent, keeps the agent the only MLS end,
  lets Pidgin run beside every other client on one store, and packages
  like the plugins distros already carry. Its protocol is the one mimid
  already treats as its standard local API.
- (b) is the only option without a daemon, and it pays for that with
  keys inside Pidgin, a new device per Pidgin, the largest binary, an
  `unsafe` crate, and a plugin that changes whenever agent-core does. If
  an in-process binding is built for mobile (mimid-1wgh.39), (b) could
  reuse it later; that is not a reason to start here.
- (c) gains a resumable feed and a simpler plugin, at the cost of a
  third protocol with one client. JMAP's `cannotCalculateChanges` after
  an agent restart is its only real gap, and agent-frontends.md §2
  already plans state strings from the store's sequence numbers, which
  closes it for every JMAP client.
- (e) inherits IRC's limits and needs mimid-specific IRC tags for what
  IRC lacks; it is worse than (a) at about the same size.
- (d) costs nothing and works today, so it should be written up in
  agent.md whatever is decided, as "Pidgin and BitlBee with the IRC
  front end".

C rather than (a2)'s Rust: libpurple 2's main loop, json-glib and its
SSL calls are enough for a JMAP client over loopback or TLS, and a C-only
plugin is what Debian, Fedora and Windows users can install. Rust would
bring crate-jmapchat-client's types, but also tokio inside Pidgin, a
thread hand-off for every event, and vendoring.

## 3. Decisions (Mark, 2026-11-22)

P1 to P7 are recorded on bead mimid-s4oy.2 and PQ1 to PQ12 on
mimid-s4oy.3, both closed with them. P1 to P7 replaced the seven open
questions of step 2; PQ1 to PQ12 the twelve of the design, and each but
PQ7 is the recommendation its question made.

- **P1. Option (b), embedded core.** The plugin embeds mimid-agent-core
  through a C ABI and is the MLS client: each Pidgin profile is a new
  device of the user.
- **P2. Both libpurple 2.14 and libpurple 3, from the start.** Two glue
  layers over one core.
- **P3. Thin C glue over a Rust library with a C ABI**, one glue for
  libpurple 2 and one for libpurple 3.
- **P4. A separate repository, MarkAtwood/purple-mimi, under
  GPL-3.0-or-later.** mimid stays Apache-2.0.
- **P5. The plugin talks to the provider over the binary live stream**
  (binary-live-stream.md), so it works with mimid providers only. The
  provider's bearer token goes in the account's password field. Each
  Pidgin is a device with its own Client record.
- **P6. A state lock per profile.** A second instance takes over, and
  the first disconnects cleanly. MLS state must not be corrupted: the
  first instance releases the state before the second writes to it.
- **P7. Linux and Homebrew macOS first.** The Windows i686 DLL is a
  step of its own, later.

- **PQ1. Embed both mimid-agent-core and mimid-agent-store** (§5.1).
- **PQ2. The state lock lives in mimid-agent-core's `StateDir`**
  (§6.2), so the daemon and every embedder take it. The takeover
  handshake (§6.3) is purple-mimi's.
- **PQ3. The token is kept in `<state>/provider-token` (0600)**, and
  libpurple's remembered password is cleared, on libpurple 2 and 3
  alike (§12.3).
- **PQ4. The account username is the handle `alice@a.example`**; a full
  `mimi://` URI is accepted too. The Provider URL defaults to
  `https://<domain>`, with an account option to override it (§8.1).
- **PQ5. `[n]` message numbers on libpurple 2**, on by default, with an
  account option to hide them (§8.7).
- **PQ6. Invites follow the daemon's default** (join invites from
  allowed users, ask for the rest), with an account option (§8.1,
  §8.11).
- **PQ7. Token listing and revocation are built in mimid-server before
  purple-mimi, as a prerequisite** (bead mimid-v9co, step 3p in §13;
  §12.5), not a bead outside the epic with no order.
- **PQ8. CMake calling cargo directly** (§10.1), so a distro build
  needs no network.
- **PQ9. A taken-over Pidgin 3 refuses its own automatic reconnect** and
  takes the account back only by an account action (§6.6).
- **PQ10. BasicCredential first**; a `did_webvh` log file as an account
  option in a later step (§5.7, §8.13).
- **PQ11. Shared BitlBee hosts are allowed**, and the README says what
  that means for the keys; purple-mimi does not try to detect them
  (§12.1).
- **PQ12. purple-mimi pins mimid by git revision**, with vendored source
  tarballs; crates.io is decided when a distro packager asks (§5.2).

## 4. Uncertainties

- keep.imfreedom.org refused every request (HTTP 418, lockdown), so
  Pidgin's hg HEAD is not recorded; the Pidgin 3 facts come from the
  2.98.0 tarball and the Discourse announcements.
- When Arch moved libpurple out of its official repositories; BitlBee
  3.6's release date; whether Pidgin 2.x has an end-of-life date.
- Which IRCv3 capabilities Pidgin 2's IRC and Pidgin 3's `ircv3` and
  `soju` protocols request. Pidgin 2 was not run against the agent's
  IRC front end.
- ~~Whether libpurple 2 keeps passwords in plain text in
  `accounts.xml` without a keyring plugin.~~ Checked on 2026-11-22: it
  does (§12.3).
- Every line count and binary size is an estimate. The ABI, the event
  set and the glue mappings are designs. The libpurple 3 findings hold
  for 2.98.0 and may change with each monthly alpha.
- *From memory*, not checked: std's file lock is `flock(2)` on Unix;
  `flock` over NFS on Linux; Pidgin 2's single-instance check and `-m`;
  Pidgin 2's reconnect delays; libpurple 2's user directory mode;
  `PURPLE_MESSAGE_SEND` on received lines; the `purple-3` pkg-config
  name; Homebrew's libpurple loading `.so` plugins on macOS; GLib
  versions in Debian 12 and 13; libpurple 2 on Windows watching only
  sockets.
- Not checked in libpurple 3 (2.98.0): whether the conversation view
  redraws an edited `PurpleMessage`; whether closing a tab calls
  `leave_conversation_async`; where `purple_data_dir()` points; whether
  a message can be removed from a conversation's view.
- The mimid GitHub URL in §5.2 is a guess.
- Every size and timing marked INVENTED or *estimate* is a guess. The
  takeover timings (1 s watch, 10 s grace, 30 s wait, 100 ms poll) are
  untested.

## 5. Architecture

Sections 5 to 13 are the design of step 3 (bead mimid-s4oy.3); their
statements marked *from memory* were not checked against a source on
2026-11-22.

### 5.1 What the library embeds

The Rust library embeds **mimid-agent-core and mimid-agent-store**, and
nothing above them.

- **mimid-agent-core** is the engine: MLS keys, groups, the journal, the
  outbox, the provider binding (`Binding::Stream`). It was built to be
  embedded: "no UI, no HTTP server and no runtime of its own" (its
  `lib.rs`; decision mimid-1wgh.39).
- **mimid-agent-store** is the plaintext layer every mimid front end
  shares. It is taken whole:
  - **Crash safety.** `Store::sync` is the agent's only journal
    consumer, and a sync's records commit in the same SQLite transaction
    as the agent's acknowledgement (`db.rs`, `Agent::acknowledge_in`).
    A purple-side store would have to rebuild that rule, and getting it
    wrong loses or doubles messages after a crash. Inside Pidgin crashes
    are more likely than in the daemon (§2.4).
  - **What the user sees.** History pages (`history.rs`), edits with
    their revisions, retractions and tombstones, reactions, replies
    (`inReplyTo` and its id), attachments (the blob store, fetch retries,
    safe file names), the agent's notices, disappearing messages
    (`expiry.rs`), direct rooms (`direct`, `open_direct`), read
    positions, bans, the invite policy, and `join_own_rooms` at each
    sync, which a new device needs. That is 9,400 lines of Rust already
    tested against the daemon.
  - **One behaviour.** The JMAP and IRC front ends sit on the same
    store, so purple-mimi behaves as they do, and bugs are fixed once.
  - **Its cost.** None beyond agent-core: the store adds `ulid`, `hmac`
    and SQLite, which agent-core's MLS store already brings. It depends
    on neither crate-jmap nor IRC code (its `Cargo.toml`).
- **Not embedded:** mimid-agent-jmap, mimid-agent-irc and the mimid-agent
  daemon (axum, jmap-server, the loopback listeners, the attachment-link
  HTTP route). Pidgin serves nothing.

What the daemon does around the store (about 200 lines of
`crates/mimid-agent/src/daemon.rs`: `sync_loop`, `expiry_loop`,
`top_up_key_packages`, `follow_stream`) purple-mimi needs too. Copying
it would be one more copy that "must stay in step", as `uri.rs` already
is. Step 3a (§13) moves it into mimid-agent-store as a runner that the
daemon and purple-mimi both call.

A thin purple-side store over agent-core alone would save no binary
size, since agent-core already brings SQLite and OpenMLS, and would
redo the crash rules above for one client.

### 5.2 Repositories and crates

- **mimid** (Apache-2.0) is unchanged in shape. purple-mimi depends on
  it by git revision: `mimid-agent-core` and `mimid-agent-store` from
  `https://github.com/MarkAtwood/mimid` at a pinned `rev` (INVENTED: the
  remote's URL is my guess; the crates are `publish = false`).
  purple-mimi's workspace must repeat mimid's `[patch.crates-io]` for
  the OpenMLS fork (Cargo applies only the top workspace's patches), at
  the same revision; a CI check compares the two.
- **MarkAtwood/purple-mimi** (GPL-3.0-or-later):

  | Path | What | Language |
  |---|---|---|
  | `core/` (crate `purple-mimi-core`) | the runtime, accounts, the state lock and takeover (§6), the event queue, the purple front end over the store (§5.6), text forms and command parsing | Rust, `#![forbid(unsafe_code)]` |
  | `ffi/` (crate `purple-mimi-ffi`, `staticlib`) | the C ABI (§5.5) and nothing else: argument checks, conversions, `catch_unwind` | Rust; the only `unsafe` |
  | `include/purple-mimi.h` | the C header, generated by cbindgen (pinned) and committed; CI fails when it is stale | C |
  | `purple2/` | the libpurple 2.14 glue (§8) | C |
  | `purple3/` | the libpurple 3 glue (§9) | C |
  | `tests/` | the C ABI test program, the libpurple 3 headless host, the end-to-end scripts (§11) | C, shell, Python |

  One CMake build makes two plugins from the same static library:
  `libpurple-mimi.so` for libpurple 2 and `libpurple3-mimi.so` for
  libpurple 3 (names INVENTED). §10 has the build.

### 5.3 Where state lives

One state directory per MIMI account in a purple profile:

- libpurple 2: `<purple_user_dir()>/mimi/<handle>/`,
  `~/.purple/mimi/alice@a.example/` by default, or under the directory
  of `pidgin -c` / `finch -c`.
- libpurple 3: `<purple_data_dir()>/mimi/<handle>/`. Which directory
  `purple_data_dir()` names on each platform I did not check.
- `<handle>` is the account's handle (§8.1), percent-encoded where a
  file name cannot hold a character. The library computes the path from
  the base directory and the user URI (`mimi_state_dir_for`, §5.5), so
  both glues agree.

The directory is mimid-agent-core's state directory, unchanged: mode
0700, `mimid.sqlite` (0600) with the MLS keys, groups, journal, outbox
and the store's records, and `blobs/`. purple-mimi adds three files
(§6, §12.3): `lock`, `takeover` while a takeover is asked for, and
`provider-token`.

A purple 2 profile and a purple 3 profile are different directories,
so a user running Pidgin 2 and Pidgin 3 has two devices. Two Pidgins on
one profile share one device, which is what the lock of §6 is for.

### 5.4 Threads

libpurple is single-threaded: every libpurple call happens on the
thread that runs its main loop, the GLib main loop in Pidgin and Finch,
BitlBee's own loop in BitlBee. purple-presage and purple-gowhatsapp
already run another runtime beside it and hand events over (§1.5).

- **One tokio runtime per process**, multi-threaded with 2 worker
  threads (INVENTED), named `mimi-rt`, started by `mimi_init` and shared
  by every MIMI account in the process. Every async call into the store
  and the agent runs there.
- **The main thread never waits on the runtime.** User actions are
  requests: the C call checks its arguments, queues the work, and
  returns at once with a request id; the result comes back as an event.
- **The main thread may read records directly.** The store keeps every
  record in memory behind a `std::sync::Mutex` that is never held
  across an await (`Store::state`, `store.rs`). Reading rooms, messages
  and history from the main thread takes that lock for a copy and
  nothing else. The agent's async lock is never taken from the main
  thread: a sync can hold it for seconds.
- **Events go one way, through one file descriptor.** The library has
  one process-wide queue of events (§5.5). When it goes from empty to
  not empty, the runtime writes one byte to a pipe (a non-blocking
  `pipe(2)`; `eventfd(2)` on Linux MAY be used). The glue watches the
  read end, `purple_input_add` on libpurple 2 and `g_unix_fd_add` on
  libpurple 3, and on wake-up drains the pipe and takes every queued
  event with `mimi_next_event`. The runtime never calls into C and never
  touches libpurple.

  A descriptor rather than `purple_timeout_add(0, ...)` from a foreign
  thread, which purple-presage uses (`src/c/bridge.c`): libpurple 2's
  event loop belongs to the UI. Pidgin's is GLib's, which is
  thread-safe, but BitlBee's and other UIs' are not documented as
  callable from another thread. Writing to a pipe is safe from any
  thread, and `purple_input_add` is called once, on the main thread.
  (Windows, §13 step 9, wakes through a loopback socket pair, since
  libpurple 2 on Windows watches sockets only, *from memory*.)
- **Logging.** A `tracing` layer turns the library's log events into
  `MIMI_EV_LOG` events, which the glue writes with `purple_debug_*` on
  the main thread. The level is set with `mimi_set_log_level`. Secrets
  stay out of logs as mimid's rule says (AGENTS.md "Secrets never reach
  logs"): a canary test captures the log of a full session and looks
  for the token, a key and message text.
- **Shutdown.** `mimi_shutdown` (plugin unload, which libpurple 2 does
  at quit) closes every account by the release path of §6.3, waits up to
  10 s (INVENTED) for them, then shuts the runtime down. That bound is
  the release path's own grace period (§6.3 item 8) and must not be
  shorter than it: a shorter one cuts a release in the middle of work the
  release path says it waits out. A process that exits sooner is a crash
  as far as the state is concerned, which the state survives (§6.4).

### 5.5 The C ABI

Rules for every function:

- **Thread.** Call it only on the thread that called `mimi_init`. A
  call from another thread returns `MIMI_ERR_WRONG_THREAD` and does
  nothing.
- **No panics across the boundary.** Every exported function runs its
  body inside `std::panic::catch_unwind` and returns `MIMI_ERR_PANIC`
  if it panicked. A panic in a runtime task is caught at its
  `JoinHandle`. After either, the account is poisoned: it is closed by
  the release path (§6.3), the glue gets `MIMI_EV_DISCONNECTED` with
  `MIMI_ERR_PANIC`, and its other calls return `MIMI_ERR_POISONED`. The
  profile keeps `panic = "unwind"` (the default); `catch_unwind` does
  nothing under `abort`.
- **No callbacks.** No C function pointer crosses the ABI. The library
  reports everything through events (§5.4).
- **Strings in** are `const char *`, UTF-8, NUL-terminated, borrowed for
  the call only; the library copies them. NULL where a string is
  required, or invalid UTF-8, is `MIMI_ERR_INVALID_ARGUMENT`.
- **Strings out** are UTF-8 and NUL-terminated. Text from peers can hold
  U+0000; the library replaces it with U+FFFD before it reaches C.
  Strings inside a returned struct belong to the struct and live until
  the struct's free function. A standalone string is freed with
  `mimi_string_free`. Nothing from the library is freed with `g_free`
  or `free`, and the library never frees memory it did not allocate.
- **Records are copies.** `mimi_room`, `mimi_message` and the others are
  snapshots taken under the store's lock, with no pointer into Rust
  state. The glue may keep them across main-loop iterations.
- **Handles.** `mimi_account *` is opaque. It is valid from
  `mimi_account_open` until `mimi_account_close`, after which no event
  names it.
- **Status codes.** Every fallible call returns `mimi_status` (`int32_t`)
  and, where it says so, sets `char **error` to a text for the user,
  freed with `mimi_string_free`. The codes are:

  | Code | Meaning |
  |---|---|
  | `MIMI_OK` (0) | done, or queued for a request |
  | `MIMI_ERR_ABI` | header and library versions differ |
  | `MIMI_ERR_WRONG_THREAD` | not the `mimi_init` thread |
  | `MIMI_ERR_INVALID_ARGUMENT` | NULL, invalid UTF-8, a value out of range |
  | `MIMI_ERR_NOT_CONNECTED` | the account is not open |
  | `MIMI_ERR_NO_SUCH_ROOM`, `_NO_SUCH_MESSAGE`, `_NO_SUCH_INVITE`, `_NO_SUCH_DEVICE` | as named |
  | `MIMI_ERR_NOT_PERMITTED` | the room's policy refuses it (`AgentError::NotPermitted`) |
  | `MIMI_ERR_REFUSED` | the hub refused it (`AgentError::Refused`) |
  | `MIMI_ERR_TOO_LARGE` | text or file past a limit |
  | `MIMI_ERR_NETWORK` | the provider could not be reached, or the stream failed |
  | `MIMI_ERR_UNAUTHORIZED` | the provider refused the token |
  | `MIMI_ERR_STREAM_OFF` | the provider does not serve the live stream (§7.1) |
  | `MIMI_ERR_WRONG_USER` | the token belongs to another user (§7.2) |
  | `MIMI_ERR_LOCKED` | another instance holds the state and did not release it (§6) |
  | `MIMI_ERR_TAKEN_OVER` | another instance took this account over (§6) |
  | `MIMI_ERR_LOCK_LOST` | the lock file was removed or replaced under us (§6.5) |
  | `MIMI_ERR_STATE` | the state directory or database cannot be used |
  | `MIMI_ERR_IO` | a local file could not be read or written |
  | `MIMI_ERR_PANIC`, `MIMI_ERR_POISONED` | see above |
  | `MIMI_ERR_INTERNAL` | anything else; the text says what |

  The library maps `AgentError`, `ActionError` and `SyncError` to these
  in one function, tested variant by variant.

The functions. *Process* calls take no account:

| Function | What it does |
|---|---|
| `uint32_t mimi_abi_version(void)` | the ABI version; the glue refuses to load on a mismatch with `MIMI_ABI_VERSION` from the header |
| `const char *mimi_version(void)` | library version and mimid revision; static, not freed |
| `mimi_status mimi_init(const mimi_init_options *, char **error)` | starts the runtime and the event queue; records the calling thread |
| `void mimi_shutdown(void)` | §5.4 |
| `int mimi_event_fd(void)` | the descriptor to watch for reading |
| `mimi_event *mimi_next_event(void)` | the next event, or NULL; drains the descriptor |
| `void mimi_event_free(mimi_event *)` | |
| `void mimi_string_free(char *)` | |
| `void mimi_set_log_level(int)` | |
| `char *mimi_state_dir_for(const char *base, const char *user_uri)` | §5.3 |
| `char *mimi_user_to_handle(const char *user_uri)`, `char *mimi_handle_to_user(const char *handle)` | §8.1; NULL when the form does not map |

*Accounts:*

| Function | What it does |
|---|---|
| `mimi_status mimi_account_open(const mimi_account_config *, mimi_account **out, char **error)` | checks the configuration and starts connecting in the background (§6.2, §7); the result is `MIMI_EV_CONNECTED` or `MIMI_EV_DISCONNECTED`. The config holds the base directory, user URI, provider URL, token (NULL: use the stored one, §12.3), invite policy, KeyPackage target, fallback sync interval, and `take_over` (§6.6) |
| `void mimi_account_close(mimi_account *)` | starts the release path (§6.3); the handle is invalid on return |
| `mimi_status mimi_account_get_info(mimi_account *, mimi_account_info **)` + free | user URI, handle, this device's Client id and key fingerprint, state directory. Not `mimi_account_info` (renamed 2026-11-22): C puts a typedef and a function in one namespace, so that name collides with the `mimi_account_info` struct and no glue compiles |

*Reads* (synchronous, from the store's records):

| Function | What it does |
|---|---|
| `mimi_rooms(acct, mimi_room_list **)` + free | every room not forgotten, with status |
| `mimi_room_get(acct, key, mimi_room **)` + free | name, subject (by, at), status, `direct` and the other user, participants with role names, local message expiry |
| `mimi_message_get(acct, key, mimi_message **)` + free | §5.6 |
| `mimi_history(acct, room, before_key, limit, mimi_message_list **)` + free | a page of `Store::history`, oldest first |
| `mimi_invites(acct, mimi_invite_list **)` + free | pending invites: number, room name, inviter |
| `mimi_person_get(acct, user_uri, mimi_person **)` + free | display name, DID if any |

*Requests* (each returns `MIMI_OK` and a `uint64_t` request id at once;
the result is `MIMI_EV_DONE` with that id):

| Function | Store call |
|---|---|
| `mimi_send_text(acct, room, text, reply_to_key, expiry, &id)` | `send`/`send_with` (reply, burn-on-read, expiry) |
| `mimi_send_file(acct, room, path, file_name, media_type, &id)` | reads the file on the runtime, then `send_message` with the attachment |
| `mimi_edit(acct, message, text, &id)` | `edit` |
| `mimi_retract(acct, message, &id)` | `retract` |
| `mimi_react(acct, message, reaction, &id)`, `mimi_unreact(...)` | `react`, `unreact` |
| `mimi_create_room(acct, name, users[], n, &id)` | `create_room`; result: the room key |
| `mimi_open_direct(acct, user, &id)` | `direct_room`, else `open_direct`; result: the room key |
| `mimi_change_members(acct, room, add[], n_add, remove[], n_remove, &id)` | `change_members` |
| `mimi_leave(acct, room, &id)` | `leave` |
| `mimi_set_subject(acct, room, subject, &id)` | `set_subject` |
| `mimi_kick`, `mimi_ban`, `mimi_unban` | `kick`, `ban`, `unban` |
| `mimi_accept_invite(acct, number, &id)` | `accept_invite`; result: the room key |
| `mimi_decline_invite(acct, number, &id)` | needs a store call that does not exist yet (§13, step 3a) |
| `mimi_allow(acct, user, &id)`, `mimi_deny(...)` | `allow`, `deny` |
| `mimi_list_devices(acct, &id)` | `devices`; result: a device list |
| `mimi_forget_device(acct, device_id, &id)` | `forget_device` |
| `mimi_mark_shown(acct, room, message, &id)` | `set_read_position`, and `mark_read` for disappearing messages (§8.11) |
| `mimi_save_attachment(acct, message, index, dest_path, &id)` | copies the blob to `dest_path` (0600, created new) on the runtime |
| `mimi_command(acct, room, line, &id)` | parses one slash command (§8.10) and runs it |

That is 51 functions, counting each free function. The header is about
400 lines (*estimate*).

*Events.* One struct, `mimi_event`: `kind`, `account` (NULL for
process-wide), and the fields its kind uses:

| Kind | Fields | When |
|---|---|---|
| `MIMI_EV_PROGRESS` | step, steps, text | while connecting (§7.3) |
| `MIMI_EV_CONNECTED` | | the account is open and its stream subscribed |
| `MIMI_EV_DISCONNECTED` | status, temporary (bool), text | connecting failed, the stream was lost (§7.4), takeover (§6), a panic |
| `MIMI_EV_DONE` | request id, status, text, result key, result list | a request finished |
| `MIMI_EV_ROOM` | change (added, changed, left, forgotten), room key | |
| `MIMI_EV_MESSAGE` | change (new, edited, retracted, deleted, expired, attachment ready), message key, room key | §5.6 |
| `MIMI_EV_REACTION` | added or removed, message key, reaction key, sender, reaction | §5.6 |
| `MIMI_EV_INVITE` | pending or gone, number | |
| `MIMI_EV_PERSON` | added or changed, user URI | |
| `MIMI_EV_RESYNC` | | the glue fell behind the change log (`TooOld`); it redraws from the records |
| `MIMI_EV_LOG` | level, text | §5.4 |

### 5.6 The purple front end over the store

purple-mimi-core registers one `Frontend` with the store
(`Store::add_frontend`), as the JMAP and IRC front ends do. Its
`before_save` turns the store's `Change`s into the events of §5.5. A
`Change` names a record, not what moved in it (`change.rs`), so for
`MessageChanged` the front end compares the record with what it last
reported, and reports the difference: a new revision is `edited`, a new
`deleted` is `retracted`, a reaction key not reported before is a
`MIMI_EV_REACTION` added, one gone is removed, an attachment that
became available is `attachment ready`. What it last reported is kept in
the record's `ext["purple"]` (the store's per-front-end map), so it
survives a restart and a takeover, and the second instance does not
report old edits again.

`ext["purple"]` also holds each message's number in its room (§8.7),
given in arrival order, and each room's next number.

`mimi_message` carries the record as the store has it (key, room,
sender URI and display name, times, body, body type, reply target key,
number, sender and an excerpt, revisions, deletion, notice kind,
attachments, reactions, expiry), plus two strings made in Rust for the
libpurple 2 glue:

- `html`: the body as libpurple 2 HTML, escaped (§12.4);
- `line_html`: the whole line libpurple 2 shows for the event, with the
  text forms of §8.6 to §8.8.

The text forms, the escaping and the diffing are Rust, tested in Rust;
the C glue only places lines.

### 5.7 What the library runs per account

The library's account task, on the runtime, does what the daemon does
(`Daemon::start` and `serve`), with the stream binding:

1. Take the state lock (§6.2).
2. `Agent::open` with `binding: Binding::Stream`, the provider URL, the
   token, the user URI and the state directory; `did_webvh` at its
   default (BasicCredential; decision PQ10).
3. Top up KeyPackages (`refresh_key_packages`, `publish_key_packages`,
   10 by default as in the daemon). The first publication makes this
   device's Client record (§12.5).
4. `Store::new(agent, invites)` with the blob store at
   `<state>/blobs`, `open_database`, `add_frontend` (§5.6).
5. Run the sync loop (`Store::sync`, which also runs
   `join_own_rooms`), woken by the stream (`Agent::stream_wake`), by any
   write, and every 30 s as a fallback; the expiry loop; the KeyPackage
   top-up after each sync; the takeover watch (§6.3).

Step 3a (§13) proposes moving step 5's loops out of the daemon into the
store crate, so both run the same code.

## 6. The state lock and takeover (P6)

### 6.1 What can go wrong without it

Two processes on one state directory each load the MLS groups into
memory (`Agent::load_members`) and both write `mimid.sqlite`. SQLite's
own locking keeps the file consistent, one transaction at a time, but
it does not stop the two processes from disagreeing about MLS state.
One process advances a group to epoch n+1 and deletes the secrets of
epoch n; the other still holds epoch n in memory, decrypts with it,
sends with it, or writes its view back. Both send under one leaf with
diverging epochs. The journal and outbox then hold entries made under
two different views. Some of this can be recovered by rejoining
(`recover_gaps`), and some of it cannot, such as a used one-time
KeyPackage private key or a Commit sent twice. So the rule is: **only
one process at a time has `mimid.sqlite` open, through any
connection**, and that process is the one holding the lock.

Pidgin 2 itself refuses a second instance when D-Bus finds another
libpurple client, unless started with `-m` (*from memory*). Finch,
BitlBee, Pidgin with `-m`, Pidgin 2 beside Finch on one `-c` directory,
and Pidgin 3 do not, so the lock is needed.

### 6.2 The lock

- The lock is an exclusive advisory lock on `<state>/lock` (created
  0600 if missing, never deleted), taken with `std::fs::File::try_lock`.
  On Unix, std implements it with `flock(2)` (*from memory*; std's file
  locking is stable since Rust 1.89); on Windows with `LockFileEx`.
  `flock` locks belong to the open file description, so two accounts in
  one process (BitlBee with two users on one MIMI account) exclude each
  other too.
- After taking it, the library checks that the path still names the
  file it locked (`fstat` of the descriptor against `stat` of the path:
  same device and inode). If not, someone replaced the file between
  open and lock; it closes and tries again.
- Only the holder opens `mimid.sqlite`. In code, the only way to build
  the account's `Agent` and `Store` is through a value of type
  `StateLock` that owns the locked file, and the release path (§6.3)
  drops every database connection before it drops the `StateLock`.
- State directories on network file systems are not supported: `flock`
  over NFS is emulated with byte-range locks on Linux (*from memory*),
  and SQLite advises against network file systems anyway.

The lock itself (the file, `try_lock`, the inode check) goes into
mimid-agent-core's `StateDir`, held for the life of the `Agent` and the
`Store` (decision PQ2). The daemon takes it too, so every embedder has
it, and a user who points mimid-agent at Pidgin's state directory gets
a clear refusal instead of corruption. The takeover protocol below stays
in purple-mimi.

### 6.3 Takeover

Instance A holds the account; instance B starts and wants it. Mark
asked that B take over and A disconnect cleanly, with A done before B
writes.

**B, connecting:**

1. Open `<state>/lock` and `try_lock`. If that succeeds (first use, or A
   has gone), go to item 5.
2. Write a takeover request: `<state>/takeover`, holding B's process id,
   the time and a random 128-bit nonce, written to a temporary file and
   renamed into place. One request file; a newer request replaces an
   older one.

   A request is **fresh** for the wait of item 3 plus 5 s (INVENTED), 35 s
   in all. A request older than that is stale, and whoever finds it
   ignores and deletes it. Without that rule a request left behind by a
   B killed between items 2 and 4 stays in the directory forever, and
   every later holder reads it as a live demand and releases the account
   the moment it takes it: one dead instance would make the account
   unusable for everyone after it (bead mimid-2vxv item 3). The rule is
   purple-mimi's own, as the takeover protocol is.
3. Poll `try_lock` every 100 ms (INVENTED) for up to 30 s (INVENTED).
   Show progress "Waiting for another instance to release this account".
4. If the 30 s run out: delete `takeover` if it still holds B's nonce,
   and fail with `MIMI_ERR_LOCKED`: "This account is open in another
   program that did not release it. Close it there, or stop that
   program." B never breaks the lock, never deletes `lock`, and never
   opens the database.

   The message names no process, and the holder writes no pid into the
   lock file (bead mimid-2vxv item 4; Mark decided against it, decision
   mimid-1wgh.90). `flock` is released when its process dies, so a
   crashed holder leaves no stuck lock and the account is free: a pid
   would label an error the user already understands, and acting on a
   reused pid is unsafe.
5. With the lock: check the inode (§6.2); delete `takeover` if it holds
   B's own nonce, and leave it if another nonce is there (a third
   instance asked after B; the watch in item 6 hands over to it).
   Then open the agent and the store (§5.7). SQLite rolls back any hot
   journal A left by crashing; that needs nothing from us.

**A, while it holds the lock:**

6. A watch task looks at `<state>/takeover` every second (INVENTED) and
   checks the lock file's inode at the same time (§6.5). A request with
   a nonce other than one A wrote itself, and fresh by item 2, starts the
   release; a stale one is deleted and nothing else happens.

**A, releasing** (also the path of `mimi_account_close`, plugin unload,
and a poisoned account):

7. Stop taking new work: requests for this account fail at once with
   `MIMI_ERR_TAKEN_OVER` (or `MIMI_ERR_NOT_CONNECTED` on a close).
8. Signal the account's loops to stop and wait up to 10 s (INVENTED) for
   the work in flight: the current `Store::sync`, requests already
   running, the expiry pass. Each of them ends at a transaction
   boundary.
9. When the 10 s run out, drop what is still running. Dropping a future
   in the middle of an operation is a crash of that operation: an open
   rusqlite `Transaction` rolls back when dropped, and the journal and
   outbox are built so that any cut point is consistent (§6.4).

   Items 8 and 9 are one call: `Runner::join_within(10 s)`, which waits
   the grace period out, aborts the loops still running and names them,
   and awaits each aborted task so that every loop has dropped its
   reference to the store before it returns, which is what item 10
   counts on. `Runner::join`, the daemon's, waits for ever: with it the
   store and its lock are held until the process exits (bead mimid-2vxv
   item 2). A loop stuck in a synchronous call cannot be cut even so,
   and item 10 reports it.
10. One last `Store::save`, then drop the `Store`, the `Agent` and with
    them both database connections (the agent's, which the MLS store
    shares, and the store's own; `db.rs`). The library then checks that
    it holds the last reference to each (`Arc::try_unwrap` in a short
    loop). If some task still holds one, A does not release: it reports
    `MIMI_ERR_INTERNAL` and keeps the lock, and B times out in item 4.
    A late release would be worse than a failed takeover.
11. `fsync` the state directory and `blobs/` (cheap; see §6.4).
12. Drop the `StateLock`: the lock is released.
13. Tell the glue: `MIMI_EV_DISCONNECTED` with `MIMI_ERR_TAKEN_OVER`
    and the text "This account was opened by another program using the
    same profile." The glue reports it to libpurple as a fatal error
    (§6.6).

A user action that was running when A released either finished (its
result was reported), or was cut at item 9. A message cut after it
entered the outbox is sent by B with the same bytes (the outbox rule,
AGENTS.md mimid-agent row); one cut before it is not sent. A reports
such requests as `MIMI_ERR_TAKEN_OVER` with the text "Not confirmed:
it may still be sent from the other program."

### 6.4 Why this keeps MLS state whole

- **Mutual exclusion** comes from the lock alone: B opens no
  connection to `mimid.sqlite` before it holds the lock (item 5), and A
  has closed every connection before it releases it (items 10 and 12).
- **No state lives only in A's memory.** `Agent::open` rebuilds
  everything from the database: groups (`load_members`), the sent
  digests (`restore_sent`), the Message state and the journal. What the
  agent keeps only in memory (`not_joinable`, `chat_rooms`, a deferred
  leaver) it also loses in a crash, which it is built to survive.
- **Every cut point is consistent.** Each received Message is handled
  in one transaction with its journal entries (`Agent::receive`, bead
  mimid-1vul.10); a sync's records commit with the acknowledgement; an
  outgoing message, Commit or external Commit is in the outbox before
  it is sent and is resent with the same bytes. mimid's crash tests
  (`mimid-agent-store/tests/crash.rs` and `send_crash.rs`, with the
  `fail-points` feature) cover these cuts. So item 9 needs no new
  recovery code: it is a crash of a few operations, which the state
  already survives.
- **Durability.** Between two processes on one host, B sees A's
  committed writes through the shared page cache whether or not they
  reached the disk, so the handoff itself needs no `fsync`. `fsync`
  matters for power loss. SQLite in its default rollback-journal mode
  with its default `synchronous = FULL` (the bundled build sets no other
  default; `libsqlite3-sys` 0.35 `build.rs`) syncs at each commit. The
  blob store syncs each blob before renaming it into place, but not the
  directory after (`blobs.rs`, near line 470), so item 11 syncs the
  directories once. A small mimid change MAY add the directory sync
  after each rename.
- **The provider sees one device.** A and B are the same device, with
  the same keys and the same Client record. A's stream connection ends
  when its `Agent` is dropped; B subscribes from the saved Message
  state. If A's connection lingers for a moment (its reader task waits
  for the server's close), it delivers to nothing. Step 3a (§13) proposes an
  explicit close in agent-core so that the tasks end at item 10.

### 6.5 When the lock is lost

`flock` is not taken away from a running process. A loses its lock only
if the lock file is deleted or replaced while A runs (by hand, by a
backup tool restoring the directory, by a profile copied over a live
one): B would then lock a new file at the same path while A still locks
the old one, and both would run. The watch of item 6 catches this
within a second: when the path no longer names A's locked inode, A
stops at once, without the grace period of item 8 (every extra write is
a risk now), drops the store and agent, and reports `MIMI_ERR_LOCK_LOST`:
"The state lock of this account was removed while it was in use; the
account was stopped. Check that no other program uses <path>." The
glue reports it as fatal. A second's overlap is possible in this case;
it needs someone deleting files under a running program, and the
message says so.

### 6.6 Not taking it back

A taken-over instance must not take the account back by itself, or the
two would alternate.

- **libpurple 2:** the glue reports `MIMI_ERR_TAKEN_OVER` with
  `purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NAME_IN_USE,
  ...)`. `NAME_IN_USE` is fatal (`purple_connection_error_is_fatal`,
  `connection.c` 2.14.12), so libpurple does not reconnect; the user
  reconnects by hand, which takes the account back. That is the rule
  Mark gave: the instance most recently connected by the user wins.
- **libpurple 3** (2.98.0) schedules a reconnect one minute after any
  disconnect of an enabled account, whatever the error
  (`purple_account_manager_schedule_account_reconnect`,
  `purpleaccountmanager.c`). So the library remembers, per state
  directory and per process, that this account was taken over. Later
  opens from this process then fail at once with `MIMI_ERR_TAKEN_OVER`,
  without writing a takeover request, unless `take_over` is set in the
  account config. The libpurple 3 glue sets it only from an account
  action, "Use this account here" (INVENTED label). The glue does not
  disable the account: the two instances share the profile's account
  store, and disabling it in A would disable it for B on its next start.

## 7. The live stream (P5)

### 7.1 The provider must serve it

purple-mimi uses `Binding::Stream` only. A provider serves the stream
only with `live_stream = true` (binary-live-stream.md §5.2; operating.md
`live_stream`, default `false`); without it, `/mimid/live` does not
exist and the WebSocket upgrade gets `404`. There is no fallback to JMAP
(§5.2 of that note).

On a `404` at the upgrade, the library fails the connection with
`MIMI_ERR_STREAM_OFF` and the text: "The provider at <url> does not
serve mimid's live stream. purple-mimi needs a mimid provider with
`live_stream = true`; ask its operator." It is fatal: reconnecting does
not help. agent-core reports it as `AgentError::StreamOff` (built in
step 3a).

The library does not read the JMAP Session first to look for the
`tag:reviewcommit.com,2026:mimid:live` capability: the stream "does not
depend on it" (§5.1 of that note), and it would add a JMAP client to the
plugin.

### 7.2 The hello

`ClientHello` carries the token from the password field (or the stored
one, §12.3). The `ProviderHello` answers with `userUri`, `roomIdPrefix`,
`hubSender`, the limits and the asset flags (CDDL in §5.11 of that
note). A bad token is `Error unauthorized` and a close: the library
reports `MIMI_ERR_UNAUTHORIZED`, fatal, "The provider refused the
token."

A token of another user would run that user's rooms under this
account's state, so `Agent::open` compares the hello's `userUri` (the
Session's on JMAP) with the configured user before it writes anything
to the state directory, and fails with `AgentError::WrongUser` (built in
step 3a); the library reports `MIMI_ERR_WRONG_USER`, fatal.

### 7.3 Connecting

Progress steps shown in the account's connection dialog
(`purple_connection_update_progress` on libpurple 2): "Locking state"
(and "Waiting for another instance", §6.3), "Opening state", "Connecting
to the provider", "Publishing keys", "Catching up". The account is
`CONNECTED` once the store is open and the first `Subscribe` was
answered; the first sync's messages then arrive as events.

### 7.4 Resume and reconnect

- **Resume** is the stream's: the agent subscribes from its saved
  Message state, and falls back to `after` per Chat on `cannotResume`
  (§5.5 of that note; `Stream::messages_since`). Nothing new in
  purple-mimi.
- **Loss of the connection while connected.** agent-core reopens the
  stream on the next call after it failed (`Stream::connection`). The
  sync loop makes that call at once (the loss wakes it). If the reopen
  fails, the library reports `MIMI_EV_DISCONNECTED` with
  `MIMI_ERR_NETWORK`, temporary, and closes the account by the release
  path.

  The library learns of it from the `AfterSync` hook it installs on the
  runner (`RunnerHooks::after`), which is handed each pass's
  `Result<&SyncReport, &SyncError>`; the runner itself only logs a
  failed sync (bead mimid-2vxv item 1). A single failure is not a lost
  connection: the sync retries at the next turn and nothing is lost
  either way, so whether to report one failure or a run of them is the
  library's, not the runner's. libpurple then reconnects by its own
  rules: Pidgin 2 with its increasing delay (*from memory*), Pidgin 3
  after a minute. While disconnected the user cannot send: sending needs
  the hub.
- **Rate limits** are the stream's: at most 16 requests outstanding per
  connection, and `rateLimited` with or without `retryAfter`, waited out
  by agent-core (1 s when absent, at most 30 s, three times;
  `Stream::call`). The store serialises the agent behind one lock, so
  purple-mimi has one request outstanding at a time in practice; it adds
  no limit of its own.
- **Limits stated in the hello** (`maxMessageBytes`, `maxRequestBytes`)
  bound attachments: `mimi_send_file` refuses a file over the smaller
  of the store's `MAX_ATTACHMENT_LEN` and `maxRequestBytes` before
  reading it, with `MIMI_ERR_TOO_LARGE`.

## 8. The libpurple 2 glue

C against libpurple 2.14 (`prpl.h`), protocol id `prpl-mimi` (INVENTED),
`PURPLE_INIT_PLUGIN`. About 2,500 to 3,000 lines (*estimate*).

### 8.1 Accounts

- **Username** is the user's handle, `alice@a.example`, which the
  library maps to `mimi://a.example/u/alice` (`mimi_handle_to_user`;
  INVENTED form: the part after the last `@` is the domain). A full
  `mimi://` URI is accepted too (decision PQ4).
- **Password** is the provider's bearer token, as `mimid admin ...
  token` prints it, one token per Pidgin (§12.5). After a connection
  succeeds the token is kept in the state directory and the remembered
  password is cleared (§12.3). `OPT_PROTO_PASSWORD_OPTIONAL` is set, so
  an account with a stored token connects with an empty password field.
- **Account options** (`protocol_options`): "Provider URL" (default
  `https://<domain>`, decision PQ4), "Join invites" (from allowed
  users / always / never; default from allowed users, as the daemon),
  "Show message numbers" (default on, §8.7), "Open rooms when a message
  arrives" (default on, §8.3), "Add rooms to the buddy list" (default
  on).
- **Status types:** available and offline, both user-settable, as
  purple-presage does (`src/c/status.c`); Pidgin shows an account
  offline without them (§1.3). `set_status` does nothing: MIMI has no
  presence.
- **Account actions** (`actions` in the plugin info): "Devices..."
  (§8.12), "Pending invites...", "About this device" (Client id, key
  fingerprint, state directory).

### 8.2 Connection state

`login` calls `mimi_account_open` and `purple_connection_set_state(gc,
PURPLE_CONNECTING)`; `MIMI_EV_PROGRESS` drives
`purple_connection_update_progress`; `MIMI_EV_CONNECTED` sets
`PURPLE_CONNECTED`. `MIMI_EV_DISCONNECTED` becomes
`purple_connection_error_reason` with:

| Status | `PurpleConnectionError` | Fatal in 2.14 |
|---|---|---|
| `MIMI_ERR_NETWORK` | `NETWORK_ERROR` | no |
| `MIMI_ERR_UNAUTHORIZED` | `AUTHENTICATION_FAILED` | yes |
| `MIMI_ERR_STREAM_OFF` | `INVALID_SETTINGS` | yes |
| `MIMI_ERR_WRONG_USER` | `INVALID_USERNAME` | yes |
| `MIMI_ERR_TAKEN_OVER` | `NAME_IN_USE` | yes |
| `MIMI_ERR_LOCKED`, `_LOCK_LOST`, `_STATE`, `_PANIC` | `OTHER_ERROR` | yes |

`close` calls `mimi_account_close`; the glue then forgets every map it
keeps for the connection.

### 8.3 Rooms as chats

- A room that is not direct is a chat. `chat_info` has one field,
  "Room" (a room name or room URI). `join_chat` with a room the store
  has opens it; with a name the store does not have, it asks "Create a
  new room named <name>?" (`purple_request_action`) and on yes calls
  `mimi_create_room`.
- `serv_got_joined_chat` opens the conversation with an int id the glue
  hands out per connection and maps to the room key. The title is the
  room's name (`purple_conversation_set_title`), the topic its subject
  (`purple_conv_chat_set_topic`, with `OPT_PROTO_CHAT_TOPIC`), the users
  its participants, with `PURPLE_CBFLAGS_OP` for holders of the admin
  role.
- **History on open:** messages since the room's read position, and up
  to 20 before it (INVENTED), from `mimi_history`, written with
  `PURPLE_MESSAGE_DELAYED` and the message's time.
- **Rooms not open.** libpurple 2 delivers chat messages only to an open
  chat. With "Open rooms when a message arrives" on, a new message opens
  its room, which then plays back from the read position. With it off,
  messages wait in the store, and the buddy-list entry shows nothing (I
  found no unread mark for chat nodes).
- `roomlist_get_list` lists the user's rooms (MIMI has no public
  directory). With "Add rooms to the buddy list", each active room gets
  a `PurpleChat` node in a group "MIMI" (INVENTED), as purple-discord
  adds its channels.
- **Closing is not leaving.** Pidgin 2 calls `chat_leave` when a chat
  window closes. In MIMI, leaving removes every device of the user from
  the room (`Agent::leave` limitations), so `chat_leave` only closes.
  Leaving is the command `/leave` (§8.10), which asks for confirmation.
- `RoomLeft` and `RoomForgotten` write a system line and mark the chat
  left (`serv_got_chat_left`).

### 8.4 Direct rooms as IMs

A room with `direct` set is an IM with the other user: received
messages through `serv_got_im` with `who` the other user's handle,
`send_im` through `mimi_open_direct` then `mimi_send_text`. The other
user is a buddy in the group "MIMI", alias their display name.
Buddies show as available (§8.1), since MIMI has no presence. A direct
room that gains a third member (MIMI allows it unless the room's policy
fixes the membership) becomes a chat from then on.

### 8.5 Messages

- Received: `serv_got_chat_in` or `serv_got_im` with the message's
  `line_html`, `PURPLE_MESSAGE_RECV`, and the hub's `acceptedAt` as the
  time.
- Own messages from another device of the user arrive as received
  messages from the user's own handle with `PURPLE_MESSAGE_SEND`, so
  Pidgin shows them as sent (*from memory*: `PURPLE_MESSAGE_SEND` on a
  received line is how purple-discord shows messages sent elsewhere).
- Sent: `chat_send` and `send_im` get HTML from the input box; the glue
  strips it to text (`purple_markup_strip_html`, then unescape), sends
  it as `text/plain`, and returns 0 so libpurple does not echo it; the
  store's `MessageAdded` for the own message writes it, so the line
  shown is the one stored.
- Each line shown calls `mimi_mark_shown` for the room's read position.
- A message over `MAX_TEXT_LEN` (16 KiB) is refused with a system line.

### 8.6 Edits and retractions (text)

libpurple 2 cannot change a line once written (§1.3). An edit is a new
line `(edited #12) <new text>` from the original sender; a retraction a
system line `#12 from bob was deleted.` Sending: `/edit 12 <text>` and
`/delete 12` (§8.10), allowed only on own messages (the store refuses
others').

### 8.7 Replies, and message numbers

To let the user name a message in a text-only window, each message gets
a number in its room, shown as a prefix `[12]` (INVENTED form) when
"Show message numbers" is on. Numbers start at 1 per room, follow
arrival order, and are kept in `ext["purple"]` (§5.6), so they hold
across restarts and takeovers. With numbers off, the commands still
work and `/history` shows them.

A received reply is shown `(reply to #12 bob: "first 60 characters...")
<text>` (INVENTED length). `/reply 12 <text>` sends one. This is the
IRC front end's idea with numbers instead of IRCv3 tags.

### 8.8 Reactions (text)

`MIMI_EV_REACTION` added becomes a system line `bob reacted 👍 to #12`,
removed `bob took back 👍 on #12`. `/react 12 👍` and `/unreact 12 👍`
send them (the store limits a reaction's length,
`MAX_REACTION_LEN`).

### 8.9 Attachments

- **Received:** when `attachment ready` arrives, a line `[file] #12
  report.pdf (120 KiB): /save 12` (INVENTED form). `/save 12 [n]` offers
  the file through a receiving `PurpleXfer` (`purple_xfer_request`):
  the user picks the destination, and the transfer's init function calls
  `mimi_save_attachment` to copy the blob there. purple-presage does
  the same with its own data (`src/c/receive_attachment.c`). The file
  name offered is the store's safe name (`content.rs`). Files are not
  offered automatically: a busy room would open a dialog per file.
- **Sent:** `send_file` (IMs) and `chat_send_file` (chats, in 2.14) make
  a sending `PurpleXfer`; its init function hands the chosen path to
  `mimi_send_file` and completes the transfer on `MIMI_EV_DONE`.
- Inline images (imgstore, `<img id>`) are left for later.

### 8.10 Commands

Registered with `purple_cmd_register` for `prpl-mimi` only
(`PURPLE_CMD_FLAG_PRPL_ONLY`), each forwarding its argument string to
`mimi_command`, which parses it in Rust:

| Command | Does |
|---|---|
| `/reply N text`, `/edit N text`, `/delete N` | §8.6, §8.7 |
| `/react N r`, `/unreact N r` | §8.8 |
| `/save N [i]` | §8.9 |
| `/history [count]` | writes older messages, with numbers |
| `/invite handle`, `/kick handle`, `/ban handle`, `/unban handle` | `change_members`, `kick`, `ban`, `unban`; `/invite` is also libpurple's own (`chat_invite`) |
| `/leave` | leaves the room for every device, after a confirmation |
| `/topic text` | libpurple's own; `set_chat_topic` calls `mimi_set_subject` |
| `/allow handle`, `/deny handle` | consent |
| `/burn text` | sends a burn-on-read message |
| `/expire duration` or `/expire off` | the room's local message expiry, as the IRC front end's `expire` |
| `/devices` | as the account action, as text |

### 8.11 Invites, consent, disappearing messages, notices

- **Invites.** `MIMI_EV_INVITE` pending becomes `serv_got_chat_invite`
  with the room's name, the inviter's handle and components holding the
  invite number. Accept calls `join_chat` with them: `mimi_accept_invite`.
  Decline calls `reject_chat`: `mimi_decline_invite`, which needs a
  store call that does not exist (step 3a). Invites the policy joins
  open no dialog; their rooms appear.
- **Consent.** The store surfaces no incoming consent request as a
  change (only invites, `Change::InvitePending`), and agent-core lists
  Consent records only on request (`Agent::consents`). The first version
  has `/allow` and `/deny` and buddy menu entries "Allow invites from"
  and "Deny" (`blist_node_menu`). Showing incoming requests as
  `purple_account_request_authorization` dialogs, which suit them, needs
  a store change and is left for later (§13).
- **Disappearing messages.** A message with an expiry is written with
  `PURPLE_MESSAGE_NO_LOG`, so Pidgin's conversation log does not keep
  what the store deletes, and with a prefix `(disappears in 1 h)`.
  Writing it to an open window counts as reading it, as in the IRC front
  end: `mimi_mark_shown` lets the store delete a burn-on-read message
  and start a delete-after-read clock. libpurple 2 cannot remove the
  line; it stays in the open window until it closes.
- **Notices** (lost messages, removals, identity changes; the store's
  `notice` kinds) are system lines (`PURPLE_MESSAGE_SYSTEM`).

### 8.12 Devices

"Devices..." requests `mimi_list_devices` and shows the list in a
`purple_request_fields` dialog: each Client record's id, its key's
fingerprint (the first 8 octets in hex, INVENTED), and "this device".
"Forget" on another device asks for confirmation, then calls
`mimi_forget_device`, which destroys its Client record and removes its
leaves from the rooms this device shares with it
(`Agent::forget_device`). The result lists the rooms where removal
failed. This device cannot be forgotten from itself.

### 8.13 What libpurple 2 does not get

Typing (MIMI has none; `send_typing` is NULL), presence, read receipts
(not adopted, mimid-1wgh.11.11), room renames (agent-core edits only the
subject), abuse reports (a later command), did:webvh credentials (a
later account option, decision PQ10).

## 9. The libpurple 3 glue

C against libpurple 3 (2.98.0 headers today; it follows each monthly
alpha), as a GPlugin native plugin registering a `PurpleProtocol`
subclass, as `protocols/zulip` does. About 2,500 to 3,500 lines
(*estimate*), more than libpurple 2 for the GObject boilerplate. The
API may change in small ways each month until beta (§1.1); the glue
tracks the latest alpha only.

| Area | libpurple 3 |
|---|---|
| Account | `get_default_account_settings` with "Provider URL" and the options of §8.1; `validate_account` checks the handle; the token comes from the credential manager (`purple_account_request_password_async`), then lives in the state directory (§12.3) |
| Connection | a `PurpleConnection` subclass whose connect starts `mimi_account_open`; errors as §8.2 with `PURPLE_CONNECTION_ERROR_NETWORK_ERROR`, `INVALID_SETTINGS` or `CUSTOM_FATAL`; the reconnect rule of §6.6 |
| Rooms | `PurpleConversation` of type `CHANNEL`, title the room name, topic the subject with its author and time, members as `PurpleConversationMember`s, the admin role as a badge |
| Direct rooms | type `DM` |
| Create, join, leave | `create_conversation_async` (DM or room with members), `join_channel_async` (a room by name or URI), `leave_conversation_async` asks for confirmation before `mimi_leave` (whether Pidgin 3 calls it on closing a tab I did not check) |
| Messages | `PurpleMessage` with `id` the store key, author, contents (plain text), timestamp; written with `purple_conversation_write_message` |
| Edits | the glue keeps a map from message key to its `PurpleMessage` and sets `contents`, `edited` and `edited_at` on it; the UI shows "(edited)" (§1.3). Whether the view redraws the new contents I did not check |
| Retractions | contents replaced with "(deleted)" and `purple_history_remove_message_async` for the old text |
| Replies | `replying_to` set to the parent's key; Pidgin 3 does not show it yet (§1.3), so the contents also carry the text form of §8.7 until it does |
| Reactions | none in libpurple 3 (§1.3): event messages with the text form of §8.8 |
| Attachments | a `PurpleAttachment` on the message (name, type, size, local URI once saved), plus the text line of §8.9, since Pidgin 3 does not show attachments yet; sending through `PurpleProtocolFileTransfer` |
| Commands | the same commands as `PurpleCommand`s, forwarded to `mimi_command` |
| Invites | libpurple 3 has no chat-invite request in 2.98.0 (I found none in its headers): a pending invite becomes a `PurpleNotification` and a DM-like conversation "Invitation to <room>" with `/accept` and `/decline`, until libpurple has one |
| Consent | later, as `PurpleAuthorizationRequest` notifications (accept is `allow`, deny is `deny`) once the store surfaces requests (§8.11) |
| Typing, presence | not implemented (`send_typing` left NULL); contacts' presence available |
| Disappearing messages | expiry removes the message from the history (`purple_history_remove_message_async`); whether a conversation can drop a message from its view I did not find (`PurpleMessages` has `add` only) |
| Devices | an entry in the connection's action menu (`purple_connection_get_action_menu`), and `/devices` |

## 10. Build and packaging

### 10.1 Build

- **CMake** (decision PQ8), calling cargo directly with
  `add_custom_command` to build `libpurple_mimi_ffi.a`, then compiling
  each glue into a shared module linked with it: about 40 lines of
  CMake (*estimate*), and a distro build needs no network but
  `cargo --offline` with vendored crates. Not Corrosion fetched at
  configure time, which purple-presage uses (`FetchContent`,
  `CMakeLists.txt`), and not Meson, which Pidgin 3 uses and whose cargo
  support is weak. libpurple 2 is found with `pkg-config purple`,
  libpurple 3 with `pkg-config purple-3` (*from memory* for the name).
  Either glue is optional: `-DPURPLE2=ON|OFF`, `-DPURPLE3=ON|OFF`.
- **Static linking.** The Rust library is a `staticlib` linked into
  each `.so` (Linux) or `.so` bundle (Homebrew's libpurple loads `.so`
  plugins on macOS too, *from memory*). The plugin then depends only on
  libpurple, GLib and the C library. SQLite is bundled (rusqlite
  `bundled`), TLS is rustls over aws-lc-rs (`aws-lc-sys` needs CMake and
  a C compiler at build time).
- **Symbol visibility.** A `staticlib` brings every exported Rust symbol
  and its whole standard library. The plugin exports only its entry
  point: `purple_init_plugin` for libpurple 2, GPlugin's `gplugin_query`,
  `gplugin_load` and `gplugin_unload` for libpurple 3. A linker version
  script on Linux (`-Wl,--version-script`) and
  `-Wl,-exported_symbols_list` on macOS hide the rest, so two Rust
  plugins in one Pidgin (purple-mimi beside purple-presage) do not
  resolve each other's symbols. `-Wl,--gc-sections` and a stripped
  release profile keep the size down.
- **Size.** About 360 crates in the tree (`cargo metadata` of
  mimid-agent-store, normal dependencies). 10 to 20 MB per plugin
  (*estimate*, as §2.6).
- **Toolchain.** Latest stable Rust, as mimid. Cargo.lock committed;
  mimid pinned by revision (§5.2).

### 10.2 Licences

- purple-mimi is GPL-3.0-or-later (P4): `COPYING` with the GPL-3.0 text,
  and a notice in each source file.
- The plugin binary contains, statically: mimid (Apache-2.0; its
  `NOTICE` must be carried, Apache-2.0 §4(d)), OpenMLS (MIT), SQLite
  (public domain), aws-lc (ISC, Apache-2.0, MIT, BSD-3-Clause; the
  `aws-lc-sys` 0.46 licence expression), `hpke-rs` (MPL-2.0, via
  OpenMLS), `minicbor` (BlueOak-1.0.0), `webpki-roots` (CDLA-Permissive
  2.0), and the rest under MIT or Apache-2.0 (counted from
  `cargo metadata`, 2026-11-22). All of these can be combined into a
  GPL-3.0 work (not legal advice). Whether any `hpke-rs` file carries
  MPL-2.0's "Incompatible With Secondary Licenses" notice I did not
  check.
- A `THIRD-PARTY-LICENSES` file is generated from Cargo.lock with
  cargo-about (pinned) at each release, and shipped beside the plugin;
  CI fails on a licence outside an allow list (cargo-deny).

### 10.3 Packages

- **Linux:** release tarballs with the `.so` files for x86_64 and
  aarch64 (as purple-discord ships), and a source tarball with vendored
  crates (`cargo vendor`). No distro package yet: the mimid crates are
  not on crates.io, which Debian and Fedora need. Later, once Mark
  decides about publishing them.
- **Homebrew macOS:** a formula in a tap of Mark's (INVENTED: a tap
  `markatwood/tap`), building from source against Homebrew's `pidgin`
  formula (which holds libpurple 2.14.14, §1.2). Homebrew has no
  libpurple 3, so macOS gets the libpurple 2 plugin only.
- **libpurple 3:** built from source by its users, who are on Pidgin 3
  alphas (AUR `pidgin-hg`, Flathub Beta). A Flatpak extension for
  Flathub Beta's Pidgin 3 is possible later.
- **Windows:** step 9 (§13).

## 11. Testing

- **Rust unit tests** in purple-mimi-core: the text forms and HTML
  escaping (hostile input per AGENTS.md: `<script>`, `&`, NUL, invalid
  surrogates from the codec, bidi and zero-width characters, 16 KiB
  lines), command parsing (every command, bad numbers, missing
  arguments), the handle mapping, the diffing front end (an edit, two
  reactions and a retraction in one save; a restart in between), error
  mapping, and the log canary.
- **Lock and takeover tests** across processes: a helper binary opens
  the account the way the library does. Cases: takeover with a running
  sync; takeover while a send is in the outbox (the message arrives
  exactly once); the owner stopped with `SIGSTOP` (the newcomer times
  out and never opens the database, which a test-only counter of
  database opens checks); the owner killed with `SIGKILL` (immediate
  takeover, hot journal rolled back); the lock file deleted under the
  owner (§6.5); three instances racing.
- **C ABI tests:** a C program calls every function with NULLs, invalid
  UTF-8, a wrong thread and a closed account, under AddressSanitizer
  and UndefinedBehaviorSanitizer, and under valgrind with Pidgin's
  suppressions file.
- **Providers:** two mimid providers with the live stream on, from
  `acceptance_fixture --two-providers`. Its test providers already set
  `live_stream = true` (`crates/mimid-agent/tests/common/mod.rs`), but
  the fixture prints its daemons' local tokens, not provider tokens.
  Step 3a adds a switch that starts the providers only and prints each
  provider's URL and fresh tokens for alice (twice: two devices) and
  bob (INVENTED name `--providers-only`).
- **libpurple 2 end to end:**
  - **BitlBee** (`bitlbee-libpurple` 3.6, in Debian 12) loads
    purple-mimi from its plugin directory and speaks IRC, so a test
    drives it with a scripted IRC client, no terminal needed: account
    add, rooms as channels, messages both ways across the two providers,
    invites, edits and reactions as text, `/save`.
  - **Finch** (`finch` 2.14.12, in Debian 12) in tmux, as the irssi
    checks were done (docs/irc-lessons.md): a smoke test of the UI
    paths BitlBee does not use (invite dialog, file transfer, buddy
    list), and the takeover test with two Finch processes on one `-c`
    directory.
  - **Pidgin 2** under Xvfb, by hand, once per release.
  The libpurple 2 packages are not installed on this host; tests run
  in a Debian podman container (podman is installed).
- **libpurple 3 end to end:** a headless test host. libpurple 3 builds
  without the GTK UI (`-Dgtkui=false`, `meson.options` of 2.98.0), and
  its own tests run against a test UI (`libpurple/tests/test_ui.c`). The
  host is a C program over that model: start the core, load
  `libpurple3-mimi.so`, add accounts, connect, create and join rooms,
  send and receive, and check `PurpleMessage` properties (`id`,
  `edited`, `replying_to`, attachments). It runs in a Debian 13
  container: libpurple 3 needs GLib 2.82, Debian 12 has 2.74, Debian 13
  has 2.84 (*from memory* for both GLib versions); GPlugin, birb,
  seagull and hasl come as meson subprojects. Not tried. Pidgin 3 from
  Flathub Beta, by hand, for what the UI shows. Not AUR `pidgin-hg`,
  after the AUR malware of 2026-06 (§1.2).
- **CI:** Linux (x86_64) builds both plugins and runs the Rust, ABI,
  BitlBee and headless libpurple 3 tests; macOS (Homebrew) builds the
  libpurple 2 plugin and runs the Rust and ABI tests.

## 12. Security

### 12.1 Keys in the Pidgin process

This is the price of (b), stated in §2.7. The MLS private keys, the
KeyPackage private keys and every plaintext message are in Pidgin's
memory and in `mimid.sqlite` under the profile:

- Every other plugin Pidgin loads can read them; so can anything that
  can attach a debugger to the user's processes.
- A core dump holds them. The library does not change the process's
  dump settings (`PR_SET_DUMPABLE`), since the process is Pidgin's.
  The README says so.
- BitlBee and Spectrum2 load one plugin for many users, so the host's
  operator holds every user's keys. The README says that purple-mimi
  on a shared BitlBee is end-to-end encrypted only as far as that host.
- AGENTS.md's crate map says mimid-agent "is the only component that
  sees" keys and plaintext. With purple-mimi, as with the mobile app of
  decision mimid-1wgh.39, an embedder does too; step 3a updates that
  row.

### 12.2 Credentials

The credential is the provider's bearer token, not an agent token or an
app password: frontend-auth.md's model is for clients of the agent and
does not apply. One token per Pidgin is advised (§12.5). The token goes
only into `ClientHello` over `wss` (or `ws` to a loopback provider in
tests); the library refuses a non-loopback `http://` provider URL
(INVENTED rule, as jmap-chat-js does for HTTP).

### 12.3 Where the token is kept

libpurple 2 writes a remembered password into `accounts.xml` in clear
text: `<password>` holds `purple_account_get_password` when "remember
password" is set (`account.c` 2.14.12, near line 395); an encrypted
password is only carried through from libpurple 3's format, never made
(near lines 400 to 420 and 905 to 926). Keyring plugins exist outside
libpurple.

So, after the first successful connection, the library writes the token
to `<state>/provider-token` (0600, like `mimid.sqlite` beside it, which
already holds the keys), and the libpurple 2 glue clears the remembered
password (`purple_account_set_remember_password(account, FALSE)` and an
empty password). Later connections use the stored token. A non-empty
password field that differs from the stored token replaces it (the user
pasted a new one). BitlBee keeps its own copy of the password in its
user files; that is BitlBee's, and nothing here changes it. On
libpurple 3, which has a credential manager with libsecret and KWallet,
the token is kept in the state directory the same way, so both glues
behave alike (decision PQ3).

### 12.4 What peers send

The plugin is now the client that renders, so the rendering rules that
AGENTS.md gives JMAP clients are purple-mimi's to keep:

- libpurple 2 renders messages as HTML. Every string from a peer (body,
  display name, room name, subject, file name, reaction) is escaped in
  Rust before it reaches the glue (`html`, `line_html`, §5.6); the glue
  passes no peer string to libpurple unescaped. Received bodies are
  `text/plain` to us whatever the sender's body type says, except
  `text/markdown`, which is shown as plain text too for now.
- Names from peers are wrapped in Unicode isolates (U+2068, U+2069) so
  a right-to-left name cannot reorder the line around it.
- File names offered for saving are the store's safe names
  (`content.rs`); the destination is the user's choice in the transfer
  dialog, and `mimi_save_attachment` creates the file new, without
  following a symlink at the last component.
- The sender shown is always the store's sender, which is the
  authenticated MLS sender (AGENTS.md).

### 12.5 Devices and file permissions

- Each Pidgin profile is a device with a Client record, made when its
  first KeyPackage is published (P5; draft-atwood-jmap-chat-mimi-00
  §Clients). It joins the user's accepted rooms by external Commit and
  reads only messages from its join on (`join_own_rooms` limitations).
  While Pidgin is closed it receives nothing and its KeyPackages may run
  out; the provider keeps what arrives.
- A lost laptop's device is forgotten from another device (§8.12). A
  stolen token is revoked at the provider: `mimid admin <cfg> tokens
  <userUri>` lists a user's tokens with their ids, names and last use,
  and `revoke-token <id>` revokes one at once and closes its
  connections. mimid builds this before purple-mimi, as a prerequisite
  (bead mimid-v9co, decision PQ7), so one token per Pidgin lets one
  device's token be revoked without touching the others.
- A provider MAY cap the clients per user (`maxClients` in the hello);
  a Pidgin past the cap cannot publish KeyPackages, and the library
  reports that the provider refused a new device.
- Files: the state directory 0700 and every file in it 0600, enforced by
  agent-core's `StateDir` (it refuses a directory others can reach);
  `<base>/mimi/` is created 0700 by the library. libpurple 2 makes its
  user directory 0700 (*from memory*).
- Pidgin's own conversation logs (`~/.purple/logs`, if logging is on)
  hold plaintext of what was shown; disappearing messages are kept out
  (§8.11), the rest is the user's choice in Pidgin's preferences.

## 13. Step plan

Effort in lines (*estimates*), no calendar time.

| Step | Bead | What | Lines |
|---|---|---|---|
| 3 | mimid-s4oy.3 | this design note | (docs) |
| 3p | mimid-v9co | **Provider token list and revoke, in mimid-server** (decision PQ7, §12.5): token ids, names and last use; `mimid admin <cfg> tokens <userUri>` and `revoke-token <id>` and their local routes; revocation at once, closing the token's EventSource and live-stream connections | (mimid) |
| 3a | mimid-s4oy.9 | **mimid groundwork, in mimid (Apache-2.0):** a typed error for a `404` stream upgrade (§7.1); `Agent::open` compares the hello's `userUri` (§7.2); `Store::decline_invite` (§8.11); the state lock in `StateDir`, which the daemon takes too (§6.2, decision PQ2); an explicit close of the stream tasks (§6.4); the daemon's loops moved into mimid-agent-store as a runner (§5.1); `acceptance_fixture --providers-only` (§11); AGENTS.md's mimid-agent row (§12.1); a tagged revision for purple-mimi to pin | 800 to 1,200 Rust with tests |
| 4 | mimid-s4oy.4 | **Skeleton**, in the new repository MarkAtwood/purple-mimi: workspace, CMake, cbindgen header; core: runtime, event queue, accounts, lock and takeover (§6), the stream connection and its errors (§7); ffi: the account and process functions; both glues load, connect, disconnect and report errors; CI on Linux and macOS | core 1,500 to 2,000; ffi 500 to 700; purple 2 glue 600 to 800; purple 3 glue 700 to 1,000; build and CI 300 to 400 |
| 5 | mimid-s4oy.5 | **Rooms and messages, libpurple 2:** the purple front end (§5.6), reads, requests, rooms as chats, direct rooms as IMs, history on open, invites, consent commands, topic, members, notices, devices, disappearing messages | core 1,200 to 1,600; purple 2 glue 1,200 to 1,600 |
| 6 | mimid-s4oy.6 | **Edits, reactions, replies, attachments, libpurple 2:** numbers, text forms, commands, file transfers | core 800 to 1,200; purple 2 glue 800 to 1,200 |
| 5b | mimid-s4oy.10 | **The libpurple 3 glue** for everything steps 5 and 6 have (§9), natively where libpurple 3 can; the headless test host | glue 2,000 to 2,800; host 500 to 800 |
| 7 | mimid-s4oy.7 | **End-to-end tests** (§11): BitlBee and Finch for libpurple 2, the headless host for libpurple 3, two providers with the live stream, the takeover across processes | 1,000 to 1,500 |
| 8 | mimid-s4oy.8 | **Packaging and release** for Linux and Homebrew macOS (§10.3), licence files, README; announce only with Mark's OK | 300 to 600, plus the README |
| 9 | mimid-s4oy.11 | **Windows i686 DLL** for Pidgin 2.14 (P7): `i686-pc-windows-gnu` or `-msvc` (purple-presage uses MSVC x86), `aws-lc-sys` on i686, `LockFileEx` and the socket-pair wake-up, the state under `%APPDATA%\.purple`, CI | 400 to 800 |

Order: 3p comes first, before 4 (decision PQ7). 3a and 4 can run in
parallel (4 pins a mimid revision from 3a before it needs the new
calls); 5 needs 4 and 3a; 6 and 5b need 5 (5b needs the core of 5, and
can run beside 6); 7 needs 5 and 5b for their halves; 8 needs 7; 9
needs 8. Step 6 also waits for epic mimid-qqtk (replies, reactions,
attachment URLs), as its bead says.

Total about 13,000 to 19,000 lines (*estimate*). §2.3's 4,000 to 5,000
for (b) counted one libpurple 2 glue and no tests; the difference is the
libpurple 3 glue, the takeover, and tests in three harnesses.

