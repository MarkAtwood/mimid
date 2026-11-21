# purple-mimi: a libpurple protocol plugin for MIMI through mimid

Design note, 2026-11-21, for Mark's review. Epic mimid-s4oy, steps 1
(bead mimid-s4oy.1, §1) and 2 (bead mimid-s4oy.2, §2). Steps 3 to 8
wait for Mark's answer to §2.

The plugin lets Pidgin, and the other programs built on libpurple
(BitlBee, Spectrum2), use MIMI rooms through mimid. Step 2 asks what the
plugin talks to. frontend-auth.md §2.4 and §6.5 assume it talks JMAP
Chat to the agent; that is not decided, and §2 weighs it against four
other shapes.

Two things are fixed by earlier notes and are not reopened here:

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
| mimid | main at `7b0d496a` |

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
- **Recommendation (§2.9):** option (a), a plugin that is a JMAP Chat
  client of the user's mimid-agent, written in C against libpurple 2,
  with the purple side kept thin so a libpurple 3 port replaces only
  that. Meanwhile, document option (d), Pidgin's built-in IRC against
  the agent's IRC front end, which works today.

## 1. libpurple 2 and 3 today

### 1.1 Releases

- **2.x.** The last release is **2.14.14, 2025-01-23** (Discourse
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
  default), soju (new in Alpha 4), xmpp, zulip. **Finch is dropped** from
  Pidgin 3 for now.

### 1.2 Who ships what

| Where | libpurple |
|---|---|
| Debian 12 | 2.14.12 |
| Debian 13 (trixie), testing, sid | 2.14.14 |
| Ubuntu 24.04 | 2.14.13 |
| Ubuntu 25.04, 25.10, 26.04, 26.10 | 2.14.14 |
| Fedora 43, 44, 45, rawhide | 2.14.14 |
| Arch | **no longer in the official repositories** (archlinux.org finds nothing; when it moved is UNVERIFIED, about late 2025); AUR has `pidgin` 2.14.14, `libpurple-minimal` and `pidgin-hg` (Pidgin 3) |
| Homebrew | formula `pidgin` 2.14.14, libpurple inside it, no separate formula |
| MacPorts, FreeBSD, Gentoo, Alpine edge, openSUSE Tumbleweed | 2.14.14 |
| Flathub | `im.pidgin.Pidgin` 2.14.14; Pidgin 3 on Flathub Beta only |
| Windows | the pidgin.im installer, 2.14.14, **32-bit (i686) GTK2**; MSYS2 `mingw-w64-pidgin` (ucrt64, clang64, clangarm64); Chocolatey, Scoop |

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
  system, no-log, delayed, images, remote-send and so on). **It has no
  id.** So there is no edit, reaction, reply, retraction or read
  receipt, and no way to change a line once written. Inline images go
  through imgstore (`<img id="N">`).
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
  Mark owns the mimid side). No daemon to install, which is the one
  thing (b) does better.
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

**(a), in C, against libpurple 2.14, with (d) documented now.**

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

## 3. Open questions for Mark

1. **Which option.** (a) JMAP Chat to the agent, (b) embedded core, (c)
   a new local protocol, (d) no plugin, (e) IRC inside.
   Recommendation: (a), and write up (d) in agent.md now.
2. **Which libpurple.** Pidgin 3 is at Alpha 4 and packaged nowhere
   mainstream; 2.14.14 is everywhere. Recommendation: libpurple 2.14
   only for the first version, the purple glue kept in its own files,
   and a port to libpurple 3 when Pidgin 3 reaches beta.
3. **Language.** C, or C glue over a Rust backend (a2).
   Recommendation: C with json-glib, no Rust in the plugin.
4. **Repository and licence.** Bead mimid-s4oy.4 says a separate
   repository, MarkAtwood/purple-mimi. libpurple is GPL-2.0-or-later;
   mimid is Apache-2.0. Recommendation: a separate repository under
   GPL-2.0-or-later that shares no code with mimid (it only speaks JMAP
   to it), so the licences never meet.
5. **Login.** Loopback with the agent token, or an app password over the
   S1 TLS listener. Recommendation: one account setting, the agent's
   JMAP Session URL, with the password field holding the agent token or
   an app password, sent as Bearer; loopback first, TLS once
   frontend-auth.md steps 1 to 6 exist.
6. **Starting the agent.** Should the plugin start mimid-agent if none is
   running? Recommendation: no. The plugin connects to a running agent
   and says plainly when it cannot; agent.md documents a systemd user
   unit.
7. **Windows.** Pidgin 2 on Windows needs a 32-bit DLL, and the agent
   runs on Unix only (agent.md, "Starting and stopping").
   Recommendation: ship the Windows DLL for users whose agent runs on
   another machine, reached over S1's TLS listener; do not port the
   agent to Windows for this.

## 4. Uncertainties

- keep.imfreedom.org refused every request (HTTP 418, lockdown), so
  Pidgin's hg HEAD is not recorded; the Pidgin 3 facts come from the
  2.98.0 tarball and the Discourse announcements.
- When Arch moved libpurple out of its official repositories; BitlBee
  3.6's release date; whether Pidgin 2.x has an end-of-life date.
- Which IRCv3 capabilities Pidgin 2's IRC and Pidgin 3's `ircv3` and
  `soju` protocols request. Pidgin 2 was not run against the agent's
  IRC front end.
- Whether libpurple 2 keeps passwords in plain text in `accounts.xml`
  without a keyring plugin (from memory).
- Every line count and binary size is an estimate. The libpurple 3
  findings hold for 2.98.0 and may change with each monthly alpha.
