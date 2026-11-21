# Front-end authentication: one credential model for every client protocol

Design note, 2026-11-21, for Mark's review. Epic mimid-e13m. It covers
how a stock client logs in to mimid-agent over each front end the agent
has or plans: IRC (mimid-i0id), Matrix (mimid-rvqk), XMPP (mimid-wmdj),
JMAP Chat (today's front end, and purple-mimi through it), and, for
completeness, IMAP for Delta Chat, which client-survey.md §5 does not
plan.

Mark's rule for this work (2026-11-21): "all of our other c2s
implementations need good enough, easy to use, not upsetting auth that
works with existing clients and users and ecosystems."

It builds on client-survey.md decisions S1 (a TLS listener on an
address the user names, off by default, the same token, no start
without TLS) and S3 (SASL PLAIN and PASS in IRC), both on branch
`store-groundwork`, not yet on main. Values marked INVENTED are mine and
open to change. Sizes marked *estimate* are guesses against
mimid-agent-irc (about 4,200 lines). Nothing here was built, run
against a client, or posted anywhere.

## Sources

Client and server source was shallow-cloned and read on 2026-11-21,
mostly the same commits as client-survey.md. Nothing was built or run.
File paths like `lib/client.dart:807` are in the client named in that
paragraph, at the commit below.

| Source | Version read |
|---|---|
| Goguma | 0.9.1+1365, `5aa7baa` |
| soju | `de8690c` |
| WeeChat | 5.0.0-dev, `30e63f1` (after 4.10.4) |
| irssi | 1.5-head, `43f1727` |
| HexChat | 2.16.2, `b544ac3` (archived) |
| Halloy | 2026.10, `a39117d` |
| The Lounge; irc-framework | 4.6.0-pre.2 `70db8bc`; irc-framework 4.14.0 `75a6824` (HEAD, not the commit The Lounge pins) |
| Textual | `9f6219f` |
| Conversations | 2.21.4, `513a741` |
| Monal | `0bde570` |
| Gajim; python-nbxmpp | 2.7.0 `760de28`; nbxmpp 7.5.0 `ea231d4` |
| Dino | `9f3a973` |
| Siskin IM; Martin | 7.4.0 `d77818f` (2024; the store has 7.4.1); Martin `6daa5f871bbbb4022d7c99f3108ae7345e8b46c1` |
| Profanity; libstrophe | 0.20.0 `a739c34`; libstrophe 0.14.0 `f549850` |
| Element X Android; matrix-rust-sdk | 26.11.1 `2d8d6cba`; sdk 0.19.1 `f4a94ad` |
| Element Web; matrix-js-sdk | 1.12.32 `a593205`; js-sdk 45.1.0 `ebbc952` |
| FluffyChat; matrix-dart-sdk | 2.11.6 `afe2da6e52c1d5b7063c2bb736c78aaabef45696`; dart sdk 17.0.0 `26016bc` |
| Cinny | 4.12.8 `24d8926` |
| Nheko; mtxclient | 0.12.1 `b15dcd1`; mtxclient 0.10.1 `f5766cb` |
| iamb | 0.14.0-alpha.1 `fbc4700` |
| Delta Chat core (chatmail/core) | 2.70.0-dev, `3027da4` |
| tailscale | 1.105.0, `1db8e79` |
| crate-jmapchat-client; jmap-chat-js; gurk-to-jmap (local) | `74d32a8`; `7789c2b`; `6f05569` |
| crates.io | instant-acme 0.8.5, rustls-acme 0.15.4, rcgen 0.14.10, argon2 0.6.0, rsasl 2.3.1 (2026-11-21) |
| mimid | main at `ca712fe2`; S1 to S7 from branch `store-groundwork` (`aeb548f6`) |

Statements marked *from memory* were not checked against a source
today.

## Summary

- **One credential model.** Each device gets a named **app password**:
  16 lowercase letters shown as four groups of four
  (`kqzv-trwm-hpaf-dnye`), 75 bits, the form Google and Apple already
  use. Any app password works on every front end. The existing
  `agent-token` becomes one more credential. Credentials are listed and
  revoked from a CLI, from `/msg mimid`, and over JMAP. Revoking one
  closes its open sessions and logs out its Matrix devices.
- **Stored as SCRAM verifiers.** XMPP clients want SCRAM, and SCRAM
  needs salted keys, not a password hash. So the agent keeps SCRAM-SHA-1
  and SCRAM-SHA-256 verifiers for every credential, made when the
  password is made, and checks plain logins (SASL PLAIN, PASS, HTTP
  Basic and Bearer, Matrix password login, IMAP LOGIN) against the same
  verifiers. An argon2id hash beside them would protect nothing more,
  because the weakest stored verifier sets the bar (§3.3, question 2).
- **Per protocol.** IRC: SASL PLAIN and PASS, with
  `soju.im/account-required`. JMAP: Bearer and Basic. Matrix:
  `m.login.password` issuing a per-device access token, no refresh
  tokens, never a soft logout. XMPP: SCRAM-SHA-256, SCRAM-SHA-1 and
  PLAIN over TLS, on SASL1 and on SASL2 (Monal uses SCRAM only over
  SASL2); FAST tokens; -PLUS with `tls-exporter` and
  `tls-server-end-point` later, and once offered, never withdrawn.
- **TLS, ranked.** (1) `tailscale cert` when the listener is on a
  tailnet; (2) ACME DNS-01, or certificate files the user already has,
  when the user has a domain; (3) a local CA the agent makes,
  name-constrained, with a setup page, as a last resort. No self-signed
  certificate with warnings by default.
- **Onboarding.** `mimid-agent <config> setup <client> <device>` makes
  an app password and prints what that client needs: an `ircs://` URL,
  a Matrix homeserver URL, an XMPP address, a JMAP Session URL, with a
  QR code where the client can read one.
- **Before IRC v2** (mimid-i0id): steps 1 to 5 of §9 (credential
  store, TLS core with files and tailscale, IRC SASL, IRC and CLI
  management, setup output). **Before Matrix** (mimid-rvqk): step 7
  (Matrix login and devices) and JMAP over the network (step 6).

## 1. Today

- The agent writes `<state_dir>/agent-token` on first start: 32 random
  octets as 43 characters of unpadded base64url, mode 0600
  (crates/mimid-agent/src/token.rs). `LocalToken::matches` compares in
  constant time.
- JMAP takes it as `Authorization: Bearer`, after a Host check that
  blocks DNS rebinding (crates/mimid-agent/src/http.rs `guard`,
  `host_allowed`). IRC takes it as `PASS`; the IRC crate gets a
  `PasswordCheck` closure from the daemon and never sees the token
  (crates/mimid-agent-irc/src/lib.rs, `PasswordCheck`;
  crates/mimid-agent/src/daemon.rs).
- Every listener must be loopback (crates/mimid-agent/src/config.rs,
  `ConfigError::NotLoopback`). There is no TLS, no SASL, no notion of a
  device, and no way to revoke one client without changing the token
  for all of them.
- AGENTS.md's boundary table has one row per agent boundary, each
  checking the same token. That stays true in shape: one check per
  boundary, now against the credential table.

## 2. What stock clients do

### 2.1 IRC

| Client | SASL mechanisms | Default | Sends PASS | Untrusted certificate | `ircs://` links |
|---|---|---|---|---|---|
| Goguma | PLAIN (and ANONYMOUS) | PLAIN when a password is given | No: the code can, no screen sets it | Dialog, "Accept Always" pins its SHA-1 | Android and iOS open them; host, port and nick only |
| WeeChat | PLAIN, SCRAM-SHA-1/256/512, EXTERNAL, ECDSA-NIST256P-CHALLENGE | PLAIN | If `password` is set | Refused (`tls_verify` on); `tls_fingerprint` pins | `/connect ircs://nick:pass@host`; the password becomes PASS |
| irssi | PLAIN, EXTERNAL, SCRAM-SHA-1/256/512 | none | If a password is set | Refused (`tls_verify` on); `tls_pinned_cert`, `tls_pinned_pubkey` | none found |
| HexChat | PLAIN, EXTERNAL, SCRAM (OpenSSL builds) | **PASS** is the default login method | With the PASS method | Per-network "accept invalid certificates"; no pinning | yes |
| Halloy | PLAIN, EXTERNAL | none | If `password` is set | `dangerously_accept_invalid_certs` or `root_cert_path`; no pinning | yes; user and password ignored |
| The Lounge | PLAIN, EXTERNAL | PLAIN | If a server password is set | Refused by default; no pinning | host, port, channel |

What matters for the agent:

- **Goguma shows a password field only when the server offers SASL
  PLAIN.** It hides the field when `!containsSasl('PLAIN')`
  (`lib/page/connect.dart:255,365`); a bare `sasl` cap counts as PLAIN
  (`lib/irc/caps.dart:50-61`). With `soju.im/account-required` or
  ISUPPORT `draft/ACCOUNTREQUIRED` the field is labelled "Password"
  instead of "Password (optional)" (`caps.dart:63`, `isupport.dart:51`,
  `connect.dart:256,368,386`).
- **Goguma's SASL username is the nick** on first connect
  (`connect.dart:86`); a separate username can be set only after a 904
  failure (`app.dart:90-101`). So the agent cannot insist on a
  username.
- **Goguma pipelines**: `CAP REQ sasl` and `AUTHENTICATE PLAIN` go out
  without waiting for the `CAP LS` reply (`lib/client.dart:510-546`).
- **Goguma drops a password in a URL.** `IrcUri.parse` reads
  `user:password@` (`lib/irc/uri.dart:29-61`) but the connect page fills
  only server and nick (`connect.dart:64-76`). No QR scanner in the app.
- **Goguma pins on accept**: issuer and SHA-1 in a dialog, the pin in
  its database (`client.dart:230-234`, `connect.dart:402-416`,
  `database.dart:22,34`).
- **HexChat defaults to PASS** (`servlist.h:68`), and if the `sasl=`
  value lacks its configured mechanism it silently skips SASL
  (`inbound.c:1866-1869`). PASS stays.
- **irc-framework sends the same password as both PASS and SASL
  PLAIN** when only a server password is set (`src/client.js:338-340`,
  `registration.js:446-452`). The Lounge turns that off; other users of
  the library may not. Both arriving must be fine.
- **WeeChat retries a failed SASL forever** by default
  (`sasl_fail = reconnect`, `irc-server.c:90`).
- **soju**, the bouncer Goguma is built for: one bcrypt password per
  user (`database/database.go:130-158`), plus per-device client
  certificates for SASL EXTERNAL (`doc/soju.1.scd:292-305`). It takes
  `user/network@client` in the SASL authcid and in USER
  (`downstream.go:1523-1547`), lets SASL win over PASS
  (`:1567-1597`), sends `FAIL * ACCOUNT_REQUIRED` or 464 with no
  credentials, and has **no rate limiting** on failed logins; a failed
  SASL leaves the connection open until a 30 s registration timeout
  (`downstream.go:884-890`, `server.go:42`). soju has no app passwords.
- **SCRAM**: WeeChat, irssi, HexChat and Textual do it; Goguma, Halloy
  and The Lounge do not. No IRC client found refuses PLAIN over TLS.

### 2.2 Matrix

| Client | Login flows it uses | Username it sends | Refresh token | On `M_UNKNOWN_TOKEN` | Certificate trust |
|---|---|---|---|---|---|
| Element X Android | OAuth if `/auth_metadata` answers, else `m.login.password`; QR login is OAuth only | the typed text, bare or full | not asked | ignores `soft_logout`; signs out and wipes its local store | Android store **including user CAs**; no override |
| Element Web | OAuth, password, SSO | the typed text | not asked | soft logout kept and re-login on the same device; else full wipe | browser |
| FluffyChat | OIDC, SSO, password; **goes straight to SSO if `/login` lists it** | typed text, plus the old `user` field | **asks for one** | refreshes on `soft_logout`, else clears the session | Android: system store plus bundled ISRG roots; user CAs probably not (*unverified*) |
| Cinny | password, SSO, `m.login.token` from a URL | localpart only | not asked; keeps one if given | wipes and reloads | browser |
| Nheko | password, SSO | localpart; the user must type a full `@user:server` | not asked | asks before deleting data | libcurl; a setting turns checks off |
| iamb | password, SSO, OAuth | full user id from its config | not asked | logs it; on restore failure, exits | `ssl_verify = false` setting |

What matters for the agent:

- **Element X logs in with a password when there is no OAuth.** Any
  error from `GET /_matrix/client/v1/auth_metadata` means "no OAuth"
  (matrix-rust-sdk `bindings/matrix-sdk-ffi/src/client.rs:569-589`);
  password login is used if `GET /login` lists `m.login.password`
  (element-x-android `LoginModePresenter.kt:89-98`). Its hard
  requirement is sliding sync in `/versions` (client-survey.md §3), not
  OAuth.
- **Element X replays the login password as UIA** to upload
  cross-signing keys right after login (matrix-rust-sdk
  `authentication/matrix/mod.rs:813-827`, `encryption/mod.rs:2255-2258`).
  The UIA stage must accept the same app password.
- **Nheko refuses a server whose `/versions` lists none of v1.1 to
  v1.10** (`src/LoginPage.cpp:153-196`). The agent lists v1.10 among its
  versions.
- **FluffyChat asks for `refresh_token: true`** (matrix-dart-sdk
  `client.dart:792`) and, if a server sends `soft_logout: true` with no
  refresh token, seems to stay stuck (`client.dart:333-334,2469-2475`,
  inferred). The spec lets a server ignore the request.
- **FluffyChat skips the password form when `/login` lists SSO**
  (`utils/sign_in_flows/check_homeserver.dart:42-75`). The agent lists
  only `m.login.password` (and `m.login.token`, below).
- **Usernames**: Element X and Element Web send what was typed, bare or
  `@user:server`; Cinny and Nheko send the localpart; iamb the full id.
  The agent takes all of them.
- **Discovery**: every client falls back from `.well-known/matrix/client`
  to the typed URL, and none requires it. A typed name without a scheme
  becomes `https://name` on port 443 (Element X `UrlUtils.kt:26-31`,
  Element Web `ServerPickerDialog.tsx:93-100`). Clients that start from
  a full user id (Element Web, FluffyChat, Nheko) look up well-known on
  its domain.
- **Login links**: QR login needs OAuth in every client
  (matrix-rust-sdk `authentication/oauth/qrcode/login.rs:133-146`,
  matrix-js-sdk `rendezvous/index.ts:42-58`). Cinny alone takes a login
  token by URL, `/login/<server>?loginToken=…` (`app/pages/paths.ts:17`,
  `TokenLogin.tsx:63-68`). Element X has a deep link carrying the server
  and a login hint, no secret (`DefaultLoginIntentResolver.kt:19-30`).
- **UIA**: a 200 without a challenge is fine for every client read; the
  Dart SDK fails a 401 challenge that has no `session`
  (`utils/uia_request.dart:53-56`).
- **Revocation looks like a remote sign-out.** Element X, Cinny and
  Element Web (without `soft_logout`) wipe their local store. That
  loses nothing: the agent holds the messages and the client has no
  keys of its own to lose (the agent is the encryption end).

### 2.3 XMPP

| Client | Mechanisms, most preferred first | PLAIN | SASL2 / Bind2 / FAST | Pins the mechanism | Untrusted certificate | Setup URIs |
|---|---|---|---|---|---|---|
| Conversations | EXTERNAL, SCRAM-512/256/1-PLUS, SCRAM-512/256/1, OAUTHBEARER, PLAIN | After TLS only | all three | **Yes** | Accept dialog, remembers the leaf; a name mismatch is fatal | `register;preauth`, `roster;preauth;ibr=y`, https invites |
| Monal | SASL2: SCRAM-512/256/1-PLUS, SCRAM-512/256/1. SASL1: **PLAIN only** | Only with "allow MITM-prone PLAIN"; off for good after one SASL2 login | all three; FAST `HT-SHA-*-EXPR` | **Yes** (SASL2) | System trust only | `register;preauth`, `roster;preauth` |
| Gajim | SCRAM-512/256/1, PLAIN (no -PLUS) | yes | SASL2 only | no | Unknown CA: can add it; name mismatch fatal | none for accounts |
| Dino | **SCRAM-SHA-1**, PLAIN | yes, TLS required | SASL2, Bind2 | no | **System CAs only, no dialog** | none for accounts |
| Siskin | SCRAM-256/1, PLAIN (no -PLUS) | yes | SASL1 only | no | System trust, or an accepted SHA-1 fingerprint | `register;preauth`, `roster;preauth` |
| Profanity | SCRAM-512/256/1-PLUS, SCRAM-512/256/1, DIGEST-MD5, PLAIN | only if nothing else is offered | SASL1 only | no | Prompt, `/tls always` | none |

What matters for the agent:

- **Monal's SASL1 is PLAIN only, and SCRAM only over SASL2.** If the
  server offers SCRAM over SASL2 Monal uses it; a server offering SCRAM
  over SASL1 alone fails with "No supported auth mechanism"
  (`Monal/Classes/xmpp.m:3667-3690`). Its simple login turns PLAIN on
  for any domain but three (`MLXMPPManager.m:817-818`); after one SASL2
  login PLAIN is off for good, and a server that later lacks SASL2 gets
  the account disabled with a MITM warning (`xmpp.m:2985-2988,3329-3335`).
- **Monal and channel binding**: offering -PLUS without a XEP-0440
  list, or a list with no type Monal knows, disables the account
  (`xmpp.m:3393-3407,2764-2774`). Monal knows `tls-exporter` (TLS 1.3
  only) and `tls-server-end-point` (`MLStream.m:812-818`). With no -PLUS
  and no list, SCRAM-SHA-256 over SASL2 works; the `<success>` needs an
  `<authorization-identifier>` (`xmpp.m:2994`).
- **Conversations pins the mechanism** by priority after the first
  login (`XmppConnection.java:898-900,1898-1911`): a later, weaker
  offer (dropping -PLUS, or tls-exporter to tls-server-end-point) fails
  as a downgrade attack. FAST is exempt (`:1895`). So whatever the agent
  offers it MAY add to later, and never take away.
- **Dino does SCRAM-SHA-1 and PLAIN only** (`xmpp-vala/src/module/sasl.vala:117-136`)
  and has no manual host setting, so the JID domain must resolve to the
  agent, and the certificate must chain to a system CA
  (`libdino/src/service/connection_manager.vala:386-394`).
- **The certificate must name the JID domain.** Gajim (`nbxmpp/tcp.py:163-166`),
  Dino, Monal (SNI is the JID domain even with a manual host,
  `MLStream.m:428-439`) and libstrophe (`tls_openssl.c:720-740`) check
  the JID domain; Conversations also accepts the manual hostname
  (`crypto/XmppDomainVerifier.java:107-141`). So the agent's XMPP domain
  is its TLS name (`alice@host.tailnet.ts.net`), not the MIMI domain.
- **No client takes a password from a URI or QR code** for an existing
  account. The setup URIs make a **new** account by in-band
  registration (XEP-0077) with a token: Conversations sends it in a
  `urn:xmpp:pars:0` `<preauth>` IQ (`xmpp/manager/RegistrationManager.java:224-232`),
  Monal uses `urn:xmpp:ibr-token:0` (XEP-0445) when offered
  (`xmpp.m:3356-3368`). In both the user picks the password (question 4).
- **No client needs SRV records**; all but Dino have a manual host and
  port. Conversations uses direct TLS on 443 or 5223 and STARTTLS
  elsewhere (`utils/Resolver.java:76-102`).

### 2.4 JMAP Chat and purple-mimi

- crate-jmapchat-client has `BearerAuth` and `BasicAuth`, and a
  transport that trusts a custom CA from DER (`src/auth.rs:41-60,117-210`).
- jmap-chat-js sends `Authorization: Bearer` and sends it only over
  HTTPS, or plain HTTP to a loopback host
  (`src/lib/jmap/session.ts:77-85,115`).
- gurk-to-jmap sends Bearer (`src/jmap.rs:59`).
- purple-mimi (mimid-s4oy, not written) will talk JMAP Chat to the
  agent, so it gets whatever JMAP gets; Pidgin's account dialog has a
  username and a password field, which suits Basic.

### 2.5 Delta Chat (IMAP), not planned

Delta Chat logs in with IMAP `LOGIN` only (`src/imap.rs:360-363`). Its
`dclogin:` QR code **does** carry a password:
`dclogin://user@host/?p=password&v=1`, with host, port, security and a
certificate-check setting (`src/qr/dclogin_scheme.rs:13-62`). Its
certificate checks can be set to accept anything, with no pinning
(`src/login_param.rs:37-60`). Recorded for completeness; client-survey.md
§5 rules Delta Chat out as a front end.

## 3. The credential model

### 3.1 What a credential is

A row in a new table in `mimid.sqlite` (INVENTED names):

| Field | Meaning |
|---|---|
| `id` | Integer, never reused. |
| `name` | What the user called it: `phone`, `laptop-weechat`. 1 to 32 characters of `[a-z0-9-]`, unique among unrevoked credentials. |
| `kind` | `app-password` or `agent-token`. |
| `scram` | For each of SCRAM-SHA-1 and SCRAM-SHA-256: salt (16 random octets), iteration count, StoredKey, ServerKey (RFC 5802 §3). |
| `created_at`, `created_by` | When, and from where (`cli`, `irc`, `jmap`, and the credential that asked). |
| `last_used_at`, `last_used_by` | The last successful login: time, front end, peer address. Written at most once a minute per credential (INVENTED) so busy HTTP clients do not churn the database. |
| `revoked_at` | Null until revoked. A revoked row is kept 30 days (INVENTED) so the listing can say "revoked", then deleted. |

At most 64 unrevoked credentials (INVENTED). That bounds the cost of a login
that has to try each one (§3.3).

Things that hang off a credential and die with it:

- Matrix devices and their access tokens (§4.3);
- XMPP FAST tokens (§4.4);
- open connections and sessions on every front end (§3.7).

### 3.2 The secret

**App password.** 16 letters from `a` to `z`, drawn from the OS RNG,
shown as four groups of four joined by `-`: `kqzv-trwm-hpaf-dnye`.

- Entropy: 26^16 is about 2^75.2.
- Lowercase letters only, so a phone stays on its first keyboard
  layer: no shift, no digits, no symbols. The hyphens are display only.
- Before checking, the agent lowercases what it was given and drops
  spaces and hyphens. `KQZV TRWM HPAF DNYE`, `kqzvtrwmhpafdnye` and the
  shown form all work. Google shows its app passwords in four groups of
  four with spaces, Apple with hyphens, so users have seen both.
- The secret is shown once, when it is made. The agent does not keep
  it.

Other forms considered:

| Form | Entropy | Typed length | Against it |
|---|---|---|---|
| 4×4 letters (chosen) | 75.2 bits | 16 | none worth naming |
| 4×4 Crockford base32 | 80 bits | 16 | digits mean switching keyboards on a phone |
| 6 words, EFF long list (7,776 words) | 77.5 bits | about 40 | long; phones capitalise and autocorrect words, though password fields usually turn that off |
| 7 words, EFF short list (1,296 words) | 72.4 bits | about 35 | same |
| today's 43-character base64url token | 256 bits | 43 | cannot be typed on a phone; case matters |

75 bits is far past what online guessing can reach at any rate limit in
§7, and past offline guessing against the stored verifiers at 4,096
PBKDF2 iterations (about 2^87 HMAC operations; *estimate*).

**User-chosen passwords: none.** The agent makes every secret. That is
what lets the storage in §3.3 be simple, and no one reuses a password
they never chose.

### 3.3 Storage

The agent stores SCRAM verifiers, not a password hash:

- XMPP clients prefer SCRAM, and some will not use PLAIN at all
  (§2.3). SCRAM's server side needs StoredKey and ServerKey, which come
  from PBKDF2 of the password with a salt. They can only be made while
  the plain password is in hand: when it is created. So the agent makes
  SCRAM-SHA-1 and SCRAM-SHA-256 verifiers for every credential from the
  first version, even before any front end offers SCRAM. Adding
  SCRAM-SHA-512 later would need every app password made again.
- For a login that carries the password itself (SASL PLAIN, PASS, HTTP
  Basic and Bearer, Matrix `m.login.password`, IMAP LOGIN), the agent
  runs the SCRAM-SHA-256 derivation on what it was given and compares
  the result with each unrevoked credential's StoredKey in constant time.
- Iterations: 4,096, the floor RFC 7677 sets and what many XMPP servers
  use (INVENTED as a choice; raising it slows every login that tries
  all 64 credentials).

**Why not argon2id as well.** The task asked for argon2id. An argon2id
hash beside the SCRAM verifiers would not make the stored data harder
to attack, since an attacker with the database tries the cheapest
verifier: SCRAM-SHA-1 at 4,096 iterations. It would make each login
slower, and a plain login has no way to name the credential, so the
check may run once per unrevoked credential. And an attacker who can read
`mimid.sqlite` already has the user's MLS keys and every message in
plaintext (agent.md, "Files"). The secrets are random, so a stolen
verifier leaks no password used anywhere else. Question 2 asks Mark to
confirm. If he wants argon2id anyway, it goes in a separate column and
SCRAM is still needed for XMPP.

**A cache.** A JMAP client sends Bearer on every request. After a
successful check the agent keeps, in memory only, SHA-256 of the
presented secret mapped to the credential id. A later request with the
same secret is one hash and one map lookup. The map is cleared for a
credential when it is revoked. Nothing in it is written to disk.

### 3.4 The agent token

`agent-token` becomes the credential named `agent-token`, kind
`agent-token`:

- Its file stays as it is: 43 characters, mode 0600, made on first
  start, so local clients and scripts that read it keep working.
- Its SCRAM verifiers are made at each start from the file, so it works
  on every front end, SCRAM included, as S1 said ("the same token").
- It is compared byte for byte, case and all, before the app-password
  normalisation of §3.2 is applied to the input.
- It cannot be revoked, only replaced:
  `mimid-agent <config> app-password rotate-token` writes a new file and
  closes every session that used the old one.

### 3.5 The username

The agent serves one user, so the password picks the credential and the
username adds nothing to security. Clients still ask for one, and each
protocol has rules about what comes back:

- The agent accepts any username in IRC SASL, PASS (which has none),
  HTTP Basic, Matrix password login and IMAP LOGIN. It logs at DEBUG
  whether the name was one it would have suggested, and never logs the
  text: users paste passwords into username fields.
- What it suggests, and prints in setup output, is the local part of
  the user's MIMI URI: `alice` for `mimi://a.example/u/alice`. That is
  already the IRC nick (agent-frontends.md §4, "Names").
- XMPP is the exception. The client builds its JID from the username
  and the domain it connected to, and the agent's bind answer must be
  that JID, so the XMPP username must be the local part; anything else
  gets `not-authorized` (§4.4).
- Each front end tells the client who it is after login, as now: IRC
  900, Matrix `user_id`, the XMPP bind result, the JMAP Session's
  `username`.

soju takes `username/network@client` in its usernames (§2.1); the
agent accepts those like any other name and ignores the suffixes.

### 3.6 Managing credentials

Three places, one set of operations (all INVENTED, NOT FROM SPEC):

| Operation | CLI | IRC | JMAP |
|---|---|---|---|
| List | `mimid-agent <config> app-password list` | `/msg mimid passwords` | `AppPassword/get` |
| Add | `mimid-agent <config> app-password add <name>` | `/msg mimid password add <name>` | `AppPassword/set` create; the response carries the secret once |
| Revoke | `mimid-agent <config> app-password revoke <name>` | `/msg mimid password revoke <name>` | `AppPassword/set` destroy |
| Replace the token | `mimid-agent <config> app-password rotate-token` | none | none |

- A listing shows name, kind, created, last used (time, front end,
  address) and revoked. Never a secret or a verifier.
- The JMAP methods sit under a capability
  `tag:reviewcommit.com,2026:mimid:app-passwords`, named like the
  existing `…:mimid:live` and `…:mimid:nostr`. They are the agent's
  own, not forwarded to the provider.
- **Adding from IRC** puts the new secret in a NOTICE, and most IRC
  clients log every line to disk (irssi, WeeChat, HexChat by default,
  *unverified* for each default). Question 5 asks whether IRC may add,
  or only list and revoke.
- Any authenticated session may list, add and revoke, including revoking
  the credential it is using. There is one user; every device is equal,
  as on a Google or Apple account.
- **The CLI and a running daemon.** The CLI opens `mimid.sqlite` itself,
  so it works whether or not the daemon runs. The daemon reads SQLite's
  `PRAGMA data_version` before each login and every 2 seconds
  (INVENTED), and on a change re-reads the table and closes sessions of
  any revoked credential (§3.7). No new control endpoint is needed.

### 3.7 Revocation and open sessions

Revoking a credential:

- closes every IRC connection and XMPP stream that logged in with it
  (IRC: `ERROR :Closing Link (credential revoked)`; XMPP: stream error
  `not-authorized`, *INVENTED* choice of condition);
- deletes its Matrix devices and access tokens, so the next request
  gets `401 M_UNKNOWN_TOKEN` without `soft_logout` (§4.3);
- deletes its XMPP FAST tokens;
- drops it from the Bearer cache, so the next JMAP request gets 401 and
  any open EventSource stream for it is closed.

Every connection and session therefore records which credential opened
it. That id is the one new thing each front end has to carry.

### 3.8 Derived tokens

Two protocols want a token minted at login and used afterwards in place
of the password:

- **Matrix access tokens**: one per `/login`, each a Matrix device
  (§4.3).
- **XMPP FAST tokens** (XEP-0484): one per client instance (§4.4).

Both are 32 random octets, stored as SHA-256 (random and long, so a
plain hash is enough), and tied to the credential that minted them.
Their lifetimes are in §4.

## 4. Per protocol

| Front end | Offered | Username | After login |
|---|---|---|---|
| IRC | SASL PLAIN; PASS | any; Goguma sends the nick | the connection carries the credential id |
| JMAP (and purple-mimi) | `Authorization: Bearer <secret>`; `Basic` | any | each request checked (cache, §3.3) |
| Matrix | `m.login.password` | any `m.id.user` or full user id | a per-device access token |
| XMPP | SCRAM-SHA-256, SCRAM-SHA-1, PLAIN (TLS only), over SASL1 and SASL2; FAST; later -PLUS | the local part | FAST token per client instance |
| IMAP (not planned) | LOGIN, AUTHENTICATE PLAIN | any | the connection |

Everywhere: no login before TLS on a listener that is not loopback (on
loopback, as today, no TLS). PLAIN, PASS, Basic and Matrix password
login carry the secret itself, which is fine inside TLS and is what
every client in §2 can do.

### 4.1 IRC

- CAP LS advertises `sasl=PLAIN` (a value, not a bare `sasl`, so
  irc-framework and HexChat can read it; Goguma reads either) and
  `soju.im/account-required`; ISUPPORT carries `draft/ACCOUNTREQUIRED`.
- AUTHENTICATE PLAIN: authzid empty or equal to authcid, authcid any
  (§3.5), password a credential. 903 and 900 on success; 904 on a
  wrong secret, after the §7 delay if the source is being slowed; 905
  for an over-long payload; 906 on abort; 907 for a second attempt
  after success; 908 lists `PLAIN` when another mechanism is asked for.
- The agent accepts AUTHENTICATE sent before its CAP LS reply has gone
  out (Goguma pipelines it).
- PASS stays, checked against the same credentials, for HexChat's
  default and for every desktop client's "server password". If both
  PASS and SASL arrive, SASL decides and PASS is ignored, as soju does;
  a wrong PASS with a good SASL is not an error, since irc-framework
  sends the same secret twice.
- With neither before registration ends: `FAIL * ACCOUNT_REQUIRED` if
  the client enabled `sasl`, else 464, then `ERROR` and close (as soju,
  §2.1).
- Not offered at first: SCRAM (question 3), EXTERNAL with client
  certificates (soju's device certificates; a later option, since
  Goguma cannot do it), OAUTHBEARER.
- irc-lessons.md "No SASL" and agent-frontends.md §4 change to say
  this (S3).

### 4.2 JMAP Chat

- `Authorization: Bearer <secret>`, where the secret is any credential
  (the agent token, as today, or an app password in any of its
  spellings with the spaces removed; a Bearer value cannot contain a
  space, so clients get the hyphenated form).
- `Authorization: Basic`, with any username and the secret as the
  password. Pidgin-style "username and password" clients and
  purple-mimi want this; crate-jmapchat-client already has it.
- A 401 carries `WWW-Authenticate: Bearer`, as today, and adds
  `Basic realm="mimid"` (INVENTED realm) only when the request used
  Basic. Sending `Basic` to a browser that did not use it makes the
  browser pop up its own login box.
- The EventSource and blob download URLs take the same header; an
  EventSource from a browser cannot set headers, which is the CORS
  question already settled for loopback and unchanged here.
- No OAuth. JMAP Chat clients that only do OAuth (jmap-chat-js's
  `GetToken` is shaped for it) can be given an app password as the
  token.

### 4.3 Matrix

- `GET /_matrix/client/v3/login` lists `m.login.password` and, once
  setup links exist, `m.login.token`. No SSO: FluffyChat would skip the
  password form.
- `GET /_matrix/client/v1/auth_metadata` answers `404 M_UNRECOGNIZED`,
  which Element Web takes quietly and Element X takes as "no OAuth".
- `POST /login` with `m.login.password`: any `m.id.user` (bare or full
  user id; §3.5) and an app password or the agent token. Each login
  makes a device: a fresh `device_id` (or the one the client sent, if it
  belongs to the same credential; iamb and Element Web's re-login reuse
  theirs), the client's `initial_device_display_name`, and an access
  token of 32 random octets, stored as SHA-256 and tied to the
  credential (§3.8). `refresh_token: true` is ignored: no refresh
  token, no `expires_in_ms`, so the access token lasts until revoked.
  The response carries `well_known` with the agent's base URL.
- `m.login.token` (later, for Cinny links): a one-time token from
  `setup`, good for 10 minutes (INVENTED), which makes a device under
  the credential that `setup` made.
- `/logout` deletes the calling device; `/logout/all` deletes every
  device **of the same credential** (INVENTED reading: "all" means all
  of this app password's sessions; the other app passwords are revoked
  with the tools in §3.6).
- `GET /devices`, `DELETE /devices/{id}`, `POST /delete_devices`: UIA
  with one stage, `m.login.password`, which takes any unrevoked credential's
  secret; the 401 challenge always carries a `session`. The same stage
  serves `/keys/device_signing/upload` when the Element X work
  (client-survey.md §3 step 6) arrives.
- **Never `soft_logout: true`.** A revoked or unknown token gets `401
  M_UNKNOWN_TOKEN` with `soft_logout: false`. With no refresh tokens
  there is nothing a soft logout could recover.
- `/versions` lists v1.10 among its versions, for Nheko.
- `.well-known/matrix/client` is served on the HTTPS listener with
  `m.homeserver.base_url`. It helps only when the user types a full user
  id; the setup output gives the URL itself (§6.3).
- The Matrix user id is `@<local>:<TLS name>` (client-survey.md §3 had
  `@x:d` with the MIMI domain; using the TLS name means a client that
  starts from the user id finds the agent through well-known). Question
  10.

### 4.4 XMPP

What every client in §2.3 can use:

- **SASL1** (RFC 6120) offering `SCRAM-SHA-256`, `SCRAM-SHA-1` and
  `PLAIN`, after TLS. Dino needs SCRAM-SHA-1 or PLAIN, Siskin and Gajim
  take SCRAM-SHA-256, Monal on SASL1 needs PLAIN.
- **SASL2** (XEP-0388) offering `SCRAM-SHA-256` and `SCRAM-SHA-1`,
  with `<authorization-identifier>` in `<success>`, and Bind2 (XEP-0386)
  so Monal and Conversations bind in the same round trip. This is what
  Monal needs to use SCRAM at all. PLAIN is not offered inside SASL2;
  Monal ignores it there anyway (`xmpp.m:3390-3391`).
- **FAST** (XEP-0484), `HT-SHA-256-NONE` at first and `-EXPR` with
  -PLUS (Monal offers only `-EXPR`, so FAST for Monal waits for
  channel binding). A FAST token is minted inside a SASL2 login with a
  credential, stored as SHA-256, tied to that credential and to the
  client's `<user-agent id>`; it lasts 30 days from last use (INVENTED)
  and is rotated as the XEP says.
- **-PLUS** (`SCRAM-SHA-256-PLUS`, `SCRAM-SHA-1-PLUS`) with the
  XEP-0440 list `tls-exporter` and `tls-server-end-point`, both of
  which rustls can give (`export_keying_material`; the end-point hash
  from the agent's own certificate). This is a later step, and the
  one-way rule applies: once offered, it MUST stay offered, or
  Conversations calls it a downgrade and Monal disables the account
  (§2.3). That is the one MUST in this note, because both clients
  break without it. The same holds for SASL2 once offered: so offer
  SASL2 from the first XMPP release, never add-and-remove.
- Username: the local part of the user's URI, and the domain the TLS
  name (§2.3). Anything else is `not-authorized`, logged as
  `username-mismatch`.
- SCRAM verifiers come from the credential table (§3.3); nothing new is
  stored for SCRAM itself.

### 4.5 IMAP, if ever

LOGIN and AUTHENTICATE PLAIN, after TLS, against the same credentials.
The setup output would be a `dclogin:` URL carrying an app password,
the one client in this note that takes a password by QR code (§2.5).

## 5. TLS

S1 says a listener that is not loopback needs TLS, and the agent
refuses to start without it. The question here is where the
certificate comes from, so that clients accept it without a warning.

### 5.1 What clients do with a certificate they do not trust

| Client | Publicly trusted (tailscale, ACME) | A CA installed on the phone or desktop | Self-signed, no CA |
|---|---|---|---|
| Goguma | works | works through the system store (*unverified* on Android, where an app must opt in to user CAs) | dialog, "Accept Always", pinned SHA-1 |
| WeeChat, irssi | works | works if the CA is in the system store | refused; pin a fingerprint in the config |
| HexChat, Halloy, The Lounge | works | works if in the store (Halloy also `root_cert_path`) | refused unless the user sets "accept invalid" |
| Element X Android | works | **works**: it reads `AndroidCAStore`, user CAs included | refused, no override |
| Element Web, Cinny | works | works if the browser trusts the CA | browser warning page |
| FluffyChat Android | works | probably not: system store plus bundled ISRG roots (*unverified*) | refused |
| Nheko, iamb | works | works if in the store | refused unless checks are turned off |
| Conversations | works | works if Android exposes it; else the dialog | dialog, remembers the leaf; **name must match the JID domain** |
| Monal | works | works once the iOS profile is fully trusted (*unverified*) | refused, no override |
| Dino | works | works if in the store | **refused, no dialog** |
| Gajim | works | works | "add certificate" for an unknown CA; name mismatch fatal |
| Siskin | works | works once trusted (*unverified*) | accept, pins the SHA-1 fingerprint |
| Profanity | works | works | prompt, `/tls always` |
| Delta Chat | works | works | "accept invalid certificates" setting, no pinning |
| jmap-chat-js (browser) | works | works if the browser trusts it | browser warning page |

A publicly trusted certificate works in every client with no step on
the phone. A CA the user installs works in most, with the iOS steps of
§6.6 and gaps on Android. Self-signed works only in the clients that
pin. That is the ranking of §5.2.

### 5.2 Where the certificate comes from, ranked

1. **`tailscale cert`, when the listener is on a tailnet.** Tailscale's
   control plane does the ACME DNS-01 challenge for
   `<machine>.<tailnet>.ts.net` and hands the node a Let's Encrypt
   certificate. Every client trusts it; nothing is installed on the
   phone; the phone is already on the tailnet to reach the agent.
   - Needs MagicDNS and "HTTPS certificates" turned on in the tailnet's
     admin console.
   - The name goes into the public Certificate Transparency logs, so
     the tailnet's name and the machine's name become public. Tailscale
     says so when the feature is turned on (*from memory*). Question 6.
   - The agent asks tailscaled for the pair over its LocalAPI,
     `GET /localapi/v0/cert/<name>?type=pair` on the tailscaled socket
     (tailscale `ipn/localapi/cert.go:48-60`). tailscaled answers root,
     its operator user, or the uid in `TS_PERMIT_CERT_UID`
     (`ipn/ipnserver/server.go:384-401`); the agent runs as an ordinary
     user, so the docs say to set one of the last two. The other way is
     a systemd timer running `tailscale cert` as root and writing files
     the agent reads (mode 3 below).
   - tailscaled caches the certificate and renews it after two thirds
     of its lifetime, or earlier if Let's Encrypt's ARI says so
     (`feature/acme/cert.go:171-250`). The agent asks again once a day
     (INVENTED) and swaps the certificate in without dropping
     connections.
   - With the listener on the tailnet address the agent can learn which
     tailnet node and user is connecting (LocalAPI `whois`), as
     tailircd did (irc-lessons.md). That is not used for login here;
     question 7.
2. **ACME DNS-01, when the user has a domain.** A name such as
   `chat.example.org`, pointing at the agent's address, public or
   private: DNS-01 needs no inbound connection, so it works for a
   WireGuard address too. The agent needs a way to write a TXT record:
   - an RFC 2136 dynamic update with a TSIG key (BIND, Knot, PowerDNS);
   - acme-dns (a small DNS server for exactly this, reached by a CNAME
     from `_acme-challenge.chat.example.org`), which turns any provider
     into one that works, after one CNAME by hand;
   - a hook command the user writes, called with the name and value,
     the way lego, acme.sh and certbot's manual hooks work.

   The ACME client would be `instant-acme` (0.8.5, which takes any
   challenge type, so DNS-01 is the caller's code), over the rustls the
   workspace already has. HTTP-01 and TLS-ALPN-01 need the agent to be
   reachable on port 80 or 443 from the internet, which a personal
   agent usually is not; they are left out (`rustls-acme` 0.15.4 does
   TLS-ALPN-01 only, so it does not fit).
3. **Files the user already has.** `cert` and `key` paths in PEM, read
   at start and again when the files change. This covers a certificate
   from certbot, Caddy, a homelab CA or `tailscale cert` run by a timer.
   It costs little and is the escape hatch for everything else, so it
   is in the first TLS step even though it ranks below ACME for ease.
4. **A local CA, as the last resort.** The agent makes a CA key and
   certificate in its state directory, and a server certificate from
   it for the names the user gives (a LAN name, an IP address). The CA
   carries an X.509 name constraint for exactly those names, so a phone
   that trusts it trusts nothing else it might sign. The user installs
   the CA on each phone (§6.6). The leaf is renewed by the agent
   itself, every 60 days for a 90-day certificate (INVENTED), well
   under Apple's 825-day limit for TLS server certificates (from
   memory; whether it applies under a user-installed root is
   *unverified*). Whether every client honours name constraints is
   *unverified*.

**Not offered: a self-signed certificate with warnings as the
default.** Clients that pin (Goguma, Conversations, WeeChat with a
fingerprint) would cope; Element X, Monal and Dino would not, and
everyone else would see a warning on every new device. The local CA
(4) is the same work for the agent and gives a certificate the phone
then trusts for good. A user who wants a self-signed certificate can
make one and use mode 3.

### 5.3 Configuration

INVENTED names; agent.md gets the final form with the code.

```toml
[tls]                            # needed by any listener that is not loopback
source = "tailscale"             # "tailscale", "acme", "files" or "local-ca"
names = ["host.tailnet.ts.net"]  # what the certificate covers; the first is
                                 # the name setup output prints

# source = "acme"
# [tls.acme]
# directory = "https://acme-v02.api.letsencrypt.org/directory"
# contact = "mailto:..."         # optional
# dns = "rfc2136"                # "rfc2136", "acme-dns" or "hook"
# rfc2136 = { server = "ns1.example.org:53", key_name = "...", key_file = "..." }
# hook = "/usr/local/bin/acme-dns-hook"

# source = "files"
# [tls.files]
# cert = "/etc/ssl/chat.example.org/fullchain.pem"
# key = "/etc/ssl/chat.example.org/key.pem"

[irc]
listen = "127.0.0.1:6667"        # loopback, plain, as now
listen_tls = "100.64.1.2:6697"   # optional; refused without [tls]

[matrix]                         # mimid-rvqk
listen_tls = "100.64.1.2:8448"
```

- A `listen` that is loopback stays plain and keeps today's behaviour.
- A `listen_tls`, or any address that is not loopback, requires `[tls]`;
  without it the agent refuses to start (S1).
- The HTTP listener's Host check (crates/mimid-agent/src/http.rs,
  `host_allowed`) takes the `[tls] names` with the TLS port as well as
  the loopback names. It still blocks DNS rebinding: a rebinding page
  cannot present a name the certificate covers.
- One certificate serves every front end. Each front end uses its own
  port; there is no ALPN or SNI routing on one port (question 8 has the
  case for 443).

### 5.4 Renewal and failure

- The agent keeps the current certificate in memory behind a lock and
  swaps it when a new one arrives; open connections keep theirs.
- It starts renewing at two thirds of the lifetime (Let's Encrypt's
  advice, which tailscaled follows), retries with backoff, and logs
  WARN from 14 days before expiry and ERROR from 3 days (INVENTED).
- An expired certificate is still served, with an ERROR each hour,
  rather than closing the listener: clients will refuse it, and the log
  says why. A failed start (no certificate at all) refuses to start, as
  S1 says.

## 6. Onboarding

### 6.1 What the agent prints

`mimid-agent <config> setup <client> <device>` (INVENTED) makes an app
password named `<device>` and prints what that client needs, with a QR
code in the terminal where the client or the phone's camera can use
one. `/msg mimid setup <client> <device>` does the same over IRC, as
NOTICE lines (no QR). `<client>` is one of the names below, or
`generic`, which prints host, ports, username and password for every
front end that is on.

Example, INVENTED values:

```text
$ mimid-agent agent.toml setup goguma phone
App password "phone" made. It is shown once.

  Goguma
    Server     host.tailnet.ts.net:6697
    Nickname   alice
    Password   kqzv-trwm-hpaf-dnye

  Scan with the phone's camera to open Goguma with the server and
  nickname filled in; then type the password.

  [QR: ircs://alice@host.tailnet.ts.net:6697]
```

The password is never put in a QR code or URL, because no client in
§2 except Delta Chat reads one from there, and a URL ends up in browser
history and screenshots.

### 6.2 IRC

| Client | What `setup` prints |
|---|---|
| Goguma | `ircs://<nick>@<name>:<port>` as a QR code and link (Android intent filter and iOS URL scheme; it fills server and nick, drops any password, `connect.dart:64-76`), then the password to type. Goguma shows the password field because the agent offers SASL PLAIN. |
| WeeChat | `/server add mimid <name>/<port> -tls -sasl_mechanism=plain -sasl_username=<nick> -sasl_password=<password>` |
| irssi | `/network add -sasl_mechanism PLAIN -sasl_username <nick> -sasl_password <password> mimid` and `/server add -tls -network mimid <name> <port>` |
| HexChat | the steps: Network List, Add, server `<name>/<port>`, "Use SSL", login method SASL (or server password), password |
| Halloy | a `config.toml` `[servers.mimid]` block with `server`, `port`, `use_tls`, `nickname` and `[servers.mimid.sasl.plain]` |
| The Lounge | the fields to fill in its "Connect" form |

### 6.3 Matrix

- **Homeserver URL**: `https://<name>` if the Matrix listener is on
  port 443, else `https://<name>:<port>`. Every client takes a typed URL
  (§2.2). Question 8 is about using 443.
- **Username**: `<local>`; for Nheko, which wants a full id,
  `@<local>:<name>`.
- **Password**: the app password.
- **Element X**: a QR code of its deep link with the server and login
  hint (`https://mobile.element.io/element/?account_provider=<name>&login_hint=<local>`;
  the exact path is *unverified*), which opens the password screen
  with the server chosen.
- **Cinny** (later): a link `https://<cinny host>/login/<name>?loginToken=<one-time token>`,
  which logs in with no typing (§4.3).
- Element X still needs sliding sync before it can be used at all
  (mimid-rvqk); until then `setup element-x` says so and stops.

### 6.4 XMPP

- **Address**: `<local>@<name>`, where `<name>` is the TLS name (§2.3);
  **password**: the app password. Every client has "I already have an
  account" with these two fields.
- **Ports**: MagicDNS and most home DNS serve no SRV records, and every
  client then falls back to `<name>:5222` with STARTTLS (§2.3). So the
  agent listens on 5222 with STARTTLS, and on 5223 with direct TLS
  (XEP-0368) if the user wants it. Different ports need the client's
  manual host setting, which Dino lacks.
- **Monal**: the simple login turns on PLAIN for unknown domains, but
  with SASL2 offered it uses SCRAM; nothing to tell the user.
- **OMEMO**: the setup text says to turn it off for the account
  (client-survey.md §4); that is not an auth matter but is the next
  thing a user hits.
- **Preauth URIs** (`xmpp:<local>@<name>?register;preauth=<token>`)
  would make the account from a QR code, with the user choosing a
  password, in Conversations, Monal and Siskin. That needs in-band
  registration and user-chosen passwords, so it is question 4, not the
  first version.

### 6.5 JMAP Chat and purple-mimi

- **Session URL**: `https://<name>:<port>/.well-known/jmap`.
- **Token**: the app password, for clients with a token field
  (jmap-chat-js, crate-jmapchat-client); or **username** `<local>` and
  **password**, for clients with Basic (purple-mimi, Pidgin's account
  dialog).

### 6.6 Installing the local CA (source `local-ca` only)

- The agent serves a setup page on its HTTPS port at `/mimid/ca`
  (INVENTED), and the same file as plain HTTP on the address and port
  named in `[tls.local-ca] bootstrap = "<addr>:<port>"`, off by default.
  The page gives the CA certificate as `.crt` (Android, desktops) and as
  an iOS configuration profile (`.mobileconfig`), and shows the CA's
  SHA-256 fingerprint, which `setup` also prints, so the user compares
  the two before trusting.
- **iOS**: open the link in Safari, allow the profile download, install
  it in Settings, General, VPN & Device Management, then turn on full
  trust in Settings, General, About, Certificate Trust Settings. Four
  screens; Monal, Siskin and every Safari-based client then trust it
  (*from memory*; menu names change between iOS versions).
- **Android**: Settings, Security, Encryption & credentials, Install a
  certificate, CA certificate, with a full-screen warning. Since Android
  7 an app trusts user CAs only if it opts in: Element X does
  (§2.2), FluffyChat probably does not, Goguma and Conversations do not
  need to because they pin (§5.1).
- **Desktops**: the `.crt` into the system store, or the client's own
  setting (WeeChat `tls_fingerprint`, Halloy `root_cert_path`).
- This is the most upsetting path in this note, which is why it is
  last.

## 7. Rate limiting, lockout and logging

### 7.1 No lockout

An account lockout lets anyone who can reach the port lock the user out
of their own chat, and with 75-bit generated secrets it buys nothing:
no rate the agent allows makes online guessing work. So:

- **No account lockout, ever.** A credential is never disabled because
  of failed logins.
- **Per source address, a slowdown.** After 5 failed logins from one
  address in 10 minutes (INVENTED), each further failure from it is
  answered after a delay starting at 1 second and doubling to 30
  seconds; a success from that address resets it. IPv6 sources are
  counted per /64 (INVENTED). Loopback is counted like any other
  address, with a higher threshold of 20 (INVENTED), so a local script
  in a loop does not slow the user's own clients for long.
- **Why a slowdown at all.** Log noise and CPU: each failed plain login
  may run the SCRAM-SHA-256 derivation once per unrevoked credential (§3.3).
  It also tames WeeChat's default `sasl_fail = reconnect`, which retries
  a wrong password forever (§2.1).
- **Unauthenticated connections are capped**: at most 32 at once in
  total and 8 per source address (INVENTED), each closed if it has not
  logged in within 30 seconds (soju's `downstreamRegisterTimeout` is
  30 s too, §2.1).
- **A slowed source still gets a clear answer**, the protocol's normal
  failure (IRC 904 or 464, HTTP 401, Matrix `M_FORBIDDEN`, XMPP
  `not-authorized`), never a silent drop, so a user with a wrong
  password sees "wrong password" and not a timeout.
- Matrix has a rate-limit error, `429 M_LIMIT_EXCEEDED` with
  `retry_after_ms`; the agent uses it for `/login` while slowed,
  since Matrix clients show it as such (*unverified* per client).

### 7.2 Logging

Following AGENTS.md's "secrets never reach logs":

| Event | Level | Fields |
|---|---|---|
| Login succeeded on a network listener | INFO | front end, mechanism, credential name, peer address |
| Login succeeded on loopback | DEBUG | same |
| A JMAP request authenticated from the cache | TRACE | credential name |
| Login failed | INFO for the first failure from a source in 10 minutes, then DEBUG | front end, mechanism, peer address, reason (`no-such-credential`, `bad-proof`, `username-mismatch` for XMPP, `revoked`) |
| A source starts being slowed | WARN | peer address, failures counted |
| Credential added, revoked, token replaced | INFO | name, by which credential and front end |
| Session closed because its credential was revoked | INFO | front end, credential name, peer |
| Certificate renewed | INFO | names, not-after |
| Certificate renewal failed | WARN, ERROR near expiry (§5.4) | source, error |

Never logged: any secret, any SCRAM value, any token, the username
text (people paste passwords there), the SASL payload, or an
`Authorization` header. The existing canary test
(crates/mimid-agent/tests/no_token_in_logs.rs) gains an app password,
a SCRAM exchange, an HTTP Basic login, a Matrix login and a FAST token,
each checked absent from captured output at TRACE.

## 8. Threat model, in plain words

What someone gets by logging in: everything. They read every room in
plaintext, send as the user, accept invites, leave rooms, and make
more app passwords. The agent is the end of the end-to-end encryption.
So the question for each listener is who can reach it.

**Loopback (as today).** Anyone who can open a TCP connection on the
host. Other local users cannot read `agent-token` (mode 0600) and
cannot guess an app password. Processes of the same user can read the
token file, and so can do anything the user can; that was true before
this note. Browsers are kept off by the Host check for HTTP and by port
6667 being on the Fetch standard's bad-port list for IRC
(agent-frontends.md §4). Loopback stays plain, without TLS.

**Tailnet or WireGuard address.** Every device on the tailnet, and
anyone the tailnet admin shares the node with, can reach the port.
Tailscale ACLs can narrow that to the user's own devices; the docs say
to. The tailnet is encrypted, but TLS still runs, because clients
require it (§2) and because a shared or compromised tailnet node can
watch a plaintext stream. Passwords are the real gate. A stolen phone
is the realistic threat: revoke its app password (and the node in the
tailnet admin).

**A public address.** Anyone on the internet. Expect scanners within
minutes and credential-stuffing lists; generated passwords are not on
any list, and §7 keeps the noise down. What this adds over the tailnet
case is exposure of the agent's code to strangers before login: the
IRC line parser, the XMPP XML parser, the HTTP stack. That is the
larger risk, and it is why the docs recommend a tailnet or WireGuard
address and why a public listener is never the default. Question 9.

**What this design does not protect against:**

- someone with the user's unlocked phone, until the user revokes it;
- someone who can read the agent's state directory: they have the MLS
  keys and all plaintext already;
- a malicious provider (AGENTS.md: never claim that);
- push relays seeing metadata (S4 and client-survey.md §1.2);
- traffic analysis on the tailnet or the internet.

## 9. Step plan and effort

Sizes are lines of Rust with tests (*estimate*). Each step is one to
three commits and one child bead of mimid-e13m.

| Step | What | Size | Needed before |
|---|---|---|---|
| 1 | **Credential store.** The table (§3.1), secret generation and normalisation (§3.2), SCRAM-SHA-1 and -256 verifiers and the plain check against them (§3.3), the Bearer cache, `agent-token` as a credential (§3.4), `last_used`. The daemon's one check per boundary becomes `Credentials::check_plain(secret) -> Option<CredentialId>`, handed to each front end in place of `PasswordCheck`. JMAP and IRC switch to it with no change a client can see. The canary test grows. | 700 to 1,000 | IRC v2 |
| 2 | **CLI and revocation.** `mimid-agent <config> app-password list/add/revoke/rotate-token`; the `data_version` watch; closing IRC connections and EventSource streams of a revoked credential. | 400 to 600 | IRC v2 |
| 3 | **TLS core.** `[tls]` with `source = "files"` and `"tailscale"`, `listen_tls` for IRC, certificate swap without dropping connections, the Host check taking `[tls] names`, refusal to start without TLS on a non-loopback address (S1). agent.md and AGENTS.md change with it. | 600 to 900 | IRC v2 |
| 4 | **IRC SASL.** `sasl=PLAIN` in CAP, AUTHENTICATE PLAIN (pipelined, as Goguma sends it), `soju.im/account-required` and ISUPPORT `draft/ACCOUNTREQUIRED`, `FAIL * ACCOUNT_REQUIRED`, PASS kept, PASS and SASL together accepted, 903/904/905/906/907/908, the rate limiter and connection caps of §7 as a shared module. irc-lessons.md updated (S3). | 500 to 700 | IRC v2 |
| 5 | **Management in IRC and setup output.** `/msg mimid passwords`, `password add` (per question 5), `password revoke`; `mimid-agent <config> setup <client> <device>` printing the per-client text and a terminal QR code (§6). | 400 to 600 | IRC v2 |
| 6 | **JMAP over the network.** `listen_tls` for HTTP, Basic beside Bearer, the `…:mimid:app-passwords` capability with `AppPassword/get` and `/set`. | 400 to 600 | Matrix (it shares the HTTPS listener) |
| 7 | **Matrix login.** `/login` (GET and POST, `m.login.password`), per-device access tokens, `/logout`, `/logout/all`, `/devices` and `DELETE /devices/{id}` (with the UIA answer of §4.3), `/whoami`, soft logout never, hard logout on revoke, `.well-known/matrix/client`. | 600 to 900 | Matrix |
| 8 | **ACME DNS-01.** `source = "acme"` with RFC 2136, acme-dns and hook; account key and order state in the state directory; renewal. | 800 to 1,200 | none; after IRC v2 |
| 9 | **Local CA.** `source = "local-ca"`, the name-constrained CA, leaf renewal, the setup page serving the CA for iOS and Android with fingerprints (§6.6). | 500 to 800 | none |
| 10 | **XMPP SASL.** SASL1 SCRAM-SHA-1, SCRAM-SHA-256 and PLAIN; SASL2 with the same; FAST tokens; `tls-exporter` and -PLUS with XEP-0440. | 900 to 1,300 | XMPP |
| 11 | **IRC SCRAM-SHA-256**, if question 3 says yes. | 150 to 250 | none |

Steps 1 to 5 (about 2,600 to 3,800 lines) are the part IRC v2 needs:
with them Goguma on either phone logs in with an app password, over a
certificate it trusts, to an agent on the user's tailnet. Steps 6 and 7
go with Matrix, step 10 with XMPP. Steps 8 and 9 widen who can get a
trusted certificate and can go in any order after step 3.

## 10. Open questions for Mark

1. **The credential model.** One named app password per device, 16
   lowercase letters in four groups (75 bits), made by the agent, shown
   once, good on every front end; the agent token kept as one more
   credential. Recommendation: yes.
2. **SCRAM verifiers instead of argon2id.** The agent must keep SCRAM
   keys for XMPP, and those set how hard the stored data is to attack,
   so an argon2id hash beside them adds cost to every login and no
   protection. Recommendation: store SCRAM-SHA-1 and SCRAM-SHA-256
   verifiers only, 4,096 iterations, and check plain logins against
   them.
3. **SCRAM in IRC.** No IRC client needs it; Goguma, Halloy and The
   Lounge cannot do it. Recommendation: PLAIN and PASS only, as S3 said;
   add SCRAM-SHA-256 (step 11, small, the verifiers exist) only if a
   user asks.
4. **User-chosen passwords through registration.** XMPP preauth URIs
   and in-band registration would let Conversations, Monal and Siskin
   set up from one QR code, with the user choosing the password.
   Recommendation: not in the first XMPP release; app passwords typed
   by hand first. If added later, a chosen password is allowed only
   through a one-time preauth token, becomes an ordinary credential, and
   needs at least 12 characters (INVENTED).
5. **Adding an app password from IRC.** The new secret arrives in a
   NOTICE, and IRC clients log to disk. Recommendation: allow it; the
   same logs already hold every message in plaintext, and a phone-only
   user has no CLI. The NOTICE says the line may be in the client's
   log.
6. **`tailscale cert` puts the names in public CT logs.** The tailnet
   name and the machine name become public. Recommendation: make it the
   first choice anyway and say so in agent.md; a user who minds uses
   their own domain or the local CA.
7. **Tailnet identity as a login.** On a tailnet the agent could ask
   tailscaled who is connecting and skip the password for the user's
   own nodes, as tailircd did. Recommendation: no, not now. Goguma
   shows a password field only with SASL anyway, the rule would differ
   between listeners, and a shared node would get in. Revisit if users
   find typing a password once per device too much.
8. **Port 443 for Matrix.** Matrix clients turn a typed name into
   `https://name` on 443; any other port means typing it. Recommendation:
   default the Matrix (and JMAP) HTTPS listener to 443 on the tailnet
   address when `[tls] source = "tailscale"` (an unprivileged process
   needs `CAP_NET_BIND_SERVICE` or a sysctl for that; the docs say how),
   else 8448, and print the full URL either way.
9. **A listener on a public address.** S1 allows any address the user
   names. Recommendation: keep allowing it, never as a default; log a
   WARN at start naming the address as public, and point the docs at
   tailnet and WireGuard addresses.
10. **The Matrix and XMPP domain.** XMPP clients check the certificate
    against the JID domain, so XMPP addresses must use the TLS name
    (`alice@host.tailnet.ts.net`), not the MIMI domain. Matrix does not
    force it, but using the TLS name in `@alice:host.tailnet.ts.net`
    lets well-known discovery work. Recommendation: use the TLS name in
    both, and show the MIMI URI in profiles and WHOIS-like places, as
    the IRC front end does.

## 11. Uncertainties

- Whether iOS's camera opens an `ircs://` QR code in Goguma, and the
  exact Element X deep-link path.
- Whether Goguma (Flutter) and FluffyChat on Android trust a
  user-installed CA; whether Monal and Siskin accept one once the iOS
  profile is fully trusted; whether every client honours the local CA's
  name constraints.
- Apple's 825-day certificate limit under a user-installed root, and
  the iOS menu names in §6.6 (from memory).
- That `tailscale cert` warns about CT logs when turned on, and that
  tailscaled's operator user may fetch certificates (from memory and
  `PermitWrite`; not run).
- What Monal does if SASL2 `<success>` lacks `<authorization-identifier>`;
  the agent always sends it.
- Whether Matrix clients show `429 M_LIMIT_EXCEEDED` on `/login` well.
- Default logging of irssi, WeeChat and HexChat (question 5).
- Palaver, closed source and possibly withdrawn (client-survey.md §11).
- Every size is an estimate; every value marked INVENTED is open.
