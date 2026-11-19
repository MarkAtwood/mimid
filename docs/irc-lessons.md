# IRC client/server lessons from meshIRCd and tailircd

Input to the native IRC front end (epic mimid-1vul). Collected 2026-11-19
from Mark Atwood's two IRC servers in Go:
[meshIRCd](https://github.com/MarkAtwood/meshIRCd) (local clone
/data/PROJECT/meshIRCd, 24 commits, 2026-08-05..11-13) and
[tailircd](https://github.com/MarkAtwood/tailircd) (12 commits, 2026-08-08).

## How much of this was tested

- **Real clients:** only two field reports exist, both in meshIRCd's
  VIBED.md: the macOS Textual TLS failure and `MODE #chan b` answered with
  482. Neither repo has GitHub issues. Most tracker beads are LLM code
  review, mostly about concurrency and crypto.
- **Unreliable close reasons:** many beads were bulk-closed without a fix
  ("Documented positive pattern, no fix needed"). The items below were
  checked against HEAD.
- **Unverified:** items marked *unverified* are client behaviour that
  neither repo records. Check them against real clients.

## Must do

### Registration

- **CAP:**
  - Wait for the client's first line before sending anything.
  - Answer `CAP LS 302` correctly; an empty list is fine.
  - ACK or NAK a `CAP REQ` as a whole, never one cap at a time (meshIRCd
    main.go:1459-1484 got this wrong).
  - Split a long LS over `CAP * LS * :` continuation lines.
  - Once registered, use the nick, not `*`, as the CAP target.
  - Advertise only caps that are wired up (meshIRCd advertised
    account-notify, chghost, invite-notify, setname and labeled-response
    without sending them). Clients change their behaviour on the cap list.
- **NICK and the burst:**
  - Accept the client's NICK, then make the real nick the target of 001,
    with a NICK change if needed. Never answer NICK with 462 (tailircd);
    use 432 or 435.
  - Keep 001 as `Welcome to the <net> IRC Network nick!user@host`: some
    clients and bots read their hostmask from its last word (*unverified*).
  - Send 001 to 004, then 005 lines with at least CASEMAPPING, CHANTYPES,
    PREFIX, CHANMODES (list modes as type A), NICKLEN, CHANNELLEN and
    TARGMAX. Add LINELEN and UTF8ONLY if they are enforced. 004 and
    CHANMODES must agree (meshIRCd's did not).
  - End the burst with 376 or 422. HexChat's perform, ZNC and bots wait for
    it before autojoin (*unverified*).
- **No SASL:** users are authenticated out of band. Don't advertise sasl,
  or clients will try it. Show the account with 900 at registration and
  330 (or 307) in WHOIS.

### Keepalive

- Send PING on an idle connection, and close only after a PONG is missed.
  - meshIRCd never pinged and had no read deadline, so dead sessions stayed
    forever.
  - tailircd closed on a 5-minute read deadline without probing.
- Answer PING with `:server PONG server :token`. irssi matches the last
  parameter (*unverified*), and tailircd's bare `PONG token` was wrong.

### Line length and encoding

- **Reading:**
  - Read up to 8191 bytes of tags plus 512 bytes once message-tags is
    negotiated.
  - Never disconnect on a long line; answer 417 ERR_INPUTTOOLONG. Both Go
    servers used a 512-byte `bufio.Scanner` and dropped any client that
    sent a tagged line longer than that.
- **Writing:**
  - Split outbound lines to fit 512 bytes, including prefix and tags.
  - Split 353 NAMES; neither server did.
  - Split a long PRIVMSG body over several lines, on UTF-8 boundaries.
- **Tags:** unescape them per the spec: an unknown `\x` becomes `x`, and a
  trailing `\` is dropped. meshIRCd's NUL placeholder corrupted values that
  contained a NUL.
- **UTF-8:** decide what to do with invalid bytes (replace, or refuse with
  UTF8ONLY). Neither server did anything.

### Casemapping and nicks

- **Casemapping:** advertise `CASEMAPPING=ascii` and fold exactly ASCII. As
  a fallback, restrict nicks to `[A-Za-z0-9_-]` the way tailircd did.
  - meshIRCd advertised ascii but folded with Unicode `ToLower`.
  - meshIRCd allowed `[]\^{}|` in nicks, so `nick[` and `nick{` were two
    users to the server but one to an rfc1459 client.
- **Nicks:**
  - Never truncate a requested nick silently (meshIRCd main.go:1517).
  - Derived nicks need a collision rule. tailircd let a remote nick shadow
    a local one (bridge.go:390-415).
  - tailircd's `user_tailnet` nicks stayed unique but got long, and
    collided with NICKLEN 30.

### Channel state

- **MODE queries:** `MODE #c` and `MODE #c b|e|I` with no argument are
  queries. Answer 324 and 329, then 367/368, 348/349 and 346/347; never 482.
  Textual and irssi send `MODE #c b` on every join. This is a field report:
  meshIRCd 4a4382c, VIBED.md:269-282. RFC 2812 §3.2.3 never says this.
- **JOIN:** echo the JOIN to the joiner, then send 332 and 333 (or 331),
  then 353 and 366.
- **Virtual users:** people who are not on this IRC server must appear in
  353, WHO and WHOIS 319, not only as JOIN lines. tailircd never listed its
  remote users in NAMES, so they spoke without being in the nick list.
- **WHO and WHOIS:**
  - WHO always ends with 315, even for an unknown mask. Clients send
    `WHO #c` on join (*unverified*).
  - WHOIS always ends with 318, including 401 then 318 for an unknown nick.
- **Also implement:** NAMES, PART, QUIT (`ERROR :Closing Link` before
  closing), TOPIC, AWAY (305, 306 and 301), and ISON or USERHOST.
- **Everything else:** answer 421.

### Messages

- **NOTICE:** never answer NOTICE with an error numeric (tailircd did, which
  risks bot-to-bot loops).
- **PRIVMSG:** answer a missing text with 412, not 461.
- **CTCP:** pass it through untouched; optionally answer VERSION for the
  server itself.
- **msgid:** msgid rides on `message-tags`. meshIRCd's invented
  `message-ids` cap meant no real client ever got one.
- **echo-message:** the echo carries the same msgid and time as the copies
  sent to others.
- **labeled-response:** only offer it if every reply, numerics included,
  carries the label. meshIRCd's never did, so clients waited forever.
- **chathistory:** it needs the label wiring and a real store. History
  should key on the account, not the nick pair (meshIRCd keyed DMs by
  nicks).

### Transport and flood control

- **TLS:** if the front end does TLS, use an ECDSA P-256 or RSA
  certificate. macOS Secure Transport (Textual) refuses Ed25519 (error
  -9824; meshIRCd 19d57b2).
- **Flood control:** exempt registration traffic, and never drop a line
  silently.
  - meshIRCd dropped silently at 5/s with a burst of 10.
  - A client that sends CAP, NICK, USER, REQ and END in one burst can lose
    its CAP END (*unverified*).
  - A loopback front end may need no flood limit at all.

## Skip

- SASL, OAUTHBEARER, GitHub and OIDC flows. The claims in meshIRCd's
  GITHUB.md about which clients support OAUTHBEARER are unverified and
  likely wrong.
- METADATA, DID tags and IDENTITY CHALLENGE.
- WATCH (keep MONITOR at most).
- Cloaking: use a fixed synthetic host.
- Forced auto-join to a lobby channel.
- Federation and S2S.
- Persistent ban, exception and invite lists: return empty 368, 349 and
  347.
- Oper commands and KILL.
- LIST beyond a plain 322 list ending in 323.

## The two servers

- **meshIRCd:**
  - **Design:** a federated, TLS-only daemon, mostly one 3200-line
    main.go. Each client has read and write goroutines (a 256-slot write
    queue that drops when full), and each channel is an actor goroutine.
  - **State:** maps keyed by `strings.ToLower`, with in-memory ring-buffer
    history.
  - **Federation:** S2S is JSON-LD over mutual TLS with Lamport clocks.
    Peers are found through a GitHub servers.json.
  - **Accounts:** from SASL (PLAIN, EXTERNAL as did:key, OAUTHBEARER,
    GitHub, OIDC).
  - **MIMI:** bead ircd-atjq already points at mimid-agent's local IRC
    interface as the E2EE route.
- **tailircd:**
  - **Design:** a stripped fork of about 6000 lines, listening via tsnet on
    the tailnet only, with no TLS of its own.
  - **Identity:** the connection is the identity (`WhoIs(remoteAddr)`).
    The nick is forced to `login_tailnet`, +r is set, and 001 goes out
    with no handshake.
  - **Devices:** a second device takes over with KILL.
  - **Storage and federation:** channels persist to JSON. Federation is
    meshIRCd's envelopes over WebSocket through Funnel, with remote users
    shown as synthetic JOIN, PART and PRIVMSG lines.
