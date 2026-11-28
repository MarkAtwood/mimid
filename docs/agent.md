# Running mimid-agent

`mimid-agent` runs for one user on one device. It holds the user's MLS keys, talks to the user's mimid server, and serves the user's rooms in plaintext: as a JMAP Chat endpoint (on by default, loopback for plain HTTP and any address with `listen_tls`) and as an IRC server (off by default, loopback by default but any address if you say so). A standard JMAP Chat client or a stock IRC client connects to it. The server's operator guide is [operating.md](operating.md).

## Before the first start

The user needs an account and a bearer token on their mimid server. On the server host:

```sh
mimid admin server.toml add-user mimi://a.example/u/alice
mimid admin server.toml token mimi://a.example/u/alice | jq -r .token > server-token
chmod 600 server-token
```

`mimid admin ... token` prints a JSON object, `{"token": "..."}`. The agent's `token_file` must hold the bare token; whitespace around it is ignored.

## Starting and stopping

```sh
mimid-agent <config.toml>
```

On start the agent opens or creates its state directory, publishes KeyPackages, binds its listeners and then serves.

The log goes to standard output. Environment variables:

| Variable | Values | Default | Meaning |
|---|---|---|---|
| `RUST_LOG` | a `tracing` filter, such as `info` or `mimid_agent=debug,info` | `info` | Which log events are written. |
| `MIMID_LOG_FORMAT` | `text` or `json` | `text` (also when unset or empty) | The format of the log on standard output. `json` writes one JSON object per line, with the event's stable name in `event`, and `level`, `target`, `message`, `fields` and `spans`. Any other value stops the agent at startup. |

These are the server's variables and mean the same thing. The text format does not show event names; use `json` if you need them, for example to alert on `agent_sync_failed` or `agent_certificate_expiring`.

Three events are rate limited, because they fire once per item on a path whose volume the sender or the server decides: `agent_message_discarded`, `agent_jmap_push_too_large` and `live_stream_frame_refused`. Each keeps its level and its name, but at most one line per minute per event is written, and that line carries `suppressed`, how many of that event were left out of the log since the previous line. With `[telemetry]` configured, every one is counted in `mimid.refusals` by `event` whether or not it was logged. A discarded message is reported to the user's client as a problem of that room either way, so the window does not hide it from the person it happened to.

With a `[telemetry]` table the spans, the log events that `RUST_LOG` keeps and the metrics also go to an OpenTelemetry collector (see [`[telemetry]`](#telemetry)).

SIGINT and SIGTERM both stop it. The stop ends the sync loop, the HTTP server, every EventSource stream and every IRC connection. Unix only.

## The token for local clients

On first start the agent writes a token of its own to `<state_dir>/agent-token` (32 random octets as unpadded base64url, mode 0600), and reads it on later starts. This is not the server token:

- A JMAP Chat client sends it as `Authorization: Bearer <token>` to the agent's `listen` address.
- An IRC client sends it as the server password (`PASS`).

A client running as the same user reads it from that file.

The agent token is one credential among the agent's app passwords (see [App passwords](#app-passwords)); every front end takes either.

## App passwords

An app password is a secret the agent makes for one device or client: 16 lowercase letters shown in four groups of four, `kqzv-trwm-hpaf-dnye`. It is shown once and the agent keeps no copy. Every front end takes it wherever it takes the agent token. When typed, case, spaces and hyphens do not matter (`KQZV TRWM HPAF DNYE` works), except with SCRAM, which needs the form shown, hyphens included.

Manage them with:

```sh
mimid-agent <config.toml> app-password list            # names, kinds, made, last used; never a secret
mimid-agent <config.toml> app-password add <name>      # name: 1 to 32 of a-z, 0-9 and -
mimid-agent <config.toml> app-password revoke <name>
mimid-agent <config.toml> app-password rotate-token    # a new agent-token file
```

From an IRC client, `/msg mimid passwords` lists them, `/msg mimid password add <name>` makes one and `/msg mimid password revoke <name>` revokes one. The new password arrives in a NOTICE, and IRC clients usually write every line to a log on disk: delete it there, or make passwords with the command line instead.

From a JMAP client, the agent's own capability `tag:reviewcommit.com,2026:mimid:app-passwords` has `AppPassword/get` (every credential: name, kind, when made, last used, and whether revoked — never a secret) and `AppPassword/set` (`create` with a `name`, whose answer carries the new secret once; `destroy` to revoke). No property is writable, and the agent token cannot be destroyed, only replaced with `rotate-token`.

These commands open `mimid.sqlite` themselves, so they work whether or not the agent runs. A running agent reads the table again every 2 seconds and before each login: revoking a credential, or replacing the agent token, closes every IRC connection and JMAP EventSource stream that logged in with it within that time, and its next request gets `401`. After `rotate-token`, attachment links made before keep working until the agent restarts.

The agent stores each credential, the agent token included, as a SCRAM-SHA-256 verifier (4,096 iterations) in the `credentials` table of `mimid.sqlite`. At most 64 are unrevoked at once. A revoked one is listed for 30 days, then deleted. Design: docs/design/frontend-auth.md §3.

## Setting up a client

```sh
mimid-agent <config.toml> setup ca                     # with source = "local-ca": the fingerprint to compare
mimid-agent <config.toml> setup <client> <device>
```

makes an app password named `<device>` and prints what the IRC client `<client>` needs: `goguma`, `weechat`, `irssi`, `hexchat`, `halloy`, `thelounge`, or `generic`. It uses the TLS listener (`[irc] listen_tls`) and the first of `[tls] names`; without a TLS listener it prints the loopback address and says so. For Goguma it also prints a QR code of `ircs://<nick>@<name>:<port>`, which a phone's camera opens in Goguma with the server and nickname filled in; the password is never in the QR code, so type it. With `[tls] source = "tailscale"` it first asks the question of `setup tls` if that is due.

## The configuration file

The file is TOML. Parsing is strict: an unknown key in any table is an error, and so is a missing required key. Put every top-level key before the first `[table]` line; in TOML a key written after `[irc]` belongs to `[irc]`.

### Top-level keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `server_url` | string | required | The base URL of the user's mimid server, starting with `http://` or `https://`. The agent reads the JMAP Session at `<server_url>/.well-known/jmap`. |
| `binding` | `"jmap"` or `"stream"` | `"jmap"` | How the agent talks to the server. `stream` uses mimid's live stream at `<server_url>/mimid/live`, which the server must have on (`live_stream = true`). A stream quiet for 30 seconds is sent a WebSocket Ping, and one that answers nothing by the next probe is dropped and opened again, so a carrier a NAT has reaped costs a reconnect rather than a lost push (decision mimid-1wgh.133). The server probes the same way. There is no setting for the interval. |
| `user_uri` | string | required | The user's URI, `mimi://<domain>/u/<id>`. |
| `token_file` | path | required | The file holding the user's bearer token at `server_url`, as `mimid admin ... token` issued it, without the JSON around it. |
| `state_dir` | path | required | The agent's state directory. See [Files](#files). |
| `listen` | socket address, loopback | none; required while JMAP is on | Where the HTTP endpoint listens: JMAP Chat and the did:webvh log endpoint. It must be a loopback address (`127.0.0.1:<port>` or `[::1]:<port>`); any other is refused. With `[jmap] enabled = false` it may be left out, and then there is no HTTP listener. |
| `sync_interval_ms` | integer, milliseconds, at least 50 | `30000` | The fallback poll. The agent follows the server's EventSource (or the live stream) and syncs as soon as it reports a change, and also syncs after this long without a sync. This is how messages arrive while the stream is down. |
| `key_packages` | integer, 0 to 64 | `10` | How many one-time KeyPackages the agent keeps published. The count is an estimate: the agent learns that one was used only when it joins. |
| `invites` | `"from-allowed"`, `"any"` or `"never"` | `"from-allowed"` | Which room invites the agent joins: those from users this user has allowed, all of them, or none. A call's own room is joined whatever this says, when its parent is a room this user is in: see below. |
| `allowed_origins` | list of strings | `[]` | Web origins allowed to call the HTTP endpoint from a browser (CORS), such as `http://localhost:5173`: lowercase `http` or `https`, a host, an optional port, no path. Compared exactly with the request's `Origin`. `*` and `null` are refused. With none, the endpoint sends no CORS headers. |
| `full_tree_hubs` | list of domains | `[]` | Provider domains of hubs whose rooms get the full ratchet tree with every Commit, for a hub that does not rebuild the tree from the Commits it sees. Other hubs get `distributionService`. The full tree grows with the room and is sent on every Commit. Compared without regard to case. |
| `blob_quota_bytes` | integer, octets | `268435456` (256 MiB) | The most octets of uploads that no stored message refers to yet. An upload past the quota first deletes the oldest such uploads older than an hour, or is refused. |
| `blob_quota_count` | integer | `256` | The most such uploads. Same rule. |

### `[jmap]`

The JMAP Chat front end. On by default.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | boolean | `true` | Serve JMAP Chat at `listen`. With `false`, the HTTP listener, if `listen` is set, still serves the did:webvh log endpoint and answers `404` on the JMAP paths after the Host and credential checks. |
| `listen_tls` | socket address | none | Where the endpoint also listens with HTTPS, on any address: a tailnet or WireGuard address is the safe choice. Needs `[tls]` and `enabled = true`. Off by default. An address that may be reachable from the internet is allowed, with a WARN at start. |
| `webpush` | boolean | `true` | Whether a JMAP client may register for Web Push (`chatPush`). See [Push](#push-what-the-push-service-sees). |
| `vtc` | boolean | `false` | Whether the agent offers calls: `VTCCall` and its signalling, and `VTCCall/exportMediaSecret`. Off by default, unlike everything else here. See below. |

With `[jmap] enabled = false` and no `[irc]`, the agent would serve nothing, and the configuration is refused.

#### `[jmap] vtc`: calls, and why it is off

With `vtc = true` the Session advertises `urn:ietf:params:jmap:vtc` and a JMAP client can start a call in a chat, learn that one is running, exchange SDP offers, answers and ICE candidates, and fetch the call's media secret. The agent hosts the call's own MIMI room under the chat's room and carries the signalling as messages in it, so the signalling is authenticated and end-to-end encrypted like any other message. mimid ships no media stack: the client does the audio and video itself.

`VTCCall/exportMediaSecret` hands the client the call room's MLS exporter secret for the epoch the group is in. That is input keying material for the client's own media key schedule, never a media key: the client derives afresh for each epoch, and a membership change rekeys the call because it rekeys the room. Ask with the epoch you believe the call is in and you get `stateMismatch` with the current one rather than a secret nobody else is using.

It is off by default because it is the one capability here that hands out key material, and because nothing implements the extension yet. While it is off the capability is absent from the Session and a request naming it in `using` gets `unknownCapability` (HTTP 400), so a client can tell "no calls here" from "calls refused".

**Nothing announces a call outside its own room.** The only signal a call exists is the MLS invite into its own room, which a client with no VTC surface cannot interpret as a call. There is no message in the parent chat and no marker for a call having ended. The `mediaTypes` and `subject` a client sets on `VTCCall/set` go no further than its own object, because the call room carries neither, so a client that joins a call it did not start learns neither; the SDP is what says which media a call carries.

Receiving signals needs the JMAP WebSocket at `/jmap/ws`, which the Session advertises: a call signal is an ephemeral event and the EventSource carries only "these types changed, re-fetch", which a signal is not. A client sends `VTCStreamEnable` on the socket and the agent pushes each `VTCCallSignal` as it arrives.

`listen` itself stays loopback only, because it is plaintext; `listen_tls` is how a client on another device reaches the endpoint. Its Session is its own: `apiUrl`, `uploadUrl`, `downloadUrl`, `eventSourceUrl` and the WebSocket URL all name the first `[tls] names` entry over `https:` (`wss:` for the socket), so a client is given URLs it can reach and whose certificate matches. With no configured name the address itself is used. One certificate serves every front end, each on its own port; there is no HTTP/2.

### `[irc]`

The IRC front end. Absent means no IRC. An empty `[irc]` table turns it on with the defaults.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `listen` | socket address | `127.0.0.1:6667` | Where the IRC server listens, without TLS. Any address, not only loopback (decision mimid-1wgh.92). Off loopback the traffic is cleartext: message bodies, and the credential itself with `PASS` or SASL PLAIN, though not with SASL SCRAM-SHA-256. Keeping it off the wrong network is yours to do, with a firewall or a proxy. A credential is required on every listener. Browsers refuse to connect to port 6667, which blocks web pages from sending HTTP to it. |
| `listen_tls` | socket address | none | Where the IRC server also listens with TLS, on any address: a tailnet or WireGuard address is the safe choice. Needs `[tls]`. Off by default. An address that may be reachable from the internet is allowed, with a WARN at start. |
| `server_name` | string | `"mimid.invalid"` | The name the IRC server gives itself: at most 63 characters, letters, digits, `-` and `.`, with at least one dot and no empty label. |
| `webpush` | boolean | `true` | Whether IRC clients may register for Web Push (the `soju.im/webpush` capability). See [Push](#push-what-the-push-service-sees). |

**Calls on IRC.** A stock IRC client has no media stack and no way to exchange SDP, so it cannot join a call mimid keys. It is told about one anyway: a call started elsewhere appears in the chat's channel as a server notice — *"alice started a video call: standup — this client cannot join it"* — rather than as an ordinary message, which would look like something to act on. The call's own room gets no channel, so there is nothing to join by mistake, and `call` given no URL answers that one is required: IRC can send a link to a call hosted elsewhere but cannot host one itself.

The client logs in with a credential (the token in `<state_dir>/agent-token`, or an app password) by SASL PLAIN, SASL SCRAM-SHA-256 or as its server password (`PASS`). If both SASL and PASS come, SASL decides. A client that turned on the `sasl` capability and sent no credential gets `FAIL * ACCOUNT_REQUIRED`; others get 464.

Failed logins are never locked out, but after 5 failures from one address in 10 minutes (20 from loopback; IPv6 counted per /64) each further failure is answered after a delay, 1 second doubling to 30, until a login from that address succeeds. At most 32 connections that have not logged in are open at once, 8 per address, and each must log in within 30 seconds.

### `[tailnet]`

Tailnet identity: a connection from a Tailscale node this agent recognises needs no password, because the connection itself is the login (docs/design/frontend-auth.md §4.6). **Off by default.** It applies to IRC only — the HTTP endpoint keeps its credential on purpose, see below.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `identity` | boolean | `false` | Whether a matching node may register with no credential. |
| `owners` | list of Tailscale login names | the owner of this node | Whose own devices are let in. Read from tailscaled at start when left empty. |
| `nodes` | list of node names | `[]` | Extra nodes let in whoever owns them, e.g. `pixel-8.tailnet.ts.net`. |
| `tags` | list of ACL tags | `[]` | Extra tags let in, e.g. `tag:chat-client`. Each must start with `tag:`. |
| `socket` | path | `/var/run/tailscale/tailscaled.sock` | tailscaled's LocalAPI socket. |
| `recheck_s` | integer, at least 10 | `300` | How often an open session's node is checked again. |

A node is let in when its user's login name is in `owners` **and** it is not tagged, is not this agent's own node, and advertises no routes; or when its name is in `nodes` or one of its tags is in `tags`. Each exclusion closes a hole: a tagged node has no user and its tags come from whoever writes the ACL policy; this agent's own node answers for connections from this host, so every local account would pass as the owner; and a subnet router or exit node source-NATs the traffic it forwards, so a device on its LAN would pass as the router's owner.

Anything else falls back to the password rules, including tailscaled not answering: a failed lookup never lets a connection in. On IRC a matched client is not told `soju.im/account-required`, so Goguma labels its password field optional; any password it does send is accepted and decides nothing.

`/msg mimid tailnet` says what matched for this connection, then lists every node with a connection open and the sessions from it, and the nodes denied. `/msg mimid tailnet deny <node>` refuses a node from now on and closes its sessions at once; the list is kept in `tailnet-denied` in the state directory, so it survives a restart, and the only way to undo a denial is to edit that file — an undeny typed from a client the denied node might be holding would be a way back in.

The agent reads tailscaled's `status` at start and refuses to start if it cannot — serving the password rules while you believe otherwise would be worse. It also refuses if this node is tagged and `owners` is empty (a tagged node has no owner to default to), so set `owners` on a tagged host.

**Real revocation is the tailnet admin console.** Removing the node, letting its key expire or taking its tag away ends its sessions within `recheck_s`. A `tailnet deny` here refuses the node at this agent only: it keeps its place in the tailnet and everything else on it.

**Why not JMAP.** With no `Authorization` header a request would be authorized by where it comes from, and a web page open in a browser on your laptop comes from your laptop — so any site you visit could POST JMAP calls to the agent. CORS stops such a page reading the answer, not the call happening.

With `tailscale cert` as the `[tls] source`, a phone needs only Tailscale installed, which it needs anyway to reach the agent, and the server name typed.

Linux only: macOS's App Store Tailscale exposes the LocalAPI differently.

### `[tls]`

Where the certificate of the TLS listeners comes from (docs/design/frontend-auth.md §5). Needed by any `listen_tls`; absent by default.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `source` | `"files"`, `"tailscale"`, `"acme"` or `"local-ca"` | required | `files`: a PEM certificate chain and key you already have. `tailscale`: tailscaled's certificate for the machine's MagicDNS name, fetched over its LocalAPI. `acme`: a publicly trusted certificate from an ACME authority over DNS-01, if you have a domain. `local-ca`: an authority the agent makes itself, which you install on each device (see below). |
| `names` | list of DNS names | `[]` | The names the certificate covers. The first is the name setup prints, and with `tailscale` the one asked for, which must then be the machine's `<machine>.<tailnet>.ts.net`. Required with `tailscale`. |

`[tls.files]` has `cert` and `key`, PEM paths. The agent reads them at start, and again within a minute of either changing; open connections keep the certificate they started with.

`[tls.tailscale]` has `socket`, tailscaled's LocalAPI socket, default `/var/run/tailscale/tailscaled.sock`. tailscaled hands certificates only to root, its operator user (`tailscale set --operator=$USER`) or the uid in `TS_PERMIT_CERT_UID`; the tailnet needs MagicDNS and HTTPS certificates turned on in its admin console. The agent asks again once a day.

**`tailscale cert` makes your names public.** Every certificate a public CA issues is published in Certificate Transparency logs, which anyone can search, so the tailnet's name and the machine's name become public. The agent therefore asks first: `mimid-agent <config.toml> setup tls` explains this and asks. A yes is kept in `<state_dir>/tailscale-cert-consent` with the names; without it, or after the names change, the agent refuses to start with `source = "tailscale"`. If you do not want the names public, use your own certificate with `source = "files"`.

A renewal that works logs `agent_certificate_renewed` at INFO with the new `not_after`; one that fails logs `agent_certificate_renewal_failed` at WARN, or at ERROR once the certificate in use is within 3 days of expiry, and the old certificate stays in use either way.

**The agent warns before the certificate expires.** Whatever `source` it came from, the agent reads the certificate's own `notAfter` and logs `agent_certificate_expiring` at WARN from 14 days before, at ERROR from 3 days before, and `agent_certificate_expired` at ERROR every hour once it has expired. Each carries `names`, `source`, `not_after` (RFC 3339) and `days_left`. An expired certificate keeps being served rather than closing the listener: clients will refuse it, and the log says why. With `source = "files"` this is the only sign you get that your own certbot or `tailscale cert` timer has stopped working. A certificate the agent cannot parse is served with no expiry check, which it says once at DEBUG.

#### `source = "acme"`

A publicly trusted certificate from an ACME authority, renewed without you, for a user who has a domain. Nothing is installed on any device. `[tls] names` are the names it is ordered for, all in one certificate, and they have to be names you control the DNS for.

**DNS-01 only.** HTTP-01 and TLS-ALPN-01 need the agent reachable on port 80 or 443 from the internet, which a personal agent usually is not. DNS-01 needs no inbound connection, so it works for a name pointing at a tailnet or WireGuard address — but something has to write a TXT record at `_acme-challenge.<name>`, which `dns` picks.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `directory` | https URL | required | The authority's directory, e.g. `https://acme-v02.api.letsencrypt.org/directory`. |
| `contact` | string | none | A contact URI for the account, e.g. `mailto:you@example.org`. |
| `dns` | `"hook"` or `"acme-dns"` | `"hook"` | How the TXT record is written. |
| `hook` | path | required with `dns = "hook"` | A command called with the record's name and value. |
| `root` | path | none | A PEM root to trust for the directory and the acme-dns instance instead of the public roots, for a private authority (Boulder, Pebble, step-ca). |

`[tls.acme.acme-dns]`, with `dns = "acme-dns"`: `url`, `username`, `password` and `subdomain`, all from the one-time registration at that instance.

The hook is your command, the way lego's, acme.sh's and certbot's manual hooks work: the agent runs it with two arguments, the record's name and its value, and takes a zero exit as "the record is live". It does not look the record up to confirm, so a hook that returns before its provider has published leaves the authority to fail the challenge, and the order starts over. Give it up to two minutes.

```sh
#!/bin/sh
# $1 is _acme-challenge.chat.example.org, $2 is the value
your-dns-tool txt set "$1" "$2" && sleep 10
```

In the state directory: `acme-account.json` (0600), the account, so the same one is used at every start; `acme-cert.pem` and `acme-key.pem` (0600), the certificate. A new certificate is ordered once two thirds of the certificate's own lifetime has passed, which is Let's Encrypt's advice. The lifetime is read from the certificate, so a short-lived profile (Let's Encrypt's six-day one, for instance) renews on its own schedule; a certificate the agent cannot parse falls back to the file's age against an assumed 90 days.

##### `dns = "acme-dns"`

[acme-dns](https://github.com/joohoi/acme-dns) is a DNS server for this one job: it serves the `_acme-challenge` records for a subdomain you CNAME to it, so your own provider needs no API. Register once at an instance (your own, or the public `auth.acme-dns.io`), which gives you a username, a password and a subdomain; then put a CNAME in your zone, by hand, once:

```
_acme-challenge.chat.example.org.  CNAME  <subdomain>.auth.acme-dns.io.
```

From then on the agent posts each challenge value to that instance and it serves the record. **The agent never touches your real zone**, and the credentials it holds can write nothing but that one subdomain, unlike a hook with full DNS access. The password is a secret: it is redacted wherever the configuration is printed and never logged.

As with the hook, a 2xx is taken as proof the record is live; the CNAME is not checked, so a missing one shows up only as the authority failing the challenge.

**Not built, and not planned:** the third way §5.2 names, an RFC 2136 dynamic update with a TSIG key. A hook calling `nsupdate` drives the same protocol with a tool you already have.

#### `source = "local-ca"`

For a user with neither a domain nor a tailnet. The agent makes its own certificate authority, signs a certificate for the `[tls] names` with it, and you install the authority on each device; after that your clients trust it with no warning. This is the most work of the four. The alternative is a self-signed certificate, which many clients refuse outright and the rest warn about on every connection.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bootstrap` | socket address | none | A plain-HTTP address serving the install page and nothing else. Off by default. |

In the state directory: `local-ca.key` (0600) and `local-ca.pem`, the authority; `local-ca-leaf.key` (0600) and `local-ca-leaf.pem`, the listener's; `local-ca.names`, what they were made for.

- **The authority is name-constrained** to exactly the `[tls] names`, as DNS-name and IP-address permitted subtrees with a path length of 0. A device that trusts it trusts nothing else it could sign — not another name, and not another authority under it.
- **The certificate lasts 90 days** and is made again once it is 60 days into that life, judged by its own `notAfter` so that a certificate copied in with a fresh timestamp is still renewed when it is due. The authority lasts 10 years and nothing renews it: at that point the agent makes a new one and you install it again.
- **The certificate is kept** across restarts, not made fresh each time, because Goguma and Conversations remember the one they first saw and would ask again otherwise.
- **Changing `[tls] names` remakes both**, since neither the constraint nor the certificate would cover the new names, and you install the new authority.

To install it, run `mimid-agent <config.toml> setup ca`, which prints the authority's SHA-256 fingerprint and the address to open. The page at `/mimid/ca` offers the certificate as `.crt` and as an Apple configuration profile, and shows the same fingerprint: compare the two before trusting it. The page needs no credential — its content is the authority certificate, which the TLS listener already sends in every handshake.

A device that does not trust the authority yet cannot open that page over TLS, which is what `bootstrap` is for: it serves the same page in the clear, on an address you name, and answers 404 on every other path. It is off by default; the other way is to copy `local-ca.pem` across by hand.

Per-device steps are on the page: on iOS, install the profile and then turn it on in Certificate Trust Settings (it is not trusted until that second step); on Android, install the `.crt` and accept the warning, though Goguma and Conversations do not need it; on a computer, add the `.crt` to the system store or point the client at it.

There is no revocation: a certificate expires rather than being revoked.

### `[telemetry]`

OpenTelemetry export over OTLP/HTTP, with the same keys and defaults as the server's `[telemetry]` table (see [operating.md](operating.md#telemetry)). Off when the table is absent, which is the default: the agent runs on the user's machine, so it exports nothing until the user names a collector.

```toml
[telemetry]
endpoint = "http://127.0.0.1:4318"
```

Differences from the server:

- `service.instance.id` is `user_uri`, so a collector that holds several agents, or an agent and its provider, can tell them apart. It also tells the collector which user this agent is; leave the table out if you do not want that.
- The spans follow a message, not a user action: `store_send`, `store_sync` and `store_received` in the store, `agent_send_content` and `agent_receive` in the agent, and under those `mls_encrypt_and_stage`, `provider_submit`, `finish_outbox`, `provider_fetch` and `handle_message`. They are at DEBUG, which `[telemetry] span_level` exports without the log printing them. `store_send`, `agent_send_content` and `store_received` carry `msgid`, the message ID as lowercase hex, the rendering a record and an IRC `msgid` tag already use, so one message's path can be followed across both binaries. A front end's own work has no span, so a trace starts at the store.

`service_name` defaults to `mimid` in both binaries. Set it to `mimid-agent` if one collector takes the agent's export and a server's, so the two are not one service.

If telemetry cannot be flushed at shutdown, the agent logs `agent_telemetry_flush_failed`.

### `[did_webvh]`

draft-atwood-mls-didwebvh-credential. The table is optional, and so is each key in it.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `support` | boolean | `true` | Whether a BasicCredential agent shares rooms with `did_webvh` users. |
| `credential_type` | integer, 16 bits | `0x0008` | The `did_webvh` credential type, the draft's suggested value. 0x0000 to 0x0002 and GREASE values are refused. |
| `heads_component` | integer, 16 bits | `0xf013` | The `app_data_dictionary` component that carries the `did_webvh_heads` record; 0xF013 is a private-use value of mimid's own. 0x0000 to 0x0005 and GREASE values below 0x8000 are refused. |
| `log_file` | path | none | The `did.jsonl` log from the user's controller for this device. Without it the agent uses a BasicCredential. With it, at every start the agent takes the log as its credential if it is newer than the one it holds and offers it to its rooms, and while it runs it takes the file again whenever it changes. The log must list this device's signature key and the user's URI in `alsoKnownAs`. |
| `witness_file` | path | none | The `did-witness.json` that goes with `log_file`. |

`credential_type` and `heads_component` must match the server's `[did_webvh]` values and those of every other member of the user's rooms. The key `heads_extension_type` of earlier versions is refused as unknown.

The HTTP endpoint also accepts a newer log at `POST /mimid/did-webvh/log`, with the same Host and token checks as JMAP.

There is no separate push setting. The agent always follows the server's EventSource, or the live stream with `binding = "stream"`. An EventSource stream that cannot be opened, or ends, is tried again after 1 second, the delay doubling up to 60 seconds; meanwhile `sync_interval_ms` keeps polling.

## Example

```toml
server_url = "https://mimi.a.example"
user_uri = "mimi://a.example/u/alice"
token_file = "/home/alice/.config/mimid-agent/server-token"
state_dir = "/home/alice/.local/state/mimid-agent"
listen = "127.0.0.1:8484"

[irc]
listen = "127.0.0.1:6667"
```

For the two loopback providers in [operating.md](operating.md#example-two-federated-providers-on-loopback), an agent for alice on `a.example` sets `server_url = "http://127.0.0.1:18401"`.

## How clients connect

- **JMAP Chat**: the Session is at `http://127.0.0.1:<port>/.well-known/jmap`, with `Authorization: Bearer <credential>` or `Authorization: Basic <base64(any-username:credential)>`, where the credential is the agent token or an app password. With Basic the username is ignored: the agent serves one user, so the secret alone picks the credential, and that is what a "username and password" client (Pidgin-shaped, purple-mimi) needs. A `401` offers `Basic` back only to a request that used it, so a browser that sent a bearer token is not given its own login box. The request's `Host` must be `127.0.0.1:<port>`, `[::1]:<port>` or `localhost:<port>`; any other gets `421`. This blocks DNS rebinding.
- **JMAP Chat over TLS**, with `[jmap] listen_tls`: the Session is at `https://<name>:<port>/.well-known/jmap`, where `<name>` is a `[tls] names` entry. The Host check takes those names and the listener's own address at that port, and the loopback names too; anything else is `421`. Failed credentials are slowed per source address exactly as IRC's are (see `[irc]` below).
- **IRC**: connect to the `[irc]` `listen` address, or with TLS to `listen_tls`, and send a credential with SASL or `PASS`. With `[tailnet] identity = true`, a connection from a tailnet node the agent recognises needs no credential at all (see `[tailnet]`).

## Goguma

Goguma (Android and iOS) is the phone client the IRC front end is built for. Run `setup goguma <device>` (above) and add the server in Goguma from the QR code, with the app password it printed. It needs the TLS listener: Goguma offers no password field without TLS and SASL PLAIN. A self-signed or tailnet certificate is fine; Goguma asks once and pins it.

What works:

- **Channels and private queries.** Each room is a channel. A one-to-one room is a private query with the other user's nick; to write to someone you have never seen, start the query with `bob@b.example` as the nick. Closing a query in Goguma only archives it on the phone; `/part` in a query hides it from the agent's list of conversations until the next message. Neither leaves the room.
- **History.** Goguma fetches what came while it was away (`draft/chathistory`), from the agent's store: channels and queries, 1000 messages a request. Messages deleted or expired here are not served.
- **Read markers.** What you read on the phone is read in every other client of this agent, JMAP Chat clients included, and the other way round (`draft/read-marker`).
- **Push.** On by default; see below.
- **Replies and reactions** show and can be sent. Edits show as a new line starting `(edited)`. Deleting your own message in Goguma retracts it for everyone (`REDACT`); a message someone retracted disappears in Goguma, and shows as a notice in clients without that feature.

Not there: attachments, sending edits, user presence (no `MONITOR` or away status: MIMI carries no presence), file upload (`soju.im/FILEHOST`), avatars and pinned or muted state on the server (`draft/metadata-2`; Goguma keeps them on the phone).

## Push: what the push service sees

With `[irc] webpush = true` (the default) an IRC client can register a Web Push subscription (`WEBPUSH REGISTER`). Goguma does this at every connection. The agent then pushes the client one IRC line for each private message from someone else, each channel message from someone else that names your nick or replies to you, each pending invite, and each read marker moved on another device (so the phone clears notifications you have read elsewhere). Goguma shows no notification of its own while it has a push subscription, so the agent pushes whether or not the phone is connected.

The push goes to the endpoint the client registered: for Goguma, its own relay (`pushgarden.emersion.fr`, which passes it to Google's or Apple's push service) or a UnifiedPush distributor you chose. Each push is encrypted to keys the phone made (RFC 8291) and signed with the agent's VAPID key (RFC 8292). What the relay and the push service see:

- that this agent sent a push to this endpoint, and when;
- a body of the same size every time (1024 bytes of padded plaintext): no text, sender, room or length;
- the `Urgency` (`high` for a message or invite, `normal` for a read marker), a `TTL` of 7 days, and the agent's VAPID public key, the same for every push of this agent;
- the agent's address, as any HTTP client shows it.

They can count your messages and see when they come. Set `webpush = false` to send nothing; the phone then only learns of messages when Goguma connects. An endpoint must be `https`, or `http` on loopback. A subscription is dropped when the client unregisters it or the push service answers 404 or 410. Design: docs/design/agent-frontends.md §7.35.

## Attachment links

With `listen` set, the agent can hand a front end's client a link to one attachment: `http://<listen>/attachment/<blobId>/<expires>/<mac>/<name>`. With `[jmap] listen_tls` the links are its `https://<name>:<port>/attachment/...` instead, since a client on another device can reach only that listener. The link needs no credential: whoever holds it can fetch that file until it expires (an hour by default, a day at most) and while a message the agent keeps names the file. Treat a link like the file itself. A new `agent-token` file (delete it and restart) revokes every link. Design: docs/design/agent-frontends.md §7.30.

## Files

Everything is under `state_dir`:

- The directory is created with mode 0700. An existing directory or file that group or others can reach is refused.
- `mimid.sqlite` (mode 0600): the user's MLS private keys, KeyPackage private keys and groups, the delivery journal, the outbox of messages being sent, the plaintext message, room and contact records, the credentials, and the Web Push subscriptions with the agent's VAPID key.
- `agent-token` (mode 0600): the token for local clients.
- `blobs/`: attachments, in plaintext.
- `lock` (mode 0600, never deleted): while the agent runs it holds an exclusive lock on this file, so a second agent on the same directory (another `mimid-agent`, or purple-mimi pointed at it) refuses to start with "the state directory is in use by another agent" instead of corrupting the MLS state. Do not delete it while the agent runs.

The agent also refuses to start when `token_file` holds another user's token: the server's Session names the token's user, and it must be `user_uri`.

A directory that holds files of an older layout (`state.json`, `mls.sqlite`, `chat.sqlite` or `agent.sqlite`) is refused; nothing is converted. A database of another schema version is refused too.

Keep `token_file` readable only by the user.
