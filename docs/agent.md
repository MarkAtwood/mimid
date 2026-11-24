# Running mimid-agent

`mimid-agent` runs for one user on one device. It holds the user's MLS keys, talks to the user's mimid server, and serves the user's rooms in plaintext on loopback only: as a JMAP Chat endpoint (on by default) and as an IRC server (off by default). A standard JMAP Chat client or a stock IRC client connects to it. The server's operator guide is [operating.md](operating.md).

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

`RUST_LOG` filters the log, which goes to standard output in text form; it defaults to `info`. On start the agent opens or creates its state directory, publishes KeyPackages, binds its listeners and then serves.

SIGINT and SIGTERM both stop it. The stop ends the sync loop, the HTTP server, every EventSource stream and every IRC connection. Unix only.

## The token for local clients

On first start the agent writes a token of its own to `<state_dir>/agent-token` (32 random octets as unpadded base64url, mode 0600), and reads it on later starts. This is not the server token:

- A JMAP Chat client sends it as `Authorization: Bearer <token>` to the agent's `listen` address.
- An IRC client sends it as the server password (`PASS`).

A client running as the same user reads it from that file.

The agent token is one credential among the agent's app passwords (see [App passwords](#app-passwords)); every front end takes either. The agent keeps, for each, only a SCRAM-SHA-256 verifier in `mimid.sqlite`.

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
| `binding` | `"jmap"` or `"stream"` | `"jmap"` | How the agent talks to the server. `stream` uses mimid's live stream at `<server_url>/mimid/live`, which the server must have on (`live_stream = true`). |
| `user_uri` | string | required | The user's URI, `mimi://<domain>/u/<id>`. |
| `token_file` | path | required | The file holding the user's bearer token at `server_url`, as `mimid admin ... token` issued it, without the JSON around it. |
| `state_dir` | path | required | The agent's state directory. See [Files](#files). |
| `listen` | socket address, loopback | none; required while JMAP is on | Where the HTTP endpoint listens: JMAP Chat and the did:webvh log endpoint. It must be a loopback address (`127.0.0.1:<port>` or `[::1]:<port>`); any other is refused. With `[jmap] enabled = false` it may be left out, and then there is no HTTP listener. |
| `sync_interval_ms` | integer, milliseconds, at least 50 | `30000` | The fallback poll. The agent follows the server's EventSource (or the live stream) and syncs as soon as it reports a change, and also syncs after this long without a sync. This is how messages arrive while the stream is down. |
| `key_packages` | integer, 0 to 64 | `10` | How many one-time KeyPackages the agent keeps published. The count is an estimate: the agent learns that one was used only when it joins. |
| `invites` | `"from-allowed"`, `"any"` or `"never"` | `"from-allowed"` | Which room invites the agent joins: those from users this user has allowed, all of them, or none. |
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

With `[jmap] enabled = false` and no `[irc]`, the agent would serve nothing, and the configuration is refused.

`listen` itself stays loopback only, because it is plaintext; `listen_tls` is how a client on another device reaches the endpoint. Its Session is its own: `apiUrl`, `uploadUrl`, `downloadUrl`, `eventSourceUrl` and the WebSocket URL all name the first `[tls] names` entry over `https:` (`wss:` for the socket), so a client is given URLs it can reach and whose certificate matches. With no configured name the address itself is used. One certificate serves every front end, each on its own port; there is no HTTP/2.

### `[irc]`

The IRC front end. Absent means no IRC. An empty `[irc]` table turns it on with the defaults.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `listen` | socket address, loopback | `127.0.0.1:6667` | Where the IRC server listens, without TLS. It must be a loopback address. Browsers refuse to connect to port 6667, which blocks web pages from sending HTTP to it. |
| `listen_tls` | socket address | none | Where the IRC server also listens with TLS, on any address: a tailnet or WireGuard address is the safe choice. Needs `[tls]`. Off by default. An address that may be reachable from the internet is allowed, with a WARN at start. |
| `server_name` | string | `"mimid.invalid"` | The name the IRC server gives itself: at most 63 characters, letters, digits, `-` and `.`, with at least one dot and no empty label. |
| `webpush` | boolean | `true` | Whether IRC clients may register for Web Push (the `soju.im/webpush` capability). See [Push](#push-what-the-push-service-sees). |

The client logs in with a credential (the token in `<state_dir>/agent-token`, or an app password) by SASL PLAIN, SASL SCRAM-SHA-256 or as its server password (`PASS`). If both SASL and PASS come, SASL decides. A client that turned on the `sasl` capability and sent no credential gets `FAIL * ACCOUNT_REQUIRED`; others get 464.

Failed logins are never locked out, but after 5 failures from one address in 10 minutes (20 from loopback; IPv6 counted per /64) each further failure is answered after a delay, 1 second doubling to 30, until a login from that address succeeds. At most 32 connections that have not logged in are open at once, 8 per address, and each must log in within 30 seconds.

### `[tailnet]`

Tailnet identity: a connection from a Tailscale node this agent recognises needs no password, because the connection itself is the login (docs/design/frontend-auth.md §4.6). **Off by default.** It applies to **IRC only** — the HTTP endpoint keeps its credential on purpose, see below.

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

The agent reads tailscaled's `status` at start and **refuses to start** if it cannot — serving the password rules while you believe otherwise would be worse. It also refuses if this node is tagged and `owners` is empty (a tagged node has no owner to default to), so set `owners` on a tagged host.

**Real revocation is the tailnet admin console.** Removing the node, letting its key expire or taking its tag away ends its sessions within `recheck_s`. A `tailnet deny` here refuses the node at this agent only: it keeps its place in the tailnet and everything else on it.

**Why not JMAP.** With no `Authorization` header a request would be authorized by where it comes from, and a web page open in a browser on your laptop comes from your laptop — so any site you visit could POST JMAP calls to the agent. CORS stops such a page reading the answer, not the call happening. So JMAP keeps its credential.

With `tailscale cert` as the `[tls] source`, this is the least-friction phone setup there is: nothing to install but Tailscale, which the phone needs anyway to reach the agent, and nothing to type but the server name.

Linux only: macOS's App Store Tailscale exposes the LocalAPI differently.

### `[tls]`

Where the certificate of the TLS listeners comes from (docs/design/frontend-auth.md §5). Needed by any `listen_tls`; absent by default.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `source` | `"files"`, `"tailscale"` or `"local-ca"` | required | `files`: a PEM certificate chain and key you already have. `tailscale`: tailscaled's certificate for the machine's MagicDNS name, fetched over its LocalAPI. `local-ca`: an authority the agent makes itself, which you install on each device (see below). |
| `names` | list of DNS names | `[]` | The names the certificate covers. The first is the name setup prints, and with `tailscale` the one asked for, which must then be the machine's `<machine>.<tailnet>.ts.net`. Required with `tailscale`. |

`[tls.files]` has `cert` and `key`, PEM paths. The agent reads them at start, and again within a minute of either changing; open connections keep the certificate they started with.

`[tls.tailscale]` has `socket`, tailscaled's LocalAPI socket, default `/var/run/tailscale/tailscaled.sock`. tailscaled hands certificates only to root, its operator user (`tailscale set --operator=$USER`) or the uid in `TS_PERMIT_CERT_UID`; the tailnet needs MagicDNS and HTTPS certificates turned on in its admin console. The agent asks again once a day.

**`tailscale cert` makes your names public.** Every certificate a public CA issues is published in Certificate Transparency logs, which anyone can search, so the tailnet's name and the machine's name become public. The agent therefore asks first: run `mimid-agent <config.toml> setup tls`, which explains this and asks. A yes is kept in `<state_dir>/tailscale-cert-consent` with the names; without it, or after the names change, the agent refuses to start with `source = "tailscale"`. If you do not want the names public, use your own certificate with `source = "files"`.

No warning is logged before the certificate expires; a client's refusal is what shows it.

#### `source = "local-ca"`

For a user with neither a domain nor a tailnet. The agent makes its own certificate authority, signs a certificate for the `[tls] names` with it, and you install the authority on each device; after that your clients trust it with no warning. This is the last resort of the four, and the most work for you, which is why it is last — but the alternative is a self-signed certificate that Element X, Monal and Dino refuse outright and that warns on every other client, every time.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bootstrap` | socket address | none | A plain-HTTP address serving the install page and nothing else. Off by default. |

In the state directory: `local-ca.key` (0600) and `local-ca.pem`, the authority; `local-ca-leaf.key` (0600) and `local-ca-leaf.pem`, the listener's; `local-ca.names`, what they were made for.

- **The authority is name-constrained** to exactly the `[tls] names`, as DNS-name and IP-address permitted subtrees with a path length of 0. A device that trusts it trusts nothing else it could sign — not another name, and not another authority under it.
- **The certificate lasts 90 days** and is made again once its file is 60 days old. The authority lasts 10 years and nothing renews it: at that point the agent makes a new one and you install it again.
- **The certificate is kept** across restarts, not made fresh each time, because Goguma and Conversations remember the one they first saw and would ask again otherwise.
- **Changing `[tls] names` remakes both**, since neither the constraint nor the certificate would cover the new names, and you install the new authority.

To install it, run `mimid-agent <config.toml> setup ca`, which prints the authority's SHA-256 fingerprint and the address to open. The page at `/mimid/ca` offers the certificate as `.crt` and as an Apple configuration profile, and shows the same fingerprint: **compare the two before trusting it.** The page needs no credential — its content is the authority certificate, which the TLS listener already sends in every handshake.

A device that does not trust the authority yet cannot open that page over TLS, which is what `bootstrap` is for: it serves the same page in the clear, on an address you name, and answers 404 on every other path. It is off by default; the other way is to copy `local-ca.pem` across by hand.

Per-device steps are on the page: on iOS, install the profile and then turn it on in Certificate Trust Settings (it is not trusted until that second step); on Android, install the `.crt` and accept the warning, though Goguma and Conversations do not need it; on a computer, add the `.crt` to the system store or point the client at it.

There is no revocation: a certificate expires rather than being revoked, which for one listener on one host is all there is to want.

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
