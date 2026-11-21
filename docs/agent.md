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

The agent stores each credential, the agent token included, as a SCRAM-SHA-256 verifier (4,096 iterations) in the `credentials` table of `mimid.sqlite`. At most 64 are unrevoked at once. A revoked one is listed for 30 days, then deleted. Design: docs/design/frontend-auth.md §3.

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
| `enabled` | boolean | `true` | Serve JMAP Chat at `listen`. With `false`, the HTTP listener, if `listen` is set, still serves the did:webvh log endpoint and answers `404` on the JMAP paths after the Host and token checks. |

With `[jmap] enabled = false` and no `[irc]`, the agent would serve nothing, and the configuration is refused.

### `[irc]`

The IRC front end. Absent means no IRC. An empty `[irc]` table turns it on with the defaults.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `listen` | socket address, loopback | `127.0.0.1:6667` | Where the IRC server listens. It must be a loopback address. Browsers refuse to connect to port 6667, which blocks web pages from sending HTTP to it. |
| `server_name` | string | `"mimid.invalid"` | The name the IRC server gives itself: at most 63 characters, letters, digits, `-` and `.`, with at least one dot and no empty label. |

The client's `PASS` is the token in `<state_dir>/agent-token`. There is no SASL.

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

- **JMAP Chat**: the Session is at `http://127.0.0.1:<port>/.well-known/jmap`, with `Authorization: Bearer <agent-token>`. The request's `Host` must be `127.0.0.1:<port>`, `[::1]:<port>` or `localhost:<port>`; any other gets `421`. This blocks DNS rebinding.
- **IRC**: connect to the `[irc]` `listen` address and send the agent token with `PASS`.

## Attachment links

With `listen` set, the agent can hand a front end's client a link to one attachment: `http://<listen>/attachment/<blobId>/<expires>/<mac>/<name>`. The link needs no token: whoever holds it can fetch that file, from a loopback address, until it expires (an hour by default, a day at most) and while a message the agent keeps names the file. Treat a link like the file itself. A new `agent-token` file (delete it and restart) revokes every link. Design: docs/design/agent-frontends.md §7.30.

## Files

Everything is under `state_dir`:

- The directory is created with mode 0700. An existing directory or file that group or others can reach is refused.
- `mimid.sqlite` (mode 0600): the user's MLS private keys, KeyPackage private keys and groups, the delivery journal, the outbox of messages being sent, and the plaintext message, room and contact records.
- `agent-token` (mode 0600): the token for local clients.
- `blobs/`: attachments, in plaintext.

A directory that holds files of an older layout (`state.json`, `mls.sqlite`, `chat.sqlite` or `agent.sqlite`) is refused; nothing is converted. A database of another schema version is refused too.

Keep `token_file` readable only by the user.
