# Running the mimid server

This is the operator's guide to `mimid`, the provider server. It covers starting and stopping it, every configuration key, the admin commands, and the files it keeps. The agent, `mimid-agent`, has its own guide in [agent.md](agent.md).

mimid is a work in progress and not ready for production use. Read "Known weaknesses" in the [README](../README.md) before you federate with anyone.

## Starting

```sh
mimid <config.toml>
```

The one argument is the configuration file. `mimid` reads it, opens the database, binds its listeners and logs `mimid listening` (event `server_listening`) once it serves. Any error in the configuration stops it before it binds anything.

Environment variables:

| Variable | Values | Default | Meaning |
|---|---|---|---|
| `RUST_LOG` | a `tracing` filter, such as `info` or `mimid_server=debug,info` | `info` | Which log events are written. |
| `MIMID_LOG_FORMAT` | `text` or `json` | `text` (also when unset or empty) | The format of the log on standard output. `json` writes one JSON object per line, with the event's stable name in `event`, and `level`, `target`, `message`, `fields` and `spans`. Any other value stops `mimid` at startup. |

The log goes to standard output. The text format does not show event names; use `json` if you need them, for example to alert on `shutdown_grace_expired` or `welcome_too_large`.

With a `[telemetry]` table, spans, the log events that `RUST_LOG` keeps, and metrics also go to an OpenTelemetry collector (see [telemetry](#telemetry)).

## Stopping

SIGINT and SIGTERM do the same thing. On either signal `mimid`:

1. stops accepting connections;
2. ends every open EventSource stream and live stream at once;
3. gives the requests in flight, the local control listener and the database 10 seconds to finish;
4. exits. Whatever is still running after the 10 seconds is abandoned, and `mimid` logs `shutdown_grace_expired` at WARN before it exits.

Other details:

- A signal that arrives while `mimid` is still starting is kept, and `mimid` stops as soon as it serves. A signal that arrives while the configuration file is still being read kills the process.
- The fanout worker, which delivers to peers, is abandoned mid-request. The delivery is sent again on the next start.
- With `[tls]`, `mimid` stops accepting connections but does not wait for HTTPS connections already in flight.
- Signals are handled on Unix only.

## The configuration file

The file is TOML. Parsing is strict:

- An unknown key, in any table, is an error.
- A missing required key is an error.
- A malformed domain, address or URL is an error.

Put every top-level key before the first `[table]` line. In TOML, a key after `[peers]` belongs to `[peers]`, so a `local_listen = ...` line written after `[peers]` is read as a peer named `local_listen` and refused.

Value forms used below:

- **domain**: a DNS name in lowercase ASCII, labels of letters, digits and `-`, no trailing dot, at most 253 octets (63 per label). `B.example`, `b.example.` and `mimi://b.example` are refused.
- **base URL**: `http://host[:port]` or `https://host[:port]`, with no path, query or user name. A single trailing `/` is accepted and dropped. `http://127.0.0.1:9080` is fine; `http://127.0.0.1:9080/mimi` and `127.0.0.1:9080` are refused.
- **socket address**: an IP address and a port, `127.0.0.1:8080` or `[::1]:8080`. A host name such as `localhost:8080` is refused.
- **path**: a file system path, as a string.

### Top-level keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `domain` | domain | required | This provider's domain, as in `mimi://<domain>`. User URIs of this provider are `mimi://<domain>/u/<id>`. |
| `listen` | socket address | required | Where the protocol and JMAP listener binds. It speaks plain HTTP, or HTTPS with `[tls]`. |
| `base_url` | base URL | required | The public URL other providers and JMAP clients use to reach this server. The directory document at `/.well-known/mimi-protocol-directory` and the JMAP Session's URLs are built from it. Peers sign requests to this URL, so it must be the URL they actually use. |
| `database` | path | required | The SQLite database file. It is created if missing. See [Files](#files). |
| `max_key_packages` | integer, 0 or more | `97` | The most KeyPackages the server stores per account, advertised to JMAP clients as `maxKeyPackages`. |
| `live_stream` | boolean | `false` | Serve mimid's live stream at `/mimid/live`, a second binding between agent and server beside JMAP. An agent with `binding = "stream"` needs it on. |
| `reuse_last_resort_key_packages` | boolean | `false` | `false` hands out a client's last-resort KeyPackage once, as protocol-07 §5.2 requires; the client is then reported as out of key material until it publishes more. `true` hands it out, and keeps it, in every keyMaterial answer in which the client has no other usable KeyPackage, as mls-extensions-11 §6.4 allows and draft-atwood-jmap-chat-mimi-00 permits. |
| `local_listen` | socket address | none | The address of the local control listener, which `mimid admin` talks to. It must be a loopback address, or `mimid` refuses to start. Without it there is no local control listener and `mimid admin` does not work. |
| `local_token` | string, at least 32 visible ASCII characters | none | The bearer token every call to the local control listener must carry. Without it, anyone who can reach the host's loopback interface can use the listener. Set it on any host where other people have shells. |
| `require_franking` | boolean | `false` | Refuse to host a room that does not require franking (`frank_aad`). |
| `require_room_policy` | boolean | `true` | Refuse to host a room without a `base_room_policy`. In a room without one, every participant holds every capability. Set it to `false` to host such open rooms. It applies only to rooms this provider hosts. |
| `peer_clock_tolerance_secs` | integer, seconds | `5` | How far a configured peer's clock (its HTTP `Date` header) may be from this server's before `mimid` logs a warning. No request is refused for clock skew. A warning about the same peer is repeated at most every 10 minutes. |
| `max_name_octets` | integer, octets | `1024` | The longest name accepted: role names, room names, room subjects and moods. |
| `max_description_octets` | integer, octets | `4096` | The longest description accepted: role descriptions, room descriptions and abuse report notes. |
| `max_uri_octets` | integer, octets | `2048` | The longest URI accepted: participant list users, room metadata URIs, a base policy's `parent_room`, and the URIs in identifierQuery, consent and keyMaterial requests. |
| `blob_lifetime_secs` | integer, seconds, at least 3600 | `2592000` (30 days) | How long an uploaded attachment is kept. Every upload is deleted this long after it was uploaded, whether or not anyone fetched it, because the server cannot read the messages that refer to it. The JMAP Session reports it as `assetLifetime`. A value under 3600 is refused. |
| `message_retention_secs` | integer, seconds, at least 3600, or `"unlimited"` | `604800` (7 days) | How long a message is kept after the hub accepted it. See [Message retention](#message-retention). A value under 3600 is refused. |
| `client_idle_unbind_secs` | integer, seconds, at least 86400, or `"unlimited"` | `7776000` (90 days) | How long a client's signature key may be idle before it is unbound from its account. See [Idle clients](#idle-clients). A value under 86400 is refused. |

The three `max_*_octets` keys are mimid's own policy; the drafts set no limit for these fields. A longer value is refused.

### `[peers]`

The peer providers this server talks to. Peers are found only here, not through DNS. Each key is a peer's domain and each value is the base URL used to reach it.

```toml
[peers]
"b.example" = "https://mimi.b.example"
"c.example" = "http://127.0.0.1:9080"
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| any domain | base URL | none (the table is optional and empty by default) | The peer's base URL. mimid fetches the peer's directory from `<url>/.well-known/mimi-protocol-directory`. |

Rules:

- This provider's own domain may not appear.
- Fanout (`/notify`) is accepted only from domains listed here. Other providers get `403`.
- Only listed peers are checked for clock skew.

### `[provider_auth]`

How peers prove which provider they are, and how this server proves its own identity. Without the table, every provider is held to `enforce` with no configured keys, DNS keys and DANE on.

mimid signs every request it sends to a peer with its own Ed25519 key (RFC 9421 HTTP message signatures). `mimid admin <config.toml> provider-key` prints its public half and the DNS record to publish for it.

The key comes from one of two places. Set `key_file` and mimid signs with the 32-byte seed in that file — 32 raw octets or 64 hex characters, whitespace trimmed — and never writes it to the database, so you hold, back up and rotate the provider's identity with ordinary file tools. Leave `key_file` unset and mimid makes a key on first start and keeps it in the database.

Either way `mimid admin <config.toml> provider-key --private` prints the seed as hex, so a provider's identity can be backed up or moved to another host. Treat its output as you would a TLS private key: anything holding it can sign requests as this provider. It cannot read any message — this key authenticates provider-to-provider requests and is not MLS key material.

To move a provider to a new host, keeping its identity and so its rooms: take the seed with `provider-key --private` on the old host, write it to a file mode 0600 on the new one, point `key_file` at it, and leave the published `<selector>._mimi.<domain>` record alone. Check `provider-key` reports the same `publicKey` on both before cutting over.

On each request to a protocol endpoint (`/v1/...`), mimid tries these mechanisms, and the first that succeeds authenticates the peer named in the `From` header:

1. a request signature with a key configured for that peer (`keys`);
2. a request signature with a key published in DNS at `<selector>._mimi.<domain>` (`dns_keys`);
3. the peer's TLS client certificate against TLSA records at `_mimi._client.<domain>` (`dane`);
4. the peer's TLS client certificate against configured CA files (`pkix_anchors`).

If none succeeds, the peer's mode decides: `enforce` refuses the request with `403`; `observe` logs the failure and lets the request through unauthenticated. JMAP clients are not affected; they authenticate with bearer tokens.

A client certificate reaches mimid only through `[tls]` or `[trusted_proxy]`. Without one of them, only request signatures can authenticate a peer.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `"enforce"` or `"observe"` | `"enforce"` | The mode for every provider without a `mode` of its own. `observe` lets unauthenticated requests through; it is meant for rollout and testing only. |
| `selector` | string | `"mimid1"` | The `keyid` of this server's own request signatures, and the selector of its DNS key record, `<selector>._mimi.<domain>`. |
| `key_file` | path | unset | A file holding this server's request-signing key: the 32-byte seed as 32 raw octets or 64 hex characters. When set, the key is never written to the database. When unset, mimid makes one on first start and keeps it there. |
| `dns_keys` | boolean | `true` | Look up peers' signing keys in DNS. Lookups validate DNSSEC. |
| `require_dnssec` | boolean | `false` | Refuse a DNS key whose record is not DNSSEC-secure. |
| `dns_servers` | list of IP addresses | `[]` (the system's resolvers) | The resolvers used for DNS keys and TLSA records. They must pass DNSSEC records through; some cloud resolvers, such as AWS's VPC resolver, do not. |
| `dane` | boolean | `true` | Check peers' client certificates against DNSSEC-secure TLSA records at `_mimi._client.<domain>`. Only the DANE-EE and DANE-TA usages are accepted. |
| `pkix_anchors` | list of paths | `[]` | PEM files of CA certificates trusted for client certificates from any peer, such as a federation's CA. Not a Web PKI root store. A certificate must name the peer's domain as a SAN dNSName. The files are read at startup; a file that cannot be read stops `mimid`. |

If `dns_keys` and `dane` are both `false`, mimid builds no DNS resolver. If they are on and no resolver can be built, mimid logs `provider_auth_dns_unavailable` and runs with both off.

At startup mimid logs `provider_auth_configured` at INFO with the mode, the selector, its public key and the counts of configured peers and anchors.

#### `[provider_auth.peers."<domain>"]`

Settings for one peer. The domain may not be this provider's own.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `"enforce"` or `"observe"` | the `[provider_auth]` `mode` | This peer's mode. |
| `keys` | table of selector = key | `{}` | Request-signing keys trusted for this peer, by selector (`keyid`). Each key is a 32-byte Ed25519 public key in standard base64, as `mimid admin ... provider-key` prints it in `publicKey`. A malformed key is a configuration error. |
| `pkix_anchors` | list of paths | `[]` | PEM CA files trusted for this peer's client certificates only. |

Either form works:

```toml
[provider_auth.peers."b.example"]
mode = "enforce"
keys = { "mimid1" = "JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=" }

# or, for several peers at once:
[provider_auth.peers]
"c.example" = { mode = "observe" }
```

Limits of provider authentication:

- A signature without a `nonce` can be replayed for up to 5 minutes. mimid's own signatures carry a nonce, and a signature with one is refused the second time. Seen nonces are kept in memory, so a restart forgets them.
- A signature is accepted up to 60 seconds in the future and 5 minutes in the past.
- A peer in `observe` mode is let through unauthenticated.
- With BasicCredential, a provider can claim any identity for its own users. Provider authentication does not change that. mimid does not protect against a malicious provider.

### `[tls]`

With this table, `mimid` serves HTTPS on `listen` itself and asks each client for a certificate, without requiring one. The certificate, if any, goes to provider authentication (DANE and PKIX). Without the table, `listen` speaks plain HTTP, and TLS is expected to end in a proxy in front.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cert` | path | required in the table | PEM certificate chain, leaf first. |
| `key` | path | required in the table | PEM private key. |

The files are read at startup; a file that cannot be read, or a key that does not fit the certificate, stops `mimid`. The local control listener stays plain HTTP on loopback either way.

### `[trusted_proxy]`

A proxy in front of `mimid` that ends TLS and forwards the peer's client certificate in a header. mimid takes the header only from the listed addresses and removes it from every other request, so a peer cannot claim a certificate it did not present.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `addresses` | list of IP addresses | required in the table | The proxy's addresses, as `mimid` sees the TCP peer. |
| `header` | string | `"x-client-cert"` | The header that carries the leaf certificate as base64 DER. An invalid header name stops `mimid` at startup. |

Only the leaf certificate arrives through a proxy, so intermediate CA certificates must be in the trust configuration (`pkix_anchors` or the TLSA records). For Caddy, the forwarding is `header_up X-Client-Cert {http.request.tls.client.certificate_der_base64}` with `client_auth { mode request }`.

### `[peer_tls]` and `[peer_tls.identity]`

TLS toward peers, when `mimid` connects to their `https` base URLs.

`[peer_tls]`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `roots` | list of paths | `[]` | PEM files of CA certificates trusted for peers' server certificates, in addition to the system's. |

`[peer_tls.identity]` (optional): this provider's client certificate. **Naming it here presents it to nobody.**

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cert` | path | required in the table | PEM certificate chain, leaf first. Its SAN dNSName should be this provider's domain. |
| `key` | path | required in the table | PEM private key. |

`[peer_tls.peers."<domain>"]` (optional) says which peers it goes to. The domain must also be in `[peers]`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `client_certificate` | bool | `false` | Present `[peer_tls.identity]` to this peer. |
| `identity` | table | none | A `cert`/`key` pair for this peer alone, instead of `[peer_tls.identity]`, for a peer that trusts a different CA. Presented whether or not `client_certificate` is set. |

**Turn `client_certificate` on only after the peer has confirmed it trusts your issuer.** Offering a client certificate a peer does not trust is strictly worse than offering none, and the failure looks like the peer being down. A peer that asks for a client certificate without requiring one — which is a common and correct configuration — rejects an untrusted one at the TLS layer, so the handshake dies before any HTTP request is sent and the RFC 9421 signature that would have authenticated you is never seen. This happened on a live host on 2026-11-22: enabling `[peer_tls.identity]` turned a working peer into `tlsv1 alert unknown ca` on every request, and removing it restored `200`. That is why the setting is per peer (bead mimid-75nk.14).

If `[peer_tls.identity]` is set and no peer asks for it, `mimid` logs `peer_tls_identity_unused` at WARN at startup: the certificate is configured and doing nothing. The startup event `provider_auth_configured` carries `client_certificate_peers`, the number of peers it is presented to.

protocol-07 calls for mutually authenticated TLS between providers. mimid has both halves (`[tls]` or `[trusted_proxy]` inbound, `[peer_tls.identity]` outbound), but they have not been deployed or tested with another implementation, and mimid does not claim conformance to that part of protocol-07.

### `[wire_profiles]`

The encoding a peer speaks for the update requests and responses that mimi-protocol issue #190 extends. Each key is a peer's domain, which must also be in `[peers]`; each value is a profile name.

| Value | Meaning |
|---|---|
| `"draft07"` | protocol-07 as published. The default for every peer not listed. |
| `"extensions190"` | protocol-07 with the #190 extension points (mimi-protocol draft PR #220). |

```toml
[wire_profiles]
"b.example" = "extensions190"
```

### `[telemetry]`

OpenTelemetry export over OTLP/HTTP with protobuf bodies. Off when the table is absent.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `endpoint` | string | required in the table | The collector's OTLP/HTTP base URL, such as `http://127.0.0.1:4318`. `/v1/traces`, `/v1/logs` and `/v1/metrics` are appended. It is not checked when the file is parsed; an endpoint the exporter cannot use stops `mimid` at startup ("starting telemetry"). |
| `service_name` | string | `"mimid"` | The `service.name` resource attribute. `service.instance.id` is always this provider's domain. |
| `traces` | boolean | `true` | Export spans. |
| `span_level` | string | the log's own filter | The filter the exported spans follow, in `RUST_LOG` syntax (`"debug"`, `"info,mimid_server=debug"`). Set it to send the collector spans the terminal log does not print. A value that is not a filter stops `mimid` at startup ("[telemetry] span_level is not a filter"). It does not affect the log records, which always follow `RUST_LOG`. |
| `logs` | boolean | `true` | Export the log events that `RUST_LOG` keeps, as log records. |
| `metrics` | boolean | `true` | Export metrics. |
| `metrics_interval_secs` | integer, seconds | `60` | How often metrics are exported. |

No trace context is sent to or accepted from peers. If telemetry cannot be flushed at shutdown, `mimid` logs `telemetry_flush_failed`.

**Which spans you get depends on the span filter:** `span_level` when it is set, and otherwise `RUST_LOG`. With neither set the filter is `info`, and the spans at INFO are:

| Span | Opened for | Fields |
|---|---|---|
| `provider_auth` | every `/v1/` request carrying a `From` header | `peer`, `endpoint`, `outcome` (`authenticated`, `refused` or `observed`), then `mechanism` or `reason` |
| `protocol_request` | every `/v1/` request that reaches its handler | `endpoint`, `peer`, and the path value under its own key (`room_id`, `target_user`, …) |

`http_request`, which carries `method`, `route`, `status` and `elapsed_ms`, is at DEBUG, to keep the terminal log quiet. To send it to the collector without making the log noisy, set `span_level` rather than `RUST_LOG`:

```toml
[telemetry]
endpoint   = "http://127.0.0.1:4318"
span_level = "info,mimid_server=debug"
```

A request refused by provider authentication never reaches a handler, so its only span is `provider_auth`; that span is why a refusal is visible in a trace at all.

### `[did_webvh]`

The code points of draft-atwood-mls-didwebvh-credential, which IANA has not assigned. The hub uses them to apply the draft's rules to KeyPackage uploads and keyMaterial answers. Every member of a room must use the same values, so the agents' `[did_webvh]` settings must match the server's.

The table is optional. If it is present, both keys are required.

| Key | Type | Default (without the table) | Meaning |
|---|---|---|---|
| `credential_type` | integer, 16 bits | `0x0008` | The `did_webvh` credential type: the draft's suggested value. 0x0000 to 0x0002 and the GREASE values (0x0A0A, 0x1A1A, ... 0xEAEA) are refused. |
| `heads_component` | integer, 16 bits | `0xf013` | The `app_data_dictionary` component that carries the `did_webvh_heads` record. 0xF013 is in the private-use range and is mimid's own choice. 0x0000 to 0x0005 and the GREASE values below 0x8000 are refused. |

The key `heads_extension_type` of earlier versions is gone and is refused as unknown.

### Idle clients

Every KeyPackage upload or external join with a new signature key binds that key to the account as a client, and each bound key counts toward `maxClients` and gets KeyPackages handed out for it. Clients that no longer exist, such as reinstalled apps, would otherwise pile up. Once an hour, `mimid` unbinds every key that has been idle for `client_idle_unbind_secs`, as if the user had destroyed its Client record: its KeyPackages are deleted and JMAP `Client/changes` lists it as destroyed. A key is idle when, for the whole period:

- it had no KeyPackage on the server: none stored that had not expired, and none handed out to an invitation; and
- the server saw it do nothing. Activity is what the server can tie to one key: a KeyPackage upload with the key, a `Room/update` the hub accepted whose Commit carries the key in its UpdatePath leaf, and a `GroupInfo/fetch` signed with the key that the hub answered.

Sending messages (`Room/send`) is not activity, because the server cannot see which client sent an encrypted message. A client that only sends messages and keeps no KeyPackage on the server is unbound after the period; its next KeyPackage upload or external join binds it again. Unbinding a key does not remove its client from any room.

With `client_idle_unbind_secs = "unlimited"` no key is unbound for being idle. Each unbinding is logged as `client_unbound_idle`.

### Message retention

`mimid` keeps each message, its users' JMAP Messages and the events of the rooms it hosts as hub, for `message_retention_secs` after the hub accepted it, and then deletes it. The default is 7 days (`604800`). The shortest accepted value is one hour (`3600`); `"unlimited"` keeps everything.

```toml
message_retention_secs = 604800       # the default, 7 days
# message_retention_secs = "unlimited"
```

The JMAP Session and the live stream's `ProviderHello` report the value as `messageRetention`, and leave it out when it is unlimited. A sweep runs every 10 minutes and deletes expired rows 500 at a time, so a large backlog never holds the database for long; each sweep that deletes anything logs `message_sweep`.

What this means for users and operators:

- The server cannot read messages, so it cannot keep some and drop others: every message, Commit and Welcome is deleted on the same schedule.
- A device that is offline longer than the retention misses messages, and the Commits among them, for good. `mimid-agent` then rejoins its rooms by external Commit, where room policy lets it, and the messages sent while it was away are lost to that device.
- A Welcome deleted before its user's device fetched it is lost; the inviter has to invite again.
- A request the hub accepted longer ago than the retention is no longer recognised as a repeat by the hub; the server's own record of accepted requests, kept 30 days, still answers a user's repeat.
- Rows an operator deletes by hand from `follower_event` are handled the same way as expired ones.

## Example: one provider

A provider behind a TLS proxy, with no peers yet, and the local control listener on for `mimid admin`.

```toml
domain = "a.example"
listen = "127.0.0.1:8080"
base_url = "https://mimi.a.example"
database = "/var/lib/mimid/mimid.sqlite"
local_listen = "127.0.0.1:8099"
# Replace with your own random value, for example from `openssl rand -hex 32`.
local_token = "replace-with-at-least-32-random-characters"
```

Every other key takes its default: `[provider_auth]` in `enforce` mode with DNS keys and DANE on, plain HTTP on `listen`, attachments kept 30 days, rooms required to have a room policy.

## Example: two federated providers on loopback

Two providers, `a.example` and `b.example`, on one host, each listing the other under `[peers]`. Plain HTTP, no certificates. This is a test setup.

`a.toml`:

```toml
domain = "a.example"
listen = "127.0.0.1:18401"
base_url = "http://127.0.0.1:18401"
database = "/var/tmp/mimid-a/mimid.sqlite"
local_listen = "127.0.0.1:18402"

[peers]
"b.example" = "http://127.0.0.1:18501"

[provider_auth]
mode = "observe"
dns_keys = false
dane = false
```

`b.toml`:

```toml
domain = "b.example"
listen = "127.0.0.1:18501"
base_url = "http://127.0.0.1:18501"
database = "/var/tmp/mimid-b/mimid.sqlite"
local_listen = "127.0.0.1:18502"

[peers]
"a.example" = "http://127.0.0.1:18401"

[provider_auth]
mode = "observe"
dns_keys = false
dane = false
```

The database directories must exist; the database files are created. `dns_keys = false` and `dane = false` stop mimid from looking up `a.example` and `b.example` in DNS, where they do not exist.

Start both, then make a user on each:

```sh
mkdir -p /var/tmp/mimid-a /var/tmp/mimid-b
mimid a.toml &
mimid b.toml &
mimid admin a.toml add-user mimi://a.example/u/alice
mimid admin a.toml token mimi://a.example/u/alice     # prints {"token":"..."}
mimid admin b.toml add-user mimi://b.example/u/bob
mimid admin b.toml token mimi://b.example/u/bob
```

### Moving the pair from `observe` to `enforce`

`observe` lets every peer request through. To make each provider check the other's request signatures:

1. Start both once, so each makes its signing key.
2. Run `mimid admin b.toml provider-key` and take `selector` and `publicKey` from its output. Do the same for `a.toml`.
3. In `a.toml`, replace the `[provider_auth]` table with:

   ```toml
   [provider_auth]
   dns_keys = false
   dane = false

   [provider_auth.peers."b.example"]
   keys = { "mimid1" = "<b.example's publicKey>" }
   ```

   and in `b.toml` the same with `"a.example"` and a.example's key. `mode` defaults to `enforce`.
4. Restart both.

## The admin commands

```sh
mimid admin <config.toml> <command> [argument ...]
```

`mimid admin` is a client of a running server's local control listener. It reads the same configuration file as the server and needs:

- `local_listen`: the listener's address. Without it, `mimid admin` fails with "the configuration has no local_listen".
- `local_token`, if the server has one. `mimid admin` sends it as a bearer token.

The whole file must parse, so `mimid admin` needs read access to it, including the `local_token` line.

`mimid admin` prints the server's JSON answer as it is, on one line, and exits 0. An error answer is printed as `Error: <status>: <problem body>` and the exit status is 1. The problem body is RFC 9457 JSON with `type` and `status` only; the reason is in the server's log.

| Command | Argument(s) | Prints | Errors |
|---|---|---|---|
| `hub-sender` | none | `{"signatureKey": <base64url>, "identity": "mimi://<domain>"}`: the hub's external-sender identity, which a client needs to build a room this hub hosts. | |
| `rooms` | none | `{"rooms": [<room summary>, ...]}`, every room hosted here, ordered by room ID. | |
| `room` | `<roomId>` | One `<room summary>`. | `404` `no-such-room` if the room is not hosted here. |
| `remove` | `<roomId> <userUri>` | `{"result": "proposed"}`. The hub, as the room's external sender, proposes removing each of the user's clients and removing the user from the participant list. It takes effect when a member next commits; until then the user is still in the room. | `404` `no-such-room` or `not-a-participant`; `409` `proposal-refused`, also when the room's external senders do not name this hub. |
| `ban` | `<roomId> <userUri>` | `{"result": "proposed"}`. As `remove`, except that the user stays in the participant list with role 1, the banned role of room-policy-04. | As `remove`. |
| `users` | none | `{"users": [{"user", "accountId", "createdAt"}, ...]}`, every JMAP account, ordered by user URI; `createdAt` in milliseconds since the Unix epoch. | |
| `add-user` | `<userUri>` | `{"user", "accountId"}`. Creates the JMAP account of a local user, `mimi://<domain>/u/<id>`. | `400` if the URI is not a user of this provider; `409` if the user has an account. |
| `token` | `<userUri> [name]` | `{"token": "<token>", "id", "name"}`, a JSON object, not a bare token. Issues a new JMAP bearer token for the user, named `name` if given (1 to 64 characters, no control characters; quote it in the shell if it has spaces). The token is shown once; the server does not store it in clear and does not log it. `id` is what `tokens` lists and `revoke-token` takes. Issue one token per device or program, so that one can be revoked alone. | `400` `bad-token-name`; `404` if the user has no account. |
| `tokens` | `<userUri>` | `{"tokens": [{"id", "name", "createdAt", "lastUsedAt", "revokedAt"}, ...]}`, every token of the user, valid and revoked, oldest first. Times are milliseconds since the Unix epoch; `lastUsedAt` is kept to the minute and is `null` for a token never used; `revokedAt` is `null` while the token is valid. The tokens themselves are never shown. | `404` if the user has no account. |
| `revoke-token` | `<id>` | `{"id", "result"}`, `result` `"revoked"`, or `"already-revoked"` for a token revoked before. The revocation holds at once: the next request with the token is refused, and its open EventSource and live-stream connections close. | `404` `no-such-token` for an unknown id. |
| `consent` | none | `{"consent": [{"requester", "target", "room", "decision", "from", "receivedAt"}, ...]}`, the consent entries other providers sent: held requests first (`decision` is `null`), then updates (`"grant"` or `"revoke"`). `room` is `null` for any room. | |
| `provider-key` | none | `{"selector", "publicKey", "dnsName", "dnsTxt"}`: this server's request-signing selector, its Ed25519 public key in standard base64, the DNS name to publish it at (`<selector>._mimi.<domain>`), and the TXT record (`v=MIMI1; k=ed25519; p=<key>`). The record format is provisional. | |
| `provider-key --private` | none | `{"selector", "privateKeyHex", "publicKey"}`: the 32-byte signing seed as hex, for backing up or moving this provider's identity. Logs `provider_key_exported` with the selector, never the key. Anything holding the seed can sign as this provider; it reads no message. | |

A room summary is `{"roomId", "groupId", "epoch", "members", "participants", "roles"}`. `groupId` is base64url without padding. `members` is a list of `{"leaf", "identity"}`. `participants` is a list of `{"user", "role"}` and `roles` a list of `{"index", "name"}`; each is `null` when the room has no such component or it does not decode. Identities, users and role names are JSON strings when they are UTF-8, else `{"base64url": ...}`.

`remove` and `ban` are an operator power outside the drafts: room-policy-04 gives only the room's own roles the right to remove or ban.

Room IDs and user URIs are percent-encoded by `mimid admin`; pass them as they are, for example `mimid admin a.toml room mimi://a.example/r/one`.

To put a user's token in a file for `mimid-agent`, which wants the bare token:

```sh
mimid admin a.toml token mimi://a.example/u/alice | jq -r .token > alice.token
chmod 600 alice.token
```

The local control listener also has `POST /local/v1/rooms`, a room creation route for testing, which `mimid admin` does not call.

## Files

- **The database** (`database`). `mimid` creates it with mode 0600 and refuses to open an existing file that its group or others can read, write or execute. SQLite's `-wal` and `-shm` files next to it get the same mode. It holds, unencrypted:
  - the hub's signing and franking keys;
  - this server's request-signing key;
  - JMAP accounts (bearer tokens are not stored in clear);
  - uploaded attachments (at most 16 MiB each; at most 512 MiB and 4096 attachments per account), deleted `blob_lifetime_secs` after upload;
  - the rooms hosted here, the delivery queue to peers, received consent entries, and a record of accepted requests, kept 30 days, so a client that lost an answer can repeat a request and get the same answer.

  Back it up as a secret, and keep its directory private.
- **Certificate and key files** named in `[tls]`, `[peer_tls]`, `[peer_tls.identity]` and `pkix_anchors`. They are read once, at startup.
- **The configuration file**, which may hold `local_token`. Make it readable only by the account that runs `mimid` and `mimid admin`.

An attachment is served at `/assets/<blobId>` to anyone who knows its ID. The ID is 128 random bits; it is the only protection. `mimid-agent` encrypts attachments before it uploads them; the server cannot check what another client uploads.

## What the listener serves

On `listen`:

- `/.well-known/mimi-protocol-directory`: the protocol-07 directory document;
- `/v1/...`: the MIMI protocol endpoints, where provider authentication applies;
- `/.well-known/jmap`, `/jmap/api`, `/jmap/eventsource` and the upload and download paths: the JMAP Chat endpoint for this provider's users, with bearer tokens from `mimid admin token`;
- `/assets/<blobId>`: attachments;
- `/mimid/live`: the live stream, only with `live_stream = true`.

On `local_listen`, loopback only: `/local/v1/...`, the routes `mimid admin` uses.

One provider sends another at most 4 MiB in a request or response body. See "Limits" in the [README](../README.md) for what that means for room size.
