# A binary live stream between the agent and its provider

Design note, no code. Written 2026-11-20 against main at eedc290 for
Mark's review. Code waits for that review.

The agent (mimid-agent-core) talks to its provider (mimid-server) only
through JMAP today: draft-atwood-jmap-chat-mimi-00 over HTTPS, with a
bearer token. MIMI protocol-07 covers provider to provider. Client to
provider is outside MIMI, so a live stream here is mimid's own protocol.

The session and framing layer comes from Mark's Agora spec,
`agora-spec/spec/11-transport.md` §11.2, §11.4 and §11.6, with the
split of §11.8.8 and the CBOR conventions of `spec/13-encoding.md`
§13.1 and §13.2. Agora is all rights reserved by Mark; this note reuses
it with his permission and cites it section by section.

Every name, value and path below that no spec defines is INVENTED, NOT
FROM SPEC, and will need a decision bead before code.

## 1. Today, and why a stream

How the agent hears of new messages now:

- `Agent::receive` (crates/mimid-agent-core/src/agent.rs:2527) calls
  `Jmap::messages_since` (crates/mimid-agent-core/src/client.rs:601):
  `Message/changes` from the saved state, then `Message/get` of the new
  ids with `properties: ["body"]`. Each body is one FanoutMessage in
  base64url.
- The daemon calls it every `sync_interval_ms`, 2000 by default
  (crates/mimid-agent/src/config.rs:100), and at once after a local
  write. It does not listen to the server's EventSource
  (crates/mimid-agent/src/lib.rs:114-116), although mimid-server serves
  one (crates/mimid-server/src/jmap/eventsource.rs).
- The agent keeps `message_state` (the JMAP Message state string) and
  `handled` (Message ids after that state already processed) in its
  state (crates/mimid-agent-core/src/state.rs:155-161).
- The server's Message state is `s.m`: s is the highest follower_event
  `seq` the user may see, m the user's highest follower_member id
  (crates/mimid-server/src/jmap/projection.rs:26-31). seq is one counter
  for the whole provider (migrations/0003_follower.sql:21).
- Sends are `Room/send` and `Room/update`; each is one HTTPS round trip
  that waits for the hub's answer (client.rs:663, client.rs:761).

What a stream would give:

- **Latency.** A message reaches the agent when the provider stores it,
  not at the next poll. Today the wait is up to one interval plus two
  round trips.
- **One connection.** No poll requests when nothing happens.
- **Binary bytes.** FanoutMessages travel as CBOR byte strings, not
  base64url inside JSON (a third larger, and decoded on every poll).

What stays on JMAP, as in Agora §11.8.8: history and catch-up
(`Message/changes`, `Message/get`), management (Chats, Consent records,
`privateMetadata`), and blobs (upload, `assetDownloadUrl`). A client
that never opens the stream loses nothing but latency.

## 2. Alternatives

- **JMAP + EventSource.** This exists today on the server. The agent
  could follow `eventSourceUrl` and run `Message/changes` on each
  StateChange. That removes the poll delay with almost no new protocol.
  It keeps two round trips per wake-up and base64url bodies, and it
  stays text. It is the honest baseline: anything new has to beat it.
- **COSE.** A signing and encryption format for CBOR (CBOR's JOSE), not
  a protocol. It adds nothing here: MLS gives end-to-end protection and
  TLS protects the connection.
- **Protobufs.** An encoding swap. It still needs a hello, request ids
  and an Ack/Error layer, and it brings codegen and a second schema
  language next to TLS-presentation and CDDL.
- **gRPC.** Bidirectional streams, request matching and status codes are
  built in. But it needs HTTP/2, codegen, and grpc-web for any browser
  client, and it does not fit MIMI's CBOR/CDDL world (mimi-content is
  CBOR).
- **CBOR over WebSocket (this note).** Small: one framing rule, a few
  CDDL maps, and an existing design (Agora) to copy. CBOR carries the
  TLS-encoded MLS bytes as opaque byte strings. WebSocket runs over the
  same TLS listener and HTTP stack as JMAP, so the bearer-token check can
  stay where it is.

Among the binary options CBOR over WebSocket wins. Against JMAP +
EventSource it wins only on round trips and base64, which matters only
if those costs show up. See §8 question 1.

## 3. Taken from Agora as is

- **Messages.** Each message is one CBOR data item (RFC 8949), a map
  with text keys, matching the CDDL (RFC 8610) in §5. No JSON on the
  stream (Agora §11.4).
- **`v` and `t`.** Every message has `v`, the negotiated version, and
  `t`, its name. A receiver discards a message with an unknown `v` and
  MAY close the connection. It ignores map keys it does not know. The
  provider answers an unknown `t` with `Error` code `bad-message`; the
  agent ignores one (Agora §11.4 "Common members", §13.2).
- **Framing.** One message per binary WebSocket message, no prefix. A
  text WebSocket message closes the connection (Agora §11.2, §11.4
  "Framing").
- **Hello.** `ClientHello` lists the versions the client supports; the
  provider answers with the highest common one, or `Error`
  `unsupported-version` and closes. Neither side sends anything else
  before the hello exchange ends. The hello messages keep their v1 form
  in every later version, so any two versions can negotiate (Agora
  §11.6 "Client Hello").
- **Request ids.** Each client request has `id`, a uint unique among the
  client's outstanding requests. The provider answers each with exactly
  one `Ack` or one `Error` with that `id` (Agora §11.4 "Request IDs").
- **Errors.** One registry of codes. `detail` is diagnostic text, not for
  display. An `Error` without `id` concerns the connection, and the
  provider MAY close after it (Agora §11.4, "Error").
- **Exact bytes.** Payloads travel as the exact bytes their sender
  encoded. MLS messages, UpdateRequests and FanoutMessages are
  TLS-encoded (RFC 9420, protocol-07) and travel as opaque `bstr`. No
  side re-encodes them (Agora §11.4 first paragraph, §13.1).
- **Size cap.** A named limit on a message, stated in the hello. Larger
  content goes another way (Agora §11.4 "Size"; here, JMAP, see §5).
- **Version surface.** The stream version is separate from the version
  in the endpoint path (Agora §11.6, §13.2 registry).

Datagrams for loss-tolerant traffic (Agora §11.4 "Framing") need
WebTransport, so they are in §6.

Two places where this note differs from Agora's conventions:

- Times are uint milliseconds since the UNIX epoch, as protocol-07 has
  them (`accepted_timestamp`, FanoutMessage `timestamp`), not RFC 3339
  text (Agora §13.1 "Common value encodings").
- Decoding follows AGENTS.md: reject duplicate keys, indefinite-length
  items, non-shortest integers and trailing bytes in a frame. Key order
  stays free, as in Agora §13.1.

## 4. Left out, and why

Agora's relay is blind: it never learns who a client is
(Agora §11.6, first paragraph). A MIMI provider is the opposite. It
holds the user's account, stores the user's FanoutMessages and speaks
for the user to hubs. So these parts of Agora do not apply:

- no-client-auth rule and the per-envelope `admissionSig`;
- channel tokens, `Subscribe` by token, `unknown-token`,
  `token-withdrawn`, `token-rotated`;
- proof-of-work admission (`AdmissionChallenge`, `AdmissionProof`); the
  bearer token is the admission;
- `PinInstruction` (retention is the provider's own policy);
- `PushRegister` and the push proxy (§11.7); mimid has no push
  (decision mimid-1wgh.12.30);
- relay federation and gossip; providers federate with protocol-07.

## 5. Version 1

WebSocket only, at `wss://<provider>/v1/mimid/ws` (INVENTED, NOT FROM
SPEC). The path is advertised in the JMAP Session under a vendor
capability, `https://reviewcommit.com/mimid/live` (INVENTED, NOT FROM
SPEC), with `{"wsUrl": ...}`, so an agent finds it from the Session it
already reads (client.rs:140).

v1 replaces polling and nothing else. Sends, room creation, KeyPackages
and consent stay on JMAP in v1.

### Authentication

The `ClientHello` carries the JMAP bearer token. The provider checks it
with the same code as the JMAP `Account` extractor
(crates/mimid-server/src/jmap/auth.rs), so there is still one check at
the JMAP boundary (AGENTS.md "Security invariants"). A bad token gets
`Error` `unauthorized` without `id`, and the connection closes. Every
refusal looks the same, as on JMAP. A token revoked while connected
gets the same error and close.

Other options, not taken for v1:

- `Authorization` header on the WebSocket upgrade. It reuses the
  extractor without change, but browsers' WebSocket API cannot set
  headers, and Mark asked for the hello.
- A token bound to the TLS connection: the client sends
  HMAC(token, TLS exporter value, RFC 8446 §7.5) instead of the token.
  A token copied off one connection would not work on another. It does
  not help while the same token travels as a plain bearer on JMAP, so
  it waits until JMAP does the same.

### Positions and resume

A position is the JMAP Message state string. The agent keeps no new
kind of state.

1. At start the agent catches up on JMAP as today and gets state S.
2. It opens the stream and sends `Subscribe` with `since` S.
3. The provider sends a `Deliver` for each Message that
   `Message/changes` from S would return, in the same order, then each
   new one as it is stored. After any run of `Deliver`s, it sends
   `Position` with the Message state that covers every `Deliver` before
   it.
4. The agent handles each `Deliver` as it handles a Message now. It adds
   the id to `handled`, and on `Position` sets `message_state` and clears
   `handled`. This is the same bookkeeping as `Agent::receive`
   (agent.rs:2527-2557), so a crash between a `Deliver` and a `Position`
   resumes without handling anything twice.
5. On reconnect it sends `Subscribe` with its `message_state`. Nothing
   stored between the last `Position` and the reconnect is lost.

`Position` exists because the state is `s.m`, not one counter. A new
membership (m) makes older Messages of that room visible, so there is no
single state after each `Deliver`. The provider emits `Position` only
where it can name a state that Message/changes would accept.

If the provider cannot resume from `since` (unparsable, or the change
bus lagged, crates/mimid-server/src/jmap/bus.rs), it answers `Error`
`cannot-resume`. The agent then catches up on JMAP and subscribes again.
`Subscribe` without `since` starts at the current state, and its `Ack`
names that state.

The agent's own messages still come back, as on JMAP today; it skips
them by digest (`Jmap::is_own`, client.rs:580).

### Size

`maxMessageBytes` in `ProviderHello`, 1 MiB (INVENTED, NOT FROM SPEC;
mimid's HTTP body cap is 4 MiB, crates/mimid-server/src/http.rs:90). A
FanoutMessage larger than that goes as a `Deliver` without `fanout`; the
agent fetches it with `Message/get` by `messageId`. A large Welcome or
Commit with a ratchet tree is the likely case.

### CDDL

```cddl
message      = client-msg / provider-msg
client-msg   = ClientHello / Subscribe
provider-msg = ProviderHello / Deliver / Position / Ack / Error

req-id     = uint
room-id    = tstr          ; MIMI room URI
jmap-id    = tstr          ; JMAP Message id
jmap-state = tstr          ; JMAP Message state, opaque to the agent

ClientHello = {
  "v": 1, "t": "ClientHello",
  "versions": [+ uint],
  "token": tstr            ; the JMAP bearer token
}

ProviderHello = {
  "v": 1, "t": "ProviderHello",
  "version": uint,         ; negotiated version
  "accountId": tstr,       ; the JMAP account
  "userUri": tstr,         ; the mimi capability's userUri
  "maxMessageBytes": uint
}

Subscribe = {
  "v": uint, "t": "Subscribe", "id": req-id,
  ? "since": jmap-state    ; absent: from now on
}

Deliver = {
  "v": uint, "t": "Deliver",
  "messageId": jmap-id,
  "room": room-id,
  ? "fanout": bstr         ; one FanoutMessage, exact bytes as stored;
                           ; absent when over maxMessageBytes
}

Position = {
  "v": uint, "t": "Position",
  "state": jmap-state
}

Ack = {
  "v": uint, "t": "Ack", "id": req-id,
  ? "state": jmap-state    ; for Subscribe without "since"
}

Error = {
  "v": uint, "t": "Error",
  ? "id": req-id,          ; absent for a connection-level error
  "code": error-code,
  ? "detail": tstr         ; diagnostic text, not for display
}

error-code = "bad-message" / "unsupported-version" / "unauthorized"
           / "cannot-resume" / "too-large" / "rate-limited"
           / "internal"
```

One `Subscribe` per connection; a second gets `bad-message`.
`Deliver` carries a whole FanoutMessage, so Welcomes arrive the same way
as on JMAP (draft-atwood-jmap-chat-mimi-00 §application/mimi-fanout,
stored only for the account that owns the named KeyPackageRef). Unlike
Agora, Welcomes do travel on this stream (compare Agora §11, opening).

### Mapping

| JMAP call or flow the agent uses today | v1 stream | Later (§6) |
|---|---|---|
| Poll: `Message/changes` + `Message/get` (client.rs:601) | `Subscribe` + `Deliver` + `Position` | |
| First sync, catch-up after `cannot-resume` | stays on JMAP | |
| Welcome arrival (FanoutMessage in a Message) | `Deliver` | |
| `Room/send` (client.rs:761) | stays on JMAP | `Send` |
| `Room/update`, external Commit too (client.rs:663) | stays on JMAP | `Update` |
| `Room/create` (client.rs:376) | stays on JMAP | `CreateRoom` |
| `KeyPackage/set` (client.rs:361) | stays on JMAP | `PublishKeyPackage` |
| KeyPackage handed out (KeyPackage state change) | not watched today | `KeyPackageClaimed` |
| `KeyMaterial/fetch` (client.rs:470) | stays on JMAP | `FetchKeyMaterial` |
| `Consent/get` (client.rs:338) | stays on JMAP | `ConsentChanged` notice |
| `Consent/set` (client.rs:356) | stays on JMAP | stays on JMAP |
| `GroupInfo/fetch` (client.rs:452) | stays on JMAP | stays on JMAP |
| `Room/reportAbuse` (client.rs:730) | stays on JMAP | stays on JMAP |
| `Room/unbind` | stays on JMAP | stays on JMAP |
| `Chat/get` own chats, `Chat/set` privateMetadata (client.rs:403, 434) | stays on JMAP | stays on JMAP |
| Blob upload, `assetDownloadUrl` (client.rs:268, 299) | stays on JMAP | stays on JMAP |
| Session read (client.rs:140) | stays on JMAP | stays on JMAP |

## 6. Later, if needed

Each item waits for a concrete need, and each gets a version bump or new
`t` values negotiated in the hello.

- **Writes on the stream.** Sketch, same conventions as §5:

  ```cddl
  Send   = { "v": uint, "t": "Send", "id": req-id,
             "room": room-id, "message": bstr }   ; MLSMessage, application
  Update = { "v": uint, "t": "Update", "id": req-id,
             "room": room-id, "request": bstr }   ; UpdateRequest
  CreateRoom = { "v": uint, "t": "CreateRoom", "id": req-id,
                 "room": room-id, "groupInfo": bstr, "ratchetTree": bstr }
  PublishKeyPackage = { "v": uint, "t": "PublishKeyPackage", "id": req-id,
                        "keyPackage": bstr }
  FetchKeyMaterial = { "v": uint, "t": "FetchKeyMaterial", "id": req-id,
                       "room": room-id, "request": bstr }  ; KeyMaterialRequest

  ; the hub's answer, carried in the Ack of Send or Update
  hub-answer = {
    "code": "accepted" / "notAllowed" / "epochTooOld"         ; Send
          / "success" / "wrongEpoch" / "invalidProposal",     ; Update
    ? "acceptedAt": uint,          ; accepted_timestamp, ms
    ? "frank": bstr,               ; protocol-07 §5.4 Frank, TLS-encoded
    ? "currentEpoch": uint,
    ? "invalidProposals": [* bstr],
    ? "errorDescription": tstr
  }
  ```

  The hub's refusal is a result, in the `Ack`; `Error` is for the stream
  and the provider (`hub-unreachable`, `not-bound`, `over-quota`). The
  `frank` is new compared with JMAP `Room/send`, which drops it from its
  answer. Writes gain one round trip less and no base64; they are rare
  next to reads, which is why they wait.
- **Notices.** `KeyPackageClaimed` (so the agent replenishes) and
  `ConsentChanged` (a consent request arrived), each with no content
  beyond what changed. JMAP EventSource already says both.
- **WebTransport.** One bidirectional stream carrying a CBOR sequence
  (RFC 8742), as Agora §11.1 and §11.4. Needs HTTP/3 in mimid-server.
- **Datagrams.** For typing and presence, as Agora §11.4 and §5.3: no
  `Ack` for a datagram, never a `Deliver` of a FanoutMessage. mimid has
  no typing or presence today, and MIMI defines none.
- **Exporter-bound token** (§5 "Authentication").
- **Several subscriptions or per-room filters.**

## 7. Implementation plan

1. Mark answers §8. Each answer becomes a decision bead under
   mimid-1wgh; every INVENTED value gets one.
2. A small pure crate for the stream's types and CBOR codec, sync, no
   I/O, with the limits as named constants. Fixtures from outside the
   code: CBOR encoded by hand from the CDDL with byte comments, cross
   checked with Python `cbor2`, with a PROVENANCE file. Decode, compare,
   re-encode, require identical bytes. Hostile-input tests: oversized
   frames, duplicate keys, indefinite lengths, unknown `v` and `t`.
3. mimid-server: the WebSocket route next to the JMAP routes; hello and
   token check through the code the `Account` extractor uses; a test
   that a wrong token is refused.
4. mimid-server: `Subscribe` replay from the projection's
   `Message/changes` query, then follow the change bus; `Position` at
   each batch; `cannot-resume` on a lagged bus or bad state. Tests: no
   gap and no duplicate across reconnects, membership change mid-stream,
   oversized FanoutMessage.
5. mimid-agent-core: a receive path fed by `Deliver`, sharing
   `handle_message` and the `handled` / `message_state` bookkeeping with
   the poll path. Fallback to polling while the stream is down.
6. mimid-agent: the daemon syncs on `Deliver` and keeps the interval as a
   slow fallback.
7. An end-to-end offline test with two agents on one provider: a message
   sent by one reaches the other with no poll.

## 8. Open questions for Mark

1. **Build it now, or wait for a concrete need?** Recommendation: wait.
   First make the agent follow the server's EventSource and run
   `Message/changes` on each StateChange. That is a small change to code
   that exists, and it removes the poll delay. Build the stream when
   something shows the remaining costs matter: measured round-trip
   latency, base64 cost on large Commits or Welcomes, a mobile client, or
   a second client implementation that wants it.
2. **Token in the hello, or on the upgrade header?** Recommendation: in
   the hello, as you asked, checked by the same code as the JMAP
   extractor. The header form needs no new check code but shuts out
   browser clients.
3. **Is the hub's answer on a later `Send` synchronous?**
   Recommendation: one `Ack` per request, sent when the hub answers, as
   `Room/send` waits today. Other requests and `Deliver`s flow in the
   meantime, so nothing blocks behind a slow hub.
4. **Position as the JMAP Message state string?** Recommendation: yes.
   The agent keeps no new state, and catch-up and stream meet at one
   value.
5. **Strict CBOR decoding?** Recommendation: reject duplicate keys,
   indefinite lengths, non-shortest integers and trailing bytes; allow
   any key order.
6. **Does this ever become an Internet-Draft?** Recommendation: not now.
   Keep it mimid's own until a second implementation wants it. If it
   does, it would be a companion to draft-atwood-jmap-chat-mimi, and
   Agora would be cited once it is CC-BY.
