# A binary live stream between the agent and its provider

Design note. First written 2026-11-20 against main at eedc290 for Mark's
review; rewritten the same day after Mark's direction (below), against
main at 3d4676a. Epic mimid-e64f.

## 1. Purpose

The agent (mimid-agent-core) talks to its provider (mimid-server)
through JMAP: draft-atwood-jmap-chat-mimi-00 over HTTPS, with a bearer
token. That draft is Mark's proposal for the standard client-provider
protocol of MIMI. MIMI protocol-07 covers only provider to provider.

The live stream is a **second binding of the same client-provider
operations**: CBOR messages over one WebSocket. Its purpose is to find
gaps in draft-atwood-jmap-chat-mimi-00. Writing every operation again
without JMAP's conventions (Session, `/get` and `/changes`, state strings,
base64url in JSON, SetErrors) shows what the draft leaves to JMAP and
what it does not say at all. It is not a transport upgrade:

- JMAP stays the standard and the agent's default. The stream sits
  behind a configuration switch on the server and on the agent (§5.2).
- The stream covers the whole draft, not only receiving: sending and the
  hub's answer, KeyPackages, key material, rooms and their membership,
  consent, attachments, catch-up and history (§5.9).
- Both bindings call the same server functions, so they can differ in
  shape but not in behaviour (§5.10). Integration tests run the same
  scenarios over both and require the same results (§7).
- The main output is the findings log,
  `docs/design/binary-live-stream-findings.md`: one entry per gap, with
  the draft's text, how each binding handles it, and proposed draft
  text. Proposed text lives only there; changes to jmap-chat-spec need
  Mark's OK.

The session and framing layer comes from Mark's Agora spec,
`agora-spec/spec/11-transport.md` §11.2, §11.4 and §11.6, with the
split of §11.8.8 and the CBOR conventions of `spec/13-encoding.md`
§13.1 and §13.2. Agora is all rights reserved by Mark; this note reuses
it with his permission and cites it section by section.

The stream is mimid's own protocol. Every name, value and path below
that no spec defines is INVENTED, NOT FROM SPEC, and has a decision bead
under mimid-1wgh (§8).

### 1.1 Today

How the agent hears of new messages now:

- `Agent::receive` (crates/mimid-agent-core/src/agent.rs:2527) calls
  `Jmap::messages_since` (crates/mimid-agent-core/src/client.rs:601):
  `Message/changes` from the saved state, then `Message/get` of the new
  ids with `properties: ["body"]`. Each body is one FanoutMessage in
  base64url.
- The daemon calls it on each StateChange from the server's EventSource
  (bead mimid-ak29: crates/mimid-agent-core/src/push.rs,
  crates/mimid-agent/src/push.rs; crates/mimid-server/src/jmap/eventsource.rs),
  at once after a local write, and every `sync_interval_ms` as a
  fallback, 30 s by default (crates/mimid-agent/src/config.rs).
- The agent keeps `message_state` (the JMAP Message state string) and
  `handled` (Message ids after that state already processed) in its
  state (crates/mimid-agent-core/src/state.rs:155-161).
- The server's Message state is `s.m`: s is the highest follower_event
  `seq` the user may see, m the user's highest follower_member id
  (crates/mimid-server/src/jmap/projection.rs:26-31). seq is one counter
  for the whole provider (migrations/0003_follower.sql:21).
- Every other operation is one JMAP method call over HTTPS: `Room/send`,
  `Room/update`, `Room/create`, `KeyPackage/set`, `KeyMaterial/fetch`,
  `Consent/get` and `Consent/set`, `GroupInfo/fetch`,
  `Room/reportAbuse`, `Chat/get` and `Chat/set`, and blob upload and
  attachment fetch (client.rs:211-791).

## 2. Alternatives

Kept from the first version of this note, which asked whether a stream
was worth building as a transport. Mark answered that it is built now,
for the purpose of §1 (§9 question 1).

- **JMAP + EventSource.** This exists today on the server. The agent
  could follow `eventSourceUrl` and run `Message/changes` on each
  StateChange. That removes the poll delay with almost no new protocol
  (bead mimid-ak29 does this). It keeps two round trips per wake-up and
  base64url bodies, and it stays text.
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
  same TLS listener and HTTP stack as JMAP, so the token check can stay
  where it is.

For finding gaps the choice matters less than for speed: any binding
that is not JMAP will do. CBOR over WebSocket is the smallest one and
the one closest to MIMI's own encodings.

## 3. Taken from Agora as is

- **Messages.** Each message is one CBOR data item (RFC 8949), a map
  with text keys, matching the CDDL (RFC 8610) in §5.11. No JSON on the
  stream (Agora §11.4).
- **`v` and `t`.** Every message has `v`, the negotiated version, and
  `t`, its name. A receiver discards a message with an unknown `v` and
  MAY close the connection. It ignores map keys it does not know. The
  provider answers an unknown `t` with `Error` code `badMessage`; the
  agent ignores one (Agora §11.4 "Common members", §13.2).
- **Framing.** One message per binary WebSocket message, no prefix. A
  text WebSocket message closes the connection (Agora §11.2, §11.4
  "Framing").
- **Hello.** `ClientHello` lists the versions the client supports; the
  provider answers with the highest common one, or `Error`
  `unsupportedVersion` and closes. Neither side sends anything else
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
- **Size cap.** A named limit on a message, stated in the hello (Agora
  §11.4 "Size"; §5.8).
- **Version surface.** The stream version is separate from any version
  in the endpoint path (Agora §11.6, §13.2 registry).

Datagrams for loss-tolerant traffic (Agora §11.4 "Framing") need
WebTransport, so they are in §6.

Two places where this note differs from Agora's conventions:

- Times are uint milliseconds since the UNIX epoch, as protocol-07 has
  them (`accepted_timestamp`, FanoutMessage `timestamp`), not RFC 3339
  text (Agora §13.1 "Common value encodings").
- Decoding is strict, as AGENTS.md asks and Mark chose (§9 question 5):
  reject duplicate keys, indefinite-length items, non-shortest integers
  and lengths, and trailing bytes in a frame. Key order stays free on
  input, as in Agora §13.1. Output uses the RFC 8949 §4.2.1 key order,
  so one value has one encoding.

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

### 5.1 Endpoint

WebSocket at `<server>/mimid/live`, where `<server>` is the agent's
`server_url` with `http` turned into `ws` and `https` into `wss`
(INVENTED, NOT FROM SPEC). The stream is not advertised in the JMAP
Session: a client of the stream never reads JMAP, which is how the
stream shows that it stands on its own. What the Session's mimi
capability says (userUri, roomIdPrefix, hubSender, ...) the
`ProviderHello` says (§5.11).

### 5.2 Configuration switch

- **Server:** `live_stream = true` in mimid-server's configuration
  serves the route; it is `false` by default, and the route then does
  not exist (`404`).
- **Agent:** `binding = "stream"` in mimid-agent's configuration, or
  `Binding::Stream` in `AgentConfig`, makes the agent use the stream for
  every operation; `"jmap"` is the default.

Nothing runs in production, so there is no fallback from one binding to
the other: an agent set to the stream fails if the server does not
serve it.

### 5.3 Authentication

The `ClientHello` carries the bearer token. The provider checks it with
the same code as the JMAP `Account` extractor
(crates/mimid-server/src/jmap/auth.rs), so there is still one check at
the JMAP boundary (AGENTS.md "Security invariants"); the boundary table
gains a row for the stream that names that code. A bad token gets
`Error` `unauthorized` without `id`, and the connection closes. Every
refusal looks the same, as on JMAP. The provider checks the token again
before each request and each batch of `Deliver`s, so a token revoked
while connected gets the same error and close. A client that sends no
`ClientHello` within 10 seconds of the upgrade is closed (INVENTED).

Other options, not taken:

- `Authorization` header on the WebSocket upgrade. It reuses the
  extractor without change, but browsers' WebSocket API cannot set
  headers, and Mark asked for the hello (§9 question 2).
- A token bound to the TLS connection: the client sends
  HMAC(token, TLS exporter value, RFC 8446 §7.5) instead of the token.
  A token copied off one connection would not work on another. It does
  not help while the same token travels as a plain bearer on JMAP, so
  it waits until JMAP does the same (§6).

### 5.4 Requests and answers

Every operation of the draft is one request with an `id`. The provider
answers it with one `Ack` (the operation was done; what it returned is
in the `Ack`) or one `Error` (it was not; why, in `code` and the
fields the code names). A request that goes to a hub is answered once
the hub answers, and other traffic flows meanwhile (§9 question 3). The
hub's refusal is an `Error` whose `code` is the refusal's name in the
draft (`notAllowed`, `epochTooOld`, `wrongEpoch`, `invalidProposal`,
...), with the hub's fields (`currentEpoch`, `invalidProposals`,
`errorDescription`). This differs from JMAP, where a hub's refusal is a
successful method response with a `responseCode`.

Error codes are camelCase. A code with the same meaning as a code of
RFC 8620 or of the draft has that code's name (`invalidArguments`,
`serverUnavailable`, `forbidden`, `notFound`, `overQuota`,
`invalidProperties`, `alreadyExists`, `consentNotSent`, ...). The
stream's own codes are `badMessage`, `unsupportedVersion`,
`unauthorized`, `cannotResume`, `tooLarge`, `rateLimited` and
`serverFail`.

At most 16 requests may be outstanding on one connection (INVENTED);
one more is answered with `rateLimited`. JMAP's limit is 4 requests in
flight per account (crates/mimid-server/src/jmap/api.rs:72), each
carrying one method call here.

### 5.5 Positions and resume

A position is the JMAP Message state string (§9 question 4). The agent
keeps no new kind of state, and JMAP and the stream meet at one value.

1. The agent sends `Subscribe` with `since`, its saved Message state, or
   without `since` the first time.
2. The provider sends a `Deliver` for each Message that `Message/changes`
   from `since` and then `Message/get` of the ids would return, in the
   same order. Without `since` it sends every stored Message, as
   `Message/get` with `ids: null`. It then answers the `Subscribe` with
   an `Ack` whose `state` is the Message state that covers every
   `Deliver` before it.
3. From then on, each time the account's Message state may have moved
   (the change bus, crates/mimid-server/src/jmap/bus.rs), the provider
   runs the same `Message/changes` and `Message/get` from the last
   state it sent, sends a `Deliver` for each new Message and then a
   `Position` with the new state.
4. The agent handles each `Deliver` as it handles a Message now. It adds
   the id to `handled`, and at the `Ack` or a `Position` sets
   `message_state` and clears `handled`. This is the same bookkeeping as
   `Agent::receive` (agent.rs:2527-2557), so a crash between a `Deliver`
   and a `Position` resumes without handling anything twice.
5. On reconnect it sends `Subscribe` with its `message_state`. Nothing
   stored between the last position and the reconnect is lost, because
   the provider computes the changes from the store, not from what it
   buffered.

`Position` exists because the state is `s.m`, not one counter. A new
membership (m) makes older Messages of that room visible, so there is no
single state after each `Deliver`, and a `Deliver` cannot carry its own
position. The provider sends `Position` only where it can name a state
that `Message/changes` accepts. This is the first finding of the log.

A lagging change bus does not lose anything: the bus only says when to
look again. If `since` does not parse, or names a state the provider
never gave (ahead of the account's current state), the provider answers
`Error` `cannotResume`. The agent then subscribes again without `since`,
as it falls back to `Message/get` of every Message on
`cannotCalculateChanges` today (client.rs:616-620). One `Subscribe` per
connection; a second gets `badMessage`.

The agent's own messages still come back, as on JMAP today; it skips
them by digest (`Jmap::is_own`, client.rs:580).

### 5.6 Notices

`Changed` names the data types whose state moved for the account:
`Chat`, `KeyPackage` and `Consent`, computed as the EventSource computes
its `StateChange` (eventsource.rs). It is sent only after a `Subscribe`.
The client then lists what it wants again (`ListChats`,
`ListKeyPackages`, `ListConsent`). Messages need no notice: they arrive
as `Deliver`s.

### 5.7 Identifiers

The stream names records by what the draft's structures already name
them by, not by JMAP ids, where it can:

- a KeyPackage by its KeyPackageRef (exact bytes);
- a room by its room ID;
- a Message by `messageId`, the JMAP Message id, because nothing in the
  FanoutMessage names one stored copy;
- a Chat by `chatId`, and a Consent record by `consentId`, the JMAP ids,
  because the draft defines no other name for them.

### 5.8 Size

`ProviderHello` states two limits (INVENTED):

- `maxMessageBytes`, 16 MiB + 64 KiB: no frame in either direction is
  larger. It fits an `Upload` or a `FetchAsset` answer of the largest
  blob mimid stores (16 MiB, crates/mimid-server/src/store/blobs.rs).
- `maxRequestBytes`, 4 MiB + 64 KiB: no client request other than
  `Upload` is larger. It fits the largest MLS object mimid takes on any
  other route (4 MiB, crates/mimid-server/src/http.rs:90), as JMAP's
  `maxSizeRequest` does after base64url (api.rs:59).

A larger frame gets `Error` `tooLarge` without `id`, and the connection
closes. No FanoutMessage mimid stores is larger than the protocol
routes' body cap, so a `Deliver` always fits.

### 5.9 Mapping

Every method the draft defines, every flow the agent uses, and the
stream message for each. "Agent" marks what the agent uses today.

| Draft (section) | JMAP in mimid-server | Agent | Stream |
|---|---|---|---|
| Session, mimi capability (§capability) | `GET /.well-known/jmap` (session.rs) | yes, client.rs:140 | `ClientHello` / `ProviderHello` |
| Authentication (base draft §Authorization) | `Authorization: Bearer` (auth.rs) | yes | `token` in `ClientHello` |
| `KeyPackage/get` (§keypackage) | methods/key_package.rs | no | `ListKeyPackages` |
| `KeyPackage/set` create | methods/key_package.rs | yes, client.rs:361 | `PublishKeyPackage` |
| `KeyPackage/set` update (always `forbidden`) | methods/key_package.rs | no | none: KeyPackages are immutable |
| `KeyPackage/set` destroy | methods/key_package.rs | no | `DestroyKeyPackage` |
| KeyPackage handed out (§keypackage-claim, StateChange) | EventSource `KeyPackage` | no | `Changed` `KeyPackage` |
| `KeyMaterial/fetch` (§keymaterial-fetch) | methods/key_material.rs | yes, client.rs:470 | `FetchKeyMaterial` |
| `Consent/get` (§consent) | methods/consent.rs | yes, client.rs:338 | `ListConsent` |
| `Consent/changes` | methods/consent.rs | no | `Changed` `Consent`, then `ListConsent` |
| `Consent/query` | methods/consent.rs | no | none: the client filters `ListConsent` |
| `Consent/set` create, update, destroy (§consent-set) | methods/consent.rs | yes, client.rs:356 | `CreateConsent`, `UpdateConsent`, `DestroyConsent` |
| Consent from other providers (§consent-received) | EventSource `Consent` | no | `Changed` `Consent` |
| `Chat/get`, `roomId` (§chat-roomid) | projection.rs | yes, client.rs:403 | `ListChats` |
| `Chat/set` `privateMetadata` (metadata-05; decision mimid-1wgh.63) | metadata.rs | yes, client.rs:434 | `SetChatAccepted` |
| `Chat/set` of name, members (refused, §chat-roomid) | methods/chat_set.rs | no | none: no such request |
| `Room/create` (§room-create) | methods/room_create.rs | yes, client.rs:376 | `CreateRoom` |
| `Room/update`, external Commit too (§room-update) | methods/room_update.rs | yes, client.rs:663 | `Update` |
| `Room/send` (§room-send) | methods/room_send.rs | yes, client.rs:761 | `Send` |
| `Room/reportAbuse` (§room-report-abuse) | methods/room_report_abuse.rs | yes, client.rs:730 | `ReportAbuse` |
| `Room/unbind` (§room-unbind) | methods/room_unbind.rs | no (the agent leaves by Commit) | `Unbind` |
| `GroupInfo/fetch` (§groupinfo-fetch) | methods/group_info.rs | yes, client.rs:452 | `FetchGroupInfo` |
| `Message/changes` + `Message/get` (§fanout-messages) | projection.rs | yes, client.rs:601 | `Subscribe`, `Deliver`, `Position` |
| `Message/get` of every Message, first sync | projection.rs | yes | `Subscribe` without `since` |
| StateChange for `Message` (base draft §Push) | eventsource.rs | mimid-ak29 | `Deliver` |
| `Message/set` (refused, §private-messages, §fanout-messages) | methods/message_set.rs | no | none: no such request |
| Blob upload (RFC 8620 §6.1) and `assetUrl` (§capability) | blobs.rs | yes, client.rs:268 | `Upload`; `assetUrl` in `ProviderHello` |
| `assetDownloadUrl` (§capability) | blobs.rs | yes, client.rs:299 | `FetchAsset` |
| `Message/reportAbuse` (§report-abuse) | not served: for a converting party | no | none |
| `Blob/get`, `Blob/set`, `Blob/lookup`, `Blob/convert` (blobext-03) | methods/blob.rs | no | none: not part of the draft |

### 5.10 One behaviour, two shapes

Each JMAP method of the draft in mimid-server becomes two layers:

- a core function in the method's file that takes the decoded arguments
  (bytes, not base64url; typed values, not JSON) and the authenticated
  account, does every check and the work, and returns a typed result or
  a `JmapError` / SetError;
- the JMAP handler, which reads the JSON arguments into that call and
  writes the result as JSON.

The stream handler calls the same core function and writes the result as
CBOR; an error's `type` becomes the `Error` `code` of the same name.
So the bindings cannot differ in what they check or do, only in how
they say it. Where the JMAP layer itself refuses something (a body
over `maxSizeRequest`, a bad `accountId`), the stream has its own
check, listed in §5.8 and §5.3.

### 5.11 Messages

The CDDL (RFC 8610) of version 1. The codec is crates/mimid-live; its
fixtures (crates/mimid-live/tests/fixtures) are encoded by hand from
this text. Every map may carry members not named here; a receiver
ignores them, and the codec keeps them so they round-trip.

```cddl
message      = client-msg / provider-msg
client-msg   = ClientHello / request
provider-msg = ProviderHello / Ack / Error / Deliver / Position / Changed

req-id     = uint
room-id    = tstr          ; MIMI room ID
jmap-state = tstr          ; a JMAP state string, opaque to the client
ms         = uint          ; milliseconds since the UNIX epoch
tls        = bstr          ; exact TLS-presentation octets (RFC 9420,
                           ; protocol-07), never re-encoded

common = ( "v": uint, "t": tstr )

; ---- hello: the same form in every version ----

ClientHello = {
  "v": 1, "t": "ClientHello",
  "versions": [+ uint],
  "token": tstr            ; the bearer token (mimid-1wgh.73)
}

ProviderHello = {
  "v": 1, "t": "ProviderHello",
  "version": uint,         ; negotiated
  "userUri": tstr,         ; as the mimi capability's
  "roomIdPrefix": tstr,
  "hubSender": tls,        ; ExternalSender
  "cipherSuites": [* uint],
  "maxKeyPackages": uint,
  "maxMessageBytes": uint, ; no frame is larger (mimid-1wgh.78)
  "maxRequestBytes": uint, ; no request but Upload is larger
  "storesAssets": bool,    ; assetUrl present
  ? "assetLifetime": uint, ; seconds
  "fetchesAssets": bool,   ; assetDownloadUrl present
  "acceptedRooms": bool    ; SetChatAccepted works (mimid-1wgh.63)
}

; ---- requests: each answered by one Ack or one Error with its id ----

request = { common, "id": req-id, op }

op = (
    "t": "Subscribe", ? "since": jmap-state )                 ; absent: every Message
  // ( "t": "Send", "room": room-id, "message": tls )          ; MLSMessage
  // ( "t": "Update", "room": room-id, "request": tls )        ; UpdateRequest
  // ( "t": "CreateRoom", "room": room-id,
       "groupInfo": tls, "ratchetTree": tls )
  // ( "t": "Unbind", "room": room-id )
  // ( "t": "ReportAbuse", "room": room-id, "report": tls )    ; AbuseReport
  // ( "t": "FetchGroupInfo", "room": room-id, "request": tls )   ; GroupInfoRequest
  // ( "t": "FetchKeyMaterial", "room": room-id, "request": tls ) ; KeyMaterialRequest
  // ( "t": "PublishKeyPackage", "keyPackage": tls, ? "lastResort": bool )
  // ( "t": "ListKeyPackages" )
  // ( "t": "DestroyKeyPackage", "keyPackageRef": tls )
  // ( "t": "ListConsent" )
  // ( "t": "CreateConsent", "requesterUri": tstr, "targetUri": tstr,
       ? "room": room-id, ? "requested": bool, ? "decision": decision )
  // ( "t": "UpdateConsent", "consentId": tstr,
       ? "requested": bool, ? "decision": decision / null )
  // ( "t": "DestroyConsent", "consentId": tstr )
  // ( "t": "ListChats" )
  // ( "t": "SetChatAccepted", "chatId": tstr, "accepted": bool )
  // ( "t": "Upload", "data": bstr, ? "type": tstr )
  // ( "t": "FetchAsset", "room": room-id, "url": tstr )

decision = "grant" / "revoke"

; ---- answers ----

Ack = { common, "id": req-id, ack-result }   ; "t": "Ack"

ack-result = (
    "state": jmap-state )                               ; Subscribe
  // ( "acceptedAt": ms, ? "frank": tls )               ; Send
  // ( "acceptedAt": ms, ? "errorDescription": tstr )   ; Update
  // ( "chatId": tstr )                                 ; CreateRoom
  // ( )                     ; Unbind, ReportAbuse, DestroyKeyPackage,
                             ; UpdateConsent, DestroyConsent, SetChatAccepted
  // ( "status": tstr, "response": tls )                ; FetchGroupInfo
  // ( "response": tls )                                ; FetchKeyMaterial
  // ( "keyPackageRef": tls, "lastResort": bool )       ; PublishKeyPackage
  // ( "state": tstr, "keyPackages": [* key-package] )  ; ListKeyPackages
  // ( "state": tstr, "records": [* consent] )          ; ListConsent
  // ( "record": consent )                              ; CreateConsent
  // ( "state": tstr, "chats": [* chat] )               ; ListChats
  // ( "blobId": tstr, "url": tstr, "size": uint )      ; Upload
  // ( "data": bstr )                                   ; FetchAsset

key-package = { "keyPackageRef": tls, "keyPackage": tls, "lastResort": bool }
consent = {
  "consentId": tstr, "requesterUri": tstr, "targetUri": tstr,
  "room": room-id / null, "requested": bool,
  "decision": decision / null, "updated": ms
}
chat = { "chatId": tstr, "room": room-id, "bound": bool, "accepted": bool }

Error = {
  common,                  ; "t": "Error"
  ? "id": req-id,          ; absent: the connection
  "code": tstr,            ; §5.4 (mimid-1wgh.79)
  ? "detail": tstr,        ; diagnostic, not for display
  ? "currentEpoch": uint,  ; epochTooOld, wrongEpoch
  ? "invalidProposals": [* tls],  ; invalidProposal: ProposalRefs
  ? "errorDescription": tstr,     ; a refused Update: the hub's text
  ? "status": uint,        ; refused: another provider's HTTP status
  ? "properties": [* tstr],       ; invalidProperties
  ? "existingId": tstr     ; alreadyExists
}

; ---- unsolicited, after a Subscribe ----

Deliver  = { common, "messageId": tstr, "chatId": tstr, "fanout": tls }
Position = { common, "state": jmap-state }
Changed  = { common, "types": [+ ("Chat" / "KeyPackage" / "Consent")] }
```

The `Ack` has no member naming its request's type: the client knows it
from the `id`. A `Deliver` names no room; the FanoutMessage and the
Chat do.

`Deliver` carries a whole FanoutMessage, so Welcomes arrive the same way
as on JMAP (draft-atwood-jmap-chat-mimi-00 §application/mimi-fanout,
stored only for the account that owns the named KeyPackageRef). Unlike
Agora, Welcomes do travel on this stream (compare Agora §11, opening).

## 6. Later, if needed

Each item waits for a concrete need, and each gets a version bump or new
`t` values negotiated in the hello.

- **WebTransport.** One bidirectional stream carrying a CBOR sequence
  (RFC 8742), as Agora §11.1 and §11.4. Needs HTTP/3 in mimid-server.
- **Datagrams.** For typing and presence, as Agora §11.4 and §5.3: no
  `Ack` for a datagram, never a `Deliver` of a FanoutMessage. mimid has
  no typing or presence today, and MIMI defines none.
- **Exporter-bound token** (§5.3).
- **Several subscriptions or per-room filters.**
- **Chunked uploads**, if blobs grow past what one frame should hold.

## 7. Tests: the two bindings side by side

- **Same scenarios, same results.** crates/mimid-agent-core/tests/bindings.rs
  runs the two-agent scenario of tests/two_agents.rs (publish, host,
  refused and allowed consent, invite, join, both send, restart, a
  message received but not acknowledged comes again, leave) three
  times against one server that serves both bindings: both agents on
  JMAP, both on the stream, and one on each. Each run records what the
  agents report (events, message text, members, epochs, refusals) in a
  form without ids, room URIs or times, and the test requires the three
  records to be equal.
- **The daemon.** crates/mimid-agent/tests/push.rs: two daemons with
  `binding = "stream"` and an hour's poll interval exchange a Welcome
  and messages, woken by the stream alone.
- **Stream only:**
  - no gap and no duplicate across reconnects, including a crash after
    a `Deliver` was handled but before its position was saved
    (bindings.rs);
  - a membership change while subscribed: the Welcome and the Messages
    it makes visible arrive, and JMAP's `Message/changes` from the
    stream's first position lists exactly the delivered ids in the same
    order and ends at the stream's last position (bindings.rs);
  - a frame over each limit (`tooLarge`, closed) and one at it
    (crates/mimid-server/tests/live_stream.rs);
  - a wrong, malformed or revoked token (`unauthorized`, closed), also
    while connected, as the JMAP boundary test does for HTTP (AGENTS.md
    "Each check has a test showing a wrong identity is rejected";
    live_stream.rs, and bindings.rs through the agent);
  - hostile frames: text frames, duplicate keys, a second hello, an
    unknown `t` (answered with its `id`), unknown versions
    (live_stream.rs), and in the codec indefinite lengths,
    non-shortest integers, trailing bytes, deep nesting, invalid UTF-8
    and every one-byte corruption of a frame (crates/mimid-live/tests).
- **Codec** fixtures from outside the code (§8 step 2).

## 8. Implementation plan

Each step is its own commits and its own bead under mimid-e64f. Every
gap found on the way goes into the findings log with file:line
references.

1. This note; the decisions as beads under mimid-1wgh, one for each of
   Mark's answers and each INVENTED value (mimid-1wgh.72 purpose and
   scope, .73 token, .74 hub answers, .75 positions, .76 CBOR, .77
   endpoint, messages and identifiers, .78 limits, .79 error codes,
   .80 configuration switch); the findings log, seeded.
2. A pure crate, `mimid-live`, for the stream's types and strict CBOR
   codec: sync, no I/O, limits as named constants. The CDDL goes in this
   note. Fixtures from outside the code: CBOR encoded by hand from the
   CDDL with byte comments, cross-checked with Python `cbor2`, with a
   PROVENANCE file. Decode, compare, re-encode, require identical bytes.
   Hostile-input tests.
3. mimid-server: split each draft method into core and JMAP layer
   (§5.10); the WebSocket route behind `live_stream`; hello and token
   check through the `Account` extractor's code; every request of
   §5.9.
4. mimid-agent-core and mimid-agent: the provider client becomes one
   interface with a JMAP and a stream implementation, chosen by
   configuration, JMAP by default. Only `Store::sync` calls
   `Agent::receive` and `Agent::acknowledge`, on either binding.
5. The side-by-side tests of §7.
6. The findings log, filled as the steps go.

AGENTS.md gains the crate in its crate map and the stream in its
boundary table.

## 9. Questions answered by Mark

All six answered by Mark on 2026-11-20. Each answer is a decision bead
under mimid-1wgh (§8 step 1); the recommendation text is kept below each
answer. On the same day Mark set the purpose of §1, which moved every
"later" item of the first version (sends, room creation, KeyPackages,
key material, consent, notices) into version 1.

1. **Build it now, or wait for a concrete need?** ANSWERED: build the
   stream now, not the EventSource step first. Recommendation was: wait.
   First make the agent follow the server's EventSource and run
   `Message/changes` on each StateChange. That is a small change to code
   that exists, and it removes the poll delay. Build the stream when
   something shows the remaining costs matter: measured round-trip
   latency, base64 cost on large Commits or Welcomes, a mobile client, or
   a second client implementation that wants it.
2. **Token in the hello, or on the upgrade header?** ANSWERED: in the
   `ClientHello`, checked by the same code as the JMAP `Account`
   extractor. Recommendation was: in
   the hello, as you asked, checked by the same code as the JMAP
   extractor. The header form needs no new check code but shuts out
   browser clients.
3. **Is the hub's answer on a later `Send` synchronous?** ANSWERED: a
   `Send` is answered once the hub answers, with one `Ack` carrying
   `acceptedAt` and `frank`, or one `Error` carrying the refusal; other
   traffic flows meanwhile. §5.4 applies the same rule to every request
   that goes to a hub. Recommendation was: one
   `Ack` per request, sent when the hub answers, as
   `Room/send` waits today. Other requests and `Deliver`s flow in the
   meantime, so nothing blocks behind a slow hub.
4. **Position as the JMAP Message state string?** ANSWERED: yes.
   Recommendation was: yes.
   The agent keeps no new state, and catch-up and stream meet at one
   value. Whether it holds up is recorded in the findings log.
5. **Strict CBOR decoding?** ANSWERED: strict. Reject duplicate keys,
   indefinite lengths, non-shortest integers and trailing bytes; accept
   any key order. Recommendation was: reject duplicate keys,
   indefinite lengths, non-shortest integers and trailing bytes; allow
   any key order.
6. **Does this ever become an Internet-Draft?** ANSWERED: not now.
   Recommendation was: not now.
   Keep it mimid's own until a second implementation wants it. If it
   does, it would be a companion to draft-atwood-jmap-chat-mimi, and
   Agora would be cited once it is CC-BY.
