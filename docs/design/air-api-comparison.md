# Air's client API and draft-atwood-jmap-chat-mimi-00

Design note, 2026-11-21. Compares the client-server API of Air, Phoenix
R&D's messenger, with draft-atwood-jmap-chat-mimi-00 (jmap-chat-spec
813ad11, which has F1 to F18 of binary-live-stream-findings.md applied).

Air was read at github.com/phnx-im/air commit
`0f712b603a13f25edef29857ca4010ad454fa61c` (2026-11-19). References like
`queue_service.proto` mean `protos/api/queue_service/v1/queue_service.proto`
at that commit; `backend/...` and `server/...` are paths in the same
tree. The repo has no design documents beyond module comments
(`backend/src/qs/mod.rs`, `backend/src/ds/process.rs`), which say
themselves that they are work in progress. Where this note reads
behaviour from code rather than from a comment or proto, it says so.

Nothing here has gone to Phoenix or to jmap-chat-spec. Proposed draft
text needs Mark's OK, as for the F-findings.

## 1. Air's architecture in brief

One server binary (`server/src/lib.rs`) serves four gRPC services over
HTTP/2 from one tonic server, with a health service. Field types are
mostly `bytes` wrappers around TLS-encoded MLS structures (`MlsMessage`,
`AssistedMessage`, `KeyPackage`, `RatchetTree` all have one `bytes tls`
field). Shared types are in `common/v1/common.proto`.

### 1.1 The services

- **AuthService** (`auth_service.proto`, the AS). Accounts and identity:
  registration (`RegisterUser`, gated by `GetRegistrationInfo`,
  `CheckInvitationCode`, `CreateAdmissionSession`), user credentials and
  the AS's own signing chain (`AsCredentials`), encrypted user profiles
  (`StageUserProfile`, `MergeUserProfile`, `GetUserProfile`), usernames
  stored only as hashes (`CreateUsername`, `RefreshUsername`,
  `DeleteUsername`, `CheckUsernameExists`), first contact by username
  (`PublishConnectionPackages`, `ConnectUsername`, `ListenUsername`),
  Privacy Pass tokens (`IssueTokens`, `IssueTokenBatch`) and
  `ReportSpam`.
- **DeliveryService** (`delivery_service.proto`, the DS). The MLS
  delivery service: it holds each group's public state, checks
  handshake messages, and fans out to members' queues. Group creation
  (`RequestGroupId`, `CreateGroup`, `CreateApqGroup`, `CreateGroupV2`),
  join support (`WelcomeInfo`, `ExternalCommitInfo`, `EpochSnapshot`),
  commits (`GroupOperation`, `SelfRemove`, `Resync`, `DeleteGroup`),
  application messages (`SendMessage`, `TargetedMessage`), connection
  groups for first contact (`ConnectionGroupInfo`,
  `JoinConnectionGroup`, `CloseConnectionGroup`), `UpdateProfileKey`,
  and attachment storage (`ProvisionAttachment`, `GetAttachmentUrl`).
  Most operations come twice, plain and `Apq*`: an APQ group is a pair
  of MLS groups, one with a classical and one with a post-quantum
  cipher suite (the `apqmls` crate), and every APQ message carries one
  message per leg (`ApqAssistedMlsMessage`).
- **QueueService** (`queue_service.proto`, the QS). Per-client queues:
  pseudonymous user and client records (`CreateUser`, `CreateClient`,
  their `Update*` and `Delete*`), KeyPackage storage
  (`PublishKeyPackages`, `StageKeyPackages`, `KeyPackage`,
  `PublishApqKeyPackages`, `ApqKeyPackage`), the QS's public key
  (`QsEncryptionKey`), and the bidirectional `Listen` stream.
- **RelayService** (`relay_service.proto`). A rendezvous for linking a
  new device to an existing one: `MultiDeviceProvisionClient` (the new
  device waits) and `MultiDeviceLinkClient` (the existing device
  connects); both are bidi streams of opaque `RelayFrame`s. State is in
  memory only (`backend/src/relay_service/mod.rs`).

Federation between Air servers is not gRPC: the QS POSTs a TLS-encoded
`QsToQsMessage` with `AirProtocolVersion::Alpha` to the other server's
federation endpoint over HTTPS (`backend/src/qs/ds_api.rs`
`enqueue_message`, `server/src/network_provider.rs`). User ids and group
ids are qualified by domain (`common.v1.UserId`, `QualifiedGroupId`).

### 1.2 Authentication

There is no session, login, or bearer token. Each request that needs
authority carries a `payload` and a `signature` over its encoding
(`SignedRequest` in the `airprotos` crate), and the server checks the
signature against a key it already holds:

- AS: the key of the user credential the AS issued at `RegisterUser`
  (a CSR in `UserCredentialPayload`); username operations are signed by
  a per-username key (`UsernameSignature`).
- QS: per-record keys the client chose at creation,
  `user_record_auth_key` and `client_record_auth_key`
  (`backend/src/qs/auth.rs`). `Listen` is signed in its `init` step.
- DS: the signature key of the sender's leaf in the group's ratchet
  tree (`resolve_and_verify` in `backend/src/ds/grpc.rs`), plus the
  `GroupStateEarKey`, which the DS needs to decrypt its own stored state
  for the group (§1.3). Reads such as `ExternalCommitInfo` and
  `EpochSnapshot` are authorized by the EAR key alone.

Unauthenticated: `RequestGroupId`, `CreateUser`, `RegisterUser` (gated
by challenge, §3 A11), `AsCredentials`, `QsEncryptionKey`, and the
KeyPackage fetches, which are authorized by knowing the target's
`FriendshipToken`. A stale comment in `backend/src/qs/grpc.rs` says
"currently, *no* authentication is done" for the QS; the code verifies
signatures as above.

Every request carries `ClientMetadata` (the client's semver and commit
hash) for version policy (§1.8). The whole server sits behind a per-IP
rate limiter (`GovernorLayer` with `ClientIpExtractor`,
`server/src/lib.rs`).

### 1.3 Identities, KeyPackages, groups

- **Identity.** A user is `UserId {uuid, domain}` at the AS, with a
  `UserCredential` signed by an AS intermediate credential. The same
  user is, at the QS, an unrelated random `QsUserId` with one
  `QsClientId` per device; the QS does not know the AS user id.
- **KeyPackages** live at the QS per client. Another user fetches one
  with `KeyPackage` / `ApqKeyPackage` by presenting the target's
  `FriendshipToken`, a secret the target shares only with contacts.
  `StageKeyPackages` holds a batch invisible until the DS sees the
  commit that publishes it (for "virtual clients", where several
  devices act as one MLS client). First contact uses separate
  *connection packages* (HPKE keys, `ConnectionPackage`), published at
  the AS under a username hash, fetched in `ConnectUsername` for a
  Privacy Pass token, with `is_last_resort` as in RFC 9420.
- **Groups.** The client asks `RequestGroupId` for a fresh
  `QualifiedGroupId` and then `CreateGroup` with the ratchet tree,
  GroupInfo, `RoomState` (a TLS-encoded room-policy state, checked with
  Phoenix's `mimi-room-policy` crate, `backend/src/ds/create_group.rs`)
  and a sealed reference to its queue. The DS stores the group's state
  encrypted at rest under the `GroupStateEarKey`, which clients send
  with each request and which is ratcheted with fresh input on every
  commit (`backend/src/ds/process.rs` module comment). Handshake
  messages go as `AssistedMessage` (PublicMessage, or a PrivateMessage
  with an assisted part) so that the DS can check and apply commits.
  `GroupOperation` carries a commit plus, for adds, the Welcome and
  encrypted attribution info; the DS forwards Welcomes to the new
  members' queues. Joiners get the tree and room state from
  `WelcomeInfo` (after a Welcome) or `ExternalCommitInfo` (external
  join).
- **Membership changes the DS initiates.** `DeleteGroup` writes a
  tombstone into the group context; afterwards writes fail with
  `NOT_FOUND` and detail `GROUP_CLOSED`, reads still work
  (`ensure_no_tombstone`, `backend/src/ds/grpc.rs`).

### 1.4 Messages and fanout

`SendMessage` takes an `AssistedMessage`, the sender's leaf index,
`suppress_notifications`, and `collision_tags` (truncated hashes; the
DS refuses a tag already used for that group and epoch with
`GENERATION_COLLISION`, so that sibling devices of one virtual client do
not both send the same generation, `backend/src/ds/collision_tags.rs`).
The DS loads the group, checks the tombstone and the leaf signature,
and fans the message out to every other member's queue; the answer is
`fanout_timestamp`. Application messages do not change group state, so
`SendMessage` takes no lock (comment in `send_message`).

Fanout targets are `QsReference {client_homeserver_domain,
sealed_reference}`: the reference to the member's queue is HPKE-sealed
to the QS's key (`QsEncryptionKey`), so the DS stores per leaf only an
opaque blob and a domain. The QS opens it to find the `QsClientId` and
the key it needs to decrypt the push token (`backend/src/qs/ds_api.rs`).
A reference to another domain goes over federation.

Queues are encrypted at rest to the owning client: the client gave the
QS a `queue_encryption_key` (HPKE) and an initial ratchet secret, and
the QS ratchets the symmetric key forward per message
(`backend/src/qs/mod.rs` module comment). A `QueueMessage` on the wire
is `{sequence_number, ciphertext}`.

### 1.5 Queues and `Listen`

`Listen` (`queue_service.proto`) is a bidi stream:

- Client sends first `InitListenRequest {client_id,
  sequence_number_start}` (signed). Later: `AckListenRequest
  {up_to_sequence_number}` (exclusive), `FetchListenRequest` (look
  again), `ReportClientStateListenRequest` (an encrypted blob of at
  most 256 octets for sibling devices), `KeepAliveListenRequest`.
- Server sends first `VersionStatus {expires_at, max_devices}`, then
  one `SiblingClientState` per sibling currently listening, then
  `QueueMessage`s from `sequence_number_start` in order, then
  `QueueEmpty` when the backlog is drained. It goes on with new
  `QueueMessage`s (woken by Postgres `NOTIFY`), `QueueEmpty` after each
  burst, `QueueEventPayload` (ephemeral, only to clients listening at
  that moment; the Air client ignores them today,
  `coreclient/src/clients/process/qs_stream.rs`) and sibling state
  changes.

Resume semantics (rpc comment and `backend/src/listen_session.rs`):

- An ack deletes the acknowledged messages from the queue
  (`Queue::delete`).
- If the client half-closes its side, the server handles every request
  received before and closes with `OK`. `OK` means every ack sent is
  durable. Any other end leaves the last acks unconfirmed, and those
  messages come again on the next `Listen`.
- One listener per client: a second `Listen` for the same `QsClientId`
  ends the first with `ABORTED "evicted"`. Server shutdown ends it with
  `UNAVAILABLE`.
- Push: the QS sends a push notification only for a client that has no
  listener at enqueue time (`QsClientRecord::enqueue`), and not when
  the sender set `suppress_notifications`. The push token is stored
  encrypted (`EncryptedPushToken`); the key to decrypt it arrives in
  the sealed reference with each fanout.

`ListenUsername` (AS) is a second queue with a different ack: per
message, by `message_id`, and "on reconnect, all messages are resent
that were not acknowledged". It carries connection offers only.

### 1.6 Attachments

`ProvisionAttachment` takes a declared `content_length` and an object
type (`STORAGE_OBJECT_TYPE_ATTACHMENT`, `_GROUP_PROFILE`,
`_USER_PROFILE`, `_DEBUG_LOGS`), checks it against a size limit
(`ATTACHMENT_TOO_LARGE` with `max_size_bytes`), and returns an object id
and a presigned PUT URL with headers and an expiry. The client uploads
straight to object storage. `GetAttachmentUrl` returns a presigned GET
URL. Both are scoped to a group (EAR key + leaf) or to a user. Content
is encrypted by the client; the server never sees it.

### 1.7 Error model

gRPC status codes, with an optional `common.v1.StatusDetails` in the
status details: a `StatusDetailsCode` and a typed `oneof detail`
(`VersionUnsupportedDetail`, `AttachmentTooLargeDetail`,
`WrongEpochDetail`, `TokenQuotaExceededDetail {retry_after_secs,
tokens_available}`, `GenerationCollisionDetail {tags}`,
`DeviceLimitReachedDetail {max_devices}`, `UncommittedSelfRemoveDetail`,
`GroupClosedDetail`). Outcomes that are part of the protocol rather
than failures come back as a `oneof outcome` in the response instead
(`RegisterUserResponse`: credential, `ChallengeRequired`,
`ChallengeRejected`; `IssueTokenBatchResponse`). The server's tracing
counts `INVALID_ARGUMENT`, `NOT_FOUND`, `ALREADY_EXISTS`,
`FAILED_PRECONDITION`, `RESOURCE_EXHAUSTED`, `UNAUTHENTICATED` and
`ABORTED` as business outcomes, not failures (`server/src/lib.rs`).

### 1.8 Versioning

- Proto packages are versioned (`*.v1`); removed fields are `reserved`
  by number and name; renamed rpcs are kept working by a path-rewrite
  layer (`server/src/grpc_method_alias.rs`, e.g. `CreateHandle` to
  `CreateUsername`). New behaviour is added as new rpcs
  (`CreateGroupV2`, `ListenUsername` "will replace the old `Listen`").
- Client software version: every request carries `ClientMetadata`; a
  server policy (`backend/src/version.rs`) rejects expired versions
  with `FAILED_PRECONDITION` + `VersionUnsupportedDetail
  {client_version_requirement}`, and `Listen` tells a client in
  advance when its version expires (`VersionStatus.expires_at`).
- Feature flags between clients: `AirFeatures` in signed connection
  packages (`pq_groups`, `apq_connection_groups`, ...).
- Protocol version: `AirProtocolVersion {version}` in AS credentials
  and connection packages; `Alpha` on the federation wire.

## 2. Mapping

"Draft" is draft-atwood-jmap-chat-mimi-00; "base" is
draft-atwood-jmap-chat-00; RFC 8620 items are what both build on.

### 2.1 Every Air rpc

| Service | Air rpc | Draft method |
|---|---|---|
| AS | `CheckInvitationCode` | none (account creation out of scope) |
| AS | `GetInvitationCodes` | none |
| AS | `GetRegistrationInfo` | none |
| AS | `CreateAdmissionSession` | none |
| AS | `RegisterUser` | none; JMAP has no account creation |
| AS | `DeleteUser` | none |
| AS | `PublishConnectionPackages` | none; nearest `KeyPackage/set` create |
| AS | `StageUserProfile`, `MergeUserProfile`, `GetUserProfile` | none; profiles are in MLS group state or base `ChatContact` |
| AS | `AsCredentials` | none; nearest the account capability (`userUri`, `hubSender`) |
| AS | `IssueTokens`, `IssueTokenBatch` | none |
| AS | `ReportSpam` | `Room/reportAbuse`, loosely: Air reports a user, the draft reports messages |
| AS | `CheckUsernameExists`, `CreateUsername`, `DeleteUsername`, `RefreshUsername` | none (discovery out of scope) |
| AS | `ConnectUsername` | `Consent/set` (request) then `KeyMaterial/fetch`, loosely |
| AS | `ListenUsername` | `Consent/changes` / StateChange for Consent, loosely |
| DS | `RequestGroupId` | none: the client picks room ID and group ID (`Room/create` checks 5 and 6) |
| DS | `CreateGroup`, `CreateApqGroup`, `CreateGroupV2` | `Room/create` |
| DS | `WelcomeInfo` | none: the Welcome arrives as a FanoutMessage; the tree comes in it or by `GroupInfo/fetch` (not checked against MIMI protocol-06) |
| DS | `ExternalCommitInfo` | `GroupInfo/fetch` |
| DS | `EpochSnapshot` | none |
| DS | `ConnectionGroupInfo` | `GroupInfo/fetch`, loosely |
| DS | `JoinConnectionGroup`, `ApqJoinConnectionGroup` | `Room/update` with an external Commit |
| DS | `CloseConnectionGroup`, `ApqCloseConnectionGroup` | none |
| DS | `Resync`, `ApqResync` | `Room/update` with an external Commit (rejoin) |
| DS | `SelfRemove`, `ApqSelfRemove` | `Room/update` (self-remove proposal), then `Room/unbind` |
| DS | `SendMessage` | `Room/send` |
| DS | `DeleteGroup`, `ApqDeleteGroup` | none (MIMI has no room deletion) |
| DS | `GroupOperation`, `ApqGroupOperation` | `Room/update` |
| DS | `TargetedMessage` | none |
| DS | `UpdateProfileKey` | none |
| DS | `ProvisionAttachment` | RFC 8620 blob upload + `assetUrl` |
| DS | `GetAttachmentUrl` | `assetDownloadUrl` (another provider's asset) or RFC 8620 `downloadUrl` |
| QS | `CreateUser`, `UpdateUser`, `DeleteUser` | none |
| QS | `CreateClient`, `DeleteClient` | none: a client exists once its first KeyPackage binds its signature key |
| QS | `UpdateClient` (push token, queue key) | RFC 8620 `PushSubscription/set` for the push part; none for the rest |
| QS | `PublishKeyPackages`, `PublishApqKeyPackages` | `KeyPackage/set` create |
| QS | `StageKeyPackages` | none |
| QS | `KeyPackage`, `ApqKeyPackage` | `KeyMaterial/fetch` |
| QS | `QsEncryptionKey` | none |
| QS | `Listen` | `Message/changes` + `Message/get` + EventSource StateChange (mimid's stream: `Subscribe`) |
| Relay | `MultiDeviceProvisionClient`, `MultiDeviceLinkClient` | none |

### 2.2 Every draft method

| Draft method | Air rpc |
|---|---|
| Session `urn:ietf:params:jmap:chat:mimi` capability | none as such; `VersionStatus` and `AsCredentials` carry parts |
| `KeyPackage/get` | none (the server never lists a client's KeyPackages back) |
| `KeyPackage/changes` | none (no signal that a KeyPackage was handed out) |
| `KeyPackage/set` create | `PublishKeyPackages`, `PublishApqKeyPackages`, `StageKeyPackages` |
| `KeyPackage/set` destroy | none |
| `KeyMaterial/fetch` | `KeyPackage`, `ApqKeyPackage` (one per call; the client fans out per device itself, not traced) |
| `Consent/get`, `/changes`, `/query`, `/set` | none; first contact is `ConnectUsername` + connection groups, and later KeyPackage access is by `FriendshipToken` |
| `Chat/get` with `roomId`, `roomBound` | none: the server keeps no per-user list of groups |
| `Chat/set` `privateMetadata` (F6) | none; Air uses its self-group and `group_bootstrap` echoes for sibling devices |
| `Room/create` | `CreateGroup` / `CreateApqGroup` / `CreateGroupV2` (+ `RequestGroupId`) |
| `Room/update` | `GroupOperation`, `SelfRemove`, `Resync`, `JoinConnectionGroup`, `DeleteGroup` (and `Apq*`) |
| `Room/send` | `SendMessage` |
| `Room/reportAbuse` | `ReportSpam`, loosely (no messages, no franking) |
| `Room/unbind` | none |
| `GroupInfo/fetch` | `ExternalCommitInfo` |
| `Message/get`, `/changes`, `/query` | `Listen` |
| `Message/reportAbuse` (converting party) | `ReportSpam`, loosely |
| `Message/set` (refused for room Chats) | none |
| Blob upload, `assetUrl`, `assetLifetime` | `ProvisionAttachment` (upload URL expiry, no stated object lifetime) |
| `assetDownloadUrl` | `GetAttachmentUrl` |
| EventSource / PushSubscription (base §Push) | `Listen`; push via `CreateClient` / `UpdateClient` `encrypted_push_token` |

## 3. What Air has that the draft lacks

Numbered A1 onward, in the style of F1 to F18.

### A1. Nothing bounds how long a provider keeps FanoutMessages

**Gap.** Air deletes a queue message once the client acks it
(`AckListenRequest`, `Queue::delete`); storage is bounded by what
clients have not yet read. The draft stores every FanoutMessage as a
Message in every bound Chat and never says when the server may drop
one. A JMAP account has no per-client read point, so the server cannot
know when all of an account's clients have the Message.

**Draft.** §application/mimi-fanout: "The server stores each
FanoutMessage it receives or originates for a room as one Message".
Nothing on removal.

**Proposed text.** In §capability, account-level object:

> `messageRetention` (UnsignedInt, optional):
> : The number of seconds a server keeps a Message in a Chat with a
> `roomId` after storing it. The server MAY destroy such a Message after
> that time. A client that was away longer recovers by external join
> ({{groupinfo-fetch}}, {{room-update}}). Absent if the server states
> no limit.

Per-client acks, as Air has, would need a client identity at the JMAP
layer, which the draft does not have; not proposed.

**Built** (bead mimid-e64f.19; jmap-chat-spec 43ee02c; decisions
mimid-1wgh.82, mimid-1wgh.83). mimid-server keeps Messages 7 days after
hub acceptance by default (`message_retention_secs`: seconds, at least
3600, or `"unlimited"`), advertises `messageRetention` in the mimi
capability and in `ProviderHello` (absent when unlimited), and sweeps
`follower_event` and `room_event` every 10 minutes in batches of 500.
Rows deleted by hand are handled the same way: triggers keep the
Message state, Welcome refs and Message ids right; a state from before
a deletion gets `cannotCalculateChanges` (stream: `cannotResume`). The
agent rejoins a room whose Commits it missed by external Commit and
shows one lost-messages notice; a room that refuses the rejoin is left
for a new invite. The draft counts retention "after storing it"; mimid
counts from the hub's acceptance (Mark, 2026-11-21), which for a
FanoutMessage that arrives late is earlier.

### A2. A sender cannot ask that a message not wake anyone

**Gap.** Air's `SendMessagePayload.suppress_notifications` stops push
notifications for a message the recipients need but need not be woken
for. The Air client sets it for status updates (receipts), edits and
deletions (`replaces`), and messages to the user's own devices
(`suppress_notifications` in `coreclient/src/groups/application_message.rs`).
The draft's server cannot see content, so it cannot make that choice
itself, and every message status report (draft §status) wakes every
member's phone.

**Draft.** §Room/send has no such argument. The base §Push leaves push
to RFC 8620 §7.2.

**Proposed text.** In §Room/send, request arguments:

> `silent` (Boolean, optional, default `false`):
> : When `true`, the server MAY skip push notifications ({{RFC8620,
> Section 7.2}}) for the Messages it stores for this message in its
> own accounts. The flag does not reach other providers.

The last sentence marks a MIMI gap: `SubmitMessageRequest` and
`FanoutMessage` carry no such flag, so remote recipients are woken
anyway. That is a question for #mimi, not for this draft.

**Built** (bead mimid-e64f.20; jmap-chat-spec 43ee02c). mimid-server
takes `silent` on Room/send and the stream's `Send` (`? "silent":
bool`), refuses a non-Boolean with `invalidArguments`, and otherwise
does nothing with it: mimid has no PushSubscription (decision
mimid-1wgh.12.30), and the EventSource `StateChange` goes out for a
silent message as for any other, since clients need it to sync. The
agent sends edits and retractions silent (`Agent::send_edit`,
`send_retraction`, `send_content_with`), keeps the flag in its outbox
(schema 4) so a send again after a crash is silent too, and the store's
`Store::set_silent_edits` (on by default) decides it for every front
end's edits. The agent sends no reactions or status reports, so there
is nothing else to mark.

### A3. Push goes out even to a client that is connected

**Gap.** Air pushes only to a client with no open `Listen`
(`QsClientRecord::enqueue`). RFC 8620 push and EventSource are not
linked: a server pushes to every PushSubscription whatever is open.

**Draft.** Silent; base §Push requires EventSource and recommends
PushSubscription.

**Proposed text.** None now. RFC 8620 gives an EventSource connection
no `deviceClientId`, so the server cannot tell which PushSubscription
belongs to an open connection. This belongs in a JMAP core extension,
if anywhere. (Uncertain whether any JMAP server already does this by
other means.)

### A4. No way to say "slow down" or when to retry

**Gap.** Air answers quota refusals with `RESOURCE_EXHAUSTED` and
`TokenQuotaExceededDetail {retry_after_secs}`, and per-IP limits sit in
front of everything. The draft already asks servers to rate-limit key
material and consent requests (§Security Considerations: "Servers
SHOULD rate-limit key material requests per requester"), but names no
error for it. A client that is refused cannot tell a limit from a
fault.

**Draft.** §Security Considerations, quoted above. The base draft
defines a method-level `rateLimited` only for `Peer/*` methods.

**Proposed text.** In §capability, after the account-level object:

> A server that limits how often an account calls the methods of this
> document answers a call over its limit with the method-level error
> `rateLimited` ({{JMAP-CHAT}}). It MAY add `retryAfter`
> (UnsignedInt), the number of seconds after which the call may
> succeed.

And extend the base draft's `rateLimited` registration to name this
document's methods.

**Built** (bead mimid-e64f.21; jmap-chat-spec 43ee02c, bde5330).
All of mimid-server's limits on the draft's methods: a token
bucket per account on `KeyMaterial/fetch` (the draft's SHOULD; burst 30,
then one a second, INVENTED; `[key_material_rate]`, `burst = 0` for
none), shared by both bindings and answered `rateLimited` with
`retryAfter`; and the stream's own limits, 16 outstanding requests and
4 concurrent uploads per account, answered `rateLimited` without
`retryAfter`. JMAP's `maxConcurrentRequests` and `maxConcurrentUpload`
stay RFC 8620 request-level `limit` errors. The stream's `Error` gains
`retryAfter`. The agent, on either binding, waits `retryAfter` (1 s
when absent, at most 30 s, three times) and calls again. Not built: the
draft's SHOULD to rate-limit consent requests per requester and per
provider concerns requests from other providers, not this document's
methods.

### A5. No limit on the number of clients per account

**Gap.** Air caps devices per user (`max_devices`, announced in
`VersionStatus`, refused with `DEVICE_LIMIT_REACHED`). In the draft
any number of signature keys can bind to an account
(§KeyPackage/set: "the first KeyPackage the server accepts with a given
signature key binds that signature key to the account"), and each one
is one more KeyPackage handed out per key material request.

**Proposed text.** In §capability, account-level object:

> `maxClients` (UnsignedInt, optional):
> : The maximum number of signature keys the server binds to this
> account ({{keypackage}}). The server rejects a create whose
> KeyPackage would bind one more with `overQuota`. Absent if the
> server states no limit.

**Built** (beads mimid-e64f.22, mimid-e64f.23; jmap-chat-spec 43ee02c,
bde5330). mimid-server advertises `maxClients` = 10 (INVENTED;
`KeyPackages::with_max_clients`) in the mimi capability and
`ProviderHello`, keeps a Client record per bound signature key
(migration 0015: the key, and a change log for `Client/changes`), and
serves `Client/get`, `Client/changes` and `Client/set` (destroy only;
create and update `forbidden`); the stream has `ListClients`,
`DestroyClient` and `Changed` `Client`. A KeyPackage/set create with a
new key past `maxClients` is `overQuota`. An external Commit's
UpdatePath key (now read by `MLSMessage::external_commit_signature_key`)
bound to another account is `invalidArguments`, a new one past
`maxClients` is method-level `forbidden`, both before anything is
submitted, and once the hub accepts it the key is bound. Destroying a
record deletes its KeyPackages and unbinds the key, so Room/create
refuses it. The agent lists the account's devices and forgets a lost
one (`Agent::devices`, `Agent::forget_device`, `Store::devices`,
`Store::forget_device`), removing its leaves by Commit from the rooms
they share; the IRC service has `devices` and `forget-device <id>`.
The JMAP Chat front end has no notion of devices.

### Nothing proposed (A6 to A12)

Recorded so the list is complete: Air has a mechanism, and nothing in
the draft or in mimid changes because of it.

| | Finding | Air's mechanism, and why nothing changes |
|---|---|---|
| A6 | The caught-up point is implicit | Air sends `QueueEmpty` after the backlog, so a client can process a batch and show "up to date". JMAP has this already: `Message/changes` with `hasMoreChanges: false`. mimid's stream has the `Subscribe` `Ack`. |
| A7 | One listener per client, and what ends a listen | Air's `Listen` defines its endings: half-close then `OK` means acks are durable; a newer listener evicts the older with `ABORTED`; shutdown is `UNAVAILABLE`. The draft's push is EventSource, where the client keeps its position and nothing is acked, so there is nothing to make durable. No change for JMAP. Worth copying in a gRPC binding (§6). |
| A8 | Client software version policy | Air refuses expired client versions and warns in advance (`VersionStatus.expires_at`). The draft versions the protocol by capability URN only. No change. Which client builds a provider accepts is product policy, and a client-reported version is not a security check. |
| A9 | Metadata the provider sees | Air's DS stores per member only a sealed queue reference and a domain; the QS knows queues by random ids unrelated to the AS user; group state is encrypted at rest under a key only members hold; logs use per-process pseudonyms (`backend/src/pseudonym.rs`). In the draft the provider knows the account's `userUri`, every room each account is in, and stores GroupInfo in the clear as hub. **Draft.** §Security Considerations already states what a provider sees. No change. MIMI's hub must answer other providers' GroupInfo requests and enforce room policy on user URIs without a member present, so Air's EAR-key and sealed-reference design does not carry over to a MIMI hub. Worth a sentence in a later version. |
| A10 | Ephemeral data between a user's devices | Air's `Listen` relays a small encrypted state blob between a user's listening devices (`ReportClientStateListenRequest`, `SiblingClientState`) and has an unused ephemeral payload event (`QueueEventPayload`). The draft has `privateMetadata` (F6) for state that must persist, and nothing ephemeral for MLS rooms. No change. Air does not use the ephemeral event yet, and typing indicators in an encrypted room are a MIMI content question. |
| A11 | Registration gating, usernames, device linking, Privacy Pass | Air has invitation codes, a push-delivered admission challenge, hashed usernames with expiry, a device-linking relay, and Privacy Pass tokens that pay for username operations and connection package fetches. No change. Account creation and discovery are out of scope for the draft, and a new device joins by external commit with the account's credentials. Privacy Pass as a rate limit for `KeyMaterial/fetch` from other providers would be a MIMI protocol matter. |
| A12 | Group deletion and targeted messages | Air can close a group with a tombstone (`DeleteGroup`, `GROUP_CLOSED`) and send to one member (`TargetedMessage`, a stopgap "until we implement MLS's targeted message feature"). No change. MIMI has neither; both would start in MIMI protocol or room policy, not here. |

## 4. What the draft has that Air lacks

- MIMI room IDs and hub routing: rooms named by URI, hub-and-follower
  relay, the hub as `hubSender` external sender. Air's
  `QualifiedGroupId` is a UUID and a domain; there is no hub/follower
  split, the group's own server is the DS.
- Consent records with request, grant and revoke, per room or for any
  room (§consent). Air's nearest is connection groups and the
  `FriendshipToken`.
- `KeyMaterial/fetch` routed through the hub so the hub can forward the
  Welcome; per-client status codes (`userStatus`, `clientStatus`).
- Franking and abuse reports of specific messages, verified by the hub
  (`Room/reportAbuse`, `Message/reportAbuse`, unverified messages).
- A server-kept history the client can re-read: `Message/get`,
  `/query` with anchors (F12), `/changes` from any state the server
  gave. Air's queue forgets on ack.
- Account-wide Chat list with binding state (`roomId`, `roomBound`)
  and `Room/unbind`.
- Hub answers passed through unchanged (`response` fields) and decoded
  (`responseCode`, `currentEpoch`, `invalidProposals`).
- Retry rules for lost answers (F11) and `messageIds` of the stored
  copy (F18).
- Proxy download of another provider's asset (`assetDownloadUrl`).
- The conversion rules (§message-ids to §moderation) for parties that
  decrypt; Air has no gateway role.
- Standard JMAP machinery: one Session, batching, back-references,
  `/changes` for every type.

## 5. How MIMI-specific Air's API is

Mostly not. Air uses three MIMI pieces, all inside opaque bytes or the
client:

- **mimi-content.** The client uses Phoenix's `mimi_content` crate for
  message bodies and `application/mimi-message-status` for receipts
  (`coreclient/src/chats/messages/content/media_type.rs`). The server
  never sees content.
- **Room policy.** `RoomState` is a TLS-encoded state from Phoenix's
  `mimi-room-policy` crate, carried in `CreateGroup`, `WelcomeInfo`,
  `ExternalCommitInfo` and `EpochSnapshot`, and checked by the DS on
  adds and removes (`room_state_change_role` in
  `backend/src/ds/group_operation.rs`). Whether that crate tracks
  draft-ietf-mimi-room-policy-04 was not checked; it is pinned to
  rev 603f3e0 of phnx-im/mimi-room-policy.
- **MLS.** RFC 9420 throughout, via OpenMLS and `mls-assist`, plus the
  APQ pair and virtual clients, both Phoenix-specific.

Not in the API: MIMI room URIs, user URIs (identities are
`UserId {uuid, domain}`), hub and follower roles, MIMI protocol
messages (`KeyMaterialRequest`, `UpdateRequest`, `SubmitMessageRequest`,
`FanoutMessage`, `GroupInfoRequest`), consent, franking, and MIMI's
provider-to-provider transport; Air federates with its own
`QsToQsMessage`. The DS's public-state tracking and the room-policy
check are close to what a MIMI hub does, so a MIMI hub could sit behind
Air's DS, but the API would change in every rpc that names a group.

## 6. A mimid gRPC binding

A third layer over the core functions of binary-live-stream.md §5.10,
next to JMAP and the CBOR stream, with the same behaviour. Names are
INVENTED, NOT FROM SPEC.

Package `mimid.client.v1`. Bearer token in the `authorization`
metadata, checked by the same code as the JMAP `Account` extractor and
again on each request, as the stream does (§5.3). MLS and MIMI
structures as `bytes`, never base64url.

| Service | Rpc | Mirrors |
|---|---|---|
| `ProviderService` | `GetProvider` | Session mimi capability (`userUri`, `roomIdPrefix`, `hubSender`, `cipherSuites`, limits, `assetUrl`) |
| `KeyPackageService` | `ListKeyPackages`, `PublishKeyPackage`, `DestroyKeyPackage` | `KeyPackage/get`, `/set` create, destroy |
| `KeyPackageService` | `FetchKeyMaterial` | `KeyMaterial/fetch` |
| `ConsentService` | `ListConsent`, `CreateConsent`, `UpdateConsent`, `DestroyConsent` | `Consent/get`, `/set` |
| `RoomService` | `ListChats`, `SetChatAccepted` | `Chat/get`, `Chat/set` `privateMetadata` |
| `RoomService` | `CreateRoom`, `UpdateRoom`, `Send`, `ReportAbuse`, `Unbind`, `FetchGroupInfo` | `Room/*`, `GroupInfo/fetch` |
| `AssetService` | `Upload` (client stream), `FetchAsset` (server stream) | blob upload, `assetDownloadUrl` |
| `ListenService` | `Listen` (bidi) | `Message/changes` + `/get`, StateChange |

`Listen`: the client's first message is `Init {since}` (a Message state)
or `Init {after: map chatId to messageId}` after `cannotResume`, as the
stream's `Subscribe` (§5.5). The server sends `ProviderStatus` first
(limits, as Air's `VersionStatus`), then `Deliver {messageId, chatId,
body}` in storage order, then `Position {state}` and `CaughtUp` after
the backlog and after each later burst, and `Changed {types}` for Chat,
KeyPackage and Consent. The client keeps its position; there are no
acks, because the provider keeps Messages (until A1's retention, if
taken). `KeepAlive` in both directions.

Worth copying from Air:

- Hub refusals as a `oneof outcome` in the response (`Accepted`,
  `NotAllowed`, `EpochTooOld {current_epoch}`, ...), as
  `RegisterUserResponse` does, and gRPC status only for provider
  errors. This is a third answer to the question F-findings raised for
  the stream (JMAP: `responseCode`; stream: `Error`).
- Provider errors as a status code plus a typed detail message
  carrying the draft's error name and its fields (`StatusDetails`
  pattern), with `retry_after_secs` for `rateLimited` (A4).
- `Listen`'s endings: half-close then `OK`; a newer `Listen` for the
  same token evicts the older with `ABORTED`; shutdown is
  `UNAVAILABLE`.
- `CaughtUp` after each burst, like `QueueEmpty`.
- Versioned package, `reserved` field numbers, a method-alias layer for
  renames.
- Status first on `Listen`, like `VersionStatus`.

Not worth copying: per-request signatures (the draft leaves
authentication to the transport), deleting on ack (positions are
client-held), and KeyPackage fetch by bearer secret.

## 7. Uncertainties

- Behaviour read from code, not from documentation: push only without a
  listener, the meaning of collision tags, the ignored
  `QueueEventPayload`.
- Whether the Air client fetches one KeyPackage per call or per device
  was not traced through `coreclient`.
- Whether the queue has any expiry for unacked messages was not
  checked.
- Phoenix's `mimi-room-policy` and `mimi_content` crates were not
  compared with the current MIMI drafts.
- How the joiner gets the ratchet tree with a Welcome under MIMI
  protocol-06 (row `WelcomeInfo` in §2.1) was not checked against that
  draft.
