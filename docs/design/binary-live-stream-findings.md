# Findings: gaps in draft-atwood-jmap-chat-mimi-00 found by a second binding

The log of epic mimid-e64f (docs/design/binary-live-stream.md). Each
entry is one gap in draft-atwood-jmap-chat-mimi-00 (jmap-chat-spec
125749a), found while writing the same operations a second time for
the CBOR live stream:

- **Gap:** what is missing or ambiguous.
- **Draft:** where, with section and quote. "Draft" alone is
  draft-atwood-jmap-chat-mimi-00; "base draft" is draft-atwood-jmap-chat-00.
- **JMAP binding:** how mimid-server handles it today.
- **Stream:** how the live stream handles it.
- **Proposed text:** for the draft. Nothing here has gone to
  jmap-chat-spec; each change needs Mark's OK.

File references are to the live-stream branch.

## F1. A Message state is not a point in what was delivered

**Gap.** The draft says when a FanoutMessage is stored and in which
Chats, but not what `Message/changes` promises when a Chat's set of
Messages grows "backwards": a new membership can make Messages visible
that were stored before the client's state. Then no state string names
"everything up to this Message", and a client cannot keep one position
per Message it has handled.

**Draft.** §application/mimi-fanout: "The server stores each
FanoutMessage it receives or originates for a room as one Message, in
the order received, in every Chat of a local account bound to that
room". §Room/update: "When the hub accepts an external Commit from an
account that has no Chat bound to the room, the server creates a Chat
bound to it, or binds the account's unbound Chat with that `roomId`
again." The base draft §Message/changes says only "Standard JMAP
`/changes`." Nothing says from which stored Message a new or re-bound
Chat starts, or whether Messages stored between the hub's acceptance
and the binding belong to it.

**JMAP binding.** mimid keeps one follower log for the provider and
derives each account's Messages from its memberships
(crates/mimid-server/src/store/jmap.rs:302-316). A join relayed for the
account starts its membership at the next log `seq` before the hub
answers (crates/mimid-server/src/store/follower_log.rs:221-262), so
events the fanout stores in that window become visible only when the
membership row is written, with `seq` values below the account's
current high-water mark. The Message state is therefore `s.m`, the
highest visible `seq` and the highest membership id
(crates/mimid-server/src/jmap/projection.rs:26-31), and
`Message/changes` from `s.m` returns first the Messages that a
membership newer than `m` reveals, then those above `s`
(crates/mimid-server/src/store/jmap.rs:715-772). States are only
comparable as pairs; between two Messages of one `/changes` answer
there is no state at all.

**Stream.** A `Deliver` cannot carry its own position. The provider
sends a `Position` (or the `Subscribe` `Ack`) after a run of
`Deliver`s, with the state `Message/changes` itself returned for that
run, and the agent keeps the ids handled since the last position, as
it does on JMAP (docs/design/binary-live-stream.md §5.5). Mark's answer
that a position is the JMAP Message state string (§9 question 4) holds,
but only because positions are sparse: the stream could not resume
between two `Deliver`s without the `handled` list.

**Proposed text.** In §application/mimi-fanout, after the first
paragraph:

> A Chat that is created or bound again holds the Messages the server
> stores for its room from then on. A server MAY also place in it
> Messages it stored for the room earlier, for example those stored
> while the hub was still answering the request that bound it. Such
> Messages appear in `Message/changes` as created, even from a state
> given after they were stored. A client therefore cannot treat a
> Message state as "every Message up to some point"; it can only resume
> from a state the server gave it.

And, as a question for the base draft: whether `/changes` for chat
types promises anything about the order of `created`, which RFC 8620
§5.2 does not (see F2).

## F2. Nothing promises the order in which a client sees a room's Messages

**Gap.** An MLS client must process a room's handshake messages in the
hub's order. The draft has the server store them "in the order
received", but no method returns them in that order: RFC 8620 lets
`/get` answer in any order and lets `/changes` page newest first.

**Draft.** §application/mimi-fanout: "in the order received". RFC 8620
§5.1: "The results MAY be in a different order to the "ids" in the
request arguments." RFC 8620 §5.2: "it will provide a better user
experience to return the more recent changes first". Base draft
§Message IDs: "ULIDs are lexicographically ordered by time" (at
millisecond resolution, so two Messages stored in one millisecond have
no order unless the server makes the random part monotonic).

**JMAP binding.** mimid answers `Message/get` in log order
(`ORDER BY e.seq`, crates/mimid-server/src/store/jmap.rs:622-672) and mints Message ids that
increase with the log `seq` even when the clock goes back (decision
mimid-1wgh.12.31; crates/mimid-server/src/store/follower_log.rs:454-475).
The agent handles Messages in the order `Message/get` lists them
(crates/mimid-agent-core/src/agent.rs:2529-2531), so it relies on mimid's
choice, not on the draft.

**Stream.** `Deliver`s come in the order `Message/get` lists them,
which the stream makes part of its contract: a `Deliver` is never sent
before one stored earlier for the same room (§5.5).

**Proposed text.** In §application/mimi-fanout:

> The server assigns Message `id`s in the order in which it stores the
> Messages of a Chat, so that sorting a Chat's Messages by `id` gives
> that order. A client processes the handshake messages of a room in
> that order. A server MAY also return Messages in that order from
> `Message/get` and `Message/changes`.

## F3. Room/send drops the hub's frank

**Gap.** The hub's SubmitMessageResponse carries the frank of an
accepted message, which the sender's own clients need to report or
verify it later. The method response does not carry it, so the sending
client gets it only by reading back its own stored Message.

**Draft.** §Room/send lists the response arguments `accountId`,
`responseCode`, `acceptedAt` and `currentEpoch`, and then: "the server
MUST store ... a Message ... with ... `frank` copied from the response
when present".

**JMAP binding.** crates/mimid-server/src/jmap/methods/room_send.rs:96-109
writes `responseCode` and `acceptedAt` or `currentEpoch`; the frank in
`SubmitResult::Accepted` is dropped.

**Stream.** The `Send` `Ack` carries `acceptedAt` and, when the hub
gave one, `frank` (Mark's answer, §9 question 3).

**Proposed text.** In §Room/send, after `acceptedAt`:

> `frank` (String, optional):
> : When `responseCode` is `"accepted"` and the hub franked the
> message: the hub's Frank ({{MIMI-PROTOCOL, Section 5.4}}).

## F4. A client cannot tell whether its Chat is still bound

**Gap.** Binding decides whether the server stores new FanoutMessages
for the account, whether `Room/send` and `KeyMaterial/fetch` work, and
whether a non-external `Room/update` is accepted. The draft has no
property for it, so a client learns that it is unbound only from an
`invalidArguments`.

**Draft.** §Chat.roomId: "An unbound Chat keeps its `roomId` and its
Messages. The server stores no further FanoutMessage in it, and
`KeyMaterial/fetch` and `Room/send` treat it as if no Chat in the
account had that `roomId`".

**JMAP binding.** "Unbinding is invisible on the Chat"
(crates/mimid-server/src/jmap/projection.rs:13). The store knows
(`ChatRow::bound`, crates/mimid-server/src/store/jmap.rs:329).

**Stream.** `ListChats` gives `bound` for each Chat. The agent does not
use it yet.

**Proposed text.** In §Chat.roomId, after `roomId`:

> `roomBound` (Boolean, server-set, optional):
> : `true` while the Chat is bound to its room, `false` once it is
> unbound. Present exactly when `roomId` is.

## F5. KeyMaterial/fetch takes the KeyMaterialResponse apart

**Gap.** Every other answer from a hub that the client must reason
about comes as exact bytes or as named fields of one structure. The
KeyMaterialResponse is split into JSON fields, its `protocol` is lost,
and a client that wants the structure must rebuild and re-encode it.
That goes against the draft's own rule on exact octets.

**Draft.** §KeyMaterial/fetch: "The response has the following
arguments, decoded from the KeyMaterialResponse: ... `clients`
(Object\[]): One object per ClientKeyMaterial". §Conventions: "Servers
MUST NOT re-encode these octets, because clients sign some of them and
verify signatures over others."

**JMAP binding.** crates/mimid-server/src/jmap/methods/key_material.rs:213-222
writes the fields; the agent rebuilds a `KeyMaterialResponse` with
`Protocol::Mls10` assumed (crates/mimid-agent-core/src/client.rs:470-554).

**Stream.** The `FetchKeyMaterial` `Ack` carries the KeyMaterialResponse
as received (`response`, bstr), as `GroupInfo/fetch` already does in the
draft.

**Proposed text.** In §KeyMaterial/fetch, after `clients`:

> `response` (String):
> : The whole KeyMaterialResponse, unchanged.

## F6. The user's devices have nowhere to agree that a room was accepted

**Gap.** A Welcome puts the user in a room on every device at once. A
client that asks the user before showing a room has no place in the
draft to record the answer for the user's other devices.

**Draft.** §application/mimi-fanout stores the Welcome "only in the
account owning a KeyPackageRef named in the Welcome", and §Chat.roomId
leaves the Chat's other fields as the base draft has them. Nothing
covers a per-user, per-room flag.

**JMAP binding.** mimid uses the JMAP metadata extension's
`privateMetadata` on the Chat, under its own namespace
(decision mimid-1wgh.63; crates/mimid-agent-core/src/client.rs:431-447),
which a server without draft-ietf-jmap-metadata cannot hold.

**Stream.** `SetChatAccepted` and `accepted` in `ListChats`: a mimid
message, INVENTED, NOT FROM SPEC.

**Proposed text.** In §Chat.roomId:

> A client MAY record per-user state about the room, such as whether
> the user accepted it, in the Chat's `privateMetadata`
> ({{JMAP-METADATA}}), so that the user's other clients see it.

## F7. Attachment upload and fetch have no error vocabulary

**Gap.** Every method of the draft says which error a client gets.
Uploading an attachment and fetching one through `assetDownloadUrl`
are plain HTTP, and the draft names no status or problem type for any
refusal, so a client cannot tell "not a member of that room" from "no
such asset" from "the other provider failed".

**Draft.** §Account-Level Capability Object, `assetDownloadUrl`: "The
server MUST refuse a `roomId` that no Chat of the account has." It does
not say how. Uploads follow RFC 8620 §6.1, whose errors are about size
and quota, not about MIMI.

**JMAP binding.** mimid answers with its own RFC 9457 problem types
(`no-such-room` 404, `no-such-asset` 404, `asset-refused` 403,
`asset-provider-failed` and `peer-provider-failed` 502;
crates/mimid-server/src/jmap/blobs.rs:456-580).

**Stream.** The same refusals, each with a stream code chosen for its
status (`notFound`, `forbidden`, `serverUnavailable`, `serverFail`;
`code_of`, blobs.rs:525). Writing the stream showed that the HTTP route
was the only place the reasons lived; the two now come from one
function (`fetch_asset_core`).

**Proposed text.** In §Account-Level Capability Object, after
`assetDownloadUrl`:

> The server answers a `roomId` that no Chat of the account has, and a
> `url` it cannot find, with status 404; a `url` the room's hub or the
> asset's provider refuses with 403; and a provider that cannot be
> reached with 502. It MAY add an RFC 9457 problem body.

## F8. Room/reportAbuse's "refused" says nothing

**Gap.** "refused" covers every refusal but two, with no field for the
reason, so a client cannot tell a report the hub found malformed from
one it will never take.

**Draft.** §Room/reportAbuse: "`"refused"` for any other refusal. A hub
that reports a refusal reason the server cannot tell apart from others
is answered as `"refused"`."

**JMAP binding.** mimid adds `status`, the other provider's HTTP status
(INVENTED, decision mimid-1wgh.58;
crates/mimid-server/src/jmap/methods/room_report_abuse.rs:88-93), and
the agent requires it (crates/mimid-agent-core/src/client.rs:746-751),
so a strict client of the draft alone would fail against a server
that leaves it out, and the agent against one that follows the draft.

**Stream.** `Error` `refused` with `status` (crates/mimid-server/src/jmap/live.rs:750).

**Proposed text.** In §Room/reportAbuse, after `responseCode`:

> `status` (UnsignedInt, optional):
> : When `responseCode` is `"refused"` and the hub is another provider:
> the HTTP status of its answer ({{MIMI-PROTOCOL, Section 5.9}}).

## F9. KeyPackage changes cannot be followed

**Gap.** The draft tells a client to watch the KeyPackage state to learn
that a KeyPackage was handed out, and registers KeyPackage for state
change, but defines no `KeyPackage/changes`, so the client must read
every record again and compare.

**Draft.** §Handing Out KeyPackages: "A destroyed record appears in a
new state for the KeyPackage type, so a client that receives the
`StateChange` can replenish its KeyPackages." §KeyPackages defines only
`KeyPackage/get` and `KeyPackage/set`. §IANA: "Can Use for State
Change: Yes".

**JMAP binding.** No `KeyPackage/changes`
(crates/mimid-server/src/jmap/methods/key_package.rs:29-31); the state
is a digest of the stored KeyPackageRefs.

**Stream.** `Changed` `KeyPackage`, then `ListKeyPackages`, the same
read-all-and-compare. Neither binding can say which client's KeyPackage
went.

**Proposed text.** In §KeyPackages:

> ## KeyPackage/changes
>
> Standard JMAP `/changes` ({{RFC8620, Section 5.2}}). A KeyPackage
> handed out appears in `destroyed`.

## F10. Nothing bounds the size of the MLS objects a client sends

**Gap.** A Commit with a ratchet tree, a Welcome, or the `groupInfo` and
`ratchetTree` of `Room/create` grow with the group. The draft gives no
limit and no other path for a large one, so the only bound is the JMAP
request size after base64url, which no client can see per argument.

**Draft.** §Conventions: "Every byte-string property ... is the
unpadded base64url encoding". §Room/create takes `groupInfo` and
`ratchetTree` in one call; §Room/update takes the whole `request`. No
section mentions a size.

**JMAP binding.** `maxSizeRequest` is sized so that a 4 MiB MLS object
fits after base64url (crates/mimid-server/src/jmap/api.rs:59), the
largest body mimid takes on the protocol routes
(crates/mimid-server/src/http.rs:90).

**Stream.** `maxRequestBytes`, stated in `ProviderHello`, 4 MiB + 64 KiB
of raw bytes (decision mimid-1wgh.78). The stream had to pick the
number again, and got a different effective limit for the same object
(raw, not base64url): an object a little over 3 MiB fits the stream
but not one JMAP request with another argument beside it.

**Proposed text.** In §capability, Account-Level Capability Object:

> `maxMlsObjectSize` (UnsignedInt, optional):
> : The largest MLS or MIMI structure, in octets before base64url
> encoding, that the server accepts in any argument of this document's
> methods. A client that would send a larger one MAY choose a ratchet
> tree option ({{?MLS-RATCHET-TREE-OPTIONS}}) that keeps the tree out
> of the message.

## F11. A lost answer to Room/send or Room/update cannot be retried safely

**Gap.** If the connection drops after the hub accepted a message or
Commit but before the client got the answer, the client cannot ask
what happened. Sending again submits the same MLSMessage twice; for a
Commit it may meet `wrongEpoch` against its own Commit.

**Draft.** §Room/send: "returns `serverUnavailable` if the hub cannot be
reached". §application/mimi-fanout: "The server MUST NOT store a
FanoutMessage whose `message` is byte-identical to the `message` of a
FanoutMessage already stored in the Chat", which protects the store,
not the client's view of the outcome.

**JMAP binding.** No idempotency: each call relays again. The agent
treats an HTTP error as a failed send.

**Stream.** The same: a dropped connection loses the outstanding
`Ack`s. The client can see its own message come back as a `Deliver`,
which tells it the hub accepted it, but only after the fact and only
because the server stores the owner's own messages.

**Proposed text.** In §Room/send:

> A client that did not receive the response MAY submit the same
> `message` again. The server SHOULD answer a `message` byte-identical
> to one the hub already accepted for the room with the earlier
> response, without submitting it again.

and the same for `request` in §Room/update.

## F12. Recovering from cannotCalculateChanges is undefined for an MLS client

**Gap.** The base draft tells a client that cannot get changes to
fall back to `/get`, which for Messages means every Message. An MLS
client cannot process old handshake messages again, and has no way to
ask for "the Messages after the last one I handled".

**Draft.** Base draft §Push: "Clients SHOULD call the corresponding
`/changes` method upon receipt. On `cannotCalculateChanges`, fall back
to `/get`." The mimi draft adds nothing for `application/mimi-fanout`.

**JMAP binding.** mimid answers `cannotCalculateChanges` only for a state
it never gave (crates/mimid-server/src/jmap/projection.rs, `message_changes_since`).
The agent then reads every Message (crates/mimid-agent-core/src/client.rs:616-620)
and hands each to MLS again, which yields Problems for the old ones.

**Stream.** `cannotResume`, then `Subscribe` without `since`: the same
replay of everything (note §5.5).

**Proposed text.** In §application/mimi-fanout:

> A client that cannot calculate Message changes from its state MAY use
> `Message/query` on each Chat, sorted by `id`, with `anchor` set to
> the last Message it processed, to fetch only the later Messages
> ({{message-order}}).

(This needs F2's order and a `Message/query` that accepts an id
anchor, which RFC 8620 §5.5 provides.)

## Push semantics (F13 to F17)

Found by the EventSource work of bead mimid-ak29 (the agent following
the provider's EventSource, crates/mimid-agent-core/src/push.rs and
crates/mimid-agent/src/push.rs) and recorded here at the coordinator's
request. Each is about what draft-atwood-jmap-chat-mimi-00 promises a
client that waits for `StateChange` events (RFC 8620 §7.1, §7.3; base
draft §Push Notifications) instead of polling. The stream answers all
five by construction, which is itself the finding: a binding that
pushes the Messages has to decide each of these, and JMAP leaves them
open.

### F13. What moves the Message and Chat states

**Gap.** The draft never says that each FanoutMessage stored for the
account moves the account's Message state: a Welcome, the owner's own
handshake echoed by `Room/update`, the owner's own message stored by
`Room/send`, a Commit that removes the owner's clients. Nor that a
Welcome or external Commit that creates or binds a Chat again moves the
Chat state.

**Draft.** §application/mimi-fanout: "The server stores each
FanoutMessage it receives or originates for a room as one Message ...
if that account has no Chat bound to the room, the server first binds
the account's unbound Chat for the room again or, if it has none,
creates a Chat bound to the room." §Room/update and §Room/send: "the
server MUST store, in every Chat of a local account bound to the room,
a Message". None of these mention state.

**JMAP binding.** mimid moves both: every stored event is published on
the change bus (crates/mimid-server/src/jmap/bus.rs, `Change::RoomEvent`,
`Change::Membership`), and the Chat state includes the membership
counter (crates/mimid-server/src/jmap/projection.rs:26-35).

**Stream.** Every stored Message reaches the client as a `Deliver`;
a binding change reaches it as `Changed` `Chat`. The stream had to name
both because it pushes the objects, not states.

**Proposed text.** In §application/mimi-fanout:

> Storing a Message changes the account's Message state, and creating
> or binding a Chat again changes its Chat state ({{RFC8620, Section
> 5.1}}), so a client that watches both types in `StateChange` events
> learns of every FanoutMessage stored for it, its own included.

### F14. Nothing on resuming after a lost push connection

**Gap.** A client whose EventSource connection drops misses the events
sent meanwhile. The draft gives no guidance: neither whether the server
sends event ids that a client returns in `Last-Event-ID`, nor that a
client calls `/changes` from its saved states after reconnecting.

**Draft.** The draft says nothing on push beyond the two sentences of
§Handing Out KeyPackages and §Consent/changes. The base draft §Push
Notifications requires EventSource (RFC 8620 §7.3), where the event id
is a SHOULD and resuming is left to the client.

**JMAP binding.** mimid-server sends no event id; the agent sends
`Last-Event-ID` when a server set one, syncs each time a stream opens,
and keeps a fallback poll (bead mimid-ak29).

**Stream.** Resume is part of the protocol: `Subscribe` carries the
saved state and the provider replays from it (note §5.5). Nothing is
lost because the provider reads the store, not a buffer.

**Proposed text.** In §mls-messages:

> Push events carry no Messages. A client that reconnects its event
> source, or starts, calls `Message/changes` from its saved Message
> state before it relies on events again. A server MAY set an event id
> on each `state` event; a client that has one sends it in
> `Last-Event-ID`.

### F15. Only KeyPackage and Consent are tied to StateChange

**Gap.** The draft names `StateChange` for KeyPackage (a destroyed or
handed-out record) and for Consent (a request received), and nothing
else. Chat changes from binding and unbinding (§Chat.roomId,
§Room/unbind) are not tied to any event.

**Draft.** §Handing Out KeyPackages: "A destroyed record appears in a
new state for the KeyPackage type, so a client that receives the
`StateChange` can replenish its KeyPackages." §Consent/changes: "A
client that watches the Consent type in `StateChange` events learns of
requests the owner receives." §Chat.roomId says when a Chat is bound or
unbound, but not that its state changes.

**JMAP binding.** Unbinding is invisible on the Chat
(crates/mimid-server/src/jmap/projection.rs:13), so it moves no Chat
state; binding moves it through the membership counter.

**Stream.** `Changed` names `Chat`, `KeyPackage` and `Consent` alike,
computed as the EventSource computes its `StateChange`
(crates/mimid-server/src/jmap/live.rs, `notices`). An unbinding is not
visible there either (see F4).

**Proposed text.** In §Chat.roomId, after the paragraph on binding:

> Binding and unbinding a Chat change its Chat state ({{RFC8620,
> Section 5.1}}).

(With F4's `roomBound`, unbinding becomes a property change.)

### F16. No promise that a pushed change is visible

**Gap.** Nothing says that when a client receives a `StateChange` for
Message, `Message/changes` from its old state already returns the new
Message. A server that announces before it commits makes the client
see "no change" and wait for the next event.

**Draft.** Silent. RFC 8620 §7.1 defines the event but not its timing
against `/changes`.

**JMAP binding.** mimid-server announces a stored event only after the
transaction that stores it commits, and the EventSource subscribes to
the change bus before it answers (server fix 2ad3188, bead mimid-ak29),
so no change falls between.

**Stream.** The same rule is built in: a `Deliver` is sent from the
store after the change (crates/mimid-server/src/jmap/live.rs, `follow`),
and the connection subscribes to the bus before its replay.

**Proposed text.** In §application/mimi-fanout:

> The server sends a `StateChange` for a stored Message only once
> `Message/changes` returns it.

### F17. Which types a pure MLS client watches

**Gap.** An MLS client (one that never converts content) needs Message
(new FanoutMessages, Welcomes), Chat (binding), Consent (requests to
answer) and KeyPackage (to top up). The draft does not list them, so
each client finds out by reading every section.

**Draft.** The only mentions are the two in F15. The base draft §Push
Notifications lists the base types and "any type defined by a companion
capability".

**JMAP binding.** The agent asks for `types=Message,Chat,Consent` and
tops KeyPackages up on its own schedule (bead mimid-ak29).

**Stream.** One `Subscribe` covers all of it: Messages as `Deliver`s,
and `Changed` for Chat, KeyPackage and Consent.

**Proposed text.** In §capability, after the account-level object:

> A client of this capability that does not convert content needs
> `StateChange` events for the Message, Chat, Consent and KeyPackage
> types; it MAY ask for only these in the event source's `types`.

## F18. A client cannot tell its own stored message from the answer

**Gap.** The server stores the owner's own message and handshake in the
owner's Chat, so every one of the owner's clients reads it back,
including the client that sent it. Neither `Room/send` nor
`Room/update` returns the id of the Message it stored, so the sending
client can recognise its own copy only by comparing content.

**Draft.** §Room/send: "When the hub accepts the message, the server
MUST store, in every Chat of a local account bound to the room, a
Message ... The hub does not forward the owner's own message to the
owner's provider ... so this is how the owner's clients and the room's
other local participants receive it." The response arguments are
`accountId`, `responseCode`, `acceptedAt`, `currentEpoch`. §Room/update
is the same.

**JMAP binding.** The agent keeps a digest of every MLSMessage it sent
and skips stored Messages that carry one
(crates/mimid-agent-core/src/client.rs, `Jmap::is_own`), and must keep
those digests across restarts (`State::sent`).

**Stream.** The same digests (crates/mimid-agent-core/src/provider.rs,
`Sent`); the `Send` `Ack` has no `messageId` either, since the stored
copy is made after the hub answers and the bindings share that code.

**Proposed text.** In §Room/send and §Room/update, among the response
arguments:

> `messageIds` (Id\[], optional):
> : The ids of the Messages the server stored in this account for the
> accepted message, so that the sending client can recognise them when
> it reads its Messages.
