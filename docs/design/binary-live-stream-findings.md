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
