# Follower catch-up: recovering fanout a provider missed

Design note, 2026-11-22. Bead mimid-1wgh.37.104. Reviewed by Mark the
same day: the four questions of §12 are answered and are closed decision
beads mimid-1wgh.104 to .107, with §7 promoted to bead
mimid-1wgh.37.105. Implementation is beads mimid-1wgh.37.104.1 to .5.

Mark arrived at this from the opposite direction: meshIRCd's S2S uses a
vector clock to reconcile what a peer missed (its `SyncRequest`), and
MIMI has no equivalent at all. The conclusion of that comparison is in
§3: MIMI wants a scalar sequence, not a vector clock, because it has one
writer per room. The question it exposed is real even so, and this note
is about that question.

Values marked INVENTED are mine. Nothing here is implemented; nothing
has been proposed to the working group.

## Sources

| Source | Version read |
|---|---|
| draft-ietf-mimi-protocol | -07, the text in `~/PROJECT/IETF/specs/draft-ietf-mimi-protocol-07.txt` |
| draft-ietf-mimi-room-policy | -04 |
| RFC 9420 (MLS) | for the epoch chain argument of §2 |
| mimid | main at `677d0d06`: `crates/mimid-server/src/peer.rs`, `follower/notify.rs`, `directory.rs`, `http.rs` |
| meshIRCd | `/data/PROJECT/meshIRCd` `s2s.go`, for the comparison only |

## 1. The gap

Application and handshake messages are submitted to a room's hub, which
stamps an acceptance time and fans out to every follower provider
(`POST /notify/{roomId}`, protocol-07 §5.5).

Searching protocol-07 for `catch-up`, `missed`, `resync`, `backlog` and
`fell behind` returns **no hits**. `retry` appears twice, neither time
about this. So:

- A follower provider that is unreachable during fanout has no specified
  way to learn what it missed, and no way to ask for it.
- `FanoutMessage` carries the `MLSMessage`, an optional `Frank`, a
  `RatchetTreeOption` and proposals. It carries **nothing identifying its
  position** in the room's stream.
- The only ordering handle is `accepted_timestamp`, milliseconds since
  the epoch. That is not an ordering key: two messages can share a
  millisecond, and nothing promises the value increases if the hub's
  clock is adjusted.

mimid covers this today with a push-only delivery queue on the hub
(`docs/operating.md`: "the delivery queue to peers"). That helps while
the hub is healthy and retrying. It does not help when the hub gives up,
when the hub's queue is lost, or when the follower was down longer than
the hub was willing to retry.

The consequence is worse than a late message. The ciphertext of an MLS
application message exists only in that fanout: the hub cannot
regenerate it, and no other party can mint it. A follower that misses it
and cannot ask for it has lost it for its users permanently — and under
protocol-07 it does not even know that it should tell them.

## 2. Why the room itself cannot be eventually consistent

Worth stating once, because it bounds every design below.

RFC 9420 advances a group by exactly one Commit per epoch, and the key
schedule is derived from that chain. Two Commits applied at epoch N give
two groups with different secrets and **no merge function exists**. A
vector clock would let two providers *detect* that they had diverged; it
would give them nothing to do about it but discard a branch and re-add
those members, which is strictly worse than preventing the divergence.

MIMI then makes the authority structural: "The hub of a room is the
provider identified by the authority of the roomId" (§5.6). The hub's
identity is part of the room's name, so a room cannot be re-homed or
co-owned without becoming a different room.

So this note proposes nothing about ordering. The hub's order stays the
only order. What is missing is a way to **learn the hub's order after
being absent from it**.

## 3. A scalar sequence, not a vector clock

A vector clock reconciles concurrent origins. MIMI has one writer per
room. The whole state a follower needs is "the last position I hold from
this room", which is one number.

A vector clock returns in §7, where a follower fills a gap from another
follower rather than from the hub — and even there the hub's sequence is
the authority, so the question is "who holds 400 to 450", not "how do
these histories merge". Availability is per origin; order is not.

This is the one place where the meshIRCd comparison is actively
misleading, and the note says so plainly so that the next reader does
not reintroduce it.

## 4. The sequence

The hub assigns each fanout of a room a **monotonic sequence**, starting
at 1 for the room's first fanout and increasing by one. It is per room,
assigned by the hub, and never reused or renumbered.

It is not a timestamp, not an MLS epoch and not a message id. An epoch
covers many application messages; a sequence numbers every fanout,
handshake and application alike, because a follower that missed a
handshake needs it as much as a message.

**Where it goes is the one wire question in this note.** Three readings:

1. **A new field in `FanoutMessage`.** Plainest to read, and a wire
   change to a struct other implementations already parse. Weigh against
   the extension-point work of bead mimid-1wgh.55.
2. **Beside the message, in the `POST /notify/{roomId}` envelope** — a
   header, or a wrapper object. No change to `FanoutMessage`, so an
   implementation that does not know the sequence is unaffected, and a
   proxy cannot strip it without the receiver noticing its absence.
3. **In an AppDataDictionary extension**, if fanout gains one. Most
   deniable, least legible.

**Decided by Mark, 2026-11-22 (decision mimid-1wgh.104): (2), beside the
message.** It keeps a parsed structure stable, so an implementation that
does not know the sequence is unaffected and a proxy cannot strip it
without the receiver noticing its absence. And it models the number
correctly: the sequence is a property of the *delivery*, not of the
message. The same `MLSMessage` fanned out to five followers is one
message at one sequence, and if it were ever re-sent the sequence would
be the thing that said so.

**An HTTP header, `mimi-fanout-sequence`** (bead mimid-1wgh.37.104.1).
The note left this turning on whether franking has to cover the
sequence, and that question dissolves: the frank is inside
`FanoutMessage`, and reading (2) puts the sequence outside it, so
neither a header nor a wrapper is franked. What can cover it is the RFC
9421 signature mimid already puts on every peer request, and a header
can go in that signature's covered components. A wrapper object would be
covered by `content-digest` for free, but it would change the
concatenated-FanoutMessages body of §5.5 — the exact cost reading (2)
was chosen to avoid.

So mimid signs the header when the request carries it
(`provider_auth::RequestSigner`), and a proxy that strips or rewrites a
sequence fails the signature rather than silently renumbering a room.
The component is added per request and not to the standing list,
because RFC 9421 §2.5 makes a covered field that is absent an error and
every other endpoint's request has no sequence.

One value per request is enough, which §5.5's "concatenated
FanoutMessages" hides: the hub writes one outbox row per (event,
destination) and sends one row per request, so a `/notify` carries one
fanout.

## 5. The catch-up primitive

A new provider operation, **discovered through the directory** (§5.1's
URI templates, which mimid serves from `directory.rs`):

```
"catchUp": "https://mimi.example.com/v1/catchUp/{roomId}"
```

Discovery through the directory is what makes this safe to add: a
provider that does not publish the template does not support it, a
requester learns that without a failed request, and nothing needs a
version negotiation. That mechanism already exists and is already how
`reportAbuse` and `proxyDownload` were added.

The request says what the follower holds and how much it will take:

- `roomId`, in the path;
- `from`, the sequence after which the follower wants fanout;
- `limit`, the most fanouts it will accept in one answer (INVENTED:
  mimid asks for 256, and a hub may return fewer).

The answer is fanouts in hub order, each with its sequence, plus the
hub's current highest sequence so the follower knows whether it is
caught up or should ask again.

### 5.1 When the gap cannot be filled

A hub keeps fanout for a bounded window (§6). If `from` is older than
the window, the hub MUST say so distinctly rather than returning the
oldest it still has, which would look like a complete answer and hide
the loss. The follower then knows it has an unfillable gap and must
surface it: silent loss is the thing this note exists to remove.

mimid already has this shape internally. Its change feed answers
`TooOld` when a consumer has fallen behind the log, and its front ends
redraw rather than pretend (`mimid-agent-store`'s `feed`, and
`MIMI_EV_RESYNC` in purple-mimi). The same honesty is owed across
providers.

This one is a MUST where §8's bound is a SHOULD, and by §8.1's own test:
a follower behaves differently depending on the answer -- it surfaces a
gap to its users instead of showing a conversation with a silent hole --
so a violation is observable on the wire and testable by the requester.
It is correctness, not bandwidth.

## 6. Retention is the cost, and it must be stated

Catch-up is only as good as what the hub still holds, so the draft has to
say something about retention rather than leaving it to taste. The
cheapest defensible rule: a hub SHOULD keep fanout for a room for at
least a stated minimum, and MUST answer out-of-window requests
distinctly (§5.1).

mimid has the knob already: `message_retention_secs`, 7 days by default,
operator-settable to unlimited (`docs/operating.md`). INVENTED: mimid
offers catch-up over exactly that window, so an operator who shortens
retention shortens catch-up, and the two cannot drift apart.

## 7. Filling a gap from another follower

A follower could ask a *peer* follower for sequences 400 to 450 instead
of the hub. Mark promoted this on 2026-11-22 from a parked idea to a
design item of its own: bead mimid-1wgh.37.105, blocked on this note's
work landing first.

What promoted it is the resilience argument, which is stronger than the
load-spreading one. A hub outage stops the room accepting *new*
messages, necessarily: the hub is the only writer and its identity is in
the roomId. But *reading* backlog needs the hub only because the hub is
the only place to read from. Today an outage takes both; it need not.

It is also where a vector clock earns its place. §3's conclusion — that
the room's order wants a scalar sequence — holds and is not reopened.
But once several followers hold overlapping *pieces* of one hub-ordered
stream, "who holds 400 to 450" is a per-origin holdings question, and a
vector clock or an interval set is the right shape for it. The sequence
stays the authority on order; the clock describes availability.

### 7.1 The piece this design does not have

A receiver taking bytes from a peer instead of the hub has to verify
both the message and **its position**. Franking covers hub acceptance
where it applies, but nothing here binds a sequence to a message in a
way a third party can check, so a relaying peer could renumber, reorder
or quietly omit.

The natural answer is for the hub to sign a running hash over the fanout
stream — a chain entry over (previous, sequence, message digest) — so
any holder can prove a message's position and no holder can hide a gap.
That is an addition to *this* design, not only to §7's, and it is much
cheaper to assign alongside the sequence in §4 than to retrofit once
other implementations parse the envelope. Bead mimid-1wgh.37.104.1
carries the question.

### 7.2 What still has no answer

Question 1 of mimid-1wgh.37.105, and it gates the rest: **may a follower
serve a room's fanout to another follower at all?** That is about who
may hold and redistribute a room's history, not about transport, and it
plausibly wants a say from room policy or a hub-published permission —
"my provider may hand my room's history to a provider of its choosing"
is a thing a room might refuse. Discovery, the privacy widening of
asking a third party, and amplification abuse are the remaining ones.

## 8. Bounding the answer to what the requester was there for

Who is asking is authenticated by the provider authentication that
already exists (RFC 9421 request signatures, PKIX or DANE client
certificates; epic mimid-75nk). What they may be given is this section.

**The hub SHOULD bound the answer by the requester's own participation
window.** A provider:

- may receive fanout from the sequences during which it had a
  participant in the room;
- SHOULD NOT receive anything from before its first participant joined;
- SHOULD NOT receive anything from after its last participant left.

### 8.1 Why SHOULD and not MUST

Mark's call, 2026-11-22 (decision mimid-1wgh.107), and it corrects an
earlier draft of this note that made it a MUST and called a loose bound
"a worse hole than the one being fixed". That overstated it.

A provider is not a member of the MLS group. It holds no group keys and
never decrypts application content; only its users' clients do. Fanout
from sequences when it had nobody in the room is therefore ciphertext it
cannot read. A hub that bounds the window loosely wastes its own
bandwidth and the follower's storage. It does not hand over message
content.

Nor is a loose bound detectable. The requester cannot tell whether what
it received was bounded correctly, and a correctly bounded hub and a
sloppy one are indistinguishable to every other implementation. A MUST
whose violation no peer can observe and no test can catch buys
conformance language and nothing else, so this is an efficiency
requirement, not an interoperability one, and the keyword should say so.

### 8.2 What a loose bound does leak

Worth stating, because "it is only efficiency" is true of the content
and not of everything:

- that fanouts occurred, when, and how large they were;
- whatever handshake messages carry outside the ciphertext. An MLS
  `PublicMessage` handshake is authenticated, not encrypted, so
  membership changes in periods the requester was absent for would be
  readable.

So the SHOULD is worth following, and mimid follows it. It is simply not
a thing to fail a peer over.

### 8.3 The state it needs

A hub bounding the window has to know, per room and per provider, the
sequence ranges during which that provider was represented. mimid's hub
already tracks the participant list and the Commits that changed it;
what it does not keep is the mapping from those changes to sequences.
That is the main new state this design needs, and it is the part to
design carefully before writing code.

**mimid records what was fanned out, not what membership says** (bead
mimid-1wgh.37.104.2, table `room_provider_range`). A provider is a
destination of a fanout exactly when it had a member in the room, so the
ranges are written from the destination set in the same transaction that
records the fanout. Two things follow, and both are why this is better
than mapping the membership changes:

- The ranges and the deliveries cannot disagree. Catch-up can never
  serve a provider a sequence it was not originally sent, which is the
  property §8 is really about. Re-deriving the window from Commits would
  be a second answer to the same question, free to drift from the first.
- Presence is runs of *consecutive* sequences, because between joining
  and leaving every fanout of the room reaches the provider. So a run is
  extended exactly when it ends at the previous sequence, and a provider
  that left and rejoined gets two runs rather than a widened one. A
  single first/last pair per provider would quietly serve the gap.

## 9. Privacy

A catch-up request tells the hub which rooms a provider follows and
roughly when it was unavailable. That is information the hub largely has
already, since it fans out to that provider, but the draft should say it
rather than leave an implementer to notice.

It also gives a hub a way to distinguish "this provider has no users
interested" from "this provider was down", which it could not cleanly
tell before.

## 10. What mimid implements

Hub side:

- assign and persist the per-room sequence;
- record, per room and provider, the sequence ranges that provider was
  entitled to (§8);
- serve `catchUp`, bounded by the retention window of §6 and the
  participation window of §8, and answer out-of-window distinctly;
- publish the `catchUp` template in the directory.

Follower side:

- persist the highest sequence held per room;
- notice a gap, both from a sequence jump in live fanout and at startup
  after downtime;
- ask, apply in order, and stop when caught up;
- when the hub says the gap cannot be filled, record it against the room
  and surface it, so the agent and its front ends can tell the user
  rather than showing a conversation with a silent hole.

## 11. Limitations

- A hub that loses its own fanout store loses what catch-up would have
  served. This design adds a pull path; it does not make the hub durable.
- A follower down longer than the retention window still loses messages.
  The improvement is that it *knows*, and can say so.
- Nothing here helps a *client* that missed messages its own provider
  still holds; that is the agent's sync, which already exists.
- The sequence is per room. A provider following a thousand rooms asks a
  thousand times; there is no cross-room catch-up, deliberately, because
  entitlement (§8) is per room.
- Not written, not proposed, not implemented. No interoperability claim
  of any kind is made.

## 12. The four questions, and Mark's answers

All answered 2026-11-22. Each is a closed decision bead.

1. ~~§4: which of the three placements for the sequence.~~ **Decided
   2026-11-22: beside the message** (decision mimid-1wgh.104).
2. ~~Whether to propose this as text for protocol-08 or as a separate
   extension draft.~~ **Decided 2026-11-22: text for protocol-08**, with
   the implementation as the evidence (decision mimid-1wgh.105). The
   hole is a correctness gap in the base protocol, and proposing it as
   an extension would concede that it is optional. Posting it still
   needs Mark's own OK, as every upstream post does.
3. ~~Timing against the January 2027 interop day with Haven.~~
   **Decided 2026-11-22: implement now, fully live** (decision
   mimid-1wgh.106). This question was first put with a false premise --
   that catch-up was new surface six weeks out competing with
   interop-day scope. Bead mimid-1wgh.46.20 says "mimid needs no new
   features" for that day, and its date is not set, being gated on
   Haven's own prerequisites. So the trade was only regression risk in
   the fanout write path, which §10's two-provider test covers, and a
   live endpoint gives Haven something concrete in January and makes the
   protocol-08 proposal evidence-backed.

   Because it is live from the first deploy, the endpoint is
   peer-reachable untrusted input from the start: provider
   authentication (epic mimid-75nk), strict decoding, named limits.
   §8's participation window is a SHOULD and mimid follows it, but it is
   an efficiency bound, not a conformance point.
4. ~~§7: whether follower-to-follower gap filling is interesting enough
   to keep in view.~~ **Decided 2026-11-22: promoted to a design item of
   its own**, bead mimid-1wgh.37.105, on the strength of the hub-outage
   resilience argument. §7 is rewritten accordingly, and it surfaced one
   thing this note should settle now rather than later: whether the hub
   signs a hash-chain entry alongside the sequence (§7.1), without which
   a peer-served fanout's position cannot be verified.

All four are answered. The remaining open choice is an implementation
one, on bead mimid-1wgh.37.104.1: whether the envelope carries the
sequence as an HTTP header or as a wrapper object, which turns on
whether franking has to cover it.
