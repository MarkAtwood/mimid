# Follower catch-up: recovering fanout a provider missed

Design note, 2026-11-22, for Mark's review. Bead mimid-1wgh.37.104.

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

A vector clock returns only for the optional extension of §7, where a
follower fills a gap from another follower rather than from the hub —
and even there the hub's sequence is the authority, so the question is
"who holds 400 to 450", not "how do these histories merge".

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

(2) is my recommendation, because it keeps a parsed structure stable and
because the sequence is a property of the *delivery*, not of the message:
the same `MLSMessage` fanned out to five followers is one message at one
sequence, and if it were ever re-sent the sequence would be the thing
that said so.

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

## 7. Optional: filling a gap from another follower

Not proposed for the draft; recorded because it is the first thing
anyone will ask after reading §3.

A follower could ask a *peer* follower for sequences 400 to 450 instead
of the hub, which spreads load and survives a hub outage. The hub's
sequence stays authoritative, and the fanouts are hub-signed where
franking applies, so a peer cannot forge them. This is where a vector
clock would earn its place, because now several parties hold overlapping
pieces.

It is out of scope until the simple case works, and it needs an answer to
"may a follower serve a room's fanout to another follower at all", which
is a policy question, not a transport one.

## 8. Authorization, and the part implementers will get wrong

Catch-up is a read of a room's history, so it is an authorization
decision, not a plumbing one. The requester is authenticated by the
provider authentication that already exists (RFC 9421 request
signatures, PKIX or DANE client certificates; epic mimid-75nk).

**The hub MUST bound the answer by the requester's own participation
window.** A provider:

- may receive fanout from the sequences during which it had a
  participant in the room;
- MUST NOT receive anything from before its first participant joined;
- MUST NOT receive anything from after its last participant left.

Get this wrong and catch-up becomes a retroactive read of a room you were
removed from, which is a worse hole than the one being fixed. It deserves
its own paragraph and a MUST in any text proposed to the working group,
not a passing clause.

A hub therefore has to know, per room and per provider, the sequence
ranges during which that provider was represented. mimid's hub already
tracks the participant list and the Commits that changed it; what it does
not keep is the mapping from those changes to sequences. That is the
main new state this design needs, and it is the part to design carefully
before writing code.

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
- serve `catchUp`, bounded by the window of §6 and the entitlement of
  §8, and answer out-of-window distinctly;
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

## 12. Open questions for Mark

1. §4: which of the three placements for the sequence. I recommend (2),
   beside the message rather than inside `FanoutMessage`.
2. Whether to propose this as text for protocol-08 (the hole is in the
   WG's own draft) or as a separate extension draft. I recommend the
   former, with the implementation as the evidence.
3. Timing against the January 2027 interop day with Haven: new protocol
   surface six weeks out. I recommend the design note now and the
   implementation after the interop day, unless Haven should see it in
   January, in which case the interop-day scope has to shrink to pay for
   it.
4. §7: whether follower-to-follower gap filling is interesting enough to
   keep in view, or should be dropped from the note entirely.
