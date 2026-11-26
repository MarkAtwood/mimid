# Feedback on draft-atwood-mls-didwebvh-credential-00 from implementing it in mimid

mimid implements draft-atwood-mls-didwebvh-credential-00.
This file lists what implementing it showed to be ambiguous, underspecified or
wrong, for -01 (IETF-xgzc). Each item gives the draft section, what is unclear,
the reading mimid chose and why, and the decision bead that records it.

The did:webvh method used is v1.0, `spec-v1.0/` of
decentralized-identity/didwebvh at 91f3cba, the commit the draft cites.
`spec-v1.0/` is byte-identical at deef9cf and at main bf3d9b4 (2026-11-02).

Code: `crates/mls-didwebvh` (the credential, log verification, the heads
record and the group rules, with no MLS library) and `crates/mimi-mls` (the
same rules applied to OpenMLS groups).

Since bead mimid-1wgh.4.81.34 (Mark, 2026-11-18) mimid carries the record
only as an `app_data_dictionary` component changed by AppDataUpdate
proposals, not as the draft's GroupContext extension (item 29). Items that
the switch closes say so in a **Status** line; their text describes the
extension form as it was implemented.

## Wire format

### 1. The credential cannot be carried by OpenMLS or mls-rs as written

**§The did:webvh Credential.** The draft puts `DIDWebVHCredential did_webvh;`,
a struct of two `opaque<V>` fields, directly in the `select` arm of RFC 9420's
`Credential`.

Both OpenMLS 0.9 and mls-rs encode every credential type they do not know as
`credential_type` followed by one `opaque<V>`. OpenMLS's source says so ("The
implementation only works with credentials that are encoded as variable-sized
vectors"). Given the draft's encoding, either library reads `did_log` as the
whole credential and then parses `witness_file` as the next LeafNode field. RFC
9420's own two types (`basic`, `x509`) are both one vector, so nothing in RFC
9420 forced this assumption to be tested before.

**mimid:** carries the TLS encoding of `DIDWebVHCredential` inside one
`opaque<V>`, so that the wire is `credential_type || varint(len) ||
did_log<V> || witness_file<V>`. This is not what -00 says; it is marked
INVENTED, NOT FROM SPEC in the code. Decision mimid-1wgh.4.81.8.

**For -01:** write the arm as `opaque did_webvh<V>;` whose content is a
`DIDWebVHCredential`, or say in prose that the structure is carried inside an
`opaque<V>`. Consider a sentence noting that new credential types need this
shape to be carried by existing stacks. This also bears on the encoding
question (item 7 of Open Issues; see below).

## Log verification and the profile

### 2. Missing final LF: two of six did:webvh implementations fail the profile

**§did:webvh Profile, Encoding:** "each line ending in a single LF (0x0A),
with no blank lines and nothing after the last LF".

In the DIF did:webvh test suite (commit 703f97f), the logs written by the
dart and java implementations have no final LF. Python, Rust, TypeScript and
java-eecc conform. Under -00, the logs those two
implementations contribute to that suite are invalid as credentials,
although they are valid did:webvh.

**mimid:** refuses them, as written. Decision mimid-1wgh.4.81.11.

**For -01:** either accept a missing final LF (entries are delimited by LF
anyway, so this costs nothing and loses no determinism), or keep the rule and
say that a controller must add the LF before putting a log in a credential.

### 3. CR LF and whitespace inside lines

**§did:webvh Profile, Encoding.** JSON Lines (jsonlines.org) tolerates `\r\n`
because whitespace around a value is ignored; "a single LF" suggests not. JSON
whitespace between tokens inside a line is not mentioned; did:webvh says
entries have "all extra whitespace removed", but hashes over JCS, so
whitespace never changes validity under v1.0.

**mimid:** refuses a line ending in CR; accepts other JSON whitespace inside a
line; refuses an empty `did_log`. Decision mimid-1wgh.4.81.11.

**For -01:** say both explicitly.

### 4. "MUST be I-JSON" and numbers

**§did:webvh Profile, Encoding:** "Each log entry, and `witness_file`, MUST be
I-JSON [RFC7493]". RFC 7493 §2.2 on numbers is a SHOULD NOT ("SHOULD NOT
include numbers that express greater magnitude or precision than an IEEE 754
double"). Does "MUST be I-JSON" make it a MUST NOT?

This matters for determinism: the entry hash is over JCS, which serializes
numbers as doubles. A member whose JSON parser keeps `9007199254740993`
exactly and one that rounds it to a double compute different hashes, so they
disagree about validity. RFC 7493 also requires no noncharacters, which many
JSON parsers accept silently.

**mimid:** refuses any number whose value is integral with magnitude above
2^53 - 1, however written (`9007199254740993`, `1e20`); accepts non-integral
numbers as its parser reads them, so it cannot detect excess precision in
`3.141592653589793238`; refuses noncharacters in strings and member names;
compares member names after unescaping (`"a"` and `"a"` are duplicates).
Decision mimid-1wgh.4.81.9.

**For -01:** say which numbers are allowed. The simplest deterministic rule
is integers within ±(2^53 - 1) only: did:webvh's own parameters need nothing
else, and DID documents rarely carry numbers.

### 5. No JSON nesting limit

The draft fixes byte limits "so that every member applies the same limit",
but JSON parsers also differ in nesting depth (serde_json stops at 128). A
1 MiB log can nest far deeper than that, and members with different parsers
then disagree.

**mimid:** refuses nesting deeper than 128 (serde_json's limit). Decision
mimid-1wgh.4.81.9.

**For -01:** give a nesting limit, by the same argument as the byte limits.

### 6. The ASCII domain rule

**§did:webvh Profile, Domain:** "The DID string MUST match the
method-specific identifier syntax of [DIDWEBVH] using only ASCII letters,
digits, hyphens and dots."

- Literally the whole DID string has colons, the SCID and path segments, so
  the rule must mean the domain component.
- did:webvh writes a port as `%3A<port>` in the domain component; `%` is not
  allowed, so ports are forbidden. Intended?
- Which DID string: the head's, or every entry's `state.id`? They differ after
  a portable move.
- "No internationalized domain name processing is performed", but `xn--`
  labels are ASCII. A did:webvh verifier that runs IDNA (as mimid's inherited
  one does) refuses a malformed `xn--` label; one that does no IDNA processing
  accepts it.

**mimid:** applies the rule to the domain component of every entry's
`state.id`, which must be non-empty `[A-Za-z0-9.-]`, so ports and
percent-encoded IDNs are refused; path segments follow did:webvh; malformed
`xn--` labels are refused (documented limitation). Decision
mimid-1wgh.4.81.12.

**For -01:** say "domain component", say whether ports are allowed, and say
whether `xn--` labels are validated.

### 7. `ttl` "has no effect on validation"

**§Log Verification, change 3.** Read strictly, even a malformed `ttl`
(negative, above 2^31) would not affect validation, but did:webvh's "Allowed
Values" rule makes a log with an invalid parameter value invalid.

**mimid:** an invalid `ttl` value still makes the log invalid (did:webvh's
parameter rules apply); only its caching meaning is ignored.

**For -01:** say "the value of `ttl` is not used" rather than "has no effect
on validation".

### 8. Future `versionTime` in the DIF suite

The DIF negative scenario `negative-versiontime-future` (entries at
2000-01-01, 9999-06-15, 2000-01-03) is rejected by a v1.0 resolver at entry 2
for being in the future. Under change 3 mimid rejects it at entry 3 instead,
for going backwards. Worth a sentence in -01 that change 3 can change *where*
a log fails, not only whether, and that a log valid under change 3 may be
refused by every ordinary resolver.

### 9. Authorized keys: three gaps

**§Conventions, "Authorized key".**

1. "a 32-byte public key in the format of [RFC8032]": must the bytes decode
   as a valid Ed25519 point? If some members check and others do not, they
   compute different `authorized_keys`, the extension differs, and members
   disagree. **mimid:** no point check.
2. "A relative reference is resolved against the document's `id` as
   [DID-CORE] specifies": DID Core points to RFC 3986 §5.2, under which only
   a fragment-only reference has an obvious result against a `did:` base.
   **mimid:** `#frag` resolves to `id#frag`; absolute `did:` references are
   used as is; other relative forms resolve to nothing. Verification method
   `id`s are resolved the same way before comparing.
3. Where a reference resolves: **mimid:** only to objects in the top-level
   `verificationMethod` array; two methods sharing an `id` resolve to nothing.

Decision mimid-1wgh.4.81.10. **For -01:** say all three. A vector
(`dave-authorized-keys` in `crates/mls-didwebvh/tests/vectors/vectors.json`)
exercises each case.

### 10. `witness_file` and pruning

**§The did:webvh Credential:** `witness_file` holds "the witness proofs for
the carried entries". did:webvh says a witness proof approves all earlier
entries, and that controllers SHOULD prune the published `did-witness.json` to
the latest proof per witness. So a device whose credential carries an older
head cannot use the current published witness file: its proofs are for
versionIds beyond that device's head, which "are ignored". Each device must
keep the witness file as it was when its head was current, or the controller
must keep unpruned proofs.

**For -01:** say so in §Adding a Device or in the field description.

## Group rules

### 11. Ties for the newest log

**§Expected Heads:** "Let L be the newest log among the resulting tree's
credentials with SCID S", and "Newest log: the one whose head has the highest
version number". Two forks can have heads with the same version number; L is
then unspecified, and so is the expected extension.

**mimid:** ties go to the greatest head `versionId` bytes; a tie between
different heads always fails the consistency rule anyway, so mimid checks
consistency before the extension match and reports the fork. Decision
mimid-1wgh.4.81.14.

**For -01:** state that heads with the same version number and different
`versionId`s make the Commit invalid, before computing the expected entry.

### 12. Consistency when there is no reference entry

**§Rules, Consistency with the reference entry:** "Every credential with SCID
S whose head is newer than R's is a prefix of L." When R does not exist (a
new user) this is undefined. Read as "no check", two forked credentials of a
new SCID are both admitted: the extension records one, the other leaf is
judged only by authorization against L's keys.

**mimid:** with no R, every credential of S must be a prefix of L. Decision
mimid-1wgh.4.81.14. Vector `new-scid-two-forks`.

**For -01:** say so.

### 13. Malformed or oversized `did_webvh_heads`

**§The Heads Extension** gives no limits and does not say what a member does
with a malformed extension (unsorted, duplicates, keys not 32 bytes). Dropping
a malformed extension, as is usual for unknown extensions, would forget
revocations.

**mimid:** a malformed extension fails closed (the Commit, Welcome or
GroupInfo is refused). It caps entries at 65,536 (invented; the record grows
forever, Open Issue 6) and keys per entry at 1,048,576/48 (derived: each
distinct key needs a 48-byte `publicKeyMultibase` string in a 1 MiB
document). Decision mimid-1wgh.4.81.13.

**For -01:** say that a malformed extension means rejection, and either set a
limit on entries or say none is intended.

### 14. Successor credentials across credential types

**§Successor Credentials** defines did_webvh-to-did_webvh succession only.
RFC 9420 §5.3.1 leaves the replacement check to the application, so the draft
does not say whether an Update or UpdatePath may switch a leaf between
`did_webvh` and `basic`/`x509`. Switching away would let a leaf leave the
record's authorization rule while keeping its place; switching to it changes
an existing leaf's identity.

**mimid:** refuses both. Decision mimid-1wgh.4.81.15.

**For -01:** say so.

### 15. Every member of a mixed group must implement the draft

**§Negotiation and Mandating the Credential** describes "a group that also
admits `basic` or `x509` credentials". But RFC 9420 §7.2 already requires
every member to list every credential type in use, the draft requires
`did_webvh` in `required_capabilities`, and §The Heads Extension says a client
listing `did_webvh` MUST implement the rules. So a basic-only client can never
share a group with a did_webvh leaf; the basic members of a mixed group are
clients that implement this draft and happen to use basic credentials.
(OpenMLS enforces the RFC 9420 rule.)

**mimid:** sets `required_capabilities` itself whenever it sets the record,
keeping other entries. Decision mimid-1wgh.4.81.16. Since item 29 it writes
no `required_capabilities`: the GroupContext `app_components` list names the
record component, which makes every member list it (mls-extensions-11 §5).
The observation stands, since RFC 9420 §7.2 alone keeps a basic-only client
out.

**For -01:** say this in §Negotiation; it affects MIMI deployment (every
provider's clients in a room must implement the draft before one user can use
it).

### 16. The hub validates Commits too

**§Delivery Service and Hub** discusses what a DS or hub can do to the
credential, but a MIMI hub also *validates* every Commit before ordering it
(protocol-07; mimid's hub does, through its Observer). The group rules need
only the public tree and GroupContext, so a hub can apply them; if it does
not, it accepts Commits that every member refuses, and those members fall out
of sync with the hub's order.

**mimid:** the hub's Observer enforces the same rules once told the code
points (`Observer::enforce_did_webvh`); tests show it refusing each rule-
breaking Commit the members refuse.

**For -01:** say that a DS or hub that validates Commits MUST (or SHOULD)
apply §Group Consistency Rules, and that it can, without any secret.

### 17. External joins and MIMI rooms

**§Rules:** "A client whose SCID has no entry in `did_webvh_heads`, which
includes every new user, cannot join by external Commit". MIMI open rooms
and join links (protocol-07, room-policy-04 §6.2) join by external Commit, so
in a room that requires `did_webvh`, no new user can use them. This makes Open
Issue 1 more pressing. It is also implementable today: mls-extensions-11
allows AppDataUpdate proposals in an external Commit ("AppDataUpdate proposals
can be included in an external Commit"), and mimid already sends such
Commits for joins.

**For -01:** mention the MIMI consequence under Open Issue 1.

**Status:** closed in mimid by carrying the record as an
`app_data_dictionary` component, the only form since bead mimid-1wgh.4.81.34
(Mark, 2026-11-18; item 29). An external Commit carries the AppDataUpdate
that sets the joiner's entry (decision mimid-1wgh.4.81.33), which departs
from §Rules as written.

### 18. Open Issue 5 is real in practice

A GroupContextExtensions proposal replaces the whole list, and
mls-extensions-11 §4.7 requires it to carry `app_data_dictionary` unchanged
(the dictionary of the *current* epoch, even when the same Commit has
AppDataUpdate proposals). A record change therefore always needs a fresh GCE
proposal built from the current extensions, and conflicts with any pending GCE
proposal from someone else.

**mimid:** refuses a record-changing Commit while a GCE proposal is pending
(decision mimid-1wgh.4.81.17).

**Status:** closed in mimid by carrying the record as an
`app_data_dictionary` component, the only form since bead mimid-1wgh.4.81.34
(Mark, 2026-11-18; item 29). A record change is AppDataUpdate proposals,
which a Commit holds next to another party's GroupContextExtensions proposal;
`PendingGroupContextExtensions` is gone.

### 19. The record change is mechanical; say who adds it

The draft says a Commit that changes the expected value MUST include the GCE
proposal, and a Commit that raises a head MUST remove the leaves it no longer
authorizes. Both are fully determined by the resulting tree. mimid's
`Member::commit` computes them and adds them itself, so revocation is "give the
device the new log, then commit". The draft could say an implementation MAY do
this, so that applications do not each re-derive it.

### 20. Revocation through another device works as described

§Rules' path for revoking the committing device ("committing an Update
proposal, sent by one of the user's other devices, that carries the new log")
works over OpenMLS unchanged: mimid tests have d2 propose an Update with a log
that drops d1, and Bob's Commit removes d1. No change needed; noted as
confirmation.

### 21. Size

Each leaf carries the whole log, so KeyPackages and the ratchet tree grow with
every device change. MIMI servers bound request sizes; a 2 MiB leaf limit is
far above what most deployments will accept for a KeyPackage. Worth a sentence
that deployments will set lower operational limits, and that a member must
still accept up to the draft's limits to stay deterministic (or the draft
picks a smaller limit).

## Using it in MIMI (mimid-server and mimid-agent)

These came from wiring the credential into mimid's hub and agent (bead
mimid-1wgh.4.81.18), with an end-to-end test through a real mimid server:
a user with two `did_webvh` devices and a BasicCredential user share a room,
one device is revoked, and the hub refuses the revoked device afterwards.

### 22. Tying a credential to the application's name for the user

**§Reference Identifiers** says the presented identifier is the SCID, and
that applications pin "the SCID for each contact". It does not say how an
application knows which contact a credential belongs to. MIMI names users by
URI (`mimi://example.com/u/alice`) in the participant list, room policy,
keyMaterial and franking (protocol-07 §5.4.1.3 compares "the sender's
identity in its credential" with `senderUri`), and the hub authorizes by
that URI. A credential whose only identity is an SCID gives the hub nothing
to authorize and the member nothing to pin it under.

**mimid:** the controller lists the user's MIMI URI in the head DID
document's `alsoKnownAs`; a `did_webvh` leaf belongs to the one `mimi:` URI
there (none or several: it belongs to no user, and the hub's participant
check refuses it). The update keys sign it, so the provider cannot move an
SCID to another user, and the hub keeps its usual rule that a user URI's
domain is its provider's. Contacts are pinned by user URI. A BasicCredential
leaf for a user pinned to an SCID is treated as a change too: otherwise the
provider defeats the draft by adding a BasicCredential device for that user.
INVENTED, NOT FROM SPEC; decision mimid-1wgh.4.81.21.

**For -01:** say how an application maps a credential to its own name for a
user (suggest `alsoKnownAs`, or leave it to the application but say it must
exist), and say that a pinned contact presenting a non-`did_webvh`
credential is a change of SCID for the purposes of the MUST alert.

### 23. OpenMLS wants every GroupContext extension in required_capabilities

**§Expected Heads** has the record set by a GroupContextExtensions proposal,
and **§The Heads Extension** asks for `required_capabilities` listing
`did_webvh_heads` and `did_webvh`. OpenMLS refuses a GroupContextExtensions
proposal unless every non-default extension it carries is also listed in its
`required_capabilities` (`ExtensionNotInRequiredCapabilities`), which is
stricter than RFC 9420 §12.1.7. A MIMI room carries `app_data_dictionary`,
so the proposal that first sets the record must also list
`app_data_dictionary` (0x0006) in `extension_types`, or OpenMLS will not
build or accept it.

**mimid:** lists every non-default extension the GroupContext already
carries when it writes `required_capabilities`, and its hub accepts such a
listing as part of a record change (decision mimid-1wgh.4.81.22).

**For -01:** a sentence that the `required_capabilities` the proposal sets may
need to list other extensions the group carries, so implementations do not
read "lists `did_webvh_heads` and `did_webvh`" as "lists only those".

**Status:** closed in mimid by carrying the record as an
`app_data_dictionary` component, the only form since bead mimid-1wgh.4.81.34
(Mark, 2026-11-18; item 29). No GroupContextExtensions proposal and no
`required_capabilities` are written for the record, so the workaround is
gone. (OpenMLS's stricter check still applies to any GroupContextExtensions
proposal, which mimid's hub refuses anyway.)

### 24. A hub that refuses GroupContextExtensions proposals

A MIMI hub has reason to refuse GroupContextExtensions proposals in
general: one could drop the hub from `external_senders` or change
`required_capabilities` to lock members out. mimid's hub refused them all.
The draft makes one mandatory in every Commit that adds a new user or
carries a newer log, so a hub must recognize the record change and let it
through, while still refusing anything else in the same proposal.

**mimid:** accepts a GroupContextExtensions proposal only if it differs from
the current GroupContext in the record and the `required_capabilities`
additions it needs, and only while it enforces the rules (decision
mimid-1wgh.4.81.22). This is also an argument for Open Issue 1: as an
`app_data_dictionary` component the record would travel in an AppDataUpdate,
which MIMI hubs already handle per component.

**Status:** closed in mimid by carrying the record as an
`app_data_dictionary` component, the only form since bead mimid-1wgh.4.81.34
(Mark, 2026-11-18; item 29). The hub again refuses every
GroupContextExtensions proposal (decision mimid-1wgh.6.2); decision
mimid-1wgh.4.81.22 and `ProposalKind::DidWebvhRecord` are gone. Room policy
treats the record like any component it does not track.

### 25. Revocation needs a room-policy capability

**§Revoking a Device** has a remaining device commit the Removes. In a MIMI
room that is the removal of one's own client, which room-policy-04 §8.1.2
gates behind `canRemoveOwnClient`. A room whose roles do not grant it cannot
complete a revocation, and the revoked device stays until someone with
`canKick` removes it.

**mimid:** its default member role holds `canRemoveOwnClient` (decision
mimid-1wgh.4.81.25), and its hub also authorizes, whatever the room policy,
exactly the Removes the rules require of the committer: a leaf with the
committer's own SCID whose key the record set by the same Commit no longer
authorizes (decision mimid-1wgh.4.81.26). Every other Remove in that Commit
still needs `canRemoveOwnClient` or `canKick`. The rules decide which
Removes are mandatory from the tree and the record alone, so a hub that
enforces the rules can compute the set; one that does not cannot.

**For -01:** note under §Revoking a Device that an application's own
authorization (for MIMI, room policy) must allow a user's device to remove
another device of the same user, or must treat the Removes the rules require
as authorized by the record change itself. The second reading needs the
authorizer to enforce the rules; the draft could say which Removes are
"required" in a form an authorizer can check (same SCID as the committer,
key not in the new record).

### 26. Every member's provider must already support the draft

With item 15, a BasicCredential client must list `did_webvh` and enforce the
rules to share a room with a `did_webvh` user. mimid's agents do so by
default (decision mimid-1wgh.4.81.23), so in a mimid-only deployment a
BasicCredential user needs no configuration. In a federation, every
provider's clients in the room must do the same before one user can use the
credential, and a keyMaterial request (protocol-07 §5.2) from such a room
should require `did_webvh` and `did_webvh_heads`, or a provider may return a
KeyPackage that cannot be added (decision mimid-1wgh.4.81.24).

With the record as a component (item 29) the KeyPackage must list the
component in its leaf's `app_components`, which a protocol-07
`RequiredCapabilities` cannot express. mimid's requests name the `did_webvh`
credential type only, and both the target provider and the requester take it
to imply the component (decision mimid-1wgh.4.81.36): mimid's provider serves
such a request only KeyPackages that list it. A provider that does not know
that convention may still return one that cannot be added. For -01, or for
protocol: a way to require components in keyMaterial.

### 27. The alert when a contact's SCID changes is repeated by design

**§Reference Identifiers** says applications MUST alert the user if a
contact's SCID changes, and pin the first SCID. Keeping the pin means the
mismatch is found again at every later Commit in that room, so an
implementation that alerts on each finding alerts many times for one
change. A messenger that shows chats through a stock client (mimid's agent
behind JMAP Chat) has only a chat message to alert with.

**mimid:** the agent reports the mismatch each time; its JMAP layer stores
one notice Message per room and per (pinned SCID, presented SCID), keyed so
a replay or a repeat stores nothing more, and sets the contact's JMAP
`did` to the new DID (bead mimid-1wgh.4.81.27). The pin is never moved
automatically; there is no "accept the new identity" action yet.

**For -01:** say whether "alert" is once per change or per occurrence, and
what accepting a new SCID means (re-pinning), so implementations agree on
what a user sees.

### 28. Handing a running device a new log, and the Update-proposal fallback

The draft says what a device does with a newer log but not how it gets
one. mimid's agent takes it from a local endpoint or by watching the file
the controller writes (bead mimid-1wgh.4.81.28), and checks that it names
the user and extends the current log before committing it.

Where the Commit cannot be built, the agent sends the credential as an
Update proposal for another member to commit, as §Rules suggests for a
revoked committer. Implementing it showed two limits:

- With Open Issue 5's cause (a GroupContextExtensions proposal from
  another party pending), the other member is in the same position: its
  Commit must include the pending proposal and must also change the
  record, so it cannot be built either, unless the pending proposal
  already sets the expected record. The fallback helps only once the
  pending proposal is gone or is itself the record change.
- When another member commits a user's Update that revokes a device, the
  Remove of the revoked device is that member's, not the user's. mimid's
  hub authorizes without a capability only the Removes required of a
  committer with the same SCID (item 25), so this one needs `canKick`.

**For -01:** if Update proposals are the recommended path for a revoked or
blocked committer, say that the Removes the record then requires are
mandatory whoever commits, so an application's authorization can follow
the record rather than the committer.

**Status:** the first limit is closed by item 29 (bead mimid-1wgh.4.81.34):
with the record a component, the other member commits the Update with the
GroupContextExtensions proposal pending. The second was closed earlier by
decision mimid-1wgh.4.81.31: the hub also authorizes the Removes vouched for
by an Update proposal the Commit includes. The fallback remains for Commits
that still cannot be built, such as one that would cover a pending record
update naming an SCID with no leaf (decision mimid-1wgh.4.65).

### 29. The record as an `app_data_dictionary` component: Open Issues 1 and 5

**§The Heads Extension, §Expected Heads, Open Issues 1 and 5.** Items 18,
24 and 28 all come from the record being a GroupContext extension changed
by a GroupContextExtensions proposal. mimid prototyped the alternative
Open Issue 1 names: the record as an `app_data_dictionary` component
changed by AppDataUpdate proposals (mls-extensions-11 §4.6, §4.7), with the
group rules unchanged (spike bead mimid-1wgh.4.81.32, decision
mimid-1wgh.4.81.33, `docs/didwebvh-appdata-spike.md`).

**mimid:** first behind a code-point switch; since bead mimid-1wgh.4.81.34
(Mark, 2026-11-18) the component is the only form, with the private-use
component ID 0xF013 as a configurable default (decision mimid-1wgh.4.81.35).
With the component, a revocation Commit and the Update-proposal
fallback both succeed with another party's GroupContextExtensions proposal
pending; two record changes (a device's by reference and the committer's)
combine in one Commit; a device whose log is newer than the record joins by
external Commit; and the hub needs no record-specific exception. The update
semantics had to be invented: the `update` is a `DIDWebVHHeads` whose
entries replace or add the entries with the same SCID. Listing the
component in the GroupContext `app_components` does the work
`required_capabilities` does now (mls-extensions-11 §5).

**For -01:** carry the record as a component and close Open Issues 1 and
5; define the update semantics and forbid `remove`; let an external Commit
set the record. The spike document has suggested text for §The Heads
Extension, §Expected Heads, §Rules, §Revoking a Device, Open Issue 5 and
IANA. The cost is a normative dependency on mls-extensions.

## With mls-rs

From bead mimid-4lp4.2: an mls-rs member and a mimid user with two
`did_webvh` devices in one group, against stock mls-rs
(`docs/didwebvh-mls-rs.md`, `crates/mimi-mls/tests/didwebvh_mls_rs.rs`).

### 30. "The credential's identity" is the user's, not the member's

**§Binding to the LeafNode** says "The SCID of the log is the credential's
identity." All of a user's devices share the SCID. mls-rs indexes members
by an identity its `IdentityProvider` returns and refuses a second leaf
with the same one (`DuplicateLeafData`). An mls-rs application that takes
the sentence literally and returns the SCID cannot have two devices of one
user in a group, which is the very case the credential is for. With the SCID
plus the leaf's `signature_key`, both devices join, and mls-rs and mimid
agree on every epoch (test
`an_identity_provider_keyed_by_scid_alone_refuses_the_second_device` and
the tests after it).

**mimid:** the SCID names the user (§Reference Identifiers);
OpenMLS has no per-leaf identity index.

**For -01:** say that the SCID identifies the user (the presented
identifier of §Reference Identifiers) and that a member is a device, so
an implementation that needs a unique identity per leaf uses the SCID
together with the `signature_key`.

### 31. A member without AppDataUpdate blocks revocation

**§The Heads Component, §Negotiation and Mandating the Credential.** Since
item 29 the record changes only by AppDataUpdate. mls-extensions-11 §4.7
requires every member that processes such a Commit to support
AppDataUpdate (RFC 9420 §12.2 for proposal types). Stock mls-rs has no
AppDataUpdate, and its custom-proposal API cannot carry one (it wraps an
unknown proposal in one `opaque<V>`). With an mls-rs member in the group
that truthfully does not list the proposal type, OpenMLS refuses every
record change: no new `did_webvh` user, no device with a newer log, and no
revocation, unless the Commit also removes that member. If the member lists
the type without supporting it, the Commit goes through and mls-rs cannot
parse it. The draft's MUSTs today require a client that lists `did_webvh`
to list the component and implement the rules, but they do not mention the
proposal type. A BasicCredential member must also list the component, so
the same applies to it.

**mimid:** allows such a member, and a Commit that changes the record
also removes every member whose leaf does not list AppDataUpdate (Mark,
bead mimid-4lp4.3; details in decision mimid-1wgh.4.81.37). §4.7 exempts
members the Commit removes, and OpenMLS accepts it. The user stays in
`participant_list`, as after a kick of one client, and can rejoin. The hub
authorizes those Removes without a room-policy capability, but only for
leaves that lack the proposal type, in a Commit that carries an
AppDataUpdate of the record. The removed mls-rs member cannot parse the
Commit that removes it (it carries the AppDataUpdate), so it learns of the
removal only when later messages fail (`EpochNotFound`). A revocation is
never blocked this way, but every record change drops these members.

**For -01:** say in §The Heads Component that a client listing the
component also lists the AppDataUpdate proposal type, and in
§Negotiation that a group carrying the record MAY list AppDataUpdate in
`required_capabilities` so that a member without it cannot be added. Say
in Security Considerations that a member that cannot process AppDataUpdate
delays a revocation until it is removed, and that a Commit changing the
record may remove such members (what mimid does). The extension form (GCE) would let
RFC 9420-only stacks change the record, but it brings back items 18, 24 and
28. The better fix is AppDataUpdate in the MLS libraries.

## Section 7, item 7: the encoding question

What implementing -00 taught about "Encoding without DIDs":

1. **The mechanism is independent of the encoding, and the code shows it.**
   The group rules (`crates/mls-didwebvh/src/rules.rs`, about 200 lines of
   code, plus the `did_webvh_heads` codec, about 150) use exactly four things
   from a credential: the SCID, the ordered list of version identifiers, the
   set of 32-byte keys the head authorizes, and the prefix relation between two
   logs. Nothing in them knows about JSON, DIDs or did:webvh. Any log format
   that yields those four things plugs in unchanged; so does the OpenMLS glue
   (`crates/mimi-mls/src/didwebvh.rs`).

2. **Almost all of the ambiguity came from the encoding.** Of the items in
   this file, items 2 to 10 and 13 (JSON Lines, I-JSON numbers, nesting,
   domain syntax, IDNA, `ttl`, clocks, DID URL resolution, verification method
   selection, witness pruning) exist only because the log is did:webvh JSON.
   Each is a place where two careful implementations can reach different
   validity decisions, which is the one thing §Deterministic Validation says
   must not happen. A log defined in TLS presentation language, signed over the
   exact bytes as MLS signs everything else, would have none of them: no
   canonicalization, no number model, no parser differences, no
   internationalization, and no clock-bearing fields.

3. **But did:webvh paid for itself in testing.** Because did:webvh exists, the
   first implementation could reuse a verifier already tested against the DIF
   did:webvh test suite (six independent implementations), and test against
   those implementations' logs on day one. A new TLS-PL format would start with
   no implementations and no test suite. The same suite also showed that two of
   the six implementations' output fails the draft's profile (item 2), so
   "reuse did:webvh" in practice means "reuse a profile of did:webvh that some
   did:webvh tools do not produce".

4. **The verifier is large relative to the mechanism.** The did:webvh
   verification mimid relies on is about 1,200 lines in crate-jmap
   (`webvh.rs` and `jcs.rs`) plus about 450 lines of profile layered on top
   (`verify.rs`, `json.rs`, `keys.rs`), against about 350 lines for the rules
   and the record. A TLS-PL log of entries (previous hash, version, authorized
   device keys, update keys, next-key commitments, one signature) would need a
   verifier of perhaps 200 lines.

5. **The wire problem (item 1) is independent of the encoding.** Whatever the
   log format, the credential must be carried as one `opaque<V>` to work with
   existing MLS stacks.

6. **A possible way to put the question to the WG:** define the group
   mechanism against an abstract "verified log" (SCID, version identifiers,
   authorized keys per version, prefix), as mimid's code does, and treat the
   encoding as a separable choice: did:webvh with a strict profile now
   (implementations exist), or a TLS-PL log (determinism by construction),
   or a CWT/SD-CWT chain. mimid can add a second encoding behind the same
   rules if the WG wants to compare them.
