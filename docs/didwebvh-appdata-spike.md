# Spike: the did_webvh record as an app_data_dictionary component

Bead mimid-1wgh.4.81.32 (decision mimid-1wgh.4.81.33). Branch
`didwebvh-appdata`.

**Outcome (2026-11-18).** Mark chose the component form. Since bead
mimid-1wgh.4.81.34 it is mimid's only form: the code-point switch, the
extension form and what it needed (`ProposalKind::DidWebvhRecord`,
`is_record_change`, decision mimid-1wgh.4.81.22, the `required_capabilities`
handling of `with_heads`, `PendingGroupContextExtensions`) are gone, and the
scenario tests below are regular tests. The component ID defaults to the
private-use 0xF013 and stays a setting (decision mimid-1wgh.4.81.35); a
keyMaterial request from a `did_webvh` room requires the credential type and
takes it to imply the component (decision mimid-1wgh.4.81.36). The text below
is the spike's report as written: its references to the extension form, the
switch and the extension-form tests describe the code before the switch.

**Question.** draft-atwood-mls-didwebvh-credential keeps the
`did_webvh_heads` record as a GroupContext extension, changed by a
GroupContextExtensions (GCE) proposal. RFC 9420 §12.4 allows one GCE per
Commit, so a record change cannot be combined with another party's pending
GCE proposal (Open Issue 5), and the Update-proposal fallback fails the
same way (feedback item 28). Does carrying the record as an
`app_data_dictionary` component, changed by AppDataUpdate proposals
(mls-extensions-11 §4.6, §4.7), remove the collision, and what does it do
to the hub, which today lets through one GCE shape (decision
mimid-1wgh.4.81.22)?

**Answer.** Yes. With the record as a component, every scenario that fails
in the extension form passes, the group rules are unchanged, and the hub
needs no code of its own for the record. Recommendation for -01: switch to
the component, and close Open Issues 1 and 5 with it.

## The prototype

A switch on the code points, so the extension form stays the default and
every existing test runs unchanged:

```rust
let cp = CodePoints::SUGGESTED.with_heads_component(0xf013)?;
```

`0xf013` is a private-use component ID (mls-extensions-11 §7.5). Every
member of a group must use the same code points, as with the existing
credential and extension types.

What changes when the switch is on:

| Where | Extension form (draft -01) | Component form (spike) |
|---|---|---|
| Record | `did_webvh_heads` GroupContext extension | entry `0xf013` of the GroupContext `app_data_dictionary` |
| Changed by | one GCE proposal carrying the whole extension list | one or more AppDataUpdate proposals |
| Who must support it | `required_capabilities` lists `did_webvh_heads` and `did_webvh` | GroupContext `app_components` names the component (mls-extensions-11 §5) |
| Leaf capabilities | `did_webvh_heads` in `extensions` | the component in the leaf's `app_components` |
| External Commit | cannot change the record | can (mls-extensions-11 §4.7) |
| Removing the record | GCE that omits it; rules refuse | AppDataUpdate `remove`; component logic refuses |

The update semantics are invented (decision mimid-1wgh.4.81.33): the
`update` field is a `DIDWebVHHeads`, and each entry replaces or adds the
entry with the same `scid`, applied in Commit order. The record's
existing struct and codec serve unchanged. A whole record is a valid
update, and so is a single entry. Entries are never removed, so this loses
nothing the draft keeps. The group rules are not touched: after the
updates are applied, the record must equal the expected entries, exactly
as in the extension form.

mimi-mls is the component's application logic, as it is for the
mls-extensions-11 §5.1 built-ins, so the `apply` functions of the agent and
the hub never see it. `Member::commit` sends the whole expected record and,
the first time a record appears in a group, also extends `app_components`
by AppDataUpdate.

Code: `crates/mls-didwebvh/src/config.rs` (the switch),
`crates/mimi-mls/src/didwebvh.rs` (`heads`, `apply_heads_updates`,
`record_updates`, `required_removes`, `check_external_join`),
`crates/mimi-mls/src/member.rs` (create, commit, external join, the
component in `resolve_app_data_updates`), `crates/mimi-mls/src/identity.rs`
(the leaf lists the component). About 350 lines added; nothing in the hub.

## Scenarios

| Scenario | Extension form | Component form | Test |
|---|---|---|---|
| Revocation Commit while an unrelated GCE proposal is pending | refused, `PendingGroupContextExtensions` (`didwebvh_rogue::a_pending_group_context_extensions_proposal_blocks_the_record_change_but_not_the_update`) | **passes**; the GCE (it adds an external sender) and the record change both take effect | `didwebvh_appdata::a_revocation_commits_while_an_unrelated_group_context_extensions_proposal_is_pending` |
| Update-proposal fallback (another member commits the revoking device's Update) with the GCE still pending | refused the same way (feedback item 28) | **passes**; the hub's `did_webvh_required_removes` names the revoked leaf | `didwebvh_appdata::the_update_proposal_fallback_commits_with_a_pending_group_context_extensions_proposal` |
| Two record changes in one Commit: a device's partial update by reference, plus the committer's own | impossible: one GCE per Commit, and a GCE replaces the whole list | **passes**; two AppDataUpdates for the record, applied in order; both users' heads raised | `didwebvh_appdata::two_record_changes_compose_in_one_commit` |
| A device whose log is newer than the record joins by external Commit | refused, `ExtensionMismatch` (`didwebvh_group::a_device_not_yet_in_the_record_cannot_join_externally`) | **passes**; the joiner raises its entry in the external Commit | `didwebvh_appdata::a_device_newer_than_the_record_joins_by_external_commit` |
| Removing the record | refused, `HeadsRemoved` | refused, `InvalidAppDataUpdate` | `didwebvh_appdata::removing_the_record_component_is_refused` |
| Hub: a record update that revokes a device but does not remove it | refused by the rules | refused by the rules | `hub_didwebvh_appdata::a_record_update_that_breaks_the_rules_is_refused` |
| Hub: a revocation with the required Remove, in a room whose roles lack `canRemoveOwnClient` | accepted through the decision .22 GCE exception | accepted, no GCE at all and no hub change | `hub_didwebvh_appdata::a_revocation_by_app_data_update_passes_room_policy` |

The mimi-mls tests are in `crates/mimi-mls/tests/didwebvh_appdata.rs`, the
hub tests in `crates/mimid-server/tests/hub_didwebvh_appdata.rs`. The
unrelated GCE proposal, and the hub tests' rule-breaking Commits, come from
a plain OpenMLS client that knows nothing of the draft. Two mutations were
run to check that the tests can fail: an update function that keeps only
the first entry of each update fails all five mimi-mls tests, and a
`required_removes` that ignores the record's AppDataUpdate fails the hub
revocation test.

## What mls-extensions-11 allows and forbids that matters

- **How many per Commit.** Any number of AppDataUpdate proposals, for any
  components. For one component, either one `remove` or one or more
  `update`s, handed to the component's logic in Commit order (§4.7). Two
  record changes in one Commit are therefore legal, and the component's
  logic decides how they combine. That is why the semantics have to be in
  the draft.
- **Next to a GCE.** "A commit can contain a GroupContextExtensions
  proposal which modifies GroupContext extensions other than
  app_data_dictionary, and zero or more AppDataUpdate proposals" (§4.7).
  A GCE must carry `app_data_dictionary` exactly as in the current epoch,
  so an unrelated GCE never touches the record, and the record change
  never needs a GCE. This is what removes Open Issue 5.
- **Ordering.** AppDataUpdate proposals are processed after the RFC 9420
  proposals and after AppEphemeral (§4.7). The rules judge the resulting
  epoch, so ordering does not matter to them; within the record, a later
  update for the same SCID wins, and the rules then require the result to
  be the expected entry.
- **No UpdatePath.** An AppDataUpdate does not require one, unlike a GCE
  (§4.7). A Commit that only adds a `did_webvh` user no longer needs a
  path because of the record.
- **External Commits and external senders.** "AppDataUpdate proposals can
  be included in an external Commit", and can be sent by an external
  sender (§4.7). The first is what lets a new user, or a device with a
  newer log, join by external Commit: Open Issue 1 and feedback item 17,
  which matters for MIMI open rooms and join links. An external sender's
  record update is harmless, since the rules fix the value; the draft can
  allow it or forbid it, §4.7 lets a component restrict either.
- **Who must support it.** A GroupContext may hold state only for a
  component its `app_components` list names, and every member's leaf must
  list every component the GroupContext lists (§5), enforced like
  `required_capabilities`. Listing the component therefore does the job
  `required_capabilities` does in the extension form: a client that lists
  it claims to implement the rules. `did_webvh` in
  `required_capabilities` `credential_types` is no longer needed for
  enforcement (RFC 9420 §7.3 already requires every leaf's credential type
  to be supported by every member); it stays available to a group that wants to
  require the credential (draft §Negotiation).
- **Joiners.** `app_data_dictionary` is a GroupContext extension, so the
  record still reaches a joiner in the Welcome's and the GroupInfo's
  GroupContext and still feeds the key schedule (§4.6: "automatically
  distributes it to new joiners"). The draft's joiner checks apply as they
  are; the prototype's Welcome and external joins read the record from
  there.
- **Removal.** A `remove` is a valid AppDataUpdate in general; the
  component must say that it is invalid for the record.
- **Changing the dictionary requires AppDataUpdate support from every
  member that processes the Commit** (§4.7). In a group that uses the
  record, every member lists the component and so has it.

## What it costs

- **A normative dependency on draft-ietf-mls-extensions**, which is not
  yet an RFC, and an entry in its "MLS Component Types" registry
  (Specification Required) instead of "MLS Extension Types". The draft
  already cites mls-extensions in Open Issues 1 and 5.
- **Groups must use `app_data_dictionary` and AppDataUpdate.** Every MIMI
  room does. A plain MLS deployment without mls-extensions cannot use the
  component form; the extension form could be kept as an alternative, at
  the cost of two ways to do one thing. Not checked: whether mls-rs
  implements AppDataUpdate.
- **New spec text:** the component's update semantics (a short paragraph),
  and the rule that a `remove` is invalid.
- **The first Commit that records a `did_webvh` user** in a room that does
  not yet list the component also updates `app_components` (a full-value
  update, mls-extensions-11 §5.1). If another party's `app_components`
  update is pending, the committer's, coming later in the Commit, wins and
  drops theirs. A room created by a client that supports the draft can list
  the component from the start and avoid this; mimid's creator does when
  it holds a `did_webvh` credential.
- **A different blocker remains.** A pending AppDataUpdate that records an
  SCID with no leaf cannot be undone by a later update (entries are never
  removed), so the expected record cannot be reached and the Commit fails.
  RFC 9420 §12.4 lets a committer leave such a proposal out; mimid does
  not (decision mimid-1wgh.4.65). A hub could also refuse, on arrival, a
  standalone record update that names an SCID with no leaf. This is
  narrower than Open Issue 5: it takes a bad proposal, not any unrelated
  one.
- **Implementation size.** About 350 lines for the switch, plus tests.
  Replacing the extension form instead of adding a switch would delete
  more than it adds (below).

## What the hub no longer needs

With the component form only:

- `ProposalKind::DidWebvhRecord` (mimi-mls observer and hub policy) and
  `didwebvh::is_record_change` with its test: about 130 lines.
- The exception in decision mimid-1wgh.4.81.22. Decision mimid-1wgh.6.2
  (refuse every GCE proposal) holds again without a carve-out.
- `with_heads`'s `required_capabilities` handling, including the
  workaround for OpenMLS's demand that every GroupContext extension be
  listed (feedback item 23), and `DidWebvhError::PendingGroupContextExtensions`.

The hub still needs: the rules in its Observer (unchanged), and
`required_removes` (decisions .26 and .31), now keyed on the record's
AppDataUpdate rather than on a GCE. Room policy treats the record like any
component it does not track: no capability, since the rules fix the value.
The hub code was not changed for the spike; it was opened with the
component code points.

## Recommendation for -01

Carry the record as an `app_data_dictionary` component. It removes Open
Issue 5 outright, makes the Update-proposal fallback work, lets new users
join by external Commit (Open Issue 1), and gives MIMI hubs nothing new to
special-case. The cost is the dependency on mls-extensions, which MIMI
already has.

Suggested text for **§The Heads Extension** (renamed "The Heads
Component"):

> The record is the `did_webvh_heads` component (TBD2) of the GroupContext
> `app_data_dictionary` extension ({{Section 4.6 of I-D.ietf-mls-extensions}}).
> A client that lists `did_webvh` in the `credentials` field of its LeafNode
> `capabilities` MUST list `did_webvh_heads` in the `app_components`
> component of its LeafNode and MUST implement the rules in {{group-rules}}.
> A group whose tree contains a `did_webvh` credential MUST carry the
> component, and its GroupContext `app_components` list MUST name it, so
> that every member enforces the rules
> ({{Section 5 of I-D.ietf-mls-extensions}}). A group that carries the
> component MUST NOT remove it: an AppDataUpdate proposal for
> `did_webvh_heads` whose `op` is `remove` is invalid.
>
> The `update` field of an AppDataUpdate proposal for `did_webvh_heads` is
> a `DIDWebVHHeads`. The updates in a Commit are applied in the order they
> appear: each entry replaces the entry with the same `scid`, or is
> inserted at its place in the sort order. An update that does not decode,
> or whose entries are not sorted, is invalid.

In **§Expected Heads**, replace "A Commit that changes the expected value
MUST therefore include a GroupContextExtensions proposal that sets it" with:

> A Commit that changes the expected value MUST therefore include
> AppDataUpdate proposals for `did_webvh_heads` that set it. A committer
> can send the whole record or only the entries that change, and an
> AppDataUpdate from another member, such as a device that sends its new
> log as an Update proposal, can be committed with it.

In **§Rules**, replace the external-Commit bullet with:

> * An external Commit can carry AppDataUpdate proposals
>   ({{Section 4.7 of I-D.ietf-mls-extensions}}), so a device whose log is
>   newer than the recorded head, or a new user, can join by external
>   Commit and set its own entry, subject to the same rules.

In **§Revoking a Device**, step 2: "...together with Remove proposals for
the revoked device's leaves and an AppDataUpdate proposal that updates
`did_webvh_heads`."

**Open Issue 5**, if the change is made:

> 5. Cost of GroupContextExtensions. (Resolved in -01.) The record was a
>    GroupContext extension changed by a GroupContextExtensions proposal,
>    of which a Commit may hold only one, so a pending
>    GroupContextExtensions proposal from another party blocked every
>    record change, including the Update-proposal fallback. As an
>    `app_data_dictionary` component the record is changed by
>    AppDataUpdate proposals, which a Commit may hold alongside a
>    GroupContextExtensions proposal and alongside each other. An
>    implementation confirmed that the blocked cases now succeed.

If -01 keeps the extension, Open Issue 5 should say what was found:

> 5. Cost of GroupContextExtensions. Because a GroupContextExtensions
>    proposal replaces the whole extension list and only one is allowed
>    per Commit, a pending GroupContextExtensions proposal from another
>    party cannot be combined with a change to the record, and the
>    Update-proposal fallback is blocked the same way. An implementation
>    that carried the record as an `app_data_dictionary` component
>    instead, changed by AppDataUpdate proposals
>    ({{I-D.ietf-mls-extensions}}), committed a revocation and the
>    fallback with such a proposal pending, combined two record changes
>    in one Commit, and let a device join by external Commit.

Open Issue 1 then becomes the question of whether to keep the extension
form at all, for groups that do not use mls-extensions.

**IANA:** replace the "MLS Extension Types" entry with one in the "MLS
Component Types" registry (mls-extensions-11 §7.5): Value TBD2, Name
`did_webvh_heads`, Where `GC`, Recommended N.

## Not settled

- **Whether to keep the extension form as an alternative** for groups
  without mls-extensions. Two forms means two sets of tests and a
  negotiation question; one form means the draft needs mls-extensions.
- **The update semantics.** Replace-by-SCID (chosen) composes; a
  whole-record replacement (as mls-extensions-11 §5.1 does for its
  built-ins) is simpler but makes a by-reference partial update useless.
  The WG may prefer either.
- **External senders.** Whether the draft should forbid record updates
  from external senders. They cannot change the outcome, so the spike
  allows them.
- **mls-rs.** Not checked whether mls-rs supports AppDataUpdate, so not
  checked whether a second implementation could follow.
- **Agents.** The agent's fallback logic (bead mimid-1wgh.4.81.28) was not
  rerun in component form; the mimi-mls test of the fallback stands in
  for it. A pending GCE cannot reach a mimid agent through a mimid hub
  anyway (decision mimid-1wgh.6.2), so the collision is between mimid and
  other hubs or clients.
- **Hub KeyPackage requirements** (decision mimid-1wgh.4.81.24) still ask
  for the `did_webvh_heads` extension type; in component form they would
  ask for the component in the leaf's `app_components` instead. Not
  changed.
