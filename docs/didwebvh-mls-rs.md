# did:webvh devices and an mls-rs member in one group

Bead mimid-4lp4.2. Question: can an mls-rs client share a group with a mimid
user who has two `did_webvh` devices, and what does the mls-rs side need?
Measured against stock mls-rs at rev d9af950 (the rev mimid pins, decision
mimid-1wgh.4.13), with no patches to mls-rs. The tests are in
`crates/mimi-mls/tests/didwebvh_mls_rs.rs`.

**Short answer.** Yes, until a Commit has to change the `did_webvh_heads`
record. The mls-rs application must implement an `IdentityProvider` for
credential type 0x0008 that gives each device its own identity, and must
list the record component in its leaf. mls-rs has no AppDataUpdate
(mls-extensions-11 §4.7), and mimid changes the record only by
AppDataUpdate (decisions mimid-1wgh.4.81.33, .34). RFC 9420 §12.2 requires
every member to support every proposal type in a Commit, except, per
mls-extensions-11 §4.7, members the Commit removes. So mimid's Commit that
changes the record (a new `did_webvh` user, a device with a newer log, a
revocation) also removes the mls-rs member (bead mimid-4lp4.3, decision
mimid-1wgh.4.81.37). The mls-rs member cannot parse that Commit; it stays in
the old epoch and can be added again afterwards. If the mls-rs member
claims AppDataUpdate support anyway, it is not removed, and it cannot parse
the Commit either.

## Why two BasicCredential devices fail and two did:webvh devices do not

mls-rs indexes leaves by `IdentityProvider::identity()` and refuses a second
leaf with an identity already in the tree (`MlsError::DuplicateLeafData`,
`mls-rs/src/tree_kem/tree_index.rs` 161, 176-178). `BasicIdentityProvider`
returns the BasicCredential identifier, so two devices of one mimid user
with one BasicCredential name cannot both be in a group with an mls-rs
member. RFC 9420 does not require this uniqueness. mls-rs does.

A `did_webvh` credential is per device: each device has its own
`signature_key`, which the log's head authorizes, and all of a user's devices
share the SCID. mls-rs does not interpret the credential. The application's
provider decides what the identity is. If it returns the SCID plus the
signature key, the two devices are distinct. If it returns only the SCID,
which is the draft's "the SCID of the log is the credential's identity" read
literally, mls-rs refuses the second device exactly as it refuses two
BasicCredentials with one name.

## What works (tests)

| Test | What it shows |
|---|---|
| `mls_rs_reads_the_did_webvh_credential` | mls-rs decodes a mimid KeyPackage with the credential as a custom credential 0x0008, re-encodes it byte for byte, and its data is the DIDWebVHCredential (decision mimid-1wgh.4.81.8). |
| `an_mls_rs_member_shares_a_group_with_a_two_device_did_webvh_user` | mimid device 1 creates the group and adds the mls-rs member Bob and device 2 in one Commit (no record change, since device 2 carries the recorded log). Bob joins from the Welcome. mls-rs sees two 0x0008 leaves with one SCID and distinct identities. The `app_data_dictionary` Bob holds matches hand-encoded `app_components` = [0xF013], and the record authorizes exactly the two device keys. Application messages go from each device to Bob and from Bob to each device. mls-rs processes a Commit from device 2, and mimid processes an mls-rs Commit. Epoch authenticator and exporter secret agree after every epoch. |
| `mls_rs_adds_the_second_device` | mls-rs itself adds device 2 (log already recorded). mimid accepts the Commit (the rules hold), device 2 joins from the mls-rs Welcome, and the secrets agree. |

## A Commit that changes the record removes the mls-rs member (tests)

Bob does not list the AppDataUpdate proposal type, which is the truth for
mls-rs. Without the removal, OpenMLS refuses to build any Commit that
changes the record (`ProposalValidationError(UnsupportedProposalType)`,
RFC 9420 §12.2). `Member::commit` therefore adds a Remove of every member
whose leaf's `capabilities.proposals` lacks 0x0008 to each Commit that
carries an AppDataUpdate of the record, and reports them in
`CommitBundle::removed_without_app_data_update`; receivers see them in
`CommitSummary::removed_without_app_data_update`, the hub in
`CommitDetail::did_webvh_removes_without_app_data_update`, and the hub
authorizes these Removes without a room-policy capability
(`crates/mimid-server/tests/hub_didwebvh.rs`).

| Test | What it shows |
|---|---|
| `a_revocation_removes_an_mls_rs_member_without_app_data_update` | Device 1 revokes device 2 with no Remove asked for. The Commit removes device 2 (the rules) and Bob (no AppDataUpdate). Dave, a mimid member, processes it, is told Bob left for lacking AppDataUpdate, and agrees with device 1 on epoch, epoch authenticator, exporter secret and tree. Device 2 sees its own removal. mls-rs cannot decode the Commit (`SerializationError`, the AppDataUpdate of component 0xF013, below), stays in the old epoch and gets `EpochNotFound` for the next message: it never sees its removal. |
| `another_members_commit_of_a_revocation_removes_an_mls_rs_member` | The Update-proposal fallback (decision mimid-1wgh.4.81.31): device 2's new log revokes device 1, Dave commits device 2's Update proposal, and his Commit also removes Bob. |
| `adding_a_new_did_webvh_user_removes_an_mls_rs_member_without_app_data_update` | Adding Carol removes Bob in the same Commit; device 1, device 2 and Carol agree. Bob is then added again with a fresh KeyPackage, a Commit that changes no record, and his secrets agree with mimid's. |
| `a_commit_without_a_record_change_removes_nobody` | An empty Commit removes no one and mls-rs processes it; a Commit that removes Bob on purpose without a record change does not report him as removed for lacking AppDataUpdate, and mls-rs processes its own removal (`CommitEffect::Removed`). |

## What fails, and why (tests)

| Test | Result |
|---|---|
| `an_identity_provider_keyed_by_scid_alone_refuses_the_second_device` | With identity = SCID, mls-rs's `join_group` fails with `DuplicateLeafData(0)`. |
| `mls_rs_cannot_process_a_commit_that_changes_the_record` | Bob lists AppDataUpdate (0x0008) even though mls-rs cannot process it, so mimid does not remove him. mimid then commits the Add of Carol with an AppDataUpdate for component 0xF013. mls-rs cannot decode the message (`SerializationError(InvalidVarIntPrefix(3))`): it reads an unknown proposal type as one `opaque<V>`, and the component ID's first byte 0xF0 has the varint prefix 0b11 that RFC 9420 §2.1.2 reserves. With another component ID it would misparse instead, and in any case it could not apply the update. Bob stays in the old epoch (`EpochNotFound` on the next message). He gets back in by a Commit that removes his stale leaf and adds a fresh KeyPackage, which changes no record. |
| `mimid_refuses_an_mls_rs_commit_that_needs_a_record_change` | mls-rs adds Carol. Without AppDataUpdate it cannot add her entry to the record, and mimid refuses the Commit (`DidWebvh(Rule(ExtensionMismatch))`, §Expected Heads). Writing the new record with a GroupContextExtensions proposal, the only GroupContext change RFC 9420 gives mls-rs, is refused too: first because `app_data_dictionary` is not in `required_capabilities` (OpenMLS, feedback item 23); with that added, because of mls-extensions-11 §4.7 (`CannotUpdateDictionaryDirectly`). |

Which Commits change the record (draft §Expected Heads): adding a
`did_webvh` user the record has not seen, adding or updating a device whose
log is newer than the record, and every revocation. Commits that change no
record work with mls-rs: application messages, empty and UpdatePath
Commits, adding or removing BasicCredential members, adding a device whose
log is already recorded, and Removes.

## What an mls-rs application must implement

1. **An `IdentityProvider`** (the test's `DidWebvhIdentityProvider`):
   - `supported_types()` includes `CredentialType::new(0x0008)`. mls-rs also
     puts this list in the client's leaf `capabilities.credentials`, which
     RFC 9420 §7.2 needs once a 0x0008 leaf is in the group (mls-rs checks it,
     `InUseCredentialTypeUnsupportedByNewLeaf`).
   - `validate_member()` decodes the custom credential's data as a
     DIDWebVHCredential, verifies the log (§Log Verification), and checks
     that the head authorizes the leaf's `signature_key` (§Binding to the
     LeafNode). The test uses mimid's `mls-didwebvh` crate for this. That
     crate has no OpenMLS dependency, so an mls-rs application can use it
     too.
   - `identity()` returns a per-device value: the SCID plus the
     `signature_key`. The SCID alone fails (above).
   - `validate_external_sender()` refuses `did_webvh` (§Binding to the
     LeafNode).
   - The trait takes `MemberValidationContext`, which mls-rs does not
     re-export, so the application also depends on `mls-rs-core`.
2. **Client configuration**: `extension_type(0x0006)` (app_data_dictionary),
   or mls-rs refuses the GroupContext (`UnsupportedGroupExtension`) and a
   leaf carrying the extension.
3. **Its leaf's `app_data_dictionary`** with an `app_components` entry that
   names the record component (mimid's default 0xF013). The GroupContext's
   list names it, so mls-extensions-11 §5 and mimid require every leaf to
   list it. Per the draft (§The Heads Component), listing it means the
   client implements the group rules.
4. **The group rules** (§Group Consistency Rules). The test does not
   implement them. mls-rs offers `IdentityProvider::validate_member` (one
   leaf, with the new GroupContext extensions) and `MlsRules::
   filter_proposals` (the current roster, GroupContext and the proposals).
   Neither shows the resulting tree, so the application would have to
   recompute it. Without the rules, the mls-rs member authenticates each
   device but does not enforce revocation.
5. **AppDataUpdate**, which an application cannot add from outside. mls-rs's
   custom-proposal API encodes and decodes a proposal it does not know as
   one `opaque<V>` (`CustomDecoder` in `mls-rs/src/group/proposal.rs`; only
   the `gsma_rcs_e2ee_feature` build changes that), so the application can
   neither parse nor emit an AppDataUpdate. It also cannot update the
   `app_data_dictionary` the GroupContext holds. That would take a change
   to mls-rs.

## What mimid or the draft could change

- **Draft: say what "identity" is.** "The SCID of the log is the
  credential's identity" names the user, not the member. Stacks that index
  members by a unique identity (mls-rs) need SCID plus `signature_key`.
  Feedback item 30.
- **Draft: the component form needs AppDataUpdate in every member.**
  mls-extensions-11 §4.7 already says that changing the dictionary requires
  every member that processes the Commit to support AppDataUpdate. A member
  without it blocks revocation. The draft could require a client that lists
  `did_webvh` to also list the AppDataUpdate proposal type, and a group that
  carries the record could list AppDataUpdate in `required_capabilities`
  `proposal_types`, so that such a member cannot be added in the first
  place. Feedback item 31.
- **mimid** adds a member whose leaf lacks AppDataUpdate to a group with
  the record, and removes it in the next Commit that changes the record
  (Mark, bead mimid-4lp4.3; decision mimid-1wgh.4.81.37). The user stays in
  `participant_list`, as after a kick of one client, so it can rejoin
  without a new invitation; room-policy role constraints still apply to
  that Commit. The other choices were to refuse such a member in a
  `did_webvh` group, or to write AppDataUpdate into
  `required_capabilities` (decision mimid-1wgh.4.81.33 dropped
  `required_capabilities`). Only the record triggers the removal. In a
  MIMI room, `participant_list` and room-policy changes are AppDataUpdates
  too, and OpenMLS still refuses them while such a member is in the room.
- **The extension form would not help.** The draft's earlier form (record
  as its own GroupContext extension, changed by GroupContextExtensions) uses
  only RFC 9420 proposals, which mls-rs processes. But it brings back Open
  Issue 5 and feedback items 18, 24 and 28, which the component form fixed
  (item 29). The better fix is AppDataUpdate in mls-rs.

## Not tested

- An mls-rs member removed through a real hub. The agent's notice of the
  removal (bead mimid-4lp4.4) is tested end to end with a plain OpenMLS
  client lacking AppDataUpdate in its place
  (`crates/mimid-agent-jmap/tests/removal_notice.rs`).
- An mls-rs client creating a `did_webvh` group: it could set the record and
  `app_components` in the initial GroupContext without any proposal.
- mls-rs and mimid both using a `did_webvh` credential for the mls-rs member
  (the tests give Bob a BasicCredential).
- External Commits by the mls-rs member.
- A device rotating its `signature_key`: with the per-device identity, that
  changes the device's mls-rs identity, which mls-rs allows on an Update
  (it removes the old index entry and inserts the new one).
