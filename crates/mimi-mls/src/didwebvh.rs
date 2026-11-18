//! The `did_webvh` credential (draft-atwood-mls-didwebvh-credential-00) in
//! OpenMLS groups.
//!
//! [`mls_didwebvh`] holds the credential, its log verification and the
//! group rules over abstract leaves. This module maps OpenMLS leaves,
//! GroupContexts and staged Commits onto them, for [`Member`] and the
//! [`Observer`]:
//!
//! - every LeafNode that enters a group (KeyPackage, Add, Update, UpdatePath,
//!   a Welcome's or GroupInfo's tree) with a `did_webvh` credential has its
//!   log verified and bound to its `signature_key` (§Log Verification,
//!   §Binding to the LeafNode);
//! - an Update or UpdatePath leaf that replaces a `did_webvh` leaf must be a
//!   valid successor (§Successor Credentials);
//! - every Commit is checked against the tree and GroupContext it leads to
//!   (§Group Consistency Rules), and a joiner checks what it receives;
//! - the `did_webvh_heads` record is never removed once present, the
//!   GroupContext's `app_components` list names it whenever it is present,
//!   and no `did_webvh` credential appears in `external_senders`.
//!
//! # The record as a component
//!
//! The draft carries the record as a GroupContext extension set by a
//! GroupContextExtensions proposal. mimid carries the same `DIDWebVHHeads`
//! bytes as the entry [`CodePoints::heads_component`] of the GroupContext
//! `app_data_dictionary` extension, changed by AppDataUpdate proposals
//! (mls-extensions-11 §4.6, §4.7; decision mimid-1wgh.4.81.33, Mark
//! 2026-11-18, bead mimid-1wgh.4.81.34). INVENTED, NOT FROM SPEC:
//!
//! - this module is the component's application logic, as mimi-mls is for
//!   the mls-extensions-11 §5.1 built-ins, so the callers' `apply` functions
//!   never see it;
//! - each `update` is a `DIDWebVHHeads` whose entries replace or add the
//!   entries for the same SCIDs, applied in Commit order
//!   ([`apply_heads_updates`]); a `remove` is invalid;
//! - the GroupContext's `app_components` list names the component, which
//!   makes every member list it in its leaf (mls-extensions-11 §5), the job
//!   the draft gives `required_capabilities`; no `required_capabilities`
//!   is written;
//! - an external Commit may set the record, which the draft's §Rules
//!   forbid (its Open Issue 1).
//!
//! [`Member::commit`](crate::member::Member::commit) computes the record a
//! Commit must set (§Expected Heads) and the leaves it must remove, and adds
//! the AppDataUpdate proposals and the Removes itself (decision
//! mimid-1wgh.4.81.17). Creating a group with a `did_webvh` identity puts
//! its record, and `app_components` naming it, in the first GroupContext.
//!
//! # Limitations
//!
//! - The credential is carried inside an `opaque<V>`, not as the draft
//!   writes it (decision mimid-1wgh.4.81.8).
//! - The record is a component, not the draft's extension (above): a peer
//!   that implements the draft as written does not interoperate.
//! - The cipher suite is not checked here: mimi-mls supports only suite 1,
//!   whose signature scheme is Ed25519, as the draft requires.
//! - The record is not carried across ReInit or branches (Open Issue 2), and
//!   no proposal carries a newer log as evidence (Open Issue 3).
//! - A pending AppDataUpdate that records an SCID with no leaf cannot be
//!   undone by a later update (entries are never removed), so every Commit
//!   that covers it fails (decision mimid-1wgh.4.65).
//! - Verified logs are cached in memory by credential bytes, up to 4,096,
//!   and the cache starts over when full.
//!
//! [`Member`]: crate::member::Member
//! [`Observer`]: crate::observer::Observer

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use mls_didwebvh::rules::{self, Leaf, RuleError};
use mls_didwebvh::{
    CodePoints, DecodeError, DidWebvhCredential, DidWebvhHeads, LogError, VerifiedLog,
    verify_credential,
};
use openmls::component::ComponentsList;
use openmls::group::StagedCommit;
use openmls::messages::proposals::{AppDataUpdateOperation, Proposal};
use openmls::prelude::{
    Credential, CredentialType, Extensions, GroupContext, LeafNode, LeafNodeIndex, PublicGroup,
};
use tls_codec::{Deserialize, Serialize};

use crate::identity::APP_COMPONENTS;
use crate::member::AppDataUpdate;

/// Why a `did_webvh` check failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DidWebvhError {
    /// A `did_webvh` credential's content is not a `DIDWebVHCredential`
    /// (carried inside `opaque<V>`, decision mimid-1wgh.4.81.8).
    #[error("the did_webvh credential does not decode")]
    Credential(#[source] DecodeError),
    /// A `did_webvh` credential's log does not verify (§Log Verification).
    #[error("the did_webvh credential's log does not verify")]
    Log(#[source] LogError),
    /// A group rule, or the binding to the LeafNode, fails.
    #[error("a did_webvh rule fails")]
    Rule(#[source] RuleError),
    /// The GroupContext's `did_webvh_heads` record, or an AppDataUpdate
    /// for it, does not decode (decision mimid-1wgh.4.81.13).
    #[error("the did_webvh_heads record does not decode")]
    Heads(#[source] DecodeError),
    /// The GroupContext holds the record but its `app_components` list does
    /// not name the record's component, or the list does not decode; or an
    /// external joiner would have to add the component to the list
    /// (decision mimid-1wgh.4.81.33).
    #[error("the did_webvh_heads component is not in the GroupContext's app_components")]
    HeadsNotListed,
    /// A `did_webvh` credential is in `external_senders` (§Binding to the
    /// LeafNode).
    #[error("a did_webvh credential is in external_senders")]
    ExternalSender,
    /// The Commit or proposal removes the record (§The Heads Extension: "a
    /// group that carries it MUST NOT remove it").
    #[error("the record did_webvh_heads is removed")]
    HeadsRemoved,
    /// An Update or UpdatePath LeafNode replaces a `did_webvh` credential
    /// with one that is not a valid successor (§Successor Credentials), or
    /// changes between `did_webvh` and another credential type (decision
    /// mimid-1wgh.4.81.15).
    #[error("the new credential is not a valid successor of the leaf's credential")]
    NotASuccessor,
    /// The Commit would have to remove the committer's own leaf, which its
    /// new record no longer authorizes; another member has to commit it
    /// (§Rules; RFC 9420 §12.2).
    #[error("the record this Commit sets no longer authorizes the committer's own leaf")]
    CommitterUnauthorized,
    /// A leaf this Commit adds is not authorized by the record it sets.
    #[error("an added member is not authorized by the record")]
    AddedUnauthorized,
    /// The identity has no `did_webvh` credential, or one for other code
    /// points.
    #[error("the identity holds no did_webvh credential for these code points")]
    NoCredential,
    /// The new credential does not authorize the identity's own signature
    /// key.
    #[error("the credential does not authorize this identity's signature key")]
    NotAuthorized,
}

/// How many verified logs a [`LogCache`] keeps before it starts over.
const LOG_CACHE_CAPACITY: usize = 4096;

/// Verified logs by credential content, so that a log shared by several
/// leaves, or seen again in the next Commit, is verified once (draft
/// §Resource Use: "Implementations SHOULD verify a log shared by several
/// leaves once"). Verification is a pure function of the bytes, so a hit
/// gives the same answer a fresh verification would.
#[derive(Default)]
pub(crate) struct LogCache {
    logs: HashMap<Vec<u8>, Arc<VerifiedLog>>,
}

impl LogCache {
    /// The verified log of `credential`, or `None` if it is not a
    /// `did_webvh` credential.
    pub(crate) fn verify(
        &mut self,
        code_points: CodePoints,
        credential: &Credential,
    ) -> Result<Option<Arc<VerifiedLog>>, DidWebvhError> {
        if credential.credential_type() != CredentialType::from(code_points.credential_type()) {
            return Ok(None);
        }
        let content = credential.serialized_content();
        if let Some(log) = self.logs.get(content) {
            return Ok(Some(Arc::clone(log)));
        }
        let decoded = DidWebvhCredential::decode(content).map_err(DidWebvhError::Credential)?;
        let log = Arc::new(verify_credential(&decoded).map_err(DidWebvhError::Log)?);
        if self.logs.len() >= LOG_CACHE_CAPACITY {
            self.logs.clear();
        }
        self.logs.insert(content.to_vec(), Arc::clone(&log));
        Ok(Some(log))
    }

    /// Verifies `leaf`'s credential and its binding to the leaf's
    /// `signature_key`. Returns the log, or `None` for another credential
    /// type.
    pub(crate) fn verify_leaf(
        &mut self,
        code_points: CodePoints,
        leaf: &LeafNode,
    ) -> Result<Option<Arc<VerifiedLog>>, DidWebvhError> {
        let Some(log) = self.verify(code_points, leaf.credential())? else {
            return Ok(None);
        };
        rules::check_binding(leaf.signature_key().as_slice(), &log).map_err(DidWebvhError::Rule)?;
        Ok(Some(log))
    }
}

/// The `did_webvh` credential `credential` as an OpenMLS credential.
pub(crate) fn openmls_credential(
    code_points: CodePoints,
    credential: &DidWebvhCredential,
) -> Result<Credential, mls_didwebvh::EncodeError> {
    Ok(Credential::new(
        CredentialType::from(code_points.credential_type()),
        credential.encode()?,
    ))
}

/// The GroupContext's `did_webvh_heads` record, the `app_data_dictionary`
/// entry [`CodePoints::heads_component`], strictly decoded, or `None` when
/// it has none.
pub(crate) fn heads(
    code_points: CodePoints,
    extensions: &Extensions<GroupContext>,
) -> Result<Option<DidWebvhHeads>, DidWebvhError> {
    extensions
        .app_data_dictionary()
        .and_then(|extension| extension.dictionary().get(&code_points.heads_component()))
        .map(|data| DidWebvhHeads::decode(data).map_err(DidWebvhError::Heads))
        .transpose()
}

/// The GroupContext's `app_components` list (mls-extensions-11 §5),
/// strictly decoded; empty when absent.
fn listed_components(extensions: &Extensions<GroupContext>) -> Result<Vec<u16>, DidWebvhError> {
    extensions
        .app_data_dictionary()
        .and_then(|extension| extension.dictionary().get(&APP_COMPONENTS))
        .map(|data| {
            ComponentsList::tls_deserialize_exact(data)
                .map(ComponentsList::into_ids)
                .map_err(|_| DidWebvhError::HeadsNotListed)
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

/// The application logic (mls-extensions-11 §4.7) of the record
/// component: each `update` is a `DIDWebVHHeads` whose entries replace or
/// add the entries for the same SCIDs, applied in Commit order to `current`
/// (empty when absent). The rules then require the result to be the
/// expected record, so a committer may send the whole record or only the
/// entries it changes, and updates from several proposers compose.
///
/// INVENTED, NOT FROM SPEC (decision mimid-1wgh.4.81.33). A `remove` of
/// the component is invalid: the record is never removed (§The Heads
/// Extension); the caller refuses it.
pub(crate) fn apply_heads_updates(
    current: Option<&[u8]>,
    updates: &[&[u8]],
) -> Result<Vec<u8>, DidWebvhError> {
    let mut record = match current {
        Some(data) => DidWebvhHeads::decode(data).map_err(DidWebvhError::Heads)?,
        None => DidWebvhHeads::new(),
    };
    for update in updates {
        let entries = DidWebvhHeads::decode(update).map_err(DidWebvhError::Heads)?;
        for head in entries.heads() {
            record.insert(head.clone());
        }
    }
    record
        .encode()
        .map_err(|_| DidWebvhError::Heads(DecodeError::Invalid("record too large")))
}

/// The AppDataUpdate operations that set the record to `heads` in a group
/// whose GroupContext extensions are `current`. The whole record is sent
/// (the update semantics of [`apply_heads_updates`] would also take only
/// the changed entries). If the GroupContext's `app_components` list does
/// not name the component yet, it is extended too, since a GroupContext
/// may hold state only for a listed component (mls-extensions-11 §5);
/// listing it is what makes every member support the draft, the job the
/// draft gives `required_capabilities`.
pub(crate) fn record_updates(
    code_points: CodePoints,
    current: &Extensions<GroupContext>,
    heads: &DidWebvhHeads,
) -> Result<Vec<AppDataUpdate>, DidWebvhError> {
    let component_id = code_points.heads_component();
    let invalid = |what| DidWebvhError::Heads(DecodeError::Invalid(what));
    let mut updates = Vec::with_capacity(2);
    let listed = listed_components(current)?;
    if !listed.contains(&component_id) {
        let mut ids = listed;
        ids.push(component_id);
        updates.push(AppDataUpdate::Update {
            component_id: APP_COMPONENTS,
            update: ComponentsList::new(ids)
                .tls_serialize_detached()
                .map_err(|_| invalid("app_components"))?,
        });
    }
    updates.push(AppDataUpdate::Update {
        component_id,
        update: heads.encode().map_err(|_| invalid("record too large"))?,
    });
    Ok(updates)
}

/// The credential type of an `ExternalSender`. OpenMLS keeps its getters
/// private, so it is read from the encoding: `SignaturePublicKey
/// signature_key<V>` then `Credential`, whose first two bytes are the type.
fn external_sender_credential_type(sender: &openmls::extensions::ExternalSender) -> Option<u16> {
    let bytes = sender.tls_serialize_detached().ok()?;
    let first = *bytes.first()?;
    let (length, prefix) = match first >> 6 {
        0 => (usize::from(first), 1),
        1 => (
            usize::from(first & 0x3f) << 8 | usize::from(*bytes.get(1)?),
            2,
        ),
        2 => {
            let b = bytes.get(..4)?;
            (
                usize::from(first & 0x3f) << 24
                    | usize::from(b[1]) << 16
                    | usize::from(b[2]) << 8
                    | usize::from(b[3]),
                4,
            )
        }
        _ => return None,
    };
    let at = prefix + length;
    let type_bytes = bytes.get(at..at + 2)?;
    Some(u16::from_be_bytes([type_bytes[0], type_bytes[1]]))
}

/// The GroupContext rules that do not depend on the tree: no `did_webvh`
/// credential in `external_senders`, and `app_components` naming the
/// record's component whenever the record is present. Returns the record.
///
/// mls-extensions-11 §5 already makes a GroupContext invalid that holds
/// state for an unlisted component (checked with every GroupContext by
/// `member::required_lists`); this checks it again for the record, so that
/// the rule does not depend on the order of the checks.
pub(crate) fn check_group_context(
    code_points: CodePoints,
    extensions: &Extensions<GroupContext>,
) -> Result<Option<DidWebvhHeads>, DidWebvhError> {
    if let Some(senders) = extensions.external_senders()
        && senders
            .iter()
            .any(|s| external_sender_credential_type(s) == Some(code_points.credential_type()))
    {
        return Err(DidWebvhError::ExternalSender);
    }
    let heads = heads(code_points, extensions)?;
    if heads.is_some() && !listed_components(extensions)?.contains(&code_points.heads_component()) {
        return Err(DidWebvhError::HeadsNotListed);
    }
    Ok(heads)
}

/// One leaf of the tree a staged Commit leads to.
pub(crate) struct ResultingLeaf<'a> {
    /// The LeafNode.
    pub(crate) leaf: &'a LeafNode,
    /// Its index before the Commit, for a leaf that was already there
    /// (unchanged or replaced); `None` for an added leaf.
    pub(crate) index: Option<LeafNodeIndex>,
    /// The LeafNode it replaces, for an Update or UpdatePath leaf.
    pub(crate) replaces: Option<&'a LeafNode>,
    /// Whether the leaf is new in this Commit (added, updated or the
    /// UpdatePath leaf) rather than kept unchanged.
    pub(crate) changed: bool,
}

/// The leaves of the epoch `staged` leads to, from `current` (the group
/// before it) and the Commit's proposals and UpdatePath. `committer` is the
/// committer's leaf, `None` for an external Commit.
pub(crate) fn resulting_leaves<'a>(
    staged: &'a StagedCommit,
    current: &'a PublicGroup,
    committer: Option<LeafNodeIndex>,
) -> Vec<ResultingLeaf<'a>> {
    let mut leaves: BTreeMap<LeafNodeIndex, ResultingLeaf<'a>> = current
        .members()
        .filter_map(|member| {
            let leaf = current.leaf(member.index)?;
            Some((
                member.index,
                ResultingLeaf {
                    leaf,
                    index: Some(member.index),
                    replaces: None,
                    changed: false,
                },
            ))
        })
        .collect();
    let mut added = Vec::new();
    for queued in staged.queued_proposals() {
        let sender = match queued.sender() {
            openmls::prelude::Sender::Member(index) => Some(*index),
            _ => None,
        };
        match queued.proposal() {
            Proposal::Remove(remove) => {
                leaves.remove(&remove.removed());
            }
            Proposal::SelfRemove => {
                if let Some(index) = sender {
                    leaves.remove(&index);
                }
            }
            Proposal::Update(update) => {
                if let Some(index) = sender
                    && let Some(slot) = leaves.get_mut(&index)
                {
                    slot.replaces = Some(slot.leaf);
                    slot.leaf = update.leaf_node();
                    slot.changed = true;
                }
            }
            Proposal::Add(add) => added.push(ResultingLeaf {
                leaf: add.key_package().leaf_node(),
                index: None,
                replaces: None,
                changed: true,
            }),
            _ => {}
        }
    }
    if let Some(path_leaf) = staged.update_path_leaf_node() {
        match committer.and_then(|index| leaves.get_mut(&index)) {
            Some(slot) => {
                slot.replaces.get_or_insert(slot.leaf);
                slot.leaf = path_leaf;
                slot.changed = true;
            }
            None => added.push(ResultingLeaf {
                leaf: path_leaf,
                index: None,
                replaces: None,
                changed: true,
            }),
        }
    }
    leaves.into_values().chain(added).collect()
}

/// What a Commit must change to satisfy the rules: the record to set, if
/// it differs from the one the Commit leads to, and the leaves (by index
/// before the Commit) it must also remove.
pub(crate) struct Plan {
    pub(crate) heads: Option<DidWebvhHeads>,
    pub(crate) removes: Vec<LeafNodeIndex>,
}

/// The verified did_webvh leaves among `leaves`, with every changed leaf's
/// log verified and bound, and successors checked.
fn did_leaves(
    code_points: CodePoints,
    cache: &mut LogCache,
    leaves: &[ResultingLeaf<'_>],
) -> Result<Vec<(usize, Arc<VerifiedLog>)>, DidWebvhError> {
    let did_type = CredentialType::from(code_points.credential_type());
    let mut out = Vec::new();
    for (i, leaf) in leaves.iter().enumerate() {
        let log = if leaf.changed {
            cache.verify_leaf(code_points, leaf.leaf)?
        } else {
            cache.verify(code_points, leaf.leaf.credential())?
        };
        if let Some(old) = leaf.replaces {
            let old_is_did = old.credential().credential_type() == did_type;
            match (&log, old_is_did) {
                (Some(new_log), true) => {
                    let old_log = cache
                        .verify(code_points, old.credential())?
                        .ok_or(DidWebvhError::NotASuccessor)?;
                    if !rules::is_valid_successor(&old_log, new_log) {
                        return Err(DidWebvhError::NotASuccessor);
                    }
                }
                (None, false) => {}
                _ => return Err(DidWebvhError::NotASuccessor),
            }
        }
        if let Some(log) = log {
            out.push((i, log));
        }
    }
    Ok(out)
}

fn as_rule_leaves<'a>(
    leaves: &'a [ResultingLeaf<'a>],
    logs: &'a [(usize, Arc<VerifiedLog>)],
) -> Vec<Leaf<'a>> {
    logs.iter()
        .filter_map(|(i, log)| {
            Some(Leaf {
                signature_key: leaves.get(*i)?.leaf.signature_key().as_slice(),
                log,
            })
        })
        .collect()
}

/// §Group Consistency Rules for a Commit: checks the epoch `staged` leads
/// to against `current`, the group before it.
pub(crate) fn check_staged(
    code_points: CodePoints,
    cache: &mut LogCache,
    staged: &StagedCommit,
    current: &PublicGroup,
    committer: Option<LeafNodeIndex>,
) -> Result<(), DidWebvhError> {
    let leaves = resulting_leaves(staged, current, committer);
    let logs = did_leaves(code_points, cache, &leaves)?;
    let previous = heads(code_points, current.group_context().extensions())?;
    let resulting = check_group_context(code_points, staged.group_context().extensions())?;
    if previous.is_some() && resulting.is_none() {
        return Err(DidWebvhError::HeadsRemoved);
    }
    rules::check_commit(
        &previous.unwrap_or_default(),
        &resulting.unwrap_or_default(),
        &as_rule_leaves(&leaves, &logs),
    )
    .map_err(DidWebvhError::Rule)
}

/// The Removes of `staged` that the group rules require: each Remove of a
/// leaf whose SCID is a vouching SCID and whose signature key the record
/// the same Commit sets for that SCID does not authorize (§Rules,
/// Authorization; §Revoking a Device). The vouching SCIDs are the
/// committer's, and that of the new LeafNode of each Update proposal the
/// Commit includes: a device whose new log revokes another device of its
/// user, committed by another member because it could not commit itself
/// (decision mimid-1wgh.4.81.31; an Update is always by reference, so it
/// is that user's own signed request). Leaf indices are those before the
/// Commit. Empty if the Commit carries no AppDataUpdate of the record
/// component (it then sets no record) or there is no vouching SCID.
///
/// A hub uses this to authorize those Removes without a room-policy
/// capability (decisions mimid-1wgh.4.81.26 and .31). Call it only on a
/// Commit that [`check_staged`] accepted, so the record is the expected
/// one.
pub(crate) fn required_removes(
    code_points: CodePoints,
    staged: &StagedCommit,
    current: &PublicGroup,
    committer: LeafNodeIndex,
) -> Vec<u32> {
    let mut vouching: Vec<String> = current
        .leaf(committer)
        .and_then(|leaf| scid_of(code_points, leaf.credential()))
        .into_iter()
        .collect();
    for queued in staged.queued_proposals() {
        if let Proposal::Update(update) = queued.proposal()
            && let Some(scid) = scid_of(code_points, update.leaf_node().credential())
            && !vouching.contains(&scid)
        {
            vouching.push(scid);
        }
    }
    if vouching.is_empty() {
        return Vec::new();
    }
    let sets_record = staged.queued_proposals().any(|queued| {
        matches!(queued.proposal(), Proposal::AppDataUpdate(update)
            if update.component_id() == code_points.heads_component())
    });
    if !sets_record {
        return Vec::new();
    }
    let Ok(Some(record)) = heads(code_points, staged.group_context().extensions()) else {
        return Vec::new();
    };
    staged
        .queued_proposals()
        .filter_map(|queued| match queued.proposal() {
            Proposal::Remove(remove) => Some(remove.removed()),
            _ => None,
        })
        .filter(|&removed| {
            current.leaf(removed).is_some_and(|leaf| {
                scid_of(code_points, leaf.credential()).is_some_and(|scid| {
                    vouching.contains(&scid)
                        && record
                            .get(&scid)
                            .is_some_and(|head| !head.authorizes(leaf.signature_key().as_slice()))
                })
            })
        })
        .map(|removed| removed.u32())
        .collect()
}

/// For a Commit being built: what it must change, given the epoch it
/// leads to as staged so far.
pub(crate) fn plan(
    code_points: CodePoints,
    cache: &mut LogCache,
    staged: &StagedCommit,
    current: &PublicGroup,
    committer: LeafNodeIndex,
) -> Result<Plan, DidWebvhError> {
    let leaves = resulting_leaves(staged, current, Some(committer));
    let logs = did_leaves(code_points, cache, &leaves)?;
    let previous = heads(code_points, current.group_context().extensions())?.unwrap_or_default();
    let resulting = heads(code_points, staged.group_context().extensions())?;
    let rule_leaves = as_rule_leaves(&leaves, &logs);
    let expected = rules::expected_heads(&previous, &rule_leaves).map_err(DidWebvhError::Rule)?;
    let mut removes = Vec::new();
    for position in rules::unauthorized_leaves(&expected, &rule_leaves) {
        let Some((leaf_position, _)) = logs.get(position) else {
            continue;
        };
        match leaves.get(*leaf_position).and_then(|l| l.index) {
            Some(index) if index == committer => return Err(DidWebvhError::CommitterUnauthorized),
            Some(index) => removes.push(index),
            None => return Err(DidWebvhError::AddedUnauthorized),
        }
    }
    let unchanged = match &resulting {
        Some(resulting) => *resulting == expected,
        None => expected.is_empty(),
    };
    Ok(Plan {
        heads: (!unchanged).then_some(expected),
        removes,
    })
}

/// §Group Consistency Rules for a joiner (Welcome, or the GroupInfo of an
/// external join): every did_webvh leaf of `leaves` verified and bound,
/// the GroupContext rules, and [`rules::check_join`].
pub(crate) fn check_join<'a>(
    code_points: CodePoints,
    cache: &mut LogCache,
    extensions: &Extensions<GroupContext>,
    leaves: impl IntoIterator<Item = &'a LeafNode>,
) -> Result<(), DidWebvhError> {
    let heads = check_group_context(code_points, extensions)?.unwrap_or_default();
    let mut owned = Vec::new();
    for leaf in leaves {
        if let Some(log) = cache.verify_leaf(code_points, leaf)? {
            owned.push((leaf.signature_key().as_slice().to_vec(), log));
        }
    }
    let rule_leaves: Vec<Leaf<'_>> = owned
        .iter()
        .map(|(key, log)| Leaf {
            signature_key: key,
            log,
        })
        .collect();
    rules::check_join(&heads, &rule_leaves).map_err(DidWebvhError::Rule)
}

/// For an external join: the tree after the joiner's Commit, `leaves`
/// (signature key and credential of each existing leaf it keeps, and its
/// own), checked against the record the Commit must set. An external
/// Commit can carry an AppDataUpdate (mls-extensions-11 §4.7), so the
/// record may change: the expected record is returned when it differs from
/// the current one, for the joiner to set. INVENTED, NOT FROM SPEC
/// (decision mimid-1wgh.4.81.33): the draft's §Rules, written for the
/// GroupContext extension, forbid a newer log or a new SCID from joining
/// externally (its Open Issue 1).
pub(crate) fn check_external_join<'a>(
    code_points: CodePoints,
    cache: &mut LogCache,
    extensions: &Extensions<GroupContext>,
    leaves: impl IntoIterator<Item = (&'a [u8], &'a Credential)>,
) -> Result<Option<DidWebvhHeads>, DidWebvhError> {
    let record = check_group_context(code_points, extensions)?.unwrap_or_default();
    let mut owned = Vec::new();
    for (key, credential) in leaves {
        if let Some(log) = cache.verify(code_points, credential)? {
            rules::check_binding(key, &log).map_err(DidWebvhError::Rule)?;
            owned.push((key.to_vec(), log));
        }
    }
    let rule_leaves: Vec<Leaf<'_>> = owned
        .iter()
        .map(|(key, log)| Leaf {
            signature_key: key,
            log,
        })
        .collect();
    let expected = rules::expected_heads(&record, &rule_leaves).map_err(DidWebvhError::Rule)?;
    rules::check_commit(&record, &expected, &rule_leaves).map_err(DidWebvhError::Rule)?;
    Ok((expected != record).then_some(expected))
}

/// The leaf of a standalone Add or Update proposal, verified and bound;
/// a GroupContextExtensions proposal that would put a `did_webvh`
/// credential in `external_senders` is refused (§Binding to the LeafNode),
/// and so is an AppDataUpdate proposal for the record that removes it or
/// does not decode as a `DIDWebVHHeads` (decision mimid-1wgh.4.81.33), as
/// a Commit covering it would be.
pub(crate) fn check_proposal(
    code_points: CodePoints,
    cache: &mut LogCache,
    proposal: &Proposal,
) -> Result<(), DidWebvhError> {
    match proposal {
        Proposal::Add(add) => {
            cache.verify_leaf(code_points, add.key_package().leaf_node())?;
        }
        Proposal::Update(update) => {
            cache.verify_leaf(code_points, update.leaf_node())?;
        }
        Proposal::GroupContextExtensions(gce) => {
            if let Some(senders) = gce.extensions().external_senders()
                && senders.iter().any(|s| {
                    external_sender_credential_type(s) == Some(code_points.credential_type())
                })
            {
                return Err(DidWebvhError::ExternalSender);
            }
        }
        Proposal::AppDataUpdate(update)
            if update.component_id() == code_points.heads_component() =>
        {
            match update.operation() {
                AppDataUpdateOperation::Update(data) => {
                    DidWebvhHeads::decode(data.as_slice()).map_err(DidWebvhError::Heads)?;
                }
                AppDataUpdateOperation::Remove => return Err(DidWebvhError::HeadsRemoved),
            }
        }
        _ => {}
    }
    Ok(())
}

/// Whether a KeyPackage meets what a protocol-07 §5.2 keyMaterial request
/// asks of it for `did_webvh`: when `required` lists the `did_webvh`
/// credential type, the KeyPackage's LeafNode must also list the record
/// component in its `app_components`, or no `did_webvh` room could add it
/// (mls-extensions-11 §5). True when `required` does not list `did_webvh`,
/// or does not decode (which [`VerifiedKeyPackageInfo::satisfies`] then
/// refuses).
///
/// A keyMaterial request has no field for required components, so the
/// component is implied by the credential type: a client that lists
/// `did_webvh` implements the draft, and so lists the record (decision
/// mimid-1wgh.4.81.36). A target provider applies this next to
/// [`VerifiedKeyPackageInfo::satisfies`], and a requester to the
/// KeyPackages it gets back.
///
/// [`VerifiedKeyPackageInfo::satisfies`]: crate::wire::VerifiedKeyPackageInfo::satisfies
pub fn key_package_lists_record(
    info: &crate::wire::VerifiedKeyPackageInfo,
    required: &crate::wire::RequiredCapabilities,
    code_points: CodePoints,
) -> bool {
    let Ok(required) =
        openmls::prelude::RequiredCapabilitiesExtension::tls_deserialize_exact(required.as_bytes())
    else {
        return true;
    };
    !required
        .credential_types()
        .contains(&CredentialType::from(code_points.credential_type()))
        || info
            .app_components()
            .contains(&code_points.heads_component())
}

/// The MIMI user URI a verified log names: the one entry of its head DID
/// document's `alsoKnownAs` whose scheme is `mimi` (ASCII case-insensitive),
/// or `None` if there is none or more than one.
///
/// INVENTED, NOT FROM SPEC (decision mimid-1wgh.4.81.21): the draft makes
/// the SCID the credential's identity (§Binding to the LeafNode) and does
/// not say how an application ties it to its own name for the user. MIMI
/// names users by URI, so mimid has the controller list the user URI there;
/// the user's update keys sign it, so a provider cannot rebind the SCID.
/// The URI is returned as written; whether it is a well-formed user URI is
/// the caller's check.
pub fn mimi_user_uri(log: &VerifiedLog) -> Option<&str> {
    only_mimi_uri(log.head_also_known_as().into_iter())
}

/// The one `mimi:` URI among `entries`, or `None` if there is none or more
/// than one.
fn only_mimi_uri<'a>(mut entries: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let is_mimi = |entry: &&str| {
        entry
            .get(..5)
            .is_some_and(|s| s.eq_ignore_ascii_case("mimi:"))
    };
    let first = entries.by_ref().find(is_mimi)?;
    entries.find(is_mimi).is_none().then_some(first)
}

/// [`mimi_user_uri`] of a `did_webvh` credential already verified, read
/// from the last entry's DID document without verifying again, or `None`
/// for another credential type or when the log names no single user URI.
pub(crate) fn user_uri_of(code_points: CodePoints, credential: &Credential) -> Option<String> {
    if credential.credential_type() != CredentialType::from(code_points.credential_type()) {
        return None;
    }
    let decoded = DidWebvhCredential::decode(credential.serialized_content()).ok()?;
    // §did:webvh Profile: every line ends in LF, so the head is the last
    // non-empty piece.
    let head = decoded
        .did_log()
        .split(|&b| b == b'\n')
        .rfind(|line| !line.is_empty())?;
    let entry: serde_json::Value = serde_json::from_slice(head).ok()?;
    let entries = entry["state"]["alsoKnownAs"].as_array()?;
    only_mimi_uri(entries.iter().filter_map(serde_json::Value::as_str)).map(str::to_owned)
}

/// The DID of a `did_webvh` credential already verified: the `id` of its
/// last entry's DID document (§Reference Identifiers: applications SHOULD
/// display the DID string), read without verifying again; `None` for
/// another credential type.
pub(crate) fn did_of(code_points: CodePoints, credential: &Credential) -> Option<String> {
    if credential.credential_type() != CredentialType::from(code_points.credential_type()) {
        return None;
    }
    let decoded = DidWebvhCredential::decode(credential.serialized_content()).ok()?;
    let head = decoded
        .did_log()
        .split(|&b| b == b'\n')
        .rfind(|line| !line.is_empty())?;
    let entry: serde_json::Value = serde_json::from_slice(head).ok()?;
    entry["state"]["id"].as_str().map(str::to_owned)
}

/// The SCID of a `did_webvh` credential already verified, read from the
/// first entry's `scid` parameter without verifying again.
pub(crate) fn scid_of(code_points: CodePoints, credential: &Credential) -> Option<String> {
    if credential.credential_type() != CredentialType::from(code_points.credential_type()) {
        return None;
    }
    let decoded = DidWebvhCredential::decode(credential.serialized_content()).ok()?;
    let first = decoded.did_log().split(|&b| b == b'\n').next()?;
    let entry: serde_json::Value = serde_json::from_slice(first).ok()?;
    entry["parameters"]["scid"].as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use mls_didwebvh::DidWebvhHead;
    use mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
    use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension, Extension};

    use super::*;

    const CP: CodePoints = CodePoints::DEFAULT;

    /// A user's log listing one device, and the head of each version:
    /// `heads[0]` is v1, `heads[1]` v2.
    fn heads_of(name: &str, seed: u8) -> Vec<DidWebvhHead> {
        let signer = UpdateKey::from_seed(&[seed; 32]);
        let mut log = DidLog::create(
            "example.com",
            name,
            "2026-11-20T09:00:00Z",
            &Parameters {
                update_keys: Some(vec![signer.multikey()]),
                next_key_hashes: None,
            },
            &signer,
            &[[seed; 32]],
        )
        .expect("log");
        let v1 = DidWebvhHead::from_log(log.verified());
        log.append(
            "2026-11-20T09:00:01Z",
            &Parameters::default(),
            &signer,
            &[[seed; 32], [seed ^ 0xff; 32]],
        )
        .expect("append");
        vec![v1, DidWebvhHead::from_log(log.verified())]
    }

    fn record(heads: &[&DidWebvhHead]) -> Vec<u8> {
        let mut record = DidWebvhHeads::new();
        for head in heads {
            record.insert((*head).clone());
        }
        record.encode().expect("encode")
    }

    /// Decision mimid-1wgh.4.81.33: an update replaces the entries of its
    /// SCIDs and keeps the others; updates apply in order, so the later
    /// one for an SCID wins; a full record is an update too.
    #[test]
    fn record_updates_replace_or_add_entries_by_scid_in_order() {
        let alice = heads_of("alice", 0x41);
        let bob = heads_of("bob", 0x42);
        let current = record(&[&alice[0], &bob[0]]);
        let applied = apply_heads_updates(Some(&current), &[&record(&[&alice[1]])])
            .expect("a partial update");
        assert_eq!(applied, record(&[&alice[1], &bob[0]]));
        let applied = apply_heads_updates(
            Some(&current),
            &[&record(&[&alice[1]]), &record(&[&bob[1], &alice[0]])],
        )
        .expect("two updates");
        assert_eq!(applied, record(&[&alice[0], &bob[1]]));
        let applied = apply_heads_updates(None, &[&record(&[&bob[1]])]).expect("the first record");
        assert_eq!(applied, record(&[&bob[1]]));
        // An empty update changes nothing: entries are never removed.
        assert_eq!(
            apply_heads_updates(Some(&current), &[&record(&[])]).expect("empty"),
            current
        );
        // An update that does not decode is invalid.
        assert!(matches!(
            apply_heads_updates(Some(&current), &[&[0x01]]),
            Err(DidWebvhError::Heads(_))
        ));
    }

    /// mls-extensions-11 §5 `ComponentsList` by hand: a one-octet varint
    /// length, then big-endian component IDs.
    #[test]
    fn the_record_must_be_named_in_app_components() {
        let alice = heads_of("alice", 0x41);
        let with = |entries: &[(u16, Vec<u8>)]| {
            let mut dictionary = AppDataDictionary::new();
            for (id, data) in entries {
                dictionary.insert(*id, data.clone());
            }
            Extensions::single(Extension::AppDataDictionary(
                AppDataDictionaryExtension::new(dictionary),
            ))
            .expect("extensions")
        };
        let listed = with(&[
            (APP_COMPONENTS, vec![0x02, 0xf0, 0x13]),
            (0xf013, record(&[&alice[0]])),
        ]);
        assert!(matches!(check_group_context(CP, &listed), Ok(Some(_))));
        let unlisted = with(&[
            (APP_COMPONENTS, vec![0x02, 0x00, 0x22]),
            (0xf013, record(&[&alice[0]])),
        ]);
        assert!(matches!(
            check_group_context(CP, &unlisted),
            Err(DidWebvhError::HeadsNotListed)
        ));
        let no_list = with(&[(0xf013, record(&[&alice[0]]))]);
        assert!(matches!(
            check_group_context(CP, &no_list),
            Err(DidWebvhError::HeadsNotListed)
        ));
        // No record: nothing to list.
        let none = with(&[(APP_COMPONENTS, vec![0x00])]);
        assert!(matches!(check_group_context(CP, &none), Ok(None)));

        // record_updates lists the component the first time only.
        let heads = DidWebvhHeads::decode(&record(&[&alice[1]])).expect("decode");
        let first = record_updates(CP, &none, &heads).expect("updates");
        assert_eq!(
            first,
            [
                AppDataUpdate::Update {
                    component_id: APP_COMPONENTS,
                    update: vec![0x02, 0xf0, 0x13],
                },
                AppDataUpdate::Update {
                    component_id: 0xf013,
                    update: record(&[&alice[1]]),
                },
            ]
        );
        let later = record_updates(CP, &listed, &heads).expect("updates");
        assert_eq!(
            later,
            [AppDataUpdate::Update {
                component_id: 0xf013,
                update: record(&[&alice[1]]),
            }]
        );
    }
}
