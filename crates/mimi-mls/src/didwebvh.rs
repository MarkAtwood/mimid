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
//! - `did_webvh_heads` is never removed once present, comes with a
//!   `required_capabilities` that lists it and `did_webvh`, and no
//!   `did_webvh` credential appears in `external_senders`.
//!
//! [`Member::commit`](crate::member::Member::commit) computes the record a
//! Commit must set (§Expected Heads) and the leaves it must remove, and adds
//! the GroupContextExtensions proposal and the Removes itself (decision
//! mimid-1wgh.4.81.17). Creating a group with a `did_webvh` identity puts
//! its record and a `required_capabilities` listing it and `did_webvh` in
//! the first GroupContext (decision mimid-1wgh.4.81.16).
//!
//! # Limitations
//!
//! - The credential is carried inside an `opaque<V>`, not as the draft
//!   writes it (decision mimid-1wgh.4.81.8).
//! - The cipher suite is not checked here: mimi-mls supports only suite 1,
//!   whose signature scheme is Ed25519, as the draft requires.
//! - The record is not carried across ReInit or branches (Open Issue 2), and
//!   no proposal carries a newer log as evidence (Open Issue 3).
//! - A GroupContextExtensions proposal already pending from another member
//!   makes a record-changing Commit fail (Open Issue 5).
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
use openmls::group::StagedCommit;
use openmls::messages::proposals::Proposal;
use openmls::prelude::{
    Credential, CredentialType, Extension, ExtensionType, Extensions, GroupContext, LeafNode,
    LeafNodeIndex, PublicGroup, RequiredCapabilitiesExtension, UnknownExtension,
};
use tls_codec::Serialize;

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
    /// The GroupContext's `did_webvh_heads` extension does not decode
    /// (decision mimid-1wgh.4.81.13).
    #[error("the did_webvh_heads extension does not decode")]
    Heads(#[source] DecodeError),
    /// The GroupContext carries `did_webvh_heads` without a
    /// `required_capabilities` extension that lists it in `extension_types`
    /// and `did_webvh` in `credential_types` (§The Heads Extension).
    #[error("did_webvh_heads without required_capabilities listing it and did_webvh")]
    RequiredCapabilities,
    /// A `did_webvh` credential is in `external_senders` (§Binding to the
    /// LeafNode).
    #[error("a did_webvh credential is in external_senders")]
    ExternalSender,
    /// The Commit removes `did_webvh_heads` from the GroupContext (§The
    /// Heads Extension: "a group that carries it MUST NOT remove it").
    #[error("the Commit removes did_webvh_heads")]
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
    /// A GroupContextExtensions proposal is already pending, and the
    /// record change needs its own (Open Issue 5 of the draft).
    #[error("a GroupContextExtensions proposal is already pending")]
    PendingGroupContextExtensions,
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

/// The GroupContext's `did_webvh_heads`, strictly decoded, or `None` when
/// it has none.
pub(crate) fn heads(
    code_points: CodePoints,
    extensions: &Extensions<GroupContext>,
) -> Result<Option<DidWebvhHeads>, DidWebvhError> {
    extensions
        .unknown(code_points.heads_extension_type())
        .map(|UnknownExtension(data)| DidWebvhHeads::decode(data).map_err(DidWebvhError::Heads))
        .transpose()
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
/// credential in `external_senders`, and `required_capabilities` listing
/// `did_webvh_heads` and `did_webvh` whenever the record is present.
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
    if heads.is_some() {
        let listed = extensions.required_capabilities().is_some_and(|rc| {
            rc.extension_types()
                .contains(&ExtensionType::from(code_points.heads_extension_type()))
                && rc
                    .credential_types()
                    .contains(&CredentialType::from(code_points.credential_type()))
        });
        if !listed {
            return Err(DidWebvhError::RequiredCapabilities);
        }
    }
    Ok(heads)
}

/// The GroupContext extensions `current` with `did_webvh_heads` set to
/// `heads` and `required_capabilities` extended, if needed, to list it and
/// `did_webvh`. Every other extension is kept as it is, as a
/// GroupContextExtensions proposal must (mls-extensions-11 §4.7 for
/// `app_data_dictionary`).
pub(crate) fn with_heads(
    code_points: CodePoints,
    current: &Extensions<GroupContext>,
    heads: &DidWebvhHeads,
) -> Result<Extensions<GroupContext>, DidWebvhError> {
    let mut extensions = current.clone();
    let data = heads
        .encode()
        .map_err(|_| DidWebvhError::Heads(DecodeError::Invalid("record too large")))?;
    let heads_type = ExtensionType::from(code_points.heads_extension_type());
    let credential_type = CredentialType::from(code_points.credential_type());
    let invalid = |_| DidWebvhError::Heads(DecodeError::Invalid("extension list"));
    extensions
        .add_or_replace(Extension::Unknown(
            code_points.heads_extension_type(),
            UnknownExtension(data),
        ))
        .map_err(invalid)?;
    let (mut extension_types, proposal_types, mut credential_types) =
        match current.required_capabilities() {
            Some(rc) => (
                rc.extension_types().to_vec(),
                rc.proposal_types().to_vec(),
                rc.credential_types().to_vec(),
            ),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
    if !extension_types.contains(&heads_type) {
        extension_types.push(heads_type);
    }
    // OpenMLS refuses a GroupContextExtensions proposal unless every
    // non-default extension it carries is listed in its
    // required_capabilities (public_group/validation.rs,
    // ExtensionNotInRequiredCapabilities), stricter than RFC 9420 §12.1.7.
    // A MIMI room carries app_data_dictionary, so it is listed too; every
    // member already supports it. Feedback item 23.
    for extension in current.iter() {
        let t = extension.extension_type();
        // RFC 9420 §7.2's default extension types, 1 to 5.
        let default = (1..=5).contains(&u16::from(t));
        if !default && t != heads_type && !extension_types.contains(&t) {
            extension_types.push(t);
        }
    }
    if !credential_types.contains(&credential_type) {
        credential_types.push(credential_type);
    }
    extensions
        .add_or_replace(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(
                &extension_types,
                &proposal_types,
                &credential_types,
            ),
        ))
        .map_err(invalid)?;
    Ok(extensions)
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
/// Commit. Empty if the Commit carries no GroupContextExtensions proposal
/// (it then sets no record) or there is no vouching SCID.
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
    let sets_record = staged
        .queued_proposals()
        .any(|queued| matches!(queued.proposal(), Proposal::GroupContextExtensions(_)));
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
/// own), checked against the unchanged record, since an external Commit
/// cannot carry a GroupContextExtensions proposal (§Rules).
pub(crate) fn check_external_join<'a>(
    code_points: CodePoints,
    cache: &mut LogCache,
    extensions: &Extensions<GroupContext>,
    leaves: impl IntoIterator<Item = (&'a [u8], &'a Credential)>,
) -> Result<(), DidWebvhError> {
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
    rules::check_commit(&record, &record, &rule_leaves).map_err(DidWebvhError::Rule)
}

/// The leaf of a standalone Add or Update proposal, verified and bound;
/// a GroupContextExtensions proposal that would put a `did_webvh`
/// credential in `external_senders` is refused (§Binding to the LeafNode).
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
        _ => {}
    }
    Ok(())
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

/// Whether `proposed`, the extensions of a GroupContextExtensions proposal,
/// differ from `current` only in what the record change needs: a
/// `did_webvh_heads` record, and a `required_capabilities` that keeps what
/// it listed and adds `did_webvh_heads`, `did_webvh`, and possibly extension
/// types the GroupContext already carries (which OpenMLS requires a
/// GroupContextExtensions proposal to list, see [`with_heads`]). A hub that
/// refuses other GroupContextExtensions proposals lets these through, since
/// the group rules require them (decision mimid-1wgh.4.81.22).
pub(crate) fn is_record_change(
    code_points: CodePoints,
    current: &Extensions<GroupContext>,
    proposed: &Extensions<GroupContext>,
) -> bool {
    let heads_type = ExtensionType::from(code_points.heads_extension_type());
    let credential_type = CredentialType::from(code_points.credential_type());
    if !matches!(heads(code_points, proposed), Ok(Some(_))) {
        return false;
    }
    // Every other extension is kept exactly.
    let others = |extensions: &Extensions<GroupContext>| {
        let mut all = extensions
            .iter()
            .filter(|e| {
                e.extension_type() != heads_type
                    && e.extension_type() != ExtensionType::RequiredCapabilities
            })
            .map(Serialize::tls_serialize_detached)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        all.sort();
        Some(all)
    };
    if !matches!((others(current), others(proposed)), (Some(a), Some(b)) if a == b) {
        return false;
    }
    let Some(new) = proposed.required_capabilities() else {
        return false;
    };
    let (old_extensions, old_proposals, old_credentials) = match current.required_capabilities() {
        Some(rc) => (
            rc.extension_types().to_vec(),
            rc.proposal_types().to_vec(),
            rc.credential_types().to_vec(),
        ),
        None => (Vec::new(), Vec::new(), Vec::new()),
    };
    let present: Vec<ExtensionType> = current.iter().map(Extension::extension_type).collect();
    let extensions_ok = old_extensions
        .iter()
        .chain([&heads_type])
        .all(|t| new.extension_types().contains(t))
        && new
            .extension_types()
            .iter()
            .all(|t| old_extensions.contains(t) || *t == heads_type || present.contains(t));
    let mut credentials_expected = old_credentials;
    if !credentials_expected.contains(&credential_type) {
        credentials_expected.push(credential_type);
    }
    let same_set = |a: &[CredentialType], b: &[CredentialType]| {
        a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
    };
    extensions_ok
        && new.proposal_types() == old_proposals.as_slice()
        && same_set(new.credential_types(), &credentials_expected)
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
    use openmls::prelude::ProposalType;

    use super::*;

    const CP: CodePoints = CodePoints::SUGGESTED;

    fn record() -> DidWebvhHeads {
        let signer = UpdateKey::from_seed(&[3; 32]);
        let log = DidLog::create(
            "example.com",
            "alice",
            "2026-11-20T09:00:00Z",
            &Parameters {
                update_keys: Some(vec![signer.multikey()]),
                next_key_hashes: None,
            },
            &signer,
            &[[0xa1; 32]],
        )
        .expect("log");
        let mut heads = DidWebvhHeads::new();
        heads.insert(DidWebvhHead::from_log(log.verified()));
        heads
    }

    /// The extensions a record-setting proposal carries, built by hand
    /// from §The Heads Extension rather than by `with_heads`.
    fn by_hand(heads: &DidWebvhHeads, proposals: &[ProposalType]) -> Extensions<GroupContext> {
        Extensions::from_vec(vec![
            Extension::Unknown(0x0013, UnknownExtension(heads.encode().expect("encode"))),
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::from(0x0013)],
                proposals,
                &[CredentialType::from(0x0008)],
            )),
        ])
        .expect("extensions")
    }

    #[test]
    fn only_the_record_and_its_required_capabilities_count_as_a_record_change() {
        let empty = Extensions::<GroupContext>::empty();
        let heads = record();
        assert!(is_record_change(CP, &empty, &by_hand(&heads, &[])));
        // No record at all.
        assert!(!is_record_change(CP, &empty, &empty));
        // required_capabilities gains something else too.
        assert!(!is_record_change(
            CP,
            &empty,
            &by_hand(&heads, &[ProposalType::AppDataUpdate])
        ));
        // Another extension rides along.
        let mut extra = by_hand(&heads, &[]);
        extra
            .add_or_replace(Extension::Unknown(0xff00, UnknownExtension(vec![1])))
            .expect("add");
        assert!(!is_record_change(CP, &empty, &extra));
        // The record without required_capabilities.
        let bare = Extensions::single(Extension::Unknown(
            0x0013,
            UnknownExtension(heads.encode().expect("encode")),
        ))
        .expect("extensions");
        assert!(!is_record_change(CP, &empty, &bare));
        // An existing extension is dropped.
        let current = Extensions::single(Extension::Unknown(0xff00, UnknownExtension(vec![1])))
            .expect("extensions");
        assert!(!is_record_change(CP, &current, &by_hand(&heads, &[])));
        // An existing extension is kept, and listed in required_capabilities
        // as OpenMLS asks; listing it is allowed, not listing it too.
        let mut kept = by_hand(&heads, &[]);
        kept.add_or_replace(Extension::Unknown(0xff00, UnknownExtension(vec![1])))
            .expect("add");
        assert!(is_record_change(CP, &current, &kept));
        kept.add_or_replace(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(
                &[ExtensionType::from(0x0013), ExtensionType::from(0xff00)],
                &[],
                &[CredentialType::from(0x0008)],
            ),
        ))
        .expect("replace");
        assert!(is_record_change(CP, &current, &kept));
        // But not an extension type the GroupContext does not carry.
        kept.add_or_replace(Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(
                &[ExtensionType::from(0x0013), ExtensionType::from(0xff01)],
                &[],
                &[CredentialType::from(0x0008)],
            ),
        ))
        .expect("replace");
        assert!(!is_record_change(CP, &current, &kept));
        // with_heads writes what is_record_change accepts.
        let written = with_heads(CP, &current, &heads).expect("with_heads");
        assert!(is_record_change(CP, &current, &written));
    }
}
