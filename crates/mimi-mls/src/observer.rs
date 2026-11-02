//! A group's public state, as the hub and followers track it.
//!
//! An [`Observer`] is a non-member's view of one MLS group (RFC 9420). It
//! wraps an OpenMLS `PublicGroup`: the ratchet tree, the GroupContext and the
//! pending proposals, and no secrets. It validates PublicMessage proposals
//! and Commits, so that the hub can decide which Commit wins an epoch.
//!
//! A Commit is staged by [`Observer::process`] and applied only by
//! [`Observer::merge_pending_commit`]. Between the two, the hub checks room
//! policy: MLS validity picks the winning Commit, and policy is checked
//! afterwards.
//!
//! # Limitations
//!
//! - The `membership_tag` of a member's PublicMessage (RFC 9420 §6.2) is not
//!   checked, because computing it needs the epoch's `membership_key`, which
//!   an [`Observer`] does not have. The sender's signature is verified.
//! - The `lifetime` of received leaves (RFC 9420 §7.3, RECOMMENDED only) is
//!   not checked: not in the ratchet tree given to
//!   [`Observer::from_group_info`], nor in Add (KeyPackage), Update or
//!   UpdatePath leaves (decision mimid-1wgh.4.38). A leaf that is never
//!   updated would otherwise lock the hub out of its group once the
//!   lifetime ends. Signatures, the tree hash and all other leaf checks
//!   still apply.
//! - The required-components check (decision mimid-1wgh.4.45) refuses only
//!   Commits. The leaves in the tree given to [`Observer::from_group_info`]
//!   are reported, not refused (decision mimid-1wgh.4.57).
//! - PrivateMessages cannot be processed; the hub forwards them unread.
//! - Proposals from external senders are accepted only for the types OpenMLS
//!   supports there: Add, Remove, GroupContextExtensions and AppDataUpdate.
//! - An [`Observer`] cannot be reloaded from the [`Store`] after a restart.
//!   OpenMLS does not persist the lifetime policy, so a future reload must
//!   set it to Skip again.
//! - [`Observer::group_info`] works only after this Observer has merged a
//!   Commit, since the GroupInfo signer is the committer. It cannot rebuild
//!   the GroupInfo of the epoch the Observer started in.
//! - [`Observer::group_info`] puts a rebuilt ratchet_tree extension last in
//!   the extension list, as ratchet-tree-options-02 §4 requires. A committer
//!   that put it elsewhere signed different bytes, and the signature check
//!   fails.
//! - [`Observer::group_info`] does not check the previous-epoch half of
//!   `ratchet_tree_presence` (whether the previous GroupInfo had a
//!   ratchet_tree extension). It uses only the current-epoch half, which the
//!   signature covers (decision mimid-1wgh.4.47).
//! - [`Observer::group_info`] and [`Observer::verify_group_info`] require
//!   the GroupInfo's `signer` to be the committer of the merged Commit,
//!   since protocol-06 §5.3 has the committer send it with the Commit.
//! - [`ProposalKind::AppDataUpdate`] reports the `update` bytes of a
//!   proposal as it carries them, without decoding or checking them against
//!   the component's semantics. [`Observer::process_proposal`] stores such a
//!   proposal whatever its bytes; only the `apply` function of a later
//!   [`Observer::process`] judges them, and the caller must decode them
//!   itself to authorize the proposal.
//! - [`ProposalDetail::reference`] is `None` for a proposal a Commit carries
//!   inline: RFC 9420 §5.2 defines a ProposalRef only for proposals sent on
//!   their own, and OpenMLS does not compute one for inline proposals.
//! - [`UpdatePathDetail::identity_changed`] is always `false` in an
//!   external Commit: the joiner has no earlier leaf to compare with. In a
//!   resync, compare [`UpdatePathDetail::identity`] with the identity of the
//!   leaf its Remove proposal removes.
//! - [`Observer::external_senders`] returns an empty list both when the
//!   GroupContext has no `external_senders` extension and when the
//!   extension lists no sender. It does not check that an entry's
//!   credential is a BasicCredential; [`crate::wire::Credential::identity`]
//!   is `None` for any other type.

use openmls::component::ComponentId;
use openmls::group::{
    LeafNodeLifetimePolicy, ProposalStore, PublicGroup, QueuedProposal, StagedCommit,
};
use openmls::messages::group_info::{GroupInfo as OpenMlsGroupInfo, VerifiableGroupInfo};
use openmls::messages::proposals::{
    AppDataUpdateOperation, Proposal as OpenMlsProposal, ProposalOrRefType,
};
use openmls::prelude::{
    Extension, Extensions, ExternalProposal, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn,
    OpenMlsProvider, ProcessedMessage, ProcessedMessageContent, ProtocolMessage,
    RatchetTreeExtension, RatchetTreeIn, SenderExtensionIndex,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use tls_codec::{Deserialize, Serialize, VLBytes};

use crate::identity::CIPHERSUITE;
use crate::member::{
    AppDataUpdate, CommitSummary, ComponentOp, Sender, SharedError, basic_identity,
    check_staged_leaves, convert_sender, nonconforming_leaves, required_lists,
    resolve_app_data_updates, summarize,
};
use crate::store::Provider;
use crate::wire::{
    ExternalSender, GroupInfo, KeyPackageRef, PartialGroupInfo, ProposalRef, RatchetTreePresence,
    check_safe_aad,
};
use crate::{ErrorSource, Store, label};

/// RFC 9420 §6: the MLSMessage header for a GroupInfo, `version` mls10
/// (0x0001) and `wire_format` mls_group_info (0x0004).
const GROUP_INFO_MESSAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];

/// mls-extensions-10 §4.9: a SafeAAD struct with an empty `aad_items<V>`.
const EMPTY_SAFE_AAD: [u8; 1] = [0x00];

/// RFC 9420 §12.4.3: the SignWithLabel label of a GroupInfo signature.
const GROUP_INFO_LABEL: &str = "GroupInfoTBS";

/// The result of [`Observer::process`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Observed {
    /// A proposal, now stored until a Commit covers it.
    Proposal {
        /// Who sent the proposal.
        sender: Sender,
    },
    /// A valid Commit, now pending. Merge it with
    /// [`Observer::merge_pending_commit`] or drop it with
    /// [`Observer::clear_pending_commit`].
    ///
    /// [`CommitSummary::self_removed`] is always `false`, since an
    /// [`Observer`] has no leaf.
    Commit(CommitSummary),
}

/// One proposal, from [`Observer::process_proposal`] or in a
/// [`CommitDetail`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProposalDetail {
    /// Who sent the proposal. For a proposal a Commit carries inline, this
    /// is the committer.
    pub sender: Sender,
    /// The RFC 9420 §5.2 ProposalRef of a proposal sent on its own: one
    /// [`Observer::process_proposal`] stored, or one a Commit includes by
    /// reference (`ProposalOrRefType` `reference`, RFC 9420 §12.4). `None`
    /// for a proposal a Commit carries inline.
    pub reference: Option<ProposalRef>,
    /// What the proposal does.
    pub proposal: ProposalKind,
}

/// RFC 9420 §12.1 `Proposal`, by `ProposalType`, with the fields the hub
/// checks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProposalKind {
    /// `add` (RFC 9420 §12.1.1).
    Add {
        /// The BasicCredential identity of the KeyPackage's LeafNode.
        identity: Vec<u8>,
        /// The KeyPackageRef of the added KeyPackage (RFC 9420 §5.2).
        key_package_ref: KeyPackageRef,
    },
    /// `update` (RFC 9420 §12.1.2).
    Update {
        /// The BasicCredential identity of the new LeafNode.
        identity: Vec<u8>,
        /// Whether `identity` differs from the identity of the sender's
        /// current leaf. Always `true` if the sender is not a member, which
        /// MLS validation does not allow.
        identity_changed: bool,
    },
    /// `remove` (RFC 9420 §12.1.3).
    Remove {
        /// The leaf index to remove, in the current epoch.
        removed: u32,
        /// The BasicCredential identity of that leaf, or empty if the leaf
        /// is blank, which MLS validation does not allow.
        identity: Vec<u8>,
    },
    /// `psk` (RFC 9420 §12.1.4).
    PreSharedKey,
    /// `reinit` (RFC 9420 §12.1.5).
    ReInit,
    /// `external_init` (RFC 9420 §12.1.6).
    ExternalInit,
    /// `group_context_extensions` (RFC 9420 §12.1.7).
    GroupContextExtensions,
    /// `app_data_update` (mls-extensions-10 §4.7).
    AppDataUpdate {
        /// The component whose data it changes.
        component_id: ComponentId,
        /// The `op` and its body: `Some` with the `update` field's bytes,
        /// exactly as the proposal carries them, for `op = update`; `None`
        /// for `op = remove`. The bytes are not interpreted (see the
        /// module's `# Limitations`).
        update: Option<Vec<u8>>,
    },
    /// `self_remove` (mls-extensions-10 §6.3).
    SelfRemove,
    /// `app_ephemeral` (mls-extensions-10 §4.8).
    AppEphemeral,
    /// Any other proposal type, by its RFC 9420 §17.4 `ProposalType` value.
    Custom(u16),
}

/// The UpdatePath of a pending Commit (RFC 9420 §12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdatePathDetail {
    /// The BasicCredential identity of the UpdatePath's LeafNode.
    pub identity: Vec<u8>,
    /// Whether `identity` differs from the identity of the committer's
    /// current leaf. Always `false` in an external Commit (see the module's
    /// `# Limitations`).
    pub identity_changed: bool,
}

/// What a pending Commit does, from [`Observer::pending_commit_detail`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommitDetail {
    /// Who sent the Commit: a member, or a new member joining by external
    /// Commit.
    pub committer: Sender,
    /// The committer's leaf index in the new epoch. For an external Commit,
    /// the leaf the joiner takes (RFC 9420 §12.4.3.2).
    pub committer_leaf: u32,
    /// The BasicCredential identity whose signature key signed the Commit:
    /// the committer's current leaf for a member, the UpdatePath's LeafNode
    /// for an external joiner.
    pub committer_identity: Vec<u8>,
    /// The epoch the group is in after the Commit.
    pub epoch: u64,
    /// The proposals the Commit covers, in the order the Commit lists them.
    pub proposals: Vec<ProposalDetail>,
    /// The UpdatePath, if the Commit carries one.
    pub path: Option<UpdatePathDetail>,
}

/// The result of [`Observer::from_group_info`].
///
/// A group whose leaves miss a required component is observed, not
/// refused, and those leaves are reported (decisions mimid-1wgh.4.57,
/// mimid-1wgh.4.59).
#[derive(Debug)]
#[non_exhaustive]
pub struct ObserverStart {
    /// The new Observer.
    pub observer: Observer,
    /// The leaf indices, ascending, of the leaves that do not list a
    /// component the GroupContext `safe_aad` or `app_components` list
    /// requires (the check of [`crate::member`]'s `# Required components`).
    pub nonconforming_leaves: Vec<u32>,
}

/// Errors returned by [`Observer`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ObserverError {
    /// The input is not a well-formed TLS encoding of the expected type.
    #[error("cannot decode the MLS input")]
    Decode(#[source] ErrorSource),
    /// The input decoded, but is not the kind of message this call takes.
    #[error("unexpected MLS message type")]
    UnexpectedMessage,
    /// No ratchet tree was given, and the GroupInfo has no `ratchet_tree`
    /// extension (RFC 9420 §12.4.3.3).
    #[error("no ratchet tree was given and the GroupInfo carries none")]
    MissingRatchetTree,
    /// The GroupInfo or ratchet tree failed validation, for example its
    /// signature or tree hash (RFC 9420 §12.4.3.1). From
    /// [`Observer::verify_group_info`]: the GroupInfo does not match the
    /// current epoch, or its signature does not verify.
    #[error("invalid GroupInfo or ratchet tree")]
    InvalidGroupInfo(#[source] ErrorSource),
    /// The message failed MLS validation. The group state is unchanged.
    #[error("the MLS message is invalid")]
    Process(#[source] ErrorSource),
    /// `authenticated_data` has bytes after the SafeAAD struct
    /// (mls-extensions-10 §4.9, decision mimid-1wgh.4.17). The group state
    /// is unchanged.
    #[error("bytes follow the SafeAAD struct")]
    TrailingAad,
    /// The AppDataUpdate proposals for a component are invalid under
    /// mls-extensions-10 §4.7.
    #[error("invalid AppDataUpdate proposals for component {0:#06x}")]
    InvalidAppDataUpdate(ComponentId),
    /// The `apply` function rejected the AppDataUpdate proposals for a
    /// component.
    #[error("component {component_id:#06x} rejected its AppDataUpdate")]
    AppDataRejected {
        /// The component.
        component_id: ComponentId,
        /// Why `apply` rejected it.
        #[source]
        source: ErrorSource,
    },
    /// The data of the `safe_aad` (0x0002) or `app_components` (0x0001)
    /// component in the GroupContext is not a canonical `ComponentsList`
    /// (mls-extensions-10 §5).
    #[error("component {component_id:#06x} is not a valid ComponentsList")]
    InvalidComponentsList {
        /// The component whose data is malformed.
        component_id: ComponentId,
        /// Why decoding failed.
        #[source]
        source: ErrorSource,
    },
    /// A new or updated leaf's `safe_aad` list does not name a component
    /// that the GroupContext `safe_aad` list requires (decision
    /// mimid-1wgh.4.45). The group state is unchanged.
    #[error("a leaf does not support required Safe AAD component {0:#06x}")]
    MissingSafeAadComponent(ComponentId),
    /// A new or updated leaf's `app_components` list does not name a
    /// component that the GroupContext `app_components` list requires
    /// (decision mimid-1wgh.4.45). The group state is unchanged.
    #[error("a leaf does not support required component {0:#06x}")]
    MissingAppComponent(ComponentId),
    /// A Commit is pending; merge or clear it before processing more
    /// messages.
    #[error("a Commit is pending")]
    PendingCommit,
    /// [`Observer::merge_pending_commit`] was called with no Commit pending.
    #[error("no Commit is pending")]
    NoPendingCommit,
    /// [`Observer::group_info`] was called before this Observer merged any
    /// Commit, so the GroupInfo signer is unknown.
    #[error("no Commit has been merged")]
    NoMergedCommit,
    /// The GroupInfo rebuilt from a PartialGroupInfo is invalid: its
    /// signature does not verify under the committer's leaf signature key
    /// (RFC 9420 §12.4.3), or its extensions are not valid in a GroupInfo.
    #[error("the rebuilt GroupInfo is invalid")]
    InvalidPartialGroupInfo(#[source] ErrorSource),
    /// The proposal could not be built: `sender_index` names no entry of
    /// the `external_senders` extension, or the signature key is malformed.
    #[error("cannot build the proposal")]
    Propose(#[source] ErrorSource),
    /// The group state could not be stored.
    #[error("cannot update the group state")]
    Merge(#[source] ErrorSource),
    /// A structure could not be TLS-encoded.
    #[error("cannot encode an MLS structure")]
    Encode(#[source] ErrorSource),
}

impl From<SharedError> for ObserverError {
    fn from(error: SharedError) -> Self {
        match error {
            SharedError::Encode(source) => Self::Encode(source),
            SharedError::UnexpectedMessage => Self::UnexpectedMessage,
            SharedError::InvalidAppDataUpdate(component_id) => {
                Self::InvalidAppDataUpdate(component_id)
            }
            SharedError::AppDataRejected {
                component_id,
                source,
            } => Self::AppDataRejected {
                component_id,
                source,
            },
            SharedError::InvalidComponentsList {
                component_id,
                source,
            } => Self::InvalidComponentsList {
                component_id,
                source,
            },
            SharedError::MissingSafeAadComponent(component_id) => {
                Self::MissingSafeAadComponent(component_id)
            }
            SharedError::MissingAppComponent(component_id) => {
                Self::MissingAppComponent(component_id)
            }
        }
    }
}

/// The public state of one MLS group, without membership.
///
/// Every method that reads or writes storage takes the [`Store`] holding
/// this group's state. Use a [`Store`] that no
/// [`Member`](crate::member::Member) of the same group uses: OpenMLS keys
/// both by group ID.
pub struct Observer {
    group: PublicGroup,
    /// The Commit staged by [`Observer::process`], not yet merged, with its
    /// sender and its committer's leaf index in the new epoch.
    pending_commit: Option<(StagedCommit, Sender, LeafNodeIndex)>,
    /// The leaf index of the committer of the last merged Commit.
    committer: Option<LeafNodeIndex>,
}

impl Observer {
    /// Starts tracking a group from a TLS-encoded `MLSMessage` carrying a
    /// GroupInfo (RFC 9420 §12.4.3).
    ///
    /// `ratchet_tree` is a TLS-encoded ratchet tree (RFC 9420 §12.4.3.3).
    /// When it is `None`, the tree comes from the GroupInfo's `ratchet_tree`
    /// extension. When both are present, `ratchet_tree` is used; either way
    /// its tree hash must match the GroupContext.
    ///
    /// The GroupInfo signature is verified against the signer's leaf, the
    /// tree hash is checked, and every leaf in the tree is validated except
    /// for its `lifetime` (see the module's `# Limitations`).
    ///
    /// The returned [`ObserverStart`] also reports the leaves that miss a
    /// required component (decision mimid-1wgh.4.57).
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::Decode`] for malformed input,
    /// [`ObserverError::UnexpectedMessage`] if the message is not a
    /// GroupInfo, [`ObserverError::MissingRatchetTree`] if there is no tree,
    /// [`ObserverError::InvalidComponentsList`] if the GroupContext's
    /// `safe_aad` or `app_components` data is malformed (decisions
    /// mimid-1wgh.4.57, mimid-1wgh.4.59), and
    /// [`ObserverError::InvalidGroupInfo`] if validation fails or the state
    /// cannot be stored.
    pub fn from_group_info(
        store: &Store,
        group_info: &[u8],
        ratchet_tree: Option<&[u8]>,
    ) -> Result<ObserverStart, ObserverError> {
        let message = MlsMessageIn::tls_deserialize_exact(group_info)
            .map_err(|e| ObserverError::Decode(e.into()))?;
        let MlsMessageBodyIn::GroupInfo(group_info) = message.extract() else {
            return Err(ObserverError::UnexpectedMessage);
        };
        let ratchet_tree = match ratchet_tree {
            Some(bytes) => RatchetTreeIn::tls_deserialize_exact(bytes)
                .map_err(|e| ObserverError::Decode(e.into()))?,
            None => group_info
                .extensions()
                .ratchet_tree()
                .map(|extension| extension.ratchet_tree().clone())
                .ok_or(ObserverError::MissingRatchetTree)?,
        };
        // Decoded before anything is stored, and fails closed (decisions
        // mimid-1wgh.4.57, mimid-1wgh.4.59). Used only after the GroupInfo signature, which
        // covers the GroupContext, has been verified below.
        let required = required_lists(group_info.group_context().extensions())?;
        let provider = store.provider();
        // RFC 9420 §7.3; decision mimid-1wgh.4.38. The policy stays on the
        // group, covering later Add, Update and UpdatePath leaves too. It is
        // not persisted: a future reload must set Skip again.
        let (group, _group_info) = PublicGroup::from_external_with_lifetime_policy(
            provider.crypto(),
            provider.storage(),
            ratchet_tree,
            group_info,
            ProposalStore::new(),
            LeafNodeLifetimePolicy::Skip,
        )
        .map_err(|e| ObserverError::InvalidGroupInfo(e.into()))?;
        // Decision mimid-1wgh.4.57. An Observer has no leaf of its own.
        let nonconforming_leaves = nonconforming_leaves(&group, &required, None);
        Ok(ObserverStart {
            observer: Self {
                group,
                pending_commit: None,
                committer: None,
            },
            nonconforming_leaves,
        })
    }

    /// Processes one TLS-encoded `MLSMessage` carrying a PublicMessage
    /// proposal or Commit for this group.
    ///
    /// A valid proposal is stored. A valid Commit is staged, not merged: see
    /// [`Observed::Commit`]. A Commit carrying AppDataUpdate proposals is
    /// resolved with `apply`, exactly as [`Member::process`] does; see
    /// [`ComponentOp`].
    ///
    /// On any error the group state is left as it was.
    ///
    /// [`Member::process`]: crate::member::Member::process
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::PendingCommit`] while a Commit is pending,
    /// [`ObserverError::Decode`] for malformed input,
    /// [`ObserverError::UnexpectedMessage`] for anything but a PublicMessage
    /// proposal or Commit (a PrivateMessage included),
    /// [`ObserverError::Process`] if MLS validation fails or a required
    /// SafeAAD is malformed,
    /// [`ObserverError::TrailingAad`] if bytes follow the SafeAAD struct,
    /// [`ObserverError::InvalidAppDataUpdate`] or
    /// [`ObserverError::AppDataRejected`] for invalid AppDataUpdate
    /// proposals, [`ObserverError::MissingSafeAadComponent`],
    /// [`ObserverError::MissingAppComponent`] or
    /// [`ObserverError::InvalidComponentsList`] if a Commit fails the
    /// required-components check of [`crate::member`] (decision
    /// mimid-1wgh.4.45), and [`ObserverError::Merge`] if a proposal cannot
    /// be stored.
    pub fn process<E>(
        &mut self,
        store: &Store,
        message: &[u8],
        mut apply: impl FnMut(ComponentId, Option<&[u8]>, ComponentOp<'_>) -> Result<Option<Vec<u8>>, E>,
    ) -> Result<Observed, ObserverError>
    where
        E: Into<ErrorSource>,
    {
        let processed = self.validate(store, message)?;
        let provider = store.provider();
        let sender = convert_sender(processed.sender())?;

        let processed = if let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) =
            processed.content()
        {
            let proposals: Vec<_> = unresolved.app_data_update_proposals().cloned().collect();
            let mut updater = self.group.app_data_dictionary_updater();
            resolve_app_data_updates(&mut updater, &proposals, &mut apply)?;
            let changes = updater.changes();
            self.group
                .resolve_app_data_commit(provider.crypto(), processed, changes)
                .map_err(|e| ObserverError::Process(e.into()))?
        } else {
            processed
        };

        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(proposal)
            | ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.group
                    .add_proposal(provider.storage(), *proposal)
                    .map_err(|e| ObserverError::Merge(e.into()))?;
                Ok(Observed::Proposal { sender })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                check_staged_leaves(&staged)?;
                let committer = match sender {
                    Sender::Member(index) => LeafNodeIndex::new(index),
                    // RFC 9420 §12.4.3.2: the joiner takes the leftmost
                    // leaf left free after the Commit's Removes.
                    Sender::NewMemberCommit => self
                        .group
                        .ext_commit_sender_index(&staged)
                        .map_err(|e| ObserverError::Process(e.into()))?,
                    Sender::External(_) | Sender::NewMemberProposal => {
                        return Err(ObserverError::UnexpectedMessage);
                    }
                };
                let summary = summarize(sender, &staged, false);
                self.pending_commit = Some((*staged, sender, committer));
                Ok(Observed::Commit(summary))
            }
            _ => Err(ObserverError::UnexpectedMessage),
        }
    }

    /// Processes one TLS-encoded `MLSMessage` carrying a PublicMessage
    /// proposal for this group, stores it as [`Observer::process`] does, and
    /// describes it, with its ProposalRef (RFC 9420 §5.2).
    ///
    /// On any error the group state is left as it was.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::PendingCommit`] while a Commit is pending,
    /// [`ObserverError::Decode`] for malformed input,
    /// [`ObserverError::UnexpectedMessage`] for anything but a PublicMessage
    /// proposal (a Commit included),
    /// [`ObserverError::Process`] if MLS validation fails or a required
    /// SafeAAD is malformed,
    /// [`ObserverError::TrailingAad`] if bytes follow the SafeAAD struct,
    /// [`ObserverError::Encode`] if a reference cannot be computed, and
    /// [`ObserverError::Merge`] if the proposal cannot be stored.
    pub fn process_proposal(
        &mut self,
        store: &Store,
        message: &[u8],
    ) -> Result<ProposalDetail, ObserverError> {
        let processed = self.validate(store, message)?;
        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(proposal)
            | ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                let detail = self.proposal_detail(&proposal)?;
                self.group
                    .add_proposal(store.provider().storage(), *proposal)
                    .map_err(|e| ObserverError::Merge(e.into()))?;
                Ok(detail)
            }
            _ => Err(ObserverError::UnexpectedMessage),
        }
    }

    /// Builds an AppDataUpdate proposal (mls-extensions-10 §4.7) from the
    /// external sender at `sender_index` in the GroupContext
    /// `external_senders` extension (RFC 9420 §12.1.8.1), such as the hub
    /// (decision mimid-1wgh.4.21). Returns it as a TLS-encoded `MLSMessage`
    /// carrying a PublicMessage for the current epoch. Its
    /// `authenticated_data` is an empty SafeAAD struct if the GroupContext
    /// carries the `safe_aad` component (mls-extensions-10 §4.9), and empty
    /// otherwise.
    ///
    /// `signature_key` is the sender's 32-byte Ed25519 private key (RFC 8032
    /// seed), as for [`crate::label::sign_with_label`].
    ///
    /// The proposal is verified against the `external_senders` entry and
    /// stored, as [`Observer::process_proposal`] would store it, so that a
    /// Commit that covers it by reference can be processed. Do not pass
    /// the returned message back to this Observer. Whether the application
    /// knows the component, and what the `update` means, is judged by the
    /// `apply` function when a Commit covers the proposal.
    ///
    /// On any error the group state is left as it was.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::PendingCommit`] while a Commit is pending,
    /// [`ObserverError::InvalidAppDataUpdate`] for a remove of a component
    /// that has no data (§4.7), [`ObserverError::Propose`] if `sender_index`
    /// names no `external_senders` entry or the proposal cannot be signed,
    /// [`ObserverError::Process`] if `signature_key` does not match that
    /// entry's key, [`ObserverError::Encode`] if the message cannot be
    /// encoded, and [`ObserverError::Merge`] if it cannot be stored.
    pub fn propose_app_data_update(
        &mut self,
        store: &Store,
        signature_key: &[u8],
        sender_index: u32,
        update: &AppDataUpdate,
    ) -> Result<Vec<u8>, ObserverError> {
        if self.pending_commit.is_some() {
            return Err(ObserverError::PendingCommit);
        }
        let context = self.group.group_context();
        // mls-extensions-10 §4.9: with safe_aad present, the whole
        // authenticated_data is a SafeAAD struct, here with no items.
        let authenticated_data = if context.safe_aad_required() {
            EMPTY_SAFE_AAD.to_vec()
        } else {
            Vec::new()
        };
        let proposal = update.to_proposal();
        let component_id = proposal.component_id();
        // §4.7: "invalid if ... it specifies the removal of state for a
        // component_id that has no state present".
        if matches!(proposal.operation(), AppDataUpdateOperation::Remove)
            && self.component(component_id).is_none()
        {
            return Err(ObserverError::InvalidAppDataUpdate(component_id));
        }
        let senders = self.external_senders()?;
        let sender = senders.get(sender_index as usize).ok_or_else(|| {
            ObserverError::Propose(
                format!("no external_senders entry at index {sender_index}").into(),
            )
        })?;
        let signer = SignatureKeyPair::from_raw(
            CIPHERSUITE.signature_algorithm(),
            signature_key.to_vec(),
            sender.signature_key().to_vec(),
        );
        let message = ExternalProposal::new_app_data_update::<Provider>(
            component_id,
            proposal.operation().clone(),
            self.group.group_id().clone(),
            context.epoch(),
            &signer,
            SenderExtensionIndex::new(sender_index),
            authenticated_data,
        )
        .map_err(|e| ObserverError::Propose(e.into()))?;
        let message = encode(&message)?;
        self.process_proposal(store, &message)?;
        Ok(message)
    }

    /// Checks that `message` is a PublicMessage for this group and passes
    /// MLS validation. Changes nothing.
    fn validate(&self, store: &Store, message: &[u8]) -> Result<ProcessedMessage, ObserverError> {
        if self.pending_commit.is_some() {
            return Err(ObserverError::PendingCommit);
        }
        let bytes = message;
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| ObserverError::Decode(e.into()))?
            .try_into_protocol_message()
            .map_err(|_| ObserverError::UnexpectedMessage)?;
        if let ProtocolMessage::PrivateMessage(_) = message {
            return Err(ObserverError::UnexpectedMessage);
        }
        // Bug mimid-1wgh.33: checked before OpenMLS parses the SafeAAD, as
        // in Member::process.
        if self.group.group_context().safe_aad_required() {
            check_safe_aad(bytes).map_err(|e| ObserverError::Process(e.into()))?;
        }
        let processed = self
            .group
            .process_message(store.provider().crypto(), message)
            .map_err(|e| ObserverError::Process(e.into()))?;
        // mls-extensions-10 §4.9: the whole authenticated_data is SafeAAD,
        // as in Member::process.
        if processed.safe_aad().is_some() && !processed.tail_aad().is_empty() {
            return Err(ObserverError::TrailingAad);
        }
        Ok(processed)
    }

    /// Describes the pending Commit: its committer, every proposal it
    /// covers, and its UpdatePath. Identities are compared with the leaves
    /// of the current epoch, before the Commit is merged.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::NoPendingCommit`] if no Commit is pending,
    /// and [`ObserverError::Encode`] if a reference cannot be computed.
    pub fn pending_commit_detail(&self) -> Result<CommitDetail, ObserverError> {
        let (staged, committer, committer_leaf) = self
            .pending_commit
            .as_ref()
            .ok_or(ObserverError::NoPendingCommit)?;
        let path_identity = staged
            .update_path_leaf_node()
            .map(|leaf| basic_identity(leaf.credential()));
        let committer_identity = match committer {
            Sender::Member(index) => self
                .leaf_identity(LeafNodeIndex::new(*index))
                .unwrap_or_default(),
            // RFC 9420 §12.4.3.2: an external Commit is signed with the key
            // of the joiner's UpdatePath leaf, which it must carry.
            _ => path_identity.clone().unwrap_or_default(),
        };
        let path = path_identity.map(|identity| UpdatePathDetail {
            identity_changed: matches!(committer, Sender::Member(_))
                && identity != committer_identity,
            identity,
        });
        let proposals = staged
            .queued_proposals()
            .map(|queued| self.proposal_detail(queued))
            .collect::<Result<_, _>>()?;
        Ok(CommitDetail {
            committer: *committer,
            committer_leaf: committer_leaf.u32(),
            committer_identity,
            epoch: staged.epoch().as_u64(),
            proposals,
            path,
        })
    }

    /// The BasicCredential identity of a leaf in the current epoch, or
    /// `None` if the leaf is blank.
    fn leaf_identity(&self, index: LeafNodeIndex) -> Option<Vec<u8>> {
        self.group
            .leaf(index)
            .map(|leaf| basic_identity(leaf.credential()))
    }

    /// Describes a proposal against the current epoch's leaves.
    fn proposal_detail(&self, queued: &QueuedProposal) -> Result<ProposalDetail, ObserverError> {
        let sender = convert_sender(queued.sender())?;
        let reference = match queued.proposal_or_ref_type() {
            ProposalOrRefType::Reference => Some(to_wire(queued.proposal_reference_ref())?),
            // OpenMLS gives an inline proposal an internal hash, not an
            // RFC 9420 §5.2 ProposalRef, so it is not reported.
            ProposalOrRefType::Proposal => None,
        };
        let proposal = match queued.proposal() {
            OpenMlsProposal::Add(add) => {
                let key_package = add.key_package();
                let key_package_ref = key_package
                    .hash_ref(&RustCrypto::default())
                    .map_err(|e| ObserverError::Encode(e.into()))?;
                ProposalKind::Add {
                    identity: basic_identity(key_package.leaf_node().credential()),
                    key_package_ref: to_wire(&key_package_ref)?,
                }
            }
            OpenMlsProposal::Update(update) => {
                let identity = basic_identity(update.leaf_node().credential());
                let current = match sender {
                    Sender::Member(index) => self.leaf_identity(LeafNodeIndex::new(index)),
                    _ => None,
                };
                ProposalKind::Update {
                    identity_changed: current.as_deref() != Some(identity.as_slice()),
                    identity,
                }
            }
            OpenMlsProposal::Remove(remove) => ProposalKind::Remove {
                removed: remove.removed().u32(),
                identity: self.leaf_identity(remove.removed()).unwrap_or_default(),
            },
            OpenMlsProposal::PreSharedKey(_) => ProposalKind::PreSharedKey,
            OpenMlsProposal::ReInit(_) => ProposalKind::ReInit,
            OpenMlsProposal::ExternalInit(_) => ProposalKind::ExternalInit,
            OpenMlsProposal::GroupContextExtensions(_) => ProposalKind::GroupContextExtensions,
            OpenMlsProposal::AppDataUpdate(proposal) => ProposalKind::AppDataUpdate {
                component_id: proposal.component_id(),
                update: match proposal.operation() {
                    AppDataUpdateOperation::Update(update) => Some(update.as_slice().to_vec()),
                    AppDataUpdateOperation::Remove => None,
                },
            },
            OpenMlsProposal::SelfRemove => ProposalKind::SelfRemove,
            OpenMlsProposal::AppEphemeral(_) => ProposalKind::AppEphemeral,
            OpenMlsProposal::Custom(custom) => ProposalKind::Custom(custom.proposal_type()),
        };
        Ok(ProposalDetail {
            sender,
            reference,
            proposal,
        })
    }

    /// Merges the pending Commit, moving the group to the next epoch.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::NoPendingCommit`] if no Commit is pending,
    /// and [`ObserverError::Merge`] if the new state cannot be stored.
    pub fn merge_pending_commit(&mut self, store: &Store) -> Result<(), ObserverError> {
        let (staged, _, committer) = self
            .pending_commit
            .take()
            .ok_or(ObserverError::NoPendingCommit)?;
        self.group
            .merge_commit(store.provider().storage(), staged)
            .map_err(|e| ObserverError::Merge(e.into()))?;
        self.committer = Some(committer);
        Ok(())
    }

    /// Drops the pending Commit, if any. Stored proposals are kept.
    pub fn clear_pending_commit(&mut self) {
        self.pending_commit = None;
    }

    /// The group ID.
    pub fn group_id(&self) -> &[u8] {
        self.group.group_id().as_slice()
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.group.group_context().epoch().as_u64()
    }

    /// The current members as (leaf index, BasicCredential identity).
    pub fn members(&self) -> Vec<(u32, Vec<u8>)> {
        self.group
            .members()
            .map(|member| (member.index.u32(), basic_identity(&member.credential)))
            .collect()
    }

    /// The data of a component in the GroupContext `app_data_dictionary`
    /// (mls-extensions-10 §4.6).
    pub fn component(&self, component_id: ComponentId) -> Option<&[u8]> {
        self.group
            .group_context()
            .extensions()
            .app_data_dictionary()
            .and_then(|extension| extension.dictionary().get(&component_id))
    }

    /// The entries of the current GroupContext's `external_senders`
    /// extension (RFC 9420 §12.1.8.1), in the order the extension lists
    /// them. Empty if the extension is absent (see the module's
    /// `# Limitations`).
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::Encode`] if an entry cannot be encoded.
    pub fn external_senders(&self) -> Result<Vec<ExternalSender>, ObserverError> {
        self.group
            .group_context()
            .extensions()
            .external_senders()
            .map_or_else(
                || Ok(Vec::new()),
                |senders| senders.iter().map(to_wire).collect(),
            )
    }

    /// The TLS-encoded GroupContext (RFC 9420 §8.1) of the current epoch.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::Encode`] if it cannot be encoded.
    pub fn group_context(&self) -> Result<Vec<u8>, ObserverError> {
        self.group
            .group_context()
            .tls_serialize_detached()
            .map_err(|e| ObserverError::Encode(e.into()))
    }

    /// The TLS-encoded ratchet tree (RFC 9420 §12.4.3.3) of the current
    /// epoch.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::Encode`] if it cannot be encoded.
    pub fn ratchet_tree(&self) -> Result<Vec<u8>, ObserverError> {
        self.group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|e| ObserverError::Encode(e.into()))
    }

    /// Rebuilds the GroupInfo of the current epoch from a PartialGroupInfo
    /// (ratchet-tree-options-02 §4) and returns it as a TLS-encoded
    /// `MLSMessage` (RFC 9420 §6, §12.4.3).
    ///
    /// Call it after [`Observer::merge_pending_commit`] has merged the
    /// Commit that `partial` came with. The GroupInfo is built from this
    /// Observer's state in the new epoch (decision mimid-1wgh.4.20):
    ///
    /// - `group_context`: the current GroupContext;
    /// - `extensions`: `partial`'s `group_info_extensions`, followed by a
    ///   ratchet_tree extension carrying the current tree when
    ///   `ratchet_tree_presence` is `present` or `added`;
    /// - `confirmation_tag`: the merged Commit's;
    /// - `signer`: the merged Commit's committer;
    /// - `signature`: `partial`'s.
    ///
    /// The signature is verified with the committer's leaf signature key
    /// before anything is returned.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::PendingCommit`] while a Commit is pending,
    /// [`ObserverError::NoMergedCommit`] if this Observer has not merged a
    /// Commit, [`ObserverError::InvalidPartialGroupInfo`] if the signature
    /// does not verify (for example, because `partial` belongs to another
    /// epoch), and [`ObserverError::Encode`] if a structure cannot be
    /// encoded.
    pub fn group_info(&self, partial: &PartialGroupInfo) -> Result<Vec<u8>, ObserverError> {
        if self.pending_commit.is_some() {
            return Err(ObserverError::PendingCommit);
        }
        let committer = self.committer.ok_or(ObserverError::NoMergedCommit)?;
        // PartialGroupInfo decoding has already checked the list.
        let mut extensions =
            Extensions::<OpenMlsGroupInfo>::tls_deserialize_exact(partial.group_info_extensions())
                .map_err(|e| ObserverError::InvalidPartialGroupInfo(e.into()))?;
        // Only the current-epoch half of ratchet_tree_presence is used; the
        // previous-epoch half is not checked. ratchet-tree-options-01 §4;
        // decision mimid-1wgh.4.47.
        if matches!(
            partial.ratchet_tree_presence(),
            RatchetTreePresence::Present | RatchetTreePresence::Added
        ) {
            // The extension goes last. ratchet-tree-options-02 §4
            let mut list: Vec<Extension> = extensions.iter().cloned().collect();
            list.push(Extension::RatchetTree(RatchetTreeExtension::new(
                self.group.export_ratchet_tree(),
            )));
            extensions = Extensions::from_vec(list)
                .map_err(|e| ObserverError::InvalidPartialGroupInfo(e.into()))?;
        }

        let tbs = self.group_info_tbs(&extensions, committer)?;
        let leaf = self.group.leaf(committer).ok_or_else(|| {
            ObserverError::InvalidPartialGroupInfo("the committer's leaf is blank".into())
        })?;
        label::verify_with_label(
            leaf.signature_key().as_slice(),
            GROUP_INFO_LABEL,
            &tbs,
            partial.signature(),
        )
        .map_err(|e| ObserverError::InvalidPartialGroupInfo(e.into()))?;

        let mut message = GROUP_INFO_MESSAGE_HEADER.to_vec();
        message.extend(tbs);
        message.extend(encode(&VLBytes::new(partial.signature().to_vec()))?);
        Ok(message)
    }

    /// Verifies a full GroupInfo (RFC 9420 §12.4.3), as a Commit carries it
    /// in protocol-06's `GroupInfoOption` `full`, against the current epoch.
    ///
    /// Call it after [`Observer::merge_pending_commit`] has merged the
    /// Commit the GroupInfo came with. The GroupInfo's bytes, as received,
    /// must be exactly a GroupInfoTBS with this Observer's current
    /// GroupContext, the merged Commit's confirmation tag and its committer
    /// as `signer`, followed by a signature that verifies under the
    /// committer's leaf signature key. The extensions are the GroupInfo's
    /// own; a `ratchet_tree` extension among them is not compared with the
    /// tree.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::PendingCommit`] while a Commit is pending,
    /// [`ObserverError::NoMergedCommit`] if this Observer has not merged a
    /// Commit, [`ObserverError::Decode`] if the extensions cannot be read,
    /// [`ObserverError::InvalidGroupInfo`] if the GroupInfo does not match
    /// the current epoch or its signature does not verify, and
    /// [`ObserverError::Encode`] if a structure cannot be encoded.
    pub fn verify_group_info(&self, group_info: &GroupInfo) -> Result<(), ObserverError> {
        if self.pending_commit.is_some() {
            return Err(ObserverError::PendingCommit);
        }
        let committer = self.committer.ok_or(ObserverError::NoMergedCommit)?;
        let received = group_info.as_bytes();
        let decoded = VerifiableGroupInfo::tls_deserialize_exact(received)
            .map_err(|e| ObserverError::Decode(e.into()))?;
        let tbs = self.group_info_tbs(decoded.extensions(), committer)?;
        let signature = received.strip_prefix(tbs.as_slice()).ok_or_else(|| {
            ObserverError::InvalidGroupInfo(
                "the GroupInfo's GroupContext, confirmation tag or signer is not the current epoch's"
                    .into(),
            )
        })?;
        let signature = VLBytes::tls_deserialize_exact(signature)
            .map_err(|e| ObserverError::InvalidGroupInfo(e.into()))?;
        let leaf = self.group.leaf(committer).ok_or_else(|| {
            ObserverError::InvalidGroupInfo("the committer's leaf is blank".into())
        })?;
        label::verify_with_label(
            leaf.signature_key().as_slice(),
            GROUP_INFO_LABEL,
            &tbs,
            signature.as_slice(),
        )
        .map_err(|e| ObserverError::InvalidGroupInfo(e.into()))
    }

    /// RFC 9420 §12.4.3: the GroupInfoTBS of the current epoch with
    /// `extensions`, signed by `signer`.
    fn group_info_tbs(
        &self,
        extensions: &Extensions<OpenMlsGroupInfo>,
        signer: LeafNodeIndex,
    ) -> Result<Vec<u8>, ObserverError> {
        let mut tbs = encode(self.group.group_context())?;
        tbs.extend(encode(extensions)?);
        tbs.extend(encode(self.group.confirmation_tag())?);
        tbs.extend(encode(&signer)?);
        Ok(tbs)
    }
}

/// Converts an OpenMLS value to the [`crate::wire`] type with the same TLS
/// encoding.
fn to_wire<T: Deserialize>(value: &impl Serialize) -> Result<T, ObserverError> {
    T::tls_deserialize_exact(encode(value)?).map_err(|e| ObserverError::Encode(e.into()))
}

/// TLS-encodes `value`.
fn encode(value: &impl Serialize) -> Result<Vec<u8>, ObserverError> {
    value
        .tls_serialize_detached()
        .map_err(|e| ObserverError::Encode(e.into()))
}

impl std::fmt::Debug for Observer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observer")
            .field("group_id", &self.group_id())
            .field("epoch", &self.epoch())
            .field("pending_commit", &self.pending_commit.is_some())
            .finish_non_exhaustive()
    }
}
