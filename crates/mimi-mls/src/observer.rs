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
//! - The required-components check (decision mimid-1wgh.4.45) covers only
//!   leaves a Commit adds or updates, not the leaves in the tree given to
//!   [`Observer::from_group_info`] (mimid-1wgh.4.51).
//! - PrivateMessages cannot be processed; the hub forwards them unread.
//! - Proposals from external senders are accepted only for the types OpenMLS
//!   supports there (Add, Remove and GroupContextExtensions). An external
//!   AppDataUpdate proposal is rejected.
//! - An [`Observer`] cannot be reloaded from the [`Store`] after a restart.
//!   OpenMLS does not persist the lifetime policy, so a future reload must
//!   set it to Skip again.
//! - [`Observer::group_info`] works only after this Observer has merged a
//!   Commit, since the GroupInfo signer is the committer. It cannot rebuild
//!   the GroupInfo of the epoch the Observer started in.
//! - [`Observer::group_info`] puts a rebuilt ratchet_tree extension first in
//!   the extension list. ratchet-tree-options-01 §4 does not say where it
//!   goes; a committer that put it elsewhere signed different bytes, and the
//!   signature check fails (decision mimid-1wgh.4.46).
//! - [`Observer::group_info`] does not check the previous-epoch half of
//!   `ratchet_tree_presence` (whether the previous GroupInfo had a
//!   ratchet_tree extension). It uses only the current-epoch half, which the
//!   signature covers (decision mimid-1wgh.4.47).

use openmls::component::ComponentId;
use openmls::group::{LeafNodeLifetimePolicy, ProposalStore, PublicGroup, StagedCommit};
use openmls::messages::group_info::GroupInfo as OpenMlsGroupInfo;
use openmls::prelude::{
    Extension, Extensions, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    ProcessedMessageContent, ProtocolMessage, RatchetTreeExtension, RatchetTreeIn,
};
use tls_codec::{Deserialize, Serialize, VLBytes};

use crate::member::{
    CommitSummary, ComponentOp, Sender, SharedError, basic_identity, check_staged_leaves,
    convert_sender, resolve_app_data_updates, summarize,
};
use crate::wire::{PartialGroupInfo, RatchetTreePresence};
use crate::{ErrorSource, Store, label};

/// RFC 9420 §6: the MLSMessage header for a GroupInfo, `version` mls10
/// (0x0001) and `wire_format` mls_group_info (0x0004).
const GROUP_INFO_MESSAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];

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
    /// signature or tree hash (RFC 9420 §12.4.3.1).
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
    /// committer's leaf index in the new epoch.
    pending_commit: Option<(StagedCommit, LeafNodeIndex)>,
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
    /// # Errors
    ///
    /// Returns [`ObserverError::Decode`] for malformed input,
    /// [`ObserverError::UnexpectedMessage`] if the message is not a
    /// GroupInfo, [`ObserverError::MissingRatchetTree`] if there is no tree,
    /// and [`ObserverError::InvalidGroupInfo`] if validation fails or the
    /// state cannot be stored.
    pub fn from_group_info(
        store: &Store,
        group_info: &[u8],
        ratchet_tree: Option<&[u8]>,
    ) -> Result<Self, ObserverError> {
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
        Ok(Self {
            group,
            pending_commit: None,
            committer: None,
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
    /// [`ObserverError::Process`] if MLS validation fails,
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
        if self.pending_commit.is_some() {
            return Err(ObserverError::PendingCommit);
        }
        let provider = store.provider();
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(|e| ObserverError::Decode(e.into()))?
            .try_into_protocol_message()
            .map_err(|_| ObserverError::UnexpectedMessage)?;
        if let ProtocolMessage::PrivateMessage(_) = message {
            return Err(ObserverError::UnexpectedMessage);
        }
        let processed = self
            .group
            .process_message(provider.crypto(), message)
            .map_err(|e| ObserverError::Process(e.into()))?;
        // mls-extensions-10 §4.9: the whole authenticated_data is SafeAAD,
        // as in Member::process.
        if processed.safe_aad().is_some() && !processed.tail_aad().is_empty() {
            return Err(ObserverError::TrailingAad);
        }
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
                self.pending_commit = Some((*staged, committer));
                Ok(Observed::Commit(summary))
            }
            _ => Err(ObserverError::UnexpectedMessage),
        }
    }

    /// Merges the pending Commit, moving the group to the next epoch.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError::NoPendingCommit`] if no Commit is pending,
    /// and [`ObserverError::Merge`] if the new state cannot be stored.
    pub fn merge_pending_commit(&mut self, store: &Store) -> Result<(), ObserverError> {
        let (staged, committer) = self
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
    /// (ratchet-tree-options-01 §4) and returns it as a TLS-encoded
    /// `MLSMessage` (RFC 9420 §6, §12.4.3).
    ///
    /// Call it after [`Observer::merge_pending_commit`] has merged the
    /// Commit that `partial` came with. The GroupInfo is built from this
    /// Observer's state in the new epoch (decision mimid-1wgh.4.20):
    ///
    /// - `group_context`: the current GroupContext;
    /// - `extensions`: `partial`'s `group_info_extensions`, preceded by a
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
            // ratchet-tree-options-01 §4 does not say where the extension
            // goes. It goes first, as OpenMLS puts it.
            // ratchet-tree-options-01 §4; decision mimid-1wgh.4.46
            let mut list = vec![Extension::RatchetTree(RatchetTreeExtension::new(
                self.group.export_ratchet_tree(),
            ))];
            list.extend(extensions.iter().cloned());
            extensions = Extensions::from_vec(list)
                .map_err(|e| ObserverError::InvalidPartialGroupInfo(e.into()))?;
        }

        // RFC 9420 §12.4.3: GroupInfoTBS.
        let mut tbs = encode(self.group.group_context())?;
        tbs.extend(encode(&extensions)?);
        tbs.extend(encode(self.group.confirmation_tag())?);
        tbs.extend(encode(&committer)?);

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
