//! Group membership for a client: create, join, commit, process and send.
//!
//! A [`Member`] is one client's view of one MLS group (RFC 9420). It wraps
//! an OpenMLS group, and every MLS message crosses its API as TLS-encoded
//! bytes.
//!
//! The [`Member`] does not own the [`Identity`] whose leaf it is. Every
//! method that needs keys or storage takes that [`Identity`] as an argument,
//! so one client can be a member of many groups. Passing an identity that
//! does not own the group's leaf fails with [`MemberError::WrongIdentity`].
//!
//! # Wire formats
//!
//! Commits and proposals go out as PublicMessage, so that the hub can
//! validate them. Application data always goes out as PrivateMessage.
//! Incoming messages may use either wire format. SemiPrivateMessage is not
//! supported (design for mimid-1wgh.4, decision DR-7).
//!
//! # Application data
//!
//! The group's `app_data_dictionary` GroupContext extension
//! (mls-extensions-10 §4.6) is set by [`Member::create`] and changed only
//! through AppDataUpdate proposals (§4.7). This module enforces the §4.7
//! validity rules. What a component's data means, and how an update changes
//! it, is up to the caller's `apply` function (see [`ComponentOp`]).
//!
//! # Safe AAD
//!
//! When the GroupContext carries the `safe_aad` component, the whole
//! `authenticated_data` of every message is a SafeAAD struct
//! (mls-extensions-10 §4.9, decision mimid-1wgh.4.17). This module never
//! sends raw authenticated data, and rejects incoming messages with bytes
//! after the SafeAAD struct.
//!
//! # Required components
//!
//! The GroupContext `safe_aad` and `app_components` lists name the
//! components every member must support (mls-extensions-10 §5). A Commit
//! this module builds or receives is refused if a leaf it adds or updates
//! lacks one of them in its own list, as RFC 9420 §11.1 does for
//! `required_capabilities` (INTERPRETATION, decision mimid-1wgh.4.45). The
//! [`Observer`](crate::observer::Observer) applies the same check.
//!
//! [`Member::create`] refuses a group whose lists the creator's own leaf
//! does not meet. [`Member::join_welcome`], [`Member::join_external`] and
//! [`Observer::from_group_info`](crate::observer::Observer::from_group_info)
//! accept a group whose existing leaves do not meet them, and return those
//! leaves' indices (decision mimid-1wgh.4.57).
//!
//! # Out of sync
//!
//! The hub orders Commits, and the first valid Commit of an epoch wins.
//! Suppose MLS has authenticated a Commit for this member's current epoch,
//! but the member then refuses it or cannot apply it. The hub and the other
//! members have then moved on without this member. [`Member::process`]
//! returns the error as usual, keeps all group state as it was, and marks
//! the member out of sync ([`Member::out_of_sync`]). From then on every call
//! that would change the group state fails with [`MemberError::OutOfSync`].
//! The way back is a fresh [`Member`], from [`Member::join_external`] (a
//! resync) or [`Member::join_welcome`].
//!
//! The mark is not written to the [`Store`](crate::Store). The caller (the
//! agent) persists the [`OutOfSync`] it reads from [`Member::out_of_sync`],
//! and hands it back through [`Member::restore_out_of_sync`] after
//! [`Member::load`] (decision mimid-1wgh.4.61).
//!
//! Which failures mark the member is decision mimid-1wgh.4.60. Input that
//! fails before MLS authenticates it never marks the member: it
//! may come from anyone, and could otherwise wedge the group. This covers
//! undecodable input, another group's messages, messages from another epoch
//! (stale replays, and messages from epochs this member has not reached),
//! and failed signatures, membership tags or decryption. Only Commits mark
//! the member; a refused proposal or application message does not.
//!
//! # Limitations
//!
//! - Messages from an earlier epoch cannot be decrypted once a Commit has
//!   been merged (OpenMLS keeps no past epoch secrets by default).
//! - While a proposal received through [`Member::process`] is pending, OpenMLS
//!   refuses to [`send`](Member::send) until a Commit covers it.
//! - AppDataUpdate proposals are supported only inline in this member's own
//!   Commits and in Commits it receives. Sending a standalone AppDataUpdate
//!   proposal is not supported.
//! - A Commit is refused only for the leaves it adds or updates, judged
//!   against the post-Commit GroupContext (decision mimid-1wgh.4.49). Leaves
//!   already in a joined group's tree are reported, not refused, and only
//!   at join time (decision mimid-1wgh.4.57). [`Member::join_welcome`] does
//!   not check this identity's own leaf. This crate's leaves list only
//!   `frank_aad` (0x0020) as a Safe AAD component (decision
//!   mimid-1wgh.4.52), so it cannot create or externally join a group
//!   whose `safe_aad` list requires any other, and after joining one by
//!   Welcome it refuses its own Commits that carry an UpdatePath.
//! - A member does not check the `lifetime` of leaves it receives: in the
//!   tree of a group it joins, and in the Add, Update and UpdatePath leaves
//!   of Proposals and Commits it processes (RFC 9420 §7.3, decision
//!   mimid-1wgh.4.56). Signatures, the tree hash and every other leaf check
//!   still apply. It checks the lifetime of the KeyPackages it adds itself,
//!   but not of one in an Add proposal another member sent, even when its
//!   own Commit includes that proposal by reference (decision
//!   mimid-1wgh.4.58).
//! - [`Member::join_external`] checks its own leaf before building the
//!   Commit, and merges the Commit at once, so it cannot be rolled back if
//!   the hub rejects it (decision mimid-1wgh.4.54). It sends no
//!   PreSharedKey proposals. A join by an identity already in the group
//!   becomes a resync, allowed but reported to the caller (RFC 9420
//!   §12.4.3.2, decision mimid-1wgh.4.55). Finding the removed leaf
//!   verifies the GroupInfo and tree a second time.
//! - The out-of-sync mark is not stored: the OpenMLS SQLite storage gives
//!   this crate no access to its database connection. The caller persists
//!   it and restores it with [`Member::restore_out_of_sync`] after
//!   [`Member::load`]; a member loaded without that is not marked (decision
//!   mimid-1wgh.4.61).
//! - A Commit whose membership tag (RFC 9420 §6.2) fails does not mark the
//!   member, because the tag is checked before the signature. The hub
//!   cannot check membership tags, so it may accept such a Commit. Nor does
//!   a Commit from an epoch this member has not reached, which it cannot
//!   authenticate (decision mimid-1wgh.4.60).

use std::collections::BTreeSet;

use openmls::component::{ComponentData, ComponentId, ComponentsList};
use openmls::framing::SafeAadItem;
use openmls::grease::random_grease_value;
use openmls::group::{
    AppDataDictionaryUpdater, LeafNodeLifetimePolicy, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY, MlsGroup,
    MlsGroupJoinConfig, StagedCommit, StagedWelcome,
};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{
    AppDataDictionary, AppDataDictionaryExtension, BasicCredential, ContentType, Credential,
    Extension, Extensions, ExternalCommitBuilderError, GroupContext, GroupId, KeyPackageIn,
    LeafNode, LeafNodeIndex, LeafNodeParameters, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    ProcessMessageError, ProcessedMessage, ProcessedMessageContent, ProposalStore, ProtocolVersion,
    PublicGroup, RatchetTreeIn,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

use crate::identity::{
    APP_COMPONENTS, CIPHERSUITE, COMPONENT_GREASE, SAFE_AAD, leaf_capabilities, leaf_extensions,
};
use crate::{ErrorSource, Identity};

/// An external sender for the GroupContext `external_senders` extension
/// (RFC 9420 §12.1.8.1), with a BasicCredential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSender {
    /// The sender's signature public key.
    pub signature_key: Vec<u8>,
    /// The BasicCredential `identity` (RFC 9420 §5.3).
    pub identity: Vec<u8>,
}

/// One operation on a component's data, carried in an AppDataUpdate proposal
/// (mls-extensions-10 §4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppDataUpdate {
    /// `op = update`: the opaque `update` is interpreted by the component.
    Update {
        /// The component whose data changes.
        component_id: ComponentId,
        /// The component-defined update.
        update: Vec<u8>,
    },
    /// `op = remove`: the component's data is removed.
    Remove {
        /// The component whose data is removed.
        component_id: ComponentId,
    },
}

/// The operation the `apply` function of [`Member::commit`] and
/// [`Member::process`] is asked to judge, for one component.
///
/// `apply(component_id, current_data, op)` must return:
/// - for [`ComponentOp::Update`], `Ok(Some(new_data))`;
/// - for [`ComponentOp::Remove`], `Ok(None)`;
/// - `Err(_)` if the component is unknown or the update is invalid.
///
/// Any other answer makes the proposal list invalid
/// (mls-extensions-10 §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentOp<'a> {
    /// The `update` fields of every update proposal for the component, in
    /// the order they appear in the Commit.
    Update(&'a [&'a [u8]]),
    /// A single remove proposal. The component has data at this point.
    Remove,
}

/// Who sent a message (RFC 9420 §6, `Sender`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Sender {
    /// A member, by leaf index.
    Member(u32),
    /// An external sender, by index into `external_senders`.
    External(u32),
    /// A new member proposing to join.
    NewMemberProposal,
    /// A new member joining by external Commit.
    NewMemberCommit,
}

/// What a merged Commit changed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommitSummary {
    /// Who sent the Commit.
    pub committer: Sender,
    /// The epoch the group is in after the Commit.
    pub epoch: u64,
    /// BasicCredential identities of the members added.
    pub added: Vec<Vec<u8>>,
    /// Leaf indices, in the previous epoch, of the members removed.
    pub removed: Vec<u32>,
    /// Whether this member was removed. The group is then inactive.
    pub self_removed: bool,
    /// Components whose data an AppDataUpdate proposal changed, ascending.
    pub components: Vec<ComponentId>,
}

/// The result of [`Member::process`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Incoming {
    /// Decrypted application data.
    Application {
        /// The sender's leaf index.
        sender: u32,
        /// The sender's BasicCredential identity.
        sender_identity: Vec<u8>,
        /// The application data.
        data: Vec<u8>,
        /// The SafeAAD items (mls-extensions-10 §4.9), in ascending
        /// component order. Empty when the group does not use Safe AAD.
        safe_aad: Vec<(ComponentId, Vec<u8>)>,
    },
    /// A proposal, now stored until a Commit covers it.
    Proposal {
        /// Who sent the proposal.
        sender: Sender,
    },
    /// A Commit, now merged.
    Commit(CommitSummary),
    /// A PrivateMessage this member sent itself. It cannot be decrypted and
    /// needs no action.
    OwnMessage,
}

/// The messages produced by [`Member::commit`], each a TLS-encoded
/// `MLSMessage` (RFC 9420 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommitBundle {
    /// The Commit, as a PublicMessage.
    pub commit: Vec<u8>,
    /// The Welcome for added members, if any were added.
    pub welcome: Option<Vec<u8>>,
    /// The signed GroupInfo for the new epoch (RFC 9420 §12.4.3), with
    /// signer this member's leaf. Its extensions are exactly
    /// `[external_pub]`: no ratchet_tree, which protocol-06 §5.3 sends
    /// separately. A PartialGroupInfo (ratchet-tree-options-01 §4) is this
    /// GroupInfo's extensions and signature.
    pub group_info: Vec<u8>,
}

/// The result of [`Member::join_welcome`].
///
/// A group whose existing leaves miss a required component is joined, not
/// refused, and those leaves are reported (decisions mimid-1wgh.4.57,
/// mimid-1wgh.4.59).
#[derive(Debug)]
#[non_exhaustive]
pub struct WelcomeJoin {
    /// The new member.
    pub member: Member,
    /// The leaf indices, ascending, of the other members whose leaves do
    /// not list a component the GroupContext `safe_aad` or `app_components`
    /// list requires (see the module's `# Required components`). This
    /// identity's own leaf is not checked.
    pub nonconforming_leaves: Vec<u32>,
}

/// The result of [`Member::join_external`].
///
/// A group whose existing leaves miss a required component is joined, not
/// refused, and those leaves are reported (decisions mimid-1wgh.4.57,
/// mimid-1wgh.4.59).
#[derive(Debug)]
#[non_exhaustive]
pub struct ExternalJoin {
    /// The new member, already in the new epoch.
    pub member: Member,
    /// The external Commit and the new epoch's GroupInfo, for the hub. It
    /// has no Welcome.
    pub commit_bundle: CommitBundle,
    /// For a resync, the leaf index, in the previous epoch, of the old
    /// leaf the Commit removes; `None` for a plain join (decision
    /// mimid-1wgh.4.55).
    pub resync_removed: Option<u32>,
    /// The leaf indices, ascending and in the new epoch, of the other
    /// members whose leaves do not list a component the GroupContext
    /// `safe_aad` or `app_components` list requires (see the module's
    /// `# Required components`).
    pub nonconforming_leaves: Vec<u32>,
}

/// Why a [`Member`] is out of sync (see the module's `# Out of sync`).
///
/// The caller persists it and restores it with
/// [`Member::restore_out_of_sync`] (decision mimid-1wgh.4.61).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutOfSync {
    /// The epoch of the refused Commit. The member is still in it.
    pub epoch: u64,
    /// The error [`Member::process`] returned for the Commit, followed by
    /// its causes, as text.
    pub reason: String,
}

impl OutOfSync {
    /// Rebuilds a saved [`OutOfSync`] from its fields.
    pub fn new(epoch: u64, reason: String) -> Self {
        Self { epoch, reason }
    }
}

/// Errors returned by [`Member`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MemberError {
    /// The [`Identity`] passed in does not own this member's leaf.
    #[error("the identity does not own this group member's leaf")]
    WrongIdentity,
    /// Building the identity's LeafNode material failed.
    #[error("cannot build the LeafNode")]
    Identity(#[source] crate::Error),
    /// Two initial components share an id (mls-extensions-10 §4.6).
    #[error("component {0:#06x} is given more than once")]
    DuplicateComponent(ComponentId),
    /// The store holds no group with the requested group id.
    #[error("no stored group has this group id")]
    GroupNotFound,
    /// The stored group could not be read or decoded.
    #[error("cannot load the group from the MLS state database")]
    Load(#[source] ErrorSource),
    /// The group could not be created.
    #[error("cannot create the group")]
    Create(#[source] ErrorSource),
    /// The input is not a well-formed TLS encoding of the expected type.
    #[error("cannot decode the MLS input")]
    Decode(#[source] ErrorSource),
    /// The input decoded, but is not the kind of message this call takes.
    #[error("unexpected MLS message type")]
    UnexpectedMessage,
    /// A KeyPackage failed validation (RFC 9420 §10.1).
    #[error("invalid KeyPackage")]
    InvalidKeyPackage(#[source] ErrorSource),
    /// The Welcome, or the GroupInfo for an external join, could not be
    /// processed.
    #[error("cannot join the group")]
    Join(#[source] ErrorSource),
    /// No ratchet tree was given, and the GroupInfo has no `ratchet_tree`
    /// extension (RFC 9420 §12.4.3.3).
    #[error("no ratchet tree was given and the GroupInfo carries none")]
    MissingRatchetTree,
    /// The GroupInfo has no `external_pub` extension, so the group cannot
    /// be joined by external Commit (RFC 9420 §12.4.3.2).
    #[error("the GroupInfo has no external_pub extension")]
    MissingExternalPub,
    /// The GroupInfo or ratchet tree failed validation, for example its
    /// signature or tree hash (RFC 9420 §12.4.3.1), or the group does not
    /// use ciphersuite 1.
    #[error("invalid GroupInfo or ratchet tree")]
    InvalidGroupInfo(#[source] ErrorSource),
    /// The Commit could not be built.
    #[error("cannot build the Commit")]
    Commit(#[source] ErrorSource),
    /// The message failed MLS validation or decryption. The group state is
    /// unchanged.
    #[error("the MLS message is invalid")]
    Process(#[source] ErrorSource),
    /// `authenticated_data` has bytes after the SafeAAD struct
    /// (mls-extensions-10 §4.9, decision mimid-1wgh.4.17). The group state
    /// is unchanged.
    #[error("bytes follow the SafeAAD struct")]
    TrailingAad,
    /// SafeAAD items were given, but the group does not use Safe AAD.
    #[error("the group does not use Safe AAD")]
    SafeAadNotEnabled,
    /// SafeAAD items are not in strictly ascending component order.
    #[error("invalid SafeAAD items")]
    InvalidSafeAad(#[source] ErrorSource),
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
    /// The application message could not be created.
    #[error("cannot create the application message")]
    Send(#[source] ErrorSource),
    /// A Commit or proposal could not be stored or merged. After
    /// [`Member::join_external`], part of the new state may have been
    /// stored (decision mimid-1wgh.4.54).
    #[error("cannot update the group state")]
    Merge(#[source] ErrorSource),
    /// The member is out of sync, and the call would change group state
    /// that no longer matches the hub's (see the module's `# Out of sync`).
    /// Nothing was changed.
    #[error("the group is out of sync")]
    OutOfSync,
    /// A secret could not be exported.
    #[error("cannot export a secret")]
    Export(#[source] ErrorSource),
    /// A structure could not be TLS-encoded.
    #[error("cannot encode an MLS structure")]
    Encode(#[source] ErrorSource),
}

/// One client's membership in one MLS group.
pub struct Member {
    group: MlsGroup,
    /// The signature public key of the [`Identity`] that owns this member.
    /// Kept here because the leaf is gone from the tree after a removal.
    owner_signature_key: Vec<u8>,
    /// Set when this member refuses a Commit for its current epoch that MLS
    /// authenticated.
    out_of_sync: Option<OutOfSync>,
}

impl Member {
    /// Wraps `group`, whose own leaf belongs to `identity`. The group stops
    /// checking the `lifetime` of leaves it receives in Proposals and
    /// Commits (RFC 9420 §7.3; decision mimid-1wgh.4.56). OpenMLS does not
    /// store this policy, so every constructor, including
    /// [`Member::load`], comes through here.
    fn from_group(mut group: MlsGroup, identity: &Identity) -> Self {
        group.set_leaf_node_lifetime_policy(LeafNodeLifetimePolicy::Skip);
        Self {
            group,
            owner_signature_key: identity.signature_public_key().to_vec(),
            out_of_sync: None,
        }
    }

    /// Creates a group with `group_id`, with this identity as its only
    /// member, in epoch 0.
    ///
    /// The GroupContext carries `external_senders` (RFC 9420 §12.1.8.1) if
    /// any are given, and an `app_data_dictionary` holding `components`
    /// (mls-extensions-10 §4.6) if any are given. Including the `safe_aad`
    /// component (0x0002) turns on Safe AAD framing for the group (§4.9).
    /// The data of `safe_aad` and `app_components` (0x0001) must be a
    /// canonical `ComponentsList` (§5): the components every member must
    /// support. This identity's own leaf must support them too (decision
    /// mimid-1wgh.4.57).
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::DuplicateComponent`] if a component id repeats,
    /// [`MemberError::InvalidComponentsList`] if the `safe_aad` or
    /// `app_components` data is not a canonical `ComponentsList`,
    /// [`MemberError::MissingSafeAadComponent`] or
    /// [`MemberError::MissingAppComponent`] if this identity's leaf does not
    /// list a non-GREASE component one of them requires,
    /// [`MemberError::Identity`] if the LeafNode material cannot be built,
    /// and [`MemberError::Create`] if OpenMLS rejects the group.
    pub fn create(
        identity: &Identity,
        group_id: &[u8],
        external_senders: &[ExternalSender],
        components: &[(ComponentId, Vec<u8>)],
    ) -> Result<Self, MemberError> {
        let provider = identity.provider();
        let rand = provider.rand();

        // required_capabilities is left to the protocol layer (decision
        // mimid-1wgh.4.33).
        let mut extensions = Vec::with_capacity(2);
        if !external_senders.is_empty() {
            let senders = external_senders
                .iter()
                .map(|sender| {
                    openmls::prelude::ExternalSender::new(
                        sender.signature_key.clone().into(),
                        BasicCredential::new(sender.identity.clone()).into(),
                    )
                })
                .collect();
            extensions.push(Extension::ExternalSenders(senders));
        }
        if !components.is_empty() {
            let mut dictionary = AppDataDictionary::new();
            for (component_id, data) in components {
                if dictionary.contains(component_id) {
                    return Err(MemberError::DuplicateComponent(*component_id));
                }
                dictionary.insert(*component_id, data.clone());
            }
            extensions.push(Extension::AppDataDictionary(
                AppDataDictionaryExtension::new(dictionary),
            ));
        }
        let extensions =
            Extensions::from_vec(extensions).map_err(|e| MemberError::Create(e.into()))?;
        // mls-extensions-10 §5: the lists are decoded strictly (decision
        // mimid-1wgh.4.45), and our own leaf must meet them before anything
        // is stored (decision mimid-1wgh.4.57).
        let leaf_extensions = leaf_extensions(rand).map_err(MemberError::Identity)?;
        check_leaf(&leaf_extensions, &required_lists(&extensions)?)?;

        let group = MlsGroup::builder()
            .with_group_id(GroupId::from_slice(group_id))
            .ciphersuite(CIPHERSUITE)
            .with_wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .with_capabilities(leaf_capabilities(rand, random_grease_value(rand)))
            .with_leaf_node_extensions(leaf_extensions)
            .map_err(|e| MemberError::Create(e.into()))?
            .with_group_context_extensions(extensions)
            .build(
                provider,
                identity.signer(),
                identity.credential_with_key().clone(),
            )
            .map_err(|e| MemberError::Create(e.into()))?;
        Ok(Self::from_group(group, identity))
    }

    /// Reloads this identity's membership in the group `group_id` from the
    /// identity's [`Store`](crate::Store), for example after a restart.
    /// OpenMLS writes the group state to the store on every change, so the
    /// member is as it was after the last call that changed it.
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::GroupNotFound`] if the store holds no group
    /// `group_id`, [`MemberError::Load`] if the stored group cannot be read
    /// or decoded, and [`MemberError::WrongIdentity`] if the group's own
    /// leaf has another signature key. A member that has been removed has
    /// no own leaf, so its owner cannot be checked.
    ///
    /// The loaded member is not out of sync, because that mark is not
    /// stored. A caller that saved one restores it with
    /// [`Member::restore_out_of_sync`] (decision mimid-1wgh.4.61).
    pub fn load(identity: &Identity, group_id: &[u8]) -> Result<Self, MemberError> {
        let group = MlsGroup::load(
            identity.provider().storage(),
            &GroupId::from_slice(group_id),
        )
        .map_err(|e| MemberError::Load(e.into()))?
        .ok_or(MemberError::GroupNotFound)?;
        if group
            .own_leaf()
            .is_some_and(|leaf| leaf.signature_key().as_slice() != identity.signature_public_key())
        {
            return Err(MemberError::WrongIdentity);
        }
        Ok(Self::from_group(group, identity))
    }

    /// Joins a group from a TLS-encoded `MLSMessage` carrying a Welcome
    /// (RFC 9420 §12.4.3.1), using a KeyPackage this identity published.
    ///
    /// `ratchet_tree` is a TLS-encoded ratchet tree (RFC 9420 §12.4.3.3),
    /// needed when the Welcome's GroupInfo has no `ratchet_tree` extension.
    ///
    /// The returned [`WelcomeJoin`] also reports the existing leaves that
    /// miss a required component (decision mimid-1wgh.4.57).
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::Decode`] for malformed input,
    /// [`MemberError::UnexpectedMessage`] if the message is not a Welcome,
    /// [`MemberError::Join`] if the Welcome cannot be processed, and
    /// [`MemberError::InvalidComponentsList`] if the GroupContext's
    /// `safe_aad` or `app_components` data is malformed (decisions
    /// mimid-1wgh.4.57, mimid-1wgh.4.59).
    pub fn join_welcome(
        identity: &Identity,
        welcome: &[u8],
        ratchet_tree: Option<&[u8]>,
    ) -> Result<WelcomeJoin, MemberError> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|e| MemberError::Decode(e.into()))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(MemberError::UnexpectedMessage);
        };
        let ratchet_tree = ratchet_tree
            .map(RatchetTreeIn::tls_deserialize_exact)
            .transpose()
            .map_err(|e| MemberError::Decode(e.into()))?;
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        let provider = identity.provider();
        let mut builder = StagedWelcome::build_from_welcome(provider, &config, welcome)
            .map_err(|e| MemberError::Join(e.into()))?
            // RFC 9420 §7.3; decision mimid-1wgh.4.56.
            .skip_lifetime_validation();
        if let Some(ratchet_tree) = ratchet_tree {
            builder = builder.with_ratchet_tree(ratchet_tree);
        }
        let staged = builder.build().map_err(|e| MemberError::Join(e.into()))?;
        // Decoded before into_group stores the group; fails closed
        // (decisions mimid-1wgh.4.57, mimid-1wgh.4.59).
        let required = required_lists(staged.group_context().extensions())?;
        let group = staged
            .into_group(provider)
            .map_err(|e| MemberError::Join(e.into()))?;
        // Decision mimid-1wgh.4.57.
        let nonconforming_leaves = nonconforming_leaves(
            group.public_group(),
            &required,
            Some(group.own_leaf_index()),
        );
        // The Welcome was decrypted with this identity's KeyPackage, so the
        // new leaf belongs to it.
        Ok(WelcomeJoin {
            member: Self::from_group(group, identity),
            nonconforming_leaves,
        })
    }

    /// Joins a group by external Commit (RFC 9420 §12.4.3.2), from a
    /// TLS-encoded `MLSMessage` carrying the group's current GroupInfo.
    ///
    /// The GroupInfo must have an `external_pub` extension. `ratchet_tree`
    /// is a TLS-encoded ratchet tree (RFC 9420 §12.4.3.3), needed when the
    /// GroupInfo has no `ratchet_tree` extension; it is ignored when it
    /// does. The new leaf is built exactly as [`Member::create`] builds the
    /// creator's, and goes at the leftmost free leaf. If the group already
    /// has a leaf with this identity's signature key, the Commit also
    /// removes it (a "resync" Commit, RFC 9420 §12.4.3.2).
    ///
    /// A resync is allowed but reported (decision mimid-1wgh.4.55): RFC 9420
    /// §12.4.3.2 notes that it lets anyone holding a member's signature
    /// private key replace that member in a single Commit:
    /// [`ExternalJoin::resync_removed`] names the old leaf.
    ///
    /// Existing leaves that miss a required component are reported in
    /// [`ExternalJoin::nonconforming_leaves`], not refused (decision
    /// mimid-1wgh.4.57); this identity's own leaf must list them all.
    ///
    /// [`ExternalJoin::commit_bundle`] holds the external Commit (as a
    /// PublicMessage, with an empty SafeAAD as its `authenticated_data` when
    /// the group uses Safe AAD) and the new epoch's GroupInfo, for the hub.
    /// Unlike [`Member::commit`], the Commit is already merged: the member
    /// is in the new epoch. If the hub rejects the Commit, drop the member.
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::Decode`] for malformed input,
    /// [`MemberError::UnexpectedMessage`] if the message is not a GroupInfo,
    /// [`MemberError::MissingRatchetTree`] if no tree is available,
    /// [`MemberError::InvalidGroupInfo`] if the GroupInfo or tree fails
    /// validation or the group does not use ciphersuite 1,
    /// [`MemberError::MissingExternalPub`] if the GroupInfo lacks
    /// `external_pub`, [`MemberError::InvalidComponentsList`],
    /// [`MemberError::MissingSafeAadComponent`] or
    /// [`MemberError::MissingAppComponent`] if this identity's leaf fails
    /// the required-components check (see the module's `# Required
    /// components`), [`MemberError::Identity`] if the LeafNode material
    /// cannot be built, [`MemberError::Join`] or [`MemberError::Commit`] if
    /// OpenMLS cannot build the Commit, and [`MemberError::Merge`] if the new
    /// state cannot be stored. Nothing is stored unless the call succeeds,
    /// except after [`MemberError::Merge`].
    pub fn join_external(
        identity: &Identity,
        group_info: &[u8],
        ratchet_tree: Option<&[u8]>,
    ) -> Result<ExternalJoin, MemberError> {
        let message = MlsMessageIn::tls_deserialize_exact(group_info)
            .map_err(|e| MemberError::Decode(e.into()))?;
        let MlsMessageBodyIn::GroupInfo(group_info) = message.extract() else {
            return Err(MemberError::UnexpectedMessage);
        };
        let ratchet_tree = ratchet_tree
            .map(RatchetTreeIn::tls_deserialize_exact)
            .transpose()
            .map_err(|e| MemberError::Decode(e.into()))?;
        // Decision mimid-1wgh.23: the identity's key and leaf are suite 1.
        if group_info.ciphersuite() != CIPHERSUITE {
            return Err(MemberError::InvalidGroupInfo(
                "the group does not use ciphersuite 1".into(),
            ));
        }
        // Read only after build_group has verified the GroupInfo signature,
        // which covers the GroupContext.
        let group_context = group_info.group_context().clone();
        // The tree build_group uses: the GroupInfo's own, else the one given.
        let resync_lookup = group_info
            .extensions()
            .ratchet_tree()
            .map(|extension| extension.ratchet_tree().clone())
            .or_else(|| ratchet_tree.clone())
            .map(|tree| (tree, group_info.clone()));

        let provider = identity.provider();
        let rand = provider.rand();
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        let mut builder = MlsGroup::external_commit_builder()
            .with_config(config)
            // RFC 9420 §7.3; decision mimid-1wgh.4.56.
            .skip_lifetime_validation();
        if let Some(ratchet_tree) = ratchet_tree {
            builder = builder.with_ratchet_tree(ratchet_tree);
        }
        // build_group writes nothing to storage; finalize does.
        let builder = builder
            .build_group(provider, group_info, identity.credential_with_key().clone())
            .map_err(|e| match e {
                ExternalCommitBuilderError::MissingRatchetTree => MemberError::MissingRatchetTree,
                ExternalCommitBuilderError::MissingExternalPub => MemberError::MissingExternalPub,
                ExternalCommitBuilderError::PublicGroupError(e) => {
                    MemberError::InvalidGroupInfo(e.into())
                }
                e => MemberError::Join(e.into()),
            })?;

        // Decision mimid-1wgh.4.55. Without a tree, build_group has failed.
        let resync_removed = match resync_lookup {
            Some((tree, group_info)) => resync_leaf(provider.crypto(), tree, group_info, identity)?,
            None => None,
        };

        // Decision mimid-1wgh.4.54: OpenMLS gives no access to the staged
        // external Commit before finalize stores it, so the new leaf is
        // checked here. The Commit
        // holds only ExternalInit and possibly a Remove, so the GroupContext
        // extensions it leads to are these (decision mimid-1wgh.4.49).
        let leaf_extensions = leaf_extensions(rand).map_err(MemberError::Identity)?;
        // A malformed list fails closed (decisions mimid-1wgh.4.57,
        // mimid-1wgh.4.59).
        let required = required_lists(group_context.extensions())?;
        check_leaf(&leaf_extensions, &required)?;
        let leaf = LeafNodeParameters::builder()
            .with_capabilities(leaf_capabilities(rand, random_grease_value(rand)))
            .with_extensions(leaf_extensions)
            .build();

        let (group, bundle) = builder
            .leaf_node_parameters(leaf)
            .load_psks(provider.storage())
            .map_err(|e| MemberError::Commit(e.into()))?
            // Without a ratchet_tree extension, as in Member::commit.
            .create_group_info(true)
            .build(rand, provider.crypto(), identity.signer(), |_| true)
            .map_err(|e| MemberError::Commit(e.into()))?
            .finalize(provider)
            .map_err(|e| MemberError::Merge(e.into()))?;
        let (commit, welcome, group_info) = bundle.into_messages();
        let group_info = group_info
            .ok_or_else(|| MemberError::Commit("OpenMLS exported no GroupInfo".into()))?;
        // Decision mimid-1wgh.4.57. A resync's old leaf is gone by now.
        let nonconforming_leaves = nonconforming_leaves(
            group.public_group(),
            &required,
            Some(group.own_leaf_index()),
        );
        let commit_bundle = CommitBundle {
            commit: encode(&commit)?,
            welcome: welcome.as_ref().map(encode).transpose()?,
            group_info: encode(&group_info)?,
        };
        Ok(ExternalJoin {
            member: Self::from_group(group, identity),
            commit_bundle,
            resync_removed,
            nonconforming_leaves,
        })
    }

    /// Builds a Commit that adds the TLS-encoded `KeyPackage`s in `adds`
    /// (without an `MLSMessage` wrapper, as [`Identity::key_package`]
    /// returns them), removes the members at leaf indices `removes`, applies
    /// `app_updates`, and covers any stored proposals.
    ///
    /// `apply` computes the new component data for `app_updates` and any
    /// stored AppDataUpdate proposals; see [`ComponentOp`]. Proposals for one
    /// component are given to `apply` in the order OpenMLS puts them in the
    /// Commit: stored proposals, then `app_updates` in order (decision
    /// mimid-1wgh.4.34).
    ///
    /// The returned [`CommitBundle`] always carries the new epoch's signed
    /// GroupInfo, for the hub (protocol-06 §5.3).
    ///
    /// The Commit is pending until [`Member::process`] sees it come back
    /// from the hub, or [`Member::merge_pending_commit`] is called. If the
    /// hub rejects it, call [`Member::clear_pending_commit`].
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::InvalidKeyPackage`] if a KeyPackage is
    /// malformed or invalid, [`MemberError::InvalidAppDataUpdate`] or
    /// [`MemberError::AppDataRejected`] if the AppDataUpdate proposals are
    /// invalid, [`MemberError::MissingSafeAadComponent`] or
    /// [`MemberError::MissingAppComponent`] if a new or updated leaf lacks a
    /// required component (see the module's `# Required components`),
    /// [`MemberError::InvalidComponentsList`] if the new GroupContext's
    /// `safe_aad` or `app_components` data is malformed, and
    /// [`MemberError::Commit`] if OpenMLS cannot build the Commit, and
    /// [`MemberError::OutOfSync`] if the member is out of sync. The group
    /// state is unchanged on error.
    pub fn commit<E>(
        &mut self,
        identity: &Identity,
        adds: &[&[u8]],
        removes: &[u32],
        app_updates: &[AppDataUpdate],
        mut apply: impl FnMut(ComponentId, Option<&[u8]>, ComponentOp<'_>) -> Result<Option<Vec<u8>>, E>,
    ) -> Result<CommitBundle, MemberError>
    where
        E: Into<ErrorSource>,
    {
        self.check_identity(identity)?;
        self.check_in_sync()?;
        let provider = identity.provider();

        let key_packages = adds
            .iter()
            .map(|bytes| {
                KeyPackageIn::tls_deserialize_exact(bytes)
                    .map_err(|e| MemberError::InvalidKeyPackage(e.into()))?
                    .validate(provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|e| MemberError::InvalidKeyPackage(e.into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proposals = app_updates.iter().map(|update| {
            let proposal = match update {
                AppDataUpdate::Update {
                    component_id,
                    update,
                } => AppDataUpdateProposal::update(*component_id, update.clone()),
                AppDataUpdate::Remove { component_id } => {
                    AppDataUpdateProposal::remove(*component_id)
                }
            };
            Proposal::AppDataUpdate(Box::new(proposal))
        });

        let mut builder = self
            .group
            .commit_builder()
            .propose_adds(key_packages)
            .propose_removals(removes.iter().copied().map(LeafNodeIndex::new))
            .add_proposals(proposals)
            .load_psks(provider.storage())
            .map_err(|e| MemberError::Commit(e.into()))?
            // Without a ratchet_tree extension: the group's config leaves
            // use_ratchet_tree_extension off (protocol-06 §5.3).
            .create_group_info(true);

        let app_data_proposals: Vec<AppDataUpdateProposal> =
            builder.app_data_update_proposals().cloned().collect();
        if !app_data_proposals.is_empty() {
            let mut updater = builder.app_data_dictionary_updater();
            resolve_app_data_updates(&mut updater, &app_data_proposals, &mut apply)?;
            let changes = updater.changes();
            builder.with_app_data_dictionary_updates(changes);
        }

        let bundle = builder
            .build(
                provider.rand(),
                provider.crypto(),
                identity.signer(),
                |_| true,
            )
            .map_err(|e| MemberError::Commit(e.into()))?
            .stage_commit(provider)
            .map_err(|e| MemberError::Commit(e.into()))?;
        let (commit, welcome, group_info) = bundle.into_messages();
        // The staged Commit shows every new or updated leaf, including those
        // of stored proposals, and the GroupContext it leads to.
        let checked = match self.group.pending_commit() {
            Some(staged) => check_staged_leaves(staged).map_err(MemberError::from),
            None => Err(MemberError::Commit("OpenMLS left no Commit pending".into())),
        }
        .and_then(|()| {
            group_info.ok_or_else(|| MemberError::Commit("OpenMLS exported no GroupInfo".into()))
        });
        let group_info = match checked {
            Ok(group_info) => group_info,
            Err(e) => {
                self.group
                    .clear_pending_commit(provider.storage())
                    .map_err(|e| MemberError::Merge(e.into()))?;
                return Err(e);
            }
        };
        Ok(CommitBundle {
            commit: encode(&commit)?,
            welcome: welcome.as_ref().map(encode).transpose()?,
            group_info: encode(&group_info)?,
        })
    }

    /// Merges this member's pending Commit, after the hub accepted it.
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::Merge`] if the merge fails, for example after
    /// this member was removed, and [`MemberError::OutOfSync`] if the member
    /// is out of sync: the hub then ordered another Commit in its place.
    pub fn merge_pending_commit(&mut self, identity: &Identity) -> Result<(), MemberError> {
        self.check_identity(identity)?;
        self.check_in_sync()?;
        self.group
            .merge_pending_commit(identity.provider())
            .map_err(|e| MemberError::Merge(e.into()))
    }

    /// Discards this member's pending Commit, after the hub rejected it.
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::Merge`] if the state cannot be stored, and
    /// [`MemberError::OutOfSync`] if the member is out of sync.
    pub fn clear_pending_commit(&mut self, identity: &Identity) -> Result<(), MemberError> {
        self.check_identity(identity)?;
        self.check_in_sync()?;
        self.group
            .clear_pending_commit(identity.provider().storage())
            .map_err(|e| MemberError::Merge(e.into()))
    }

    /// Processes one TLS-encoded `MLSMessage` carrying a PublicMessage or
    /// PrivateMessage for this group.
    ///
    /// Commits are merged and proposals are stored before this returns. A
    /// Commit carrying AppDataUpdate proposals is resolved with `apply`; see
    /// [`ComponentOp`]. When this member's own pending Commit comes back, it
    /// is merged.
    ///
    /// On any error the group state is left as it was: a message that fails
    /// to decrypt or validate never deletes group state. If the message is a
    /// Commit for the current epoch that MLS authenticated, the error also
    /// marks the member out of sync (see the module's `# Out of sync`).
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::Decode`] or [`MemberError::UnexpectedMessage`]
    /// for input that is not a group message, [`MemberError::Process`] if MLS
    /// validation or decryption fails, [`MemberError::TrailingAad`] if bytes
    /// follow the SafeAAD struct, [`MemberError::InvalidAppDataUpdate`] or
    /// [`MemberError::AppDataRejected`] for invalid AppDataUpdate proposals,
    /// [`MemberError::MissingSafeAadComponent`],
    /// [`MemberError::MissingAppComponent`] or
    /// [`MemberError::InvalidComponentsList`] if a Commit fails the
    /// required-components check (see the module's `# Required
    /// components`), [`MemberError::Merge`] if the new state cannot be
    /// stored, and [`MemberError::OutOfSync`] if the member was already out
    /// of sync.
    pub fn process<E>(
        &mut self,
        identity: &Identity,
        message: &[u8],
        mut apply: impl FnMut(ComponentId, Option<&[u8]>, ComponentOp<'_>) -> Result<Option<Vec<u8>>, E>,
    ) -> Result<Incoming, MemberError>
    where
        E: Into<ErrorSource>,
    {
        self.check_identity(identity)?;
        self.check_in_sync()?;
        let provider = identity.provider();
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(|e| MemberError::Decode(e.into()))?
            .try_into_protocol_message()
            .map_err(|_| MemberError::UnexpectedMessage)?;
        // Decision mimid-1wgh.4.60. Read from the unauthenticated header, so
        // it counts only once OpenMLS has verified the message. OpenMLS also
        // rejects other groups and epochs before that; the epoch is compared
        // here too.
        let current_epoch_commit =
            message.content_type() == ContentType::Commit && message.epoch() == self.group.epoch();
        let processed = match self.group.process_message(provider, message) {
            Ok(processed) => processed,
            Err(e) => {
                // OpenMLS returns InvalidCommit only after verifying the
                // signature; every earlier failure has another variant.
                let authenticated = matches!(e, ProcessMessageError::InvalidCommit(_));
                let error = MemberError::Process(e.into());
                return Err(if current_epoch_commit && authenticated {
                    self.mark_out_of_sync(error)
                } else {
                    error
                });
            }
        };
        match self.apply_processed(provider, processed, &mut apply) {
            Err(error) if current_epoch_commit => Err(self.mark_out_of_sync(error)),
            result => result,
        }
    }

    /// Finishes [`Member::process`] for a message OpenMLS has verified.
    fn apply_processed<E: Into<ErrorSource>>(
        &mut self,
        provider: &crate::store::Provider,
        processed: ProcessedMessage,
        apply: &mut impl FnMut(
            ComponentId,
            Option<&[u8]>,
            ComponentOp<'_>,
        ) -> Result<Option<Vec<u8>>, E>,
    ) -> Result<Incoming, MemberError> {
        // mls-extensions-10 §4.9: the whole authenticated_data is SafeAAD.
        // Checked before anything is stored or merged.
        // OpenMLS parses a SafeAAD prefix exactly when the group requires it.
        // Without Safe AAD, authenticated_data is accepted but not surfaced
        // (decision mimid-1wgh.4.32).
        if processed.safe_aad().is_some() && !processed.tail_aad().is_empty() {
            return Err(MemberError::TrailingAad);
        }

        let sender = convert_sender(processed.sender())?;
        let safe_aad: Vec<(ComponentId, Vec<u8>)> = processed
            .safe_aad()
            .map(|aad| {
                aad.items()
                    .iter()
                    .map(|item| (item.component_id(), item.data().to_vec()))
                    .collect()
            })
            .unwrap_or_default();
        let sender_identity = basic_identity(processed.credential());
        let processed = self.resolve(provider, processed, apply)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                let Sender::Member(sender) = sender else {
                    return Err(MemberError::UnexpectedMessage);
                };
                Ok(Incoming::Application {
                    sender,
                    sender_identity,
                    data: message.into_bytes(),
                    safe_aad,
                })
            }
            ProcessedMessageContent::ProposalMessage(proposal)
            | ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.group
                    .store_pending_proposal(provider.storage(), *proposal)
                    .map_err(|e| MemberError::Merge(e.into()))?;
                Ok(Incoming::Proposal { sender })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                check_staged_leaves(&staged)?;
                let summary = summarize(sender, &staged, staged.self_removed());
                self.group
                    .merge_staged_commit(provider, *staged)
                    .map_err(|e| MemberError::Merge(e.into()))?;
                Ok(Incoming::Commit(summary))
            }
            ProcessedMessageContent::OwnPendingCommit => {
                let summary = self
                    .group
                    .pending_commit()
                    .map(|staged| summarize(sender, staged, staged.self_removed()))
                    .ok_or(MemberError::UnexpectedMessage)?;
                self.group
                    .merge_pending_commit(provider)
                    .map_err(|e| MemberError::Merge(e.into()))?;
                Ok(Incoming::Commit(summary))
            }
            ProcessedMessageContent::OwnPrivateMessage => Ok(Incoming::OwnMessage),
            _ => Err(MemberError::UnexpectedMessage),
        }
    }

    /// Encrypts `data` as an application message (a TLS-encoded `MLSMessage`
    /// carrying a PrivateMessage).
    ///
    /// When the group uses Safe AAD, `safe_aad` becomes the message's
    /// `authenticated_data`, as a SafeAAD struct (mls-extensions-10 §4.9);
    /// its items must be in strictly ascending component order. Otherwise
    /// `safe_aad` must be empty, and `authenticated_data` is empty.
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::SafeAadNotEnabled`] or
    /// [`MemberError::InvalidSafeAad`] for unusable `safe_aad`, and
    /// [`MemberError::Send`] if OpenMLS refuses, for example while a
    /// proposal or Commit is pending, and [`MemberError::OutOfSync`] if the
    /// member is out of sync.
    pub fn send(
        &mut self,
        identity: &Identity,
        data: &[u8],
        safe_aad: &[(ComponentId, Vec<u8>)],
    ) -> Result<Vec<u8>, MemberError> {
        self.check_identity(identity)?;
        self.check_in_sync()?;
        let safe_aad_required = self
            .group
            .public_group()
            .group_context()
            .safe_aad_required();
        if safe_aad_required {
            let items = safe_aad
                .iter()
                .map(|(component_id, data)| SafeAadItem::new(*component_id, data.clone()))
                .collect();
            self.group
                .set_safe_aad(items)
                .map_err(|e| MemberError::InvalidSafeAad(e.into()))?;
        } else if !safe_aad.is_empty() {
            return Err(MemberError::SafeAadNotEnabled);
        }
        // Raw authenticated data is never set: with Safe AAD the SafeAAD
        // struct is all of it (decision mimid-1wgh.4.17).
        let result = self
            .group
            .create_message(identity.provider(), identity.signer(), data);
        match result {
            Ok(message) => encode(&message),
            Err(e) => {
                // OpenMLS keeps staged items after a failure. Clear them so
                // they cannot leak into a later Commit.
                if safe_aad_required {
                    self.group
                        .set_safe_aad(Vec::new())
                        .map_err(|e| MemberError::InvalidSafeAad(e.into()))?;
                }
                Err(MemberError::Send(e.into()))
            }
        }
    }

    /// The data of a component in the GroupContext `app_data_dictionary`.
    pub fn component(&self, component_id: ComponentId) -> Option<&[u8]> {
        self.group
            .extensions()
            .app_data_dictionary()
            .and_then(|extension| extension.dictionary().get(&component_id))
    }

    /// The group ID.
    pub fn group_id(&self) -> &[u8] {
        self.group.group_id().as_slice()
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// This member's leaf index.
    pub fn own_leaf_index(&self) -> u32 {
        self.group.own_leaf_index().u32()
    }

    /// Whether this member is still in the group.
    pub fn is_active(&self) -> bool {
        self.group.is_active()
    }

    /// Why this member is out of sync, or `None` if it is not (see the
    /// module's `# Out of sync`). The other accessors describe the last
    /// epoch it applied.
    pub fn out_of_sync(&self) -> Option<&OutOfSync> {
        self.out_of_sync.as_ref()
    }

    /// Marks this member out of sync with `state`, which the caller saved
    /// from [`Member::out_of_sync`] for this group before a restart, after
    /// [`Member::load`] (decision mimid-1wgh.4.61). It replaces any mark
    /// already set.
    pub fn restore_out_of_sync(&mut self, state: OutOfSync) {
        self.out_of_sync = Some(state);
    }

    /// The current members as (leaf index, BasicCredential identity).
    pub fn members(&self) -> Vec<(u32, Vec<u8>)> {
        self.group
            .members()
            .map(|member| (member.index.u32(), basic_identity(&member.credential)))
            .collect()
    }

    /// The current epoch's `epoch_authenticator` (RFC 9420 §8.7).
    pub fn epoch_authenticator(&self) -> &[u8] {
        self.group.epoch_authenticator().as_slice()
    }

    /// `MLS-Exporter(label, context, length)` for the current epoch
    /// (RFC 9420 §8.5).
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::Export`] if the export fails, for example
    /// after this member was removed.
    pub fn export_secret(
        &self,
        identity: &Identity,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, MemberError> {
        self.check_identity(identity)?;
        self.group
            .export_secret(identity.provider().crypto(), label, context, length)
            .map_err(|e| MemberError::Export(e.into()))
    }

    /// The TLS-encoded ratchet tree (RFC 9420 §12.4.3.3), for joiners whose
    /// Welcome has no `ratchet_tree` extension.
    ///
    /// # Errors
    ///
    /// Returns [`MemberError::Encode`] if the tree cannot be encoded.
    pub fn ratchet_tree(&self) -> Result<Vec<u8>, MemberError> {
        self.group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|e| MemberError::Encode(e.into()))
    }

    /// Fails while this member is out of sync.
    fn check_in_sync(&self) -> Result<(), MemberError> {
        match self.out_of_sync {
            Some(_) => Err(MemberError::OutOfSync),
            None => Ok(()),
        }
    }

    /// Marks this member out of sync because of `error`, which refused a
    /// Commit for the current epoch, and returns `error`.
    fn mark_out_of_sync(&mut self, error: MemberError) -> MemberError {
        let mut reason = error.to_string();
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            reason.push_str(": ");
            reason.push_str(&cause.to_string());
            source = cause.source();
        }
        self.out_of_sync = Some(OutOfSync {
            epoch: self.epoch(),
            reason,
        });
        error
    }

    /// Fails unless `identity` owns this member.
    fn check_identity(&self, identity: &Identity) -> Result<(), MemberError> {
        if self.owner_signature_key == identity.signature_public_key() {
            Ok(())
        } else {
            Err(MemberError::WrongIdentity)
        }
    }

    /// Stages a Commit that carries AppDataUpdate proposals, after `apply`
    /// has resolved them. Any other message is returned unchanged.
    fn resolve<E: Into<ErrorSource>>(
        &self,
        provider: &crate::store::Provider,
        processed: ProcessedMessage,
        apply: &mut impl FnMut(
            ComponentId,
            Option<&[u8]>,
            ComponentOp<'_>,
        ) -> Result<Option<Vec<u8>>, E>,
    ) -> Result<ProcessedMessage, MemberError> {
        let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) = processed.content()
        else {
            return Ok(processed);
        };
        let proposals: Vec<AppDataUpdateProposal> =
            unresolved.app_data_update_proposals().cloned().collect();
        let mut updater = self.group.app_data_dictionary_updater();
        resolve_app_data_updates(&mut updater, &proposals, apply)?;
        let changes = updater.changes();
        self.group
            .resolve_app_data_commit(provider, processed, changes)
            .map_err(|e| MemberError::Process(e.into()))
    }
}

/// The leaf index of `identity`'s existing leaf in the group that
/// `group_info` and `tree` describe: the leaf OpenMLS's external Commit
/// builder removes for a resync, the first with the same signature key.
///
/// ponytail: OpenMLS exposes neither the staged external Commit nor the
/// leaf positions of a `RatchetTreeIn`, so the GroupInfo and tree, already
/// verified by `build_group`, are loaded again into a throwaway in-memory
/// PublicGroup (never the identity's Store). Ceiling: every external join
/// verifies the tree twice. Upgrade: an OpenMLS accessor for the staged
/// external Commit (an openmls fork change, which needs Mark's approval).
fn resync_leaf(
    crypto: &impl openmls::prelude::OpenMlsCrypto,
    tree: RatchetTreeIn,
    group_info: VerifiableGroupInfo,
    identity: &Identity,
) -> Result<Option<u32>, MemberError> {
    let scratch = OpenMlsRustCrypto::default();
    // RFC 9420 §7.3; decision mimid-1wgh.4.56.
    let (group, _) = PublicGroup::from_external_with_lifetime_policy(
        crypto,
        scratch.storage(),
        tree,
        group_info,
        ProposalStore::new(),
        LeafNodeLifetimePolicy::Skip,
    )
    .map_err(|e| MemberError::Join(e.into()))?;
    let key = identity.signature_public_key();
    Ok(group
        .members()
        .find(|member| member.signature_key == key)
        .map(|member| member.index.u32()))
}

impl std::fmt::Debug for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The OpenMLS group holds epoch secrets, so it is not printed.
        f.debug_struct("Member")
            .field("group_id", &self.group_id())
            .field("epoch", &self.epoch())
            .field("own_leaf_index", &self.own_leaf_index())
            .field("out_of_sync", &self.out_of_sync.is_some())
            .finish_non_exhaustive()
    }
}

/// Describes a staged Commit, before it is merged. `self_removed` says
/// whether the Commit removes the caller's own leaf.
pub(crate) fn summarize(
    committer: Sender,
    staged: &StagedCommit,
    self_removed: bool,
) -> CommitSummary {
    let added = staged
        .add_proposals()
        .map(|add| basic_identity(add.add_proposal().key_package().leaf_node().credential()))
        .collect();
    let removed = staged
        .remove_proposals()
        .map(|remove| remove.remove_proposal().removed().u32())
        .collect();
    let mut components: Vec<ComponentId> = staged
        .app_data_update_proposals()
        .map(|queued| queued.app_data_update_proposal().component_id())
        .collect();
    components.sort_unstable();
    components.dedup();
    CommitSummary {
        committer,
        epoch: staged.epoch().as_u64(),
        added,
        removed,
        self_removed,
        components,
    }
}

/// Errors from the helpers that [`Member`] and
/// [`Observer`](crate::observer::Observer) share. Each converts into the
/// public error variant of the same name.
pub(crate) enum SharedError {
    Encode(ErrorSource),
    UnexpectedMessage,
    InvalidAppDataUpdate(ComponentId),
    AppDataRejected {
        component_id: ComponentId,
        source: ErrorSource,
    },
    InvalidComponentsList {
        component_id: ComponentId,
        source: ErrorSource,
    },
    MissingSafeAadComponent(ComponentId),
    MissingAppComponent(ComponentId),
}

impl From<SharedError> for MemberError {
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

/// Strictly decodes `data`, the GroupContext data of `component_id`, as a
/// canonical mls-extensions-10 §5 `ComponentsList`.
fn decode_components_list(
    component_id: ComponentId,
    data: &[u8],
) -> Result<Vec<ComponentId>, SharedError> {
    ComponentsList::tls_deserialize_exact(data)
        .map(ComponentsList::into_ids)
        .map_err(|e| SharedError::InvalidComponentsList {
            component_id,
            source: e.into(),
        })
}

/// Checks every leaf that `staged` adds or updates (Add, Update and the
/// UpdatePath leaf) against the `safe_aad` and `app_components` lists of
/// the GroupContext the Commit leads to (mls-extensions-10 §5).
///
/// INTERPRETATION, decision mimid-1wgh.4.45 (wg mimid-1wgh.37.39): §5 gives
/// no enforcement rule, so the rule mirrors RFC 9420 §11.1
/// `required_capabilities`. A leaf's list must name every non-GREASE id in
/// the GroupContext's list; an absent list is empty. GREASE ids are ignored
/// (§5.1). The GroupContext lists are decoded strictly and fail closed.
/// Post-Commit GroupContext, GREASE ignored, and fail-closed decoding:
/// decision mimid-1wgh.4.49.
pub(crate) fn check_staged_leaves(staged: &StagedCommit) -> Result<(), SharedError> {
    // The GroupContext after the Commit; decision mimid-1wgh.4.49.
    let required = required_lists(staged.group_context().extensions())?;
    for add in staged.add_proposals() {
        check_leaf(
            add.add_proposal().key_package().leaf_node().extensions(),
            &required,
        )?;
    }
    for update in staged.update_proposals() {
        check_leaf(update.update_proposal().leaf_node().extensions(), &required)?;
    }
    if let Some(leaf) = staged.update_path_leaf_node() {
        check_leaf(leaf.extensions(), &required)?;
    }
    Ok(())
}

/// The components that a GroupContext requires every leaf to support: the
/// strictly decoded `safe_aad` and `app_components` lists of its
/// `app_data_dictionary`, each empty when absent.
pub(crate) struct RequiredLists {
    safe_aad: Vec<ComponentId>,
    app_components: Vec<ComponentId>,
}

/// Decodes the [`RequiredLists`] of the GroupContext `extensions`; a
/// malformed list fails closed (decision mimid-1wgh.4.49).
pub(crate) fn required_lists(
    extensions: &Extensions<GroupContext>,
) -> Result<RequiredLists, SharedError> {
    let dictionary = extensions
        .app_data_dictionary()
        .map(AppDataDictionaryExtension::dictionary);
    let required = |component_id| match dictionary.and_then(|d| d.get(&component_id)) {
        Some(data) => decode_components_list(component_id, data),
        None => Ok(Vec::new()),
    };
    Ok(RequiredLists {
        safe_aad: required(SAFE_AAD)?,
        app_components: required(APP_COMPONENTS)?,
    })
}

/// The leaf indices, ascending, of the leaves in `group`'s tree, other than
/// `own`, that fail [`check_leaf`] against `required`. A group is joined or
/// observed with such leaves, and they are reported (decision
/// mimid-1wgh.4.57).
pub(crate) fn nonconforming_leaves(
    group: &PublicGroup,
    required: &RequiredLists,
    own: Option<LeafNodeIndex>,
) -> Vec<u32> {
    group
        .members()
        .map(|member| member.index)
        .filter(|index| Some(*index) != own)
        .filter(|index| {
            group
                .leaf(*index)
                .is_some_and(|leaf| check_leaf(leaf.extensions(), required).is_err())
        })
        .map(|index| index.u32())
        .collect()
}

/// Checks the extensions of one leaf against `required`.
fn check_leaf(
    extensions: &Extensions<LeafNode>,
    required: &RequiredLists,
) -> Result<(), SharedError> {
    if let Some(id) = first_unsupported(extensions, SAFE_AAD, &required.safe_aad) {
        return Err(SharedError::MissingSafeAadComponent(id));
    }
    if let Some(id) = first_unsupported(extensions, APP_COMPONENTS, &required.app_components) {
        return Err(SharedError::MissingAppComponent(id));
    }
    Ok(())
}

/// The first non-GREASE id in `required` that the `component_id` list of a
/// leaf's `app_data_dictionary` (in `extensions`) does not name. A leaf's
/// list is untrusted input: an absent or malformed one counts as empty, and
/// GREASE ids in `required` are skipped (decision mimid-1wgh.4.49).
fn first_unsupported(
    extensions: &Extensions<LeafNode>,
    component_id: ComponentId,
    required: &[ComponentId],
) -> Option<ComponentId> {
    let supported: BTreeSet<ComponentId> = extensions
        .app_data_dictionary()
        .and_then(|extension| extension.dictionary().get(&component_id))
        .and_then(|data| ComponentsList::tls_deserialize_exact(data).ok())
        .map(|list| list.into_ids().into_iter().collect())
        .unwrap_or_default();
    required
        .iter()
        .copied()
        .find(|id| !COMPONENT_GREASE.contains(id) && !supported.contains(id))
}

/// Applies mls-extensions-10 §4.7 to `proposals` (sorted by component id,
/// in Commit order within a component) and records the resulting
/// dictionary changes in `updater`.
///
/// OpenMLS checks only part of §4.7, so every rule is checked here: a
/// component gets either a single remove, of data that exists, or one or
/// more updates, which `apply` turns into new data.
pub(crate) fn resolve_app_data_updates<E: Into<ErrorSource>>(
    updater: &mut AppDataDictionaryUpdater<'_>,
    proposals: &[AppDataUpdateProposal],
    apply: &mut impl FnMut(ComponentId, Option<&[u8]>, ComponentOp<'_>) -> Result<Option<Vec<u8>>, E>,
) -> Result<(), SharedError> {
    for group in proposals.chunk_by(|a, b| a.component_id() == b.component_id()) {
        let Some(first) = group.first() else {
            continue;
        };
        let component_id = first.component_id();
        let rejected = |e: E| SharedError::AppDataRejected {
            component_id,
            source: e.into(),
        };
        let updates: Vec<&[u8]> = group
            .iter()
            .filter_map(|proposal| match proposal.operation() {
                AppDataUpdateOperation::Update(update) => Some(update.as_slice()),
                AppDataUpdateOperation::Remove => None,
            })
            .collect();
        let current = updater.old_value(component_id).map(<[u8]>::to_vec);

        if updates.len() == group.len() {
            match apply(
                component_id,
                current.as_deref(),
                ComponentOp::Update(&updates),
            ) {
                Ok(Some(new_data)) => {
                    updater.set(ComponentData::from_parts(component_id, new_data.into()));
                }
                Ok(None) => return Err(SharedError::InvalidAppDataUpdate(component_id)),
                Err(e) => return Err(rejected(e)),
            }
        } else if group.len() == 1 && current.is_some() {
            match apply(component_id, current.as_deref(), ComponentOp::Remove) {
                Ok(None) => updater.remove(&component_id),
                Ok(Some(_)) => return Err(SharedError::InvalidAppDataUpdate(component_id)),
                Err(e) => return Err(rejected(e)),
            }
        } else {
            // A remove mixed with other proposals, or a remove of a
            // component that has no data.
            return Err(SharedError::InvalidAppDataUpdate(component_id));
        }
    }
    Ok(())
}

pub(crate) fn convert_sender(sender: &openmls::prelude::Sender) -> Result<Sender, SharedError> {
    Ok(match sender {
        openmls::prelude::Sender::Member(index) => Sender::Member(index.u32()),
        openmls::prelude::Sender::External(index) => {
            // OpenMLS keeps the u32 sender_index private; its TLS encoding
            // is the four big-endian bytes (RFC 9420 §6).
            let bytes: [u8; 4] = index
                .tls_serialize_detached()
                .map_err(|e| SharedError::Encode(e.into()))?
                .try_into()
                .map_err(|_| SharedError::UnexpectedMessage)?;
            Sender::External(u32::from_be_bytes(bytes))
        }
        openmls::prelude::Sender::NewMemberProposal => Sender::NewMemberProposal,
        openmls::prelude::Sender::NewMemberCommit => Sender::NewMemberCommit,
    })
}

/// The BasicCredential identity, or empty for any other credential type.
/// Only BasicCredential is negotiated (decision mimid-1wgh.16), so OpenMLS
/// rejects other types before this is reached.
pub(crate) fn basic_identity(credential: &Credential) -> Vec<u8> {
    BasicCredential::try_from(credential.clone())
        .map(|basic| basic.identity().to_vec())
        .unwrap_or_default()
}

fn encode(message: &impl Serialize) -> Result<Vec<u8>, MemberError> {
    message
        .tls_serialize_detached()
        .map_err(|e| MemberError::Encode(e.into()))
}
