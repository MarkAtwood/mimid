//! Room policy: the hub's single authorization point (AGENTS.md: the hub
//! boundary checks room policy, in exactly one place).
//!
//! Everything here is pure and synchronous. It judges plain descriptions
//! of a room and of what a client asks for, never MLS objects: the update
//! pipeline first lets MLS validity alone decide whether a Commit is
//! valid, then summarizes it as a [`Commit`] and asks [`authorize_commit`]
//! (protocol-06 §5.3; decision mimid-1wgh.6.5). A user is the identity of
//! an MLS BasicCredential, which is the user URI shared by all of that
//! user's clients (decision mimid-1wgh.6.1).
//!
//! The checks are:
//!
//! - [`authorize_commit`]: each proposal sent inline by the committer is
//!   mapped to room-policy-04 §8.1 membership actions or §8.6 capabilities
//!   and authorized for the committer (the joiner, for an external Commit).
//!   A proposal included by reference was authorized when it arrived by
//!   [`authorize_proposal`] and is not authorized again; the commit-level
//!   rules below apply to it all the same.
//! - [`authorize_proposal`]: the same mapping for a proposal sent on its own,
//!   with its sender as the actor.
//! - [`authorize_send`]: a listed participant whose role holds
//!   `canSendMessage` (room-policy-04 §8.3).
//! - [`authorize_key_material`]: a listed participant whose role holds
//!   `canAddParticipant` (decision mimid-1wgh.6.20).
//! - [`authorize_group_info`]: a listed participant holding
//!   `canAddOwnClient`, or a user that may join by `canOpenJoin` or by
//!   preauthorization (room-policy-04 §8.1.1).
//!
//! The commit-level rules are:
//!
//! - GroupContextExtensions and PreSharedKey proposals are refused
//!   (decision mimid-1wgh.6.2), as is any proposal type the hub does not
//!   know.
//! - A change of credential identity, by Update proposal or UpdatePath, is
//!   refused: it would let a client become another user.
//! - A client of a user that is removed or banned may not commit, and may
//!   propose only Remove or SelfRemove proposals for its own user's
//!   clients (protocol-06 §5.3).
//! - Every client of a user removed or banned in the commit is removed in
//!   it (room-policy-04 §8.1.2, §8.1.3), and no client of a banned user
//!   remains.
//! - An added client belongs to a user that the same proposer adds to the
//!   participant list in the commit, or to the proposer itself
//!   (`canAddOwnClient`); no one adds clients for another existing
//!   participant (room-policy-04 §8.1.1; decision mimid-1wgh.6.21).
//! - A removed client not covered by its user's removal or ban is a kick
//!   (`canKick`) or the removal of the proposer's own client
//!   (`canRemoveOwnClient`). This is checked for proposals by reference
//!   too: the proposal arm cannot know which action a Remove belongs to.
//! - A `roles_list` update may not share a commit with any participant
//!   list change, and a `preauth_list` update with any but removals
//!   (room-policy-04 §3, §4).
//! - `roles_list` needs `canChangeRoleDefinitions`, `preauth_list`
//!   `canChangePreauthorizedUserList`, `base_room_policy`
//!   `canChangeRoomMembershipStyle`, and ReInit `canSendMLSReinitProposal`
//!   (room-policy-04 §8.6; decision mimid-1wgh.6.2).
//! - After the commit, the role list passes its structural checks, the §5
//!   `max_clients`, `max_users` and `multi_device` limits hold, and every
//!   role's §3 participant constraints hold, checked once on the state
//!   after the whole commit (decision mimid-1wgh.3.24).
//!
//! Its limitations are listed in the crate documentation.

use std::collections::{BTreeMap, HashMap, HashSet};

use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{ParticipantListData, ParticipantListUpdate};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ComponentID, PREAUTH_LIST, ROLES_LIST};
use mimi_room_policy::{
    BANNED_ROLE_INDEX, BaseRoomPolicy, Capability, Denied as RoomDenied, MembershipAction,
    NO_ROLE_INDEX, Occupancy, PolicyError, PreAuthData, RoleData,
};

use super::components::{
    self, ComponentError, ParticipantChange, ParticipantListCommit, decode, is_hub_tracked,
};

/// The policy-relevant state of a room before a commit or proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomState {
    /// The `roles_list` component (room-policy-04 §3).
    pub roles: RoleData,
    /// The `preauth_list` component, empty if absent (room-policy-04 §4).
    pub preauth: PreAuthData,
    /// The `base_room_policy` component (room-policy-04 §5).
    pub base: BaseRoomPolicy,
    /// The `participant_list` component (protocol-06 §7.5).
    pub participants: ParticipantListData,
    /// The MLS group's members: leaf index to credential identity, the
    /// user URI (decision mimid-1wgh.6.1).
    pub members: BTreeMap<u32, Vec<u8>>,
}

/// The sender of a proposal that is not inline in the Commit (RFC 9420
/// §6 `Sender`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalSender {
    /// A member, by leaf index.
    Member {
        /// The sender's leaf index.
        leaf_index: u32,
    },
    /// A new member proposing to add itself; `user` is the identity in the
    /// added KeyPackage's credential.
    NewMember {
        /// The proposer's user.
        user: Vec<u8>,
    },
    /// An external sender listed in the `external_senders` extension.
    External {
        /// The index into `external_senders`.
        sender_index: u32,
    },
}

/// Where a Commit's proposal comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Sent by value in the Commit: its sender is the committer.
    Inline,
    /// Included by reference: a proposal received earlier, from `sender`.
    ByReference(ProposalSender),
}

/// The operation of an AppDataUpdate proposal (mls-extensions-10 §4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppDataOp {
    /// `update`, with the `update` field's bytes.
    Update(Vec<u8>),
    /// `remove`.
    Remove,
}

/// What a proposal does, as far as room policy cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalKind {
    /// Add a client; `user` is the identity in its credential.
    Add {
        /// The added client's user.
        user: Vec<u8>,
    },
    /// Remove the client at `leaf_index`.
    Remove {
        /// The removed client's leaf index.
        leaf_index: u32,
    },
    /// Update the sender's own leaf.
    Update {
        /// Whether the new leaf's credential identity differs from the old.
        identity_changed: bool,
    },
    /// A PreSharedKey proposal.
    PreSharedKey,
    /// A ReInit proposal.
    ReInit,
    /// An ExternalInit proposal.
    ExternalInit,
    /// A GroupContextExtensions proposal.
    GroupContextExtensions,
    /// An AppDataUpdate proposal (mls-extensions-10 §4.7).
    AppDataUpdate {
        /// The component.
        component_id: ComponentID,
        /// The operation.
        op: AppDataOp,
    },
    /// A SelfRemove proposal (mls-extensions-10): the sender removes its
    /// own client.
    SelfRemove,
    /// Any other proposal type.
    Other {
        /// The `ProposalType` value.
        proposal_type: u16,
    },
}

/// One proposal a Commit covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// What it does.
    pub kind: ProposalKind,
    /// Who sent it.
    pub origin: Origin,
}

/// The sender of a Commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Committer {
    /// A member, by leaf index.
    Member {
        /// The committer's leaf index.
        leaf_index: u32,
    },
    /// The joiner of an external Commit; `user` is the identity in its new
    /// leaf's credential.
    External {
        /// The joiner's user.
        user: Vec<u8>,
    },
}

/// A staged Commit, summarized for room policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// Who sent it.
    pub committer: Committer,
    /// Whether its UpdatePath gives the committer's leaf a different
    /// credential identity.
    pub path_identity_changed: bool,
    /// Its proposals, in the order they are applied.
    pub proposals: Vec<Proposal>,
}

/// What an authorized Commit changes in the hub-tracked components.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyOutcome {
    /// The new data of every hub-tracked component the Commit updates.
    pub new_data: BTreeMap<ComponentID, Vec<u8>>,
}

/// Why room policy refuses a Commit, proposal, message or GroupInfo
/// request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Denied {
    /// A §8.1 membership action is not authorized (room-policy-04 §8.1).
    #[error("membership action {action:?} is not authorized")]
    Membership {
        /// The action.
        action: MembershipAction,
        /// Why it is denied.
        #[source]
        reason: RoomDenied,
    },
    /// The actor's role does not hold a capability the request needs
    /// (room-policy-04 §8.3, §8.6).
    #[error("capability check failed")]
    Capability(#[source] RoomDenied),
    /// A §3 participant constraint fails after the commit (decision
    /// mimid-1wgh.3.24).
    #[error("participant constraint broken after the commit")]
    Constraint(#[source] RoomDenied),
    /// The role list after the commit breaks a room-policy-04 structural
    /// rule.
    #[error("roles_list is invalid after the commit")]
    InvalidRoles(#[source] PolicyError),
    /// A component update is malformed.
    #[error("component update is invalid")]
    Component(#[from] ComponentError),
    /// A leaf index names no member of the group.
    #[error("leaf {0} is not a member of the group")]
    UnknownMember(u32),
    /// A SelfRemove proposal does not come from a member.
    #[error("SelfRemove needs a member sender")]
    NotAMember,
    /// Proposals from MLS external senders are not accepted.
    #[error("proposals from external senders are not accepted")]
    ExternalSender,
    /// A credential identity change (decision mimid-1wgh.6.1).
    #[error("a credential identity change is refused")]
    IdentityChange,
    /// GroupContextExtensions proposals are refused (decision
    /// mimid-1wgh.6.2).
    #[error("GroupContextExtensions proposals are refused")]
    GroupContextExtensions,
    /// PreSharedKey proposals are refused (decision mimid-1wgh.6.2).
    #[error("PreSharedKey proposals are refused")]
    PreSharedKey,
    /// A proposal type the hub does not know.
    #[error("proposal type {0:#06x} is not supported")]
    UnsupportedProposal(u16),
    /// An AppDataUpdate `remove` of a hub-tracked component.
    #[error("component {0:#06x} cannot be removed")]
    ComponentRemoval(ComponentID),
    /// An AppDataUpdate of `franking_agent`, which stays the hub's key
    /// (decision mimid-1wgh.6.3).
    #[error("component {0:#06x} is set by the hub")]
    HubComponent(ComponentID),
    /// The user is removed or banned: it may not commit, send messages or
    /// propose anything but removing its own clients (protocol-06 §5.3).
    #[error("the user is removed or banned")]
    RemovedOrBanned,
    /// A `roles_list` or `preauth_list` update shares the commit with a
    /// participant list change (room-policy-04 §3, §4).
    #[error("component {0:#06x} cannot change in the same commit as the participant list")]
    PolicyMixedWithParticipantChange(ComponentID),
    /// A user removed or banned in the commit, or a banned user, keeps a
    /// client (room-policy-04 §8.1.2, §8.1.3).
    #[error("a removed or banned user keeps a client in the group")]
    RemovedUserKeepsClients,
    /// An added client is neither the proposer's own nor of a user the
    /// proposer adds in the same commit (room-policy-04 §8.1.1; decision
    /// mimid-1wgh.6.21).
    #[error("the added client is not authorized")]
    ClientNotAuthorized,
    /// The group would have more clients than `max_clients`
    /// (room-policy-04 §5).
    #[error("{actual} clients exceed max_clients {maximum}")]
    TooManyClients {
        /// `max_clients`.
        maximum: u32,
        /// The count after the commit.
        actual: u32,
    },
    /// The participant list would have more non-banned entries than
    /// `max_users` (room-policy-04 §5).
    #[error("{actual} non-banned participants exceed max_users {maximum}")]
    TooManyUsers {
        /// `max_users`.
        maximum: u32,
        /// The count after the commit.
        actual: u32,
    },
    /// A user would have more than one client in a room whose
    /// `multi_device` is false (room-policy-04 §5).
    #[error("multi_device is false and a user has more than one client")]
    MultiDevice,
    /// The user is not in the participant list.
    #[error("the user is not a participant")]
    NotParticipant,
    /// Join codes are not supported (decision mimid-1wgh.6.13).
    #[error("join codes are not supported")]
    JoinCode,
}

impl RoomState {
    /// The user's role in the participant list, or 0 if it is not listed
    /// (room-policy-04 §3).
    fn role_of(&self, user: &[u8]) -> u32 {
        role_in(&self.participants, user)
    }

    /// The user of the member at `leaf_index`.
    fn user_of(&self, leaf_index: u32) -> Result<&[u8], Denied> {
        self.members
            .get(&leaf_index)
            .map(Vec::as_slice)
            .ok_or(Denied::UnknownMember(leaf_index))
    }

    /// Whether role 1 is the "banned" role and `role_index` is it
    /// (room-policy-04 §8.1.3; decision mimid-1wgh.3.42).
    fn is_banned(&self, role_index: u32) -> bool {
        is_banned_in(&self.roles, role_index)
    }

    /// Whether a user with `role_index` is removed or banned in the sense
    /// of protocol-06 §5.3. A member whose user is not listed has been
    /// removed; a new member that is not listed is simply new.
    fn is_removed_or_banned(&self, role_index: u32, is_member: bool) -> bool {
        self.is_banned(role_index) || (is_member && role_index == NO_ROLE_INDEX)
    }

    /// The preauthorized role for a BasicCredential, which has no claims
    /// (room-policy-04 §4; decision mimid-1wgh.3.47).
    fn preauthorized_role(&self) -> Option<u32> {
        self.preauth.first_match(&[])
    }

    /// Authorizes `action` for an actor with `actor_role`.
    fn authorize(&self, actor_role: u32, action: MembershipAction) -> Result<(), Denied> {
        self.roles
            .authorize(actor_role, action)
            .map_err(|reason| Denied::Membership { action, reason })
    }

    /// Checks that `actor_role` holds `capability`.
    fn capability(&self, actor_role: u32, capability: Capability) -> Result<(), Denied> {
        self.roles
            .authorize_capability(actor_role, capability)
            .map_err(Denied::Capability)
    }

    /// Resolves a non-inline proposal sender to its user and whether it is
    /// a member.
    fn sender(&self, sender: &ProposalSender) -> Result<(Vec<u8>, bool), Denied> {
        match sender {
            ProposalSender::Member { leaf_index } => {
                Ok((self.user_of(*leaf_index)?.to_vec(), true))
            }
            ProposalSender::NewMember { user } => Ok((user.clone(), false)),
            // RFC 9420 §12.1.8; decision mimid-1wgh.6.46
            ProposalSender::External { .. } => Err(Denied::ExternalSender),
        }
    }

    /// Authorizes one participant-list change made by `actor`
    /// (room-policy-04 §8.1). A change to the actor itself is a join,
    /// leave or own role change; any other is an add, removal or role
    /// change of another user. Bans and unbans are role changes to and
    /// from role 1 (decision mimid-1wgh.3.26).
    fn authorize_change(
        &self,
        actor: &[u8],
        actor_role: u32,
        change: &ParticipantChange,
    ) -> Result<(), Denied> {
        let (from, target) = (change.from_role_index, change.target_role_index);
        if change.user != actor {
            let action = match (from, target) {
                (NO_ROLE_INDEX, _) => MembershipAction::AddParticipant {
                    target_role_index: target,
                },
                (_, NO_ROLE_INDEX) => MembershipAction::RemoveParticipant {
                    from_role_index: from,
                },
                _ => MembershipAction::ChangeUserRole {
                    from_role_index: from,
                    target_role_index: target,
                },
            };
            return self.authorize(actor_role, action);
        }
        match (from, target) {
            (NO_ROLE_INDEX, _) => self.authorize_join(actor_role, target),
            (_, NO_ROLE_INDEX) => self.authorize(actor_role, MembershipAction::RemoveSelf),
            _ => self.authorize(
                actor_role,
                MembershipAction::ChangeOwnRole {
                    target_role_index: target,
                    preauthorized_role_index: self.preauthorized_role(),
                },
            ),
        }
    }

    /// Authorizes a user adding itself with `target` by `canOpenJoin` or by
    /// preauthorization (room-policy-04 §8.1.1); join codes are not
    /// supported (decision mimid-1wgh.6.13). If both fail, the
    /// preauthorization denial is reported when an entry matched, else
    /// the open-join one.
    fn authorize_join(&self, actor_role: u32, target: u32) -> Result<(), Denied> {
        let open = self.authorize(
            actor_role,
            MembershipAction::OpenJoin {
                target_role_index: target,
            },
        );
        let Err(open_denied) = open else {
            return Ok(());
        };
        let preauthorized = self.preauthorized_role();
        let preauth = self.authorize(
            actor_role,
            MembershipAction::JoinIfPreauthorized {
                target_role_index: target,
                preauthorized_role_index: preauthorized,
            },
        );
        // room-policy-04 §4, §8.1.1; decision mimid-1wgh.6.47
        match (preauth, preauthorized) {
            (Ok(()), _) => Ok(()),
            (Err(denied), Some(_)) => Err(denied),
            (Err(_), None) => Err(open_denied),
        }
    }
}

fn role_in(list: &ParticipantListData, user: &[u8]) -> u32 {
    list.participants
        .iter()
        .find(|entry| entry.user == user)
        .map_or(NO_ROLE_INDEX, |entry| entry.role_index)
}

fn is_banned_in(roles: &RoleData, role_index: u32) -> bool {
    role_index == BANNED_ROLE_INDEX
        && roles
            .role(BANNED_ROLE_INDEX)
            .is_some_and(|role| role.is_banned_role())
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Refuses the proposals the hub never accepts, wherever they appear.
fn refuse_kind(kind: &ProposalKind) -> Result<(), Denied> {
    match kind {
        ProposalKind::GroupContextExtensions => Err(Denied::GroupContextExtensions),
        ProposalKind::PreSharedKey => Err(Denied::PreSharedKey),
        ProposalKind::Other { proposal_type } => Err(Denied::UnsupportedProposal(*proposal_type)),
        ProposalKind::Update {
            identity_changed: true,
        } => Err(Denied::IdentityChange),
        // protocol-06 §5.4.1, mls-extensions-10 §4.7; decision mimid-1wgh.6.42
        ProposalKind::AppDataUpdate { component_id, .. } if *component_id == FRANKING_AGENT => {
            Err(Denied::HubComponent(FRANKING_AGENT))
        }
        ProposalKind::AppDataUpdate {
            component_id,
            op: AppDataOp::Remove,
        } if is_hub_tracked(*component_id) => Err(Denied::ComponentRemoval(*component_id)),
        _ => Ok(()),
    }
}

/// The §8.6 capability an update to a hub-tracked policy component needs
/// (decision mimid-1wgh.6.2).
fn policy_capability(component_id: ComponentID) -> Option<Capability> {
    match component_id {
        ROLES_LIST => Some(Capability::CAN_CHANGE_ROLE_DEFINITIONS),
        PREAUTH_LIST => Some(Capability::CAN_CHANGE_PREAUTHORIZED_USER_LIST),
        // room-policy-04 §8.6; decision mimid-1wgh.6.43
        BASE_ROOM_POLICY => Some(Capability::CAN_CHANGE_ROOM_MEMBERSHIP_STYLE),
        _ => None,
    }
}

/// Checks that a policy component update decodes as its type.
fn decode_policy(component_id: ComponentID, bytes: &[u8]) -> Result<(), Denied> {
    match component_id {
        ROLES_LIST => decode::<RoleData>(component_id, bytes).map(drop),
        PREAUTH_LIST => decode::<PreAuthData>(component_id, bytes).map(drop),
        _ => decode::<BaseRoomPolicy>(component_id, bytes).map(drop),
    }
    .map_err(Denied::from)
}

/// Authorizes a proposal sent on its own, with `sender` as the actor.
///
/// The commit-level rules that need the whole Commit (clients of removed
/// users, the users of added clients, mixing policy and participant
/// changes, constraints) are checked by [`authorize_commit`] when the
/// proposal is committed. A Remove or SelfRemove may be part of a kick,
/// the removal of a user, a ban, or leaving, so it is authorized here if
/// any of these is; [`authorize_commit`] then decides which it is.
///
/// # Errors
///
/// The first check that fails.
pub fn authorize_proposal(
    state: &RoomState,
    kind: &ProposalKind,
    sender: &ProposalSender,
) -> Result<(), Denied> {
    refuse_kind(kind)?;
    let (actor, is_member) = state.sender(sender)?;
    let role = state.role_of(&actor);
    if state.is_removed_or_banned(role, is_member) {
        // protocol-06 §5.3: "MUST prevent it from sending any proposals
        // except for Remove and SelfRemove ... for its users"; decision
        // mimid-1wgh.6.39
        return match kind {
            ProposalKind::Remove { leaf_index } if state.user_of(*leaf_index)? == actor => Ok(()),
            ProposalKind::SelfRemove if is_member => Ok(()),
            _ => Err(Denied::RemovedOrBanned),
        };
    }
    match kind {
        // A new member adds only its own client, and only while listed;
        // room-policy-04 §4, §8.1.1; decision mimid-1wgh.6.46
        ProposalKind::Add { user } if *user == actor => {
            state.authorize(role, MembershipAction::AddOwnClient)
        }
        // Clients of another user come with that user's list addition, in
        // the same commit (room-policy-04 §8.1.1); an existing participant
        // cannot have clients added by another (decision mimid-1wgh.6.21).
        ProposalKind::Add { user } if state.role_of(user) != NO_ROLE_INDEX => {
            Err(Denied::ClientNotAuthorized)
        }
        ProposalKind::Add { .. } => Ok(()),
        ProposalKind::Remove { leaf_index } => {
            let target = state.user_of(*leaf_index)?;
            authorize_removal_proposal(state, role, &actor, target)
        }
        ProposalKind::SelfRemove if is_member => {
            authorize_removal_proposal(state, role, &actor, &actor)
        }
        ProposalKind::SelfRemove => Err(Denied::NotAMember),
        ProposalKind::ReInit => state.capability(role, Capability::CAN_SEND_MLS_REINIT_PROPOSAL),
        ProposalKind::AppDataUpdate {
            component_id: PARTICIPANT_LIST,
            op: AppDataOp::Update(bytes),
        } => {
            let update = decode::<ParticipantListUpdate>(PARTICIPANT_LIST, bytes)?;
            let mut list = ParticipantListCommit::new(state.participants.clone());
            for change in list.apply(&update)? {
                state.authorize_change(&actor, role, &change)?;
            }
            Ok(())
        }
        ProposalKind::AppDataUpdate {
            component_id,
            op: AppDataOp::Update(bytes),
        } => match policy_capability(*component_id) {
            Some(capability) => {
                state.capability(role, capability)?;
                decode_policy(*component_id, bytes)
            }
            None => Ok(()),
        },
        // Refused above, or need no capability.
        ProposalKind::AppDataUpdate { .. }
        | ProposalKind::Update { .. }
        | ProposalKind::ExternalInit
        | ProposalKind::PreSharedKey
        | ProposalKind::GroupContextExtensions
        | ProposalKind::Other { .. } => Ok(()),
    }
}

/// A Remove or SelfRemove proposal of a client of `target` by `actor`:
/// authorized if any action it may belong to is (room-policy-04 §8.1.2,
/// §8.1.3). The denial reported is that of the kick, or of removing an
/// own client (room-policy-04 §8.1.2; decision mimid-1wgh.6.44).
fn authorize_removal_proposal(
    state: &RoomState,
    role: u32,
    actor: &[u8],
    target: &[u8],
) -> Result<(), Denied> {
    let (first, alternatives) = if target == actor {
        (
            MembershipAction::RemoveOwnClient,
            vec![MembershipAction::RemoveSelf],
        )
    } else {
        let from_role_index = state.role_of(target);
        (
            MembershipAction::Kick,
            vec![
                MembershipAction::RemoveParticipant { from_role_index },
                MembershipAction::ChangeUserRole {
                    from_role_index,
                    target_role_index: BANNED_ROLE_INDEX,
                },
            ],
        )
    };
    let denied = match state.authorize(role, first) {
        Ok(()) => return Ok(()),
        Err(denied) => denied,
    };
    if alternatives
        .into_iter()
        .any(|action| state.authorize(role, action).is_ok())
    {
        Ok(())
    } else {
        Err(denied)
    }
}

/// A client removal in a Commit, for the commit-level rules.
struct ClientRemoval {
    proposer: Vec<u8>,
    proposer_role: u32,
    proposer_removed_or_banned: bool,
    by_reference: bool,
    target: Vec<u8>,
    leaf_index: u32,
}

/// A client addition in a Commit, for the commit-level rules.
struct ClientAddition {
    proposer: Vec<u8>,
    proposer_role: u32,
    by_reference: bool,
    user: Vec<u8>,
}

/// The participant counts after a Commit, as
/// [`RoleData::check_constraints`] reads them.
struct After<'a> {
    list: &'a ParticipantListData,
    clients: &'a HashMap<Vec<u8>, u32>,
}

impl After<'_> {
    fn has_clients(&self, user: &[u8]) -> bool {
        self.clients.get(user).is_some_and(|&n| n > 0)
    }
}

impl Occupancy for After<'_> {
    fn participants(&self, role_index: u32) -> u32 {
        count(
            self.list
                .participants
                .iter()
                .filter(|entry| entry.role_index == role_index)
                .count(),
        )
    }

    fn active_participants(&self, role_index: u32) -> u32 {
        if role_index == NO_ROLE_INDEX {
            // Users with clients but no entry (decision mimid-1wgh.3.54).
            return count(
                self.clients
                    .iter()
                    .filter(|&(user, &n)| n > 0 && role_in(self.list, user) == NO_ROLE_INDEX)
                    .count(),
            );
        }
        count(
            self.list
                .participants
                .iter()
                .filter(|entry| entry.role_index == role_index && self.has_clients(&entry.user))
                .count(),
        )
    }
}

/// Authorizes a staged Commit that MLS has already found valid
/// (protocol-06 §5.3; decision mimid-1wgh.6.5).
///
/// See the module documentation for the rules. The proposals are taken in
/// `commit.proposals` order, which must be the order MLS applies them;
/// participant list updates are applied in that order (mls-extensions-10
/// §4.7; decision mimid-1wgh.5.70).
///
/// # Errors
///
/// The first check that fails.
pub fn authorize_commit(state: &RoomState, commit: &Commit) -> Result<PolicyOutcome, Denied> {
    if commit.path_identity_changed {
        return Err(Denied::IdentityChange);
    }
    let (committer, committer_leaf, external) = match &commit.committer {
        Committer::Member { leaf_index } => (
            state.user_of(*leaf_index)?.to_vec(),
            Some(*leaf_index),
            false,
        ),
        Committer::External { user } => (user.clone(), None, true),
    };
    let committer_role = state.role_of(&committer);
    // protocol-06 §5.3: "MUST prevent any of those clients from sending
    // Commit messages"; decision mimid-1wgh.6.38
    if state.is_removed_or_banned(committer_role, !external) {
        return Err(Denied::RemovedOrBanned);
    }

    let mut list = ParticipantListCommit::new(state.participants.clone());
    let mut list_updated = false;
    let mut changes: Vec<ParticipantChange> = Vec::new();
    // The proposer of each user's list addition (§8.1.1: the holder may
    // add that user's clients).
    let mut added_by: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut replaced: BTreeMap<ComponentID, Vec<u8>> = BTreeMap::new();
    let mut removals = Vec::new();
    let mut additions = Vec::new();
    if external {
        // The joiner's own new client.
        additions.push(ClientAddition {
            proposer: committer.clone(),
            proposer_role: committer_role,
            by_reference: false,
            user: committer.clone(),
        });
    }

    for proposal in &commit.proposals {
        refuse_kind(&proposal.kind)?;
        let (proposer, proposer_leaf, is_member, by_reference) = match &proposal.origin {
            Origin::Inline => (committer.clone(), committer_leaf, !external, false),
            Origin::ByReference(sender) => {
                let (user, is_member) = state.sender(sender)?;
                let leaf = match sender {
                    ProposalSender::Member { leaf_index } => Some(*leaf_index),
                    _ => None,
                };
                (user, leaf, is_member, true)
            }
        };
        let proposer_role = state.role_of(&proposer);
        let proposer_removed_or_banned = state.is_removed_or_banned(proposer_role, is_member);
        let removal = |target: Vec<u8>, leaf_index: u32| ClientRemoval {
            proposer: proposer.clone(),
            proposer_role,
            proposer_removed_or_banned,
            by_reference,
            target,
            leaf_index,
        };
        match &proposal.kind {
            ProposalKind::Add { user } => additions.push(ClientAddition {
                proposer: proposer.clone(),
                proposer_role,
                by_reference,
                user: user.clone(),
            }),
            ProposalKind::Remove { leaf_index } => {
                let target = state.user_of(*leaf_index)?.to_vec();
                removals.push(removal(target, *leaf_index));
            }
            ProposalKind::SelfRemove => {
                let leaf_index = proposer_leaf.ok_or(Denied::NotAMember)?;
                removals.push(removal(proposer.clone(), leaf_index));
            }
            ProposalKind::ReInit if !by_reference => {
                state.capability(proposer_role, Capability::CAN_SEND_MLS_REINIT_PROPOSAL)?;
            }
            ProposalKind::AppDataUpdate {
                component_id: PARTICIPANT_LIST,
                op: AppDataOp::Update(bytes),
            } => {
                let update = decode::<ParticipantListUpdate>(PARTICIPANT_LIST, bytes)?;
                list_updated = true;
                for change in list.apply(&update)? {
                    if !by_reference {
                        state.authorize_change(&proposer, proposer_role, &change)?;
                    }
                    if change.from_role_index == NO_ROLE_INDEX {
                        added_by.insert(change.user.clone(), proposer.clone());
                    }
                    changes.push(change);
                }
            }
            ProposalKind::AppDataUpdate {
                component_id,
                op: AppDataOp::Update(bytes),
            } => {
                if let Some(capability) = policy_capability(*component_id) {
                    if !by_reference {
                        state.capability(proposer_role, capability)?;
                    }
                    decode_policy(*component_id, bytes)?;
                    replaced.insert(*component_id, bytes.clone());
                }
            }
            // Refused by refuse_kind, authorized when it arrived, or needs
            // no capability.
            ProposalKind::ReInit
            | ProposalKind::AppDataUpdate { .. }
            | ProposalKind::Update { .. }
            | ProposalKind::ExternalInit
            | ProposalKind::PreSharedKey
            | ProposalKind::GroupContextExtensions
            | ProposalKind::Other { .. } => {}
        }
    }

    // room-policy-04 §3: not valid "in the same commit as any Participant
    // List change"; §4: "... except for user removals"; decision
    // mimid-1wgh.6.40
    if replaced.contains_key(&ROLES_LIST) && !changes.is_empty() {
        return Err(Denied::PolicyMixedWithParticipantChange(ROLES_LIST));
    }
    if replaced.contains_key(&PREAUTH_LIST)
        && changes
            .iter()
            .any(|change| change.target_role_index != NO_ROLE_INDEX)
    {
        return Err(Denied::PolicyMixedWithParticipantChange(PREAUTH_LIST));
    }

    let roles = match replaced.get(&ROLES_LIST) {
        Some(bytes) => decode::<RoleData>(ROLES_LIST, bytes)?,
        None => state.roles.clone(),
    };
    let base = match replaced.get(&BASE_ROOM_POLICY) {
        Some(bytes) => decode::<BaseRoomPolicy>(BASE_ROOM_POLICY, bytes)?,
        None => state.base.clone(),
    };
    if replaced.contains_key(&ROLES_LIST) || replaced.contains_key(&BASE_ROOM_POLICY) {
        roles
            .validate(base.fixed_membership.into())
            .map_err(Denied::InvalidRoles)?;
    }
    let after_list = list.into_list();

    // Users removed, or banned, by this commit (§8.1.2, §8.1.3).
    let gone: HashSet<&[u8]> = changes
        .iter()
        .filter(|change| {
            change.target_role_index == NO_ROLE_INDEX
                || is_banned_in(&roles, change.target_role_index)
        })
        .map(|change| change.user.as_slice())
        .collect();

    let mut removed_leaves = HashSet::new();
    for removal in &removals {
        removed_leaves.insert(removal.leaf_index);
        if gone.contains(removal.target.as_slice()) {
            continue;
        }
        if removal.target == removal.proposer {
            // protocol-06 §5.3 lets a removed or banned user's clients
            // propose their own removal; it was accepted when it arrived
            // (decision mimid-1wgh.6.39).
            if removal.by_reference && removal.proposer_removed_or_banned {
                continue;
            }
            state.authorize(removal.proposer_role, MembershipAction::RemoveOwnClient)?;
        } else {
            // room-policy-04 §8.1.2; decision mimid-1wgh.6.44
            state.authorize(removal.proposer_role, MembershipAction::Kick)?;
        }
    }

    let mut clients: HashMap<Vec<u8>, u32> = HashMap::new();
    for (leaf_index, user) in &state.members {
        if !removed_leaves.contains(leaf_index) {
            *clients.entry(user.clone()).or_default() += 1;
        }
    }
    for addition in &additions {
        // room-policy-04 §8.1.1 "the holder"; decision mimid-1wgh.6.45
        let added_by_proposer = added_by.get(&addition.user) == Some(&addition.proposer);
        if !added_by_proposer {
            if addition.user != addition.proposer {
                // room-policy-04 §8.1.1; decision mimid-1wgh.6.21
                return Err(Denied::ClientNotAuthorized);
            }
            if !addition.by_reference {
                state.authorize(addition.proposer_role, MembershipAction::AddOwnClient)?;
            }
        }
        *clients.entry(addition.user.clone()).or_default() += 1;
    }

    let after = After {
        list: &after_list,
        clients: &clients,
    };
    let keeps_clients = gone.iter().any(|user| after.has_clients(user))
        || after_list
            .participants
            .iter()
            .any(|entry| is_banned_in(&roles, entry.role_index) && after.has_clients(&entry.user));
    if keeps_clients {
        return Err(Denied::RemovedUserKeepsClients);
    }

    // room-policy-04 §5; decision mimid-1wgh.6.41
    let total_clients =
        u32::try_from(clients.values().map(|&n| u64::from(n)).sum::<u64>()).unwrap_or(u32::MAX);
    if let Some(maximum) = base.max_clients
        && total_clients > maximum
    {
        return Err(Denied::TooManyClients {
            maximum,
            actual: total_clients,
        });
    }
    let users = count(
        after_list
            .participants
            .iter()
            .filter(|entry| !is_banned_in(&roles, entry.role_index))
            .count(),
    );
    if let Some(maximum) = base.max_users
        && users > maximum
    {
        return Err(Denied::TooManyUsers {
            maximum,
            actual: users,
        });
    }
    if !bool::from(base.multi_device) && clients.values().any(|&n| n > 1) {
        return Err(Denied::MultiDevice);
    }

    roles
        .check_constraints(&after)
        .map_err(Denied::Constraint)?;

    let mut new_data = replaced;
    if list_updated {
        new_data.insert(
            PARTICIPANT_LIST,
            components::encode_participant_list(&after_list)?,
        );
    }
    Ok(PolicyOutcome { new_data })
}

/// Authorizes `sending_user` to submit an application message: a listed,
/// not banned participant whose role holds `canSendMessage`
/// (room-policy-04 §8.3; protocol-06 §5.3).
///
/// # Errors
///
/// [`Denied::NotParticipant`], [`Denied::RemovedOrBanned`] or
/// [`Denied::Capability`].
pub fn authorize_send(state: &RoomState, sending_user: &[u8]) -> Result<(), Denied> {
    let role = state.role_of(sending_user);
    if role == NO_ROLE_INDEX {
        return Err(Denied::NotParticipant);
    }
    if state.is_banned(role) {
        return Err(Denied::RemovedOrBanned);
    }
    state
        .roles
        .authorize_send_message(role)
        .map_err(Denied::Capability)
}

/// Authorizes `requester` to fetch key material through the hub for a
/// user to add to the room: a listed, not banned participant whose role
/// holds `canAddParticipant` (protocol-06 §3.3 leaves the check undefined;
/// decision mimid-1wgh.6.20).
///
/// # Errors
///
/// [`Denied::NotParticipant`], [`Denied::RemovedOrBanned`] or
/// [`Denied::Capability`].
pub fn authorize_key_material(state: &RoomState, requester: &[u8]) -> Result<(), Denied> {
    let role = state.role_of(requester);
    if role == NO_ROLE_INDEX {
        return Err(Denied::NotParticipant);
    }
    if state.is_banned(role) {
        return Err(Denied::RemovedOrBanned);
    }
    state.capability(role, Capability::CAN_ADD_PARTICIPANT)
}

/// Authorizes `requester` to fetch the GroupInfo for an external join: a
/// listed participant holding `canAddOwnClient`, or, for a user not
/// listed, role 0 holding `canOpenJoin` or a preauthorization entry whose
/// role holds `canJoinIfPreauthorized` (room-policy-04 §8.1.1).
///
/// A request carrying a joining code is refused (decision
/// mimid-1wgh.6.13).
///
/// # Errors
///
/// [`Denied::JoinCode`], or the denial of the check that applies.
pub fn authorize_group_info(
    state: &RoomState,
    requester: &[u8],
    joining_code: Option<&[u8]>,
) -> Result<(), Denied> {
    if joining_code.is_some() {
        return Err(Denied::JoinCode);
    }
    let role = state.role_of(requester);
    if role != NO_ROLE_INDEX {
        return state.authorize(role, MembershipAction::AddOwnClient);
    }
    let open_denied = match state.capability(NO_ROLE_INDEX, Capability::CAN_OPEN_JOIN) {
        Ok(()) => return Ok(()),
        Err(denied) => denied,
    };
    match state.preauthorized_role() {
        Some(preauthorized) => state.authorize(
            NO_ROLE_INDEX,
            MembershipAction::JoinIfPreauthorized {
                target_role_index: preauthorized,
                preauthorized_role_index: Some(preauthorized),
            },
        ),
        None => Err(open_denied),
    }
}
