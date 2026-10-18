//! Authorization of room-policy-04 §8.1 membership actions and of
//! `canSendMessage` (§8.3), and the §3 participant constraints.

use crate::{BANNED_ROLE_INDEX, Capability, NO_ROLE_INDEX, Role, RoleData};

/// A §8.1 membership change one actor requests, described without MLS
/// types.
///
/// The hub maps a commit's proposals to these: it decides whether a change
/// concerns the actor itself or another user, and reads each user's
/// current role from the participant list. Variant names follow the §8.1
/// capability names; a role index of 0 means "not in the participant list"
/// (§3).
///
/// There is no separate ban or unban action. A ban is a change to role 1
/// and an unban a change from role 1, so [`MembershipAction::ChangeUserRole`]
/// and [`MembershipAction::AddParticipant`] accept `canBan` and `canUnban`
/// as well (room-policy-04 §8.1.3; decision mimid-1wgh.3.26).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MembershipAction {
    /// Add another user, not in the participant list, with
    /// `target_role_index` (§8.1.1 `canAddParticipant`). A target of role 1
    /// is also authorized by `canBan` (room-policy-04 §8.1.3; decision
    /// mimid-1wgh.3.51).
    AddParticipant {
        /// The role the added user gets.
        target_role_index: u32,
    },
    /// Remove another user, whose current role is `from_role_index`, from
    /// the participant list with all its clients (§8.1.2
    /// `canRemoveParticipant`).
    RemoveParticipant {
        /// The removed user's current role.
        from_role_index: u32,
    },
    /// Leave the participant list (§8.1.2 `canRemoveSelf`).
    RemoveSelf,
    /// Add the actor's own client (§8.1.1 `canAddOwnClient`).
    AddOwnClient,
    /// Remove the actor's own client without changing the participant list
    /// (§8.1.2 `canRemoveOwnClient`).
    RemoveOwnClient,
    /// Remove another participant's clients without changing the
    /// participant list (§8.1.2 `canKick`).
    Kick,
    /// Change another participant's role from `from_role_index` to
    /// `target_role_index` (§8.1.3 `canChangeUserRole`, `canBan`,
    /// `canUnban`).
    ChangeUserRole {
        /// The participant's current role.
        from_role_index: u32,
        /// The participant's new role.
        target_role_index: u32,
    },
    /// Change the actor's own role to `target_role_index` (§8.1.3
    /// `canChangeOwnRole`). It must be the first matching preauthorization
    /// entry's role; a first match of role 0 denies (room-policy-04
    /// §8.1.3; decision mimid-1wgh.3.52).
    ChangeOwnRole {
        /// The role the actor asks for.
        target_role_index: u32,
        /// [`crate::PreAuthData::first_match`] for the actor's credential.
        preauthorized_role_index: Option<u32>,
    },
    /// Join externally with `target_role_index` (§8.1.1 `canOpenJoin`).
    OpenJoin {
        /// The role the joiner asks for.
        target_role_index: u32,
    },
    /// Join externally with `target_role_index` by preauthorization (§8.1.1
    /// `canJoinIfPreauthorized`).
    JoinIfPreauthorized {
        /// The role the joiner asks for.
        target_role_index: u32,
        /// [`crate::PreAuthData::first_match`] for the joiner's credential.
        preauthorized_role_index: Option<u32>,
    },
    /// Join externally with a join code naming `target_role_index` (§8.1.1
    /// `canUseJoinCode`). The hub checks that the join code is valid and
    /// names this role.
    UseJoinCode {
        /// The role the join code names.
        target_role_index: u32,
    },
}

/// Why room policy denies an action or a post-commit state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Denied {
    /// A role the action needs is not defined in `roles_list`.
    #[error("role_index {0} is not defined in roles_list")]
    UndefinedRole(u32),
    /// The role that must hold a capability does not.
    #[error("role {role_index} does not hold capability {:#06x}", capability.0)]
    MissingCapability {
        /// The role checked.
        role_index: u32,
        /// The capability it lacks.
        capability: Capability,
    },
    /// No `authorized_role_changes` entry of the role that holds the
    /// capability allows this transition (§8.1).
    #[error(
        "no authorized_role_changes entry allows role {from_role_index} to {target_role_index}"
    )]
    RoleChangeNotAuthorized {
        /// The `from_role_index` looked up.
        from_role_index: u32,
        /// The target that no matching entry lists.
        target_role_index: u32,
    },
    /// The action names role 0 where it needs a participant's role: as the
    /// new role of an added, joining or changed user, or as the current
    /// role of a removed or changed user (§3).
    #[error("role 0 cannot be the role of a participant")]
    NoRole,
    /// The action requires an actor in the participant list, and the actor
    /// has role 0 (§8.1.1, §8.1.2, §4).
    #[error("the actor is not in the participant list")]
    ActorHasNoRole,
    /// The action is an external join, and the actor already has a role
    /// (§8.1.1).
    #[error("the actor already has role {0}")]
    ActorHasRole(u32),
    /// No preauthorization entry matches the actor (§4).
    #[error("the actor is not preauthorized")]
    NotPreauthorized,
    /// The actor's first matching preauthorization entry is for another
    /// role (§4).
    #[error(
        "the actor asks for role {target_role_index} but is preauthorized for role {preauthorized_role_index}"
    )]
    PreauthorizedForOtherRole {
        /// The role asked for.
        target_role_index: u32,
        /// The role of the first matching entry.
        preauthorized_role_index: u32,
    },
    /// A preauthorized target role is role 1 (decisions mimid-1wgh.3.49,
    /// mimid-1wgh.3.53).
    #[error("role {0} cannot be taken by preauthorization")]
    PreauthorizedRoleUnusable(u32),
    /// Fewer participants have the role than
    /// `minimum_participants_constraint` (§3).
    #[error("role {role_index} has {actual} participants, below the minimum {minimum}")]
    TooFewParticipants {
        /// The role.
        role_index: u32,
        /// `minimum_participants_constraint`.
        minimum: u32,
        /// The count after the commit.
        actual: u32,
    },
    /// More participants have the role than
    /// `maximum_participants_constraint` (§3).
    #[error("role {role_index} has {actual} participants, above the maximum {maximum}")]
    TooManyParticipants {
        /// The role.
        role_index: u32,
        /// `maximum_participants_constraint`.
        maximum: u32,
        /// The count after the commit.
        actual: u32,
    },
    /// Fewer active participants have the role than
    /// `minimum_active_participants_constraint` (§3).
    #[error("role {role_index} has {actual} active participants, below the minimum {minimum}")]
    TooFewActiveParticipants {
        /// The role.
        role_index: u32,
        /// `minimum_active_participants_constraint`.
        minimum: u32,
        /// The count after the commit.
        actual: u32,
    },
    /// More active participants have the role than
    /// `maximum_active_participants_constraint` (§3).
    #[error("role {role_index} has {actual} active participants, above the maximum {maximum}")]
    TooManyActiveParticipants {
        /// The role.
        role_index: u32,
        /// `maximum_active_participants_constraint`.
        maximum: u32,
        /// The count after the commit.
        actual: u32,
    },
}

/// Per-role participant counts of a room, as [`RoleData::check_constraints`]
/// reads them.
pub trait Occupancy {
    /// The number of participant-list entries with `role_index`.
    fn participants(&self, role_index: u32) -> u32;

    /// The number of users with `role_index` that have at least one client
    /// in the MLS group. For role 0 this counts users that are not in the
    /// participant list but have clients in the group (§3: "If the maximum
    /// number of active participants is zero, then no participants are
    /// allowed to have clients in the room's MLS group"). The role 0
    /// meaning is INVENTED, NOT FROM SPEC (room-policy-04 §3; decision
    /// mimid-1wgh.3.54).
    fn active_participants(&self, role_index: u32) -> u32;
}

/// Whether `role` has an `authorized_role_changes` entry with
/// `from_role_index` whose `target_role_indexes` include `target_role_index`.
fn allows_change(role: &Role, from_role_index: u32, target_role_index: u32) -> bool {
    role.authorized_role_changes.iter().any(|change| {
        change.from_role_index == from_role_index
            && change.target_role_indexes.contains(&target_role_index)
    })
}

/// Fails with [`Denied::NoRole`] if `role_index` is 0.
fn participant_role(role_index: u32) -> Result<u32, Denied> {
    if role_index == NO_ROLE_INDEX {
        Err(Denied::NoRole)
    } else {
        Ok(role_index)
    }
}

impl RoleData {
    /// The role with `role_index`, or [`Denied::UndefinedRole`].
    fn defined(&self, role_index: u32) -> Result<&Role, Denied> {
        self.role(role_index)
            .ok_or(Denied::UndefinedRole(role_index))
    }

    /// The role with `role_index` if it holds `capability`.
    fn holder(&self, role_index: u32, capability: Capability) -> Result<&Role, Denied> {
        let role = self.defined(role_index)?;
        if role.role_capabilities.contains(&capability) {
            Ok(role)
        } else {
            Err(Denied::MissingCapability {
                role_index,
                capability,
            })
        }
    }

    /// Whether role 1 exists and is the "banned" role, which `canBan` and
    /// `canUnban` require (§8.1.3; decision mimid-1wgh.3.42).
    fn has_banned_role(&self) -> bool {
        self.role(BANNED_ROLE_INDEX)
            .is_some_and(Role::is_banned_role)
    }

    /// Checks a preauthorized target role (§4, §8.1.1, §8.1.3; decision
    /// mimid-1wgh.3.49): it is the actor's first matching role, not 0 or
    /// 1, and defined.
    fn preauthorized(
        &self,
        target_role_index: u32,
        preauthorized_role_index: Option<u32>,
    ) -> Result<&Role, Denied> {
        participant_role(target_role_index)?;
        match preauthorized_role_index {
            None => return Err(Denied::NotPreauthorized),
            Some(preauthorized) if preauthorized != target_role_index => {
                return Err(Denied::PreauthorizedForOtherRole {
                    target_role_index,
                    preauthorized_role_index: preauthorized,
                });
            }
            Some(_) => {}
        }
        // room-policy-04 §4; decisions mimid-1wgh.3.49, mimid-1wgh.3.53
        if target_role_index == BANNED_ROLE_INDEX {
            return Err(Denied::PreauthorizedRoleUnusable(target_role_index));
        }
        self.defined(target_role_index)
    }

    /// Checks an external join by role 0's `capability` (§8.1.1
    /// `canOpenJoin`, `canUseJoinCode`): role 0 holds it and has a
    /// `from_role_index` 0 entry listing the target (decisions
    /// mimid-1wgh.3.25, mimid-1wgh.3.43).
    fn role_zero_join(
        &self,
        actor_role: u32,
        target_role_index: u32,
        capability: Capability,
    ) -> Result<(), Denied> {
        if actor_role != NO_ROLE_INDEX {
            return Err(Denied::ActorHasRole(actor_role));
        }
        self.defined(participant_role(target_role_index)?)?;
        let role_zero = self.holder(NO_ROLE_INDEX, capability)?;
        if allows_change(role_zero, NO_ROLE_INDEX, target_role_index) {
            Ok(())
        } else {
            Err(Denied::RoleChangeNotAuthorized {
                from_role_index: NO_ROLE_INDEX,
                target_role_index,
            })
        }
    }

    /// Checks a change by another actor from `from_role_index` (0 for an
    /// add) to `target_role_index`, by `capability` or, for changes to or
    /// from role 1, by `canBan` or `canUnban` (§8.1.1, §8.1.3; decision
    /// mimid-1wgh.3.26).
    fn role_change(
        &self,
        actor_role: u32,
        from_role_index: u32,
        target_role_index: u32,
        capability: Capability,
    ) -> Result<(), Denied> {
        self.defined(participant_role(target_role_index)?)?;
        let actor = self.defined(actor_role)?;
        let holds = |capability| actor.role_capabilities.contains(&capability);
        let allows = |from, to| allows_change(actor, from, to);
        let by_capability = holds(capability) && allows(from_role_index, target_role_index);
        // §8.1.3 canBan: "if the target_role_indexes for that entry
        // contains the role_index 1; that role_name = "banned" ..."; from
        // role 0 it adds a non-member as banned (room-policy-04 §8.1.3;
        // decision mimid-1wgh.3.51)
        let ban_relevant = target_role_index == BANNED_ROLE_INDEX && holds(Capability::CAN_BAN);
        let by_ban =
            ban_relevant && self.has_banned_role() && allows(from_role_index, BANNED_ROLE_INDEX);
        // §8.1.3 canUnban: "identical to the canChangeUserRole capability,
        // except that the from_role_index for the unbanned user MUST be 1"
        let unban_relevant = from_role_index == BANNED_ROLE_INDEX && holds(Capability::CAN_UN_BAN);
        let by_unban = unban_relevant
            && self.has_banned_role()
            && allows(BANNED_ROLE_INDEX, target_role_index);
        if by_capability || by_ban || by_unban {
            Ok(())
        } else if holds(capability) || ban_relevant || unban_relevant {
            Err(Denied::RoleChangeNotAuthorized {
                from_role_index,
                target_role_index,
            })
        } else {
            Err(Denied::MissingCapability {
                role_index: actor_role,
                capability,
            })
        }
    }

    /// Checks that an actor with `actor_role` may take `action`, by the
    /// §8.1 membership capabilities.
    ///
    /// `actor_role` is the actor's role in the participant list, or 0 if it
    /// is not in it (§3). Pass a `roles_list` that has passed
    /// [`RoleData::validate`]; undefined roles are denied regardless.
    ///
    /// Authorization follows §8.1 as written, with these decided readings:
    /// - a holder of `canAddParticipant` needs an `authorized_role_changes`
    ///   entry with `from_role_index` 0 listing the target role; role 0
    ///   needs one for `canOpenJoin` and `canUseJoinCode` (decisions
    ///   mimid-1wgh.3.43, mimid-1wgh.3.25);
    /// - `canOpenJoin` and `canUseJoinCode` are read from role 0, and the
    ///   join code's target must be in role 0's `from_role_index` 0 entry
    ///   (decision mimid-1wgh.3.25);
    /// - a change to or from role 1 is allowed if any of
    ///   `canChangeUserRole`, `canBan` or `canUnban` authorizes it, and
    ///   `canBan`/`canUnban` work only when role 1 is the "banned" role
    ///   ([`Role::is_banned_role`]; decisions mimid-1wgh.3.26,
    ///   mimid-1wgh.3.42);
    /// - a preauthorized target role must be the first matching role, and
    ///   neither 0 nor 1 (decisions mimid-1wgh.3.49, mimid-1wgh.3.52,
    ///   mimid-1wgh.3.53);
    /// - `canBan` may add a non-member directly as banned
    ///   ([`MembershipAction::AddParticipant`] with role 1; decision
    ///   mimid-1wgh.3.51).
    ///
    /// The minimum and maximum participant constraints that §8.1 attaches
    /// to each action are not checked here. Call
    /// [`RoleData::check_constraints`] once on the state after the whole
    /// commit (decision mimid-1wgh.3.24).
    ///
    /// # Errors
    ///
    /// The [`Denied`] reason for the first failed check.
    pub fn authorize(&self, actor_role: u32, action: MembershipAction) -> Result<(), Denied> {
        match action {
            MembershipAction::AddParticipant { target_role_index } => self.role_change(
                actor_role,
                NO_ROLE_INDEX,
                target_role_index,
                Capability::CAN_ADD_PARTICIPANT,
            ),
            MembershipAction::ChangeUserRole {
                from_role_index,
                target_role_index,
            } => {
                // §8.1.3 "change the role of another participant": a user
                // with role 0 is not one (§3); adding is canAddParticipant.
                participant_role(from_role_index)?;
                self.role_change(
                    actor_role,
                    from_role_index,
                    target_role_index,
                    Capability::CAN_CHANGE_USER_ROLE,
                )
            }
            MembershipAction::RemoveParticipant { from_role_index } => {
                participant_role(from_role_index)?;
                let actor = self.holder(actor_role, Capability::CAN_REMOVE_PARTICIPANT)?;
                if allows_change(actor, from_role_index, NO_ROLE_INDEX) {
                    Ok(())
                } else {
                    Err(Denied::RoleChangeNotAuthorized {
                        from_role_index,
                        target_role_index: NO_ROLE_INDEX,
                    })
                }
            }
            MembershipAction::RemoveSelf => {
                participant_role(actor_role).map_err(|_| Denied::ActorHasNoRole)?;
                let actor = self.holder(actor_role, Capability::CAN_REMOVE_SELF)?;
                if allows_change(actor, actor_role, NO_ROLE_INDEX) {
                    Ok(())
                } else {
                    Err(Denied::RoleChangeNotAuthorized {
                        from_role_index: actor_role,
                        target_role_index: NO_ROLE_INDEX,
                    })
                }
            }
            MembershipAction::AddOwnClient => {
                // §8.1.1: "a holder of this capability that is in the
                // participant list"
                participant_role(actor_role).map_err(|_| Denied::ActorHasNoRole)?;
                self.holder(actor_role, Capability::CAN_ADD_OWN_CLIENT)
                    .map(drop)
            }
            MembershipAction::RemoveOwnClient => self
                .holder(actor_role, Capability::CAN_REMOVE_OWN_CLIENT)
                .map(drop),
            MembershipAction::Kick => self.holder(actor_role, Capability::CAN_KICK).map(drop),
            MembershipAction::ChangeOwnRole {
                target_role_index,
                preauthorized_role_index,
            } => {
                // §4: consulted "when an existing participant explicitly
                // tries to change its _own_ role"
                participant_role(actor_role).map_err(|_| Denied::ActorHasNoRole)?;
                self.holder(actor_role, Capability::CAN_CHANGE_OWN_ROLE)?;
                // "first non-zero role it matches" = the first match, and a
                // first match of role 0 denies (room-policy-04 §8.1.3;
                // decision mimid-1wgh.3.52)
                self.preauthorized(target_role_index, preauthorized_role_index)
                    .map(drop)
            }
            MembershipAction::JoinIfPreauthorized {
                target_role_index,
                preauthorized_role_index,
            } => {
                if actor_role != NO_ROLE_INDEX {
                    return Err(Denied::ActorHasRole(actor_role));
                }
                self.preauthorized(target_role_index, preauthorized_role_index)?;
                // §8.1.1: the capability appears on the target role.
                self.holder(target_role_index, Capability::CAN_JOIN_IF_PREAUTHORIZED)
                    .map(drop)
            }
            MembershipAction::OpenJoin { target_role_index } => {
                self.role_zero_join(actor_role, target_role_index, Capability::CAN_OPEN_JOIN)
            }
            MembershipAction::UseJoinCode { target_role_index } => {
                self.role_zero_join(actor_role, target_role_index, Capability::CAN_USE_JOIN_CODE)
            }
        }
    }

    /// Checks that an actor with `actor_role` may send instant messages to
    /// the room: its role holds `canSendMessage` (§8.3).
    ///
    /// # Errors
    ///
    /// [`Denied::UndefinedRole`] or [`Denied::MissingCapability`].
    pub fn authorize_send_message(&self, actor_role: u32) -> Result<(), Denied> {
        self.holder(actor_role, Capability::CAN_SEND_MESSAGE)
            .map(drop)
    }

    /// Checks every role's §3 participant constraints against the room's
    /// state after a commit.
    ///
    /// The constraints are evaluated once, on the state after the whole
    /// commit, not per action (§8.1.2, §8.1.3; decision mimid-1wgh.3.24).
    /// A minimum of zero and an absent maximum impose nothing (§3). Roles
    /// are checked in list order, each in the order minimum participants,
    /// maximum participants, minimum active, maximum active.
    ///
    /// # Errors
    ///
    /// The first constraint broken.
    pub fn check_constraints(&self, after: &impl Occupancy) -> Result<(), Denied> {
        for role in &self.roles {
            let role_index = role.role_index;
            let actual = after.participants(role_index);
            if actual < role.minimum_participants_constraint {
                return Err(Denied::TooFewParticipants {
                    role_index,
                    minimum: role.minimum_participants_constraint,
                    actual,
                });
            }
            if let Some(maximum) = role.maximum_participants_constraint
                && actual > maximum
            {
                return Err(Denied::TooManyParticipants {
                    role_index,
                    maximum,
                    actual,
                });
            }
            let actual = after.active_participants(role_index);
            if actual < role.minimum_active_participants_constraint {
                return Err(Denied::TooFewActiveParticipants {
                    role_index,
                    minimum: role.minimum_active_participants_constraint,
                    actual,
                });
            }
            if let Some(maximum) = role.maximum_active_participants_constraint
                && actual > maximum
            {
                return Err(Denied::TooManyActiveParticipants {
                    role_index,
                    maximum,
                    actual,
                });
            }
        }
        Ok(())
    }
}
