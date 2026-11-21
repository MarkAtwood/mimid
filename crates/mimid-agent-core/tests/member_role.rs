//! The role a member has is the room's role named "member", matched
//! octet for octet (draft-atwood-jmap-chat-mimi-00 §Moderation,
//! jmap-chat-spec 735503c; clean-room finding C8): in a room whose roles
//! give "member" another index than the agent's own default (2), an
//! invited user and an unbanned one get that index, through a real mimid
//! server whose hub authorizes each change by the room's policy.
//!
//! Oracle: the participant list after each Commit, read back from the
//! inviter's group, against the role indexes the test chose.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, BOB, device, server};
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_agent_core::HostOptions;

/// The creator's role: host_room gives the creator role 3.
const ADMIN: u32 = 3;
/// "member", at an index the agent does not default to.
const MEMBER: u32 = 7;
const BANNED: u32 = 1;

fn roles() -> RoleData {
    let change = |from: u32, to: &[u32]| SingleSourceRoleChangeTargets {
        from_role_index: from,
        target_role_indexes: to.to_vec(),
    };
    let role = |role_index: u32, name: &str, caps: Vec<Capability>, changes| Role {
        role_index,
        role_name: name.to_owned(),
        role_description: String::new(),
        role_capabilities: caps,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes: changes,
    };
    let member_caps = vec![
        Capability::CAN_REMOVE_SELF,
        Capability::CAN_SEND_MESSAGE,
        Capability::CAN_RECEIVE_MESSAGE,
    ];
    let mut admin_caps = member_caps.clone();
    admin_caps.extend([
        Capability::CAN_ADD_PARTICIPANT,
        Capability::CAN_BAN,
        Capability::CAN_UN_BAN,
    ]);
    RoleData {
        roles: vec![
            role(BANNED, "banned", vec![], vec![change(BANNED, &[MEMBER])]),
            role(
                ADMIN,
                "admin",
                admin_caps,
                vec![
                    change(0, &[MEMBER]),
                    change(MEMBER, &[BANNED]),
                    change(BANNED, &[MEMBER]),
                ],
            ),
            role(MEMBER, "member", member_caps, vec![change(MEMBER, &[0])]),
        ],
    }
}

#[tokio::test]
async fn invites_and_unbans_use_the_role_named_member() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;
    alice.publish_key_packages(1).await.unwrap();
    bob.publish_key_packages(2).await.unwrap();
    let options = HostOptions {
        roles: Some(roles()),
        ..HostOptions::named("indexed")
    };
    let room = alice.host_room(&options).await.unwrap();
    assert_eq!(alice.member_role(&room).unwrap(), MEMBER);

    let role_of_bob = |agent: &mimid_agent_core::Agent| {
        agent
            .participant_roles(&room)
            .unwrap()
            .into_iter()
            .find(|(user, _)| user == BOB)
            .map(|(_, role)| role)
    };
    alice.invite(&room, BOB).await.unwrap();
    assert_eq!(role_of_bob(&alice), Some(MEMBER));

    alice.ban(&room, BOB).await.unwrap();
    assert_eq!(role_of_bob(&alice), Some(BANNED));
    alice.unban(&room, BOB).await.unwrap();
    assert_eq!(role_of_bob(&alice), Some(MEMBER));
}
