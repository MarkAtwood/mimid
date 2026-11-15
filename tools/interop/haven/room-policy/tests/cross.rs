//! room-policy-04 `roles_list` (§3) and `base_room_policy` (§5) across
//! Haven's `mimi_core::room_policy_wire` and mimid's `mimi-room-policy`,
//! both ways (bead mimid-1wgh.46.7).
//!
//! Haven keeps six capabilities and five base fields and writes the rest at
//! fixed values, so:
//!
//! - Haven → mimid: every Haven encoding decodes in mimid to the same
//!   meaning and re-encodes byte for byte.
//! - mimid → Haven: mimid's encodings, including fields Haven does not
//!   keep, decode in Haven to what Haven keeps of them.
//! - Refusals: the same malformed or rule-breaking bytes go to both, and
//!   every place the two disagree is printed. Each disagreement is
//!   asserted as found, so a change on either side shows up as a failure.
//!
//! Oracle: room-policy-04's struct layout as written by hand below for the
//! malformed cases, and the field values each test sets. Run with
//! `cargo test -- --nocapture` for the report.

use mimi_core::room_policy::{
    BaseRoomPolicy as HBase, Capability as HCap, Role as HRole,
    SingleSourceRoleChangeTargets as HChange,
};
use mimi_core::room_policy_wire as haven;
use mimi_room_policy::tls_codec::{Deserialize, Serialize};
use mimi_room_policy::{
    BaseRoomPolicy, Bool, Capability, Role, RoleData, SingleSourceRoleChangeTargets, Uri,
};

const PARENT: &str = "mimi://a.example/r/parent";

fn h_role(index: u32, name: &str, caps: &[HCap], changes: &[(u32, &[u32])]) -> HRole {
    HRole {
        role_index: index,
        role_name: name.to_owned(),
        capabilities: caps.to_vec(),
        authorized_role_changes: changes
            .iter()
            .map(|(from, to)| HChange {
                from_role_index: *from,
                target_role_indexes: to.to_vec(),
            })
            .collect(),
    }
}

/// Haven's capability as mimid's registry value.
fn wire(cap: HCap) -> Capability {
    Capability(match cap {
        HCap::AddParticipant => 0x0000,
        HCap::RemoveParticipant => 0x0001,
        HCap::Ban => 0x000a,
        HCap::Kick => 0x000c,
        HCap::ChangeRole => 0x000f,
        HCap::SendMessage => 0x0100,
    })
}

/// Haven role lists: empty, banned only, the usual three, and one role
/// with every capability Haven knows and several change entries.
fn haven_role_lists() -> Vec<(&'static str, Vec<HRole>)> {
    use HCap::*;
    let all = [AddParticipant, RemoveParticipant, Ban, Kick, ChangeRole, SendMessage];
    vec![
        ("empty", vec![]),
        ("banned only", vec![h_role(1, "banned", &[], &[])]),
        (
            "banned, member, admin",
            vec![
                h_role(1, "banned", &[], &[]),
                h_role(2, "member", &[SendMessage, AddParticipant], &[(0, &[2]), (2, &[0])]),
                h_role(3, "admin", &all, &[(0, &[2, 3]), (2, &[0, 1, 3]), (3, &[0, 2])]),
            ],
        ),
        (
            // Haven's sample_policy (mimi-core src/room_policy.rs tests).
            "Haven sample policy",
            vec![
                h_role(0, "non-participant", &[], &[]),
                h_role(1, "banned", &[], &[]),
                h_role(
                    2,
                    "admin",
                    &[SendMessage, AddParticipant, RemoveParticipant, Ban, ChangeRole],
                    &[(0, &[2, 3]), (3, &[0, 1]), (2, &[3])],
                ),
                h_role(3, "member", &[SendMessage], &[]),
            ],
        ),
        (
            "high indexes, empty target list",
            vec![h_role(0xffff_fffe, "x", &[Kick], &[(7, &[])]), h_role(7, "", &[], &[])],
        ),
    ]
}

/// The meaning of a mimid role list in Haven's terms: only the six
/// capabilities, first occurrence kept.
fn as_haven(roles: &RoleData) -> Vec<HRole> {
    roles
        .roles
        .iter()
        .map(|r| {
            let mut caps: Vec<HCap> = Vec::new();
            for c in &r.role_capabilities {
                if let Some(h) = haven::capability_from_wire(c.0) {
                    if !caps.contains(&h) {
                        caps.push(h);
                    }
                }
            }
            HRole {
                role_index: r.role_index,
                role_name: r.role_name.clone(),
                capabilities: caps,
                authorized_role_changes: r
                    .authorized_role_changes
                    .iter()
                    .map(|c| HChange {
                        from_role_index: c.from_role_index,
                        target_role_indexes: c.target_role_indexes.clone(),
                    })
                    .collect(),
            }
        })
        .collect()
}

#[test]
fn haven_role_lists_decode_and_reencode_in_mimid() {
    for (label, roles) in haven_role_lists() {
        let bytes = haven::encode_role_data(&roles);
        let mimid = RoleData::tls_deserialize_exact(&bytes[..])
            .unwrap_or_else(|e| panic!("{label}: mimid refuses Haven's roles: {e:?}"));
        assert_eq!(as_haven(&mimid), roles, "{label}");
        for (h, m) in roles.iter().zip(&mimid.roles) {
            let caps: Vec<Capability> = h.capabilities.iter().map(|c| wire(*c)).collect();
            assert_eq!(m.role_capabilities, caps, "{label}: order kept");
            assert_eq!(m.role_description, "", "{label}");
            assert_eq!(
                (
                    m.minimum_participants_constraint,
                    m.maximum_participants_constraint,
                    m.minimum_active_participants_constraint,
                    m.maximum_active_participants_constraint
                ),
                (0, None, 0, None),
                "{label}"
            );
        }
        assert_eq!(mimid.tls_serialize_detached().unwrap(), bytes, "{label}");
        // Every list here is one mimid's hub would hold, open membership.
        mimid
            .validate(false)
            .unwrap_or_else(|e| panic!("{label}: mimid's validate refuses it: {e:?}"));
    }
}

fn base(fixed: bool, parent: bool, clients: Option<u32>, users: Option<u32>, disc: bool) -> HBase {
    HBase {
        fixed_membership: fixed,
        parent_dependant: parent,
        max_clients: clients,
        max_users: users,
        discoverable: disc,
    }
}

fn haven_bases() -> Vec<(HBase, Option<&'static str>)> {
    vec![
        (base(false, false, None, None, false), None),
        (base(true, false, Some(0), Some(1), true), None),
        (base(false, true, Some(u32::MAX), None, false), Some(PARENT)),
        (base(true, true, None, Some(500), true), Some(PARENT)),
    ]
}

#[test]
fn haven_base_policies_decode_and_reencode_in_mimid() {
    for (h, parent) in haven_bases() {
        let bytes = haven::encode_base_room_policy(&h, parent);
        let m = BaseRoomPolicy::tls_deserialize_exact(&bytes[..])
            .unwrap_or_else(|e| panic!("{h:?}: mimid refuses Haven's base policy: {e:?}"));
        assert_eq!(bool::from(m.fixed_membership), h.fixed_membership);
        assert_eq!(bool::from(m.parent_dependant), h.parent_dependant);
        assert_eq!(
            m.parent_room.iter().map(Uri::as_str).collect::<Vec<_>>(),
            parent.into_iter().collect::<Vec<_>>()
        );
        assert_eq!((m.max_clients, m.max_users), (h.max_clients, h.max_users));
        assert_eq!(bool::from(m.discoverable), h.discoverable);
        // Haven's fixed values for the fields it does not keep.
        assert_eq!(
            (
                bool::from(m.multi_device),
                bool::from(m.pseudonyms_allowed),
                bool::from(m.persistent_room)
            ),
            (true, false, true)
        );
        assert!(m.policy_component_ids.is_empty());
        assert_eq!(m.tls_serialize_detached().unwrap(), bytes, "{h:?}");
    }
}

fn m_role(
    index: u32,
    name: &str,
    caps: &[Capability],
    constraints: (u32, Option<u32>, u32, Option<u32>),
    changes: &[(u32, &[u32])],
) -> Role {
    Role {
        role_index: index,
        role_name: name.to_owned(),
        role_description: format!("the {name} role"),
        role_capabilities: caps.to_vec(),
        minimum_participants_constraint: constraints.0,
        maximum_participants_constraint: constraints.1,
        minimum_active_participants_constraint: constraints.2,
        maximum_active_participants_constraint: constraints.3,
        authorized_role_changes: changes
            .iter()
            .map(|(from, to)| SingleSourceRoleChangeTargets {
                from_role_index: *from,
                target_role_indexes: to.to_vec(),
            })
            .collect(),
    }
}

/// mimid role lists with what Haven does not keep: descriptions,
/// constraints, capabilities outside Haven's six, a repeated capability.
fn mimid_role_lists() -> Vec<(&'static str, RoleData)> {
    use mimi_room_policy::Capability as C;
    vec![
        (
            // mimid-chat's `/roles` list (tools/interop/chat default_roles).
            "mimid-chat default",
            RoleData {
                roles: vec![
                    m_role(1, "banned", &[], (0, None, 0, None), &[]),
                    m_role(
                        2,
                        "member",
                        &[
                            C::CAN_ADD_PARTICIPANT,
                            C::CAN_REMOVE_SELF,
                            C::CAN_SEND_MESSAGE,
                            C::CAN_RECEIVE_MESSAGE,
                            C::CAN_REPLY_TO_MESSAGE,
                            C::CAN_REACT_TO_MESSAGE,
                            C::CAN_CHANGE_ROLE_DEFINITIONS,
                        ],
                        (0, None, 0, None),
                        &[(0, &[2]), (2, &[0])],
                    ),
                ],
            },
        ),
        (
            "constraints, unknown and repeated capabilities",
            RoleData {
                roles: vec![
                    m_role(
                        3,
                        "moderator",
                        &[C::CAN_KICK, C(0x7f01), C::CAN_BAN, C::CAN_KICK, C::CAN_UN_BAN],
                        (1, Some(5), 0, Some(5)),
                        &[(2, &[1, 0])],
                    ),
                    m_role(2, "member", &[C::CAN_SEND_MESSAGE], (0, Some(1000), 0, None), &[]),
                ],
            },
        ),
    ]
}

#[test]
fn mimid_role_lists_decode_in_haven() {
    for (label, roles) in mimid_role_lists() {
        let bytes = roles.tls_serialize_detached().unwrap();
        let h = haven::decode_role_data(&bytes)
            .unwrap_or_else(|e| panic!("{label}: Haven refuses mimid's roles: {e}"));
        assert_eq!(h, as_haven(&roles), "{label}");
    }
}

#[test]
fn mimid_base_policies_decode_in_haven() {
    let uri = |s: &str| Uri::new(s).unwrap();
    let cases = [
        // mimid-chat's `/host` policy (tools/interop/chat default_base_policy).
        BaseRoomPolicy {
            fixed_membership: Bool::False,
            parent_dependant: Bool::False,
            parent_room: vec![],
            multi_device: Bool::True,
            max_clients: None,
            max_users: None,
            pseudonyms_allowed: Bool::False,
            persistent_room: Bool::True,
            discoverable: Bool::False,
            policy_component_ids: vec![],
        },
        BaseRoomPolicy {
            fixed_membership: Bool::True,
            parent_dependant: Bool::True,
            parent_room: vec![uri(PARENT)],
            multi_device: Bool::False,
            max_clients: Some(10),
            max_users: Some(3),
            pseudonyms_allowed: Bool::True,
            persistent_room: Bool::False,
            discoverable: Bool::True,
            policy_component_ids: vec![0x0025, 0x0027, 0x8001],
        },
    ];
    for m in cases {
        let bytes = m.tls_serialize_detached().unwrap();
        let h = haven::decode_base_room_policy(&bytes)
            .unwrap_or_else(|e| panic!("Haven refuses mimid's base policy {m:?}: {e}"));
        assert_eq!(
            h,
            base(
                m.fixed_membership.into(),
                m.parent_dependant.into(),
                m.max_clients,
                m.max_users,
                m.discoverable.into()
            )
        );
    }
}

// ---- refusals: hand-built bytes to both decoders ----

fn v(content: &[u8]) -> Vec<u8> {
    // QUIC-style variable-length header (RFC 9420 §2.1.2), one or two bytes.
    let n = content.len();
    let mut out = if n < 64 {
        vec![u8::try_from(n).unwrap()]
    } else {
        let n = u16::try_from(n).unwrap() | 0x4000;
        n.to_be_bytes().to_vec()
    };
    out.extend_from_slice(content);
    out
}

/// One Role, written field by field.
#[allow(clippy::too_many_arguments)]
fn role_bytes(
    index: u32,
    caps: &[u16],
    min: u32,
    max: Option<u32>,
    min_active: u32,
    max_active: Option<u32>,
    changes: &[(u32, &[u32])],
) -> Vec<u8> {
    let opt = |x: Option<u32>| match x {
        None => vec![0],
        Some(x) => [&[1][..], &x.to_be_bytes()].concat(),
    };
    let caps: Vec<u8> = caps.iter().flat_map(|c| c.to_be_bytes()).collect();
    let changes: Vec<u8> = changes
        .iter()
        .flat_map(|(from, to)| {
            let to: Vec<u8> = to.iter().flat_map(|t| t.to_be_bytes()).collect();
            [from.to_be_bytes().to_vec(), v(&to)].concat()
        })
        .collect();
    [
        index.to_be_bytes().to_vec(),
        v(b"r"),
        v(b""),
        v(&caps),
        min.to_be_bytes().to_vec(),
        opt(max),
        min_active.to_be_bytes().to_vec(),
        opt(max_active),
        v(&changes),
    ]
    .concat()
}

fn roles(list: &[Vec<u8>]) -> Vec<u8> {
    v(&list.concat())
}

/// One BaseRoomPolicy with flags as raw bytes.
fn base_bytes(flags: [u8; 2], parents: &[&str], max_clients: &[u8], rest: [u8; 3]) -> Vec<u8> {
    let parents: Vec<u8> = parents.iter().flat_map(|p| v(p.as_bytes())).collect();
    [
        flags.to_vec(),
        v(&parents),
        vec![1],
        max_clients.to_vec(),
        vec![0],
        rest.to_vec(),
        v(&[]),
    ]
    .concat()
}

/// Whether each side accepts `bytes` as a room's role list, in a room with
/// `fixed_membership`: mimid's decoder and `RoleData::validate`, Haven's
/// decoder and `RoomPolicy::validate`, the checks each hub applies.
fn verdicts_roles(bytes: &[u8], fixed: bool) -> (bool, bool) {
    let mimid = RoleData::tls_deserialize_exact(bytes).is_ok_and(|r| r.validate(fixed).is_ok());
    let haven = haven::decode_role_data(bytes).is_ok_and(|roles| {
        mimi_core::room_policy::RoomPolicy {
            base: base(fixed, false, None, None, false),
            roles,
        }
        .validate()
        .is_ok()
    });
    (mimid, haven)
}

/// One Role with a chosen name and capabilities, otherwise unconstrained.
fn named(index: u32, name: &[u8], caps: &[u16]) -> Vec<u8> {
    let mut r = role_bytes(index, caps, 0, None, 0, None, &[]);
    // Replace the one-byte name "r" (after the 4-byte index).
    r.splice(4..6, v(name));
    r
}

fn verdicts_base(bytes: &[u8]) -> (bool, bool) {
    (
        BaseRoomPolicy::tls_deserialize_exact(bytes).is_ok(),
        haven::decode_base_room_policy(bytes).is_ok(),
    )
}

#[test]
fn refusals_compared() {
    let good = role_bytes(2, &[0x0100], 0, None, 0, None, &[]);
    // (case, bytes, fixed_membership, expected (mimid accepts, Haven accepts))
    let banned = named(1, b"banned", &[]);
    let role_cases: Vec<(&str, Vec<u8>, bool, (bool, bool))> = vec![
        ("well formed", roles(&[good.clone()]), false, (true, true)),
        ("trailing byte", [roles(&[good.clone()]), vec![0]].concat(), false, (false, false)),
        ("role_index repeated", roles(&[good.clone(), good.clone()]), false, (false, false)),
        (
            "min participants > max",
            roles(&[role_bytes(2, &[], 5, Some(1), 0, None, &[])]),
            false,
            (true, false),
        ),
        (
            "min active > max active",
            roles(&[role_bytes(2, &[], 0, None, 3, Some(2), &[])]),
            false,
            (true, false),
        ),
        (
            "optional presence byte 2",
            {
                let mut r = role_bytes(2, &[], 0, None, 0, None, &[]);
                // index(4) + name(2) + description(1) + caps(1) + min(4)
                r[12] = 2;
                roles(&[r])
            },
            false,
            (false, false),
        ),
        (
            "change names an undefined role",
            roles(&[role_bytes(2, &[], 0, None, 0, None, &[(0, &[9])])]),
            false,
            (false, false),
        ),
        (
            "canOpenJoin on role 2",
            roles(&[role_bytes(2, &[0x0004], 0, None, 0, None, &[])]),
            false,
            (false, true),
        ),
        (
            "role 1 not named banned",
            roles(&[named(1, b"blocked", &[])]),
            false,
            (true, false),
        ),
        (
            "role 0 with canSendMessage",
            roles(&[named(0, b"none", &[0x0100])]),
            false,
            (true, false),
        ),
        (
            "role 0 with canOpenJoin",
            roles(&[named(0, b"none", &[0x0004])]),
            false,
            (true, true),
        ),
        (
            "change targets role 1, not defined",
            roles(&[role_bytes(2, &[], 0, None, 0, None, &[(2, &[1])])]),
            false,
            (false, true),
        ),
        (
            "change targets role 1, defined",
            roles(&[banned.clone(), role_bytes(2, &[], 0, None, 0, None, &[(2, &[1])])]),
            false,
            (true, true),
        ),
        (
            "fixed: role 0 with canAddParticipant",
            roles(&[named(0, b"none", &[0x0000])]),
            true,
            (true, false),
        ),
        (
            "fixed: role 2 with canAddParticipant",
            roles(&[named(2, b"m", &[0x0000])]),
            true,
            (false, false),
        ),
    ];
    let base_cases: Vec<(&str, Vec<u8>, (bool, bool))> = vec![
        ("well formed", base_bytes([0, 0], &[], &[0], [0, 1, 0]), (true, true)),
        ("flag 2", base_bytes([2, 0], &[], &[0], [0, 1, 0]), (false, false)),
        ("parent-dependant, no parent", base_bytes([0, 1], &[], &[0], [0, 1, 0]), (false, false)),
        ("parent named, not dependant", base_bytes([0, 0], &[PARENT], &[0], [0, 1, 0]), (false, false)),
        ("two parents", base_bytes([0, 1], &[PARENT, PARENT], &[0], [0, 1, 0]), (false, false)),
        ("empty parent URI", base_bytes([0, 1], &[""], &[0], [0, 1, 0]), (false, false)),
        ("max_clients presence 2", base_bytes([0, 0], &[], &[2, 0, 0, 0, 1], [0, 1, 0]), (false, false)),
        (
            "trailing byte",
            [base_bytes([0, 0], &[], &[0], [0, 1, 0]), vec![0]].concat(),
            (false, false),
        ),
    ];
    let mut wrong = Vec::new();
    println!("\nroles_list                               mimid  Haven");
    for (label, bytes, fixed, want) in &role_cases {
        let got = verdicts_roles(bytes, *fixed);
        println!("  {label:<38} {:<6} {}", got.0, got.1);
        if got != *want {
            wrong.push(format!("roles_list {label}: got {got:?}, expected {want:?}"));
        }
    }
    println!("base_room_policy                         mimid  Haven");
    for (label, bytes, want) in &base_cases {
        let got = verdicts_base(bytes);
        println!("  {label:<38} {:<6} {}", got.0, got.1);
        if got != *want {
            wrong.push(format!("base_room_policy {label}: got {got:?}, expected {want:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
