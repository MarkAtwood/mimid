//! Tests for the MIMI Role Capabilities registry (room-policy-04 §10.2).
//!
//! The oracle is Table 1 of draft-ietf-mimi-room-policy-04 §10.2,
//! transcribed by hand from the draft text, and the reserved-name list of
//! §8.7, transcribed separately. Wire fixtures are hex encoded by hand from
//! `CapabilityType role_capabilities<V>` (§3, Appendix B) with the RFC 9420
//! §2.1.2 varint length prefix.

use std::collections::BTreeSet;

use mimi_room_policy::Capability;
use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};

/// room-policy-04 §10.2 Table 1, every row in order: Value and Name exactly
/// as printed, including the `(reserved)` suffix.
const TABLE_1: &[(u16, &str)] = &[
    (0x0000, "canAddParticipant"),
    (0x0001, "canRemoveParticipant"),
    (0x0002, "canAddOwnClient"),
    (0x0003, "canRemoveOwnClient"),
    (0x0004, "canOpenJoin"),
    (0x0005, "canJoinIfPreauthorized"),
    (0x0006, "canRemoveSelf"),
    (0x0007, "canCreateJoinCode (reserved)"),
    (0x0008, "canDeleteJoinCode (reserved)"),
    (0x0009, "canUseJoinCode"),
    (0x000a, "canBan"),
    (0x000b, "canUnBan"),
    (0x000c, "canKick"),
    (0x000d, "canKnock (reserved)"),
    (0x000e, "canAcceptKnock (reserved)"),
    (0x000f, "canChangeUserRole"),
    (0x0010, "canChangeOwnRole"),
    (0x0011, "canCreateSubgroup (reserved)"),
    (0x0100, "canSendMessage"),
    (0x0101, "canReceiveMessage"),
    (0x0102, "canCopyMessage"),
    (0x0103, "canReportAbuse"),
    (0x0104, "canReplyToMessage"),
    (0x0105, "canReactToMessage"),
    (0x0106, "canEditReaction"),
    (0x0107, "canDeleteOwnReaction"),
    (0x0108, "canDeleteOtherReaction"),
    (0x0109, "canEditOwnMessage"),
    (0x010a, "canDeleteOwnMessage"),
    (0x010b, "canDeleteOtherMessage"),
    (0x010c, "canStartTopic"),
    (0x010d, "canReplyInTopic"),
    (0x010e, "canEditOwnTopic"),
    (0x010f, "canEditOtherTopic"),
    (0x0110, "canSendDirectMessage (reserved)"),
    (0x0111, "canTargetMessage (reserved)"),
    (0x0200, "canUploadImage"),
    (0x0201, "canUploadAudio"),
    (0x0202, "canUploadVideo"),
    (0x0203, "canUploadAttachment"),
    (0x0204, "canDownloadImage"),
    (0x0205, "canDownloadAudio"),
    (0x0206, "canDownloadVideo"),
    (0x0207, "canDownloadAttachment"),
    (0x0208, "canSendLink"),
    (0x0209, "canSendLinkPreview"),
    (0x020a, "canFollowLink"),
    (0x020b, "canCopyLink"),
    (0x0300, "canChangeRoomName"),
    (0x0301, "canChangeRoomDescription"),
    (0x0302, "canChangeRoomAvatar"),
    (0x0303, "canChangeRoomSubject"),
    (0x0304, "canChangeRoomMood"),
    (0x0380, "canChangeOwnName (reserved)"),
    (0x0381, "canChangeOwnPresence (reserved)"),
    (0x0382, "canChangeOwnMood (reserved)"),
    (0x0383, "canChangeOwnAvatar (reserved)"),
    (0x0400, "canStartCall"),
    (0x0401, "canJoinCall"),
    (0x0402, "canSendAudio"),
    (0x0403, "canReceiveAudio"),
    (0x0404, "canSendVideo"),
    (0x0405, "canReceiveVideo"),
    (0x0406, "canShareScreen"),
    (0x0407, "canViewSharedScreen"),
    (0x0500, "canCreateRoom (reserved)"),
    (0x0501, "canDestroyRoom"),
    (0x0502, "canChangeRoomMembershipStyle"),
    (0x0503, "canChangeRoleDefinitions"),
    (0x0504, "canChangePreauthorizedUserList"),
    (0x0505, "canChangeOtherPolicyAttribute (reserved)"),
    (0x0600, "canChangeMlsOperationalPolicies (reserved)"),
    (0x0601, "canSendMLSReinitProposal"),
    (0x0602, "canSendMLSUpdateProposal (reserved)"),
    (0x0603, "canSendMLSPSKProposal (reserved)"),
    (0x0604, "canSendMLSExternalProposal (reserved)"),
    (0x0605, "canSendMLSExternalCommit (reserved)"),
];

/// room-policy-04 §8.7: the named reserved capabilities. The "MLS specific"
/// sub-bullets there are prose, not names, and are left out.
const SECTION_8_7_RESERVED: &[&str] = &[
    "canCreateJoinCode",
    "canDeleteJoinCode",
    "canKnock",
    "canAcceptKnock",
    "canCreateSubgroup",
    "canSendDirectMessage",
    "canTargetMessage",
    "canChangeOwnName",
    "canChangeOwnPresence",
    "canChangeOwnMood",
    "canChangeOwnAvatar",
    "canCreateRoom",
    "canChangeMlsOperationalPolicies",
    "canChangeOtherPolicyAttribute",
];

const RESERVED_SUFFIX: &str = " (reserved)";

fn bare(table_name: &str) -> &str {
    table_name
        .strip_suffix(RESERVED_SUFFIX)
        .unwrap_or(table_name)
}

fn table_value(bare_name: &str) -> u16 {
    TABLE_1
        .iter()
        .find(|(_, name)| bare(name) == bare_name)
        .map(|(value, _)| *value)
        .unwrap_or_else(|| panic!("{bare_name} is not in Table 1"))
}

#[test]
fn name_matches_every_table_1_row() {
    for &(value, table_name) in TABLE_1 {
        assert_eq!(
            Capability(value).name(),
            Some(bare(table_name)),
            "value {value:#06x}"
        );
    }
}

#[test]
fn name_is_none_for_every_value_outside_table_1() {
    let registered: BTreeSet<u16> = TABLE_1.iter().map(|(value, _)| *value).collect();
    assert_eq!(registered.len(), TABLE_1.len(), "Table 1 values are unique");
    for value in 0..=u16::MAX {
        if !registered.contains(&value) {
            assert_eq!(Capability(value).name(), None, "value {value:#06x}");
        }
    }
}

#[test]
fn reserved_rows_of_table_1_are_the_section_8_7_names() {
    let from_table: BTreeSet<&str> = TABLE_1
        .iter()
        .filter_map(|(_, name)| name.strip_suffix(RESERVED_SUFFIX))
        .collect();
    let from_8_7: BTreeSet<&str> = SECTION_8_7_RESERVED.iter().copied().collect();
    // Table 1 also marks the four MLS proposal/commit rows (0x0602-0x0605)
    // reserved; §8.7 describes those only as "MLS specific" prose.
    let mls_specific: BTreeSet<&str> = [
        "canSendMLSUpdateProposal",
        "canSendMLSPSKProposal",
        "canSendMLSExternalProposal",
        "canSendMLSExternalCommit",
    ]
    .into_iter()
    .collect();
    let expected: BTreeSet<&str> = from_8_7.union(&mls_specific).copied().collect();
    assert_eq!(from_table, expected);
}

#[test]
fn named_constants_have_their_table_1_values() {
    let constants = [
        (Capability::CAN_ADD_PARTICIPANT, "canAddParticipant"),
        (Capability::CAN_REMOVE_PARTICIPANT, "canRemoveParticipant"),
        (Capability::CAN_ADD_OWN_CLIENT, "canAddOwnClient"),
        (Capability::CAN_REMOVE_OWN_CLIENT, "canRemoveOwnClient"),
        (Capability::CAN_OPEN_JOIN, "canOpenJoin"),
        (
            Capability::CAN_JOIN_IF_PREAUTHORIZED,
            "canJoinIfPreauthorized",
        ),
        (Capability::CAN_REMOVE_SELF, "canRemoveSelf"),
        (Capability::CAN_CREATE_JOIN_CODE, "canCreateJoinCode"),
        (Capability::CAN_DELETE_JOIN_CODE, "canDeleteJoinCode"),
        (Capability::CAN_USE_JOIN_CODE, "canUseJoinCode"),
        (Capability::CAN_BAN, "canBan"),
        (Capability::CAN_UN_BAN, "canUnBan"),
        (Capability::CAN_KICK, "canKick"),
        (Capability::CAN_KNOCK, "canKnock"),
        (Capability::CAN_ACCEPT_KNOCK, "canAcceptKnock"),
        (Capability::CAN_CHANGE_USER_ROLE, "canChangeUserRole"),
        (Capability::CAN_CHANGE_OWN_ROLE, "canChangeOwnRole"),
        (Capability::CAN_CREATE_SUBGROUP, "canCreateSubgroup"),
        (Capability::CAN_SEND_MESSAGE, "canSendMessage"),
        (Capability::CAN_RECEIVE_MESSAGE, "canReceiveMessage"),
        (Capability::CAN_COPY_MESSAGE, "canCopyMessage"),
        (Capability::CAN_REPORT_ABUSE, "canReportAbuse"),
        (Capability::CAN_REPLY_TO_MESSAGE, "canReplyToMessage"),
        (Capability::CAN_REACT_TO_MESSAGE, "canReactToMessage"),
        (Capability::CAN_EDIT_REACTION, "canEditReaction"),
        (Capability::CAN_DELETE_OWN_REACTION, "canDeleteOwnReaction"),
        (
            Capability::CAN_DELETE_OTHER_REACTION,
            "canDeleteOtherReaction",
        ),
        (Capability::CAN_EDIT_OWN_MESSAGE, "canEditOwnMessage"),
        (Capability::CAN_DELETE_OWN_MESSAGE, "canDeleteOwnMessage"),
        (
            Capability::CAN_DELETE_OTHER_MESSAGE,
            "canDeleteOtherMessage",
        ),
        (Capability::CAN_START_TOPIC, "canStartTopic"),
        (Capability::CAN_REPLY_IN_TOPIC, "canReplyInTopic"),
        (Capability::CAN_EDIT_OWN_TOPIC, "canEditOwnTopic"),
        (Capability::CAN_EDIT_OTHER_TOPIC, "canEditOtherTopic"),
        (Capability::CAN_SEND_DIRECT_MESSAGE, "canSendDirectMessage"),
        (Capability::CAN_TARGET_MESSAGE, "canTargetMessage"),
        (Capability::CAN_UPLOAD_IMAGE, "canUploadImage"),
        (Capability::CAN_UPLOAD_AUDIO, "canUploadAudio"),
        (Capability::CAN_UPLOAD_VIDEO, "canUploadVideo"),
        (Capability::CAN_UPLOAD_ATTACHMENT, "canUploadAttachment"),
        (Capability::CAN_DOWNLOAD_IMAGE, "canDownloadImage"),
        (Capability::CAN_DOWNLOAD_AUDIO, "canDownloadAudio"),
        (Capability::CAN_DOWNLOAD_VIDEO, "canDownloadVideo"),
        (Capability::CAN_DOWNLOAD_ATTACHMENT, "canDownloadAttachment"),
        (Capability::CAN_SEND_LINK, "canSendLink"),
        (Capability::CAN_SEND_LINK_PREVIEW, "canSendLinkPreview"),
        (Capability::CAN_FOLLOW_LINK, "canFollowLink"),
        (Capability::CAN_COPY_LINK, "canCopyLink"),
        (Capability::CAN_CHANGE_ROOM_NAME, "canChangeRoomName"),
        (
            Capability::CAN_CHANGE_ROOM_DESCRIPTION,
            "canChangeRoomDescription",
        ),
        (Capability::CAN_CHANGE_ROOM_AVATAR, "canChangeRoomAvatar"),
        (Capability::CAN_CHANGE_ROOM_SUBJECT, "canChangeRoomSubject"),
        (Capability::CAN_CHANGE_ROOM_MOOD, "canChangeRoomMood"),
        (Capability::CAN_CHANGE_OWN_NAME, "canChangeOwnName"),
        (Capability::CAN_CHANGE_OWN_PRESENCE, "canChangeOwnPresence"),
        (Capability::CAN_CHANGE_OWN_MOOD, "canChangeOwnMood"),
        (Capability::CAN_CHANGE_OWN_AVATAR, "canChangeOwnAvatar"),
        (Capability::CAN_START_CALL, "canStartCall"),
        (Capability::CAN_JOIN_CALL, "canJoinCall"),
        (Capability::CAN_SEND_AUDIO, "canSendAudio"),
        (Capability::CAN_RECEIVE_AUDIO, "canReceiveAudio"),
        (Capability::CAN_SEND_VIDEO, "canSendVideo"),
        (Capability::CAN_RECEIVE_VIDEO, "canReceiveVideo"),
        (Capability::CAN_SHARE_SCREEN, "canShareScreen"),
        (Capability::CAN_VIEW_SHARED_SCREEN, "canViewSharedScreen"),
        (Capability::CAN_CREATE_ROOM, "canCreateRoom"),
        (Capability::CAN_DESTROY_ROOM, "canDestroyRoom"),
        (
            Capability::CAN_CHANGE_ROOM_MEMBERSHIP_STYLE,
            "canChangeRoomMembershipStyle",
        ),
        (
            Capability::CAN_CHANGE_ROLE_DEFINITIONS,
            "canChangeRoleDefinitions",
        ),
        (
            Capability::CAN_CHANGE_PREAUTHORIZED_USER_LIST,
            "canChangePreauthorizedUserList",
        ),
        (
            Capability::CAN_CHANGE_OTHER_POLICY_ATTRIBUTE,
            "canChangeOtherPolicyAttribute",
        ),
        (
            Capability::CAN_CHANGE_MLS_OPERATIONAL_POLICIES,
            "canChangeMlsOperationalPolicies",
        ),
        (
            Capability::CAN_SEND_MLS_REINIT_PROPOSAL,
            "canSendMLSReinitProposal",
        ),
        (
            Capability::CAN_SEND_MLS_UPDATE_PROPOSAL,
            "canSendMLSUpdateProposal",
        ),
        (
            Capability::CAN_SEND_MLS_PSK_PROPOSAL,
            "canSendMLSPSKProposal",
        ),
        (
            Capability::CAN_SEND_MLS_EXTERNAL_PROPOSAL,
            "canSendMLSExternalProposal",
        ),
        (
            Capability::CAN_SEND_MLS_EXTERNAL_COMMIT,
            "canSendMLSExternalCommit",
        ),
    ];
    assert_eq!(constants.len(), TABLE_1.len(), "one constant per row");
    for (constant, bare_name) in constants {
        assert_eq!(constant.0, table_value(bare_name), "{bare_name}");
    }
}

#[test]
fn private_use_range_boundaries() {
    // §10.2: "Assignments in the range 0xF000 to 0xFFFF are for private use."
    assert!(!Capability(0x0000).is_private_use());
    assert!(!Capability(0xEFFF).is_private_use());
    assert!(Capability(0xF000).is_private_use());
    assert!(Capability(0xFFFF).is_private_use());
}

/// Decodes `fixture`, checks it equals `expected`, and re-encodes it
/// byte-identically.
fn check_fixture<T>(fixture: &[u8], expected: &T)
where
    T: Deserialize + Serialize + PartialEq + std::fmt::Debug,
{
    let decoded = T::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

#[test]
fn single_capability_fixtures() {
    check_fixture(&[0x00, 0x00], &Capability::CAN_ADD_PARTICIPANT); // uint16 0x0000
    check_fixture(&[0x01, 0x00], &Capability::CAN_SEND_MESSAGE); // uint16 0x0100, big-endian
    check_fixture(&[0x06, 0x05], &Capability::CAN_SEND_MLS_EXTERNAL_COMMIT); // uint16 0x0605
}

#[test]
fn role_capabilities_fixture_with_unknown_and_private_use_values() {
    let fixture = [
        0x0E, // role_capabilities<V> length: 14 bytes = 7 entries (1-byte varint)
        0x00, 0x00, // 0x0000 canAddParticipant
        0x00, 0x0B, // 0x000b canUnBan
        0x01, 0x00, // 0x0100 canSendMessage
        0x00, 0x12, // 0x0012 unassigned, right after canCreateSubgroup
        0xEF, 0xFF, // 0xefff unassigned, last Specification Required value
        0xF0, 0x00, // 0xf000 first private-use value
        0xFF, 0xFF, // 0xffff last private-use value
    ];
    let expected = vec![
        Capability::CAN_ADD_PARTICIPANT,
        Capability::CAN_UN_BAN,
        Capability::CAN_SEND_MESSAGE,
        Capability(0x0012),
        Capability(0xEFFF),
        Capability(0xF000),
        Capability(0xFFFF),
    ];
    check_fixture(&fixture, &expected);
    for unregistered in &expected[3..] {
        assert_eq!(unregistered.name(), None);
    }
}

#[test]
fn empty_role_capabilities_fixture() {
    // §8: a role's capability list "in rare cases could be empty".
    check_fixture(&[0x00], &Vec::<Capability>::new()); // length: 0
}

#[test]
fn capability_rejects_short_and_trailing_input() {
    assert_eq!(
        Capability::tls_deserialize_exact([]),
        Err(Error::EndOfStream)
    );
    assert_eq!(
        Capability::tls_deserialize_exact([0x01]),
        Err(Error::EndOfStream)
    );
    assert_eq!(
        Capability::tls_deserialize_exact([0x01, 0x00, 0x00]),
        Err(Error::TrailingData)
    );
}

#[test]
fn role_capabilities_rejects_partial_entry() {
    // Length 3 cannot hold a whole number of uint16 entries.
    let wire = [
        0x03, // length: 3
        0x01, 0x00, // 0x0100
        0x02, // half an entry
    ];
    assert!(Vec::<Capability>::tls_deserialize_exact(wire).is_err());
    // The same, with a byte after the vector that the last entry could
    // borrow to overrun the declared length.
    let overrun = [
        0x03, // length: 3
        0x01, 0x00, // 0x0100
        0x02, 0x00, // last byte of the vector, then one byte past it
    ];
    assert!(Vec::<Capability>::tls_deserialize_exact(overrun).is_err());
}

#[test]
fn role_capabilities_rejects_non_minimal_length() {
    let wire = [
        0x40, 0x02, // length: 2, as a non-minimal 2-byte varint
        0x01, 0x00, // 0x0100
    ];
    assert!(Vec::<Capability>::tls_deserialize_exact(wire).is_err());
}
