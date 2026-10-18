//! The MIMI Role Capabilities registry of room-policy-04 §10.2.

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// `uint16 CapabilityType` of room-policy-04 §3 and Appendix B: a value
/// from the MIMI Role Capabilities registry (§10.2, Table 1).
///
/// Every `uint16` decodes, including values Table 1 does not assign and the
/// private-use range, and encodes back unchanged. Use [`Capability::name`]
/// to tell registered values apart.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, TlsSize, TlsSerialize, TlsDeserialize,
)]
pub struct Capability(pub u16);

impl Capability {
    /// `canAddParticipant` (§8.1.1).
    pub const CAN_ADD_PARTICIPANT: Self = Self(0x0000);
    /// `canRemoveParticipant` (§8.1.2).
    pub const CAN_REMOVE_PARTICIPANT: Self = Self(0x0001);
    /// `canAddOwnClient` (§8.1.1).
    pub const CAN_ADD_OWN_CLIENT: Self = Self(0x0002);
    /// `canRemoveOwnClient` (§8.1.2).
    pub const CAN_REMOVE_OWN_CLIENT: Self = Self(0x0003);
    /// `canOpenJoin` (§8.1.1).
    pub const CAN_OPEN_JOIN: Self = Self(0x0004);
    /// `canJoinIfPreauthorized` (§8.1.1).
    pub const CAN_JOIN_IF_PREAUTHORIZED: Self = Self(0x0005);
    /// `canRemoveSelf` (§8.1.2).
    pub const CAN_REMOVE_SELF: Self = Self(0x0006);
    /// `canCreateJoinCode`, reserved (§8.7).
    pub const CAN_CREATE_JOIN_CODE: Self = Self(0x0007);
    /// `canDeleteJoinCode`, reserved (§8.7).
    pub const CAN_DELETE_JOIN_CODE: Self = Self(0x0008);
    /// `canUseJoinCode` (§8.1.1).
    pub const CAN_USE_JOIN_CODE: Self = Self(0x0009);
    /// `canBan` (§8.1.3).
    pub const CAN_BAN: Self = Self(0x000a);
    /// `canUnBan` in Table 1, `canUnban` in §8.1.3; the value is decision
    /// mimid-1wgh.3.23 and the spelling follows Table 1 (decision
    /// mimid-1wgh.3.36).
    pub const CAN_UN_BAN: Self = Self(0x000b);
    /// `canKick` (§8.1.2).
    pub const CAN_KICK: Self = Self(0x000c);
    /// `canKnock`, reserved (§8.7).
    pub const CAN_KNOCK: Self = Self(0x000d);
    /// `canAcceptKnock`, reserved (§8.7).
    pub const CAN_ACCEPT_KNOCK: Self = Self(0x000e);
    /// `canChangeUserRole` (§8.1.3).
    pub const CAN_CHANGE_USER_ROLE: Self = Self(0x000f);
    /// `canChangeOwnRole` (§8.1.3).
    pub const CAN_CHANGE_OWN_ROLE: Self = Self(0x0010);
    /// `canCreateSubgroup`, reserved (§8.7).
    pub const CAN_CREATE_SUBGROUP: Self = Self(0x0011);

    /// `canSendMessage` (§8.3).
    pub const CAN_SEND_MESSAGE: Self = Self(0x0100);
    /// `canReceiveMessage` (§8.3).
    pub const CAN_RECEIVE_MESSAGE: Self = Self(0x0101);
    /// `canCopyMessage` (§8.3).
    pub const CAN_COPY_MESSAGE: Self = Self(0x0102);
    /// `canReportAbuse` (§8.3).
    pub const CAN_REPORT_ABUSE: Self = Self(0x0103);
    /// `canReplyToMessage` (§8.3).
    pub const CAN_REPLY_TO_MESSAGE: Self = Self(0x0104);
    /// `canReactToMessage` (§8.3).
    pub const CAN_REACT_TO_MESSAGE: Self = Self(0x0105);
    /// `canEditReaction` (§8.3).
    pub const CAN_EDIT_REACTION: Self = Self(0x0106);
    /// `canDeleteOwnReaction` (§8.3).
    pub const CAN_DELETE_OWN_REACTION: Self = Self(0x0107);
    /// `canDeleteOtherReaction` (§8.3).
    pub const CAN_DELETE_OTHER_REACTION: Self = Self(0x0108);
    /// `canEditOwnMessage` (§8.3).
    pub const CAN_EDIT_OWN_MESSAGE: Self = Self(0x0109);
    /// `canDeleteOwnMessage` (§8.3).
    pub const CAN_DELETE_OWN_MESSAGE: Self = Self(0x010a);
    /// `canDeleteOtherMessage` (§8.3).
    pub const CAN_DELETE_OTHER_MESSAGE: Self = Self(0x010b);
    /// `canStartTopic` (§8.3).
    pub const CAN_START_TOPIC: Self = Self(0x010c);
    /// `canReplyInTopic` (§8.3).
    pub const CAN_REPLY_IN_TOPIC: Self = Self(0x010d);
    /// `canEditOwnTopic` (§8.3).
    pub const CAN_EDIT_OWN_TOPIC: Self = Self(0x010e);
    /// `canEditOtherTopic` (§8.3).
    pub const CAN_EDIT_OTHER_TOPIC: Self = Self(0x010f);
    /// `canSendDirectMessage`, reserved (§8.7).
    pub const CAN_SEND_DIRECT_MESSAGE: Self = Self(0x0110);
    /// `canTargetMessage`, reserved (§8.7).
    pub const CAN_TARGET_MESSAGE: Self = Self(0x0111);

    /// `canUploadImage` (§8.4).
    pub const CAN_UPLOAD_IMAGE: Self = Self(0x0200);
    /// `canUploadAudio` (§8.4).
    pub const CAN_UPLOAD_AUDIO: Self = Self(0x0201);
    /// `canUploadVideo` (§8.4).
    pub const CAN_UPLOAD_VIDEO: Self = Self(0x0202);
    /// `canUploadAttachment` (§8.4).
    pub const CAN_UPLOAD_ATTACHMENT: Self = Self(0x0203);
    /// `canDownloadImage` (§8.4).
    pub const CAN_DOWNLOAD_IMAGE: Self = Self(0x0204);
    /// `canDownloadAudio` (§8.4).
    pub const CAN_DOWNLOAD_AUDIO: Self = Self(0x0205);
    /// `canDownloadVideo` (§8.4).
    pub const CAN_DOWNLOAD_VIDEO: Self = Self(0x0206);
    /// `canDownloadAttachment` (§8.4).
    pub const CAN_DOWNLOAD_ATTACHMENT: Self = Self(0x0207);
    /// `canSendLink` (§8.3).
    pub const CAN_SEND_LINK: Self = Self(0x0208);
    /// `canSendLinkPreview` (§8.3).
    pub const CAN_SEND_LINK_PREVIEW: Self = Self(0x0209);
    /// `canFollowLink` (§8.3).
    pub const CAN_FOLLOW_LINK: Self = Self(0x020a);
    /// `canCopyLink` (§8.3).
    pub const CAN_COPY_LINK: Self = Self(0x020b);

    /// `canChangeRoomName` (§8.2).
    pub const CAN_CHANGE_ROOM_NAME: Self = Self(0x0300);
    /// `canChangeRoomDescription` (§8.2).
    pub const CAN_CHANGE_ROOM_DESCRIPTION: Self = Self(0x0301);
    /// `canChangeRoomAvatar` (§8.2).
    pub const CAN_CHANGE_ROOM_AVATAR: Self = Self(0x0302);
    /// `canChangeRoomSubject` (§8.2).
    pub const CAN_CHANGE_ROOM_SUBJECT: Self = Self(0x0303);
    /// `canChangeRoomMood` (§8.2).
    pub const CAN_CHANGE_ROOM_MOOD: Self = Self(0x0304);
    /// `canChangeOwnName`, reserved (§8.7).
    pub const CAN_CHANGE_OWN_NAME: Self = Self(0x0380);
    /// `canChangeOwnPresence`, reserved (§8.7).
    pub const CAN_CHANGE_OWN_PRESENCE: Self = Self(0x0381);
    /// `canChangeOwnMood`, reserved (§8.7).
    pub const CAN_CHANGE_OWN_MOOD: Self = Self(0x0382);
    /// `canChangeOwnAvatar`, reserved (§8.7).
    pub const CAN_CHANGE_OWN_AVATAR: Self = Self(0x0383);

    /// `canStartCall` (§8.5).
    pub const CAN_START_CALL: Self = Self(0x0400);
    /// `canJoinCall` (§8.5).
    pub const CAN_JOIN_CALL: Self = Self(0x0401);
    /// `canSendAudio` (§8.5).
    pub const CAN_SEND_AUDIO: Self = Self(0x0402);
    /// `canReceiveAudio` (§8.5).
    pub const CAN_RECEIVE_AUDIO: Self = Self(0x0403);
    /// `canSendVideo` (§8.5).
    pub const CAN_SEND_VIDEO: Self = Self(0x0404);
    /// `canReceiveVideo` (§8.5).
    pub const CAN_RECEIVE_VIDEO: Self = Self(0x0405);
    /// `canShareScreen` (§8.5).
    pub const CAN_SHARE_SCREEN: Self = Self(0x0406);
    /// `canViewSharedScreen` (§8.5).
    pub const CAN_VIEW_SHARED_SCREEN: Self = Self(0x0407);

    /// `canCreateRoom`, reserved (§8.7).
    pub const CAN_CREATE_ROOM: Self = Self(0x0500);
    /// `canDestroyRoom` (§8.6).
    pub const CAN_DESTROY_ROOM: Self = Self(0x0501);
    /// `canChangeRoomMembershipStyle` (§8.6).
    pub const CAN_CHANGE_ROOM_MEMBERSHIP_STYLE: Self = Self(0x0502);
    /// `canChangeRoleDefinitions` (§8.6).
    pub const CAN_CHANGE_ROLE_DEFINITIONS: Self = Self(0x0503);
    /// `canChangePreauthorizedUserList` (§8.6).
    pub const CAN_CHANGE_PREAUTHORIZED_USER_LIST: Self = Self(0x0504);
    /// `canChangeOtherPolicyAttribute`, reserved (§8.7).
    pub const CAN_CHANGE_OTHER_POLICY_ATTRIBUTE: Self = Self(0x0505);

    /// `canChangeMlsOperationalPolicies`, reserved (§8.7).
    pub const CAN_CHANGE_MLS_OPERATIONAL_POLICIES: Self = Self(0x0600);
    /// `canSendMLSReinitProposal` (§8.6).
    pub const CAN_SEND_MLS_REINIT_PROPOSAL: Self = Self(0x0601);
    /// `canSendMLSUpdateProposal`, reserved (§8.7).
    pub const CAN_SEND_MLS_UPDATE_PROPOSAL: Self = Self(0x0602);
    /// `canSendMLSPSKProposal`, reserved (§8.7).
    pub const CAN_SEND_MLS_PSK_PROPOSAL: Self = Self(0x0603);
    /// `canSendMLSExternalProposal`, reserved (§8.7).
    pub const CAN_SEND_MLS_EXTERNAL_PROPOSAL: Self = Self(0x0604);
    /// `canSendMLSExternalCommit`, reserved (§8.7).
    pub const CAN_SEND_MLS_EXTERNAL_COMMIT: Self = Self(0x0605);

    /// The registered name of this value in Table 1, or `None` if Table 1
    /// does not assign it.
    ///
    /// Reserved entries return the bare name: Table 1's `(reserved)` suffix
    /// marks status, and §8.7 lists the same names without it
    /// (room-policy-04 §10.2; decision mimid-1wgh.3.35).
    pub fn name(self) -> Option<&'static str> {
        let name = match self {
            Self::CAN_ADD_PARTICIPANT => "canAddParticipant",
            Self::CAN_REMOVE_PARTICIPANT => "canRemoveParticipant",
            Self::CAN_ADD_OWN_CLIENT => "canAddOwnClient",
            Self::CAN_REMOVE_OWN_CLIENT => "canRemoveOwnClient",
            Self::CAN_OPEN_JOIN => "canOpenJoin",
            Self::CAN_JOIN_IF_PREAUTHORIZED => "canJoinIfPreauthorized",
            Self::CAN_REMOVE_SELF => "canRemoveSelf",
            Self::CAN_CREATE_JOIN_CODE => "canCreateJoinCode",
            Self::CAN_DELETE_JOIN_CODE => "canDeleteJoinCode",
            Self::CAN_USE_JOIN_CODE => "canUseJoinCode",
            Self::CAN_BAN => "canBan",
            Self::CAN_UN_BAN => "canUnBan",
            Self::CAN_KICK => "canKick",
            Self::CAN_KNOCK => "canKnock",
            Self::CAN_ACCEPT_KNOCK => "canAcceptKnock",
            Self::CAN_CHANGE_USER_ROLE => "canChangeUserRole",
            Self::CAN_CHANGE_OWN_ROLE => "canChangeOwnRole",
            Self::CAN_CREATE_SUBGROUP => "canCreateSubgroup",
            Self::CAN_SEND_MESSAGE => "canSendMessage",
            Self::CAN_RECEIVE_MESSAGE => "canReceiveMessage",
            Self::CAN_COPY_MESSAGE => "canCopyMessage",
            Self::CAN_REPORT_ABUSE => "canReportAbuse",
            Self::CAN_REPLY_TO_MESSAGE => "canReplyToMessage",
            Self::CAN_REACT_TO_MESSAGE => "canReactToMessage",
            Self::CAN_EDIT_REACTION => "canEditReaction",
            Self::CAN_DELETE_OWN_REACTION => "canDeleteOwnReaction",
            Self::CAN_DELETE_OTHER_REACTION => "canDeleteOtherReaction",
            Self::CAN_EDIT_OWN_MESSAGE => "canEditOwnMessage",
            Self::CAN_DELETE_OWN_MESSAGE => "canDeleteOwnMessage",
            Self::CAN_DELETE_OTHER_MESSAGE => "canDeleteOtherMessage",
            Self::CAN_START_TOPIC => "canStartTopic",
            Self::CAN_REPLY_IN_TOPIC => "canReplyInTopic",
            Self::CAN_EDIT_OWN_TOPIC => "canEditOwnTopic",
            Self::CAN_EDIT_OTHER_TOPIC => "canEditOtherTopic",
            Self::CAN_SEND_DIRECT_MESSAGE => "canSendDirectMessage",
            Self::CAN_TARGET_MESSAGE => "canTargetMessage",
            Self::CAN_UPLOAD_IMAGE => "canUploadImage",
            Self::CAN_UPLOAD_AUDIO => "canUploadAudio",
            Self::CAN_UPLOAD_VIDEO => "canUploadVideo",
            Self::CAN_UPLOAD_ATTACHMENT => "canUploadAttachment",
            Self::CAN_DOWNLOAD_IMAGE => "canDownloadImage",
            Self::CAN_DOWNLOAD_AUDIO => "canDownloadAudio",
            Self::CAN_DOWNLOAD_VIDEO => "canDownloadVideo",
            Self::CAN_DOWNLOAD_ATTACHMENT => "canDownloadAttachment",
            Self::CAN_SEND_LINK => "canSendLink",
            Self::CAN_SEND_LINK_PREVIEW => "canSendLinkPreview",
            Self::CAN_FOLLOW_LINK => "canFollowLink",
            Self::CAN_COPY_LINK => "canCopyLink",
            Self::CAN_CHANGE_ROOM_NAME => "canChangeRoomName",
            Self::CAN_CHANGE_ROOM_DESCRIPTION => "canChangeRoomDescription",
            Self::CAN_CHANGE_ROOM_AVATAR => "canChangeRoomAvatar",
            Self::CAN_CHANGE_ROOM_SUBJECT => "canChangeRoomSubject",
            Self::CAN_CHANGE_ROOM_MOOD => "canChangeRoomMood",
            Self::CAN_CHANGE_OWN_NAME => "canChangeOwnName",
            Self::CAN_CHANGE_OWN_PRESENCE => "canChangeOwnPresence",
            Self::CAN_CHANGE_OWN_MOOD => "canChangeOwnMood",
            Self::CAN_CHANGE_OWN_AVATAR => "canChangeOwnAvatar",
            Self::CAN_START_CALL => "canStartCall",
            Self::CAN_JOIN_CALL => "canJoinCall",
            Self::CAN_SEND_AUDIO => "canSendAudio",
            Self::CAN_RECEIVE_AUDIO => "canReceiveAudio",
            Self::CAN_SEND_VIDEO => "canSendVideo",
            Self::CAN_RECEIVE_VIDEO => "canReceiveVideo",
            Self::CAN_SHARE_SCREEN => "canShareScreen",
            Self::CAN_VIEW_SHARED_SCREEN => "canViewSharedScreen",
            Self::CAN_CREATE_ROOM => "canCreateRoom",
            Self::CAN_DESTROY_ROOM => "canDestroyRoom",
            Self::CAN_CHANGE_ROOM_MEMBERSHIP_STYLE => "canChangeRoomMembershipStyle",
            Self::CAN_CHANGE_ROLE_DEFINITIONS => "canChangeRoleDefinitions",
            Self::CAN_CHANGE_PREAUTHORIZED_USER_LIST => "canChangePreauthorizedUserList",
            Self::CAN_CHANGE_OTHER_POLICY_ATTRIBUTE => "canChangeOtherPolicyAttribute",
            Self::CAN_CHANGE_MLS_OPERATIONAL_POLICIES => "canChangeMlsOperationalPolicies",
            Self::CAN_SEND_MLS_REINIT_PROPOSAL => "canSendMLSReinitProposal",
            Self::CAN_SEND_MLS_UPDATE_PROPOSAL => "canSendMLSUpdateProposal",
            Self::CAN_SEND_MLS_PSK_PROPOSAL => "canSendMLSPSKProposal",
            Self::CAN_SEND_MLS_EXTERNAL_PROPOSAL => "canSendMLSExternalProposal",
            Self::CAN_SEND_MLS_EXTERNAL_COMMIT => "canSendMLSExternalCommit",
            _ => return None,
        };
        Some(name)
    }

    /// Whether this value is in the §10.2 private-use range, 0xF000 to
    /// 0xFFFF inclusive.
    // room-policy-04 §10.2 gives both ranges as including 0xF000; this
    // follows the private-use statement. room-policy-04 §10.2; decision
    // mimid-1wgh.3.34 (reported to the WG as mimid-1wgh.3.37).
    pub fn is_private_use(self) -> bool {
        self.0 >= 0xF000
    }
}
