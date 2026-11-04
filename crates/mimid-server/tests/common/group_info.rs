//! Helpers for the groupInfo tests: requesters with their own signature and
//! HPKE keys, protocol-07 §5.6 requests, and an independent check of the
//! hub's response with mls-rs's suite-1 crypto, plus rooms whose policy
//! allows open join or preauthorization.

use mimi_mls::label::SignatureKeyPair;
use mimi_mls::member::{ExternalSender as MemberExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::{CipherSuite, Credential, HPKEPublicKey, SignaturePublicKey};
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{GroupInfoRatchetTreeTbe, GroupInfoRequestTbs, GroupInfoResponse, Protocol};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, PREAUTH_LIST, ROLES_LIST};
use mimi_room_policy::{Capability, PreAuthData, PreAuthRoleEntry, Role, RoleData};
use mimid_server::hub::Hub;
use mls_rs::crypto::{HpkeCiphertext, HpkePublicKey, HpkeSecretKey};
use mls_rs::mls_rs_codec::MlsDecode;
use mls_rs::{CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use crate::common::{
    ALICE, APP_COMPONENTS, BOB, FRANK_AAD_ONLY, HUB_IDENTITY, ROOM_APP_COMPONENTS, SAFE_AAD,
    base_room_policy, franking_agent, no_components,
};
use crate::update::{ROLE_MEMBER, members_list};

/// RFC 9420 §6: the MLSMessage header of a GroupInfo (mls10, 0x0004).
pub const GROUP_INFO_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];

/// RFC 9420 §5.1.2 SignWithLabel and §5.1.3 EncryptWithLabel prefix every
/// label with this.
const MLS_LABEL_PREFIX: &[u8] = b"MLS 1.0 ";

fn suite() -> impl CipherSuiteProvider {
    RustCryptoProvider::default()
        .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_AES128)
        .unwrap()
}

/// `opaque<V>` (RFC 9420 §2.1.2).
fn vl(bytes: &[u8]) -> Vec<u8> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

/// A client asking for a GroupInfo: a BasicCredential identity, an Ed25519
/// signature key pair (mimi-mls) and an X25519 HPKE key pair (mls-rs).
pub struct Requester {
    pub identity: Vec<u8>,
    pub signing: SignatureKeyPair,
    pub hpke_secret: HpkeSecretKey,
    pub hpke_public: HpkePublicKey,
}

impl Requester {
    pub fn new(identity: &[u8]) -> Self {
        let (hpke_secret, hpke_public) = suite().kem_generate().unwrap();
        Self {
            identity: identity.to_vec(),
            signing: SignatureKeyPair::generate().unwrap(),
            hpke_secret,
            hpke_public,
        }
    }

    /// The TBS of a request, unsigned.
    pub fn tbs(&self, joining_code: Option<&[u8]>) -> GroupInfoRequestTbs {
        // RFC 9420 §5.3: CredentialType basic (0x0001), opaque identity<V>.
        let credential = [&[0x00, 0x01][..], &vl(&self.identity)].concat();
        GroupInfoRequestTbs {
            protocol: Protocol::Mls10,
            cipher_suite: CipherSuite::from(0x0001),
            requesting_signature_key: SignaturePublicKey::tls_deserialize_exact(vl(self
                .signing
                .verification_key()))
            .unwrap(),
            requesting_credential: Credential::tls_deserialize_exact(credential).unwrap(),
            group_info_public_key: HPKEPublicKey::tls_deserialize_exact(vl(&self.hpke_public))
                .unwrap(),
            joining_code: joining_code.map(<[u8]>::to_vec),
        }
    }

    /// A TLS-encoded `GroupInfoRequest` (protocol-07 §5.6), signed with
    /// this requester's key.
    pub fn request(&self, joining_code: Option<&[u8]>) -> Vec<u8> {
        self.tbs(joining_code)
            .sign(self.signing.signature_key())
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }
}

/// The hub's `ExternalSender` (RFC 9420 §12.1.8.1), hand-encoded: its
/// Ed25519 key and a BasicCredential for `mimi://a.example` (decision
/// mimid-1wgh.6.35).
pub fn expected_hub_sender(hub: &Hub) -> Vec<u8> {
    [
        &[0x20][..],                // signature_key<V>: 32 bytes
        hub.signature_public_key(), // the key
        &[0x00, 0x01],              // credential_type: basic
        &[0x10],                    // identity<V>: 16 bytes
        HUB_IDENTITY,
    ]
    .concat()
}

/// Checks a `success` response to `requester` for `room_id` independently
/// of mimi-protocol's crypto, and returns the decrypted payload:
///
/// - the wire layout is TBS || `signature<V>` with a 64-byte Ed25519
///   signature, and the TBS is `version` mls10, `room_id`, `status`
///   success, `cipher_suite` 1, `hub_sender`, then the ciphertext;
/// - `hub_sender` is the hub (hand-encoded);
/// - mls-rs verifies the signature with the hub's key over
///   `SignContent` (RFC 9420 §5.1.2) with label `GroupInfoResponseTBS`;
/// - mls-rs opens the HPKE ciphertext with `EncryptContext` (RFC 9420
///   §5.1.3) for label `GroupInfo and ratchet_tree encryption` and the raw
///   room ID as context (decision mimid-1wgh.5.30).
///
/// mimi-protocol's own `GroupInfoSuccess::verify` is also required to
/// pass.
pub fn open(
    hub: &Hub,
    room_id: &str,
    requester: &Requester,
    response: &[u8],
) -> GroupInfoRatchetTreeTbe {
    let (tbs, signature) = response.split_at(response.len() - 66);
    assert_eq!(&signature[..2], [0x40, 0x40], "signature<V>: 64 bytes");
    let signature = &signature[2..];

    let mut rest = tbs;
    assert_eq!(rest[0], 0x01, "protocol: mls10");
    rest = &rest[1..];
    let room = VLBytes::tls_deserialize(&mut rest).unwrap();
    assert_eq!(room.as_slice(), room_id.as_bytes());
    assert_eq!(
        &rest[..3],
        [0x01, 0x00, 0x01],
        "status success, cipher_suite 1"
    );
    rest = &rest[3..];
    let sender = expected_hub_sender(hub);
    assert_eq!(&rest[..sender.len()], sender.as_slice(), "hub_sender");
    rest = &rest[sender.len()..];
    let ciphertext = HpkeCiphertext::mls_decode(&mut &*rest).unwrap();

    let suite = suite();
    let sign_content = [
        vl(&[MLS_LABEL_PREFIX, b"GroupInfoResponseTBS"].concat()),
        vl(tbs),
    ]
    .concat();
    suite
        .verify(
            &hub.signature_public_key().to_vec().into(),
            signature,
            &sign_content,
        )
        .unwrap();
    let info = [
        vl(&[MLS_LABEL_PREFIX, b"GroupInfo and ratchet_tree encryption"].concat()),
        vl(room_id.as_bytes()),
    ]
    .concat();
    let plaintext = suite
        .hpke_open(
            &ciphertext,
            &requester.hpke_secret,
            &requester.hpke_public,
            &info,
            None,
        )
        .unwrap();

    let GroupInfoResponse::Success(success) =
        GroupInfoResponse::tls_deserialize_exact(response).unwrap()
    else {
        panic!("not a success response");
    };
    success.verify().unwrap();
    GroupInfoRatchetTreeTbe::tls_deserialize_exact(plaintext.as_slice()).unwrap()
}

/// Asserts that `response` is exactly `notAuthorized` for `room_id`,
/// hand-encoded: version mls10, room_id<V>, status 2.
pub fn assert_not_authorized(room_id: &str, response: &[u8]) {
    let expected = [&[0x01][..], &vl(room_id.as_bytes()), &[0x02]].concat();
    assert_eq!(response, expected.as_slice());
}

/// A role with only the listed capabilities and no constraints.
fn role(
    role_index: u32,
    role_name: &str,
    role_capabilities: Vec<Capability>,
    changes: Vec<mimi_room_policy::SingleSourceRoleChangeTargets>,
) -> Role {
    Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: String::new(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes: changes,
    }
}

/// How an unlisted user may join a room.
#[derive(Clone, Copy)]
pub enum Join {
    /// Role 0 holds `canOpenJoin` to role 2 (room-policy-04 §8.1.1).
    Open,
    /// A `preauth_list` entry with an empty claimset preauthorizes role 2,
    /// which holds `canJoinIfPreauthorized` (room-policy-04 §4, §8.1.1;
    /// decision mimid-1wgh.3.47).
    Preauthorized,
}

/// alice (a mimi-mls Member) creates a room listing alice and bob as
/// [`ROLE_MEMBER`], whose policy lets unlisted users join as `join` says,
/// adds bob, and hosts it on `hub` as `room_id`.
pub async fn joinable_room(hub: &Hub, room_id: &str, group_id: &[u8], join: Join) {
    let member_capabilities = |extra: &[Capability]| {
        let mut capabilities = vec![
            Capability::CAN_ADD_PARTICIPANT,
            Capability::CAN_ADD_OWN_CLIENT,
            Capability::CAN_SEND_MESSAGE,
        ];
        capabilities.extend_from_slice(extra);
        capabilities
    };
    let to_member = |from_role_index| mimi_room_policy::SingleSourceRoleChangeTargets {
        from_role_index,
        target_role_indexes: vec![ROLE_MEMBER],
    };
    let mut roles = vec![role(1, "banned", vec![], vec![])];
    let mut preauth = None;
    match join {
        Join::Open => {
            roles.insert(
                0,
                role(
                    0,
                    "no_role",
                    vec![Capability::CAN_OPEN_JOIN],
                    vec![to_member(0)],
                ),
            );
            roles.push(role(
                ROLE_MEMBER,
                "member",
                member_capabilities(&[]),
                vec![to_member(0)],
            ));
        }
        Join::Preauthorized => {
            let member = role(
                ROLE_MEMBER,
                "member",
                member_capabilities(&[Capability::CAN_JOIN_IF_PREAUTHORIZED]),
                vec![to_member(0)],
            );
            preauth = Some(
                PreAuthData {
                    preauthorized_entries: vec![PreAuthRoleEntry {
                        claimset: vec![],
                        target_role: member.clone(),
                    }],
                }
                .tls_serialize_detached()
                .unwrap(),
            );
            roles.push(member);
        }
    }
    let key = *hub.signature_public_key();
    let mut components = vec![
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        // The hub requires frank_aad as a Safe AAD component (bead
        // mimid-1wgh.6.74).
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        (
            PARTICIPANT_LIST,
            members_list(&[ALICE, BOB])
                .tls_serialize_detached()
                .unwrap(),
        ),
        (
            ROLES_LIST,
            RoleData { roles }.tls_serialize_detached().unwrap(),
        ),
        (BASE_ROOM_POLICY, base_room_policy()),
    ];
    if let Some(preauth) = preauth {
        components.push((PREAUTH_LIST, preauth));
    }
    components.sort_by_key(|(component_id, _)| *component_id);

    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders = [MemberExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let mut group = Member::create(&alice, group_id, &senders, &components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    group.merge_pending_commit(&alice).unwrap();
    hub.create_room(
        room_id,
        ALICE,
        &bundle.group_info,
        &group.ratchet_tree().unwrap(),
    )
    .await
    .unwrap();
}
