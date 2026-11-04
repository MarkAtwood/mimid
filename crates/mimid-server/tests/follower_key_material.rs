//! KeyPackage upload and the target-provider side of protocol-07 §5.2
//! keyMaterial (bead mimid-1wgh.7.22), and the hub serving users of its own
//! provider in-process (decision mimid-1wgh.7.11).
//!
//! The oracle is mls-rs: it builds every KeyPackage and computes the
//! KeyPackageRefs the claims are checked against. Responses are decoded
//! with mimi-protocol and their KeyPackages compared byte for byte with the
//! uploads. Refusals are compared with a hand-encoded `noConsent` response.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/key_packages.rs"]
mod key_packages;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::{
    ALICE, APP_COMPONENTS, BOB, FRANK_AAD_ONLY, FixedClock, HUB_IDENTITY, ROOM_APP_COMPONENTS,
    ROOM_ID, SAFE_AAD, franking_agent, no_components,
};
use key_packages::*;
use mimi_mls::KeyPackageKind;
use mimi_mls::member::{ExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{KeyPackageError, MAX_KEY_PACKAGE_LIFETIME_SECONDS};
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{
    ClientKeyMaterial, KeyMaterialResponse, KeyMaterialUserCode, ParticipantListData, UserRolePair,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{Capability, Role, RoleData};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::key_packages::{KeyPackages, UploadError};
use mimid_server::follower::relay::LocalUser;
use mimid_server::follower::{Follower, FollowerError};
use mimid_server::http::router;
use mimid_server::hub::Hub;
use mimid_server::store::{KeyPackageInsert, NewKeyPackage, Store};
use tower::ServiceExt;

/// The target user, at this provider (b.example).
const TARGET: &str = "mimi://b.example/u/bob";
/// The requester, at the room's hub provider.
const REQUESTER: &str = "mimi://a.example/u/alice";
/// The room, hosted by a.example.
const ROOM: &str = "mimi://a.example/r/one";

/// A b.example user, as the JMAP layer would authenticate them.
fn local(uri: &str) -> LocalUser {
    LocalUser::authenticated(&domain("b.example"), uri).unwrap()
}

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

/// The `From` of a request sent by the room's hub.
fn hub_domain() -> Domain {
    domain("a.example")
}

/// The hand-encoded `noConsent` response for `user` (protocol-07 §5.2):
/// protocol mls10 (1), userStatus noConsent (5), userUri, empty clients.
fn no_consent(user: &str) -> Vec<u8> {
    [&[0x01, 0x05][..], &opaque(user.as_bytes()), &[0x00]].concat()
}

fn ask() -> Ask<'static> {
    Ask {
        requesting_user: REQUESTER,
        credential_identity: REQUESTER,
        target_user: TARGET,
        room_id: ROOM,
        required_capabilities: NO_REQUIREMENTS,
    }
}

/// A b.example provider's store and KeyPackages, at the real time.
struct Provider {
    _dir: tempfile::TempDir,
    path: PathBuf,
    store: Store,
    key_packages: Arc<KeyPackages>,
}

impl Provider {
    async fn open() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let store = Store::open(&path, &domain("b.example")).await.unwrap();
        let key_packages = Arc::new(KeyPackages::new(
            store.clone(),
            domain("b.example"),
            Arc::new(FixedClock(now_ms())),
        ));
        Self {
            _dir: dir,
            path,
            store,
            key_packages,
        }
    }

    /// The same provider with its clock at `ms`.
    fn at(&self, ms: u64) -> KeyPackages {
        KeyPackages::new(
            self.store.clone(),
            domain("b.example"),
            Arc::new(FixedClock(ms)),
        )
    }

    async fn upload(&self, user: &str, key_package: &[u8]) {
        self.key_packages
            .upload_key_package(&local(user), key_package)
            .await
            .unwrap();
    }

    async fn serve(&self, request: &[u8]) -> Vec<u8> {
        self.key_packages
            .serve_key_material(&hub_domain(), TARGET, request)
            .await
            .unwrap()
    }

    async fn listed(&self) -> BTreeSet<Vec<u8>> {
        self.key_packages
            .list_key_packages(&local(TARGET))
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.reference)
            .collect()
    }

    /// Every `key_package_claim` row's (ref, requester, room_id), read with
    /// a separate connection.
    async fn claims(&self) -> Vec<(Vec<u8>, String, String)> {
        claims_in(&self.path).await
    }
}

async fn claims_in(path: &Path) -> Vec<(Vec<u8>, String, String)> {
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    let rows =
        sqlx::query_as("SELECT ref, requester, room_id FROM key_package_claim ORDER BY rowid")
            .fetch_all(&pool)
            .await
            .unwrap();
    pool.close().await;
    rows
}

fn decode(response: &[u8]) -> KeyMaterialResponse {
    KeyMaterialResponse::tls_deserialize_exact(response).unwrap()
}

/// The KeyPackage bytes of every `success` client, in order.
fn served(response: &KeyMaterialResponse) -> Vec<Vec<u8>> {
    response
        .clients
        .iter()
        .filter_map(|client| match client {
            ClientKeyMaterial::Success { key_package, .. } => Some(key_package.as_bytes().to_vec()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn uploaded_key_packages_are_served_verbatim_once_per_client() {
    let p = Provider::open().await;
    let phone = client(TARGET, 30 * DAY, &[]);
    let laptop = client(TARGET, 30 * DAY, &[]);
    let phone_kps = [key_package(&phone, false), key_package(&phone, false)];
    let laptop_kp = key_package(&laptop, false);
    for kp in phone_kps.iter().chain([&laptop_kp]) {
        p.upload(TARGET, kp).await;
    }

    let first = decode(&p.serve(&request(&ask())).await);
    assert_eq!(first.user_status, KeyMaterialUserCode::Success);
    assert_eq!(first.user_uri.as_str(), TARGET);
    assert_eq!(first.clients.len(), 2);
    let uris: BTreeSet<_> = first
        .clients
        .iter()
        .map(|c| c.client_uri().as_str())
        .collect();
    assert_eq!(uris.len(), 2, "one client URI per signature key");
    assert!(
        uris.iter()
            .all(|uri| uri.starts_with("mimi://b.example/d/"))
    );
    let first_served = served(&first);
    assert!(first_served.contains(&laptop_kp));
    assert!(phone_kps.iter().any(|kp| first_served.contains(kp)));

    let second = decode(&p.serve(&request(&ask())).await);
    assert_eq!(second.user_status, KeyMaterialUserCode::PartialSuccess);
    let second_served = served(&second);
    assert_eq!(second_served.len(), 1);
    assert!(phone_kps.contains(&second_served[0]));
    assert!(!first_served.contains(&second_served[0]), "served twice");
    assert!(
        second
            .clients
            .iter()
            .any(|c| matches!(c, ClientKeyMaterial::KeyMaterialExhausted { .. }))
    );

    let third = decode(&p.serve(&request(&ask())).await);
    assert_eq!(third.user_status, KeyMaterialUserCode::NoCompatibleMaterial);
    assert_eq!(third.clients.len(), 2);
    assert!(
        third
            .clients
            .iter()
            .all(|c| matches!(c, ClientKeyMaterial::KeyMaterialExhausted { .. }))
    );
    assert!(p.listed().await.is_empty());

    // §5.2: every served KeyPackageRef is recorded with the request.
    let claimed: Vec<_> = p.claims().await;
    let expected: Vec<_> = first_served
        .iter()
        .chain(&second_served)
        .map(|kp| (reference(kp), REQUESTER.to_owned(), ROOM.to_owned()))
        .collect();
    assert_eq!(
        claimed.iter().cloned().collect::<BTreeSet<_>>(),
        expected.into_iter().collect::<BTreeSet<_>>()
    );
    assert_eq!(claimed.len(), 3);
}

#[tokio::test]
async fn upload_reports_the_mls_rs_reference_and_lists_it() {
    let p = Provider::open().await;
    let kp = key_package(&client(TARGET, 30 * DAY, &[]), true);
    let entry = p
        .key_packages
        .upload_key_package(&local(TARGET), &kp)
        .await
        .unwrap();
    assert_eq!(entry.reference, reference(&kp));
    assert!(entry.last_resort);
    assert!(entry.client_uri.starts_with("mimi://b.example/d/"));
    assert_eq!(p.listed().await, BTreeSet::from([reference(&kp)]));
    let user = local(TARGET);
    assert!(
        !p.key_packages
            .delete_key_package(&local("mimi://b.example/u/eve"), &entry.reference)
            .await
            .unwrap()
    );
    assert!(
        p.key_packages
            .delete_key_package(&user, &entry.reference)
            .await
            .unwrap()
    );
    assert!(p.listed().await.is_empty());
}

#[tokio::test]
async fn refused_requests_get_no_consent_and_claim_nothing() {
    let p = Provider::open().await;
    p.upload(TARGET, &key_package(&client(TARGET, 30 * DAY, &[]), false))
        .await;
    let before = p.listed().await;

    let cases: Vec<(&str, Vec<u8>, Domain)> = vec![
        (
            "requestingUser is not the credential identity",
            request(&Ask {
                credential_identity: "mimi://a.example/u/mallory",
                ..ask()
            }),
            hub_domain(),
        ),
        (
            "From is not the roomId authority",
            request(&ask()),
            domain("c.example"),
        ),
        (
            "roomId absent",
            request(&Ask {
                room_id: "",
                ..ask()
            }),
            hub_domain(),
        ),
        (
            "targetUser is not the path's",
            request(&Ask {
                target_user: "mimi://b.example/u/eve",
                ..ask()
            }),
            hub_domain(),
        ),
        (
            "signature does not verify",
            {
                let mut body = request(&ask());
                *body.last_mut().unwrap() ^= 0x01;
                body
            },
            hub_domain(),
        ),
    ];
    for (case, body, from) in cases {
        let response = p
            .key_packages
            .serve_key_material(&from, TARGET, &body)
            .await
            .unwrap();
        assert_eq!(response, no_consent(TARGET), "{case}");
    }
    assert_eq!(p.listed().await, before);
    assert!(p.claims().await.is_empty());
}

#[tokio::test]
async fn unknown_and_foreign_users_get_no_consent() {
    let p = Provider::open().await;
    let eve = "mimi://b.example/u/eve";
    let body = request(&Ask {
        target_user: eve,
        ..ask()
    });
    let response = p
        .key_packages
        .serve_key_material(&hub_domain(), eve, &body)
        .await
        .unwrap();
    assert_eq!(response, no_consent(eve));

    let cathy = "mimi://c.example/u/cathy";
    let body = request(&Ask {
        target_user: cathy,
        ..ask()
    });
    let response = p
        .key_packages
        .serve_key_material(&hub_domain(), cathy, &body)
        .await
        .unwrap();
    assert_eq!(response, no_consent(cathy));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_claims_never_serve_a_key_package_twice() {
    const REQUESTS: usize = 16;
    let p = Provider::open().await;
    let phone = client(TARGET, 30 * DAY, &[]);
    let uploaded: BTreeSet<Vec<u8>> = (0..5).map(|_| key_package(&phone, false)).collect();
    for kp in &uploaded {
        p.upload(TARGET, kp).await;
    }
    let tasks: Vec<_> = (0..REQUESTS)
        .map(|_| {
            let key_packages = Arc::clone(&p.key_packages);
            let body = request(&ask());
            tokio::spawn(async move {
                key_packages
                    .serve_key_material(&hub_domain(), TARGET, &body)
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut all_served = Vec::new();
    let mut exhausted = 0;
    for task in tasks {
        let response = decode(&task.await.unwrap());
        match response.user_status {
            KeyMaterialUserCode::Success => all_served.extend(served(&response)),
            KeyMaterialUserCode::NoCompatibleMaterial => {
                assert!(matches!(
                    response.clients[..],
                    [ClientKeyMaterial::KeyMaterialExhausted { .. }]
                ));
                exhausted += 1;
            }
            other => panic!("unexpected userStatus {other:?}"),
        }
    }
    let distinct: BTreeSet<_> = all_served.iter().cloned().collect();
    assert_eq!(
        distinct.len(),
        all_served.len(),
        "a KeyPackage was served twice"
    );
    assert_eq!(distinct, uploaded);
    assert_eq!(exhausted, REQUESTS - uploaded.len());
    assert_eq!(p.claims().await.len(), uploaded.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_claims_fall_back_to_the_last_resort_only_when_one_time_ones_are_gone() {
    const REQUESTS: usize = 12;
    let p = Provider::open().await;
    let phone = client(TARGET, 30 * DAY, &[]);
    let one_time: BTreeSet<Vec<u8>> = (0..3).map(|_| key_package(&phone, false)).collect();
    let last_resort = key_package(&phone, true);
    for kp in one_time.iter().chain([&last_resort]) {
        p.upload(TARGET, kp).await;
    }
    let tasks: Vec<_> = (0..REQUESTS)
        .map(|_| {
            let key_packages = Arc::clone(&p.key_packages);
            let body = request(&ask());
            tokio::spawn(async move {
                key_packages
                    .serve_key_material(&hub_domain(), TARGET, &body)
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut served_one_time = Vec::new();
    let mut served_last_resort = 0;
    for task in tasks {
        let response = decode(&task.await.unwrap());
        assert_eq!(response.user_status, KeyMaterialUserCode::Success);
        for kp in served(&response) {
            if kp == last_resort {
                served_last_resort += 1;
            } else {
                served_one_time.push(kp);
            }
        }
    }
    let distinct: BTreeSet<_> = served_one_time.iter().cloned().collect();
    assert_eq!(
        distinct.len(),
        served_one_time.len(),
        "a KeyPackage was served twice"
    );
    assert_eq!(distinct, one_time);
    assert_eq!(served_last_resort, REQUESTS - one_time.len());
    assert_eq!(p.listed().await, BTreeSet::from([reference(&last_resort)]));
}

#[tokio::test]
async fn last_resort_is_served_after_one_time_ones_and_never_consumed() {
    let p = Provider::open().await;
    let phone = client(TARGET, 30 * DAY, &[]);
    let last_resort = key_package(&phone, true);
    let one_time = key_package(&phone, false);
    // Uploaded first, the last-resort KeyPackage must still wait its turn.
    p.upload(TARGET, &last_resort).await;
    p.upload(TARGET, &one_time).await;

    assert_eq!(
        served(&decode(&p.serve(&request(&ask())).await)),
        [one_time]
    );
    for _ in 0..3 {
        let response = decode(&p.serve(&request(&ask())).await);
        assert_eq!(response.user_status, KeyMaterialUserCode::Success);
        assert_eq!(served(&response), std::slice::from_ref(&last_resort));
    }
    assert_eq!(p.listed().await, BTreeSet::from([reference(&last_resort)]));
    assert_eq!(p.claims().await.len(), 4);
}

#[tokio::test]
async fn expired_key_packages_are_never_served() {
    let p = Provider::open().await;
    let phone = client(TARGET, 30 * DAY, &[]);
    let one_time = key_package(&phone, false);
    let last_resort = key_package(&phone, true);
    p.upload(TARGET, &one_time).await;
    p.upload(TARGET, &last_resort).await;

    // 31 days on, both lifetimes (30 days from a minute ago) have ended.
    let later = p.at(now_ms() + 31 * DAY * 1_000);
    let response = later
        .serve_key_material(&hub_domain(), TARGET, &request(&ask()))
        .await
        .unwrap();
    let response = decode(&response);
    assert_eq!(
        response.user_status,
        KeyMaterialUserCode::NoCompatibleMaterial
    );
    assert!(matches!(
        response.clients[..],
        [ClientKeyMaterial::KeyMaterialExhausted { .. }]
    ));
    assert_eq!(p.listed().await.len(), 2, "expiry does not consume");
    assert!(p.claims().await.is_empty());
}

#[tokio::test]
async fn unsuitable_key_packages_are_nothing_compatible_and_kept() {
    let p = Provider::open().await;
    let plain = key_package(&client(TARGET, 30 * DAY, &[]), false);
    p.upload(TARGET, &plain).await;
    let requiring = Ask {
        required_capabilities: REQUIRE_PRIVATE_EXTENSION,
        ..ask()
    };

    let response = decode(&p.serve(&request(&requiring)).await);
    assert_eq!(
        response.user_status,
        KeyMaterialUserCode::NoCompatibleMaterial
    );
    assert!(matches!(
        response.clients[..],
        [ClientKeyMaterial::NothingCompatible {
            client_capabilities: None,
            ..
        }]
    ));
    assert_eq!(p.listed().await, BTreeSet::from([reference(&plain)]));

    let capable = key_package(&client(TARGET, 30 * DAY, &[PRIVATE_EXTENSION]), false);
    p.upload(TARGET, &capable).await;
    let response = decode(&p.serve(&request(&requiring)).await);
    assert_eq!(response.user_status, KeyMaterialUserCode::PartialSuccess);
    assert_eq!(served(&response), [capable]);
    assert_eq!(p.listed().await, BTreeSet::from([reference(&plain)]));
}

#[tokio::test]
async fn uploads_that_fail_a_check_are_refused() {
    let p = Provider::open().await;
    let user = local(TARGET);
    let upload = |bytes: Vec<u8>| {
        let key_packages = Arc::clone(&p.key_packages);
        let user = user.clone();
        async move { key_packages.upload_key_package(&user, &bytes).await }
    };

    let alices = key_package(&client(REQUESTER, 30 * DAY, &[]), false);
    assert!(matches!(
        upload(alices).await,
        Err(UploadError::IdentityMismatch)
    ));

    let mut tampered = key_package(&client(TARGET, 30 * DAY, &[]), false);
    // RFC 9420 §10: the KeyPackage ends with `opaque signature<V>`.
    *tampered.last_mut().unwrap() ^= 0x01;
    assert!(matches!(
        upload(tampered).await,
        Err(UploadError::Invalid(KeyPackageError::InvalidSignature))
    ));

    let too_long = key_package(
        &client(TARGET, MAX_KEY_PACKAGE_LIFETIME_SECONDS + 1, &[]),
        false,
    );
    assert!(matches!(
        upload(too_long).await,
        Err(UploadError::Invalid(KeyPackageError::LifetimeTooLong))
    ));
    let longest = key_package(
        &client(TARGET, MAX_KEY_PACKAGE_LIFETIME_SECONDS, &[]),
        false,
    );
    upload(longest).await.unwrap();

    let phone = client(TARGET, 30 * DAY, &[]);
    upload(key_package(&phone, true)).await.unwrap();
    assert!(matches!(
        upload(key_package(&phone, true)).await,
        Err(UploadError::SecondLastResort)
    ));
    // Another client may have its own last-resort KeyPackage.
    upload(key_package(&client(TARGET, 30 * DAY, &[]), true))
        .await
        .unwrap();

    let once = key_package(&phone, false);
    upload(once.clone()).await.unwrap();
    assert!(matches!(
        upload(once.clone()).await,
        Err(UploadError::Duplicate)
    ));
    assert!(matches!(
        upload([once.clone(), vec![0x00]].concat()).await,
        Err(UploadError::Undecodable(_))
    ));

    // A served one-time KeyPackage cannot be uploaded again to be served
    // twice.
    let fresh = Provider::open().await;
    fresh.upload(TARGET, &once).await;
    assert_eq!(
        served(&decode(&fresh.serve(&request(&ask())).await)),
        std::slice::from_ref(&once)
    );
    assert!(matches!(
        fresh.key_packages.upload_key_package(&user, &once).await,
        Err(UploadError::Duplicate)
    ));
}

#[tokio::test]
async fn follower_serves_through_its_key_packages() {
    let p = Provider::open().await;
    let kp = key_package(&client(TARGET, 30 * DAY, &[]), false);
    p.upload(TARGET, &kp).await;
    let follower = Follower::new(
        domain("b.example"),
        p.store.clone(),
        Arc::new(FixedClock(now_ms())),
    )
    .with_key_packages(Arc::clone(&p.key_packages));

    let response = follower
        .key_material(TARGET, &hub_domain(), &request(&ask()))
        .await
        .unwrap();
    assert_eq!(served(&decode(&response)), [kp]);

    let mut body = request(&ask());
    body.push(0x00);
    assert!(matches!(
        follower.key_material(TARGET, &hub_domain(), &body).await,
        Err(FollowerError::InvalidRequest(_))
    ));
}

/// A user at the hub's own provider (a.example).
const ZOE: &str = "mimi://a.example/u/zoe";
/// A listed user whose role holds `canAddParticipant`.
const ADDER: &[u8] = BOB;
/// A user not in the participant list.
const STRANGER: &str = "mimi://b.example/u/mallory";

fn role(role_index: u32, role_name: &str, role_capabilities: Vec<Capability>) -> Role {
    Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: String::new(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes: vec![],
    }
}

/// alice creates [`ROOM_ID`] listing alice and bob with `canAddParticipant`,
/// adds bob, and hosts it on `hub`.
async fn create_room(hub: &Hub) {
    let key = *hub.signature_public_key();
    let alice =
        mimi_mls::Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob =
        mimi_mls::Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let roles = RoleData {
        roles: vec![
            role(1, "banned", vec![]),
            role(2, "adder", vec![Capability::CAN_ADD_PARTICIPANT]),
        ],
    };
    let participants = ParticipantListData {
        participants: [ALICE, ADDER]
            .iter()
            .map(|user| UserRolePair {
                user: user.to_vec(),
                role_index: 2,
            })
            .collect(),
    };
    let components = [
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        // The hub requires frank_aad as a Safe AAD component (bead
        // mimid-1wgh.6.74).
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        (
            PARTICIPANT_LIST,
            participants.tls_serialize_detached().unwrap(),
        ),
        (ROLES_LIST, roles.tls_serialize_detached().unwrap()),
        (BASE_ROOM_POLICY, common::base_room_policy()),
    ];
    let senders = [ExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let mut member =
        Member::create(&alice, b"group-local-key-material", &senders, &components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = member
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    member.merge_pending_commit(&alice).unwrap();
    hub.create_room(
        ROOM_ID,
        ALICE,
        &bundle.group_info,
        &member.ratchet_tree().unwrap(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn hub_serves_its_own_users_in_process_after_its_policy_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = common::open_hub(&path).await;
    let own = Arc::new(KeyPackages::new(
        store.clone(),
        common::domain(),
        Arc::new(FixedClock(now_ms())),
    ));
    let hub = hub.with_local_key_material(Arc::clone(&own) as _);
    create_room(&hub).await;
    let zoe = LocalUser::authenticated(&common::domain(), ZOE).unwrap();
    let kp = key_package(&client(ZOE, 30 * DAY, &[]), false);
    own.upload_key_package(&zoe, &kp).await.unwrap();
    let adder = std::str::from_utf8(ADDER).unwrap();
    let asking = |requester: &'static str| Ask {
        requesting_user: requester,
        credential_identity: requester,
        target_user: ZOE,
        room_id: ROOM_ID,
        required_capabilities: NO_REQUIREMENTS,
    };

    // Room policy refuses a requester who is not a participant; the local
    // KeyPackage is untouched.
    let refused = hub
        .key_material(ZOE, &domain("b.example"), &request(&asking(STRANGER)))
        .await
        .unwrap();
    assert_eq!(refused, no_consent(ZOE));
    assert_eq!(own.list_key_packages(&zoe).await.unwrap().len(), 1);

    let response = hub
        .key_material(ZOE, &domain("b.example"), &request(&asking(adder)))
        .await
        .unwrap();
    let response = decode(&response);
    assert_eq!(response.user_status, KeyMaterialUserCode::Success);
    assert_eq!(served(&response), std::slice::from_ref(&kp));
    assert!(own.list_key_packages(&zoe).await.unwrap().is_empty());
    assert_eq!(
        claims_in(&path).await,
        [(reference(&kp), adder.to_owned(), ROOM_ID.to_owned())]
    );
}

/// [`ZOE`] percent-encoded by hand (RFC 3986 §2.1; decision
/// mimid-1wgh.5.18).
const ZOE_ENCODED: &str = "mimi%3A%2F%2Fa.example%2Fu%2Fzoe";

#[tokio::test]
async fn remote_requester_gets_our_users_key_package_for_a_room_we_host_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = common::open_hub(&path).await;
    let own = Arc::new(KeyPackages::new(
        store.clone(),
        common::domain(),
        Arc::new(FixedClock(now_ms())),
    ));
    let hub = hub.with_local_key_material(Arc::clone(&own) as _);
    create_room(&hub).await;
    let kp = key_package(&client(ZOE, 30 * DAY, &[]), false);
    own.upload_key_package(
        &LocalUser::authenticated(&common::domain(), ZOE).unwrap(),
        &kp,
    )
    .await
    .unwrap();
    let adder = std::str::from_utf8(ADDER).unwrap();
    let body = request(&Ask {
        requesting_user: adder,
        credential_identity: adder,
        target_user: ZOE,
        room_id: ROOM_ID,
        required_capabilities: NO_REQUIREMENTS,
    });

    // Decision mimid-1wgh.7.27: our user in a room we host, so the hub's
    // policy check runs and the hub serves the KeyPackage in-process.
    let base = BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap();
    let follower = Follower::new(common::domain(), store, Arc::new(FixedClock(now_ms())));
    let response = router(directory(&base), Arc::new(hub), Arc::new(follower))
        .oneshot(
            Request::post(format!("/v1/keyMaterial/{ZOE_ENCODED}"))
                .header(header::FROM, "mimi@b.example")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let decoded = decode(&bytes);
    assert_eq!(decoded.user_status, KeyMaterialUserCode::Success);
    assert_eq!(decoded.user_uri.as_str(), ZOE);
    assert_eq!(served(&decoded), std::slice::from_ref(&kp));
    assert_eq!(
        claims_in(&path).await,
        [(reference(&kp), adder.to_owned(), ROOM_ID.to_owned())]
    );
}

/// Stores `key_package` for `user` without the upload checks, as a row
/// written before decision mimid-1wgh.6.76 could be: uploads now refuse a
/// URI that is not `mimi://<domain>/u/<id>`.
async fn store_unchecked(store: &Store, user: &str, key_package: &[u8]) {
    let inserted = store
        .insert_key_package(&NewKeyPackage {
            client_id: &format!("{user}/client"),
            user_uri: user,
            reference: &reference(key_package),
            bytes: key_package,
            last_resort: false,
            not_after: now_seconds() + 30 * DAY,
        })
        .await
        .unwrap();
    assert_eq!(inserted, KeyPackageInsert::Inserted);
}

#[tokio::test]
async fn local_uris_that_are_not_user_uris_get_no_consent() {
    // protocol-07 §2.1; decision mimid-1wgh.6.76: only mimi://<domain>/u/<id>
    // names a user, so the provider URI and a room URI are no target user.
    // §5.2 noConsent is the catch-all refusal (decision mimid-1wgh.7.9).
    let p = Provider::open().await;
    for uri in ["mimi://b.example", "mimi://b.example/r/bob"] {
        let kp = key_package(&client(uri, 30 * DAY, &[]), false);
        store_unchecked(&p.store, uri, &kp).await;
        let body = request(&Ask {
            target_user: uri,
            ..ask()
        });
        let response = p
            .key_packages
            .serve_key_material(&hub_domain(), uri, &body)
            .await
            .unwrap();
        assert_eq!(response, no_consent(uri), "{uri}");
    }
    assert!(p.claims().await.is_empty());
}

#[tokio::test]
async fn local_uris_that_are_not_user_uris_get_no_consent_on_either_route() {
    // http.rs routes a keyMaterial request by the target's domain (decision
    // mimid-1wgh.7.27): a room we host goes to the hub, which serves in
    // process, any other room to the follower. Both reach
    // KeyPackages::serve_key_material, which refuses a non-user URI
    // (decision mimid-1wgh.6.76).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = common::open_hub(&path).await;
    let own = Arc::new(KeyPackages::new(
        store.clone(),
        common::domain(),
        Arc::new(FixedClock(now_ms())),
    ));
    let hub = hub.with_local_key_material(Arc::clone(&own) as _);
    create_room(&hub).await;
    let follower = Follower::new(
        common::domain(),
        store.clone(),
        Arc::new(FixedClock(now_ms())),
    )
    .with_key_packages(Arc::clone(&own));
    let base = BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap();
    let app = router(directory(&base), Arc::new(hub), Arc::new(follower));
    let adder = std::str::from_utf8(ADDER).unwrap();
    // Each URI with its percent-encoding (RFC 3986 §2.1; decision
    // mimid-1wgh.5.18), done by hand.
    let targets = [
        ("mimi://a.example", "mimi%3A%2F%2Fa.example"),
        (
            "mimi://a.example/r/hall",
            "mimi%3A%2F%2Fa.example%2Fr%2Fhall",
        ),
    ];
    // (roomId, From): a room we host goes to the hub; a room hosted by
    // c.example, asked by its hub, goes to the follower.
    let routes = [
        (ROOM_ID, "mimi@b.example"),
        ("mimi://c.example/r/elsewhere", "mimi@c.example"),
    ];
    for (target, encoded) in targets {
        let kp = key_package(&client(target, 30 * DAY, &[]), false);
        store_unchecked(&store, target, &kp).await;
        for (room_id, from) in routes {
            let body = request(&Ask {
                requesting_user: adder,
                credential_identity: adder,
                target_user: target,
                room_id,
                required_capabilities: NO_REQUIREMENTS,
            });
            let response = app
                .clone()
                .oneshot(
                    Request::post(format!("/v1/keyMaterial/{encoded}"))
                        .header(header::FROM, from)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{target} {room_id}");
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert_eq!(bytes, no_consent(target), "{target} {room_id}");
        }
    }
    assert!(claims_in(&path).await.is_empty());
}
