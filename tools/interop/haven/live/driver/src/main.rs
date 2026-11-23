//! Live run: mimid's outbound PeerClient against Haven's mimi-hubd
//! (beads mimid-1wgh.46.1.6 and mimid-1wgh.46.6). Runs inside the B3
//! harness namespace, where haven.localhost:443 is the mTLS-supplying proxy
//! and SSL_CERT_FILE trusts the throwaway CA, or on a host whose outbound
//! proxy supplies the client certificate to a public hub (see `Names`). Setup (KeyPackages, consent,
//! the room's first participant, an enrolled handle) is done by b4.sh over
//! Haven's JSON lane and store before this runs.
//!
//! Usage:
//!   mimid-haven-live make-kp <identity URI> <out file>   a mimid KeyPackage
//!   mimid-haven-live unicode                             Unicode stress (src/unicode.rs)
//!   mimid-haven-live                                     the live steps
//!
//! Each line starting with STEP is one request; its result is printed as
//! Haven answered it, decoded by mimid where there is a body.

use std::collections::BTreeMap;
use std::time::SystemTime;

use mimi_mls::member::{AppDataUpdate, CommitBundle, ComponentOp, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{
    AppDataDictionary, CipherSuite, Credential, GroupInfo, KeyPackage, MLSMessage,
    RatchetTreeOption, RequiredCapabilities, SignaturePublicKey, Welcome,
};
use mimi_mls::{Identity, KeyPackageKind, Store};
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::{
    AbuseReport, AbuseType, ClientKeyMaterial, ConsentEntry, ConsentOperation, FanoutEvent,
    FanoutMessage, GroupInfoOption, HandshakeBundle, IdentifierRequest, IdentifierResponse,
    IdentifierUri, KeyMaterialRequestTbs, KeyMaterialResponse, ParticipantListData,
    ParticipantListUpdate, Protocol, QueryElement, QuerySearch, SubmitMessageRequest,
    SubmitMessageResponse, UpdateRequest, UpdateResult, UpdateRoomResponse, UserRolePair,
};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::{PeerClient, PeerError};

mod unicode;

/// The names one run uses. The defaults are the namespace run's
/// (run.sh); a run against a public hub sets them from the environment:
///   HAVEN_DOMAIN    Haven's provider domain (default haven.localhost)
///   OWN_DOMAIN      mimid's provider domain (default b.example). The mTLS
///                   client certificate must name it as a dNSName SAN, so
///                   Haven's From check (DIV-16, protocol-07 §4.1) and its
///                   /notify source check (§5.5) can pass.
///   HAVEN_BASE_URL  where the directory is fetched (default https://HAVEN_DOMAIN)
///   RUN_TAG         appended to every user and room name (default empty),
///                   so a rerun against a hub that keeps its state starts
///                   from fresh users and rooms. b4.sh builds the same names.
struct Names {
    haven: &'static str,
    own: &'static str,
    base_url: String,
    alice: &'static str,
    carol: &'static str,
    dave: &'static str,
    erin: &'static str,
    frank: &'static str,
    bob: &'static str,
    /// A Haven user whose only KeyPackage was minted by mimid (b4.sh).
    grace: &'static str,
    /// The MLS group ID of mimid's copy of the room: its name.
    room_name: &'static str,
    /// A room hosted by Haven.
    room: &'static str,
    /// A room hosted by mimid, for /notify (protocol-07 §5.5: only the hub
    /// of the room may send it).
    own_room: &'static str,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

static N: std::sync::LazyLock<Names> = std::sync::LazyLock::new(|| {
    let haven = leak(env_or("HAVEN_DOMAIN", "haven.localhost"));
    let own = leak(env_or("OWN_DOMAIN", "b.example"));
    let tag = env_or("RUN_TAG", "");
    let user = |domain: &str, name: &str| leak(format!("mimi://{domain}/u/{name}{tag}"));
    let room_name = leak(format!("live1{tag}"));
    Names {
        haven,
        own,
        base_url: env_or("HAVEN_BASE_URL", &format!("https://{haven}")),
        alice: user(own, "alice"),
        carol: user(own, "carol"),
        dave: user(own, "dave"),
        erin: user(own, "erin"),
        frank: user(own, "frank"),
        bob: user(haven, "bob"),
        grace: user(haven, "grace"),
        room_name,
        room: leak(format!("mimi://{haven}/r/{room_name}")),
        own_room: leak(format!("mimi://{own}/r/notify1{tag}")),
    }
});
const SEED: [u8; 32] = [0x11; 32];
/// Ed25519 public key for seed 0x11 * 32 (mimi-protocol tests/key_material.rs oracle).
const PUB: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4, 0xe6,
    0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77, 0x87, 0x37,
];
/// A hand-encoded PrivateMessage (mimi-protocol tests/submit.rs).
const PRIVATE_APPLICATION: &[u8] = &[
    0x00, 0x01, 0x00, 0x02, 0x04, b'r', b'o', b'o', b'm', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x07, 0x01, 0x00, 0x03, 0xa1, 0xa2, 0xa3, 0x05, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
];
/// RFC 9420 §6 MLSMessage headers: mls10, then wire_format.
const GROUP_INFO_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];
const WELCOME_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x03];
/// mls-extensions-11 §5 `app_components` component.
const APP_COMPONENTS: u16 = 0x0001;

fn uri(text: &str) -> IdentifierUri {
    IdentifierUri::new(text).expect("valid URI")
}

fn opaque(bytes: &[u8]) -> Vec<u8> {
    [vec![u8::try_from(bytes.len()).expect("short")], bytes.to_vec()].concat()
}

fn work(name: &str) -> std::path::PathBuf {
    std::path::Path::new(&std::env::var("WORK").expect("WORK")).join(name)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn dictionary() -> AppDataDictionary {
    AppDataDictionary::new(&[]).expect("dictionary")
}

fn identity(user: &str) -> Identity {
    Identity::generate(user.as_bytes(), Store::open_in_memory().expect("store")).expect("identity")
}

fn pairs(users: &[&str]) -> Vec<UserRolePair> {
    users
        .iter()
        .map(|u| UserRolePair {
            user: u.as_bytes().to_vec(),
            role_index: 1,
        })
        .collect()
}

fn list(users: &[&str]) -> Vec<u8> {
    ParticipantListData {
        participants: pairs(users),
    }
    .tls_serialize_detached()
    .expect("list")
}

fn change(removed_indices: Vec<u32>, added: &[&str]) -> AppDataUpdate {
    AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices,
            added_participants: pairs(added),
        }
        .tls_serialize_detached()
        .expect("update"),
    }
}

/// What `Member::commit`'s `apply` callback returns: the component's new
/// data, or `None` to remove it.
type Applied = Result<Option<Vec<u8>>, std::io::Error>;

/// The driver does not resolve ParticipantListUpdates itself: each Commit
/// states the list it leads to.
fn to(after: Vec<u8>) -> impl FnMut(u16, Option<&[u8]>, ComponentOp<'_>) -> Applied {
    move |id, _current, op| {
        assert_eq!(id, PARTICIPANT_LIST);
        assert!(matches!(op, ComponentOp::Update(_)));
        Ok(Some(after.clone()))
    }
}

fn print_error(e: &PeerError) {
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        println!("  caused by: {s}");
        source = s.source();
    }
}

/// protocol-07 §5.3 UpdateRequest around a mimid CommitBundle, pending in
/// `member`. The `full` RatchetTreeOption is the tree of the epoch the
/// Commit leads to, the one its GroupInfo describes: mimi-hubd since
/// ffd9e24 seeds a room's tree from the two, and refused the current
/// epoch's tree sent here before ("its GroupInfo and tree are not a valid
/// group"; bead mimid-1wgh.46.6).
fn commit_request(member: &Member, identity: &Identity, bundle: &CommitBundle) -> Vec<u8> {
    UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(&bundle.commit).expect("commit"),
            welcome: bundle.welcome.as_ref().map(|w| {
                Welcome::tls_deserialize_exact(w.strip_prefix(&WELCOME_HEADER).expect("Welcome"))
                    .expect("welcome")
            }),
            group_info_option: GroupInfoOption::Full {
                group_info: GroupInfo::tls_deserialize_exact(
                    bundle
                        .group_info
                        .strip_prefix(&GROUP_INFO_HEADER)
                        .expect("GroupInfo"),
                )
                .expect("group info"),
            },
            ratchet_tree_option: RatchetTreeOption::full(
                &member
                    .pending_ratchet_tree(identity)
                    .expect("the next epoch's tree"),
            )
            .expect("tree option"),
        },
    }
    .tls_serialize_detached()
    .expect("UpdateRequest")
}

/// protocol-07 §5.3 UpdateRequest carrying proposals.
fn proposal_request(proposal: &[u8]) -> Vec<u8> {
    UpdateRequest {
        bundle: HandshakeBundle::Proposal {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(proposal).expect("proposal"),
            more_proposals: vec![],
        },
    }
    .tls_serialize_detached()
    .expect("UpdateRequest")
}

/// Sends `body` to Haven's update endpoint for N.room and prints the answer.
async fn update(
    client: &PeerClient,
    haven: &Domain,
    step: &str,
    body: Vec<u8>,
) -> Option<UpdateResult> {
    match client.update(haven, N.room, body).await {
        Ok(body) => match UpdateRoomResponse::tls_deserialize_exact(&body[..]) {
            Ok(r) => {
                let refs: Vec<String> = match &r.result {
                    UpdateResult::InvalidProposal { invalid_proposals } => invalid_proposals
                        .iter()
                        .map(|p| hex(&p.tls_serialize_detached().expect("ref")))
                        .collect(),
                    _ => vec![],
                };
                println!(
                    "STEP {step}: 200, {:?} errorDescription={:?}{}",
                    r.result,
                    r.error_description,
                    if refs.is_empty() {
                        String::new()
                    } else {
                        format!(" invalidProposals(hex, with length)={refs:?}")
                    }
                );
                Some(r.result)
            }
            Err(e) => {
                println!(
                    "STEP {step}: 200 but no UpdateRoomResponse: {e:?} (body {} bytes: {})",
                    body.len(),
                    hex(&body)
                );
                None
            }
        },
        Err(e) => {
            println!("STEP {step}: FAIL - {e:?}");
            None
        }
    }
}

/// Commits `bundle` at Haven: merges it if Haven answers success, else
/// clears it.
async fn commit_at_haven(
    client: &PeerClient,
    haven: &Domain,
    step: &str,
    alice: &Identity,
    group: &mut Member,
    bundle: &CommitBundle,
    file: &str,
) -> bool {
    std::fs::write(work(file), &bundle.commit).unwrap();
    let accepted = matches!(
        update(client, haven, step, commit_request(group, alice, bundle)).await,
        Some(UpdateResult::Success { .. })
    );
    if accepted {
        group.merge_pending_commit(alice).expect("merge");
    } else {
        group.clear_pending_commit(alice).expect("clear");
    }
    accepted
}

async fn key_material(
    client: &PeerClient,
    haven: &Domain,
    step: &str,
    requester: &str,
    target: &str,
) {
    let key = [vec![0x20], PUB.to_vec()].concat();
    let credential = [vec![0x00, 0x01], opaque(requester.as_bytes())].concat();
    let request = KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: uri(requester),
        target_user: uri(target),
        room_id: uri(N.room),
        acceptable_ciphersuites: vec![CipherSuite::tls_deserialize_exact([0x00, 0x01]).unwrap()],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact([0x00, 0x00, 0x00])
            .unwrap(),
        requester_signature_key: SignaturePublicKey::tls_deserialize_exact(&key).unwrap(),
        requester_credential: Credential::tls_deserialize_exact(&credential).unwrap(),
    }
    .sign(&mimi_mls::label::SignatureKeyPair::from_raw(&SEED, &PUB).expect("SEED and PUB are a pair"))
    .expect("sign")
    .tls_serialize_detached()
    .expect("encode");
    match client.key_material(haven, target, request).await {
        Ok(body) => match KeyMaterialResponse::tls_deserialize_exact(&body[..]) {
            Ok(response) => {
                println!(
                    "STEP {step}: 200, userStatus={:?} userUri={} clients={}",
                    response.user_status,
                    response.user_uri.as_str(),
                    response.clients.len()
                );
                for c in &response.clients {
                    match c {
                        ClientKeyMaterial::Success {
                            client_uri,
                            key_package,
                        } => match key_package.verify(SystemTime::now()) {
                            Ok(_) => println!(
                                "  client {} success; KeyPackage verifies (RFC 9420 §10.1)",
                                client_uri.as_str()
                            ),
                            Err(e) => println!(
                                "  client {} success; KeyPackage FAILS verify: {e:?}",
                                client_uri.as_str()
                            ),
                        },
                        other => println!("  client {other:?}"),
                    }
                }
            }
            Err(e) => println!(
                "STEP {step}: 200 but mimid cannot decode: {e:?} body={}",
                hex(&body)
            ),
        },
        Err(e) => println!("STEP {step}: FAIL - {e:?}"),
    }
}

fn consent(op: ConsentOperation, requester: &str, target: &str, kps: Vec<KeyPackage>) -> Vec<u8> {
    ConsentEntry {
        consent_operation: op,
        requester_uri: uri(requester),
        target_uri: uri(target),
        room_id: matches!(op, ConsentOperation::Request | ConsentOperation::Cancel)
            .then(|| uri(N.room)),
        client_key_packages: kps,
        consent_extensions: dictionary(),
    }
    .tls_serialize_detached()
    .expect("ConsentEntry")
}

/// Prints the outcome of a request whose answer has no body.
fn show(step: &str, result: Result<(), PeerError>, want: &str) {
    match result {
        Ok(()) => println!("STEP {step}: {want} (mimid accepted it)"),
        Err(e) => println!("STEP {step}: {e:?} (mimid accepts only {want})"),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("make-kp") {
        let bytes = identity(&args[2])
            .key_package(KeyPackageKind::OneTime)
            .expect("key package");
        std::fs::write(&args[3], bytes).expect("write");
        return;
    }

    let haven = Domain::try_from(N.haven.to_owned()).expect("domain");
    let own = Domain::try_from(N.own.to_owned()).expect("domain");
    let peers = BTreeMap::from([(
        haven.clone(),
        BaseUrl::try_from(N.base_url.clone()).expect("base"),
    )]);
    // With MIMID_CLIENT_CERT and MIMID_CLIENT_KEY set, mimid presents its
    // OWN client certificate instead of relying on the harness's socat
    // proxy to add one (bead mimid-6x2f). That is the half that had never
    // been tested against a non-mimid peer: up.sh has socat hold the
    // certificate, so the default path proves only that mimi-hubd accepts
    // a proxy's certificate, not mimid's. MIMID_PEER_ROOTS adds a CA for
    // the peer's SERVER certificate, which the harness's throwaway CA
    // needs since it is not in the system store.
    let tls = match (
        std::env::var("MIMID_CLIENT_CERT"),
        std::env::var("MIMID_CLIENT_KEY"),
    ) {
        (Ok(cert), Ok(key)) => mimid_server::tls::PeerTlsConfig {
            roots: std::env::var("MIMID_PEER_ROOTS")
                .ok()
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect(),
            identity: Some(mimid_server::tls::TlsConfig {
                cert: std::path::PathBuf::from(cert),
                key: std::path::PathBuf::from(key),
            }),
        },
        _ => mimid_server::tls::PeerTlsConfig::default(),
    };
    let presenting = tls.identity.is_some();
    let client = PeerClient::with_tls(&own, peers, &tls).expect("PeerClient");
    eprintln!(
        "driver: own={} peer={} client certificate presented by mimid: {presenting}",
        own.as_str(),
        haven.as_str()
    );

    if args.get(1).map(String::as_str) == Some("unicode") {
        unicode::run(&client, &haven).await;
        return;
    }

    // 1. Directory fetch (TLS trust + partial directory). Before 9195662
    // Haven's directory had no groupInfo, so a working fetch ended in
    // NotOffered; since then it offers groupInfo, and the empty body this
    // sends is refused there with a 400 problem (bead mimid-1wgh.46.6).
    match client.group_info(&haven, N.room, vec![]).await {
        Err(PeerError::NotOffered { endpoint }) => {
            println!("STEP 1: ok - directory fetched over TLS and parsed; {endpoint} not offered")
        }
        Err(PeerError::Rejected {
            status: 400,
            response,
            ..
        }) => {
            println!(
                "STEP 1: ok - directory fetched over TLS and parsed; groupInfo offered, an empty body refused 400 {}",
                String::from_utf8_lossy(&response.preview)
            )
        }
        other => {
            println!("STEP 1: FAIL - {other:?}");
            if let Err(e) = &other {
                print_error(e);
            }
            std::process::exit(1);
        }
    }

    // 2. keyMaterial (§5.2), with signed mimid requests.
    // 2a: bob's one Haven-minted KeyPackage; alice has bob's consent.
    key_material(&client, &haven, "2a keyMaterial bob (Haven KeyPackage)", N.alice, N.bob).await;
    // 2b: bob again: his only KeyPackage is gone (the DIV-13 answer).
    key_material(&client, &haven, "2b keyMaterial bob again (exhausted)", N.alice, N.bob).await;
    // 2c: grace's one KeyPackage was minted by mimid, with GREASE (Haven's
    // gate refused these at 2c14e62, mimid-1wgh.46.1.13).
    key_material(&client, &haven, "2c keyMaterial grace (mimid KeyPackage)", N.alice, N.grace).await;
    // 2d: carol has no consent from bob.
    key_material(&client, &haven, "2d keyMaterial bob for carol (no consent)", N.carol, N.bob).await;

    // 3. submitMessage (§5.4) from a participant, then from a non-participant.
    let submit = |sender: &str| {
        SubmitMessageRequest {
            protocol: Protocol::Mls10,
            app_message: MLSMessage::tls_deserialize_exact(PRIVATE_APPLICATION).unwrap(),
            sending_uri: uri(sender),
        }
        .tls_serialize_detached()
        .unwrap()
    };
    std::fs::write(work("submitted_app_message.bin"), PRIVATE_APPLICATION).unwrap();
    for (step, sender) in [
        ("3a submitMessage from alice", N.alice),
        ("3b submitMessage from erin (not a participant)", N.erin),
    ] {
        match client.submit_message(&haven, N.room, submit(sender)).await {
            Ok(body) => match SubmitMessageResponse::tls_deserialize_exact(&body[..]) {
                Ok(r) => println!("STEP {step}: 200, {:?} {:?}", r.protocol, r.result),
                Err(e) => println!(
                    "STEP {step}: 200 but mimid cannot decode: {e:?} body={}",
                    hex(&body)
                ),
            },
            Err(e) => println!("STEP {step}: FAIL - {e:?}"),
        }
    }

    // 4. update (§5.3). Haven's room starts with alice (b4.sh); mimid's
    // group starts with the same list.
    let alice = identity(N.alice);
    let carol = identity(N.carol);
    let mut group = Member::create(
        &alice,
        N.room_name.as_bytes(),
        &[],
        &[
            // mls-extensions-11 §5: a ComponentsList naming participant_list.
            (APP_COMPONENTS, vec![0x02, 0x00, 0x22]),
            (PARTICIPANT_LIST, list(&[N.alice])),
        ],
    )
    .expect("create");

    // 4a: one AppDataUpdate (0x0022) adding dave, no Add: a participant
    // listed before any client is added.
    let bundle = group
        .commit(&alice, &[], &[], &[change(vec![], &[N.dave])], to(list(&[N.alice, N.dave])))
        .expect("commit 4a");
    commit_at_haven(
        &client,
        &haven,
        "4a update: AppDataUpdate adds dave",
        &alice,
        &mut group,
        &bundle,
        "update_commit.bin",
    )
    .await;

    // 4b: Add(carol's KeyPackage) beside the AppDataUpdate adding carol
    // (protocol-07 §3.2; Haven DIV-10 takes Adds since e8db28f).
    let carol_kp = carol.key_package(KeyPackageKind::OneTime).expect("carol kp");
    let bundle = group
        .commit(
            &alice,
            &[&carol_kp],
            &[],
            &[change(vec![], &[N.carol])],
            to(list(&[N.alice, N.dave, N.carol])),
        )
        .expect("commit 4b");
    let mut carol_group = None;
    if commit_at_haven(
        &client,
        &haven,
        "4b update: Add carol + AppDataUpdate adds carol",
        &alice,
        &mut group,
        &bundle,
        "update_commit_add.bin",
    )
    .await
    {
        let tree = group.ratchet_tree().expect("tree");
        match Member::join_welcome(&carol, bundle.welcome.as_ref().expect("welcome"), Some(&tree)) {
            Ok(join) => carol_group = Some(join.member),
            Err(e) => println!("  carol cannot join from the Welcome: {e:?}"),
        }
    }
    let listed: Vec<&str> = if carol_group.is_some() {
        vec![N.alice, N.dave, N.carol]
    } else {
        vec![N.alice, N.dave]
    };

    // 4c: two changes in one Commit: two AppDataUpdates for 0x0022 (erin,
    // then frank). protocol-07 §7.5 allows more than one
    // ParticipantListUpdate in a Commit; Haven DIV-10 refuses a second change.
    let bundle = group
        .commit(
            &alice,
            &[],
            &[],
            &[change(vec![], &[N.erin]), change(vec![], &[N.frank])],
            to(list(&[listed.as_slice(), &[N.erin, N.frank]].concat())),
        )
        .expect("commit 4c");
    if commit_at_haven(
        &client,
        &haven,
        "4c update: two AppDataUpdates (0x0022) in one Commit",
        &alice,
        &mut group,
        &bundle,
        "update_commit_two_changes.bin",
    )
    .await
    {
        println!("  NOTE: accepted; the later steps assume it was refused");
    }

    // 4d-4g: carol leaves (protocol-07 §3.5). mimid's MLS layer builds the
    // AppDataUpdate proposal but has no way to build a Remove proposal, so
    // the leave carries the change alone and the committer adds the Remove.
    let Some(mut carol_group) = carol_group else {
        println!("STEP 4d-4g: skipped (carol is not in the group)");
        return finish(&client, &haven, &alice).await;
    };
    let carol_leaf = carol_group.own_leaf_index();
    // [alice, dave, carol]: carol is index 2.
    let proposal = carol_group
        .propose_app_data_update(&carol, &change(vec![2], &[]))
        .expect("carol's proposal");
    std::fs::write(work("leave_proposal.bin"), &proposal).unwrap();
    let held = update(
        &client,
        &haven,
        "4d update: carol's leave (AppDataUpdate removing carol, no Remove)",
        proposal_request(&proposal),
    )
    .await;
    if matches!(held, Some(UpdateResult::Success { .. })) {
        // 4e: a Commit that leaves the held proposal out.
        let bundle = group
            .commit(
                &alice,
                &[],
                &[],
                &[change(vec![], &[N.erin])],
                to(list(&[N.alice, N.dave, N.carol, N.erin])),
            )
            .expect("commit 4e");
        if commit_at_haven(
            &client,
            &haven,
            "4e update: Commit leaving the held proposal out",
            &alice,
            &mut group,
            &bundle,
            "update_commit_without_held.bin",
        )
        .await
        {
            println!("  NOTE: accepted; 4f will not fit");
        }

        // 4f: alice stores carol's proposal and commits it by reference,
        // with the Remove of carol's leaf by value.
        match group.process(&alice, &proposal, to(list(&[N.alice, N.dave]))) {
            Ok(incoming) => println!("  alice stored carol's proposal: {incoming:?}"),
            Err(e) => println!("  alice cannot process carol's proposal: {e:?}"),
        }
        let bundle = group
            .commit(&alice, &[], &[carol_leaf], &[], to(list(&[N.alice, N.dave])))
            .expect("commit 4f");
        commit_at_haven(
            &client,
            &haven,
            "4f update: Commit with carol's proposal by reference + Remove of carol's leaf",
            &alice,
            &mut group,
            &bundle,
            "update_commit_by_reference.bin",
        )
        .await;

        // 4g: the same leave again, now at a past epoch.
        update(
            &client,
            &haven,
            "4g update: carol's leave sent again after its Commit",
            proposal_request(&proposal),
        )
        .await;
    }
    finish(&client, &haven, &alice).await;
}

/// Steps 5 to 8: notify, consent, identifierQuery and reportAbuse.
async fn finish(client: &PeerClient, haven: &Domain, alice: &Identity) {
    // 5. notify (§5.5) with one FanoutMessage (application).
    let fanout = FanoutMessage {
        timestamp: 1_700_000_000_000,
        event: FanoutEvent::Application {
            message: MLSMessage::tls_deserialize_exact(PRIVATE_APPLICATION).unwrap(),
            frank: None,
        },
    }
    .tls_serialize_detached()
    .unwrap();
    // 5a: a room mimid hosts: Haven should accept it.
    show(
        "5a notify for mimid's room",
        client.notify(haven, N.own_room, fanout.clone()).await,
        "201",
    );
    // 5b: the same body again: §5.5 answers a duplicate 201 too.
    show(
        "5b notify duplicate",
        client.notify(haven, N.own_room, fanout.clone()).await,
        "201",
    );
    // 5c: a room Haven hosts: mimid is not its hub, so §5.5 rejects it.
    show(
        "5c notify for Haven's room (mimid is not its hub; rejection expected)",
        client.notify(haven, N.room, fanout).await,
        "201",
    );

    // 6. requestConsent / updateConsent (§5.7): 202, and 422 for an
    // operation the endpoint does not take.
    show(
        "6a requestConsent request",
        client
            .request_consent(haven, consent(ConsentOperation::Request, N.alice, N.bob, vec![]))
            .await,
        "202",
    );
    show(
        "6b requestConsent cancel",
        client
            .request_consent(haven, consent(ConsentOperation::Cancel, N.alice, N.bob, vec![]))
            .await,
        "202",
    );
    show(
        "6c requestConsent carrying grant (422 expected)",
        client
            .request_consent(haven, consent(ConsentOperation::Grant, N.alice, N.bob, vec![]))
            .await,
        "202",
    );
    // updateConsent: a Haven user (the requester) asked a mimid user.
    let alice_kp = KeyPackage::tls_deserialize_exact(
        alice.key_package(KeyPackageKind::OneTime).expect("kp"),
    )
    .expect("KeyPackage");
    show(
        "6d updateConsent grant (with a mimid KeyPackage)",
        client
            .update_consent(haven, consent(ConsentOperation::Grant, N.bob, N.alice, vec![alice_kp]))
            .await,
        "202",
    );
    show(
        "6e updateConsent revoke",
        client
            .update_consent(haven, consent(ConsentOperation::Revoke, N.bob, N.alice, vec![]))
            .await,
        "202",
    );
    show(
        "6f updateConsent carrying request (422 expected)",
        client
            .update_consent(haven, consent(ConsentOperation::Request, N.bob, N.alice, vec![]))
            .await,
        "202",
    );

    // 7. identifierQuery (§5.8): one Handle element, for an enrolled handle
    // and for an unknown one.
    // b4.sh enrols bob plus RUN_TAG.
    let tag = env_or("RUN_TAG", "");
    for (step, handle) in [
        ("7a identifierQuery handle bob (enrolled)", format!("bob{tag}")),
        ("7b identifierQuery handle nobody", format!("nobody{tag}")),
    ] {
        let request = IdentifierRequest {
            query_elements: vec![QueryElement {
                search: QuerySearch::Handle,
                search_value: handle.as_bytes().to_vec(),
            }],
            id_request_extensions: dictionary(),
        }
        .tls_serialize_detached()
        .expect("IdentifierRequest");
        match client.identifier_query(haven, request).await {
            Ok(body) => match IdentifierResponse::tls_deserialize_exact(&body[..]) {
                Ok(r) => println!("STEP {step}: 200, {r:?}"),
                Err(e) => println!(
                    "STEP {step}: 200 but no IdentifierResponse: {e:?} (body {} bytes)",
                    body.len()
                ),
            },
            Err(e) => println!("STEP {step}: FAIL - {e:?}"),
        }
    }

    // 8. reportAbuse (§5.9), metadata only (no AbusiveMessage, DIV-8).
    let report = AbuseReport {
        reporting_user: uri(N.alice),
        alleged_abuser_uri: uri(N.dave),
        reason_code: AbuseType(1),
        note: b"live interop test".to_vec(),
        messages: vec![],
        abuse_extensions: dictionary(),
    }
    .tls_serialize_detached()
    .expect("AbuseReport");
    match client.report_abuse(haven, N.room, report).await {
        Ok(body) => println!("STEP 8 reportAbuse: 200 (body {} bytes)", body.len()),
        Err(e) => println!("STEP 8 reportAbuse: FAIL - {e:?} (mimid accepts only 200)"),
    }
}
