//! Read-only probe of Jason's seeded hub (mimi.havenmessenger.com) from the
//! mimid host, whose outbound proxy adds mimid's client certificate.
//! Steps: directory, keyMaterial erin (consumes one of erin's 20 KeyPackages),
//! keyMaterial grace (none seeded), identifierQuery erin and nobody.
//! Based on ../live/driver. Usage is in ../README.
//!
//! `haven-probe sign-iq <seed file> <out dir>` instead writes one signed
//! identifierQuery for erin's handle, signed with the 32-byte seed in
//! `<seed file>` (mimid's provider key, selector mimid1), as `body.bin` and
//! `headers.txt` (curl `-H @` lines) in `<out dir>`, for sending without a
//! client certificate (Haven's DNS-key check, 3bd065c).

use std::collections::BTreeMap;
use std::time::SystemTime;

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{
    AppDataDictionary, CipherSuite, Credential, RequiredCapabilities, SignaturePublicKey,
};
use mimi_protocol::{
    ClientKeyMaterial, IdentifierRequest, IdentifierResponse, IdentifierUri, KeyMaterialRequestTbs,
    KeyMaterialResponse, Protocol, QueryElement, QuerySearch,
};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::{PeerClient, PeerError};

const HUB: &str = "mimi.havenmessenger.com";
const OWN: &str = "mimi.reviewcommit.com";
const ALICE: &str = "mimi://mimi.reviewcommit.com/u/alice";
const ROOM: &str = "mimi://mimi.havenmessenger.com/r/table";
const SEED: [u8; 32] = [0x11; 32];
const PUB: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4, 0xe6,
    0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77, 0x87, 0x37,
];

fn uri(text: &str) -> IdentifierUri {
    IdentifierUri::new(text).expect("valid URI")
}

fn opaque(bytes: &[u8]) -> Vec<u8> {
    [
        vec![u8::try_from(bytes.len()).expect("short")],
        bytes.to_vec(),
    ]
    .concat()
}

fn print_error(e: &PeerError) {
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        println!("  caused by: {s}");
        source = s.source();
    }
}

async fn key_material(client: &PeerClient, hub: &Domain, step: &str, target: &str) {
    let key = [vec![0x20], PUB.to_vec()].concat();
    let credential = [vec![0x00, 0x01], opaque(ALICE.as_bytes())].concat();
    let request = KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: uri(ALICE),
        target_user: uri(target),
        room_id: uri(ROOM),
        acceptable_ciphersuites: vec![CipherSuite::tls_deserialize_exact([0x00, 0x01]).unwrap()],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact([0x00, 0x00, 0x00])
            .unwrap(),
        requester_signature_key: SignaturePublicKey::tls_deserialize_exact(&key).unwrap(),
        requester_credential: Credential::tls_deserialize_exact(&credential).unwrap(),
    }
    .sign(
        &mimi_mls::label::SignatureKeyPair::from_raw(&SEED, &PUB).expect("SEED and PUB are a pair"),
    )
    .expect("sign")
    .tls_serialize_detached()
    .expect("encode");
    match client.key_material(hub, target, request).await {
        Ok(body) => match KeyMaterialResponse::tls_deserialize_exact(&body[..]) {
            Ok(r) => {
                println!(
                    "STEP {step}: 200, userStatus={:?} userUri={} clients={}",
                    r.user_status,
                    r.user_uri.as_str(),
                    r.clients.len()
                );
                for c in &r.clients {
                    match c {
                        ClientKeyMaterial::Success {
                            client_uri,
                            key_package,
                        } => match key_package.verify(SystemTime::now()) {
                            Ok(_) => println!(
                                "  client {} success; KeyPackage verifies",
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
                "STEP {step}: 200 but mimid cannot decode: {e:?} ({} bytes)",
                body.len()
            ),
        },
        Err(e) => {
            println!("STEP {step}: FAIL - {e:?}");
            print_error(&e);
        }
    }
}

async fn identifier(client: &PeerClient, hub: &Domain, step: &str, handle: &str) {
    let request = IdentifierRequest {
        query_elements: vec![QueryElement {
            search: QuerySearch::Handle,
            search_value: handle.as_bytes().to_vec(),
        }],
        id_request_extensions: AppDataDictionary::new(&[]).expect("dictionary"),
    }
    .tls_serialize_detached()
    .expect("IdentifierRequest");
    match client.identifier_query(hub, request).await {
        Ok(body) => match IdentifierResponse::tls_deserialize_exact(&body[..]) {
            Ok(r) => println!("STEP {step}: 200, {r:?}"),
            Err(e) => println!(
                "STEP {step}: 200 but no IdentifierResponse: {e:?} ({} bytes)",
                body.len()
            ),
        },
        Err(e) => {
            println!("STEP {step}: FAIL - {e:?}");
            print_error(&e);
        }
    }
}

/// Haven's identifierQuery URL from its directory, for this provider.
const IQ_URL: &str =
    "https://mimi.havenmessenger.com:8443/mimi/pl/identifierQuery/mimi.havenmessenger.com";

/// `sign-iq`: see the module documentation.
fn sign_iq(seed_file: &str, out: &str) {
    use mimid_server::httpsig::SigningKey;
    use mimid_server::provider_auth::RequestSigner;

    let seed = std::fs::read(seed_file).expect("seed file");
    let seed: [u8; 32] = seed.try_into().expect("32-byte seed");
    let signer = RequestSigner::new(SigningKey::from_seed(&seed), "mimid1".to_owned());
    let body = IdentifierRequest {
        query_elements: vec![QueryElement {
            search: QuerySearch::Handle,
            search_value: b"mimi://mimi.havenmessenger.com/u/erin".to_vec(),
        }],
        id_request_extensions: AppDataDictionary::new(&[]).expect("dictionary"),
    }
    .tls_serialize_detached()
    .expect("IdentifierRequest");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::FROM,
        http::HeaderValue::from_static("mimi@mimi.reviewcommit.com"),
    );
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/mimi-protocol"),
    );
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    signer
        .sign(
            &http::Method::POST,
            &IQ_URL.parse().expect("uri"),
            &mut headers,
            &body,
            i64::try_from(now).expect("time"),
        )
        .expect("sign");
    let lines: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {}\n", value.to_str().expect("ascii")))
        .collect();
    std::fs::write(format!("{out}/body.bin"), body).expect("body");
    std::fs::write(format!("{out}/headers.txt"), lines).expect("headers");
    println!("signed at {now} for {IQ_URL}");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("sign-iq") {
        sign_iq(&args[2], &args[3]);
        return;
    }
    let hub = Domain::try_from(HUB.to_owned()).expect("domain");
    let client = PeerClient::new(
        &Domain::try_from(OWN.to_owned()).expect("domain"),
        BTreeMap::from([(
            hub.clone(),
            BaseUrl::try_from(format!("https://{HUB}")).expect("base"),
        )]),
    )
    .expect("PeerClient");
    // MIMID_SEED_FILE: sign every request with mimid's provider key
    // (selector mimid1), for a hub that checks DNS-key signatures.
    let client = match std::env::var("MIMID_SEED_FILE") {
        Ok(path) => {
            let seed: [u8; 32] = std::fs::read(path)
                .expect("seed file")
                .try_into()
                .expect("32-byte seed");
            println!("signing with mimid1");
            client.with_signer(std::sync::Arc::new(
                mimid_server::provider_auth::RequestSigner::new(
                    mimid_server::httpsig::SigningKey::from_seed(&seed),
                    "mimid1".to_owned(),
                ),
            ))
        }
        Err(_) => client,
    };

    match client.group_info(&hub, ROOM, vec![]).await {
        Err(PeerError::NotOffered { endpoint }) => {
            println!("STEP 1 directory: ok, fetched and parsed; {endpoint} not offered")
        }
        other => {
            println!("STEP 1 directory: unexpected {other:?}");
            if let Err(e) = &other {
                print_error(e);
            }
        }
    }
    key_material(
        &client,
        &hub,
        "2 keyMaterial erin (as alice)",
        "mimi://mimi.havenmessenger.com/u/erin",
    )
    .await;
    key_material(
        &client,
        &hub,
        "3 keyMaterial grace (none seeded)",
        "mimi://mimi.havenmessenger.com/u/grace",
    )
    .await;
    identifier(
        &client,
        &hub,
        "4 identifierQuery handle erin",
        "mimi://mimi.havenmessenger.com/u/erin",
    )
    .await;
    identifier(
        &client,
        &hub,
        "5 identifierQuery handle nobody",
        "mimi://mimi.havenmessenger.com/u/nobody",
    )
    .await;
}
