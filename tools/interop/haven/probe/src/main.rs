//! Read-only probe of Jason's seeded hub (mimi.havenmessenger.com) from the
//! mimid host, whose outbound proxy adds mimid's client certificate.
//! Steps: directory, keyMaterial erin (consumes one of erin's 20 KeyPackages),
//! keyMaterial grace (none seeded), identifierQuery erin and nobody.
//! Based on ../live/driver. Usage is in ../README.

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
const OWN: &str = "mimid.reviewcommit.com";
const ALICE: &str = "mimi://mimid.reviewcommit.com/u/alice";
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
    .sign(&mimi_mls::label::SignatureKeyPair::from_raw(&SEED, &PUB).expect("SEED and PUB are a pair"))
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

#[tokio::main]
async fn main() {
    let hub = Domain::try_from(HUB.to_owned()).expect("domain");
    let client = PeerClient::new(
        &Domain::try_from(OWN.to_owned()).expect("domain"),
        BTreeMap::from([(
            hub.clone(),
            BaseUrl::try_from(format!("https://{HUB}")).expect("base"),
        )]),
    )
    .expect("PeerClient");

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
    identifier(&client, &hub, "4 identifierQuery handle erin", "erin").await;
    identifier(&client, &hub, "5 identifierQuery handle nobody", "nobody").await;
}
