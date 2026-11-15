//! `mimid-seed-probe`: sends one protocol-07 §5.2 keyMaterial request per
//! user to a mimid provider, as a peer would, and checks the KeyPackages
//! that come back (bead mimid-1wgh.46.10).
//!
//! Usage:
//!
//! ```text
//! mimid-seed-probe --target-domain <domain> --target-url <base URL>
//!                  --from <peer domain> --users alice,carol,dave
//! ```
//!
//! The requester is `mimi://<from>/u/seed-probe`, with a fresh signature
//! key per request, and the room is `mimi://<from>/r/seed-probe`, so the
//! `From` domain is the room's authority (step 4 of
//! `KeyPackages::serve_key_material`). The request goes through
//! [`PeerClient`], which fetches the target's directory first.
//!
//! Each successful request claims KeyPackages: a one-time KeyPackage is
//! consumed for good. Run it against a production provider only when that
//! is what you want.
//!
//! The exit status is 0 only if every user answered `success` and every
//! KeyPackage verified, named the user, and came from a client of the
//! target domain.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::time::SystemTime;

use anyhow::{Context, anyhow, bail, ensure};
use mimi_mls::label::SignatureKeyPair;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{CipherSuite, Credential, RequiredCapabilities, SignaturePublicKey};
use mimi_protocol::{
    ClientKeyMaterial, IdentifierUri, KeyMaterialRequestTbs, KeyMaterialResponse,
    KeyMaterialUserCode, Protocol,
};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::PeerClient;

const USAGE: &str = "usage: mimid-seed-probe --target-domain <domain> --target-url <base URL> \
                     --from <peer domain> --users alice,carol,dave";

/// TLS `opaque<V>` with a one-byte QUIC varint length (RFC 9420 §2.1.2).
fn opaque(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let len = u8::try_from(bytes.len())
        .ok()
        .filter(|len| *len < 64)
        .ok_or_else(|| anyhow!("value too long for a one-byte length"))?;
    Ok([vec![len], bytes.to_vec()].concat())
}

fn uri(text: &str) -> anyhow::Result<IdentifierUri> {
    IdentifierUri::new(text).map_err(|_| anyhow!("{text:?} is not a URI"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut flags = BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| anyhow!("{flag} needs a value\n{USAGE}"))?;
        flags.insert(flag, value);
    }
    let mut take = |flag: &str| {
        flags
            .remove(flag)
            .ok_or_else(|| anyhow!("{flag} is required\n{USAGE}"))
    };
    let target = Domain::try_from(take("--target-domain")?).context("--target-domain")?;
    let target_url = BaseUrl::try_from(take("--target-url")?).context("--target-url")?;
    let from = Domain::try_from(take("--from")?).context("--from")?;
    let users = take("--users")?;
    if let Some(flag) = flags.keys().next() {
        bail!("unknown argument {flag}\n{USAGE}");
    }

    let client = PeerClient::new(&from, BTreeMap::from([(target.clone(), target_url)]))
        .context("building the PeerClient")?;
    let requester = format!("mimi://{from}/u/seed-probe");
    let room = format!("mimi://{from}/r/seed-probe");
    let mut all_ok = true;
    for name in users.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        let target_user = format!("mimi://{target}/u/{name}");
        match probe(&client, &target, &target_user, &requester, &room).await {
            Ok(()) => {}
            Err(error) => {
                all_ok = false;
                println!("{target_user}: FAIL: {error:#}");
            }
        }
    }
    ensure!(all_ok, "some probes failed");
    Ok(())
}

async fn probe(
    client: &PeerClient,
    target: &Domain,
    target_user: &str,
    requester: &str,
    room: &str,
) -> anyhow::Result<()> {
    let key = SignatureKeyPair::generate().context("generating the requester key")?;
    let signature_key = [vec![0x20], key.verification_key().to_vec()].concat();
    let credential = [vec![0x00, 0x01], opaque(requester.as_bytes())?].concat();
    let request = KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: uri(requester)?,
        target_user: uri(target_user)?,
        room_id: uri(room)?,
        acceptable_ciphersuites: vec![CipherSuite::tls_deserialize_exact([0x00, 0x01])?],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact([0x00, 0x00, 0x00])?,
        requester_signature_key: SignaturePublicKey::tls_deserialize_exact(&signature_key)?,
        requester_credential: Credential::tls_deserialize_exact(&credential)?,
    }
    .sign(&key)
    .context("signing the request")?
    .tls_serialize_detached()?;

    let body = client
        .key_material(target, target_user, request)
        .await
        .context("keyMaterial request")?;
    let response = KeyMaterialResponse::tls_deserialize_exact(&body[..])
        .context("decoding the KeyMaterialResponse")?;
    println!(
        "{target_user}: userStatus {:?}, userUri {}, {} client(s)",
        response.user_status,
        response.user_uri.as_str(),
        response.clients.len()
    );
    ensure!(
        response.user_uri.as_str() == target_user,
        "userUri is not the target user"
    );
    let client_prefix = format!("mimi://{target}/d/");
    let mut ok = response.user_status == KeyMaterialUserCode::Success;
    for entry in &response.clients {
        match entry {
            ClientKeyMaterial::Success {
                client_uri,
                key_package,
            } => match key_package.verify(SystemTime::now()) {
                Ok(info) => {
                    let names_user = info.identity() == Some(target_user.as_bytes());
                    let local_client = client_uri.as_str().starts_with(&client_prefix);
                    ok &= names_user && local_client;
                    println!(
                        "  {} success: KeyPackage verifies, ref {}, identity {}, {}, \
                         not_after {}",
                        client_uri.as_str(),
                        hex(info.reference().as_bytes()),
                        if names_user {
                            "is the user"
                        } else {
                            "IS NOT THE USER"
                        },
                        if info.is_last_resort() {
                            "last-resort"
                        } else {
                            "one-time"
                        },
                        info.not_after()
                    );
                }
                Err(error) => {
                    ok = false;
                    println!(
                        "  {} success but the KeyPackage FAILS verify: {error}",
                        client_uri.as_str()
                    );
                }
            },
            other => {
                ok = false;
                println!("  {other:?}");
            }
        }
    }
    ensure!(ok, "not a full success");
    Ok(())
}
