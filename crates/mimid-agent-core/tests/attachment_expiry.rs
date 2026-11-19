//! The `expires` of a sent attachment's ExternalPart (bead
//! mimid-1wgh.14.6), through a real mimid server: alice sends bob a file,
//! once from a server that advertises `assetLifetime` and once from one
//! that does not.
//!
//! Oracles:
//!
//! - draft-atwood-jmap-chat-mimi-00 §Account-Level Capability Object
//!   (jmap-chat-spec 120db2c): a client MAY set `expires` to the upload
//!   time plus `assetLifetime`; mimi-content-10 §4.5: `expires` is
//!   seconds since the UNIX epoch, 0 if the content does not expire.
//! - The upload time is bracketed by the test's own clock read before
//!   the send and after it.
//! - The ExternalPart is read from the MLS `application_data` bob
//!   received, decoded here with `MimiContent::decode`, not from the
//!   agent's own decoding; and the file bob fetches is the one sent.

#![forbid(unsafe_code)]

mod common;

use std::time::SystemTime;

use common::{ALICE, BOB, device, poll_until, server_with};
use mimid_agent_core::{Event, HostOptions, MimiContent, OutgoingAttachment};
use mimid_server::jmap::JmapOptions;

/// A lifetime no default uses: 2 hours and 1 second.
const LIFETIME: u64 = 7_201;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// alice sends bob a file through a server with `options`; the `expires`
/// of the ExternalPart bob receives, and the send's start and end times.
async fn sent_expiry(options: JmapOptions) -> (u32, u64, u64) {
    let dir = tempfile::tempdir().unwrap();
    let server = server_with(dir.path(), &[ALICE, BOB], options).await;
    let mut alice = device(&server, ALICE, dir.path(), "alice").await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;
    for agent in [&mut alice, &mut bob] {
        agent.publish_key_packages(1).await.unwrap();
    }
    let room = alice.host_room(&HostOptions::named("files")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let number = poll_until(&mut bob, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    assert_eq!(bob.join(number).unwrap(), room);

    let file = OutgoingAttachment {
        content: b"%PDF-1.7 not really".to_vec(),
        content_type: "application/pdf".to_owned(),
        filename: "report.pdf".to_owned(),
    };
    let before = now();
    alice
        .send_message(&room, "", std::slice::from_ref(&file))
        .await
        .unwrap();
    let after = now();
    let got = poll_until(&mut bob, |e| match e {
        Event::Message(m) if m.room == room => Some(m.clone()),
        _ => None,
    })
    .await;
    assert_eq!(got.sender, ALICE);
    let content = MimiContent::decode(&got.application_data).unwrap();
    let mimi_content::Part::External(part) = &content.nested_part.part else {
        panic!("one attachment without text is sent on its own: {content:?}");
    };
    assert_eq!(part.filename, "report.pdf");
    // The URL still works, and serves the file sent.
    assert_eq!(
        bob.fetch_attachment(&room, part).await.unwrap(),
        file.content
    );
    (part.expires, before, after)
}

#[tokio::test]
async fn expires_is_the_upload_time_plus_the_servers_asset_lifetime() {
    let mut options = JmapOptions::default();
    options.asset_lifetime = Some(LIFETIME);
    let (expires, before, after) = sent_expiry(options).await;
    let expires = u64::from(expires);
    assert!(
        (before + LIFETIME..=after + LIFETIME).contains(&expires),
        "expires {expires} not in [{before}, {after}] + {LIFETIME}"
    );
}

#[tokio::test]
async fn without_an_asset_lifetime_the_part_does_not_expire() {
    let (expires, _, _) = sent_expiry(JmapOptions::default()).await;
    assert_eq!(expires, 0);
}
