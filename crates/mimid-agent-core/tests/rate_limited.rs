//! `rateLimited` with `retryAfter` (draft-atwood-jmap-chat-mimi-00
//! §capability, jmap-chat-spec 43ee02c; bead mimid-e64f.21): the agent
//! waits as the server says and calls again, instead of failing, on JMAP
//! and on the live stream.
//!
//! Oracle: the draft's "A client that receives `rateLimited` waits before
//! it calls again, at least `retryAfter` seconds when it is present", and
//! the limit the server was given: one KeyMaterial/fetch, then one each
//! 1.5 s, so the second invite waits `retryAfter` = 2 s.

mod common;

use std::time::{Duration, Instant};

use common::{ALICE, BOB, CAROL, Server, server_with};
use mimid_agent_core::{Agent, AgentConfig, Binding, DidWebvhConfig, HostOptions};
use mimid_server::jmap::JmapOptions;
use mimid_server::jmap::rate::RateLimit;

async fn device(
    server: &Server,
    user: &'static str,
    dir: &std::path::Path,
    binding: Binding,
) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(user.rsplit('/').next().unwrap()),
        full_tree_hubs: Vec::new(),
        did_webvh: DidWebvhConfig::default(),
    })
    .await
    .unwrap()
}

async fn invites_wait_out_the_limit(binding: Binding) {
    let dir = tempfile::tempdir().unwrap();
    let mut options = JmapOptions::default();
    options.live_stream = true;
    options.key_material_limit = Some(RateLimit {
        burst: 1,
        refill_ms: 1500,
    });
    let server = server_with(dir.path(), &[ALICE, BOB, CAROL], options).await;
    let mut alice = device(&server, ALICE, dir.path(), binding).await;
    for user in [BOB, CAROL] {
        device(&server, user, dir.path(), Binding::Jmap)
            .await
            .publish_key_packages(1)
            .await
            .unwrap();
    }
    let room = alice.host_room(&HostOptions::named("r")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let started = Instant::now();
    alice.invite(&room, CAROL).await.unwrap();
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "waited {:?}",
        started.elapsed()
    );
    let mut participants = alice.participants(&room).unwrap();
    participants.sort();
    assert_eq!(participants, [ALICE, BOB, CAROL]);
}

#[tokio::test]
async fn the_agent_waits_out_rate_limited_over_jmap() {
    invites_wait_out_the_limit(Binding::Jmap).await;
}

#[tokio::test]
async fn the_agent_waits_out_rate_limited_over_the_stream() {
    invites_wait_out_the_limit(Binding::Stream).await;
}
