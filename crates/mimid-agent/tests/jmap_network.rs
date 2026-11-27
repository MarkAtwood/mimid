//! JMAP over the network (docs/design/frontend-auth.md §4.2, §5.3, §9 step
//! 6; bead mimid-e13m.6): the HTTPS listener of `[jmap] listen_tls`, HTTP
//! Basic beside Bearer, and the agent's own `AppPassword` methods.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, BOB, Running, config, fixture, server};
use serde_json::{Value, json};

/// alice's configuration with an HTTPS listener on 127.0.0.1 and the test
/// certificate from files, whose names cover `localhost`.
fn with_https(dir: &std::path::Path, server: &common::Server) -> mimid_agent::Config {
    let mut config = config(server, ALICE, dir, "from-allowed");
    config.jmap.listen_tls = Some("127.0.0.1:0".parse().unwrap());
    config.tls = Some(mimid_agent::tls::TlsSetting {
        source: mimid_agent::tls::TlsSource::Files,
        names: vec!["localhost".to_owned()],
        files: Some(mimid_agent::tls::TlsFiles {
            cert: fixture("server.pem"),
            key: fixture("server.key"),
        }),
        tailscale: None,
        local_ca: None,
        acme: None,
    });
    config
}

/// A client trusting only the test CA, as a stock JMAP client with the
/// certificate installed would be.
fn https_client() -> reqwest::Client {
    let ca = std::fs::read(fixture("ca.pem")).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .build()
        .unwrap()
}

/// `base64(user:secret)`, as RFC 7617 wants it.
fn basic(user: &str, secret: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}"))
    )
}

/// Oracle: docs/design/frontend-auth.md §4.2 and §5.3. The HTTPS listener
/// serves the same endpoint over TLS; its Session carries `https:` URLs
/// under the certificate's name, so a client off this machine is given
/// URLs it can reach; a credential is still required; and the Host check
/// takes the certificate's names at that port and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_https_listener_serves_the_session_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_https(dir.path(), &server)).await;
    let token = alice.token();
    let base = alice.https_base();
    let client = https_client();

    let response = client
        .get(format!("{base}/.well-known/jmap"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let session: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    // The URLs are the TLS listener's own, not the loopback listener's:
    // this is the whole point of the second Session.
    for url in ["apiUrl", "uploadUrl", "downloadUrl", "eventSourceUrl"] {
        let value = session[url].as_str().unwrap_or_default();
        assert!(
            value.starts_with(&base),
            "{url} is {value}, not under {base}"
        );
    }
    // RFC 8887 §3: a TLS endpoint's socket URL is wss:.
    let socket = session["capabilities"]["urn:ietf:params:jmap:websocket"]["url"]
        .as_str()
        .unwrap();
    assert!(socket.starts_with("wss://"), "{socket}");
    // The agent's own capability is advertised on both listeners.
    assert!(
        session["capabilities"]["tag:reviewcommit.com,2026:mimid:app-passwords"].is_object(),
        "{session}"
    );

    // Still a credential per request, TLS or not.
    let refused = client
        .get(format!("{base}/.well-known/jmap"))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 401);

    // The Host check: a name the certificate does not cover is 421, even
    // over a handshake that succeeded (the certificate covers 127.0.0.1
    // too, so the request reaches the guard).
    let misdirected = client
        .get(format!(
            "https://127.0.0.1:{}/.well-known/jmap",
            alice.https.unwrap().port()
        ))
        .header(reqwest::header::HOST, "evil.example")
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(misdirected.status(), 421);

    // The plain loopback listener is unchanged and still http.
    let response = reqwest::Client::new()
        .get(format!("{}/.well-known/jmap", alice.base()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let plain: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(plain["apiUrl"].as_str().unwrap().starts_with("http://"));
    alice.stop().await;
}

/// Oracle: docs/design/frontend-auth.md §4.2: HTTP Basic carries any
/// username and the credential as the password, so a "username and
/// password" client logs in; the `401` offers `Basic` back only to a
/// request that used it, so a browser that sent a bearer token is not
/// given its own login box.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn basic_credentials_log_in_and_only_basic_is_challenged_back() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "from-allowed")).await;
    let token = alice.token();
    let (_, password) = alice.store_credentials().add("pidgin", "cli").unwrap();
    let shown = password.shown().to_owned();
    let get = async |authorization: String| {
        reqwest::Client::new()
            .get(format!("{}/.well-known/jmap", alice.base()))
            .header(reqwest::header::AUTHORIZATION, authorization)
            .send()
            .await
            .unwrap()
    };

    // Any username, including the one the agent would suggest, one it
    // would not, and none at all (§3.5).
    for user in ["alice", "whoever", "", "alice/mimid@phone"] {
        assert_eq!(
            get(basic(user, &shown)).await.status(),
            200,
            "user {user:?}"
        );
    }
    // The agent token works under Basic too (§3.4).
    assert_eq!(get(basic("alice", &token)).await.status(), 200);
    // Any spelling of the app password (§3.2).
    assert_eq!(
        get(basic("alice", &shown.replace('-', ""))).await.status(),
        200
    );

    // A wrong secret under Basic: 401, and the challenge offers Basic.
    let refused = get(basic("alice", "aaaa-aaaa-aaaa-aaaa")).await;
    assert_eq!(refused.status(), 401);
    let challenges: Vec<&str> = refused
        .headers()
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert!(challenges.contains(&"Bearer"), "{challenges:?}");
    assert!(
        challenges.iter().any(|c| c.starts_with("Basic realm=")),
        "{challenges:?}"
    );

    // A wrong bearer token: 401, and no Basic challenge, so a browser
    // does not pop up its own login box over the client's.
    let refused = get("Bearer wrong".to_owned()).await;
    assert_eq!(refused.status(), 401);
    let challenges: Vec<&str> = refused
        .headers()
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(challenges, ["Bearer"]);

    // A revoked credential stops working under Basic as under Bearer.
    // Revoked by another connection, as the CLI does, so it reaches the
    // daemon's bearer cache with its recheck (§3.6, §3.7): a request
    // whose secret is cached takes no database read, which is why this
    // waits rather than asserting at once.
    // The cache's own clock is the event here: an entry is rechecked
    // `CREDENTIAL_RECHECK` after it was cached, and nothing publishes
    // when it falls due. One sleep past that, then one request, rather
    // than a request every hundred milliseconds until a deadline: the
    // assertion is on the answer after the recheck is due.
    alice.store_credentials().revoke("pidgin", "cli").unwrap();
    tokio::time::sleep(mimid_agent::CREDENTIAL_RECHECK + std::time::Duration::from_millis(100))
        .await;
    let refused = get(basic("alice", &shown)).await.status().as_u16();
    assert_eq!(refused, 401, "the revoked password is refused under Basic");
    alice.stop().await;
}

/// Oracle: docs/design/frontend-auth.md §3.6 and decision mimid-1wgh.126:
/// a JMAP client lists, adds and revokes credentials, the new secret comes
/// back once and works, and a revoked one stops working. This is the third
/// place §3.6 requires, beside the CLI and `/msg mimid`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_passwords_are_listed_added_and_revoked_over_jmap() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "from-allowed")).await;
    let client = alice.client().await;
    let capability = "tag:reviewcommit.com,2026:mimid:app-passwords";

    // Only the agent token is there at first, and it is listed.
    let listed = client
        .call_using(&[capability], "AppPassword/get", json!({}))
        .await;
    let list = listed["list"].as_array().unwrap();
    assert_eq!(list.len(), 1, "{listed}");
    assert_eq!(list[0]["name"], "agent-token");
    assert_eq!(list[0]["kind"], "agent-token");
    assert!(list[0]["secret"].is_null(), "a listing never has a secret");
    let state = listed["state"].as_str().unwrap().to_owned();

    // Added: the secret comes back once, and it works.
    let created = client
        .call_using(
            &[capability],
            "AppPassword/set",
            json!({"create": {"new": {"name": "phone"}}}),
        )
        .await;
    assert_eq!(created["notCreated"], json!({}), "{created}");
    let made = &created["created"]["new"];
    let secret = made["secret"].as_str().unwrap().to_owned();
    let id = made["id"].as_str().unwrap().to_owned();
    assert_eq!(made["name"], "phone");
    assert_eq!(made["kind"], "app-password");
    assert_eq!(made["createdBy"], "jmap");
    assert!(made["lastUsedAt"].is_null());
    assert_ne!(
        created["newState"].as_str().unwrap(),
        state,
        "the state moved"
    );
    assert_eq!(
        reqwest::Client::new()
            .get(format!("{}/.well-known/jmap", alice.base()))
            .bearer_auth(&secret)
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "the new password works"
    );

    // Named ids, and one that is not there.
    let fetched = client
        .call_using(
            &[capability],
            "AppPassword/get",
            json!({"ids": [id, "c99999"]}),
        )
        .await;
    assert_eq!(fetched["list"].as_array().unwrap().len(), 1, "{fetched}");
    assert_eq!(fetched["notFound"], json!(["c99999"]));

    // No property is writable, and the agent token cannot be destroyed.
    let refused = client
        .call_using(
            &[capability],
            "AppPassword/set",
            json!({"update": {&id: {"name": "laptop"}}}),
        )
        .await;
    assert_eq!(refused["notUpdated"][&id]["type"], "forbidden", "{refused}");
    let token_id = list[0]["id"].as_str().unwrap().to_owned();
    let refused = client
        .call_using(
            &[capability],
            "AppPassword/set",
            json!({"destroy": [&token_id]}),
        )
        .await;
    assert_eq!(
        refused["notDestroyed"][&token_id]["type"], "forbidden",
        "{refused}"
    );
    // A name that is not a name, and one already taken.
    let refused = client
        .call_using(
            &[capability],
            "AppPassword/set",
            json!({"create": {"bad": {"name": "Phone!"}, "dup": {"name": "phone"}}}),
        )
        .await;
    assert_eq!(refused["notCreated"]["bad"]["type"], "invalidProperties");
    assert_eq!(refused["notCreated"]["dup"]["type"], "invalidProperties");
    // Nothing but `name`: the agent makes the secret.
    let refused = client
        .call_using(
            &[capability],
            "AppPassword/set",
            json!({"create": {"mine": {"name": "laptop", "secret": "hunter2"}}}),
        )
        .await;
    assert_eq!(refused["notCreated"]["mine"]["type"], "invalidProperties");

    // Revoked from JMAP: the secret stops working, and the row stays
    // listed as revoked, as the CLI lists it.
    let destroyed = client
        .call_using(&[capability], "AppPassword/set", json!({"destroy": [&id]}))
        .await;
    assert_eq!(destroyed["destroyed"], json!([&id]), "{destroyed}");
    assert_eq!(
        reqwest::Client::new()
            .get(format!("{}/.well-known/jmap", alice.base()))
            .bearer_auth(&secret)
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "the revoked password is refused"
    );
    let listed = client
        .call_using(&[capability], "AppPassword/get", json!({}))
        .await;
    let revoked = listed["list"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id.as_str())
        .expect("the revoked row is still listed");
    assert!(!revoked["revokedAt"].is_null(), "{revoked}");
    alice.stop().await;
}

/// Oracle: bead mimid-036n, and `Daemon::serve`'s contract: when `serve`
/// returns, everything has stopped, so the state directory can be opened
/// again at once. The programs that embed mimid-agent-store in their own
/// process (purple-mimi, the mobile app of decision mimid-1wgh.39) are
/// exactly the callers that stop a daemon and start another on the same
/// directory, and an intermittent `Locked` is what they would see.
///
/// This is a contract test, not a regression test: the bug it belongs to
/// is a race, and on a healthy machine it does not lose. It was seen
/// twice, both times on a volume with no free space, where the I/O under
/// teardown widened the window; without the fix this test passes anyway.
/// The failing proof is in axum 0.8.9's source instead: `handle_connection`
/// drops its `close_rx` as its last statement, but the connection's
/// service clone, which holds the store and so the lock, drops with the
/// task's future, after `close_tx.closed()` has already let `serve`
/// return. `StateLock::release` makes the contract hold whatever the drop
/// order turns out to be. No test fails before that fix, which AGENTS.md
/// asks for: the mechanism in axum's source is the whole evidence, and
/// this test and `mimid_agent_core::lock`'s
/// `releasing_frees_the_lock_while_a_clone_is_still_alive` guard the
/// contract from here on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_state_directory_can_be_reopened_as_soon_as_serve_returns() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let config = config(&server, ALICE, dir.path(), "from-allowed");
    let alice = Running::start(&config).await;
    // A client whose connection is still pooled and open when the daemon
    // stops, which is the shape the failure was first seen in
    // (tests/jmap_seed.rs): the connection task is then alive at
    // shutdown and tears down in the window.
    let client = alice.client().await;
    client.get("Chat", None).await;
    client.get("Message", None).await;
    alice.stop().await;

    // No sleep: `serve` has returned, so the lock is free. The daemon is
    // dropped at once, so nothing here holds a lock of its own.
    match mimid_agent::Daemon::start(&config).await {
        Ok(daemon) => drop(daemon),
        Err(error) => {
            panic!("the state directory was still locked after serve returned: {error:?}")
        }
    }
}

/// Oracle: docs/design/frontend-auth.md §7.1: on the network listener, a
/// source that keeps getting it wrong is answered more slowly, and the
/// answer is still the protocol's own `401` rather than a silent drop. A
/// success from that source forgets the failures.
///
/// The source here is loopback, which §7.1 counts with the higher
/// threshold of [`LOOPBACK_FAILURES`] so that a local script in a loop
/// does not slow the user's own clients; the test therefore has to get it
/// wrong that many times before the delay starts. A non-loopback source
/// cannot be presented offline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_credentials_are_answered_more_slowly_on_the_network_listener() {
    use mimid_agent_store::credentials::limits::{FIRST_DELAY, LOOPBACK_FAILURES};
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_https(dir.path(), &server)).await;
    let base = alice.https_base();
    let client = https_client();
    let wrong = async || {
        client
            .get(format!("{base}/.well-known/jmap"))
            .bearer_auth("aaaa-aaaa-aaaa-aaaa")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    };

    // Up to the threshold: refused at once.
    for _ in 0..LOOPBACK_FAILURES {
        assert_eq!(wrong().await, 401);
    }
    // Past it: still a 401, and not before the first delay.
    let began = std::time::Instant::now();
    assert_eq!(wrong().await, 401, "a slowed source still gets a clear 401");
    let waited = began.elapsed();
    assert!(
        waited >= FIRST_DELAY,
        "the answer came after {waited:?}, sooner than {FIRST_DELAY:?}"
    );

    // A success forgets the source's failures, so the next wrong one is
    // answered at once again.
    assert_eq!(
        client
            .get(format!("{base}/.well-known/jmap"))
            .bearer_auth(alice.token())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let began = std::time::Instant::now();
    assert_eq!(wrong().await, 401);
    assert!(
        began.elapsed() < FIRST_DELAY,
        "a success resets the source's count"
    );
    alice.stop().await;
}

/// Oracle: docs/design/frontend-auth.md §5.3 and client-survey.md S1: an
/// HTTPS listener needs `[tls]`, and a JMAP listener needs JMAP on.
#[test]
fn a_jmap_tls_listener_needs_tls_and_jmap_on() {
    let base = r#"
        server_url = "http://127.0.0.1:1"
        user_uri = "mimi://a.example/u/alice"
        token_file = "/nonexistent"
        state_dir = "/nonexistent"
        listen = "127.0.0.1:0"
    "#;
    let refused = mimid_agent::Config::parse(&format!(
        "{base}\n[jmap]\nlisten_tls = \"100.64.1.2:8448\"\n"
    ));
    assert!(
        matches!(refused, Err(mimid_agent::ConfigError::NoTls(_))),
        "{refused:?}"
    );
    let tls = "[tls]\nsource = \"files\"\nnames = [\"chat.example.org\"]\n\
               [tls.files]\ncert = \"/nonexistent\"\nkey = \"/nonexistent\"\n";
    let refused = mimid_agent::Config::parse(&format!(
        "{base}\n[irc]\nlisten = \"127.0.0.1:6667\"\n\
         [jmap]\nenabled = false\nlisten_tls = \"100.64.1.2:8448\"\n{tls}"
    ));
    assert!(
        matches!(refused, Err(mimid_agent::ConfigError::JmapOff(_))),
        "{refused:?}"
    );
    let ok = mimid_agent::Config::parse(&format!(
        "{base}\n[jmap]\nlisten_tls = \"100.64.1.2:8448\"\n{tls}"
    ))
    .expect("an HTTPS listener with [tls] is accepted");
    assert_eq!(ok.jmap.listen_tls, Some("100.64.1.2:8448".parse().unwrap()));
    // The plain HTTP listener still refuses to leave loopback: off
    // loopback, JMAP goes over TLS (decision S1).
    let refused = mimid_agent::Config::parse(
        r#"
        server_url = "http://127.0.0.1:1"
        user_uri = "mimi://a.example/u/alice"
        token_file = "/nonexistent"
        state_dir = "/nonexistent"
        listen = "100.64.1.2:8484"
    "#,
    );
    assert!(
        matches!(refused, Err(mimid_agent::ConfigError::NotLoopback(_))),
        "{refused:?}"
    );
}
