//! Tailnet identity (docs/design/frontend-auth.md §4.6, decision A7; bead
//! mimid-e13m.12): a connection from a matching tailnet node registers on
//! IRC with no credential, is told so in CAP and ISUPPORT, and loses its
//! session when the node stops matching.
//!
//! The tests drive a **fake tailscaled**: a Unix socket answering the two
//! LocalAPI paths the agent asks for, with the JSON shapes §4.6 cites.
//! Nothing here reaches a real tailnet, so the tests are offline like
//! every other (AGENTS.md).

#![forbid(unsafe_code)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use common::irc::Irc;
use common::{ALICE, BOB, Running, config, server};
use serde_json::{Value, json};

/// A fake tailscaled: it answers `GET /localapi/v0/status` and
/// `/localapi/v0/whois?...` from what the test put in it, as HTTP/1.0 with
/// the connection closed after, which is what `tls::localapi_get` reads.
struct FakeTailscaled {
    socket: PathBuf,
    answers: Arc<Mutex<Answers>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct Answers {
    status: Value,
    whois: Option<Value>,
    /// How many `whois` calls arrived, so a test can see the recheck.
    whois_calls: usize,
}

impl FakeTailscaled {
    /// Listens on a socket under `dir`, answering `status` and, until a
    /// test changes it, `whois`.
    async fn start(dir: &Path, status: Value, whois: Option<Value>) -> Self {
        let socket = dir.join("tailscaled.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let answers = Arc::new(Mutex::new(Answers {
            status,
            whois,
            whois_calls: 0,
        }));
        let task = tokio::spawn({
            let answers = Arc::clone(&answers);
            async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let answers = Arc::clone(&answers);
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut request = vec![0u8; 4096];
                        let read = stream.read(&mut request).await.unwrap_or(0);
                        let head = String::from_utf8_lossy(&request[..read]).to_string();
                        let body = {
                            let mut answers =
                                answers.lock().unwrap_or_else(PoisonError::into_inner);
                            if head.contains("/localapi/v0/status") {
                                Some(answers.status.clone())
                            } else if head.contains("/localapi/v0/whois") {
                                answers.whois_calls += 1;
                                answers.whois.clone()
                            } else {
                                None
                            }
                        };
                        let answer = match body {
                            Some(value) => {
                                let text = value.to_string();
                                format!(
                                    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{text}"
                                )
                            }
                            // What tailscaled answers for an address it
                            // knows no node for.
                            None => "HTTP/1.0 404 Not Found\r\n\r\nno node".to_owned(),
                        };
                        let _ = stream.write_all(answer.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            }
        });
        Self {
            socket,
            answers,
            task,
        }
    }

    /// What `whois` answers from now on; `None` for "no such node", which
    /// is what removing a node from the tailnet looks like.
    fn set_whois(&self, whois: Option<Value>) {
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .whois = whois;
    }

    fn whois_calls(&self) -> usize {
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .whois_calls
    }
}

impl Drop for FakeTailscaled {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `status` for a node of alice's that is not tagged.
fn status() -> Value {
    json!({
        "Self": {"ID": "nSELF", "UserID": 7, "Tags": []},
        "User": {"7": {"LoginName": "alice@github", "DisplayName": "Alice"}},
    })
}

/// `whois` for alice's own phone: untagged, routing nothing.
fn alices_phone() -> Value {
    json!({
        "Node": {
            "Name": "pixel-8.tailnet.ts.net.",
            "StableID": "nPIXEL",
            "Addresses": ["100.64.1.9/32"],
            "AllowedIPs": ["100.64.1.9/32"],
        },
        "UserProfile": {"LoginName": "alice@github"},
    })
}

/// alice's configuration with IRC and tailnet identity against `fake`.
fn with_tailnet(
    dir: &Path,
    server: &common::Server,
    fake: &FakeTailscaled,
    recheck_s: u64,
) -> mimid_agent::Config {
    let mut config = config(server, ALICE, dir, "from-allowed");
    config.irc = Some(mimid_agent::config::IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..mimid_agent::config::IrcSetting::default()
    });
    config.tailnet = mimid_agent::tailnet::TailnetSetting {
        identity: true,
        socket: fake.socket.clone(),
        recheck_s,
        ..mimid_agent::tailnet::TailnetSetting::default()
    };
    config
}

/// Oracle: docs/design/frontend-auth.md §4.6: a connection from the
/// owner's own node registers with no credential at all, and the agent
/// does not ask for one — no `soju.im/account-required` in CAP LS and no
/// `draft/ACCOUNTREQUIRED` in ISUPPORT, which is what makes Goguma label
/// its password field optional instead of demanding one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_matching_node_registers_with_no_credential() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeTailscaled::start(dir.path(), status(), Some(alices_phone())).await;
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_tailnet(dir.path(), &server, &fake, 3600)).await;
    let addr = alice.irc.unwrap();

    let mut irc = Irc::connect(addr).await;
    irc.send("CAP LS 302").await;
    let caps = irc.until_command("CAP").await.raw.clone();
    assert!(
        !caps.contains("account-required"),
        "a matched node is not told an account is required: {caps}"
    );
    assert!(caps.contains("sasl=PLAIN"), "{caps}");
    irc.send("CAP END").await;
    // No PASS and no SASL: the node is the login.
    irc.send("NICK alice").await;
    irc.send("USER alice 0 * :x").await;
    let welcome = irc.until_command("001").await;
    assert!(welcome.raw.contains("Welcome"), "{}", welcome.raw);
    let mut isupport = String::new();
    for _ in 0..4 {
        let line = irc.until_command("005").await;
        isupport.push_str(&line.raw);
        if line.raw.contains("CLIENTTAGDENY") {
            break;
        }
    }
    assert!(
        !isupport.contains("ACCOUNTREQUIRED"),
        "a matched node is not told an account is required: {isupport}"
    );

    // `/msg mimid tailnet` says which node and rule let it in.
    irc.send("PRIVMSG mimid :tailnet").await;
    let notice = irc.until_command("NOTICE").await;
    assert!(
        notice.raw.contains("pixel-8.tailnet.ts.net") && notice.raw.contains("alice@github"),
        "{}",
        notice.raw
    );
    alice.stop().await;
}

/// Oracle: §4.6: "any PASS or SASL PLAIN succeeds" from a matched node,
/// so a client that kept an old password in its settings still gets in
/// rather than being refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_matching_node_may_send_any_credential() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeTailscaled::start(dir.path(), status(), Some(alices_phone())).await;
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_tailnet(dir.path(), &server, &fake, 3600)).await;
    let addr = alice.irc.unwrap();

    // A wrong PASS: accepted, because the node is what authorizes.
    let mut irc = Irc::connect(addr).await;
    irc.send("PASS :aaaa-aaaa-aaaa-aaaa").await;
    irc.send("NICK alice").await;
    irc.send("USER alice 0 * :x").await;
    irc.until_command("001").await;

    // A wrong SASL PLAIN: 903, not 904, so the client finishes SASL.
    let mut sasl = Irc::connect(addr).await;
    sasl.send("CAP REQ :sasl").await;
    sasl.send("AUTHENTICATE PLAIN").await;
    sasl.until_command("AUTHENTICATE").await;
    sasl.send(&format!(
        "AUTHENTICATE {}",
        common::b64(b"\0alice\0aaaa-aaaa-aaaa-aaaa")
    ))
    .await;
    sasl.until_command("903").await;
    sasl.send("CAP END").await;
    sasl.send("NICK alice").await;
    sasl.send("USER alice 0 * :x").await;
    sasl.until_command("001").await;

    // A right credential still works, and then it is an ordinary
    // session: `tailnet` says the node matched but did not log it in.
    let (_, password) = alice.store_credentials().add("phone", "cli").unwrap();
    let mut with_password = Irc::connect(addr).await;
    with_password
        .send(&format!("PASS :{}", password.shown()))
        .await;
    with_password.send("NICK alice").await;
    with_password.send("USER alice 0 * :x").await;
    with_password.until_command("001").await;
    with_password.send("PRIVMSG mimid :tailnet").await;
    let notice = with_password.until_command("NOTICE").await;
    assert!(
        notice.raw.contains("logged in with a credential"),
        "{}",
        notice.raw
    );
    alice.stop().await;
}

/// Oracle: §4.6: the node is asked about again every `recheck_s`, and a
/// session let in by a node that no longer matches closes. This is the
/// only revocation tailnet identity has: removing the node in the admin
/// console.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_closes_when_its_node_stops_matching() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeTailscaled::start(dir.path(), status(), Some(alices_phone())).await;
    let server = server(dir.path(), &[ALICE, BOB]).await;
    // The least recheck the configuration allows, so the test waits
    // seconds rather than minutes.
    let recheck = mimid_agent::tailnet::MIN_RECHECK_SECS;
    let alice = Running::start(&with_tailnet(dir.path(), &server, &fake, recheck)).await;

    let mut irc = Irc::connect(alice.irc.unwrap()).await;
    irc.send("NICK alice").await;
    irc.send("USER alice 0 * :x").await;
    irc.until_command("001").await;
    let before = fake.whois_calls();
    assert!(before >= 1, "the connection was identified once");

    // The node leaves the tailnet.
    fake.set_whois(None);
    let closed = tokio::time::timeout(std::time::Duration::from_secs(recheck * 3), async {
        irc.closes().await
    })
    .await
    .expect("the connection closes within a few rechecks");
    assert!(closed, "the connection closed");
    assert!(
        fake.whois_calls() > before,
        "the node was asked about again: {} then {}",
        before,
        fake.whois_calls()
    );
    alice.stop().await;
}

/// Oracle: §4.6: a node tailscaled knows nothing about falls back to the
/// password rules, and a failed WhoIs never lets a connection in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_node_falls_back_to_the_password() {
    let dir = tempfile::tempdir().unwrap();
    // tailscaled answers `status`, so the daemon starts, but knows no
    // node for the peer.
    let fake = FakeTailscaled::start(dir.path(), status(), None).await;
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_tailnet(dir.path(), &server, &fake, 3600)).await;
    let addr = alice.irc.unwrap();

    // No credential: refused, with the account-required answer, as with
    // tailnet identity off.
    let mut irc = Irc::connect(addr).await;
    irc.send("CAP REQ :sasl").await;
    irc.send("CAP END").await;
    irc.send("NICK alice").await;
    irc.send("USER alice 0 * :x").await;
    let refused = irc.until_command("FAIL").await;
    assert!(refused.raw.contains("ACCOUNT_REQUIRED"), "{}", refused.raw);
    assert!(irc.closes().await);

    // The token still works.
    let (mut good, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;
    good.send("PRIVMSG mimid :tailnet").await;
    let notice = good.until_command("NOTICE").await;
    assert!(notice.raw.contains("did not match"), "{}", notice.raw);
    alice.stop().await;
}

/// Oracle: §4.6: identity on with a tailscaled that cannot be reached is
/// a start failure, not a silent fall back to the password rules, so an
/// operator never believes identity is on when it is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_without_tailscaled_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut config = config(&server, ALICE, dir.path(), "from-allowed");
    config.irc = Some(mimid_agent::config::IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..mimid_agent::config::IrcSetting::default()
    });
    config.tailnet = mimid_agent::tailnet::TailnetSetting {
        identity: true,
        socket: dir.path().join("not-a-socket"),
        ..mimid_agent::tailnet::TailnetSetting::default()
    };
    let failed = mimid_agent::Daemon::start(&config).await;
    assert!(
        matches!(failed, Err(mimid_agent::StartError::Tls(_))),
        "{:?}",
        failed.map(|_| ())
    );
}

/// Oracle: §4.6 and the `[tailnet]` table: the setting is checked before
/// anything starts — a bad tag, too small a recheck, and identity with no
/// IRC front end to apply it to.
#[test]
fn the_tailnet_table_is_checked() {
    let base = r#"
        server_url = "http://127.0.0.1:1"
        user_uri = "mimi://a.example/u/alice"
        token_file = "/nonexistent"
        state_dir = "/nonexistent"
        listen = "127.0.0.1:0"
    "#;
    let irc = "[irc]\nlisten = \"127.0.0.1:6667\"\n";
    for bad in [
        // A node name in the tags list, which would never match.
        format!("{irc}[tailnet]\nidentity = true\ntags = [\"phone\"]\n"),
        // A recheck that would ask tailscaled constantly.
        format!("{irc}[tailnet]\nidentity = true\nrecheck_s = 1\n"),
        // Identity with nothing to apply it to: JMAP keeps its
        // credential, so without [irc] it does nothing.
        "[tailnet]\nidentity = true\n".to_owned(),
    ] {
        let refused = mimid_agent::Config::parse(&format!("{base}\n{bad}"));
        assert!(
            matches!(refused, Err(mimid_agent::ConfigError::Tailnet(_))),
            "{bad:?} gave {refused:?}"
        );
    }
    // Off by default, and off needs no [irc].
    let off = mimid_agent::Config::parse(base).unwrap();
    assert!(!off.tailnet.identity);
    assert_eq!(
        off.tailnet.recheck_s,
        mimid_agent::tailnet::DEFAULT_RECHECK_SECS
    );
    let on = mimid_agent::Config::parse(&format!(
        "{base}\n{irc}[tailnet]\nidentity = true\n\
         owners = [\"alice@github\"]\ntags = [\"tag:chat\"]\n"
    ))
    .expect("identity with [irc] is accepted");
    assert!(on.tailnet.identity);
    assert_eq!(on.tailnet.owners, ["alice@github"]);
}

/// Oracle: §4.6: a tagged own node has no owner to default to, so
/// identity stays off until `owners` is set, and so does a node whose id
/// tailscaled does not give (the own-node exclusion compares it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tagged_or_nameless_own_node_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    for status in [
        // Tagged: no owner.
        json!({"Self": {"ID": "nSELF", "UserID": 0, "Tags": ["tag:server"]}, "User": {}}),
        // No id: the own-node exclusion could not work.
        json!({"Self": {"UserID": 7}, "User": {"7": {"LoginName": "alice@github"}}}),
        // No owner at all.
        json!({"Self": {"ID": "nSELF", "UserID": 7}, "User": {}}),
    ] {
        let fake_dir = tempfile::tempdir_in(dir.path()).unwrap();
        let fake = FakeTailscaled::start(fake_dir.path(), status.clone(), None).await;
        let setting = mimid_agent::tailnet::TailnetSetting {
            identity: true,
            socket: fake.socket.clone(),
            ..mimid_agent::tailnet::TailnetSetting::default()
        };
        assert!(
            mimid_agent::tailnet::Tailnet::start(&setting)
                .await
                .is_err(),
            "{status} should refuse to start"
        );
    }
    // With `owners` set, a tagged own node is fine: the operator said
    // whose devices to let in.
    let fake_dir = tempfile::tempdir_in(dir.path()).unwrap();
    let fake = FakeTailscaled::start(
        fake_dir.path(),
        json!({"Self": {"ID": "nSELF", "Tags": ["tag:server"]}, "User": {}}),
        None,
    )
    .await;
    let setting = mimid_agent::tailnet::TailnetSetting {
        identity: true,
        owners: vec!["alice@github".to_owned()],
        socket: fake.socket.clone(),
        ..mimid_agent::tailnet::TailnetSetting::default()
    };
    assert!(mimid_agent::tailnet::Tailnet::start(&setting).await.is_ok());
}
