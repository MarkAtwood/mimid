//! The `mimid-agent` binary's log (bead mimid-c90r). The daemon names its
//! INFO, WARN and ERROR events for a reader that queries them, as
//! mimid-server does, and until now printed them in the one format that
//! cannot show a name. With `MIMID_LOG_FORMAT=json` the binary writes one
//! JSON object per line, each with the event's name in `event`.
//!
//! The binary is started as a process, because what is under test is the
//! subscriber `main` installs and the signal handlers it installs beside
//! it: a test that builds a subscriber of its own would pass whatever
//! `main` did.
//!
//! One process is started, not one per property, because starting the
//! daemon is the expensive part: it opens its database and publishes
//! KeyPackages to the provider.
//!
//! Oracles: the agent's own `agent_listening` and `shutdown_requested`
//! call sites, and the event-identity policy of mimid-telemetry's
//! `logging` module -- every line of mimid's own targets above DEBUG
//! carries a name.

#![forbid(unsafe_code)]

mod common;

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use common::{ALICE, server};
use tokio::io::AsyncBufReadExt;
use tokio::process::{Child, Command};

/// The lines a stream of the agent has produced, and a signal for each
/// arrival, so waiting for one is an await and not a poll.
#[derive(Clone, Default)]
struct Lines {
    seen: Arc<Mutex<Vec<String>>>,
    arrived: Arc<tokio::sync::Notify>,
}

impl Lines {
    fn joined(&self) -> String {
        self.seen.lock().unwrap().join("\n")
    }
}

/// Reads `stream` into `lines`, waking a waiter on every line and once
/// more when the stream closes, so a waiter also learns that no further
/// line is coming. The pipe is registered with the reactor, so the task
/// is woken by epoll; nothing here sleeps.
fn read_lines(
    stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    lines: &Lines,
) -> tokio::task::JoinHandle<()> {
    let lines = lines.clone();
    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stream).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            lines.seen.lock().unwrap().push(line);
            lines.arrived.notify_waiters();
        }
        lines.arrived.notify_waiters();
    })
}

/// The `mimid-agent` process and what it wrote.
struct Agent {
    child: Child,
    stdout: Lines,
    stderr: Lines,
    readers: Vec<tokio::task::JoinHandle<()>>,
}

// No Drop: the command sets kill_on_drop, so the runtime signals the
// child and reaps it.

impl Agent {
    /// Starts the binary on `config` with `env`, and returns once it has
    /// written a line containing `line`.
    async fn start(config: &Path, env: &[(&str, &str)], line: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mimid-agent"))
            .kill_on_drop(true)
            .arg(config)
            .envs(env.iter().copied())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = Lines::default();
        let stderr = Lines::default();
        let readers = vec![
            read_lines(child.stdout.take().unwrap(), &stdout),
            read_lines(child.stderr.take().unwrap(), &stderr),
        ];
        let mut agent = Self {
            child,
            stdout,
            stderr,
            readers,
        };
        agent.wait_for(line).await;
        agent
    }

    /// Waits for a line containing `line`.
    ///
    /// Both outcomes are events: a line arriving wakes the reader task
    /// through epoll, and the process exiting wakes `Child::wait`
    /// through SIGCHLD. So there is no deadline to pick and nothing to
    /// poll. An agent that neither logs nor exits hangs the test, which
    /// is what it is.
    async fn wait_for(&mut self, line: &str) {
        loop {
            if self.logs().contains(line) {
                return;
            }
            // Registered before the check below, so a line that arrives
            // between the two still wakes this.
            let arrived = self.stdout.arrived.notified();
            let also = self.stderr.arrived.notified();
            tokio::select! {
                status = self.child.wait() => {
                    status.unwrap();
                    panic!("the agent exited before writing {line:?}:\n{}", self.logs());
                }
                () = arrived => {}
                () = also => {}
            }
        }
    }

    /// Sends SIGINT and waits for the exit.
    async fn interrupt(&mut self) -> std::process::ExitStatus {
        let pid = self.child.id().expect("the child is running").to_string();
        let killed = std::process::Command::new("kill")
            .args(["-INT", &pid])
            .status()
            .unwrap();
        assert!(killed.success());
        self.child.wait().await.unwrap()
    }

    fn logs(&self) -> String {
        format!("{}\n{}", self.stdout.joined(), self.stderr.joined())
    }

    /// Standard output once the agent has exited: all of it. Awaits the
    /// reader tasks, so every line the kernel had buffered is drained.
    async fn exited_stdout(&mut self) -> Vec<String> {
        for reader in self.readers.drain(..) {
            reader.await.unwrap();
        }
        std::mem::take(&mut *self.stdout.seen.lock().unwrap())
    }
}

/// Writes alice's configuration, against the in-process provider
/// `server_base` with `token`, and returns its path.
///
/// `[telemetry]` is there to put a line in the log before the daemon
/// starts, which is what lets the test signal the process during its
/// startup; every signal is off, so nothing is exported and nothing is
/// flushed at the exit.
fn config_file(dir: &Path, server_base: &str, token: &str) -> std::path::PathBuf {
    let token_file = dir.join("alice-server-token");
    std::fs::write(&token_file, format!("{token}\n")).unwrap();
    let path = dir.join("mimid-agent.toml");
    std::fs::write(
        &path,
        format!(
            "server_url = \"{server_base}\"\n\
             user_uri = \"{ALICE}\"\n\
             token_file = \"{}\"\n\
             state_dir = \"{}\"\n\
             listen = \"127.0.0.1:0\"\n\
             key_packages = 3\n\
             \n\
             [telemetry]\n\
             endpoint = \"http://127.0.0.1:4318\"\n\
             traces = false\n\
             logs = false\n\
             metrics = false\n",
            token_file.display(),
            dir.join("alice-state").display(),
        ),
    )
    .unwrap();
    path
}

/// With `MIMID_LOG_FORMAT=json` every line is a JSON object, and every
/// line from the agent's own crates above DEBUG carries its event name.
/// `agent_listening` carries the user and the front ends, and SIGINT is
/// logged as `shutdown_requested`.
///
/// The SIGINT is sent at the agent's first line, while it is still
/// starting, and the daemon must still get as far as `agent_listening`
/// and then exit cleanly. That is the window in which SIGINT took its
/// default action and killed the process, because the handler was
/// installed only when the serving loop first polled for it: the signal
/// is now kept and stops the daemon as soon as it serves (bead
/// mimid-8jsy for the same window in mimid-server).
#[tokio::test]
async fn json_log_format_writes_named_events() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let config = config_file(dir.path(), &server.base, &server.tokens[ALICE]);
    let mut agent = Agent::start(
        &config,
        &[("RUST_LOG", "info"), ("MIMID_LOG_FORMAT", "json")],
        "agent_telemetry_configured",
    )
    .await;
    let status = agent.interrupt().await;
    // A failure here is the daemon dying on the signal rather than
    // stopping on it.
    assert!(
        status.success(),
        "the agent did not exit cleanly on a SIGINT during startup: \
         {status:?}\n{}",
        agent.logs()
    );
    let stdout = agent.exited_stdout().await;
    let text = stdout.join("\n");

    let lines: Vec<serde_json::Value> = stdout
        .iter()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}")))
        .collect();
    for line in &lines {
        let target = line["target"].as_str().unwrap_or_default();
        let level = line["level"].as_str().unwrap_or_default();
        if target.starts_with("mimid") && level != "DEBUG" && level != "TRACE" {
            assert!(
                line["event"].is_string(),
                "an {level} event of {target} without a name: {line}"
            );
        }
    }
    let events: Vec<&str> = lines
        .iter()
        .filter_map(|line| line["event"].as_str())
        .collect();
    assert!(
        events.contains(&"agent_listening"),
        "the signal was kept, so the daemon served before it stopped:\n{text}"
    );
    assert!(events.contains(&"shutdown_requested"), "{text}");

    let listening = lines
        .iter()
        .find(|line| line["event"] == "agent_listening")
        .unwrap();
    assert_eq!(listening["level"], "INFO");
    assert_eq!(listening["message"], "mimid-agent listening");
    assert_eq!(listening["fields"]["user"], ALICE);
    assert_eq!(listening["fields"]["jmap"], true);
    assert_eq!(listening["fields"]["irc"], false);
    // No credential of any kind in the log, in either direction.
    assert!(
        !text.contains(&server.tokens[ALICE]),
        "the server token reached the log"
    );
}

/// A `MIMID_LOG_FORMAT` that names no format stops the agent at startup
/// with a message naming the variable, rather than logging in the
/// default format and leaving the operator with neither.
#[test]
fn unknown_log_format_stops_startup() {
    // A one-shot run with nothing to wait on, so no reactor is needed.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mimid-agent"))
        .arg("unused.toml")
        .env("MIMID_LOG_FORMAT", "yaml")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MIMID_LOG_FORMAT"), "{stderr}");
    assert!(output.stdout.is_empty());
}
