//! `mimid-chat`: an interactive command-line chat client over MIMI
//! protocol-07, for the IETF 127 hackathon table (bead mimid-1wgh.46.14).
//!
//! A throwaway interop tool, not mimid's client design: that is
//! mimid-agent (bead mimid-1wgh.13). One process is one user,
//! `mimi://<own-domain>/u/<name>`, whose MLS state lives in a state
//! directory and survives restarts. It talks to one hub, mimi-hubd at
//! `haven.reviewcommit.com` by default, over the protocol-07 wire lane
//! (keyMaterial, update, submitMessage, updateConsent) and mimi-hubd's
//! JSON lane (room set-up, KeyPackage publication, Welcome relay, and the
//! per-user queues it pulls, since the hub never dials out). See `chat.rs`
//! for how Welcomes and messages travel, and the README for running it.
//!
//! Usage:
//!
//! ```text
//! mimid-chat --user alice --state-dir DIR [--hub haven.reviewcommit.com]
//!            [--hub-url https://HUB] [--lane-url https://HUB:8443]
//!            [--own-domain mimid.reviewcommit.com] [--poll-ms 2000]
//!            [--script FILE]
//! ```
//!
//! On a terminal, commands are read with rustyline: the prompt names the
//! current room, incoming lines are printed above it without disturbing a
//! half-typed line, and history is kept in `<state-dir>/history` (0600).
//! Ctrl-C clears the line; Ctrl-D quits. When stdin is not a terminal,
//! lines are read plainly. With `--script FILE` they come from the file,
//! each echoed as `> line`. `/sleep <s>` and `/expect <text> [timeout s]` pause the
//! command stream (polling continues), so two scripted processes can take
//! turns. Logging goes to stderr, filtered by `RUST_LOG` (default `warn`).
//!
//! # Limitations
//!
//! - Every proposal from a member is taken as that member's leave
//!   (protocol-07 §3.5), the only proposal mimid-chat sends.
//! - A queue item is lost if the process dies between pulling and
//!   processing it (the hub's queues are deliver-once).
//! - KeyPackages at the hub are counted, not queried: the hub does not say
//!   when one is claimed. `/publish` adds more.
//! - The keyMaterial request is signed with a fresh key, not the MLS
//!   signature key (`Identity` does not expose it).
//! - BasicCredential only, and no authentication between providers beyond
//!   the outbound proxy's mTLS (mimid's known weaknesses apply).

#![forbid(unsafe_code)]

mod chat;
mod hub;
mod state;

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{BufRead, IsTerminal};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::Parser;
use rustyline::ExternalPrinter;
use rustyline::error::ReadlineError;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::chat::{Client, valid_name};
use crate::hub::Hub;
use crate::state::StateDir;

const DEFAULT_HUB: &str = "haven.reviewcommit.com";
const DEFAULT_OWN_DOMAIN: &str = "mimid.reviewcommit.com";
/// The longest `/expect` wait without an explicit timeout.
const DEFAULT_EXPECT_SECS: u64 = 60;

/// An interactive MIMI protocol-07 chat client for the IETF 127 table.
#[derive(Parser)]
#[command(name = "mimid-chat")]
struct Args {
    /// The user name: you are mimi://<own-domain>/u/<user>.
    #[arg(long, value_parser = parse_user)]
    user: String,
    /// Where the MLS state and bookkeeping live (created 0700).
    #[arg(long)]
    state_dir: PathBuf,
    /// The hub's provider domain.
    #[arg(long, default_value = DEFAULT_HUB)]
    hub: String,
    /// Where the hub's directory is fetched [default: https://<hub>].
    #[arg(long)]
    hub_url: Option<String>,
    /// The base of mimi-hubd's JSON lane [default: https://<hub>:8443].
    #[arg(long)]
    lane_url: Option<String>,
    /// This provider's domain; the proxy's client certificate must name it.
    #[arg(long, default_value = DEFAULT_OWN_DOMAIN)]
    own_domain: String,
    /// How often the hub is polled, in milliseconds.
    #[arg(long, default_value_t = 2000, value_parser = clap::value_parser!(u64).range(100..=600_000))]
    poll_ms: u64,
    /// Read commands from FILE instead of stdin, echoing each.
    #[arg(long, value_name = "FILE")]
    script: Option<PathBuf>,
    /// Publish KeyPackages only on an explicit /publish, never at start-up
    /// or after a join.
    #[arg(long)]
    no_publish: bool,
}

fn parse_user(user: &str) -> Result<String, String> {
    if valid_name(user) {
        Ok(user.to_owned())
    } else {
        Err("must be 1 to 64 of a-z 0-9 . _ - and not start with '.'".to_owned())
    }
}

/// A pause in the command stream.
enum Wait {
    Until(Instant),
    /// A printed line after `from` containing `text`, before the deadline.
    Expect {
        text: String,
        from: usize,
        deadline: Instant,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    match run().await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("mimid-chat: {e:#}");
            std::process::exit(2);
        }
    }
}

async fn run() -> anyhow::Result<i32> {
    let args = Args::parse();
    let me = format!("mimi://{}/u/{}", args.own_domain, args.user);
    let base = args
        .hub_url
        .clone()
        .unwrap_or_else(|| format!("https://{}", args.hub));
    let lane = args
        .lane_url
        .clone()
        .unwrap_or_else(|| format!("https://{}:8443", args.hub));
    let hub = Hub::new(&args.own_domain, &args.hub, &base, &lane)?;
    let dir = StateDir::open(&args.state_dir)?;
    let mut client = Client::open(dir, me, hub)?;
    client.auto_publish = !args.no_publish;
    client.top_up_key_packages().await;
    client.greet();

    let scripted = args.script.is_some();
    let interactive =
        !scripted && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let (mut lines, editor) = if interactive {
        let (lines, editor) = spawn_editor(&args.state_dir.join("history"), prompt(&client))?;
        client.set_printer(editor.printer);
        (lines, Some(editor.control))
    } else {
        (spawn_reader(args.script.clone())?, None)
    };
    // Lines the editor has handed over and is waiting to hear are done.
    let mut unacknowledged = 0usize;
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut eof = false;
    let mut wait: Option<Wait> = None;
    let mut expect_cursor = 0usize;
    let mut failed = false;
    let mut ticker = tokio::time::interval(Duration::from_millis(args.poll_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Resolve a pending wait.
        if let Some(w) = &wait {
            match w {
                Wait::Until(t) if Instant::now() >= *t => wait = None,
                Wait::Expect {
                    text,
                    from,
                    deadline,
                } => {
                    if let Some(i) = client.printed[*from..]
                        .iter()
                        .position(|l| l.contains(text.as_str()) && !l.starts_with("> "))
                    {
                        expect_cursor = from + i + 1;
                        wait = None;
                    } else if Instant::now() >= *deadline {
                        let text = text.clone();
                        client.error(format!("/expect timed out waiting for {text:?}"));
                        failed = true;
                        wait = None;
                    }
                }
                Wait::Until(_) => {}
            }
        }
        // Run queued commands while not waiting.
        while wait.is_none() {
            let Some(line) = queue.pop_front() else { break };
            if scripted {
                client.say(format!("> {line}"));
            }
            if let Some(w) = script_command(&line, &client, expect_cursor) {
                match w {
                    Ok(w) => wait = Some(w),
                    Err(e) => client.error(format!("{e:#}")),
                }
                continue;
            }
            if !client.command(&line).await {
                return Ok(i32::from(failed));
            }
        }
        if eof && queue.is_empty() && wait.is_none() {
            return Ok(i32::from(failed));
        }
        // The editor shows its next prompt only once the line it sent has
        // run, so the prompt names the room the line left current.
        if let Some(control) = &editor
            && queue.is_empty()
            && wait.is_none()
        {
            while unacknowledged > 0 {
                *control
                    .prompt
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = prompt(&client);
                let _ = control.ack.send(());
                unacknowledged -= 1;
            }
        }
        tokio::select! {
            line = lines.recv(), if !eof => match line {
                Some(line) => {
                    queue.push_back(line);
                    if editor.is_some() {
                        unacknowledged += 1;
                    }
                }
                None => eof = true,
            },
            _ = ticker.tick() => client.poll().await,
        }
    }
}

/// `/sleep` and `/expect`, which only the main loop can run.
fn script_command(
    line: &str,
    client: &Client,
    expect_cursor: usize,
) -> Option<anyhow::Result<Wait>> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("/sleep") {
        return Some(
            rest.trim()
                .parse::<f64>()
                .ok()
                .filter(|s| (0.0..=3600.0).contains(s))
                .map(|s| Wait::Until(Instant::now() + Duration::from_secs_f64(s)))
                .ok_or_else(|| anyhow!("usage: /sleep <seconds>")),
        );
    }
    if let Some(rest) = line.strip_prefix("/expect") {
        let rest = rest.trim();
        // An optional trailing timeout in seconds.
        let (text, secs) = match rest.rsplit_once(' ') {
            Some((text, secs)) if secs.parse::<u64>().is_ok() => {
                (text.trim(), secs.parse().unwrap_or(DEFAULT_EXPECT_SECS))
            }
            _ => (rest, DEFAULT_EXPECT_SECS),
        };
        if text.is_empty() {
            return Some(Err(anyhow!("usage: /expect <text> [timeout seconds]")));
        }
        return Some(Ok(Wait::Expect {
            text: text.to_owned(),
            from: expect_cursor.min(client.printed.len()),
            deadline: Instant::now() + Duration::from_secs(secs),
        }));
    }
    None
}

/// Reads command lines on a thread (stdin or the script file) and sends
/// them to the main loop; the channel closes at end of input.
fn spawn_reader(script: Option<PathBuf>) -> anyhow::Result<mpsc::UnboundedReceiver<String>> {
    let (tx, rx) = mpsc::unbounded_channel();
    // Comment lines are skipped in scripts only: typed, they are messages.
    let skip_comments = script.is_some();
    let reader: Box<dyn BufRead + Send> = match script {
        Some(path) => Box::new(std::io::BufReader::new(
            std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?,
        )),
        None => Box::new(std::io::BufReader::new(std::io::stdin())),
    };
    std::thread::spawn(move || {
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if skip_comments && line.trim_start().starts_with('#') {
                continue;
            }
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    Ok(rx)
}

/// The prompt: the current room's name.
fn prompt(client: &Client) -> String {
    match client.current_room_name() {
        Some(room) => format!("[{room}]> "),
        None => "> ".to_owned(),
    }
}

/// What the main loop keeps of the line editor.
struct EditorControl {
    /// The prompt for the next line.
    prompt: Arc<Mutex<String>>,
    /// One message per line handed over, once it has run.
    ack: std::sync::mpsc::Sender<()>,
}

struct Editor {
    control: EditorControl,
    printer: Box<dyn ExternalPrinter + Send>,
}

/// Runs a rustyline editor on a thread. Each line is sent to the main loop,
/// and the editor waits for its acknowledgement before the next prompt.
/// Ctrl-C clears the line; Ctrl-D (end of input) closes the channel.
fn spawn_editor(
    history: &Path,
    first_prompt: String,
) -> anyhow::Result<(mpsc::UnboundedReceiver<String>, Editor)> {
    // Created 0600 before rustyline writes it, which keeps the mode.
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(history)
        .with_context(|| format!("creating {}", history.display()))?;
    let (tx, rx) = mpsc::unbounded_channel();
    let (ack, ack_rx) = std::sync::mpsc::channel::<()>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let prompt = Arc::new(Mutex::new(first_prompt));
    let shared = Arc::clone(&prompt);
    let history = history.to_path_buf();
    std::thread::spawn(move || {
        let mut rl = match rustyline::DefaultEditor::new() {
            Ok(rl) => rl,
            Err(e) => {
                let _ = ready_tx.send(Err(anyhow!("starting the line editor: {e}")));
                return;
            }
        };
        let printer = match rl.create_external_printer() {
            Ok(p) => Box::new(p) as Box<dyn ExternalPrinter + Send>,
            Err(e) => {
                let _ = ready_tx.send(Err(anyhow!("starting the line editor: {e}")));
                return;
            }
        };
        if let Err(e) = rl.load_history(&history) {
            tracing::warn!(error = %e, "cannot load the history");
        }
        if ready_tx.send(Ok(printer)).is_err() {
            return;
        }
        loop {
            let prompt = shared
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            match rl.readline(&prompt) {
                Ok(line) => {
                    if !line.trim().is_empty() {
                        let _ = rl.add_history_entry(line.as_str());
                        if let Err(e) = rl.save_history(&history) {
                            tracing::warn!(error = %e, "cannot save the history");
                        }
                    }
                    if tx.send(line).is_err() || ack_rx.recv().is_err() {
                        break;
                    }
                }
                Err(ReadlineError::Interrupted) => {}
                Err(ReadlineError::Eof) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "reading a line");
                    break;
                }
            }
        }
    });
    let printer = ready_rx
        .recv()
        .map_err(|_| anyhow!("the line editor did not start"))??;
    Ok((
        rx,
        Editor {
            control: EditorControl { prompt, ack },
            printer,
        },
    ))
}
