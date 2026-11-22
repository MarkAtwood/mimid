//! `mimid-agent <config> app-password ...`: the app passwords, managed
//! from the command line (docs/design/frontend-auth.md §3.6; bead
//! mimid-e13m.2). INVENTED, NOT FROM SPEC.
//!
//! | Command | Does |
//! |---|---|
//! | `app-password list` | lists every credential: name, kind, made, last used, revoked |
//! | `app-password add <name>` | makes an app password and prints it, once |
//! | `app-password revoke <name>` | revokes it: a running daemon closes its sessions within [`crate::CREDENTIAL_RECHECK`] |
//! | `app-password rotate-token` | writes a new `agent-token` file; a running daemon closes the old token's sessions |
//! | `setup tls` | with `[tls] source = "tailscale"`, explains that the names go into public Certificate Transparency logs and asks before the agent may use `tailscale cert` (decision A6) |
//! | `setup <client> <device>` | asks the `setup tls` question if it is due, makes an app password named `<device>`, and prints what the IRC client needs, with a terminal QR code of the `ircs://` URL for Goguma (docs/design/frontend-auth.md §6.1, §6.2); the password never goes into the QR code |
//!
//! The commands open `<state_dir>/mimid.sqlite` themselves, so they work
//! whether or not the daemon runs; a running daemon notices the change
//! through SQLite's `PRAGMA data_version`.
//!
//! # Limitations
//!
//! - After `rotate-token`, attachment links stay valid until the daemon
//!   restarts: the running daemon keeps the link key it made from the old
//!   token at start.

use std::io::{BufRead, Write};
use std::os::unix::fs::DirBuilderExt;

use mimid_agent_store::credentials::{CredentialError, Credentials, describe};

use crate::config::Config;
use crate::tls::{TlsSource, consent_question, has_consent, record_consent};
use crate::token::{LocalToken, TokenError};

/// Why a command failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    /// The arguments are not a command.
    #[error(
        "usage: mimid-agent <config.toml> app-password list | add <name> | revoke <name> | rotate-token"
    )]
    Usage,
    /// The arguments are not a `setup` command.
    #[error(
        "usage: mimid-agent <config.toml> setup tls | setup <goguma|weechat|irssi|hexchat|halloy|thelounge|generic> <device name>"
    )]
    SetupUsage,
    /// The credential table refused or failed.
    #[error(transparent)]
    Credentials(#[from] CredentialError),
    /// The token file could not be written.
    #[error("the agent token")]
    Token(#[from] TokenError),
    /// The output could not be written.
    #[error("writing the output")]
    Output(#[from] std::io::Error),
}

/// The credential table of `config`'s agent, opened as the CLI opens it.
///
/// # Errors
///
/// [`CredentialError`].
pub fn open_credentials(config: &Config) -> Result<Credentials, CredentialError> {
    Credentials::open(&config.state_dir.join(mimid_agent_core::DATABASE_FILE))
}

/// Runs `app-password <args>` for `config`, writing to `out`.
///
/// # Errors
///
/// [`CliError`].
pub fn app_password(config: &Config, args: &[String], out: &mut dyn Write) -> Result<(), CliError> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["list"] => {
            let credentials = open_credentials(config)?;
            let listed = credentials.list();
            if listed.is_empty() {
                writeln!(
                    out,
                    "no credentials yet; the agent token is added at the agent's first start"
                )?;
            }
            for info in listed {
                writeln!(out, "{}", describe(&info))?;
            }
        }
        ["add", name] => {
            let credentials = open_credentials(config)?;
            let (info, password) = credentials.add(name, "cli")?;
            writeln!(out, "App password {:?} made. It is shown once:", info.name)?;
            writeln!(out)?;
            writeln!(out, "    {}", password.shown())?;
            writeln!(out)?;
            writeln!(
                out,
                "Any front end takes it as the password; case, spaces and hyphens do not matter,"
            )?;
            writeln!(out, "except with SCRAM, which needs it exactly as shown.")?;
        }
        ["revoke", name] => {
            let credentials = open_credentials(config)?;
            let info = credentials.revoke(name, "cli")?;
            writeln!(
                out,
                "Revoked {:?}; a running agent closes its sessions within a few seconds.",
                info.name
            )?;
        }
        ["rotate-token"] => {
            let credentials = open_credentials(config)?;
            let token = LocalToken::replace(&config.state_dir)?;
            credentials.set_agent_token(token.as_bytes())?;
            writeln!(
                out,
                "Wrote a new {}; a running agent closes the old token's sessions within a few seconds.",
                config.state_dir.join(crate::token::TOKEN_FILE).display()
            )?;
        }
        _ => return Err(CliError::Usage),
    }
    Ok(())
}

/// The IRC clients `setup` knows (docs/design/frontend-auth.md §6.2), and
/// `generic`.
pub const SETUP_CLIENTS: [&str; 7] = [
    "goguma",
    "weechat",
    "irssi",
    "hexchat",
    "halloy",
    "thelounge",
    "generic",
];

/// The local part of `mimi://<domain>/u/<local>`: the username and nick
/// setup suggests (§3.5).
fn local_part(user_uri: &str) -> &str {
    user_uri.rsplit('/').next().unwrap_or("user")
}

/// Asks `question` on `out` and reads one line from `input`: whether the
/// answer is `y` or `yes`, in any case.
fn ask(question: &str, input: &mut dyn BufRead, out: &mut dyn Write) -> Result<bool, CliError> {
    write!(out, "{question}")?;
    out.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Decision A6: with `[tls] source = "tailscale"`, asks before the agent
/// may use `tailscale cert`, unless the user agreed for these names
/// already, and records a yes. Returns whether the agent may.
fn tailscale_consent(
    config: &Config,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<bool, CliError> {
    let Some(tls) = &config.tls else {
        return Ok(true);
    };
    if tls.source != TlsSource::Tailscale || has_consent(&config.state_dir, &tls.names) {
        return Ok(true);
    }
    if ask(&consent_question(&tls.names), input, out)? {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&config.state_dir)?;
        record_consent(&config.state_dir, &tls.names)?;
        writeln!(
            out,
            "Recorded. The agent will ask tailscaled for the certificate at its next start."
        )?;
        Ok(true)
    } else {
        writeln!(
            out,
            "Not using tailscale cert. Set [tls] source = \"files\" with your own certificate, \
             or run setup tls again."
        )?;
        Ok(false)
    }
}

/// Runs `setup <words>` for `config`: `setup tls` asks the question of
/// decision A6 if it is due; `setup <client> <device>` asks it too, then
/// makes an app password named `<device>` and prints what `<client>`
/// needs, with a QR code where a phone's camera can use one (§6).
///
/// # Errors
///
/// [`CliError`].
pub fn setup(
    config: &Config,
    words: &[String],
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["tls"] => setup_tls(config, input, out),
        [client, device] if SETUP_CLIENTS.contains(client) => {
            if !tailscale_consent(config, input, out)? {
                return Ok(());
            }
            let Some(irc) = &config.irc else {
                writeln!(
                    out,
                    "IRC is off: add an [irc] table to the configuration first."
                )?;
                return Ok(());
            };
            let credentials = open_credentials(config)?;
            let (info, password) = credentials.add(device, "setup")?;
            let nick = local_part(&config.user_uri);
            let (host, port, tls) = match irc.listen_tls {
                Some(addr) => (
                    config
                        .tls
                        .as_ref()
                        .and_then(|t| t.names.first().cloned())
                        .unwrap_or_else(|| addr.ip().to_string()),
                    addr.port(),
                    true,
                ),
                None => (irc.listen.ip().to_string(), irc.listen.port(), false),
            };
            let password = password.shown();
            writeln!(out, "App password {:?} made. It is shown once.", info.name)?;
            writeln!(out)?;
            if !tls {
                writeln!(
                    out,
                    "Note: there is no TLS listener ([irc] listen_tls), so only clients on this \
                     machine can connect, without TLS."
                )?;
                writeln!(out)?;
            }
            let scheme = if tls { "ircs" } else { "irc" };
            let tls_word = if tls { "on" } else { "off" };
            match *client {
                "goguma" => {
                    writeln!(out, "  Goguma")?;
                    writeln!(out, "    Server     {host}:{port}")?;
                    writeln!(out, "    Nickname   {nick}")?;
                    writeln!(out, "    Password   {password}")?;
                    if tls {
                        let url = format!("{scheme}://{nick}@{host}:{port}");
                        writeln!(out)?;
                        writeln!(
                            out,
                            "  Scan with the phone's camera to open Goguma with the server and"
                        )?;
                        writeln!(out, "  nickname filled in; then type the password.")?;
                        writeln!(out)?;
                        write!(out, "{}", qr_text(&url))?;
                        writeln!(out, "  {url}")?;
                    }
                }
                "weechat" => {
                    let tls_flag = if tls { " -tls" } else { "" };
                    writeln!(out, "  WeeChat")?;
                    writeln!(
                        out,
                        "    /server add mimid {host}/{port}{tls_flag} -sasl_mechanism=plain \
                         -sasl_username={nick} -sasl_password={password}"
                    )?;
                    writeln!(out, "    /connect mimid")?;
                }
                "irssi" => {
                    let tls_flag = if tls { " -tls" } else { "" };
                    writeln!(out, "  irssi")?;
                    writeln!(
                        out,
                        "    /network add -sasl_mechanism PLAIN -sasl_username {nick} \
                         -sasl_password {password} mimid"
                    )?;
                    writeln!(
                        out,
                        "    /server add{tls_flag} -network mimid {host} {port}"
                    )?;
                    writeln!(out, "    /connect mimid")?;
                }
                "hexchat" => {
                    writeln!(out, "  HexChat: Network List, Add, then Edit:")?;
                    writeln!(out, "    Servers           {host}/{port}")?;
                    writeln!(out, "    Use SSL           {tls_word}")?;
                    writeln!(out, "    Nick name         {nick}")?;
                    writeln!(
                        out,
                        "    Login method      SASL (username + password), or Server password"
                    )?;
                    writeln!(out, "    User name         {nick}")?;
                    writeln!(out, "    Password          {password}")?;
                }
                "halloy" => {
                    writeln!(out, "  Halloy: add to config.toml")?;
                    writeln!(out, "    [servers.mimid]")?;
                    writeln!(out, "    nickname = \"{nick}\"")?;
                    writeln!(out, "    server = \"{host}\"")?;
                    writeln!(out, "    port = {port}")?;
                    writeln!(out, "    use_tls = {tls}")?;
                    writeln!(out, "    [servers.mimid.sasl.plain]")?;
                    writeln!(out, "    username = \"{nick}\"")?;
                    writeln!(out, "    password = \"{password}\"")?;
                }
                "thelounge" => {
                    writeln!(out, "  The Lounge: Connect, then")?;
                    writeln!(out, "    Server            {host}")?;
                    writeln!(out, "    Port              {port}")?;
                    writeln!(out, "    Use secure connection (TLS)  {tls_word}")?;
                    writeln!(out, "    Nick              {nick}")?;
                    writeln!(out, "    Authentication    SASL PLAIN, username {nick}")?;
                    writeln!(out, "    Password          {password}")?;
                }
                _ => {
                    writeln!(out, "  Any IRC client")?;
                    writeln!(out, "    Server     {host}")?;
                    writeln!(out, "    Port       {port}, TLS {tls_word}")?;
                    writeln!(out, "    Nick       {nick}")?;
                    writeln!(
                        out,
                        "    Login      SASL PLAIN or SCRAM-SHA-256 with username {nick}, or the server password (PASS)"
                    )?;
                    writeln!(out, "    Password   {password}")?;
                }
            }
            writeln!(out)?;
            writeln!(
                out,
                "Revoke it with: mimid-agent <config> app-password revoke {}",
                info.name
            )?;
            Ok(())
        }
        _ => Err(CliError::SetupUsage),
    }
}

/// `setup tls`.
fn setup_tls(
    config: &Config,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let Some(tls) = config
        .tls
        .as_ref()
        .filter(|t| t.source == TlsSource::Tailscale)
    else {
        writeln!(out, "Nothing to ask: [tls] source is not \"tailscale\".")?;
        return Ok(());
    };
    if has_consent(&config.state_dir, &tls.names) {
        writeln!(out, "Already agreed for these names.")?;
        return Ok(());
    }
    tailscale_consent(config, input, out)?;
    Ok(())
}

/// `text` as a QR code in terminal characters: two rows a line, with the
/// quiet zone, for a terminal with a dark background: the light modules
/// are drawn as blocks and the dark ones left as background, as
/// `qrencode -t UTF8` does.
///
/// # Limitations
///
/// - On a terminal with a light background the code shows inverted; most
///   phone cameras still read it.
#[must_use]
pub fn qr_text(text: &str) -> String {
    match qrcode::QrCode::new(text.as_bytes()) {
        Ok(code) => {
            code.render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build()
                + "\n"
        }
        Err(_) => String::new(),
    }
}
