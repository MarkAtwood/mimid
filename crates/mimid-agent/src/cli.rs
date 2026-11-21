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
    #[error("usage: mimid-agent <config.toml> setup tls")]
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
/// decision A6 if it is due.
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
