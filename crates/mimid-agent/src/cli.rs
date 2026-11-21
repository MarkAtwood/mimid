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

use std::io::Write;

use mimid_agent_store::credentials::{CredentialError, Credentials, describe};

use crate::config::Config;
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
