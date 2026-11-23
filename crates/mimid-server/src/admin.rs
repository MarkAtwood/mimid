//! `mimid admin`: a command-line client of the local control listener
//! ([`crate::local`], bead mimid-1wgh.47.6). It replaces the offline admin
//! CLI planned in mimid-1wgh.32 (Mark, 2026-11-15): every action goes
//! through the running server, so it reaches the hub's in-memory rooms.
//!
//! Usage: `mimid admin <config.toml> <command> [arguments]`, where the
//! configuration names `local_listen` (and `local_token` if the listener
//! requires one). Commands:
//!
//! - `hub-sender`: the hub's external-sender identity;
//! - `rooms`: every hosted room; `room <roomId>`: one room;
//! - `remove <roomId> <userUri>` and `ban <roomId> <userUri>`: the hub
//!   proposes the user's removal or ban (it takes effect at the next
//!   Commit);
//! - `users`: every JMAP account; `add-user <userUri>`: create one;
//!   `token <userUri> [name]`: issue a bearer token for it, optionally
//!   named (one token per device, so that one can be revoked alone);
//!   `tokens <userUri>`: its tokens, with their ids, names, creation, last
//!   use and revocation; `revoke-token <id>`: revoke one at once, closing
//!   its open connections (bead mimid-v9co);
//! - `consent`: the consent entries other providers sent;
//! - `provider-key`: this server's request-signing selector and public key,
//!   and the provisional DNS record for it (bead mimid-75nk.1).
//!
//! The answer's JSON body is printed as is. A problem answer is an error,
//! whose message carries the status and the problem `type`.

use std::net::SocketAddr;

use crate::local::LocalToken;

/// Why an admin command failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdminError {
    /// The command line is not a known command with its argument.
    #[error(
        "usage: mimid admin <config.toml> hub-sender | rooms | room <roomId> | remove <roomId> <userUri> | ban <roomId> <userUri> | users | add-user <userUri> | token <userUri> [name] | tokens <userUri> | revoke-token <id> | consent | provider-key [--private]"
    )]
    Usage,
    /// The configuration has no `local_listen`.
    #[error("the configuration has no local_listen, so there is no local control listener")]
    NoListener,
    /// The request could not be sent or the answer read.
    #[error("local control listener at {addr}")]
    Http {
        /// The listener's address.
        addr: SocketAddr,
        /// The transport error.
        #[source]
        source: reqwest::Error,
    },
    /// The listener answered with an error status.
    #[error("{status}: {body}")]
    Refused {
        /// The HTTP status.
        status: u16,
        /// The answer's body, an RFC 9457 problem.
        body: String,
    },
}

/// One admin command, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    HubSender,
    Rooms,
    Room(String),
    Remove {
        room: String,
        user: String,
        ban: bool,
    },
    Users,
    AddUser(String),
    Token {
        user: String,
        name: Option<String>,
    },
    Tokens(String),
    RevokeToken(String),
    Consent,
    ProviderKey,
    /// `provider-key --private`: the signing key's seed, for backup and
    /// migration (bead mimid-75nk.13).
    ProviderKeyPrivate,
}

impl Command {
    fn parse(args: &[String]) -> Result<Self, AdminError> {
        match args {
            [c] if c == "hub-sender" => Ok(Self::HubSender),
            [c] if c == "rooms" => Ok(Self::Rooms),
            [c, room] if c == "room" => Ok(Self::Room(room.clone())),
            [c, room, user] if c == "remove" || c == "ban" => Ok(Self::Remove {
                room: room.clone(),
                user: user.clone(),
                ban: c == "ban",
            }),
            [c] if c == "users" => Ok(Self::Users),
            [c, user] if c == "add-user" => Ok(Self::AddUser(user.clone())),
            [c, user] if c == "token" => Ok(Self::Token {
                user: user.clone(),
                name: None,
            }),
            [c, user, name] if c == "token" => Ok(Self::Token {
                user: user.clone(),
                name: Some(name.clone()),
            }),
            [c, user] if c == "tokens" => Ok(Self::Tokens(user.clone())),
            [c, id] if c == "revoke-token" => Ok(Self::RevokeToken(id.clone())),
            [c] if c == "consent" => Ok(Self::Consent),
            [c] if c == "provider-key" => Ok(Self::ProviderKey),
            [c, f] if c == "provider-key" && f == "--private" => Ok(Self::ProviderKeyPrivate),
            _ => Err(AdminError::Usage),
        }
    }
}

/// A URI as one path segment: every octet outside the RFC 3986 unreserved
/// set percent-encoded.
fn segment(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Runs the admin command `args` against the local control listener at
/// `listen`, presenting `token` if given, and returns the answer's body.
///
/// # Errors
///
/// [`AdminError::Usage`] for an unknown command, [`AdminError::NoListener`]
/// without `listen`, [`AdminError::Http`] if the listener cannot be
/// reached, and [`AdminError::Refused`] for an error answer.
pub async fn run(
    listen: Option<SocketAddr>,
    token: Option<&LocalToken>,
    args: &[String],
) -> Result<String, AdminError> {
    let command = Command::parse(args)?;
    let addr = listen.ok_or(AdminError::NoListener)?;
    let base = format!("http://{addr}/local/v1");
    let client = reqwest::Client::new();
    let request = match &command {
        Command::HubSender => client.get(format!("{base}/hub-sender")),
        Command::Rooms => client.get(format!("{base}/rooms")),
        Command::Room(room) => client.get(format!("{base}/rooms/{}", segment(room))),
        Command::Remove { room, user, ban } => client
            .post(format!("{base}/rooms/{}/remove", segment(room)))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::json!({ "user": user, "ban": ban }).to_string()),
        Command::Users => client.get(format!("{base}/users")),
        Command::AddUser(user) => client
            .post(format!("{base}/users"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::json!({ "user": user }).to_string()),
        Command::Token { user, name } => {
            let request = client.post(format!("{base}/users/{}/tokens", segment(user)));
            match name {
                Some(name) => request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(serde_json::json!({ "name": name }).to_string()),
                None => request,
            }
        }
        Command::Tokens(user) => client.get(format!("{base}/users/{}/tokens", segment(user))),
        Command::RevokeToken(id) => client.post(format!("{base}/tokens/{}/revoke", segment(id))),
        Command::Consent => client.get(format!("{base}/consent")),
        Command::ProviderKey => client.get(format!("{base}/provider-key")),
        Command::ProviderKeyPrivate => client.get(format!("{base}/provider-key/private")),
    };
    let request = match token {
        Some(token) => request.bearer_auth(token.secret()),
        None => request,
    };
    let http = |source| AdminError::Http { addr, source };
    let response = request.send().await.map_err(http)?;
    let status = response.status();
    let body = response.text().await.map_err(http)?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(AdminError::Refused {
            status: status.as_u16(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn commands_parse_with_their_arguments() {
        assert_eq!(Command::parse(&args(&["rooms"])).unwrap(), Command::Rooms);
        assert_eq!(
            Command::parse(&args(&["token", "mimi://a.example/u/alice"])).unwrap(),
            Command::Token {
                user: "mimi://a.example/u/alice".to_owned(),
                name: None
            }
        );
        assert_eq!(
            Command::parse(&args(&[
                "token",
                "mimi://a.example/u/alice",
                "Pidgin at home"
            ]))
            .unwrap(),
            Command::Token {
                user: "mimi://a.example/u/alice".to_owned(),
                name: Some("Pidgin at home".to_owned())
            }
        );
        assert_eq!(
            Command::parse(&args(&["tokens", "mimi://a.example/u/alice"])).unwrap(),
            Command::Tokens("mimi://a.example/u/alice".to_owned())
        );
        assert_eq!(
            Command::parse(&args(&["revoke-token", "00ff"])).unwrap(),
            Command::RevokeToken("00ff".to_owned())
        );
        for bad in [
            &[][..],
            &["room"][..],
            &["rooms", "x"][..],
            &["drop-tables"][..],
            &["tokens"][..],
            &["revoke-token"][..],
            &["revoke-token", "a", "b"][..],
            &["token", "u", "n", "extra"][..],
        ] {
            assert!(
                matches!(Command::parse(&args(bad)), Err(AdminError::Usage)),
                "{bad:?}"
            );
        }
    }

    /// `provider-key` and `provider-key --private` are different
    /// commands, and only that one flag is accepted (bead mimid-75nk.13).
    #[test]
    fn the_private_provider_key_is_its_own_command() {
        assert_eq!(
            Command::parse(&args(&["provider-key"])).unwrap(),
            Command::ProviderKey
        );
        assert_eq!(
            Command::parse(&args(&["provider-key", "--private"])).unwrap(),
            Command::ProviderKeyPrivate
        );
        // Nothing else stands in for the flag, so a typo asks rather
        // than quietly printing the public key.
        for bad in [
            &["provider-key", "private"][..],
            &["provider-key", "--public"][..],
            &["provider-key", "--private", "extra"][..],
        ] {
            assert!(
                matches!(Command::parse(&args(bad)), Err(AdminError::Usage)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_uri_is_one_path_segment() {
        assert_eq!(
            segment("mimi://a.example/r/one"),
            "mimi%3A%2F%2Fa.example%2Fr%2Fone"
        );
    }
}
