//! The `mimid` service nick (INVENTED, NOT FROM SPEC;
//! docs/design/agent-frontends.md §4, §7.5): what IRC has no command for.
//! The user sends it text (`/msg mimid <command>`) and it answers with
//! NOTICEs from `mimid!mimid@<server>`.
//!
//! | Command | Does |
//! |---|---|
//! | `help` | lists these commands |
//! | `allow <nick, user URI or user@domain>` | consents to the user: their invites are joined from the next sync (`Store::allow`) |
//! | `deny <nick, user URI or user@domain>` | refuses the user: they may no longer fetch the user's KeyPackages to invite them, and their invites are not joined (`Store::deny`) |
//!
//! `user@domain` stands for the user URI `mimi://domain/u/user` (§7.15),
//! here and in INVITE.
//! | `invites` | lists the pending invites, each accepted by JOIN of the channel name it is shown under (§7.13) or of `&invite-<number>` |
//!
//! # Limitations
//!
//! - English only.
//! - Rooms are made with JOIN and left with PART (§7.1), so the service
//!   has no `create` or `leave`; reports and removing participants have
//!   no command in v1.

use crate::command::Who;
use crate::conn::{Session, one_line};
use crate::line::Out;
use crate::names::SERVICE_NICK;
use mimid_agent_store::record::Invite;

/// The help text, one NOTICE a line.
const HELP: &[&str] = &[
    "mimid service commands:",
    "  allow <user>  let this user's invites in (joined at the next sync)",
    "  deny <user>   refuse this user: they can no longer invite you",
    "  invites       list pending invites; JOIN of the invite's channel accepts it",
    "A <user> is a nick, a user URI (mimi://domain/u/name) or name@domain,",
    "which stands for mimi://domain/u/name.",
    "Rooms: JOIN #name hosts a new room; PART leaves a room for good;",
    "INVITE <user> #channel invites someone; TOPIC #channel :text sets the",
    "room's subject, if your role may. No private messages.",
];

impl Session {
    /// A NOTICE from the service to the user.
    fn service_says(&mut self, text: &str) {
        let me = self.me();
        let source = format!("{SERVICE_NICK}!{SERVICE_NICK}@{}", self.shared.server);
        self.send(&Out::new(&source, "NOTICE", vec![me.nick, one_line(text)]));
    }

    /// Text the user sent the service.
    pub(crate) async fn service(&mut self, text: &str) {
        let mut words = text.split_whitespace();
        let command = words.next().unwrap_or_default().to_ascii_lowercase();
        let argument = words.next();
        match (command.as_str(), argument) {
            ("help", _) | ("", _) => {
                for line in HELP {
                    self.service_says(line);
                }
            }
            ("allow" | "deny", Some(name)) => {
                let Who::User(user) = self.who_or_address(name) else {
                    self.service_says(&format!(
                        "{name} is no nick here; give the user URI (mimi://<domain>/u/<name>) or <name>@<domain>"
                    ));
                    return;
                };
                let store = self.store();
                let result = if command == "allow" {
                    store.allow(&user).await
                } else {
                    store.deny(&user).await
                };
                match result {
                    Ok(()) if command == "allow" => self.service_says(&format!(
                        "allowed {user}: their invites are joined from now on"
                    )),
                    Ok(()) => self.service_says(&format!(
                        "denied {user}: they may not fetch your keys to invite you, and their invites are not joined"
                    )),
                    Err(error) => self.service_says(&format!("{command} {user} failed: {error}")),
                }
            }
            ("allow" | "deny", None) => {
                self.service_says(&format!("usage: {command} <nick, user URI or name@domain>"));
            }
            ("invites", _) => {
                let invites: Vec<Invite> = self.shared.store.state().invites.clone();
                if invites.is_empty() {
                    self.service_says("no pending invites");
                }
                for invite in invites {
                    let number = invite.number;
                    let (from, channel) = {
                        let mut names = self.shared.names();
                        let from = match &invite.inviter {
                            Some(uri) => format!("{} ({uri})", names.nick(uri)),
                            None => "an unknown inviter".to_owned(),
                        };
                        (from, names.invite_channel(&invite))
                    };
                    let how = if channel.starts_with('#') {
                        format!("JOIN {channel} or JOIN &invite-{number} to accept")
                    } else {
                        format!("JOIN &invite-{number} to accept")
                    };
                    self.service_says(&format!("invite {number} from {from}: {how}"));
                }
            }
            _ => self.service_says(&format!("unknown command {command:?}; try help")),
        }
    }
}
