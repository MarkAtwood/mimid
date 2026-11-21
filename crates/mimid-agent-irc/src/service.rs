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
//! | `expire <#channel> [<duration> or off]` | shows or sets the room's local expiry policy: messages older than the duration are deleted here (`Store::set_message_expiry`, §7.21) |
//! | `burn <#channel> <text>` | sends `text` to be deleted by each mimid recipient once read; the user's own copy stays (`Store::send_with`, §7.22) |
//! | `call <#channel> <url> [<description>]` | sends a call to join: `url`, which must be `https` or `wss`, as mimi-content-10 §5.10 has it (`Store::send_call`, §7.24) |
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
use mimid_agent_store::record::{Call, Invite, MessageExpiry};

/// The help text, one NOTICE a line.
const HELP: &[&str] = &[
    "mimid service commands:",
    "  allow <user>  let this user's invites in (joined at the next sync)",
    "  deny <user>   refuse this user: they can no longer invite you",
    "  invites       list pending invites; JOIN of the invite's channel accepts it",
    "  expire #channel [<duration>|off]  show or set how long messages are kept",
    "                here: 90s, 30m, 12h, 7d or 2w; off keeps them",
    "  burn #channel <text>  send text that each mimid recipient deletes once",
    "                read; your own copy stays; other software keeps it",
    "  call #channel <url> [<description>]  send a call to join; the URL",
    "                must be https:// or wss://",
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
            ("expire", Some(channel)) => self.expire(channel, words.next()).await,
            ("burn", Some(channel)) => {
                // The text is the rest of the line as sent, spaces kept.
                let text = text
                    .trim_start()
                    .split_once(char::is_whitespace)
                    .and_then(|(_, rest)| rest.trim_start().split_once(char::is_whitespace))
                    .map_or("", |(_, text)| text.trim_start());
                self.burn(channel, text).await;
            }
            ("call", Some(channel)) => {
                let Some(url) = words.next() else {
                    self.service_says("usage: call #channel <url> [<description>]");
                    return;
                };
                // The description is the rest of the line, spaces kept.
                let description = after_words(text, 3).trim_end();
                self.call(channel, url, description).await;
            }
            ("call", None) => self.service_says("usage: call #channel <url> [<description>]"),
            ("expire", None) => {
                self.service_says("usage: expire #channel [<duration> or off]");
            }
            ("burn", None) => self.service_says("usage: burn #channel <text>"),
            _ => self.service_says(&format!("unknown command {command:?}; try help")),
        }
    }

    /// `expire #channel [duration|off]` (docs/design/agent-frontends.md
    /// §7.21): shows or sets the room's local expiry policy.
    async fn expire(&mut self, channel: &str, duration: Option<&str>) {
        let Some(key) = self.shown_room(channel) else {
            self.service_says(&format!("{channel}: no such channel here"));
            return;
        };
        let store = self.store();
        let Some(duration) = duration else {
            let now = store
                .state()
                .rooms
                .get(&key)
                .and_then(|r| r.message_expiry_seconds);
            self.service_says(&match now {
                Some(seconds) => format!(
                    "{channel}: messages are deleted here {} after they arrive",
                    show_duration(seconds)
                ),
                None => format!("{channel}: messages are kept"),
            });
            return;
        };
        let Some(seconds) = parse_duration(duration) else {
            self.service_says(&format!(
                "{duration:?} is no duration; give 90s, 30m, 12h, 7d, 2w, or off"
            ));
            return;
        };
        store.set_message_expiry(&key, seconds);
        self.save().await;
        self.service_says(&match seconds {
            Some(seconds) => format!(
                "{channel}: messages are deleted here {} after they arrive;                  others in the room keep their own copies",
                show_duration(seconds)
            ),
            None => format!("{channel}: messages are kept"),
        });
    }

    /// `burn #channel text` (docs/design/agent-frontends.md §7.22): sends
    /// `text` with burnOnRead.
    async fn burn(&mut self, channel: &str, text: &str) {
        let Some(key) = self.shown_room(channel) else {
            self.service_says(&format!("{channel}: no such channel here"));
            return;
        };
        if text.is_empty() {
            self.service_says("usage: burn #channel <text>");
            return;
        }
        let store = self.store();
        let message_key = store.new_key();
        let expiry = MessageExpiry {
            burn_on_read: true,
            ..MessageExpiry::default()
        };
        self.own_sends.insert(message_key.clone());
        match store
            .send_with(message_key.clone(), &key, text, &[], expiry)
            .await
        {
            Ok(_) => self.save().await,
            Err(error) => {
                self.own_sends.remove(&message_key);
                self.service_says(&format!("{channel}: not sent: {error}"));
            }
        }
    }
}

impl Session {
    /// `call #channel url [description]` (docs/design/agent-frontends.md
    /// §7.24): sends a call to join.
    async fn call(&mut self, channel: &str, url: &str, description: &str) {
        let Some(key) = self.shown_room(channel) else {
            self.service_says(&format!("{channel}: no such channel here"));
            return;
        };
        let store = self.store();
        let message_key = store.new_key();
        let call = Call {
            url: url.to_owned(),
            description: description.to_owned(),
            expires: None,
        };
        self.own_sends.insert(message_key.clone());
        match store
            .send_call(
                message_key.clone(),
                &key,
                "",
                &call,
                MessageExpiry::default(),
            )
            .await
        {
            Ok(_) => self.save().await,
            Err(error) => {
                self.own_sends.remove(&message_key);
                self.service_says(&format!("{channel}: not sent: {error}"));
            }
        }
    }
}

/// `text` after its first `n` words, the space after them left out.
fn after_words(text: &str, n: usize) -> &str {
    let mut rest = text.trim_start();
    for _ in 0..n {
        rest = rest
            .split_once(char::is_whitespace)
            .map_or("", |(_, tail)| tail)
            .trim_start();
    }
    rest
}

/// The largest duration `expire` takes: a year, as mimi-content-10 §9.1
/// bounds an expiry. INVENTED, NOT FROM SPEC: applying that bound to a
/// local policy.
const MAX_DURATION_SECS: u64 = mimid_agent_store::expiry::ONE_YEAR_SECS;

/// `off` or `0` as `None`; `<n>[s|m|h|d|w]` (seconds without a unit) as
/// seconds, up to [`MAX_DURATION_SECS`]; `None` inside for off, outer
/// `None` for anything else.
fn parse_duration(text: &str) -> Option<Option<u64>> {
    let text = text.to_ascii_lowercase();
    if text == "off" || text == "0" {
        return Some(None);
    }
    let (digits, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => text.split_at(i),
        None => (text.as_str(), "s"),
    };
    let unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    let seconds = digits.parse::<u64>().ok()?.checked_mul(unit)?;
    match seconds {
        0 => Some(None),
        s if s <= MAX_DURATION_SECS => Some(Some(s)),
        _ => None,
    }
}

/// `seconds` in the largest unit that divides it.
fn show_duration(seconds: u64) -> String {
    for (unit, name) in [(604_800, "w"), (86_400, "d"), (3600, "h"), (60, "m")] {
        if seconds.is_multiple_of(unit) {
            return format!("{}{name}", seconds / unit);
        }
    }
    format!("{seconds}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_description_is_the_rest_of_the_line() {
        assert_eq!(
            after_words(" call  #c\thttps://example.com/j  Join the  Foo ", 3),
            "Join the  Foo "
        );
        assert_eq!(after_words("call #c https://example.com/j", 3), "");
        assert_eq!(after_words("call", 3), "");
    }

    #[test]
    fn durations_parse_with_units_and_off() {
        assert_eq!(parse_duration("off"), Some(None));
        assert_eq!(parse_duration("OFF"), Some(None));
        assert_eq!(parse_duration("0"), Some(None));
        assert_eq!(parse_duration("0h"), Some(None));
        assert_eq!(parse_duration("90"), Some(Some(90)));
        assert_eq!(parse_duration("90s"), Some(Some(90)));
        assert_eq!(parse_duration("30m"), Some(Some(1_800)));
        assert_eq!(parse_duration("12h"), Some(Some(43_200)));
        assert_eq!(parse_duration("7d"), Some(Some(604_800)));
        assert_eq!(parse_duration("2W"), Some(Some(1_209_600)));
        assert_eq!(parse_duration("365d"), Some(Some(31_536_000)));
        for bad in [
            "",
            "m",
            "-5",
            "5x",
            "1.5h",
            "366d",
            "99999999999999999999w",
            "5 m",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
        assert_eq!(show_duration(90), "90s");
        assert_eq!(show_duration(1_800), "30m");
        assert_eq!(show_duration(1_209_600), "2w");
    }
}
