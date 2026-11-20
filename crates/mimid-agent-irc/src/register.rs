//! Registration: `CAP`, `PASS`, `NICK`, `USER`, and the burst
//! (docs/irc-lessons.md "Registration"; docs/design/agent-frontends.md §4
//! "Commands in v1").
//!
//! - Nothing is sent before the client's first line.
//! - `CAP LS [302]` lists [`CAPS`]; a `CAP REQ` is acknowledged or refused
//!   as a whole; `CAP LS` or `CAP REQ` before registration holds it until
//!   `CAP END`. The CAP target is `*` until registered, then the nick.
//! - Registration ends once NICK and USER came and CAP is not being
//!   negotiated. The last PASS must have been the local token, or the
//!   client gets 464 and `ERROR`, and the connection closes.
//! - The burst: 001 (`Welcome to the mimid IRC Network nick!user@host`,
//!   to the user's own nick), a NICK change from the client's nick if it
//!   differs, 002 to 004, 005 ([`isupport`]), 900 with the user URI, 422.
//!   Then the client is shown every room the user is in, and the pending
//!   invites.

use crate::conn::{Session, VERSION, one_line};
use crate::line::{Line, MAX_LINE, Out, pack_words};
use crate::names::{CHANNELLEN, NICKLEN};

/// The capabilities offered: only those that are wired up
/// (docs/irc-lessons.md "CAP").
pub const CAPS: [&str; 3] = ["echo-message", "message-tags", "server-time"];

/// The 005 tokens (docs/design/agent-frontends.md §4 "Capabilities in
/// v1"). 004 lists the same channel modes as `CHANMODES` and `PREFIX`.
#[must_use]
pub fn isupport() -> Vec<String> {
    vec![
        "CASEMAPPING=ascii".to_owned(),
        "CHANTYPES=#&".to_owned(),
        "PREFIX=(o)@".to_owned(),
        "CHANMODES=b,,,nt".to_owned(),
        format!("NICKLEN={NICKLEN}"),
        format!("CHANNELLEN={CHANNELLEN}"),
        "TARGMAX=PRIVMSG:1,NOTICE:1,JOIN:,PART:,KICK:1,WHOIS:1".to_owned(),
        format!("LINELEN={MAX_LINE}"),
        "UTF8ONLY".to_owned(),
        "NETWORK=mimid".to_owned(),
    ]
}

/// The 004 channel modes: `CHANMODES` and `PREFIX` together.
const CHANNEL_MODES: &str = "bnot";

/// The 004 channel modes that take a parameter.
const PARAMETER_MODES: &str = "bo";

/// The CAP LS lines for `caps`: as many as needed within [`MAX_LINE`]
/// given that the rest of a line takes `overhead` octets, each but the
/// last marked `*` if `multiline` (CAP 302), as (more, list).
#[must_use]
pub fn cap_ls_lines(caps: &[String], overhead: usize, multiline: bool) -> Vec<(bool, String)> {
    let room = MAX_LINE.saturating_sub(overhead);
    if !multiline {
        return vec![(false, caps.join(" "))];
    }
    let lines = pack_words(caps, room);
    if lines.is_empty() {
        return vec![(false, String::new())];
    }
    let last = lines.len() - 1;
    lines
        .into_iter()
        .enumerate()
        .map(|(i, list)| (i < last, list))
        .collect()
}

impl Session {
    /// A line before registration: only CAP, PASS, NICK, USER, PING, PONG
    /// and QUIT are read.
    pub(crate) async fn unregistered(&mut self, line: &Line) {
        match line.verb().as_str() {
            "CAP" => self.cap(line),
            "PASS" => match line.param(0) {
                Some(pass) => {
                    let ok = self.shared.password_matches(pass.as_bytes());
                    self.pass_ok = Some(ok);
                }
                None => self.numeric("461", &["PASS", "Not enough parameters"]),
            },
            "NICK" => match line.param(0).filter(|n| !n.is_empty()) {
                Some(nick) => self.client_nick = Some(nick.to_owned()),
                None => self.numeric("431", &["No nickname given"]),
            },
            "USER" => {
                if line.params.len() < 4 {
                    self.numeric("461", &["USER", "Not enough parameters"]);
                } else {
                    self.got_user = true;
                }
            }
            "PING" => self.ping(line),
            "PONG" => {}
            "QUIT" => self.close("Quit"),
            _ => self.numeric("451", &["You have not registered"]),
        }
        if !self.closing {
            self.try_register();
        }
    }

    /// `PING <token>`: `:server PONG server :token` (docs/irc-lessons.md
    /// "Keepalive").
    pub(crate) fn ping(&mut self, line: &Line) {
        match line.param(0) {
            Some(token) => {
                // The token as trailing, which irssi matches.
                let server = &self.shared.server;
                let wire = format!(":{server} PONG {server} :{}\r\n", one_line(token));
                self.send_raw(&wire);
            }
            None => self.numeric("409", &["No origin specified"]),
        }
    }

    /// `CAP`, before or after registration.
    pub(crate) fn cap(&mut self, line: &Line) {
        let sub = line.param(0).unwrap_or_default().to_ascii_uppercase();
        let target = self.target();
        let server = self.shared.server.clone();
        match sub.as_str() {
            "LS" => {
                if self.me.is_none() {
                    self.cap_negotiating = true;
                }
                let multiline = line
                    .param(1)
                    .and_then(|v| v.parse::<u32>().ok())
                    .is_some_and(|v| v >= 302);
                let caps: Vec<String> = CAPS.iter().map(|c| (*c).to_owned()).collect();
                let overhead = format!(":{server} CAP {target} LS * :\r\n").len();
                for (more, list) in cap_ls_lines(&caps, overhead, multiline) {
                    let mut params = vec![target.clone(), "LS".to_owned()];
                    if more {
                        params.push("*".to_owned());
                    }
                    params.push(list);
                    self.send_trailing(&server, "CAP", params);
                }
            }
            "LIST" => {
                let mut on = Vec::new();
                for (cap, enabled) in [
                    ("echo-message", self.caps.echo_message),
                    ("message-tags", self.caps.message_tags),
                    ("server-time", self.caps.server_time),
                ] {
                    if enabled {
                        on.push(cap);
                    }
                }
                self.send_trailing(&server, "CAP", vec![target, "LIST".into(), on.join(" ")]);
            }
            "REQ" => {
                if self.me.is_none() {
                    self.cap_negotiating = true;
                }
                let asked = line.param(1).unwrap_or_default().to_owned();
                let mut caps = self.caps;
                let mut known = true;
                for item in asked.split(' ').filter(|i| !i.is_empty()) {
                    let (on, name) = match item.strip_prefix('-') {
                        Some(name) => (false, name),
                        None => (true, item),
                    };
                    match name {
                        "echo-message" => caps.echo_message = on,
                        "message-tags" => caps.message_tags = on,
                        "server-time" => caps.server_time = on,
                        _ => known = false,
                    }
                }
                // As a whole: all or nothing (docs/irc-lessons.md "CAP").
                let answer = if known {
                    self.caps = caps;
                    "ACK"
                } else {
                    "NAK"
                };
                self.send_trailing(&server, "CAP", vec![target, answer.into(), asked]);
            }
            "END" => self.cap_negotiating = false,
            _ => {
                let sub = line.param(0).unwrap_or_default().to_owned();
                self.numeric("410", &[&sub, "Invalid CAP command"]);
            }
        }
    }

    /// Queues `params` from `source`, the last always as trailing (CAP
    /// lists may be one word or none).
    fn send_trailing(&mut self, source: &str, command: &str, params: Vec<String>) {
        let mut wire = format!(":{source} {command}");
        let last = params.len().saturating_sub(1);
        for (i, param) in params.iter().enumerate() {
            wire.push(' ');
            if i == last {
                wire.push(':');
            }
            wire.push_str(param);
        }
        wire.push_str("\r\n");
        self.send_raw(&wire);
    }

    /// Ends registration if it can: NICK and USER came, and CAP is not
    /// being negotiated.
    fn try_register(&mut self) {
        if self.me.is_some() || self.client_nick.is_none() || !self.got_user || self.cap_negotiating
        {
            return;
        }
        if self.pass_ok != Some(true) {
            self.numeric("464", &["Password incorrect"]);
            self.close("Bad password");
            return;
        }
        self.burst();
    }

    /// 001 to 005, 900, 422, then the rooms and the invites.
    fn burst(&mut self) {
        let me = self.shared.names().own().clone();
        self.me = Some(me.clone());
        self.connected_at = crate::render::now_ms();
        let server = self.shared.server.clone();
        self.numeric(
            "001",
            &[&format!("Welcome to the mimid IRC Network {}", me.mask())],
        );
        if let Some(asked) = self.client_nick.clone()
            && asked != me.nick
        {
            let out = Out::new(
                &format!("{asked}!{}@{}", me.user, me.host),
                "NICK",
                vec![me.nick.clone()],
            );
            self.send(&out);
        }
        self.numeric(
            "002",
            &[&format!("Your host is {server}, running version {VERSION}")],
        );
        let created = self.shared.created.clone();
        self.numeric("003", &[&format!("This server was created {created}")]);
        self.numeric(
            "004",
            &[&server, VERSION, "i", CHANNEL_MODES, PARAMETER_MODES],
        );
        let tokens = isupport();
        let overhead = format!(
            ":{server} 005 {} :are supported by this server\r\n",
            me.nick
        )
        .len();
        for group in pack_words(&tokens, MAX_LINE - overhead) {
            let mut params: Vec<&str> = group.split(' ').collect();
            params.push("are supported by this server");
            self.numeric("005", &params);
        }
        self.numeric(
            "900",
            &[
                &me.mask(),
                &me.nick,
                &format!("You are now logged in as {}", me.uri),
            ],
        );
        self.numeric("422", &["MOTD File is missing"]);
        let store = std::sync::Arc::clone(&self.shared.store);
        self.feed = Some(store.subscribe());
        self.mark = store.last_seq();
        self.show_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: IRCv3 Capability Negotiation, "CAP LS": with 302, every
    /// line but the last carries `*`; without it, one line.
    #[test]
    fn a_long_cap_list_is_split_over_continuation_lines() {
        let caps: Vec<String> = (0..60).map(|i| format!("vendor.example/cap-{i}")).collect();
        let overhead = ":s.x CAP * LS * :\r\n".len();
        let lines = cap_ls_lines(&caps, overhead, true);
        assert!(lines.len() > 1);
        for (i, (more, list)) in lines.iter().enumerate() {
            assert_eq!(*more, i + 1 < lines.len());
            assert!(overhead + list.len() <= MAX_LINE, "{list}");
        }
        let joined: Vec<String> = lines
            .iter()
            .flat_map(|(_, l)| l.split(' ').map(str::to_owned))
            .collect();
        assert_eq!(joined, caps);
        assert_eq!(cap_ls_lines(&caps, overhead, false).len(), 1);
        assert_eq!(cap_ls_lines(&[], overhead, true), [(false, String::new())]);
    }

    /// Oracle: docs/irc-lessons.md "NICK and the burst": at least
    /// CASEMAPPING, CHANTYPES, PREFIX, CHANMODES (list modes as type A),
    /// NICKLEN, CHANNELLEN and TARGMAX, LINELEN and UTF8ONLY as enforced;
    /// 004 agrees with CHANMODES and PREFIX.
    #[test]
    fn isupport_has_the_tokens_the_lessons_ask_for() {
        let tokens = isupport();
        for prefix in [
            "CASEMAPPING=ascii",
            "CHANTYPES=",
            "PREFIX=(o)@",
            "CHANMODES=b,,,nt",
            "NICKLEN=30",
            "CHANNELLEN=64",
            "TARGMAX=",
            "LINELEN=512",
            "UTF8ONLY",
        ] {
            assert!(tokens.iter().any(|t| t.starts_with(prefix)), "{prefix}");
        }
        let mut from_005: Vec<char> = "bnt".chars().chain("o".chars()).collect();
        from_005.sort_unstable();
        let mut from_004: Vec<char> = CHANNEL_MODES.chars().collect();
        from_004.sort_unstable();
        assert_eq!(from_004, from_005);
        assert!(!tokens.iter().any(|t| t.contains("sasl")));
    }
}
