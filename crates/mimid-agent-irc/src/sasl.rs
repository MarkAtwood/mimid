//! SASL: `AUTHENTICATE` with PLAIN and SCRAM-SHA-256 (IRCv3 SASL 3.1 and
//! 3.2; docs/design/frontend-auth.md §4.1; decision A3), against the
//! daemon's credential table.
//!
//! - `CAP LS 302` offers `sasl=PLAIN,SCRAM-SHA-256`, and
//!   `soju.im/account-required`, which makes Goguma label its password
//!   field "Password" rather than "Password (optional)".
//! - AUTHENTICATE is read before registration, also before the client's
//!   `CAP REQ sasl` is answered, as Goguma pipelines it.
//! - PLAIN: authzid empty or equal to authcid; authcid anything (Goguma
//!   sends the nick); the password any credential in any spelling.
//! - SCRAM-SHA-256: the agent's one salt; the proof is checked against
//!   every unrevoked credential.
//! - 900 and 903 on success; 904 on failure, after the limiter's delay
//!   (mimid_agent_store::credentials::limits); 905 for a payload past
//!   [`MAX_PAYLOAD`]; 906 on `AUTHENTICATE *`; 907 once logged in; 908 and
//!   904 for another mechanism.
//!
//! No payload, username or password is ever logged.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mimid_agent_store::credentials::Login;
use mimid_agent_store::credentials::scram::ServerFirst;

use crate::conn::Session;

/// The mechanisms offered, as `sasl=` and 908 list them.
pub const MECHANISMS: &str = "PLAIN,SCRAM-SHA-256";

/// The longest payload read, base64 octets of all its chunks. INVENTED
/// VALUE, NOT FROM SPEC: a SCRAM message is at most
/// `mimid_agent_store::credentials::scram::MAX_MESSAGE` octets.
pub const MAX_PAYLOAD: usize = 2048;

/// The octets of a full AUTHENTICATE chunk (IRCv3 SASL 3.1).
const CHUNK: usize = 400;

/// Where a SASL exchange stands.
#[derive(Debug, Default)]
pub(crate) enum Sasl {
    /// No exchange.
    #[default]
    Idle,
    /// PLAIN, reading the payload.
    Plain(String),
    /// SCRAM, reading the client's first message.
    ScramFirst(String),
    /// SCRAM, reading the client's final message.
    ScramFinal(Box<ServerFirst>, String),
    /// SCRAM, the server's final message sent; waiting for `+`.
    ScramDone(Login, String),
}

impl Sasl {
    fn buffer(&mut self) -> Option<&mut String> {
        match self {
            Self::Idle => None,
            Self::Plain(b)
            | Self::ScramFirst(b)
            | Self::ScramFinal(_, b)
            | Self::ScramDone(_, b) => Some(b),
        }
    }
}

impl Session {
    /// `AUTHENTICATE <mechanism | chunk | + | *>`.
    pub(crate) async fn authenticate(&mut self, argument: Option<&str>) {
        let Some(argument) = argument else {
            self.numeric("461", &["AUTHENTICATE", "Not enough parameters"]);
            return;
        };
        if self.me.is_some() || self.sasl_login.is_some() {
            self.numeric("907", &["You have already authenticated using SASL"]);
            return;
        }
        if argument == "*" {
            self.sasl = Sasl::Idle;
            self.numeric("906", &["SASL authentication aborted"]);
            return;
        }
        if matches!(self.sasl, Sasl::Idle) {
            match argument.to_ascii_uppercase().as_str() {
                "PLAIN" => self.sasl = Sasl::Plain(String::new()),
                "SCRAM-SHA-256" => self.sasl = Sasl::ScramFirst(String::new()),
                _ => {
                    self.numeric("908", &[MECHANISMS, "are available SASL mechanisms"]);
                    self.numeric("904", &["SASL authentication failed"]);
                    return;
                }
            }
            self.send_raw("AUTHENTICATE +\r\n");
            return;
        }
        let Some(buffer) = self.sasl.buffer() else {
            return;
        };
        if argument != "+" {
            buffer.push_str(argument);
        }
        if buffer.len() > MAX_PAYLOAD {
            self.sasl = Sasl::Idle;
            self.numeric("905", &["SASL message too long"]);
            return;
        }
        if argument.len() == CHUNK {
            // More follows.
            return;
        }
        let encoded = std::mem::take(buffer);
        let Ok(payload) = STANDARD.decode(encoded.as_bytes()) else {
            self.sasl_failed("malformed").await;
            return;
        };
        match std::mem::take(&mut self.sasl) {
            Sasl::Idle => {}
            Sasl::Plain(_) => self.plain(&payload).await,
            Sasl::ScramFirst(_) => match self.shared.credentials.scram_start(&payload) {
                Ok(exchange) => {
                    let message = exchange.message().as_bytes().to_vec();
                    self.sasl = Sasl::ScramFinal(Box::new(exchange), String::new());
                    self.send_payload(&message);
                }
                Err(_) => self.sasl_failed("malformed").await,
            },
            Sasl::ScramFinal(exchange, _) => {
                match self.shared.credentials.scram_finish(&exchange, &payload) {
                    Ok((login, last)) => {
                        self.sasl = Sasl::ScramDone(login, String::new());
                        self.send_payload(last.as_bytes());
                    }
                    Err(_) => self.sasl_failed("bad-proof").await,
                }
            }
            Sasl::ScramDone(login, _) => {
                if payload.is_empty() {
                    self.sasl_succeeded(login, "SCRAM-SHA-256");
                } else {
                    self.sasl_failed("malformed").await;
                }
            }
        }
    }

    /// The PLAIN payload: `authzid NUL authcid NUL password` (RFC 4616).
    async fn plain(&mut self, payload: &[u8]) {
        let mut parts = payload.split(|b| *b == 0);
        let (Some(authzid), Some(authcid), Some(password), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            self.sasl_failed("malformed").await;
            return;
        };
        if !authzid.is_empty() && authzid != authcid {
            self.sasl_failed("authzid").await;
            return;
        }
        match self.shared.credentials.check_plain(password) {
            Some(login) => self.sasl_succeeded(login, "PLAIN"),
            // docs/design/frontend-auth.md §4.6: from a matched tailnet
            // node, "any PASS or SASL PLAIN succeeds". The client is told
            // 900 and 903 so that it finishes SASL and registers; what
            // it put in the field, right or wrong, decides nothing, and
            // the node is what authorized the connection
            // (`Session::by_tailnet`, set when registration ends).
            None if self.tailnet.is_some() => self.tailnet_succeeded("PLAIN"),
            None => self.sasl_failed("no-such-credential").await,
        }
    }

    /// 900 and 903 to a matched tailnet node whose credential, if it sent
    /// one, was not one of the agent's (§4.6). No `Login` is recorded:
    /// `try_register` sees `self.sasl_login` still empty and takes the
    /// tailnet path, so the session closes with the node and not with a
    /// credential.
    fn tailnet_succeeded(&mut self, mechanism: &str) {
        let Some(matched) = self.tailnet.clone() else {
            return;
        };
        self.shared.credentials.limiter().succeeded(self.peer.ip());
        tracing::debug!(
            peer = %self.peer,
            mechanism,
            node = %matched.node,
            "SASL from a tailnet node succeeded without a credential"
        );
        let me = self.shared.names().own().clone();
        self.numeric(
            "900",
            &[
                &me.mask(),
                &me.nick,
                &format!("You are now logged in as {}", me.uri),
            ],
        );
        self.numeric("903", &["SASL authentication successful"]);
    }

    /// Sends `payload` as AUTHENTICATE chunks, ending with `+` if the last
    /// chunk is full.
    fn send_payload(&mut self, payload: &[u8]) {
        let encoded = STANDARD.encode(payload);
        let mut rest = encoded.as_str();
        loop {
            let (chunk, tail) = rest.split_at(rest.len().min(CHUNK));
            self.send_raw(&format!("AUTHENTICATE {chunk}\r\n"));
            rest = tail;
            if rest.is_empty() {
                if chunk.len() == CHUNK {
                    self.send_raw("AUTHENTICATE +\r\n");
                }
                return;
            }
        }
    }

    fn sasl_succeeded(&mut self, login: Login, mechanism: &str) {
        self.shared.credentials.limiter().succeeded(self.peer.ip());
        self.log_login(&login, mechanism);
        let me = self.shared.names().own().clone();
        self.numeric(
            "900",
            &[
                &me.mask(),
                &me.nick,
                &format!("You are now logged in as {}", me.uri),
            ],
        );
        self.numeric("903", &["SASL authentication successful"]);
        self.sasl_login = Some(login);
    }

    async fn sasl_failed(&mut self, reason: &str) {
        self.sasl = Sasl::Idle;
        self.sasl_failures = true;
        self.login_failed("SASL", reason).await;
        self.numeric("904", &["SASL authentication failed"]);
    }
}
