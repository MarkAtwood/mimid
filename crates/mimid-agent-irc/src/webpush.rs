//! soju.im/webpush (docs/design/client-survey.md §10 S4;
//! docs/design/agent-frontends.md §7.35): the client registers a Web Push
//! subscription, and the agent pushes it one IRC line, encrypted to the
//! client's keys (RFC 8291, [`crate::push_crypto`]) and signed with the
//! agent's VAPID key (RFC 8292), for each message the user would want to
//! be woken for.
//!
//! - **Offered** only with the front end's push switched on
//!   ([`crate::IrcFrontEnd::enable_web_push`]; `[irc] webpush`, on by
//!   default): the `soju.im/webpush` capability, and ISUPPORT `VAPID`, the
//!   agent's P-256 public key, made once and kept in the agent's database
//!   ([`mimid_agent_store::push`]).
//! - **`WEBPUSH REGISTER <endpoint> <keys>`** keeps the subscription,
//!   replacing one with the same endpoint, and answers `WEBPUSH REGISTER
//!   <endpoint>`; `<keys>` is in the message-tag format, with `p256dh` and
//!   `auth` in base64url, padded or not. The endpoint must be `https`, or
//!   `http` to a loopback address. **`WEBPUSH UNREGISTER <endpoint>`**
//!   drops it, and is echoed whether or not there was one. Errors are
//!   `FAIL WEBPUSH INVALID_PARAMS` or `INTERNAL_ERROR`.
//! - **What is pushed**, to every subscription, whether or not a client is
//!   connected (Goguma shows no notification of its own for a line it
//!   reads live once it has a push subscription, goguma 5aa7baa5
//!   `lib/client_controller.dart:1137-1141`): a message from another user
//!   in a private query; a channel message from another user that names
//!   the user's nick or replies to the user's message; a pending invite;
//!   and a moved read marker, so the client clears the notifications of
//!   what was read elsewhere. Each is one line, as the client's
//!   connection would show it, with only `msgid` and `time` as tags if
//!   the registering connection had message-tags and server-time; the
//!   text is the message's first line.
//! - **What the push service sees**: the endpoint, the time, a body of
//!   fixed size (the plaintext is padded to [`PAD_TO`] octets), the
//!   urgency, the TTL and the VAPID public key. Not the text, the sender
//!   or the room.
//! - A push service's 404 or 410 drops the subscription (RFC 8030 §7.3);
//!   other failures are logged and the line is not pushed again.
//!
//! # Limitations
//!
//! - At most [`MAX_PUSHES_PER_ROUND`] lines per subscription for the
//!   changes of one save; a long sync after downtime pushes its latest.
//! - A mention is the user's nick as a whole word, ASCII case folded; the
//!   user's display name or URI is not looked for.
//! - Pushes are not retried; a line a push service refused is lost to
//!   that device until it reads history.

use std::sync::Arc;
use std::time::Duration;

use mimid_agent_store::Change;
use mimid_agent_store::push::{PushError, PushSubscriptions, Subscription};
use mimid_agent_store::record::{Message, Reply, RoomStatus, Sender};
use p256::SecretKey;
use serde_json::json;
use tokio::sync::{broadcast, watch};

use crate::conn::{Session, Shared, stopped};
use crate::line::{Line, Out, unescape_tag_value};
use crate::push_crypto::{self, ClientKeys};
use crate::render::{data, server_time};

/// The front end's name on its subscriptions.
pub(crate) const FRONT_END: &str = "irc";

/// The name of the VAPID key in the push tables.
const VAPID_KEY: &str = "irc-vapid";

/// How long a push service keeps an undelivered push: 7 days, as soju
/// does (`server.go`). INVENTED VALUE, NOT FROM SPEC.
pub const TTL_SECONDS: u64 = 7 * 24 * 3600;

/// How long a VAPID token is valid: 12 hours, under RFC 8292 §2's 24.
const VAPID_LIFETIME_SECONDS: u64 = 12 * 3600;

/// The plaintext every push is padded to, so that its size tells nothing
/// (RFC 8291 §4 allows padding). A line of the most text with `msgid` and
/// `time` fits. INVENTED VALUE, NOT FROM SPEC.
pub const PAD_TO: usize = 1024;

/// The most lines pushed to one subscription for one save's changes.
/// INVENTED VALUE, NOT FROM SPEC.
pub const MAX_PUSHES_PER_ROUND: usize = 20;

/// How long one push may take.
const PUSH_TIMEOUT: Duration = Duration::from_secs(30);

/// The most text of a message a push carries, in octets.
const MAX_TEXT: usize = 400;

/// The agent's Web Push sender.
pub(crate) struct WebPush {
    pub(crate) subscriptions: Arc<PushSubscriptions>,
    vapid: SecretKey,
    /// The VAPID public key, base64url, for ISUPPORT.
    pub(crate) vapid_public: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for WebPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebPush")
            .field("vapid_public", &self.vapid_public)
            .finish_non_exhaustive()
    }
}

/// Why pushing could not be set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WebPushError {
    /// The push tables failed.
    #[error("the IRC front end's push subscriptions")]
    Subscriptions(#[from] PushError),
    /// The kept VAPID key is not a P-256 key.
    #[error("the IRC front end's VAPID key is malformed")]
    BadKey,
    /// The HTTP client could not be made.
    #[error("the IRC front end's push client")]
    Client(#[source] reqwest::Error),
}

impl WebPush {
    /// The sender over `subscriptions`, with the VAPID key kept there,
    /// made now if there is none.
    pub(crate) fn new(subscriptions: Arc<PushSubscriptions>) -> Result<Self, WebPushError> {
        let key = subscriptions.key(VAPID_KEY, || {
            push_crypto::random_secret()
                .map(|k| k.to_bytes().to_vec())
                .map_err(|e| e.to_string())
        })?;
        let vapid = SecretKey::from_slice(&key).map_err(|_| WebPushError::BadKey)?;
        let vapid_public = push_crypto::b64url(&push_crypto::point(&vapid.public_key()));
        let client = reqwest::Client::builder()
            .timeout(PUSH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(WebPushError::Client)?;
        Ok(Self {
            subscriptions,
            vapid,
            vapid_public,
            client,
        })
    }

    /// Pushes `line` to `subscription` with `urgency` (RFC 8030 §5.3);
    /// drops the subscription if the push service says it is gone.
    async fn push(&self, subscription: &Subscription, line: &str, urgency: &str) {
        let host = reqwest::Url::parse(&subscription.endpoint)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default();
        let (Some(p256dh), Some(auth)) = (
            subscription.keys.get("p256dh"),
            subscription.keys.get("auth"),
        ) else {
            return;
        };
        let Some(keys) = ClientKeys::parse(p256dh, auth) else {
            return;
        };
        let Ok(url) = reqwest::Url::parse(&subscription.endpoint) else {
            return;
        };
        let body = match push_crypto::encrypt(line.as_bytes(), &keys, PAD_TO) {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(
                    name: "agent_irc_push_failed",
                    host = %host,
                    error = &error as &dyn std::error::Error,
                    "a push was not encrypted"
                );
                return;
            }
        };
        let expires = mimid_agent_store::sync::now_ms() / 1000 + VAPID_LIFETIME_SECONDS;
        let authorization = push_crypto::vapid_authorization(
            &self.vapid,
            &url.origin().ascii_serialization(),
            expires,
        );
        let sent = self
            .client
            .post(url)
            .header("TTL", TTL_SECONDS.to_string())
            .header("Urgency", urgency)
            .header("Content-Encoding", "aes128gcm")
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", authorization)
            .body(body)
            .send()
            .await;
        match sent {
            Ok(response) if response.status().is_success() => {
                tracing::debug!(host = %host, "pushed a line");
            }
            Ok(response) if matches!(response.status().as_u16(), 404 | 410) => {
                tracing::info!(
                    name: "agent_irc_push_gone",
                    host = %host,
                    status = response.status().as_u16(),
                    "a push subscription is gone; dropped"
                );
                if let Err(error) = self
                    .subscriptions
                    .unregister(FRONT_END, &subscription.endpoint)
                {
                    tracing::warn!(
                        name: "agent_irc_push_failed",
                        error = &error as &dyn std::error::Error,
                        "a push subscription that is gone was not dropped"
                    );
                }
            }
            Ok(response) => tracing::info!(
                name: "agent_irc_push_refused",
                host = %host,
                status = response.status().as_u16(),
                "a push service refused a push"
            ),
            Err(error) => tracing::info!(
                name: "agent_irc_push_failed",
                host = %host,
                error = &error as &dyn std::error::Error,
                "a push did not reach its push service"
            ),
        }
    }
}

/// Whether `endpoint` may be pushed to: an `https` URL, or `http` to a
/// loopback address. INVENTED, NOT FROM SPEC: the agent POSTs to what the
/// client names, so plain HTTP goes nowhere but this host.
fn endpoint_allowed(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    let host = url.host_str().unwrap_or_default();
    match url.scheme() {
        "https" => !host.is_empty(),
        "http" => {
            host == "localhost"
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        _ => false,
    }
}

/// Whether `text` names `nick` as a whole word, ASCII case folded.
fn mentions(text: &str, nick: &str) -> bool {
    let (text, nick) = (text.to_ascii_lowercase(), nick.to_ascii_lowercase());
    let word =
        |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    text.match_indices(&nick).any(|(at, _)| {
        !word(text[..at].chars().next_back()) && !word(text[at + nick.len()..].chars().next())
    })
}

impl Session {
    /// `FAIL WEBPUSH <code> <context...> :<description>`.
    fn webpush_fail(&mut self, code: &str, context: &[&str], description: &str) {
        let mut params = vec!["WEBPUSH".to_owned(), code.to_owned()];
        params.extend(context.iter().map(|c| (*c).to_owned()));
        params.push(description.to_owned());
        let server = self.shared.server.clone();
        self.send_cut(Out::new(&server, "FAIL", params));
    }

    /// `WEBPUSH REGISTER|UNREGISTER`.
    pub(crate) fn webpush(&mut self, line: &Line) {
        let Some(push) = self.shared.web_push() else {
            self.numeric("421", &["WEBPUSH", "Unknown command"]);
            return;
        };
        let sub = line.param(0).unwrap_or_default().to_ascii_uppercase();
        let Some(endpoint) = line.param(1).map(str::to_owned) else {
            self.webpush_fail("INVALID_PARAMS", &[&sub], "Insufficient parameters");
            return;
        };
        let server = self.shared.server.clone();
        match sub.as_str() {
            "REGISTER" => {
                let Some(raw) = line.param(2) else {
                    self.webpush_fail(
                        "INVALID_PARAMS",
                        &[&sub, &endpoint],
                        "Insufficient parameters",
                    );
                    return;
                };
                if !endpoint_allowed(&endpoint) {
                    self.webpush_fail(
                        "INVALID_PARAMS",
                        &[&sub, &endpoint],
                        "The endpoint must be an https URL",
                    );
                    return;
                }
                let keys: std::collections::BTreeMap<String, String> = raw
                    .split(';')
                    .filter(|item| !item.is_empty())
                    .filter_map(|item| {
                        let (k, v) = item.split_once('=')?;
                        Some((k.to_owned(), unescape_tag_value(v)))
                    })
                    .collect();
                let valid = matches!(
                    (keys.get("p256dh"), keys.get("auth")),
                    (Some(p), Some(a)) if ClientKeys::parse(p, a).is_some()
                );
                if !valid {
                    self.webpush_fail(
                        "INVALID_PARAMS",
                        &[&sub, &endpoint],
                        "The keys must hold a P-256 p256dh and a 16-octet auth",
                    );
                    return;
                }
                let ext = json!({
                    "messageTags": self.caps.message_tags,
                    "serverTime": self.caps.server_time,
                });
                let subscription = Subscription::new(FRONT_END, endpoint.clone(), keys, ext);
                match push.subscriptions.register(&subscription) {
                    Ok(()) => {
                        self.send(&Out::new(
                            &server,
                            "WEBPUSH",
                            vec!["REGISTER".into(), endpoint],
                        ));
                    }
                    Err(error @ (PushError::TooMany | PushError::TooLong)) => {
                        self.webpush_fail("INVALID_PARAMS", &[&sub, &endpoint], &error.to_string());
                    }
                    Err(error) => {
                        tracing::warn!(
                            name: "agent_irc_push_failed",
                            error = &error as &dyn std::error::Error,
                            "a push subscription was not kept"
                        );
                        self.webpush_fail(
                            "INTERNAL_ERROR",
                            &[&sub, &endpoint],
                            "The subscription could not be kept",
                        );
                    }
                }
            }
            "UNREGISTER" => match push.subscriptions.unregister(FRONT_END, &endpoint) {
                Ok(_) => {
                    self.send(&Out::new(
                        &server,
                        "WEBPUSH",
                        vec!["UNREGISTER".into(), endpoint],
                    ));
                }
                Err(_) => self.webpush_fail(
                    "INTERNAL_ERROR",
                    &[&sub, &endpoint],
                    "The subscription could not be dropped",
                ),
            },
            _ => self.webpush_fail("INVALID_PARAMS", &[&sub], "Unknown subcommand"),
        }
    }
}

/// A line to push, as the client would see it, and its urgency.
struct Pushed {
    /// The line without its tags.
    out: Out,
    /// `msgid`, if any.
    msgid: Option<String>,
    /// The hub's time, if any.
    time: Option<u64>,
    urgency: &'static str,
}

impl Pushed {
    /// The line on the wire, without CR-LF, with the tags a client that
    /// registered with `ext` takes.
    fn wire(&self, ext: &serde_json::Value) -> String {
        let mut out = self.out.clone();
        if ext["messageTags"].as_bool() == Some(true) {
            if let Some(msgid) = &self.msgid {
                out = out.tag("msgid", msgid);
            }
            if ext["serverTime"].as_bool() == Some(true)
                && let Some(time) = self.time
            {
                out = out.tag("time", &server_time(time));
            }
        }
        out.to_wire(true).trim_end_matches("\r\n").to_owned()
    }
}

/// The line for message `m`, if the user would be woken for it: from
/// another user, in a query, or naming the user or replying to them in a
/// channel.
fn message_line(shared: &Shared, m: &Message) -> Option<Pushed> {
    let Sender::User(sender) = &m.sender else {
        return None;
    };
    let me = shared.names().own().clone();
    if *sender == me.uri || m.deleted.is_some() {
        return None;
    }
    let (target, direct, replies_to_me) = {
        let state = shared.store.state();
        let room = state.rooms.get(&m.room)?;
        if room.status != RoomStatus::Active {
            return None;
        }
        let replies_to_me = matches!(&m.in_reply_to, Some(Reply::Message(k))
            if state.messages.get(k).is_some_and(|t| t.sender == Sender::User(me.uri.clone())));
        if room.direct_peer(&me.uri) == Some(sender.as_str()) {
            (me.nick.clone(), true, replies_to_me)
        } else {
            (
                shared.names().channel(&m.room)?.to_owned(),
                false,
                replies_to_me,
            )
        }
    };
    let first = data(m.body.lines().find(|l| !l.trim().is_empty())?);
    if !direct && !replies_to_me && !mentions(&m.body, &me.nick) {
        return None;
    }
    let mut text = match first.strip_prefix("/me ") {
        Some(action) => format!("\x01ACTION {action}\x01"),
        None => first.clone(),
    };
    if text.len() > MAX_TEXT {
        let mut end = MAX_TEXT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    let who = shared.names().identity(sender);
    Some(Pushed {
        out: Out::new(&who.mask(), "PRIVMSG", vec![target, text]),
        msgid: Some(m.sender_msg_id.clone()),
        time: Some(m.accepted_at),
        urgency: "high",
    })
}

/// The lines `change` pushes.
fn lines_of(shared: &Shared, change: &Change) -> Option<Pushed> {
    match change {
        Change::MessageAdded(key) => {
            let m = shared.store.state().messages.get(key)?.clone();
            message_line(shared, &m)
        }
        Change::InvitePending(number) => {
            let invite = shared
                .store
                .state()
                .invites
                .iter()
                .find(|i| i.number == *number)?
                .clone();
            let me = shared.names().own().clone();
            let (source, channel) = {
                let mut names = shared.names();
                let source = match &invite.inviter {
                    Some(uri) => names.identity(uri).mask(),
                    None => shared.server.clone(),
                };
                (source, names.invite_channel(&invite))
            };
            Some(Pushed {
                out: Out::new(&source, "INVITE", vec![me.nick, channel]),
                msgid: None,
                time: None,
                urgency: "high",
            })
        }
        Change::ReadPositionMoved(key) => {
            let me = shared.names().own().clone();
            let (target, at) = {
                let state = shared.store.state();
                let position = state.read_positions.get(key)?;
                let at = state.messages.get(position.message.as_ref()?)?.accepted_at;
                let room = state.rooms.get(&position.room)?;
                let target = match room.direct_peer(&me.uri) {
                    Some(peer) => peer.to_owned(),
                    None => String::new(),
                };
                (target, at)
            };
            let target = if target.is_empty() {
                shared
                    .names()
                    .channel(&shared.store.state().read_positions.get(key)?.room)?
                    .to_owned()
            } else {
                shared.names().nick(&target)
            };
            Some(Pushed {
                out: Out::new(
                    &shared.server,
                    "MARKREAD",
                    vec![target, format!("timestamp={}", server_time(at))],
                ),
                msgid: None,
                time: None,
                urgency: "normal",
            })
        }
        _ => None,
    }
}

/// Follows the store's change feed until `stop`, pushing what
/// [`lines_of`] gives to every subscription.
pub(crate) async fn run(shared: Arc<Shared>, push: Arc<WebPush>, mut stop: watch::Receiver<bool>) {
    let store = Arc::clone(&shared.store);
    let mut feed = store.subscribe();
    let mut mark = store.last_seq();
    loop {
        tokio::select! {
            () = stopped(&mut stop) => return,
            woken = feed.recv() => match woken {
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
        let changes = match store.changes_since(mark) {
            Ok(changes) => changes,
            Err(_too_old) => {
                mark = store.last_seq();
                continue;
            }
        };
        let mut lines = Vec::new();
        for (seq, change) in changes {
            mark = seq;
            if let Some(line) = lines_of(&shared, &change) {
                lines.push(line);
            }
        }
        if lines.is_empty() {
            continue;
        }
        let from = lines.len().saturating_sub(MAX_PUSHES_PER_ROUND);
        let lines = &lines[from..];
        let subscriptions = match push.subscriptions.list(FRONT_END) {
            Ok(subscriptions) => subscriptions,
            Err(error) => {
                tracing::warn!(
                    name: "agent_irc_push_failed",
                    error = &error as &dyn std::error::Error,
                    "the push subscriptions could not be read"
                );
                continue;
            }
        };
        for subscription in subscriptions {
            let wires: Vec<(String, &'static str)> = lines
                .iter()
                .map(|l| (l.wire(&subscription.ext), l.urgency))
                .collect();
            let push = Arc::clone(&push);
            // In order, per subscription; subscriptions side by side.
            tokio::spawn(async move {
                for (wire, urgency) in wires {
                    push.push(&subscription, &wire, urgency).await;
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: the IRC custom of a highlight: the nick as a word, any
    /// case, not inside a longer nick.
    #[test]
    fn a_mention_is_the_nick_as_a_word() {
        assert!(mentions("alice-a: hi", "alice-a"));
        assert!(mentions("hi ALICE-A!", "alice-a"));
        assert!(mentions("ping alice-a", "alice-a"));
        assert!(!mentions("alice-ab: hi", "alice-a"));
        assert!(!mentions("xalice-a", "alice-a"));
        assert!(!mentions("hello", "alice-a"));
    }

    /// Oracle: §7.35's rule: https anywhere, http only to loopback.
    #[test]
    fn endpoints_are_https_or_loopback() {
        assert!(endpoint_allowed("https://pushgarden.emersion.fr/x"));
        assert!(endpoint_allowed("http://127.0.0.1:8080/push"));
        assert!(endpoint_allowed("http://[::1]/push"));
        assert!(endpoint_allowed("http://localhost/push"));
        assert!(!endpoint_allowed("http://push.example/x"));
        assert!(!endpoint_allowed("http://10.0.0.1/x"));
        assert!(!endpoint_allowed("ftp://push.example/x"));
        assert!(!endpoint_allowed("not a url"));
    }
}
