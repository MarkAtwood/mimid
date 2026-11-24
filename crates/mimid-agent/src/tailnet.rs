//! Tailnet identity: the connection is the login
//! (docs/design/frontend-auth.md §4.6, decision A7; bead mimid-e13m.12).
//!
//! On a listener bound to a tailnet address, the agent can ask tailscaled
//! who is on the other end of a connection and let the owner's own
//! devices in with no password. It is **off by default**: `[tailnet]
//! identity = true` turns it on, and `mimid-agent <config> setup tailnet`
//! explains it and offers it.
//!
//! INVENTED, NOT FROM SPEC: every name here is mimid's. The shape comes
//! from Mark's tailircd, which takes `UserProfile.LoginName` and `Node`
//! from `lc.WhoIs` as the user with no password.
//!
//! # What matches
//!
//! A peer is let in when [`Tailnet::identify`] says so, which it does for
//! a node whose
//!
//! - user's `LoginName` is in `owners` — by default the owner of the
//!   agent's own node, read from LocalAPI `status` at start — **and**
//!   which is not tagged, not the agent's own node, and advertises no
//!   routes; or
//! - name is in `nodes`, or one of whose ACL tags is in `tags`.
//!
//! Anything else, a LocalAPI error included, falls back to the password
//! rules of §3: a failed WhoIs never lets a connection in.
//!
//! A peer on the loopback interface is asked about like any other, and
//! tailscaled's own answer is what refuses it: it knows no node at
//! `127.0.0.1`. §4.6's "same-host clients use loopback and the token" is
//! therefore enforced by tailscaled, with the own-node exclusion as the
//! backstop for a connection from the host to its own tailnet address —
//! which is why [`Tailnet::start`] refuses to run without the node id
//! that exclusion compares.
//!
//! The three exclusions each close a hole (§4.6):
//!
//! - **A tagged node has no user.** Tailscale gives it a placeholder
//!   profile, and tags are granted by whoever writes the ACL policy, so a
//!   tag matches only when it is listed by name.
//! - **The agent's own node** answers WhoIs for a connection from the
//!   host to its own tailnet address, so every local account on the host
//!   would pass as the owner. Clients on the host use loopback and a
//!   credential.
//! - **A node advertising subnet routes, or an exit node**, source-NATs
//!   the traffic it forwards to its own tailnet address, so a device on
//!   its LAN would pass as its owner.
//!
//! # Where it applies
//!
//! IRC only, today. The agent's HTTP endpoint keeps its credential on
//! purpose (decision A7): with no `Authorization` header a request would
//! be authorized by where it comes from, and a web page open in a browser
//! on the owner's laptop comes from the laptop, so any site the owner
//! visits could POST JMAP calls. CORS stops such a page reading the
//! answer, not the call happening.
//!
//! # Limitations
//!
//! - **A denial is this agent's own, not the tailnet's.** `/msg mimid
//!   tailnet deny <node>` refuses a node here and closes its sessions
//!   (bead mimid-e13m.18), and the list survives a restart in
//!   [`DENIED_FILE`], but the node keeps its place in the tailnet and can
//!   still reach every other service on it. The real revocation is
//!   removing the node in the admin console, which this module notices
//!   within `recheck_s`. Nothing takes a node off the deny list but
//!   editing that file, which is deliberate: an undeny from a client the
//!   denied node might be holding would be a way back in.
//! - **XMPP and Matrix** have no mapping yet, because neither front end
//!   exists (beads mimid-wmdj, mimid-rvqk). §4.6's table says what they
//!   will do: a fixed SCRAM word for XMPP, node-bound tokens for Matrix.
//! - **Linux first.** macOS's App Store Tailscale exposes the LocalAPI
//!   over a TCP port and a token file instead of a Unix socket
//!   (*unverified*), so `[tailnet]` does not work there.
//! - The LocalAPI answer's field names are read from tailscale's
//!   `apitype.Node` and `ipnstate.Status` as docs/design/frontend-auth.md
//!   §4.6 cites them; every field is optional here, and a missing one
//!   means no match rather than an error. `AllowedIPs` beyond the node's
//!   own `Addresses` is read as "advertises routes" (*unverified* that
//!   this is how tailscaled always reports an exit node).
//! - Headscale answers WhoIs the same way, with its own user names, so
//!   `owners` is written in that form (*unverified* exact format), but it
//!   issues no certificates: `[tls] source = "acme"` would be needed, and
//!   is not built (bead mimid-e13m.8).

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::tls::{TlsError, localapi_get};

/// How often an open session's node is checked again (§4.6).
pub const DEFAULT_RECHECK_SECS: u64 = 300;

/// The least `recheck_s` accepted, so a configuration cannot make the
/// agent ask tailscaled constantly.
pub const MIN_RECHECK_SECS: u64 = 10;

/// The nodes the user denied, one a line, in the state directory
/// (§4.6; bead mimid-e13m.18). INVENTED.
///
/// It is a file rather than a table in `mimid.sqlite`, which §4.6's
/// wording suggests: it is a short list of names written only by the
/// running daemon, so it needs no transaction and no schema, and the
/// `tailscale cert` consent of §5.2 is already kept this way beside it
/// ([`crate::tls::consented_names`]). Nothing else in the agent reads it,
/// so no other crate has to know about it.
pub const DENIED_FILE: &str = "tailnet-denied";

/// The most nodes the deny list holds, so the file cannot grow without
/// bound. INVENTED. Past it the oldest denial is dropped: the real
/// revocation is removing the node in the tailnet (§4.6).
pub const MAX_DENIED: usize = 256;

/// The `[tailnet]` table. INVENTED names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailnetSetting {
    /// Whether a connection from a matching tailnet node needs no
    /// credential. Off by default (decision A7).
    #[serde(default)]
    pub identity: bool,
    /// Tailscale login names whose own devices are let in. Empty, the
    /// default, means the owner of the agent's own node.
    #[serde(default)]
    pub owners: Vec<String>,
    /// Node names let in whoever owns them, e.g. `pixel-8`.
    #[serde(default)]
    pub nodes: Vec<String>,
    /// ACL tags let in, e.g. `tag:chat-client`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// tailscaled's LocalAPI socket.
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    /// How often an open session's node is checked again, in seconds.
    #[serde(default = "default_recheck")]
    pub recheck_s: u64,
}

impl Default for TailnetSetting {
    fn default() -> Self {
        Self {
            identity: false,
            owners: Vec::new(),
            nodes: Vec::new(),
            tags: Vec::new(),
            socket: default_socket(),
            recheck_s: DEFAULT_RECHECK_SECS,
        }
    }
}

fn default_socket() -> PathBuf {
    PathBuf::from(crate::tls::DEFAULT_TAILSCALE_SOCKET)
}

fn default_recheck() -> u64 {
    DEFAULT_RECHECK_SECS
}

impl TailnetSetting {
    /// What [`crate::Config::parse`] checks.
    ///
    /// # Errors
    ///
    /// A `recheck_s` under [`MIN_RECHECK_SECS`], or a `tags` entry that
    /// is not a `tag:` name, which would never match and is more likely a
    /// node name in the wrong list.
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if self.recheck_s < MIN_RECHECK_SECS {
            return Err("[tailnet] recheck_s is too small");
        }
        if self.tags.iter().any(|tag| !tag.starts_with("tag:")) {
            return Err("[tailnet] every tags entry must start with \"tag:\"");
        }
        Ok(())
    }
}

/// One node of the tailnet, as LocalAPI `whois` answers. Every field is
/// optional: a missing one means no match.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Node {
    /// The MagicDNS name, with its trailing dot as tailscaled gives it.
    #[serde(default)]
    name: String,
    /// The stable node id, which `status` also reports for the agent's
    /// own node.
    #[serde(default, rename = "StableID")]
    stable_id: String,
    /// The ACL tags, absent for an untagged node.
    #[serde(default)]
    tags: Vec<String>,
    /// The node's own addresses, as CIDR strings.
    #[serde(default)]
    addresses: Vec<String>,
    /// Everything routed to the node, which for a subnet router or exit
    /// node is more than its own addresses.
    #[serde(default, rename = "AllowedIPs")]
    allowed_ips: Vec<String>,
    /// The routes it advertises and that are approved.
    #[serde(default)]
    primary_routes: Vec<String>,
}

/// The user of a node.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserProfile {
    #[serde(default)]
    login_name: String,
}

/// LocalAPI `whois`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WhoIs {
    #[serde(default)]
    node: Node,
    #[serde(default)]
    user_profile: UserProfile,
}

/// What this module reads of LocalAPI `status`: the agent's own node and
/// the users it knows.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Status {
    #[serde(default, rename = "Self")]
    this: Option<StatusNode>,
    #[serde(default)]
    user: std::collections::BTreeMap<String, UserProfile>,
}

/// The agent's own node in `status`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StatusNode {
    #[serde(default, rename = "ID")]
    id: String,
    #[serde(default, rename = "UserID")]
    user_id: i64,
    #[serde(default)]
    tags: Vec<String>,
}

/// A node the agent let in: what §7.2 logs and `/msg mimid tailnet`
/// shows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TailnetPeer {
    /// The node's MagicDNS name, without its trailing dot.
    pub node: String,
    /// Why it matched: the login name, the node name or the tag.
    pub matched: String,
}

/// Tailnet identity as configured and started: the rules, the socket, and
/// the owner of the agent's own node if that is the default.
#[derive(Debug)]
pub struct Tailnet {
    setting: TailnetSetting,
    /// `owners` as it will be matched: the configured list, or the owner
    /// of the agent's own node.
    owners: Vec<String>,
    /// The agent's own node's id, which never matches.
    own_node: String,
    /// The nodes the user denied with `/msg mimid tailnet deny`, read
    /// from [`DENIED_FILE`] at start (§4.6).
    denied: std::sync::Mutex<Vec<String>>,
    /// Where [`DENIED_FILE`] lives.
    state_dir: PathBuf,
    /// Ticks whenever the deny list changes, so a session of a node just
    /// denied is asked about at once rather than at the next recheck.
    changes: tokio::sync::watch::Sender<u64>,
}

impl Tailnet {
    /// Reads LocalAPI `status` once, for the agent's own node and, with
    /// no configured `owners`, its owner.
    ///
    /// With `identity = false` this is never called: [`Tailnet`] exists
    /// only when identity is on.
    ///
    /// # Errors
    ///
    /// [`TlsError::LocalApi`] if tailscaled cannot be reached or its
    /// answer cannot be read, since starting with identity on and no way
    /// to ask would serve the password rules while the operator believes
    /// otherwise.
    pub async fn start(setting: &TailnetSetting, state_dir: &Path) -> Result<Self, TlsError> {
        let status: Status = fetch(&setting.socket, "/localapi/v0/status").await?;
        let this = status.this.unwrap_or_default();
        let mut owners = setting.owners.clone();
        if owners.is_empty() {
            // §4.6: a tagged own node has no owner to default to, so
            // identity stays off until `owners` is set.
            if !this.tags.is_empty() {
                return Err(TlsError::LocalApi {
                    socket: setting.socket.clone(),
                    why: "this node is tagged, so it has no owner to default to: \
                          set [tailnet] owners"
                        .to_owned(),
                });
            }
            let owner = status
                .user
                .get(&this.user_id.to_string())
                .map(|profile| profile.login_name.clone())
                .filter(|name| !name.is_empty())
                .ok_or_else(|| TlsError::LocalApi {
                    socket: setting.socket.clone(),
                    why: "tailscaled does not say who owns this node: \
                          set [tailnet] owners"
                        .to_owned(),
                })?;
            tracing::info!(
                name: "agent_tailnet_owner",
                owner = %owner,
                "tailnet identity is on for this node's owner"
            );
            owners.push(owner);
        }
        // The own-node exclusion is what stops every local account on the
        // host from passing as the owner (§4.6), and it is an id
        // comparison, so without the id there is no exclusion. Fail
        // closed rather than serve identity without it.
        if this.id.is_empty() {
            return Err(TlsError::LocalApi {
                socket: setting.socket.clone(),
                why: "tailscaled does not say what this node's id is, so a connection \
                      from this host could not be told apart from the owner's devices"
                    .to_owned(),
            });
        }
        let denied = read_denied(state_dir);
        if !denied.is_empty() {
            tracing::info!(
                name: "agent_tailnet_denied",
                nodes = %denied.join(", "),
                "these tailnet nodes are denied"
            );
        }
        Ok(Self {
            setting: setting.clone(),
            owners,
            own_node: this.id,
            denied: std::sync::Mutex::new(denied),
            state_dir: state_dir.to_owned(),
            changes: tokio::sync::watch::Sender::new(0),
        })
    }

    /// How often an open session is checked again.
    #[must_use]
    pub fn recheck(&self) -> Duration {
        Duration::from_secs(self.setting.recheck_s)
    }

    /// Who `peer` is, if the rules let it in with no credential; `None`
    /// for anything else, including a LocalAPI failure.
    pub async fn identify(&self, peer: SocketAddr) -> Option<TailnetPeer> {
        let path = format!("/localapi/v0/whois?addr={peer}");
        let who: WhoIs = match fetch(&self.setting.socket, &path).await {
            Ok(who) => who,
            Err(error) => {
                // Not a refusal of the connection: the password rules
                // apply instead (§4.6).
                tracing::debug!(
                    peer = %peer,
                    error = &error as &dyn std::error::Error,
                    "tailscaled did not say who this peer is"
                );
                return None;
            }
        };
        self.matches(&who)
    }

    /// Whether `node` is on the deny list.
    #[must_use]
    pub fn is_denied(&self, node: &str) -> bool {
        self.denied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|denied| denied == node)
    }

    /// The nodes the user denied, in the order they were denied.
    #[must_use]
    pub fn denied(&self) -> Vec<String> {
        self.denied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Adds `node` to the deny list and writes it; `false` if it was
    /// there already. [`Tailnet::changes`] then ticks, which is what ends
    /// that node's open sessions.
    ///
    /// # Errors
    ///
    /// [`TlsError::Write`] if the file cannot be written. The node is
    /// then not denied at all, rather than denied only until a restart.
    pub fn deny(&self, node: &str) -> Result<bool, TlsError> {
        let mut denied = self
            .denied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if denied.iter().any(|listed| listed == node) {
            return Ok(false);
        }
        let mut wanted = denied.clone();
        wanted.push(node.to_owned());
        if wanted.len() > MAX_DENIED {
            wanted.remove(0);
        }
        write_denied(&self.state_dir, &wanted)?;
        *denied = wanted;
        drop(denied);
        self.changes.send_modify(|count| *count += 1);
        tracing::info!(
            name: "agent_tailnet_deny",
            node,
            "a tailnet node was denied; its sessions close now"
        );
        Ok(true)
    }

    /// Ticks whenever the deny list changes.
    #[must_use]
    pub fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// [`Tailnet::identify`]'s rules over an answer already read.
    fn matches(&self, who: &WhoIs) -> Option<TailnetPeer> {
        let node = who.node.name.trim_end_matches('.').to_owned();
        // A denied node is refused before any rule, the listed ones
        // included: the user said no to this node by name (§4.6).
        if !node.is_empty() && self.is_denied(&node) {
            tracing::debug!(node = %node, "a denied tailnet node is refused");
            return None;
        }
        let peer = |matched: &str| {
            Some(TailnetPeer {
                node: node.clone(),
                matched: matched.to_owned(),
            })
        };
        // The listed ways in, which need no owner and allow a tagged
        // node: the operator named this node or this tag.
        if !node.is_empty() && self.setting.nodes.contains(&node) {
            return peer(&node);
        }
        if let Some(tag) = who
            .node
            .tags
            .iter()
            .find(|tag| self.setting.tags.iter().any(|listed| listed == *tag))
        {
            return peer(tag);
        }
        // The owner's own devices, with the three exclusions.
        let login = who.user_profile.login_name.as_str();
        if login.is_empty() || !self.owners.iter().any(|owner| owner == login) {
            return None;
        }
        if !who.node.tags.is_empty() {
            tracing::debug!(node = %node, "a tagged node is not let in by its owner");
            return None;
        }
        if who.node.stable_id == self.own_node {
            tracing::debug!(node = %node, "this node is the agent's own");
            return None;
        }
        if advertises_routes(&who.node) {
            tracing::debug!(node = %node, "a node that routes for others is not let in");
            return None;
        }
        peer(login)
    }
}

/// Whether `node` carries traffic that is not its own: an approved subnet
/// route, or anything routed to it beyond its own addresses, which is how
/// an exit node shows (§4.6; *unverified*).
fn advertises_routes(node: &Node) -> bool {
    if !node.primary_routes.is_empty() {
        return true;
    }
    node.allowed_ips
        .iter()
        .any(|route| !node.addresses.contains(route))
}

/// [`Tailnet`] as the IRC front end asks it (mimid-agent-irc's
/// `PeerIdentity`): the rules stay here, and that crate only asks.
impl mimid_agent_irc::PeerIdentity for Tailnet {
    fn identify(
        &self,
        peer: SocketAddr,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<mimid_agent_irc::PeerName>> + Send + '_>>
    {
        Box::pin(async move {
            self.identify(peer)
                .await
                .map(|matched| mimid_agent_irc::PeerName::new(matched.node, matched.matched))
        })
    }

    fn recheck(&self) -> Duration {
        self.recheck()
    }

    fn deny(&self, node: &str) -> Result<bool, String> {
        self.deny(node).map_err(|error| error.to_string())
    }

    fn denied(&self) -> Vec<String> {
        self.denied()
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes()
    }
}

/// The denied node names from [`DENIED_FILE`]; empty if it cannot be
/// read, which includes the first start.
fn read_denied(state_dir: &Path) -> Vec<String> {
    std::fs::read_to_string(state_dir.join(DENIED_FILE))
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_owned)
                .take(MAX_DENIED)
                .collect()
        })
        .unwrap_or_default()
}

/// Writes `nodes` to [`DENIED_FILE`], mode 0600 as the consent file is.
fn write_denied(state_dir: &Path, nodes: &[String]) -> Result<(), TlsError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = state_dir.join(DENIED_FILE);
    let fail = |source| TlsError::Write {
        path: path.clone(),
        source,
    };
    let mut text = String::from(
        "# Tailnet nodes denied with `/msg mimid tailnet deny`. They are\n\
         # refused even when the rules in [tailnet] would let them in. The\n\
         # real revocation is removing the node in the tailnet.\n",
    );
    for node in nodes {
        text.push_str(node);
        text.push('\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(fail)?;
    file.write_all(text.as_bytes()).map_err(fail)
}

/// A LocalAPI `GET` whose JSON body is `T`.
async fn fetch<T: serde::de::DeserializeOwned>(socket: &Path, path: &str) -> Result<T, TlsError> {
    let body = localapi_get(socket, path).await?;
    serde_json::from_slice(&body).map_err(|error| TlsError::LocalApi {
        socket: socket.to_owned(),
        why: format!("the answer to {path} could not be read: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`Tailnet`] with these rules and no LocalAPI, to test the
    /// matching alone.
    fn rules(setting: TailnetSetting, owners: &[&str], own_node: &str) -> Tailnet {
        Tailnet {
            setting,
            owners: owners.iter().map(|o| (*o).to_owned()).collect(),
            own_node: own_node.to_owned(),
            denied: std::sync::Mutex::new(Vec::new()),
            state_dir: PathBuf::from("/nonexistent"),
            changes: tokio::sync::watch::Sender::new(0),
        }
    }

    fn whois(json: serde_json::Value) -> WhoIs {
        serde_json::from_value(json).unwrap()
    }

    /// Oracle: docs/design/frontend-auth.md §4.6: the owner's own
    /// untagged, non-routing node is let in, and nothing else is.
    #[test]
    fn the_owners_own_device_is_let_in() {
        let tailnet = rules(TailnetSetting::default(), &["alice@github"], "nSELF");
        let matched = tailnet.matches(&whois(serde_json::json!({
            "Node": {
                "Name": "pixel-8.tailnet.ts.net.",
                "StableID": "nPIXEL",
                "Addresses": ["100.64.1.9/32"],
                "AllowedIPs": ["100.64.1.9/32"],
            },
            "UserProfile": {"LoginName": "alice@github"},
        })));
        assert_eq!(
            matched,
            Some(TailnetPeer {
                node: "pixel-8.tailnet.ts.net".to_owned(),
                matched: "alice@github".to_owned(),
            })
        );
        // Another user's device on the same tailnet.
        assert_eq!(
            tailnet.matches(&whois(serde_json::json!({
                "Node": {"Name": "bobs-laptop.tailnet.ts.net.", "StableID": "nBOB"},
                "UserProfile": {"LoginName": "bob@github"},
            }))),
            None
        );
        // No profile at all, which is what a failed or empty answer is.
        assert_eq!(tailnet.matches(&whois(serde_json::json!({}))), None);
    }

    /// Oracle: §4.6's three exclusions, each for its own reason.
    #[test]
    fn tagged_own_and_routing_nodes_are_excluded() {
        let tailnet = rules(TailnetSetting::default(), &["alice@github"], "nSELF");
        let owned = |node: serde_json::Value| {
            tailnet.matches(&whois(serde_json::json!({
                "Node": node,
                "UserProfile": {"LoginName": "alice@github"},
            })))
        };
        // Tagged: no user, and tags come from whoever writes the ACL.
        assert_eq!(
            owned(serde_json::json!({"Name": "ci.ts.net.", "Tags": ["tag:ci"]})),
            None
        );
        // The agent's own node: every local account would pass as the
        // owner.
        assert_eq!(
            owned(serde_json::json!({"Name": "host.ts.net.", "StableID": "nSELF"})),
            None
        );
        // A subnet router: it source-NATs its LAN to its own address.
        assert_eq!(
            owned(serde_json::json!({
                "Name": "router.ts.net.",
                "StableID": "nROUTER",
                "Addresses": ["100.64.1.5/32"],
                "PrimaryRoutes": ["192.168.1.0/24"],
            })),
            None
        );
        // An exit node: more is routed to it than its own addresses.
        assert_eq!(
            owned(serde_json::json!({
                "Name": "exit.ts.net.",
                "StableID": "nEXIT",
                "Addresses": ["100.64.1.6/32"],
                "AllowedIPs": ["100.64.1.6/32", "0.0.0.0/0", "::/0"],
            })),
            None
        );
    }

    /// Oracle: §4.6: a listed node or tag is let in whoever owns it,
    /// which is how a tagged client is allowed at all.
    #[test]
    fn listed_nodes_and_tags_are_let_in() {
        let setting = TailnetSetting {
            nodes: vec!["pixel-8.tailnet.ts.net".to_owned()],
            tags: vec!["tag:chat-client".to_owned()],
            ..TailnetSetting::default()
        };
        let tailnet = rules(setting, &["alice@github"], "nSELF");
        // A node someone else owns, named by the operator.
        assert_eq!(
            tailnet
                .matches(&whois(serde_json::json!({
                    "Node": {"Name": "pixel-8.tailnet.ts.net.", "StableID": "nPIXEL"},
                    "UserProfile": {"LoginName": "bob@github"},
                })))
                .map(|peer| peer.matched),
            Some("pixel-8.tailnet.ts.net".to_owned())
        );
        // A tagged node whose tag is listed, which the owner rule refuses.
        assert_eq!(
            tailnet
                .matches(&whois(serde_json::json!({
                    "Node": {
                        "Name": "kiosk.tailnet.ts.net.",
                        "StableID": "nKIOSK",
                        "Tags": ["tag:chat-client", "tag:other"],
                    },
                    "UserProfile": {"LoginName": "tagged-devices"},
                })))
                .map(|peer| peer.matched),
            Some("tag:chat-client".to_owned())
        );
        // A tag that is not listed.
        assert_eq!(
            tailnet.matches(&whois(serde_json::json!({
                "Node": {"Name": "other.ts.net.", "Tags": ["tag:other"]},
                "UserProfile": {"LoginName": "tagged-devices"},
            }))),
            None
        );
    }

    #[test]
    fn the_setting_is_checked() {
        let bad_tag = TailnetSetting {
            tags: vec!["chat-client".to_owned()],
            ..TailnetSetting::default()
        };
        assert!(bad_tag.check().is_err());
        let too_often = TailnetSetting {
            recheck_s: 1,
            ..TailnetSetting::default()
        };
        assert!(too_often.check().is_err());
        assert!(TailnetSetting::default().check().is_ok());
    }
}
