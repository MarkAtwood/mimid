//! The agent's VTC surface: what a client needs to hold a call whose
//! room is a MIMI room (bead mimid-1wgh.114.2; draft-atwood-jmap-vtc-00
//! as extended on 2026-11-23).
//!
//! A call is a room of its own, parent-dependent on the chat it belongs
//! to (room-policy-04 §5; decision mimid-1wgh.113). Its signalling goes
//! through that room's own messages
//! (`mimid_agent_core::call_signal`) and its media secret comes from
//! that room's MLS group (`Agent::media_secret`), so neither needs a
//! media service. What a client cannot get from either is somewhere to
//! relay media when the two ends cannot reach each other directly, and
//! that is what this module's configuration carries.
//!
//! # Limitations
//!
//! - NAT traversal is the one part of a call no amount of MLS makes
//!   peer-to-peer. A relay learns the addresses of the clients that use
//!   it and that encrypted bytes flow between them; it never learns the
//!   media, which is why a relay is acceptable at all.
//! - The default relay is a PUBLIC THIRD PARTY's
//!   ([`demo_ice_servers`]). It makes a call work out of the box, which
//!   is why Mark chose it, and it is the arrangement
//!   draft-atwood-jmap-vtc-00 §NAT Traversal Is Not Negotiated warns
//!   about: when both ends use the same third party's relay, that party
//!   learns both addresses and that those two parties spoke. A
//!   deployment that minds configures its own.

use jmap_vtc_types::VtcIceServer;

/// The STUN and TURN servers a deployment offers its clients when it
/// configures none, taken from MarkAtwood/ParlorVTC's `web/webrtc.js` so
/// that a call works with no setup at all (Mark 2026-11-23: "for the sake
/// of fast and easy demo, the default TURN server is the one from
/// Parlor"). INVENTED, NOT FROM SPEC, and not a recommendation: see this
/// module's limitations.
///
/// The TURN credentials are the public ones Jami publishes for its own
/// relay, which is why they are in the source rather than in a secret.
#[must_use]
pub fn demo_ice_servers() -> Vec<VtcIceServer> {
    let server = |urls: &[&str], credentials: Option<(&str, &str)>| {
        serde_json::from_value::<VtcIceServer>(serde_json::json!({
            "urls": urls,
            "username": credentials.map(|(user, _)| user),
            "credential": credentials.map(|(_, secret)| secret),
        }))
        .expect("a VtcIceServer of our own making")
    };
    vec![
        server(&["stun:stun.l.google.com:19302"], None),
        server(&["stun:stun.jami.net:3478"], None),
        server(
            &[
                "turn:turn.jami.net:3478",
                "turn:turn.jami.net:3478?transport=tcp",
            ],
            Some(("ring", "ring")),
        ),
    ]
}

/// The Session capability this surface is advertised under
/// (draft-atwood-jmap-vtc-00 §Account-Level Capability Object). Absent
/// from the Session when the surface is off (decision mimid-1wgh.119).
pub const CAPABILITY: &str = jmap_vtc_types::JMAP_VTC_URI;

/// How the agent's VTC surface is configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtcOptions {
    /// Whether the surface is offered at all. Off by default: decision
    /// mimid-1wgh.119, because a capability that hands out key material
    /// should wait for a client that uses it, and nothing implements the
    /// extension yet. When off, the capability is not advertised and
    /// neither method answers.
    pub enabled: bool,
    /// The STUN and TURN servers to advertise
    /// (`VtcCapability::ice_servers`). Empty advertises none, which
    /// leaves a client to its own. Defaults to [`demo_ice_servers`].
    pub ice_servers: Vec<VtcIceServer>,
}

impl Default for VtcOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            ice_servers: demo_ice_servers(),
        }
    }
}

impl VtcOptions {
    /// The surface, offered, with the default relays.
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    /// The surface with `servers` in place of the default relays.
    #[must_use]
    pub fn with_ice_servers(mut self, servers: Vec<VtcIceServer>) -> Self {
        self.ice_servers = servers;
        self
    }
}

/// What this agent advertises as `urn:ietf:params:jmap:vtc`
/// (draft-atwood-jmap-vtc-00 §Account-Level Capability Object).
///
/// Narrow on purpose. mimid has no media plane of its own: it hosts the
/// call's MIMI room, carries its signalling and exports its media
/// secret, and the client does the media. So it advertises ROOM CALLS
/// only, and nothing that would need a server-side media pipeline.
///
/// Each `false` here closes a path in the handlers that mimid could not
/// honour: no ring call, so no ring targets to notify and no ring
/// timeout; no scheduled call, so no clock to fire; no breakout rooms,
/// no recording, no livestream, no lobby, since every one of those wants
/// a server that can see or compose media.
#[must_use]
pub fn capability(options: &VtcOptions) -> jmap_vtc_types::VtcCapability {
    serde_json::from_value(serde_json::json!({
        "mayCreateCall": true,
        "supportsRingCalls": false,
        "supportsRoomCalls": true,
        "supportsScheduledCalls": false,
        "supportsRecording": false,
        "supportsLivestream": false,
        "livestreamModes": [],
        "supportsRecordingPause": false,
        "livestreamPushSchemes": [],
        "layouts": [],
        "supportsLobby": false,
        "supportsBreakoutRooms": false,
        "supportedMediaTypes": ["audio", "video", "screen"],
        "maxParticipantsPerCall": serde_json::Value::Null,
        "maxConcurrentCalls": serde_json::Value::Null,
        "iceServers": options.ice_servers,
        // The agent keys a call from the call room's MLS group and
        // signals it through that room's messages, which is what
        // supportsMimiCalls says (draft-atwood-jmap-vtc-00 §Capability).
        "supportsMimiCalls": true,
        // And it exports that room's per-epoch secret as input keying
        // material, which is what supportsMimiKeyedCalls says
        // (draft-atwood-jmap-vtc-00 §Account-Level Capability Object, the
        // addition of jmap-chat-spec fb05ead). A server advertising
        // false, or omitting it, offers neither VTCCall/signal nor
        // VTCCall/exportMediaSecret; this agent offers both, over the
        // call room's own MLS group (`VtcBackend::export_media_secret`).
        "supportsMimiKeyedCalls": true,
    }))
    .expect("a VtcCapability of our own making")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults are ParlorVTC's, and the TURN entry carries the
    /// credentials a TURN server needs while the STUN entries carry
    /// none: a STUN entry with a null username is not what WebRTC
    /// expects.
    #[test]
    fn the_demo_relays_are_parlors() {
        let servers = demo_ice_servers();
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0].urls, ["stun:stun.l.google.com:19302"]);
        assert!(servers[0].username.is_none() && servers[0].credential.is_none());
        assert!(servers[1].urls[0].starts_with("stun:stun.jami.net"));
        let turn = &servers[2];
        assert_eq!(turn.urls.len(), 2, "UDP and the TCP fallback");
        assert!(turn.urls.iter().all(|url| url.starts_with("turn:")));
        assert_eq!(turn.username.as_deref(), Some("ring"));
        assert_eq!(turn.credential.as_deref(), Some("ring"));
    }

    /// Off unless asked for (decision mimid-1wgh.119), and the relays
    /// are there either way so that turning it on needs one field.
    #[test]
    fn the_surface_is_off_by_default() {
        assert!(!VtcOptions::default().enabled);
        assert!(VtcOptions::enabled().enabled);
        assert_eq!(VtcOptions::default().ice_servers, demo_ice_servers());
        assert!(
            VtcOptions::enabled()
                .with_ice_servers(Vec::new())
                .ice_servers
                .is_empty()
        );
    }

    /// The capability advertises what the handlers will honour, and nothing
    /// more: every `false` closes a path that would need a media plane
    /// mimid does not have.
    #[test]
    fn the_capability_offers_only_room_calls() {
        let cap = capability(&VtcOptions::enabled());
        assert!(cap.supports_room_calls, "the one shape mimid can host");
        assert!(!cap.supports_ring_calls, "no ring targets to notify");
        assert!(!cap.supports_scheduled_calls, "no clock to fire");
        assert!(!cap.supports_recording && !cap.supports_livestream);
        assert!(!cap.supports_breakout_rooms && !cap.supports_lobby);
        assert!(cap.may_create_call);
        // The relays reach the client through the capability, which is the
        // channel they belong on.
        assert_eq!(cap.ice_servers.as_deref(), Some(&demo_ice_servers()[..]));
        // And the MIMI keying is advertised, since it is what the agent does
        // that a plain VTC server does not.
        assert_eq!(
            cap.extra.get("supportsMimiCalls"),
            Some(&serde_json::Value::Bool(true))
        );
    }
}
