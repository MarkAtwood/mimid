//! Room state shared by the hub endpoints: the policy inputs read from a
//! room's GroupContext, and the provider domains of its members.

use std::collections::BTreeSet;

use mimi_mls::observer::Observer;
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::component_id::{PARTICIPANT_LIST, ROOM_METADATA};
use mimi_room_policy::BaseRoomPolicy;
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ComponentID, PREAUTH_LIST, ROLES_LIST};

use super::policy::RoomState;
use crate::config::Domain;
use mimi_protocol::components::{ComponentError, decode};

/// The URI scheme of MIMI identifiers (protocol-07 §2.1).
const MIMI_SCHEME_PREFIX: &str = "mimi://";

/// `uri` in the normal form of RFC 3986 §6.2.2.1 and §6.2.2.2: the scheme
/// and host in lowercase, percent-encoding hex digits in uppercase, and
/// percent-encoded unreserved characters (§2.3: ALPHA, DIGIT, `-`, `.`,
/// `_`, `~`) decoded. Two URIs with the same normal form are the same URI.
///
/// protocol-07 §5.8 says only that a handle "matches exactly", and §5.2 and
/// §5.7 do not say how user URIs compare. mimid reads RFC 3986 equivalence
/// as the clear meaning and looks a user or room up by this form (decision
/// mimid-1wgh.52). It is applied only to lookups: MLS credentials, the
/// participant list and anything signed are still compared byte for byte.
/// Nothing else is changed: the path keeps its case, and there is no
/// Unicode normalization or case folding. A URI with userinfo keeps its
/// authority as is, and a `%` not followed by two hex digits is left alone.
pub fn normalized_uri(uri: &str) -> std::borrow::Cow<'_, str> {
    let Some((scheme, rest)) = uri.split_once(':') else {
        return uri.into();
    };
    let scheme_ok = scheme
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    if !scheme_ok {
        return uri.into();
    }
    let mut out = scheme.to_ascii_lowercase();
    out.push(':');
    let rest = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            let (authority, tail) = after.split_at(end);
            out.push_str("//");
            if authority.contains('@') {
                out.push_str(&normalize_percent(authority));
            } else {
                out.push_str(&normalize_percent(authority).to_ascii_lowercase());
            }
            tail
        }
        None => rest,
    };
    out.push_str(&normalize_percent(rest));
    if out == uri { uri.into() } else { out.into() }
}

/// RFC 3986 §6.2.2.1 and §6.2.2.2 on percent-encodings: hex digits in
/// uppercase, unreserved characters decoded.
fn normalize_percent(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        if bytes[i] == b'%'
            && let (Some(&h), Some(&l)) = (bytes.get(i + 1), bytes.get(i + 2))
            && let (Some(h), Some(l)) = (hex(h), hex(l))
        {
            let byte = u8::try_from(h * 16 + l).expect("two hex digits fit a byte");
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                out.push(char::from(byte));
            } else {
                out.push_str(&format!("%{byte:02X}"));
            }
            i += 3;
            continue;
        }
        // Copy one UTF-8 character.
        let ch = text[i..]
            .chars()
            .next()
            .expect("i is on a character boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// [`normalized_uri`], logging at DEBUG when it changes `uri`, so a lookup
/// that succeeded only after normalizing can be seen (decision
/// mimid-1wgh.52: lenient on clear meaning, logged).
pub(crate) fn lookup_uri<'a>(uri: &'a str, field: &'static str) -> std::borrow::Cow<'a, str> {
    let normalized = normalized_uri(uri);
    if let std::borrow::Cow::Owned(canonical) = &normalized {
        tracing::debug!(
            field,
            uri,
            canonical,
            "URI normalized for lookup (RFC 3986 §6.2.2)"
        );
    }
    normalized
}

/// The domain of a `mimi://<domain>/...` user URI (protocol-07 §2.1), or
/// `None` for any other URI.
pub(super) fn user_domain(uri: &str) -> Option<&str> {
    uri.strip_prefix(MIMI_SCHEME_PREFIX)?
        .split('/')
        .next()
        .filter(|domain| !domain.is_empty())
}

/// The provider domain of a credential identity, which is a user URI
/// (decision mimid-1wgh.6.1), or `None` if it names no valid domain.
pub(crate) fn identity_domain(identity: &[u8]) -> Option<Domain> {
    std::str::from_utf8(identity)
        .ok()
        .and_then(user_domain)
        .and_then(|domain| Domain::try_from(domain.to_owned()).ok())
}

/// The most remote provider domains [`note_non_user_uri`] remembers.
/// INVENTED, NOT FROM SPEC.
const MAX_NOTED_DOMAINS: usize = 256;

/// Notes, once per provider domain per process, a remote identity whose
/// domain is valid but which is not a user URI `mimi://<domain>/u/<id>`
/// (protocol-07 §2.1). mimid accepts it, checking the domain only, and logs
/// the divergence (decision mimid-1wgh.6.80, Mark 2026-11-16; rule 3 of
/// mimid-1wgh.52). `field` names where it was seen. The callers' domains
/// are tied to the authenticated `From` domain, so the set stays small; it
/// is capped all the same.
pub(crate) fn note_non_user_uri(field: &'static str, identity: &[u8]) {
    static NOTED: std::sync::Mutex<std::collections::BTreeSet<Domain>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    let Some(domain) = identity_domain(identity) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(identity) else {
        return;
    };
    if user_uri_domain(text).is_some() {
        return;
    }
    // The set is valid after any panic: inserting is its only change.
    let mut noted = NOTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if noted.len() >= MAX_NOTED_DOMAINS || !noted.insert(domain.clone()) {
        return;
    }
    tracing::debug!(
        field,
        domain = domain.as_str(),
        uri = text,
        "remote user URI is not mimi://<domain>/u/<id>; accepted (logged once per domain)"
    );
}

/// The provider domain of a user URI `mimi://<domain>/u/<id>` (protocol-07
/// §2.1), or `None` for any other URI, including the provider URI
/// `mimi://<domain>` that is the hub's identity (decision mimid-1wgh.6.35).
pub(crate) fn user_uri_domain(uri: &str) -> Option<Domain> {
    typed_uri_domain(uri, "u")
}

/// The provider domain of a room URI `mimi://<domain>/r/<name>`
/// (protocol-07 §2.1), or `None` for any other URI.
pub(crate) fn room_uri_domain(uri: &str) -> Option<Domain> {
    typed_uri_domain(uri, "r")
}

/// The provider domain of a MIMI URI `mimi://<domain>/<kind>/<id>`, whose
/// first path segment `kind` is the identifier type (protocol-07 §2.1), or
/// `None` for any other URI.
fn typed_uri_domain(uri: &str, kind: &str) -> Option<Domain> {
    // protocol-07 §2.1; decision mimid-1wgh.6.76: `<id>` is one non-empty
    // path segment, with no query or fragment.
    let (_, id) = uri
        .strip_prefix(MIMI_SCHEME_PREFIX)?
        .split_once('/')?
        .1
        .split_once('/')
        .filter(|(segment, _)| *segment == kind)?;
    if id.is_empty() || id.contains(['/', '?', '#']) {
        return None;
    }
    identity_domain(uri.as_bytes())
}

/// Why a room's policy state cannot be read.
#[derive(Debug, thiserror::Error)]
pub(super) enum StateError {
    #[error(transparent)]
    Component(#[from] ComponentError),
}

/// The room's policy state from its GroupContext components. An absent
/// participant list, role list or preauthorization list is empty. An
/// absent `base_room_policy` makes an open room ([`RoomState::open`]) with
/// [`open_base_policy`] (decision mimid-1wgh.52, superseding
/// mimid-1wgh.6.51); a malformed one is an error.
pub(super) fn room_state(observer: &Observer) -> Result<RoomState, StateError> {
    fn component_or_default<T: Deserialize + Default>(
        observer: &Observer,
        component_id: ComponentID,
    ) -> Result<T, ComponentError> {
        observer
            .component(component_id)
            .map_or_else(|| Ok(T::default()), |bytes| decode(component_id, bytes))
    }
    let (base, open) = match observer.component(BASE_ROOM_POLICY) {
        Some(base) => (decode(BASE_ROOM_POLICY, base)?, false),
        None => (open_base_policy(), true),
    };
    Ok(RoomState {
        roles: component_or_default(observer, ROLES_LIST)?,
        preauth: component_or_default(observer, PREAUTH_LIST)?,
        base,
        participants: component_or_default(observer, PARTICIPANT_LIST)?,
        members: observer.members().into_iter().collect(),
        room_metadata: observer.component(ROOM_METADATA).map(<[u8]>::to_vec),
        open,
    })
}

/// The base policy an open room is judged by (decision mimid-1wgh.52):
/// membership not fixed, several devices, no limits, persistent, not
/// discoverable (room-policy-04 §5).
pub(super) fn open_base_policy() -> BaseRoomPolicy {
    BaseRoomPolicy {
        fixed_membership: false.into(),
        parent_dependant: false.into(),
        parent_room: vec![],
        multi_device: true.into(),
        max_clients: None,
        max_users: None,
        pseudonyms_allowed: false.into(),
        persistent_room: true.into(),
        discoverable: false.into(),
        policy_component_ids: vec![],
    }
}

/// The provider domains of the group's members: the domains of their
/// credential identities, which are their user URIs (decision
/// mimid-1wgh.6.1). A member whose identity names no domain is logged and
/// left out.
pub(super) fn member_domains(observer: &Observer) -> BTreeSet<String> {
    let mut domains = BTreeSet::new();
    for (leaf_index, identity) in observer.members() {
        match identity_domain(&identity) {
            Some(domain) => {
                domains.insert(domain.as_str().to_owned());
            }
            None => {
                tracing::warn!(
                    name: "member_domain_missing",
                    leaf_index,
                    "member identity names no domain; not delivered"
                )
            }
        }
    }
    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_domain_is_the_mimi_authority() {
        assert_eq!(user_domain("mimi://b.example/u/bob"), Some("b.example"));
        assert_eq!(user_domain("mimi://b.example"), Some("b.example"));
        for uri in ["https://b.example/u/bob", "mimi:///u/bob", "b.example", ""] {
            assert_eq!(user_domain(uri), None, "{uri}");
        }
        assert_eq!(
            user_domain("mimi://eve@b.example/u/bob"),
            Some("eve@b.example")
        );
    }

    #[test]
    fn normalized_uri_follows_rfc3986_6_2_2() {
        for (input, expected) in [
            ("mimi://b.example/u/bob", "mimi://b.example/u/bob"),
            ("MIMI://B.Example/u/bob", "mimi://b.example/u/bob"),
            (
                "mimi://b.example/u/%c3%a9mile",
                "mimi://b.example/u/%C3%A9mile",
            ),
            ("mimi://b.example/u/%62%6F%62", "mimi://b.example/u/bob"),
            ("mimi://b.example/u/a%2Fb", "mimi://b.example/u/a%2Fb"),
            ("mimi://b.example/u/a%2fb%7e", "mimi://b.example/u/a%2Fb~"),
            // The path keeps its case; no Unicode normalization.
            ("mimi://b.example/u/BOB", "mimi://b.example/u/BOB"),
            ("mimi://b.example/u/e%CC%81", "mimi://b.example/u/e%CC%81"),
            ("mimi://b.example/u/\u{e9}", "mimi://b.example/u/\u{e9}"),
            // Userinfo keeps its case; broken escapes are left alone.
            ("mimi://Eve@B.example/u/x", "mimi://Eve@B.example/u/x"),
            ("mimi://b.example/u/%G1%4", "mimi://b.example/u/%G1%4"),
            ("not a uri", "not a uri"),
            ("", ""),
        ] {
            assert_eq!(normalized_uri(input), expected, "{input}");
        }
        assert!(matches!(
            normalized_uri("mimi://b.example/u/bob"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn identity_domain_requires_a_valid_domain() {
        assert_eq!(
            identity_domain(b"mimi://b.example/u/bob").map(|d| d.as_str().to_owned()),
            Some("b.example".to_owned())
        );
        for identity in [
            &b"mimi://eve@b.example/u/bob"[..],
            b"mimi:///u/bob",
            b"mimi://b\xff.example/u/bob",
            b"",
        ] {
            assert!(identity_domain(identity).is_none(), "{identity:?}");
        }
    }

    /// Decision mimid-1wgh.6.80: a remote identity that is not
    /// mimi://<domain>/u/<id> is logged once per domain; user URIs and
    /// identities with no valid domain are not.
    #[test]
    fn a_non_user_remote_identity_is_logged_once_per_domain() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Clone, Default)]
        struct Count(Arc<Mutex<Vec<String>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Count {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                struct Domain(Option<String>);
                impl tracing::field::Visit for Domain {
                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        if field.name() == "domain" {
                            self.0 = Some(value.to_owned());
                        }
                    }
                    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {
                    }
                }
                let mut domain = Domain(None);
                event.record(&mut domain);
                if let Some(domain) = domain.0 {
                    self.0.lock().unwrap().push(domain);
                }
            }
        }
        let count = Count::default();
        let subscriber = tracing_subscriber::registry().with(count.clone());
        tracing::subscriber::with_default(subscriber, || {
            // Domains unique to this test, since the noted set is
            // process-wide.
            note_non_user_uri("t", b"mimi://nou-a.example/alice");
            note_non_user_uri("t", b"mimi://nou-a.example/bob");
            note_non_user_uri("t", b"mimi://nou-b.example/x/carol");
            note_non_user_uri("t", b"mimi://nou-c.example/u/dave");
            note_non_user_uri("t", b"https://nou-d.example/u/erin");
            note_non_user_uri("t", b"mimi://");
        });
        assert_eq!(*count.0.lock().unwrap(), ["nou-a.example", "nou-b.example"]);
    }
}
