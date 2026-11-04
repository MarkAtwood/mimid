//! Room state shared by the hub endpoints: the policy inputs read from a
//! room's GroupContext, and the provider domains of its members.

use std::collections::BTreeSet;

use mimi_mls::observer::Observer;
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ComponentID, PREAUTH_LIST, ROLES_LIST};

use super::components::{ComponentError, decode};
use super::policy::RoomState;
use crate::config::Domain;

/// The URI scheme of MIMI identifiers (protocol-07 §2.1).
const MIMI_SCHEME_PREFIX: &str = "mimi://";

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
    #[error("component {0:#06x} is absent")]
    Missing(ComponentID),
    #[error(transparent)]
    Component(#[from] ComponentError),
}

/// The room's policy state from its GroupContext components. An absent
/// participant list, role list or preauthorization list is empty; an
/// absent `base_room_policy` is an error (decision mimid-1wgh.6.51).
pub(super) fn room_state(observer: &Observer) -> Result<RoomState, StateError> {
    fn component_or_default<T: Deserialize + Default>(
        observer: &Observer,
        component_id: ComponentID,
    ) -> Result<T, ComponentError> {
        observer
            .component(component_id)
            .map_or_else(|| Ok(T::default()), |bytes| decode(component_id, bytes))
    }
    let base = observer
        .component(BASE_ROOM_POLICY)
        .ok_or(StateError::Missing(BASE_ROOM_POLICY))?;
    Ok(RoomState {
        roles: component_or_default(observer, ROLES_LIST)?,
        preauth: component_or_default(observer, PREAUTH_LIST)?,
        base: decode(BASE_ROOM_POLICY, base)?,
        participants: component_or_default(observer, PARTICIPANT_LIST)?,
        members: observer.members().into_iter().collect(),
    })
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
            None => tracing::warn!(leaf_index, "member identity names no domain; not delivered"),
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
}
