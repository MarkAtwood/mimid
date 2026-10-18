//! The `join_link_policy` and `join_links` components of room-policy-04
//! §6.2.

use std::collections::HashSet;

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{Bool, PolicyError, Uri};

/// The `JoinLinkPolicy` struct of room-policy-04 §6.2: how new join links
/// behave, and the data of the `join_link_policy` component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct JoinLinkPolicy {
    /// `bool on_request`. If true, at most one join link is persisted in
    /// the room policy; otherwise several may be.
    pub on_request: Bool,
    /// `opaque join_link<V>`: the URI a client may use to request an
    /// invite code, which the §6.2 prose calls `link_requests`. A
    /// zero-length value means there is none (decision mimid-1wgh.3.21).
    /// The bytes on the wire are the same as an `opaque<V>`; as a
    /// [`Uri`], a non-empty value must be an RFC 3986 `URI` (decisions
    /// mimid-1wgh.36, mimid-1wgh.3.55).
    // room-policy-04 §6.2; decision mimid-1wgh.3.55
    pub join_link: Uri,
    /// `bool multiuser`. If true, links can be generated for several users.
    pub multiuser: Bool,
    /// `uint32 expiration`: how many seconds a new link may stay valid
    /// after it is created.
    pub expiration: u32,
}

/// `JoinLinkPolicy JoinLinkPolicyData` of room-policy-04 §6.2.
pub type JoinLinkPolicyData = JoinLinkPolicy;

/// `JoinLinkPolicy JoinLinkPolicyUpdate` of room-policy-04 §6.2: an
/// `AppDataUpdate` that replaces the whole `join_link_policy` (decision
/// mimid-1wgh.3.20).
pub type JoinLinkPolicyUpdate = JoinLinkPolicy;

/// The `JoinLink` struct of room-policy-04 §6.2: one active join link.
///
/// `join_link` is opaque: §6.2 does not say what it holds, so this crate
/// does not interpret or check it (decision mimid-1wgh.3.56).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct JoinLink {
    /// `opaque join_link<V>`.
    // room-policy-04 §6.2; decision mimid-1wgh.3.56
    pub join_link: Vec<u8>,
}

/// `JoinLink JoinLinksData<V>` of room-policy-04 §6.2: the active join
/// links, and the data of the `join_links` component.
pub type JoinLinksData = Vec<JoinLink>;

/// The `JoinLinksUpdate` struct of room-policy-04 §6.2: an `AppDataUpdate`
/// that edits the `join_links` component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct JoinLinksUpdate {
    /// `uint32 removedIndices<V>`: indexes into the list before the update
    /// (decision mimid-1wgh.3.19).
    pub removed_indices: Vec<u32>,
    /// `JoinLink added_links<V>`: links appended after the removals.
    pub added_links: Vec<JoinLink>,
}

impl JoinLinksUpdate {
    /// Applies this update to `join_links` and returns the new list.
    ///
    /// Every index in `removed_indices` refers to `join_links` as given.
    /// The entries they name are removed first, keeping the order of the
    /// rest, and then `added_links` are appended in order (decision
    /// mimid-1wgh.3.19). `removed_indices` may be in any order (decision
    /// mimid-1wgh.3.58).
    ///
    /// # Errors
    ///
    /// The update is rejected as a whole, and nothing is applied, if an
    /// index is out of range ([`PolicyError::RemovedIndexOutOfRange`]) or
    /// appears more than once ([`PolicyError::DuplicateRemovedIndex`]). If
    /// several indices are bad, the first in wire order is reported
    /// (decision mimid-1wgh.3.58).
    pub fn apply(&self, join_links: &[JoinLink]) -> Result<JoinLinksData, PolicyError> {
        // room-policy-04 §6.2; decision mimid-1wgh.3.58
        let mut removed = HashSet::with_capacity(self.removed_indices.len());
        for &index in &self.removed_indices {
            let position = usize::try_from(index)
                .ok()
                .filter(|&position| position < join_links.len())
                .ok_or(PolicyError::RemovedIndexOutOfRange(index))?;
            if !removed.insert(position) {
                return Err(PolicyError::DuplicateRemovedIndex(index));
            }
        }
        Ok(join_links
            .iter()
            .enumerate()
            .filter(|(position, _)| !removed.contains(position))
            .map(|(_, link)| link)
            .chain(&self.added_links)
            .cloned()
            .collect())
    }
}
