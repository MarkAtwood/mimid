//! draft-atwood-mls-didwebvh-credential-01 in the agent (bead
//! mimid-1wgh.4.81.18): the settings, the contact pins of §Reference
//! Identifiers, and the keyMaterial requirements of a `did_webvh` room.
//!
//! An agent runs with a BasicCredential by default and supports
//! `did_webvh` in its rooms (decision mimid-1wgh.4.81.23). It switches to a
//! `did_webvh` credential when its user's controller hands it a log that
//! lists the device's signature key and the user's URI in `alsoKnownAs`
//! (decision mimid-1wgh.4.81.21), either through
//! [`crate::Agent::use_did_webvh_credential`] or a log file named in
//! [`DidWebvhConfig::log_file`] and read at [`crate::Agent::open`]. The
//! same method takes each newer log while the agent runs (the daemon's
//! endpoint and file watch, bead mimid-1wgh.4.81.28): it commits the log
//! to every active room, or, where that Commit cannot be built, sends it
//! as an Update proposal that the room's lowest other leaf commits.
//!
//! # Limitations
//!
//! - The switch from BasicCredential to `did_webvh` is allowed only before
//!   the identity's first KeyPackage and room: a leaf cannot change
//!   credential type (decision mimid-1wgh.4.81.15), and KeyPackages
//!   already published would still carry the BasicCredential.
//!   INVENTED, NOT FROM SPEC.
//! - The controller side (writing logs, holding update keys) is not part of
//!   the agent; it is [`mimi_mls::mls_didwebvh::controller`], run by the
//!   user wherever the update keys are kept (draft §Custody).
//! - Pins are kept per agent, not shared between a user's devices.
//! - The record is an `app_data_dictionary` component (decision
//!   mimid-1wgh.4.81.33), so a pending GroupContextExtensions proposal no
//!   longer blocks a credential Commit; the Update-proposal fallback is for
//!   Commits that still cannot be built, such as one covering a pending
//!   record update that names an SCID with no leaf (decision
//!   mimid-1wgh.4.65), and the member that commits the Update fails the
//!   same way then.
//! - A log file at [`crate::Agent::open`] older than the log the agent
//!   holds is skipped with a warning; one that is neither older nor a
//!   successor stops the agent from opening.

use std::collections::BTreeMap;
use std::path::PathBuf;

use mimi_mls::mls_didwebvh::CodePoints;

/// How an agent uses the `did_webvh` credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidWebvhConfig {
    /// The `did_webvh` credential type and the record's
    /// `app_data_dictionary` component ID, which IANA has not assigned.
    /// Every member of a room must use the same values. Defaults to the
    /// draft's suggested credential type 0x0008 and the private-use
    /// component 0xF013 (decision mimid-1wgh.4.81.35).
    pub code_points: CodePoints,
    /// Whether a BasicCredential identity lists `did_webvh` in its leaves
    /// and enforces the draft's group rules, which a room with `did_webvh`
    /// members requires of every member (decision mimid-1wgh.4.81.23).
    /// Defaults to true.
    pub support: bool,
    /// A `did.jsonl` the user's controller writes for this device. When
    /// set, [`crate::Agent::open`] reads it and, if it is newer than the
    /// credential the agent holds, uses it
    /// ([`crate::Agent::use_did_webvh_credential`]).
    pub log_file: Option<PathBuf>,
    /// The `did-witness.json` that goes with `log_file`, if the log has
    /// witnesses.
    pub witness_file: Option<PathBuf>,
}

impl Default for DidWebvhConfig {
    fn default() -> Self {
        Self {
            code_points: CodePoints::DEFAULT,
            support: true,
            log_file: None,
            witness_file: None,
        }
    }
}

/// One leaf of a room as the agent sees it: the user it belongs to and,
/// for a `did_webvh` leaf, its SCID.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RoomClient {
    /// The leaf index.
    pub leaf: u32,
    /// The user URI: the BasicCredential identity, or the URI a
    /// `did_webvh` leaf's log names (decision mimid-1wgh.4.81.21); empty
    /// if it names none.
    pub user: String,
    /// The SCID of a `did_webvh` leaf (draft §Reference Identifiers), or
    /// `None` for a BasicCredential leaf.
    pub scid: Option<String>,
    /// The DID of a `did_webvh` leaf: the `id` of its log's head DID
    /// document (`did:webvh:<SCID>:<domain>...`), which the draft says
    /// applications SHOULD display; `None` for a BasicCredential leaf.
    pub did: Option<String>,
}

/// What [`check_pin`] makes of a leaf presented for a contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pin {
    /// Nothing pinned and nothing to pin: a BasicCredential leaf of a user
    /// never seen with `did_webvh`.
    Unpinned,
    /// The SCID matches the pin, or was pinned now.
    Matches,
    /// The contact is pinned to `pinned`, and the leaf presents `presented`
    /// (`None`: a BasicCredential leaf).
    Changed {
        pinned: String,
        presented: Option<String>,
    },
}

/// draft-atwood-mls-didwebvh-credential-01 §Reference Identifiers: pins
/// `scid` for `user` the first time it is learned and compares it after.
/// A BasicCredential leaf (`scid` is `None`) for a user pinned to an SCID
/// is a change too: otherwise a provider could add a BasicCredential
/// device for a user whose devices its own update keys control (decision
/// mimid-1wgh.4.81.21). `user` is a normalized user URI.
pub(crate) fn check_pin(
    pins: &mut BTreeMap<String, String>,
    user: &str,
    scid: Option<&str>,
) -> Pin {
    match (pins.get(user), scid) {
        (Some(pinned), Some(scid)) if pinned == scid => Pin::Matches,
        (Some(pinned), presented) => Pin::Changed {
            pinned: pinned.clone(),
            presented: presented.map(str::to_owned),
        },
        (None, Some(scid)) => {
            pins.insert(user.to_owned(), scid.to_owned());
            Pin::Matches
        }
        (None, None) => Pin::Unpinned,
    }
}

/// The RFC 9420 §11.1 `RequiredCapabilities` of a keyMaterial request
/// (protocol-07 §5.2) for a room: mimid's own requirements, the
/// `app_data_dictionary` extension (0x0006) and the `AppDataUpdate`
/// proposal (0x0008) of mls-extensions-11, plus, in a room whose
/// GroupContext carries the `did_webvh` record, the `did_webvh` credential
/// type (decision mimid-1wgh.4.81.24).
///
/// Such a room's GroupContext `app_components` names the record component,
/// which a KeyPackage must list too, but `RequiredCapabilities` has no
/// field for components: the credential type stands for it, and the
/// KeyPackages that come back are checked with
/// [`mimi_mls::didwebvh::key_package_lists_record`] (decision
/// mimid-1wgh.4.81.36).
pub(crate) fn required_capabilities(did_webvh_room: Option<CodePoints>) -> Vec<u8> {
    match did_webvh_room {
        None => vec![0x02, 0x00, 0x06, 0x02, 0x00, 0x08, 0x00],
        Some(code_points) => {
            let [ch, cl] = code_points.credential_type().to_be_bytes();
            vec![0x02, 0x00, 0x06, 0x02, 0x00, 0x08, 0x02, ch, cl]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_contact_is_pinned_on_first_sight_and_a_change_is_caught() {
        let mut pins = BTreeMap::new();
        let alice = "mimi://a.example/u/alice";
        assert_eq!(check_pin(&mut pins, alice, None), Pin::Unpinned);
        assert!(pins.is_empty());
        assert_eq!(check_pin(&mut pins, alice, Some("QmA")), Pin::Matches);
        assert_eq!(pins.get(alice).map(String::as_str), Some("QmA"));
        assert_eq!(check_pin(&mut pins, alice, Some("QmA")), Pin::Matches);
        assert_eq!(
            check_pin(&mut pins, alice, Some("QmB")),
            Pin::Changed {
                pinned: "QmA".to_owned(),
                presented: Some("QmB".to_owned())
            }
        );
        // A downgrade to BasicCredential is a change.
        assert_eq!(
            check_pin(&mut pins, alice, None),
            Pin::Changed {
                pinned: "QmA".to_owned(),
                presented: None
            }
        );
        // The pin is not moved by a change.
        assert_eq!(pins.get(alice).map(String::as_str), Some("QmA"));
    }

    /// RFC 9420 §11.1 by hand: `ExtensionType extension_types<V>;
    /// ProposalType proposal_types<V>; CredentialType credential_types<V>;`,
    /// each vector a one-octet varint length (RFC 9420 §2.1.2) then
    /// big-endian uint16s.
    #[test]
    fn required_capabilities_of_a_did_webvh_room() {
        assert_eq!(
            required_capabilities(None),
            [
                0x02, 0x00, 0x06, // extension_types: app_data_dictionary
                0x02, 0x00, 0x08, // proposal_types: AppDataUpdate
                0x00, // credential_types: none
            ]
        );
        assert_eq!(
            required_capabilities(Some(CodePoints::DEFAULT)),
            [
                0x02, 0x00, 0x06, // extension_types: app_data_dictionary
                0x02, 0x00, 0x08, // proposal_types: AppDataUpdate
                0x02, 0x00, 0x08, // credential_types: did_webvh
            ]
        );
    }
}
