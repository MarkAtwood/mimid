//! The group rules (draft-atwood-mls-didwebvh-credential-00 §Binding to the
//! LeafNode and §Group Consistency Rules), over abstract leaves so that
//! they can be checked without an MLS library.

use std::collections::BTreeMap;

use crate::heads::{DidWebvhHead, DidWebvhHeads};
use crate::verify::VerifiedLog;

/// One leaf of a ratchet tree that carries a `did_webvh` credential: its
/// LeafNode `signature_key` and its verified log.
#[derive(Debug, Clone, Copy)]
pub struct Leaf<'a> {
    /// The LeafNode's `signature_key`.
    pub signature_key: &'a [u8],
    /// The leaf credential's verified log.
    pub log: &'a VerifiedLog,
}

/// Which group rule failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RuleError {
    /// §Binding to the LeafNode: the `signature_key` is not an authorized
    /// key of the head's DID document.
    #[error("the LeafNode signature_key is not an authorized key of the credential's head")]
    KeyNotInHead,
    /// §Expected Heads: the newest log for an SCID is newer than the
    /// reference entry but does not contain its `versionId`.
    #[error("the newest log for SCID {scid} does not contain the recorded head {version_id}")]
    NewestLogLacksReference {
        /// The SCID.
        scid: String,
        /// The reference entry's `versionId`.
        version_id: String,
    },
    /// §Rules, Extension matches: `did_webvh_heads` is not exactly the
    /// expected entries. Named for the draft's rule; in mimid the record is
    /// an `app_data_dictionary` component, not an extension (decision
    /// mimid-1wgh.4.81.33).
    #[error("did_webvh_heads does not hold exactly the expected entries")]
    ExtensionMismatch {
        /// The expected record.
        expected: Box<DidWebvhHeads>,
    },
    /// §Rules, Consistency with the reference entry: a credential at or
    /// past the recorded version does not contain the recorded `versionId`.
    #[error("a credential for SCID {scid} at or past the recorded head does not contain it")]
    MissingReference {
        /// The SCID.
        scid: String,
    },
    /// §Rules, Consistency with the reference entry: a credential newer
    /// than the recorded head is not a prefix of the newest log.
    #[error("a credential for SCID {scid} is not a prefix of the newest log (a fork)")]
    Fork {
        /// The SCID.
        scid: String,
    },
    /// §Rules, Authorization: a leaf's `signature_key` is not in the
    /// recorded head's `authorized_keys`.
    #[error("a leaf for SCID {scid} has a signature_key the recorded head does not authorize")]
    Unauthorized {
        /// The SCID.
        scid: String,
        /// The leaf's `signature_key`.
        signature_key: Vec<u8>,
    },
    /// §Group Consistency Rules, Welcome: an SCID in the tree has no entry.
    #[error("did_webvh_heads has no entry for SCID {scid}, which is in the tree")]
    MissingEntry {
        /// The SCID.
        scid: String,
    },
    /// §Group Consistency Rules, Welcome: a leaf's head is newer than the
    /// recorded version for its SCID.
    #[error("a leaf for SCID {scid} carries a log newer than the recorded head")]
    NewerThanRecorded {
        /// The SCID.
        scid: String,
    },
    /// §Group Consistency Rules, Welcome: a recorded head that a leaf
    /// carries as its head lists different `authorized_keys`.
    #[error("the recorded authorized_keys for SCID {scid} do not match its DID document")]
    KeysMismatch {
        /// The SCID.
        scid: String,
    },
}

/// §Binding to the LeafNode: "The `signature_key` of the LeafNode
/// containing the credential MUST equal the 32-byte public key of an
/// authorized key in the head's DID document."
///
/// # Errors
///
/// Returns [`RuleError::KeyNotInHead`].
pub fn check_binding(signature_key: &[u8], log: &VerifiedLog) -> Result<(), RuleError> {
    if log.authorizes(signature_key) {
        Ok(())
    } else {
        Err(RuleError::KeyNotInHead)
    }
}

/// §Successor Credentials: `new` replaces `old` validly if it has the same
/// SCID and `old`'s log is a prefix of `new`'s.
pub fn is_valid_successor(old: &VerifiedLog, new: &VerifiedLog) -> bool {
    old.scid() == new.scid() && old.is_prefix_of(new)
}

/// The leaves grouped by SCID, in SCID byte order.
fn by_scid<'a>(leaves: &[Leaf<'a>]) -> BTreeMap<&'a str, Vec<Leaf<'a>>> {
    let mut map: BTreeMap<&str, Vec<Leaf<'a>>> = BTreeMap::new();
    for leaf in leaves {
        map.entry(leaf.log.scid()).or_default().push(*leaf);
    }
    map
}

/// L for one SCID: "the newest log among the resulting tree's credentials
/// with SCID S", the one whose head has the highest version number. Ties
/// go to the greatest head `versionId` bytes, so the choice is
/// deterministic; a tie between different heads then fails the
/// consistency rule whichever is chosen (decision mimid-1wgh.4.81.14).
fn newest<'a>(leaves: &[Leaf<'a>]) -> Option<&'a VerifiedLog> {
    leaves.iter().map(|leaf| leaf.log).max_by(|a, b| {
        a.head_version_number()
            .cmp(&b.head_version_number())
            .then_with(|| a.head_version_id().cmp(b.head_version_id()))
    })
}

/// §Expected Heads: the `did_webvh_heads` entries the epoch a Commit leads
/// to must carry, from `previous` (the previous epoch's record, empty when
/// it has none) and the did_webvh `leaves` of the resulting tree.
///
/// # Errors
///
/// Returns [`RuleError::NewestLogLacksReference`] when the newest log for
/// an SCID is newer than its reference entry but does not contain it.
pub fn expected_heads(
    previous: &DidWebvhHeads,
    leaves: &[Leaf<'_>],
) -> Result<DidWebvhHeads, RuleError> {
    // SCIDs with no leaf keep their previous entry unchanged.
    let mut expected = previous.clone();
    for (scid, group) in by_scid(leaves) {
        let Some(newest) = newest(&group) else {
            continue;
        };
        let entry = match previous.get(scid) {
            Some(reference) if newest.head_version_number() <= reference.version_number() => {
                reference.clone()
            }
            Some(reference) => {
                if !newest.contains(reference.version_id()) {
                    return Err(RuleError::NewestLogLacksReference {
                        scid: scid.to_owned(),
                        version_id: reference.version_id().to_owned(),
                    });
                }
                DidWebvhHead::from_log(newest)
            }
            None => DidWebvhHead::from_log(newest),
        };
        expected.insert(entry);
    }
    Ok(expected)
}

/// §Rules, Consistency with the reference entry, for one SCID.
///
/// With a reference entry R: every credential whose head version number is
/// at least R's contains R's `versionId`, and every credential newer than R
/// is a prefix of L. With none, every credential must be a prefix of L
/// (decision mimid-1wgh.4.81.14: "newer than R's" read as "any", so that
/// two forks of a new SCID cannot both be admitted).
fn check_consistency(
    scid: &str,
    reference: Option<&DidWebvhHead>,
    group: &[Leaf<'_>],
) -> Result<(), RuleError> {
    let Some(newest) = newest(group) else {
        return Ok(());
    };
    for leaf in group {
        let log = leaf.log;
        let (at_least, newer) = match reference {
            Some(r) => (
                log.head_version_number() >= r.version_number(),
                log.head_version_number() > r.version_number(),
            ),
            None => (false, true),
        };
        if at_least
            && let Some(r) = reference
            && !log.contains(r.version_id())
        {
            return Err(RuleError::MissingReference {
                scid: scid.to_owned(),
            });
        }
        if newer && !log.is_prefix_of(newest) {
            return Err(RuleError::Fork {
                scid: scid.to_owned(),
            });
        }
    }
    Ok(())
}

/// §Rules, Authorization, for one SCID against its recorded head.
fn check_authorization(
    scid: &str,
    recorded: Option<&DidWebvhHead>,
    group: &[Leaf<'_>],
) -> Result<(), RuleError> {
    for leaf in group {
        if !recorded.is_some_and(|r| r.authorizes(leaf.signature_key)) {
            return Err(RuleError::Unauthorized {
                scid: scid.to_owned(),
                signature_key: leaf.signature_key.to_vec(),
            });
        }
    }
    Ok(())
}

/// §Rules for a Commit: the resulting GroupContext's record `resulting`
/// must be exactly the expected entries computed from `previous` and the
/// resulting tree's did_webvh `leaves`; every credential must be consistent
/// with its reference entry; and every leaf must be authorized by the
/// recorded head of its SCID.
///
/// For an external Commit, `resulting` may differ from `previous` when the
/// joiner sets the record: with the record as an `app_data_dictionary`
/// component, an external Commit can carry the AppDataUpdate proposal that
/// sets it (mls-extensions-11 §4.7; decision mimid-1wgh.4.81.33). The
/// draft's §Rules, written for the GroupContext extension, say it cannot.
///
/// # Errors
///
/// Returns the first [`RuleError`] found.
pub fn check_commit(
    previous: &DidWebvhHeads,
    resulting: &DidWebvhHeads,
    leaves: &[Leaf<'_>],
) -> Result<(), RuleError> {
    let expected = expected_heads(previous, leaves)?;
    let groups = by_scid(leaves);
    // Consistency before the extension match: when two forks tie for the
    // newest log, which one is L is not specified, so the extension the
    // Commit had to carry is not either; the fork is the error to report
    // (decision mimid-1wgh.4.81.14).
    for (scid, group) in &groups {
        check_consistency(scid, previous.get(scid), group)?;
    }
    if *resulting != expected {
        return Err(RuleError::ExtensionMismatch {
            expected: Box::new(expected),
        });
    }
    for (scid, group) in &groups {
        check_authorization(scid, resulting.get(scid), group)?;
    }
    Ok(())
}

/// The leaves, by position in `leaves`, that `heads` does not authorize:
/// those a Commit raising the record to `heads` has to remove.
pub fn unauthorized_leaves(heads: &DidWebvhHeads, leaves: &[Leaf<'_>]) -> Vec<usize> {
    leaves
        .iter()
        .enumerate()
        .filter(|(_, leaf)| {
            !heads
                .get(leaf.log.scid())
                .is_some_and(|r| r.authorizes(leaf.signature_key))
        })
        .map(|(i, _)| i)
        .collect()
}

/// §Rules for a member joining by Welcome, or checking a GroupInfo: it has
/// no previous epoch, so it checks that `heads` has an entry for each SCID
/// in the tree, that no leaf's head is newer than its recorded version,
/// the consistency and authorization rules with R taken from `heads`, and
/// that each recorded head some leaf carries as its own head lists that
/// DID document's authorized keys. Sorting and uniqueness were checked when
/// `heads` was decoded.
///
/// # Errors
///
/// Returns the first [`RuleError`] found.
pub fn check_join(heads: &DidWebvhHeads, leaves: &[Leaf<'_>]) -> Result<(), RuleError> {
    for (scid, group) in by_scid(leaves) {
        let Some(recorded) = heads.get(scid) else {
            return Err(RuleError::MissingEntry {
                scid: scid.to_owned(),
            });
        };
        for leaf in &group {
            if leaf.log.head_version_number() > recorded.version_number() {
                return Err(RuleError::NewerThanRecorded {
                    scid: scid.to_owned(),
                });
            }
            if leaf.log.head_version_id() == recorded.version_id()
                && leaf.log.authorized_keys() != recorded.authorized_keys()
            {
                return Err(RuleError::KeysMismatch {
                    scid: scid.to_owned(),
                });
            }
        }
        check_consistency(scid, Some(recorded), &group)?;
        check_authorization(scid, Some(recorded), &group)?;
    }
    Ok(())
}
