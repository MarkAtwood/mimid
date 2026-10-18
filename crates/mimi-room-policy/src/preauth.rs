//! The `preauth_list` component of room-policy-04 §4.

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::Role;

/// `uint16 CredentialType` of RFC 9420 §5.3, used by [`ClaimId`].
///
/// Every value decodes and encodes back unchanged, including values the
/// IANA registry does not assign, because the registry is open (RFC 9420
/// §17.5).
pub type CredentialType = u16;

/// The `ClaimId` struct of room-policy-04 §4: names one claim in an MLS
/// credential.
///
/// `id` is opaque: §4 says it is "the binary representation of an X.509
/// OID, a JWT claim name string, or the CBOR map claim key in a CWT (an int
/// or tstr)". This crate does not interpret or check it; the bytes are
/// compared exactly. §4 does not define those binary forms (wg
/// mimid-1wgh.37.58).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct ClaimId {
    /// `CredentialType credential_type`: the MLS credential type the claim
    /// belongs to.
    pub credential_type: CredentialType,
    /// `opaque id<V>`.
    pub id: Vec<u8>,
}

/// The `Claim` struct of room-policy-04 §4: a claim and the value it must
/// have.
///
/// The same struct describes both a claim a [`PreAuthRoleEntry`] requires
/// and a claim a requester's credential carries, for
/// [`PreAuthData::first_match`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct Claim {
    /// `ClaimId claim_id`.
    pub claim_id: ClaimId,
    /// `opaque claim_value<V>`, compared byte for byte.
    pub claim_value: Vec<u8>,
}

/// The `PreAuthRoleEntry` struct of room-policy-04 §4: a set of claims and
/// the role a requester whose credential satisfies all of them may take.
///
/// `target_role` is a whole [`Role`] on the wire, as §4 writes it. Only its
/// `role_index` is used: the role definition in `roles_list` is
/// authoritative (decision mimid-1wgh.3.16).
///
/// # Security
///
/// An entry with an empty `claimset` preauthorizes anyone, including every
/// BasicCredential user, and shadows every later entry (room-policy-04 §4;
/// decision mimid-1wgh.3.47).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct PreAuthRoleEntry {
    /// `Claim claimset<V>`: the entry matches when every claim in it is
    /// satisfied.
    pub claimset: Vec<Claim>,
    /// `Role target_role`.
    pub target_role: Role,
}

/// The `PreAuthData` struct of room-policy-04 §4: the data of the
/// `preauth_list` component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct PreAuthData {
    /// `PreAuthRoleEntry preauthorized_entries<V>`, in priority order.
    pub preauthorized_entries: Vec<PreAuthRoleEntry>,
}

/// `PreAuthData PreAuthUpdate` of room-policy-04 §4: an `AppDataUpdate`
/// that replaces the whole `preauth_list` (decision mimid-1wgh.3.20).
pub type PreAuthUpdate = PreAuthData;

impl PreAuthData {
    /// The `role_index` of the first entry whose claims all match
    /// `claims`, or `None` if no entry matches.
    ///
    /// `claims` are the claims of the requester's MLS credential, each
    /// with its [`ClaimId::credential_type`] set to that credential's type.
    /// §4: "A PreAuthRoleEntry matches for a requester when every
    /// Claim.claim_id has a corresponding claim in the requester's MLS
    /// Credential which exactly matches the corresponding claim_value. When
    /// the rules ... match multiple roles, the requesting client receives
    /// the first role which matches its claims."
    ///
    /// A required claim is satisfied when `claims` holds a claim with an
    /// equal [`ClaimId`] (credential type and `id` bytes) and an equal
    /// `claim_value`. If `claims` holds several claims with that
    /// [`ClaimId`], any one of them may match (room-policy-04 §4; decision
    /// mimid-1wgh.3.48). Extra claims are ignored.
    ///
    /// The result is the matching entry's `target_role.role_index`. Look
    /// the role up in `roles_list` with [`crate::RoleData::role`] (decision
    /// mimid-1wgh.3.16); this method does not check that it exists, which
    /// is checked at authorization (room-policy-04 §4; decision
    /// mimid-1wgh.3.49).
    ///
    /// # Security
    ///
    /// An entry with an empty `claimset` matches every requester, because
    /// "every Claim.claim_id" of an empty set holds. Such an entry
    /// preauthorizes anyone, including every BasicCredential user (a
    /// BasicCredential carries no claims, so `claims` is empty and only
    /// such entries match it), and shadows every later entry
    /// (room-policy-04 §4; decision mimid-1wgh.3.47).
    pub fn first_match(&self, claims: &[Claim]) -> Option<u32> {
        self.preauthorized_entries
            .iter()
            // room-policy-04 §4; decisions mimid-1wgh.3.47, mimid-1wgh.3.48
            .find(|entry| entry.claimset.iter().all(|claim| claims.contains(claim)))
            .map(|entry| entry.target_role.role_index)
    }
}
