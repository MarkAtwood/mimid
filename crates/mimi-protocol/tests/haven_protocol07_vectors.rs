//! Haven's protocol-07 wire vectors (havenmessenger/interop
//! `tests/vectors/protocol07-vectors.json` at 44331e4; see
//! `fixtures/haven-vectors/PROVENANCE`), replayed through mimid's decoders
//! (bead mimid-1wgh.46.6.9).
//!
//! The vectors are laid out field by field by Haven's generator, not by an
//! encoder, so they are an independent oracle for mimid's codecs. Every
//! vector id has an expected outcome below. A vector both implementations
//! decode must also re-encode to the same bytes. Where mimid and Haven
//! disagree, the outcome names the bead or Haven divergence that records
//! why. A vector added, removed or renamed in a regenerated file fails the
//! test until this list is reviewed.
//!
//! Only the wire layer is checked here. The `answer` and participant
//! fields of the `up-` vectors describe what Haven's hub decides; mimid's
//! hub decides from MLS group state these throwaway groups do not have.

use std::collections::BTreeSet;
use std::time::SystemTime;

use mimi_mls::wire::{KeyPackage, KeyPackageError};
use mimi_protocol::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{
    ClientKeyMaterial, HandshakeBundle, KeyMaterialDivergence, KeyMaterialResponse,
    KeyMaterialUserCode, UpdateRequest, UpdateRoomResponse,
};

const VECTORS: &str = include_str!("fixtures/haven-vectors/protocol07-vectors.json");

/// What mimid does with a vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Decodes and re-encodes to the same bytes; Haven decodes it too.
    Agree,
    /// Refused by mimid; Haven refuses it too.
    BothRefuse,
    /// Haven's every-client-exhausted answer (Haven DIV-13, bead
    /// mimid-1wgh.46.1.7): the strict decoder refuses it, the requesting
    /// side reads it as noCompatibleMaterial.
    ExhaustedDivergence,
    /// Haven refuses a client whose KeyPackage names another suite when it
    /// decodes the response; mimid decodes the response and refuses that
    /// KeyPackage when it verifies it.
    SuiteCheckedOnVerify,
    /// Haven's length-prefixed Partial GroupInfoOption (Haven DIV-12),
    /// marked "mimi-core only" in the vector; mimid reads a bare
    /// PartialGroupInfo and refuses it.
    HavenOnlyPartial,
}

fn expected(id: &str) -> Outcome {
    use Outcome::*;
    match id {
        "km-01-two-clients-success"
        | "km-02-partial-success-one-exhausted"
        | "km-03-nothing-compatible-with-capabilities"
        | "km-04-nothing-compatible-without-capabilities"
        | "km-05-user-unknown"
        | "km-06-no-compatible-material"
        | "km-07-no-consent"
        | "km-08-single-success"
        | "hb-01-commit-bare-welcome-full-group-info"
        | "hb-02-commit-without-welcome"
        | "kp-x1-grease-key-package"
        | "up-01-participant-list-private-type"
        | "up-02-participant-list-app-data-update"
        | "up-03-index-is-a-position"
        | "up-04-added-participants-are-appended"
        | "up-05-roles-list-app-data-update"
        | "up-x2-bundle-of-proposals"
        | "up-x3-app-data-update-other-component"
        | "up-x4-added-participant-already-listed"
        | "up-x5-removed-and-added-in-one-update"
        | "up-x6-base-room-policy-before-roles"
        | "up-x7-roles-list-cut-short"
        | "ur-01-success"
        | "ur-02-wrong-epoch"
        | "ur-03-not-allowed"
        | "ur-04-invalid-proposal" => Agree,
        "km-x2-success-with-exhausted-client"
        | "km-x3-user-unknown-with-client"
        | "hb-x1-welcome-in-mls-message"
        | "hb-x2-foreign-suite-welcome"
        | "up-x1-bare-commit" => BothRefuse,
        "km-09-single-exhausted" => ExhaustedDivergence,
        "km-x1-foreign-suite-second-client" => SuiteCheckedOnVerify,
        "hb-03-partial-group-info" => HavenOnlyPartial,
        other => panic!("vector {other} has no expected outcome; review it"),
    }
}

struct Vector {
    id: String,
    kind: String,
    /// Haven's own reading: "ok" or "refused".
    haven: String,
    variant: Option<String>,
    bytes: Vec<u8>,
}

fn vectors() -> Vec<Vector> {
    let json: serde_json::Value = serde_json::from_str(VECTORS).expect("vector file is JSON");
    assert_eq!(json["format_version"], 1);
    json["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .map(|v| {
            let field = |name: &str| v[name].as_str().expect(name).to_owned();
            Vector {
                id: field("id"),
                kind: field("kind"),
                haven: field("decode"),
                variant: v["variant"].as_str().map(str::to_owned),
                bytes: unhex(&field("hex")),
            }
        })
        .collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Decodes `bytes` as `T`; on success, also checks re-encoding.
fn agree<T: Deserialize + Serialize>(id: &str, bytes: &[u8]) -> T {
    let value = T::tls_deserialize_exact(bytes).unwrap_or_else(|e| panic!("{id}: {e:?}"));
    assert_eq!(
        value.tls_serialize_detached().expect("re-encode"),
        bytes,
        "{id}: re-encoding differs"
    );
    value
}

fn bundle_variant(bundle: &HandshakeBundle) -> &'static str {
    match bundle {
        HandshakeBundle::Commit { .. } => "Commit",
        HandshakeBundle::Proposal { .. } => "Proposal",
    }
}

fn decodes(kind: &str, bytes: &[u8]) -> bool {
    match kind {
        "KeyMaterialResponse" => KeyMaterialResponse::tls_deserialize_exact(bytes).is_ok(),
        "HandshakeBundle" => HandshakeBundle::tls_deserialize_exact(bytes).is_ok(),
        "UpdateRequest" => UpdateRequest::tls_deserialize_exact(bytes).is_ok(),
        "UpdateRoomResponse" => UpdateRoomResponse::tls_deserialize_exact(bytes).is_ok(),
        "KeyPackage" => KeyPackage::tls_deserialize_exact(bytes).is_ok(),
        other => panic!("unknown vector kind {other}"),
    }
}

#[test]
fn every_vector_has_its_expected_outcome() {
    let vectors = vectors();
    let ids: BTreeSet<&str> = vectors.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(ids.len(), vectors.len(), "duplicate vector ids");
    assert_eq!(vectors.len(), 34);

    for v in &vectors {
        match expected(&v.id) {
            Outcome::Agree => {
                assert_eq!(v.haven, "ok", "{}: Haven's own reading changed", v.id);
                match v.kind.as_str() {
                    "KeyMaterialResponse" => {
                        agree::<KeyMaterialResponse>(&v.id, &v.bytes);
                    }
                    "HandshakeBundle" => {
                        let bundle = agree::<HandshakeBundle>(&v.id, &v.bytes);
                        assert_eq!(Some(bundle_variant(&bundle)), v.variant.as_deref());
                    }
                    "UpdateRequest" => {
                        let request = agree::<UpdateRequest>(&v.id, &v.bytes);
                        assert_eq!(Some(bundle_variant(&request.bundle)), v.variant.as_deref());
                    }
                    "UpdateRoomResponse" => {
                        agree::<UpdateRoomResponse>(&v.id, &v.bytes);
                    }
                    "KeyPackage" => {
                        agree::<KeyPackage>(&v.id, &v.bytes);
                    }
                    other => panic!("unknown vector kind {other}"),
                }
            }
            Outcome::BothRefuse => {
                assert_eq!(v.haven, "refused", "{}: Haven's own reading changed", v.id);
                assert!(!decodes(&v.kind, &v.bytes), "{}: mimid decodes it", v.id);
            }
            Outcome::ExhaustedDivergence => {
                assert!(KeyMaterialResponse::tls_deserialize_exact(&v.bytes).is_err());
                let (response, divergence) =
                    KeyMaterialResponse::decode_for_requester(&v.bytes).expect(&v.id);
                assert_eq!(
                    response.user_status,
                    KeyMaterialUserCode::NoCompatibleMaterial
                );
                assert_eq!(
                    divergence,
                    Some(KeyMaterialDivergence::PartialSuccessWithoutKeyMaterial)
                );
            }
            Outcome::SuiteCheckedOnVerify => {
                assert_eq!(v.haven, "refused", "{}: Haven's own reading changed", v.id);
                let response = agree::<KeyMaterialResponse>(&v.id, &v.bytes);
                let ClientKeyMaterial::Success { key_package, .. } = &response.clients[1] else {
                    panic!("{}: second client is not a success", v.id);
                };
                // The suite is checked before anything time-dependent.
                assert!(matches!(
                    key_package.verify(SystemTime::now()),
                    Err(KeyPackageError::UnsupportedCipherSuite(_))
                ));
            }
            Outcome::HavenOnlyPartial => {
                assert_eq!(v.haven, "ok", "{}: Haven's own reading changed", v.id);
                assert!(!decodes(&v.kind, &v.bytes), "{}: mimid decodes it", v.id);
            }
        }
    }
}
