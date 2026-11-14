//! The joint IETF 127 vector set (mimid
//! crates/mimid-server/tests/fixtures/joint-ietf127/vectors.json, bead
//! mimid-1wgh.46.17) decoded with Haven's mimi-core at the pinned commit,
//! so the file's claims about Haven's decoding are tested, not recalled.
//!
//! A vector's `decode` is what the drafts give and what mimid does;
//! `decode_haven`, where present, is what Haven's decoder does instead.

use mimi_core::content::{from_content08_cbor, to_content08_cbor};
use mimi_core::protocol_wire::{
    decode_consent_entry, AbuseReport, IdentifierRequest, IdentifierResponse, UpdateRoomResponse,
};
use mimi_core::room_policy_wire::decode_role_data;

const VECTORS: &str =
    include_str!("../../../../../crates/mimid-server/tests/fixtures/joint-ietf127/vectors.json");

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Whether Haven decodes `bytes` as `kind`; content must also re-encode to
/// the same bytes.
fn haven_decodes(kind: &str, bytes: &[u8]) -> Result<(), String> {
    match kind {
        "ConsentEntry" => decode_consent_entry(bytes).map(drop).map_err(|e| e.to_string()),
        "AbuseReport" => AbuseReport::decode(bytes).map(drop).map_err(|e| e.to_string()),
        "UpdateRoomResponse" => UpdateRoomResponse::decode(bytes).map(drop).map_err(|e| e.to_string()),
        "IdentifierRequest" => IdentifierRequest::decode(bytes).map(drop).map_err(|e| e.to_string()),
        "IdentifierResponse" => IdentifierResponse::decode(bytes).map(drop).map_err(|e| e.to_string()),
        "RoleData" => decode_role_data(bytes).map(drop).map_err(|e| e.to_string()),
        "MimiContent" => {
            let value = from_content08_cbor(bytes).map_err(|e| e.to_string())?;
            (to_content08_cbor(&value).unwrap() == bytes)
                .then_some(())
                .ok_or_else(|| "re-encodes differently".to_owned())
        }
        other => Err(format!("unknown kind {other}")),
    }
}

#[test]
fn haven_decodes_every_vector_as_the_file_says() {
    let file: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let mut problems = Vec::new();
    for v in file["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let result = haven_decodes(v["kind"].as_str().unwrap(), &unhex(v["hex"].as_str().unwrap()));
        let expected_ok = v.get("decode_haven").unwrap_or(&v["decode"]) == "ok";
        match (expected_ok, &result) {
            (true, Ok(())) | (false, Err(_)) => println!("  {id}: as stated"),
            (true, Err(e)) => problems.push(format!("{id}: expected ok, Haven refuses: {e}")),
            (false, Ok(())) => problems.push(format!("{id}: expected an error, Haven decodes it")),
        }
    }
    for p in &problems {
        println!("  {p}");
    }
    assert!(problems.is_empty(), "{} problems", problems.len());
}
