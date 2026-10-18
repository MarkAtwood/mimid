//! T1: the WG example bytes decode to the hand-built messages and
//! re-encode byte for byte.
//!
//! Direction per AGENTS.md: decode the fixture, compare with the expected
//! value from `common`, re-encode, and require identical bytes.

#[allow(dead_code, reason = "each test crate uses a different subset")]
mod common;

use common::{expected, fixture};
use mimi_content::MimiContent;

fn assert_round_trips(name: &str) {
    let bytes = fixture(name);
    let decoded = MimiContent::decode(&bytes).unwrap_or_else(|e| panic!("decode {name}: {e}"));
    assert_eq!(decoded, expected(name), "{name}: decoded value differs");
    let encoded = decoded
        .encode()
        .unwrap_or_else(|e| panic!("re-encode {name}: {e}"));
    assert_eq!(encoded, bytes, "{name}: re-encoding differs from fixture");
}

#[test]
fn original() {
    assert_round_trips("original");
}

#[test]
fn reply() {
    assert_round_trips("reply");
}

#[test]
fn reaction() {
    assert_round_trips("reaction");
}

#[test]
fn mention() {
    assert_round_trips("mention");
}

#[test]
fn mention_html() {
    assert_round_trips("mention-html");
}

#[test]
fn edit() {
    assert_round_trips("edit");
}

#[test]
fn delete() {
    assert_round_trips("delete");
}

#[test]
fn unlike() {
    assert_round_trips("unlike");
}

#[test]
fn expiring() {
    assert_round_trips("expiring");
}

#[test]
fn attachment() {
    assert_round_trips("attachment");
}

#[test]
fn conferencing() {
    assert_round_trips("conferencing");
}

#[test]
fn multipart_1() {
    assert_round_trips("multipart-1");
}

#[test]
fn multipart_2() {
    assert_round_trips("multipart-2");
}

/// Four levels deep, the maximum (decision mimid-1wgh.2.13).
#[test]
fn multipart_3() {
    assert_round_trips("multipart-3");
}
