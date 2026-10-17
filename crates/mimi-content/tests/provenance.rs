//! Checks that the vendored WG fixtures match their PROVENANCE record.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wg-09");

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
            hex
        })
}

#[test]
fn every_fixture_matches_its_recorded_sha256() {
    let dir = Path::new(FIXTURE_DIR);
    let record = fs::read_to_string(dir.join("PROVENANCE")).expect("read PROVENANCE");

    let mut recorded = BTreeSet::new();
    for line in record
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [expected, name, _source] = fields[..] else {
            panic!("PROVENANCE row does not have 3 fields: {line:?}");
        };
        let bytes = fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
        assert_eq!(sha256_hex(&bytes), expected, "SHA-256 mismatch for {name}");
        assert!(recorded.insert(name.to_owned()), "{name} listed twice");
    }

    let present: BTreeSet<String> = fs::read_dir(dir)
        .expect("list fixture directory")
        .map(|entry| {
            entry
                .expect("read directory entry")
                .file_name()
                .into_string()
                .expect("fixture names are UTF-8")
        })
        .filter(|name| name != "PROVENANCE")
        .collect();
    assert_eq!(
        present, recorded,
        "fixture files and PROVENANCE rows differ"
    );
}
