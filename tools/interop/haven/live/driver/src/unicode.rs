//! `mimid-haven-live unicode`: the hub half of the Unicode stress tests
//! (bead mimid-1wgh.54), against a mimi-hubd whose store this run can reach
//! (HUB_DB_CMD, as in b4.sh). The codec half is ../../unicode.
//!
//! Inputs: the Big List of Naughty Strings vendored in mimid and mimid's
//! hand-written cases, each in its four normalization forms.
//!
//! What it checks, each against the hub's store or answer:
//!   A. identifierQuery for names enrolled with non-ASCII characters: which
//!      forms find them (normalization forms, case, a handle URI with the
//!      name raw or percent-encoded, an `im:` handle).
//!   B. identifierQuery, nick and handle, for every string: notFound, never
//!      an error. Invalid UTF-8 values too.
//!   C. reportAbuse with every string as the note: the note the store keeps
//!      is the same bytes. An invalid UTF-8 note is refused.
//!   D. requestConsent and cancel with percent-encoded UTF-8 requester
//!      URIs: what the store keeps as the key, and that the cancel finds it.
//!
//! Prints one RESULT line per check and a SUMMARY; exits 1 on a difference
//! from what is expected, so a rerun after a hub change shows what moved.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::process::{Command, Stdio};

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{
    AbuseReport, AbuseType, ConsentEntry, ConsentOperation, IdentifierQueryCode, IdentifierRequest,
    IdentifierResponse, QueryElement, QuerySearch,
};
use mimid_server::config::Domain;
use mimid_server::peer::{PeerClient, PeerError};
use unicode_normalization::UnicodeNormalization;

use crate::{dictionary, env_or, uri, N};

const BLNS: &str = include_str!(
    "../../../../../../crates/mimi-content/tests/fixtures/blns/blns.base64.txt"
);

/// Standard base64 with padding (RFC 4648 §4), enough for the fixture.
fn base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut bits, mut count, mut out) = (0u32, 0, Vec::new());
    for c in text.bytes().take_while(|&c| c != b'=') {
        let value = ALPHABET.iter().position(|&a| a == c).expect("base64");
        bits = (bits << 6) | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(((bits >> count) & 0xff) as u8);
        }
    }
    out
}

/// mimid's hand-written cases (crates/mimi-content/tests/unicode_stress.rs).
fn extra() -> Vec<String> {
    let mut cases: Vec<String> = [
        "\u{0130}stanbul \u{0131}\u{0049}\u{0069}",
        "D\u{0130}YARBAKIR",
        "caf\u{00E9}",
        "cafe\u{0301}",
        "\u{D55C}",
        "\u{1112}\u{1161}\u{11AB}",
        "Stra\u{00DF}e STRA\u{1E9E}E",
        "\u{202E}gnp.exe",
        "abc \u{2066}\u{05E9}\u{05DC}\u{05D5}\u{05DD}\u{2069} def",
        "\u{200F}\u{0645}\u{0631}\u{062D}\u{0628}\u{0627} 123",
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466} \u{1F1FA}\u{1F1F8} \u{1F44D}\u{1F3FD}",
        "\u{FEFF}hello\u{200B}wor\u{200D}ld",
        "\u{FFFE}\u{FFFF}\u{FFFD}",
        "\u{10000}\u{1D400}\u{1D7FF}",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    cases.push(format!("a{}", "\u{0301}".repeat(2047)));
    cases
}

/// The four normalization forms of `text`.
fn forms(text: &str) -> [(&'static str, String); 4] {
    [
        ("NFC", text.nfc().collect()),
        ("NFD", text.nfd().collect()),
        ("NFKC", text.nfkc().collect()),
        ("NFKD", text.nfkd().collect()),
    ]
}

/// Every valid naughty string and hand case, as given and in its four
/// forms, duplicates removed, labelled. Invalid UTF-8 entries separately.
fn texts() -> (Vec<(String, String)>, Vec<(String, Vec<u8>)>) {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    let mut seen = BTreeSet::new();
    let mut bases = Vec::new();
    for (i, line) in BLNS
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .enumerate()
    {
        match String::from_utf8(base64(line.trim())) {
            Ok(t) => bases.push((format!("blns[{i}]"), t)),
            Err(e) => invalid.push((format!("blns[{i}]"), e.into_bytes())),
        }
    }
    bases.extend(extra().into_iter().enumerate().map(|(i, t)| (format!("extra[{i}]"), t)));
    for (label, text) in bases {
        let mut all = vec![("as given", text.clone())];
        all.extend(forms(&text));
        for (form, t) in all {
            if t.len() <= 4096 && seen.insert(t.clone()) {
                valid.push((format!("{label} {form}"), t));
            }
        }
    }
    invalid.push(("lone continuation".into(), b"\x80abc".to_vec()));
    invalid.push(("overlong slash".into(), b"\xc0\xafx".to_vec()));
    invalid.push(("surrogate".into(), b"\xed\xa0\x80x".to_vec()));
    (valid, invalid)
}

/// Every byte but the RFC 3986 unreserved ones percent-encoded, hex upper.
fn pct(text: &[u8]) -> String {
    text.iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn short(text: &str) -> String {
    let t: String = text.escape_debug().collect();
    if t.chars().count() > 40 {
        format!("{}…", t.chars().take(40).collect::<String>())
    } else {
        t
    }
}

/// Runs `sql` against the hub's store; the output, one row per line.
fn sql(sql: &str) -> Vec<String> {
    let cmd = std::env::var("HUB_DB_CMD").expect("HUB_DB_CMD");
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("HUB_DB_CMD");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(sql.as_bytes())
        .expect("sql");
    let out = child.wait_with_output().expect("HUB_DB_CMD");
    assert!(out.status.success(), "HUB_DB_CMD failed on {sql}");
    String::from_utf8(out.stdout)
        .expect("hex output")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Successes whose URI mimid could not decode.
static RAW_ANSWERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// identifierQuery with one element: Ok(true) found, Ok(false) notFound,
/// Err the answer when it is neither.
async fn query(
    client: &PeerClient,
    haven: &Domain,
    search: &QuerySearch,
    value: &[u8],
) -> Result<bool, String> {
    let request = IdentifierRequest {
        query_elements: vec![QueryElement {
            search: search.clone(),
            search_value: value.to_vec(),
        }],
        id_request_extensions: dictionary(),
    }
    .tls_serialize_detached()
    .expect("IdentifierRequest");
    match client.identifier_query(haven, request).await {
        Ok(body) => match IdentifierResponse::tls_deserialize_exact(&body[..]) {
            Ok(r) if r.response_code == IdentifierQueryCode::Success => Ok(true),
            Ok(r) if r.response_code == IdentifierQueryCode::NotFound => Ok(false),
            Ok(r) => Err(format!("{:?}", r.response_code)),
            // §5.8 success whose URI mimid refuses (not RFC 3986: raw
            // non-ASCII). Counted as found, and tallied.
            Err(_) if body.first() == Some(&0) => {
                let n = RAW_ANSWERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n == 0 {
                    println!("  first success with a URI mimid refuses: body {}", hex(&body));
                }
                Ok(true)
            }
            Err(e) => Err(format!("undecodable body: {e:?}")),
        },
        Err(e) => Err(error(&e)),
    }
}

fn error(e: &PeerError) -> String {
    match e {
        PeerError::Rejected { status, .. } => format!("HTTP {status}"),
        other => format!("{other}"),
    }
}

struct Tally {
    failures: Vec<String>,
}

impl Tally {
    fn result(&mut self, check: &str, ok: bool, line: String) {
        println!("RESULT {check} {} {line}", if ok { "ok" } else { "DIFF" });
        if !ok {
            self.failures.push(format!("{check}: {line}"));
        }
    }
}

pub async fn run(client: &PeerClient, haven: &Domain) {
    let tag = env_or("RUN_TAG", "");
    let (valid, invalid) = texts();
    println!(
        "inputs: {} valid texts, {} invalid UTF-8; hub {}; tag {tag}",
        valid.len(),
        invalid.len(),
        N.haven
    );
    let mut t = Tally {
        failures: Vec::new(),
    };

    // A. Enrolled names with non-ASCII characters. The store is written
    // directly (no route enrolls), with the name's exact bytes.
    let names: Vec<(String, String)> = extra()
        .into_iter()
        .filter(|n| n.len() < 200 && !n.contains([':', '/', '@']))
        .map(|n| (n.clone(), format!("{n}-{tag}")))
        .collect();
    let enrolled: BTreeSet<Vec<u8>> = names.iter().map(|(_, n)| n.clone().into_bytes()).collect();
    let inserts: String = names
        .iter()
        .map(|(_, n)| {
            format!(
                "INSERT OR IGNORE INTO enrolled (username) VALUES (CAST(X'{}' AS TEXT));\n",
                hex(n.as_bytes())
            )
        })
        .collect();
    sql(&inserts);
    let mut matrix: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut not_exact = 0;
    for (base, name) in &names {
        let tagged = |text: String| format!("{text}-{tag}").into_bytes();
        let mut found = Vec::new();
        let mut probes: Vec<(&str, QuerySearch, Vec<u8>)> = vec![
            ("nick exact", QuerySearch::Nick, name.as_bytes().to_vec()),
            (
                "nick lowercase",
                QuerySearch::Nick,
                tagged(base.to_lowercase()),
            ),
            (
                "nick uppercase",
                QuerySearch::Nick,
                tagged(base.to_uppercase()),
            ),
            (
                "handle raw",
                QuerySearch::Handle,
                format!("mimi://{}/u/{name}", N.haven).into_bytes(),
            ),
            (
                "handle percent-encoded",
                QuerySearch::Handle,
                format!("mimi://{}/u/{}", N.haven, pct(name.as_bytes())).into_bytes(),
            ),
            (
                "handle percent-encoded lowercase hex",
                QuerySearch::Handle,
                format!(
                    "mimi://{}/u/{}",
                    N.haven,
                    pct(name.as_bytes())
                        .split('%')
                        .enumerate()
                        .map(|(i, p)| if i == 0 {
                            p.to_owned()
                        } else {
                            format!("%{}{}", p[..2].to_lowercase(), &p[2..])
                        })
                        .collect::<String>()
                )
                .into_bytes(),
            ),
            (
                "handle im:",
                QuerySearch::Handle,
                format!("im:{name}@{}", N.haven).into_bytes(),
            ),
        ];
        for (form, text) in forms(base) {
            let label: &str = match form {
                "NFC" => "nick NFC",
                "NFD" => "nick NFD",
                "NFKC" => "nick NFKC",
                _ => "nick NFKD",
            };
            probes.push((label, QuerySearch::Nick, tagged(text)));
        }
        for (label, search, value) in probes {
            match query(client, haven, &search, &value).await {
                Ok(hit) => {
                    // Byte-exact matching: a nick finds the name enrolled
                    // with exactly its bytes; a raw or im: handle finds
                    // its own name; a percent-encoded one finds nothing.
                    let exact = match label {
                        l if l.starts_with("nick") => enrolled.contains(&value),
                        "handle raw" | "handle im:" => true,
                        _ => false,
                    };
                    if hit != exact {
                        not_exact += 1;
                        println!("  A not byte-exact: {} {label} hit={hit}", short(name));
                    }
                    let e = matrix.entry(label).or_default();
                    e.1 += 1;
                    if hit {
                        e.0 += 1;
                        found.push(label);
                    }
                    // Only an exact search must find the name; the rest
                    // are recorded, not judged (the drafts don't say).
                    if label == "nick exact" && !hit {
                        t.result("A", false, format!("{}: exact nick not found", short(name)));
                    }
                }
                Err(e) => t.result("A", false, format!("{} {label}: {e}", short(name))),
            }
        }
        println!("  A {}: found by {}", short(name), found.join(", "));
    }
    for (label, (hit, of)) in &matrix {
        println!("RESULT A ok {label}: found {hit} of {of} enrolled names");
    }
    t.result(
        "A",
        not_exact == 0,
        format!("{not_exact} answers differ from byte-exact matching"),
    );
    let raw = RAW_ANSWERS.load(std::sync::atomic::Ordering::Relaxed);
    t.result(
        "A",
        raw == 0,
        format!("{raw} success answers carried a URI that is not RFC 3986 (raw non-ASCII)"),
    );

    // B. Every string as a nick and as a handle, nothing enrolled under it.
    let mut b_errors = 0;
    let mut b_found = 0;
    let mut b_total = 0;
    for (label, text) in &valid {
        let values: [(QuerySearch, Vec<u8>); 3] = [
            (QuerySearch::Nick, text.clone().into_bytes()),
            (QuerySearch::Handle, text.clone().into_bytes()),
            (
                QuerySearch::Handle,
                format!("mimi://{}/u/{}", N.haven, pct(text.as_bytes())).into_bytes(),
            ),
        ];
        for (search, value) in values {
            b_total += 1;
            match query(client, haven, &search, &value).await {
                Ok(false) => {}
                Ok(true) => {
                    b_found += 1;
                    println!("  B found {label} {search:?}: {}", short(text));
                }
                Err(e) => {
                    b_errors += 1;
                    t.result("B", false, format!("{label} {search:?}: {e}"));
                }
            }
        }
    }
    for (label, bytes) in &invalid {
        for search in [QuerySearch::Nick, QuerySearch::Handle] {
            b_total += 1;
            match query(client, haven, &search, bytes).await {
                Ok(false) => {}
                other => {
                    b_errors += 1;
                    t.result("B", false, format!("invalid {label} {search:?}: {other:?}"));
                }
            }
        }
    }
    println!(
        "RESULT B {} {b_total} searches: {} notFound, {b_found} found, {b_errors} other",
        if b_errors == 0 && b_found == 0 { "ok" } else { "DIFF" },
        b_total - b_found - b_errors
    );

    // C. reportAbuse notes, then the store's copy.
    let room = format!("mimi://{}/r/uni{tag}", N.haven);
    let mut sent: Vec<(String, Vec<u8>)> = Vec::new();
    let mut c_refused = 0;
    for (label, text) in &valid {
        match report(client, haven, &room, text.as_bytes()).await {
            Ok(()) => sent.push((label.clone(), text.clone().into_bytes())),
            Err(e) => {
                c_refused += 1;
                t.result("C", false, format!("{label} refused: {e}"));
            }
        }
    }
    let mut c_invalid_ok = 0;
    for (label, bytes) in &invalid {
        match report(client, haven, &room, bytes).await {
            Err(_) => c_invalid_ok += 1,
            Ok(()) => t.result("C", false, format!("invalid {label} accepted")),
        }
    }
    let stored = sql(&format!(
        "SELECT hex(note) FROM abuse_reports WHERE room_uri = CAST(X'{}' AS TEXT) ORDER BY id;\n",
        hex(room.as_bytes())
    ));
    let mut c_same = 0;
    if stored.len() != sent.len() {
        t.result(
            "C",
            false,
            format!("{} notes accepted, {} stored", sent.len(), stored.len()),
        );
    }
    for ((label, bytes), row) in sent.iter().zip(&stored) {
        if *row == hex(bytes) {
            c_same += 1;
        } else {
            t.result("C", false, format!("{label}: stored note differs"));
        }
    }
    println!(
        "RESULT C {} {} notes sent, {c_refused} refused, {c_same} stored byte for byte; {c_invalid_ok} of {} invalid UTF-8 notes refused",
        if c_refused == 0 && c_same == sent.len() && c_invalid_ok == invalid.len() {
            "ok"
        } else {
            "DIFF"
        },
        valid.len(),
        invalid.len()
    );

    // D. Consent keyed by percent-encoded UTF-8 requester URIs.
    let target = format!("mimi://{}/u/uni-target{tag}", N.haven);
    let mut requesters = Vec::new();
    for name in extra().iter().filter(|n| n.len() < 200) {
        for (form, text) in forms(name).into_iter().take(2) {
            let u = format!("mimi://{}/u/{}-{tag}", N.own, pct(text.as_bytes()));
            if !requesters.iter().any(|(_, r)| *r == u) {
                requesters.push((format!("{} {form}", short(name)), u));
            }
        }
    }
    for (label, requester) in &requesters {
        if let Err(e) = consent(client, haven, ConsentOperation::Request, requester, &target).await
        {
            t.result("D", false, format!("{label} request: {e}"));
        }
    }
    let target_sql = format!("CAST(X'{}' AS TEXT)", hex(target.as_bytes()));
    let rows: BTreeSet<String> = sql(&format!(
        "SELECT hex(requester) FROM consent WHERE target = {target_sql};\n"
    ))
    .into_iter()
    .collect();
    let mut d_kept = 0;
    for (label, requester) in &requesters {
        if rows.contains(&hex(requester.as_bytes())) {
            d_kept += 1;
        } else {
            t.result("D", false, format!("{label}: not stored as sent"));
        }
    }
    for (label, requester) in &requesters {
        if let Err(e) = consent(client, haven, ConsentOperation::Cancel, requester, &target).await {
            t.result("D", false, format!("{label} cancel: {e}"));
        }
    }
    let left = sql(&format!(
        "SELECT count(*) FROM consent WHERE target = {target_sql};\n"
    ));
    println!(
        "RESULT D {} {} requests, {d_kept} stored as sent ({} rows), {} left after the cancels",
        if d_kept == requesters.len() && rows.len() == requesters.len() && left == ["0"] {
            "ok"
        } else {
            "DIFF"
        },
        requesters.len(),
        rows.len(),
        left.join(",")
    );

    println!("SUMMARY {} differences", t.failures.len());
    if !t.failures.is_empty() {
        std::process::exit(1);
    }
}

async fn report(
    client: &PeerClient,
    haven: &Domain,
    room: &str,
    note: &[u8],
) -> Result<(), String> {
    let body = AbuseReport {
        reporting_user: uri(N.alice),
        alleged_abuser_uri: uri(N.dave),
        reason_code: AbuseType(1),
        note: note.to_vec(),
        messages: vec![],
        abuse_extensions: dictionary(),
    }
    .tls_serialize_detached()
    .map_err(|e| format!("encode: {e:?}"))?;
    client
        .report_abuse(haven, room, body)
        .await
        .map(drop)
        .map_err(|e| error(&e))
}

async fn consent(
    client: &PeerClient,
    haven: &Domain,
    op: ConsentOperation,
    requester: &str,
    target: &str,
) -> Result<(), String> {
    let body = ConsentEntry {
        consent_operation: op,
        requester_uri: uri(requester),
        target_uri: uri(target),
        room_id: None,
        client_key_packages: vec![],
        consent_extensions: dictionary(),
    }
    .tls_serialize_detached()
    .map_err(|e| format!("encode: {e:?}"))?;
    client
        .request_consent(haven, body)
        .await
        .map_err(|e| error(&e))
}
