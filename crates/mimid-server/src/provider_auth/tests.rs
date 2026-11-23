use axum::http::HeaderValue;

use super::*;
use crate::hub::SystemClock;

const NOW: i64 = 1_763_200_000;

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

fn signer(seed: u8, selector: &str) -> RequestSigner {
    RequestSigner::new(SigningKey::from_seed(&[seed; 32]), selector.to_owned())
}

fn key_text(signer: &RequestSigner) -> String {
    STANDARD.encode(signer.public_key().to_bytes())
}

/// A config trusting `signer` for b.example under its selector.
fn config_trusting(signer: &RequestSigner) -> ProviderAuthConfig {
    toml::from_str(&format!(
        "[peers.\"b.example\"]\nkeys = {{ \"{}\" = \"{}\" }}\n",
        signer.selector(),
        key_text(signer)
    ))
    .unwrap()
}

const URI: &str = "https://mimi.a.example/v1/requestConsent/a.example";

/// A request from b.example signed by `signer` at `created`, for `body`.
fn signed(signer: &RequestSigner, body: &[u8], created: i64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::FROM, HeaderValue::from_static("mimi@b.example"));
    signer
        .sign(
            &Method::POST,
            &URI.parse().unwrap(),
            &mut headers,
            body,
            created,
        )
        .unwrap();
    headers
}

fn check_with(
    auth: &ProviderAuth,
    headers: &HeaderMap,
    body: &[u8],
    from: &str,
) -> Result<AuthenticatedProvider, Refusal> {
    let from = domain(from);
    let uri: Uri = URI.parse().unwrap();
    block_on(auth.authenticate(&InboundRequest {
        from: &from,
        method: &Method::POST,
        uri: &uri,
        headers,
        body,
        now: NOW,
        certificate: None,
    }))
}

/// Runs `future` to completion on a current-thread runtime.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

fn auth(config: &ProviderAuthConfig) -> ProviderAuth {
    ProviderAuth::new(
        config,
        &BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap(),
        Arc::new(SystemClock),
    )
}

#[test]
fn a_trusted_signature_authenticates_the_from_domain() {
    let b = signer(7, "b1");
    let auth = auth(&config_trusting(&b));
    let provider = check_with(&auth, &signed(&b, b"entry", NOW), b"entry", "b.example").unwrap();
    assert_eq!(
        provider,
        AuthenticatedProvider {
            domain: domain("b.example"),
            mechanism: Mechanism::TrustList,
            key_id: "b1".to_owned(),
            dnssec: None,
        }
    );
}

#[test]
fn failures_are_refused_with_the_reason() {
    let b = signer(7, "b1");
    let auth = auth(&config_trusting(&b));
    let body = b"entry";

    // Unsigned.
    let mut unsigned = HeaderMap::new();
    unsigned.insert(header::FROM, HeaderValue::from_static("mimi@b.example"));
    assert_eq!(
        check_with(&auth, &unsigned, body, "b.example"),
        Err(Refusal::NoCredentials)
    );
    // Signed by a key b.example's config does not hold, same selector.
    let impostor = signer(9, "b1");
    assert_eq!(
        check_with(&auth, &signed(&impostor, body, NOW), body, "b.example"),
        Err(Refusal::Signature(httpsig::Error::BadSignature))
    );
    // A selector b.example has no key for.
    assert_eq!(
        check_with(
            &auth,
            &signed(&signer(7, "b2"), body, NOW),
            body,
            "b.example"
        ),
        Err(Refusal::UnknownKey)
    );
    // The body changed after signing.
    assert_eq!(
        check_with(&auth, &signed(&b, body, NOW), b"other", "b.example"),
        Err(Refusal::Digest)
    );
    // Too old.
    assert_eq!(
        check_with(
            &auth,
            &signed(&b, body, NOW - MAX_SIGNATURE_AGE_SECS - 1),
            body,
            "b.example"
        ),
        Err(Refusal::Signature(httpsig::Error::Time))
    );
    // A provider with no configured keys.
    assert_eq!(
        check_with(&auth, &signed(&b, body, NOW), body, "c.example"),
        Err(Refusal::NoTrustedKey)
    );
}

#[test]
fn a_signature_must_cover_the_mimi_profile() {
    let b = signer(7, "b1");
    let auth = auth(&config_trusting(&b));
    let body = b"entry";
    let mut headers = HeaderMap::new();
    headers.insert(header::FROM, HeaderValue::from_static("mimi@b.example"));
    headers.insert(httpsig::CONTENT_DIGEST, httpsig::content_digest(body));
    // Everything but `from`.
    let params = SignatureParams {
        components: ["@method", "@target-uri", "content-digest"]
            .map(str::to_owned)
            .to_vec(),
        created: Some(NOW),
        keyid: Some("b1".to_owned()),
        ..SignatureParams::default()
    };
    httpsig::sign_headers(
        &Method::POST,
        &URI.parse().unwrap(),
        &mut headers,
        "s",
        &params,
        &SigningKey::from_seed(&[7; 32]),
    )
    .unwrap();
    assert_eq!(
        check_with(&auth, &headers, body, "b.example"),
        Err(Refusal::NotCovered("from"))
    );
}

#[test]
fn modes_default_to_enforce_and_peers_can_observe() {
    let config: ProviderAuthConfig =
        toml::from_str("[peers.\"haven.example\"]\nmode = \"observe\"\n[peers.\"b.example\"]\n")
            .unwrap();
    let auth = auth(&config);
    assert_eq!(auth.mode(&domain("haven.example")), AuthMode::Observe);
    assert_eq!(auth.mode(&domain("b.example")), AuthMode::Enforce);
    assert_eq!(auth.mode(&domain("c.example")), AuthMode::Enforce);
    assert!(auth.first_observed(&domain("haven.example")));
    assert!(!auth.first_observed(&domain("haven.example")));

    let all_observe: ProviderAuthConfig = toml::from_str("mode = \"observe\"\n").unwrap();
    assert_eq!(
        super::ProviderAuth::new(
            &all_observe,
            &BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap(),
            Arc::new(SystemClock),
        )
        .mode(&domain("c.example")),
        AuthMode::Observe
    );
}

#[test]
fn configured_keys_must_be_ed25519() {
    for bad in ["not base64!", "AAAA", &STANDARD.encode([0u8; 31])] {
        let text = format!("[peers.\"b.example\"]\nkeys = {{ \"b1\" = \"{bad}\" }}\n");
        assert!(
            toml::from_str::<ProviderAuthConfig>(&text).is_err(),
            "{bad}"
        );
    }
    assert!(toml::from_str::<ProviderAuthConfig>("mode = \"lenient\"\n").is_err());
    assert!(toml::from_str::<ProviderAuthConfig>("[peers.\"b.example\"]\nkey = 1\n").is_err());
    let defaults: ProviderAuthConfig = toml::from_str("").unwrap();
    assert_eq!(defaults, ProviderAuthConfig::default());
    assert_eq!(defaults.selector, DEFAULT_SELECTOR);
}

#[test]
fn the_dns_record_names_the_public_key() {
    let b = signer(7, "b1");
    assert_eq!(
        b.dns_record(),
        format!("v=MIMI1; k=ed25519; p={}", key_text(&b))
    );
    // Debug shows no private key.
    let debug = format!("{b:?}");
    assert!(!debug.contains(&STANDARD.encode([7u8; 32])), "{debug}");
}

#[test]
fn content_digest_must_be_covered_when_there_is_a_body() {
    let b = signer(7, "b1");
    let auth = auth(&config_trusting(&b));
    let sign = |components: &[&str], body: &[u8]| {
        let mut headers = HeaderMap::new();
        headers.insert(header::FROM, HeaderValue::from_static("mimi@b.example"));
        if !body.is_empty() {
            headers.insert(httpsig::CONTENT_DIGEST, httpsig::content_digest(body));
        }
        let params = SignatureParams {
            components: components.iter().map(|c| (*c).to_owned()).collect(),
            created: Some(NOW),
            keyid: Some("b1".to_owned()),
            ..SignatureParams::default()
        };
        httpsig::sign_headers(
            &Method::POST,
            &URI.parse().unwrap(),
            &mut headers,
            "s",
            &params,
            &SigningKey::from_seed(&[7; 32]),
        )
        .unwrap();
        headers
    };
    let profile = ["@method", "@target-uri", "from"];
    // No body: no digest needed (draft-atwood-mimi-provider-auth-00 §5.2).
    assert!(check_with(&auth, &sign(&profile, b""), b"", "b.example").is_ok());
    // A body: content-digest must be covered.
    assert_eq!(
        check_with(&auth, &sign(&profile, b"entry"), b"entry", "b.example"),
        Err(Refusal::NotCovered("content-digest"))
    );
}

/// draft-atwood-mimi-provider-auth-00 Appendix A ("Example Signed
/// Request"), with the RFC 9421 B.1.4 key under selector `s1`.
mod draft_example {
    use super::*;

    const D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
    const CREATED: i64 = 1_794_700_800;
    const BODY: &[u8] = b"example MIMI notify body";
    const URI: &str = "https://b.example/v1/notify/a.example/r/clubhouse";
    const DIGEST: &str = "sha-256=:ltvFi/ijqMH79/ThrwZ/JykItjIYFA06v8rfqBdj7dY=:";
    const INPUT: &str = r#"mimi=("@method" "@target-uri" "content-digest" "from");created=1794700800;keyid="s1";tag="mimi""#;
    const SIGNATURE: &str = "mimi=:OBXnNmTPY+Gcxbn+BKcfqCpK7GrkCGO+Ab0/PS956byMzzcArSVEeJWA95WiYjfLJ9vMsEaCRab3geIFr5FpCw==:";

    fn a_signer() -> RequestSigner {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let d: [u8; 32] = URL_SAFE_NO_PAD.decode(D).unwrap().try_into().unwrap();
        RequestSigner::new(SigningKey::from_seed(&d), "s1".to_owned())
    }

    /// -00's example has no nonce; mimid's signer adds one since -01
    /// §13.2, so the example is signed with none.
    #[test]
    fn mimids_signer_reproduces_the_example_byte_for_byte() {
        let mut headers = HeaderMap::new();
        headers.insert(header::FROM, HeaderValue::from_static("mimi@a.example"));
        a_signer()
            .sign_with_nonce(
                &Method::POST,
                &URI.parse().unwrap(),
                &mut headers,
                BODY,
                CREATED,
                None,
            )
            .unwrap();
        assert_eq!(headers[httpsig::CONTENT_DIGEST], DIGEST);
        assert_eq!(headers[httpsig::SIGNATURE_INPUT], INPUT);
        assert_eq!(headers[httpsig::SIGNATURE], SIGNATURE);
    }

    #[test]
    fn the_example_authenticates_a_example() {
        let config: ProviderAuthConfig = toml::from_str(&format!(
            "[peers.\"a.example\"]\nkeys = {{ \"s1\" = \"{}\" }}\n",
            key_text(&a_signer())
        ))
        .unwrap();
        let auth = ProviderAuth::new(
            &config,
            &BaseUrl::try_from("https://b.example".to_owned()).unwrap(),
            Arc::new(SystemClock),
        );
        let mut headers = HeaderMap::new();
        headers.insert(header::FROM, HeaderValue::from_static("mimi@a.example"));
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/mimi-protocol"),
        );
        headers.insert(httpsig::CONTENT_DIGEST, HeaderValue::from_static(DIGEST));
        headers.insert(httpsig::SIGNATURE_INPUT, HeaderValue::from_static(INPUT));
        headers.insert(httpsig::SIGNATURE, HeaderValue::from_static(SIGNATURE));
        let from = domain("a.example");
        let uri: Uri = URI.parse().unwrap();
        let provider = block_on(auth.authenticate(&InboundRequest {
            from: &from,
            method: &Method::POST,
            uri: &uri,
            headers: &headers,
            body: BODY,
            now: CREATED,
            certificate: None,
        }))
        .unwrap();
        assert_eq!(provider.key_id, "s1");
        assert_eq!(provider.domain, from);
    }

    /// A [`TxtResolver`] answering from a table, by absolute name.
    struct FakeDns(BTreeMap<String, Result<TxtAnswer, TxtLookupError>>);

    impl TxtResolver for FakeDns {
        fn txt<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<TxtAnswer, TxtLookupError>> {
            let answer = self
                .0
                .get(name)
                .cloned()
                .unwrap_or(Err(TxtLookupError::NoRecords));
            Box::pin(std::future::ready(answer))
        }
    }

    /// The draft's example record (§5.1), as one character-string.
    const RECORD: &[u8] = b"v=MIMI1; k=ed25519; p=JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";
    const NAME: &str = "s1._mimi.a.example.";

    fn answer(records: &[(&[u8], DnssecStatus)]) -> Result<TxtAnswer, TxtLookupError> {
        Ok(TxtAnswer {
            records: records.iter().map(|(d, s)| (d.to_vec(), *s)).collect(),
        })
    }

    /// b.example's policy with no trust list, DNS answering `entry` for
    /// [`NAME`], and `extra` TOML.
    fn dns_auth(entry: Result<TxtAnswer, TxtLookupError>, extra: &str) -> ProviderAuth {
        let config: ProviderAuthConfig = toml::from_str(extra).unwrap();
        ProviderAuth::new(
            &config,
            &BaseUrl::try_from("https://b.example".to_owned()).unwrap(),
            Arc::new(SystemClock),
        )
        .with_dns(Arc::new(FakeDns(BTreeMap::from([(
            NAME.to_owned(),
            entry,
        )]))))
    }

    /// The draft's Appendix A request, checked at its `created` time.
    fn check_example(auth: &ProviderAuth) -> Result<AuthenticatedProvider, Refusal> {
        let mut headers = HeaderMap::new();
        headers.insert(header::FROM, HeaderValue::from_static("mimi@a.example"));
        headers.insert(httpsig::CONTENT_DIGEST, HeaderValue::from_static(DIGEST));
        headers.insert(httpsig::SIGNATURE_INPUT, HeaderValue::from_static(INPUT));
        headers.insert(httpsig::SIGNATURE, HeaderValue::from_static(SIGNATURE));
        let from = domain("a.example");
        let uri: Uri = URI.parse().unwrap();
        block_on(auth.authenticate(&InboundRequest {
            from: &from,
            method: &Method::POST,
            uri: &uri,
            headers: &headers,
            body: BODY,
            now: CREATED,
            certificate: None,
        }))
    }

    #[test]
    fn the_example_authenticates_with_its_dns_record() {
        let auth = dns_auth(answer(&[(RECORD, DnssecStatus::Insecure)]), "");
        let provider = check_example(&auth).unwrap();
        assert_eq!(provider.mechanism, Mechanism::DnsKey);
        assert_eq!(provider.key_id, "s1");
        assert_eq!(provider.dnssec, Some(DnssecStatus::Insecure));
        // The first MIMI key record counts; other TXT records are skipped.
        let auth = dns_auth(
            answer(&[
                (b"v=DKIM1; p=xyz", DnssecStatus::Insecure),
                (RECORD, DnssecStatus::Secure),
            ]),
            "",
        );
        assert_eq!(
            check_example(&auth).unwrap().dnssec,
            Some(DnssecStatus::Secure)
        );
    }

    #[test]
    fn dns_failures_refuse_with_the_reason() {
        let revoked: &[u8] = b"v=MIMI1; k=ed25519; p=";
        for (entry, refusal) in [
            (Err(TxtLookupError::NoRecords), Refusal::NoKeyRecord),
            (Err(TxtLookupError::Bogus), Refusal::DnssecBogus),
            (
                Err(TxtLookupError::Failed("timeout".to_owned())),
                Refusal::DnsFailure,
            ),
            (
                answer(&[(revoked, DnssecStatus::Insecure)]),
                Refusal::KeyRevoked,
            ),
            (
                answer(&[(b"v=DKIM1; p=x", DnssecStatus::Insecure)]),
                Refusal::NoKeyRecord,
            ),
            (
                answer(&[(b"v=MIMI1; k=rsa; p=AAAA", DnssecStatus::Insecure)]),
                Refusal::BadKeyRecord("key type is not ed25519"),
            ),
        ] {
            assert_eq!(check_example(&dns_auth(entry, "")), Err(refusal));
        }
        // A key that does not sign the request.
        let other = format!(
            "v=MIMI1; k=ed25519; p={}",
            STANDARD.encode(SigningKey::from_seed(&[3; 32]).verifying_key().to_bytes())
        );
        assert_eq!(
            check_example(&dns_auth(
                answer(&[(other.as_bytes(), DnssecStatus::Insecure)]),
                ""
            )),
            Err(Refusal::Signature(httpsig::Error::BadSignature))
        );
    }

    #[test]
    fn local_policy_can_require_dnssec_or_turn_dns_off() {
        let strict = "require_dnssec = true\n";
        assert_eq!(
            check_example(&dns_auth(
                answer(&[(RECORD, DnssecStatus::Insecure)]),
                strict
            )),
            Err(Refusal::NotSecure)
        );
        assert!(
            check_example(&dns_auth(answer(&[(RECORD, DnssecStatus::Secure)]), strict)).is_ok()
        );
        // dns_keys = false: only the trust list, which knows no a.example.
        assert_eq!(
            check_example(&dns_auth(
                answer(&[(RECORD, DnssecStatus::Secure)]),
                "dns_keys = false\n"
            )),
            Err(Refusal::NoTrustedKey)
        );
    }

    #[test]
    fn the_trust_list_is_tried_before_dns() {
        let trusting = format!(
            "[peers.\"a.example\"]\nkeys = {{ \"s1\" = \"{}\" }}\n",
            key_text(&a_signer())
        );
        let auth = dns_auth(answer(&[(RECORD, DnssecStatus::Secure)]), &trusting);
        assert_eq!(
            check_example(&auth).unwrap().mechanism,
            Mechanism::TrustList
        );
    }

    #[test]
    fn key_records_follow_the_draft_syntax() {
        let key = match parse_key_record(RECORD) {
            KeyRecord::Key(key) => key,
            other => panic!("{other:?}"),
        };
        assert_eq!(key, a_signer().public_key());
        // Tag order, spacing, tabs, unknown tags and a trailing ; are free.
        for record in [
            "v=MIMI1;p=JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=;k=ed25519",
            "v=MIMI1 ;\tk = ed25519 ; t=y; p=JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs= ;",
        ] {
            assert_eq!(
                parse_key_record(record.as_bytes()),
                KeyRecord::Key(key),
                "{record}"
            );
        }
        assert_eq!(
            parse_key_record(b"v=MIMI1; k=ed25519; p="),
            KeyRecord::Revoked
        );
        // v=MIMI1 must come first, exactly.
        for record in [
            "k=ed25519; v=MIMI1",
            "v=MIMI10; k=ed25519",
            "v=mimi1; k=ed25519",
            "",
        ] {
            assert_eq!(
                parse_key_record(record.as_bytes()),
                KeyRecord::NotMimi,
                "{record}"
            );
        }
        for (record, why) in [
            (
                "v=MIMI1; p=JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=",
                "no k tag",
            ),
            ("v=MIMI1; k=ed25519", "no p tag"),
            ("v=MIMI1; k=ed25519; p=AAAA", "p is not an Ed25519 key"),
            ("v=MIMI1; k=ed25519; garbage", "a tag without ="),
            ("v=MIMI1; k=ed25519; 9x=1; p=", "a malformed tag"),
        ] {
            assert_eq!(
                parse_key_record(record.as_bytes()),
                KeyRecord::Unusable(why),
                "{record}"
            );
        }
    }

    #[test]
    fn selectors_are_single_labels() {
        for ok in ["s1", "mimid1", "2026-11", &"a".repeat(63)] {
            assert!(valid_selector(ok), "{ok}");
        }
        for bad in ["", "_s", "a.b", "-a", "a-", "a b", &"a".repeat(64)] {
            assert!(!valid_selector(bad), "{bad}");
        }
    }
}

/// -01 §13.2 (bead mimid-75nk.9): mimid's signatures carry a fresh nonce,
/// and a verified signature's nonce counts once per key in the window.
#[test]
fn a_replayed_signature_is_refused_by_its_nonce() {
    let b = signer(7, "b1");
    let auth = auth(&config_trusting(&b));
    let headers = signed(&b, b"entry", NOW);
    let (_, params) = httpsig::signatures(&headers).unwrap().remove(0);
    let first = params.nonce.clone().expect("mimid signs with a nonce");
    assert_eq!(first.len(), 22, "16 bytes, unpadded base64url");
    // Two signings of the same request get different nonces.
    let again = signed(&b, b"entry", NOW);
    assert_ne!(httpsig::signatures(&again).unwrap()[0].1.nonce, Some(first));

    assert!(check_with(&auth, &headers, b"entry", "b.example").is_ok());
    assert!(matches!(
        check_with(&auth, &headers, b"entry", "b.example"),
        Err(Refusal::Nonce(nonce::NonceRefusal::Replayed))
    ));
    // The other signing is a different request.
    assert!(check_with(&auth, &again, b"entry", "b.example").is_ok());
}

/// A signature without a nonce is still accepted (the draft's SHOULD is on
/// the signer), and so can be replayed within the window.
#[test]
fn a_signature_without_a_nonce_is_accepted() {
    let b = signer(7, "b1");
    let auth = auth(&config_trusting(&b));
    let mut headers = HeaderMap::new();
    headers.insert(header::FROM, HeaderValue::from_static("mimi@b.example"));
    headers.insert(httpsig::CONTENT_DIGEST, httpsig::content_digest(b"entry"));
    let params = SignatureParams {
        components: SIGNED_COMPONENTS.map(str::to_owned).to_vec(),
        created: Some(NOW),
        keyid: Some("b1".to_owned()),
        tag: Some(SIGNATURE_TAG.to_owned()),
        ..SignatureParams::default()
    };
    httpsig::sign_headers(
        &Method::POST,
        &URI.parse().unwrap(),
        &mut headers,
        SIGNATURE_LABEL,
        &params,
        &SigningKey::from_seed(&[7; 32]),
    )
    .unwrap();
    assert!(check_with(&auth, &headers, b"entry", "b.example").is_ok());
    assert!(check_with(&auth, &headers, b"entry", "b.example").is_ok());
}

/// A nonce is checked only after the signature verifies, so a forged
/// request reusing a real nonce does not use it up.
#[test]
fn a_bad_signature_does_not_record_its_nonce() {
    let b = signer(7, "b1");
    let auth = auth(&config_trusting(&b));
    let headers = signed(&b, b"entry", NOW);
    // Same headers, other body: the digest fails before any nonce check.
    assert!(check_with(&auth, &headers, b"other", "b.example").is_err());
    assert!(check_with(&auth, &headers, b"entry", "b.example").is_ok());
}

/// The logged endpoint is the protocol-07 §5 endpoint name, never the room
/// or user the rest of the path names.
#[test]
fn the_logged_endpoint_is_the_path_segment_after_v1() {
    for (path, endpoint) in [
        (
            "/v1/keyMaterial/mimi%3A%2F%2Fb.example%2Fu%2Fbob",
            "keyMaterial",
        ),
        ("/v1/notify/mimi%3A%2F%2Fa.example%2Fr%2Fone", "notify"),
        ("/v1/requestConsent/b.example", "requestConsent"),
        ("/v1/update", "update"),
        ("/v1/", ""),
    ] {
        assert_eq!(endpoint_name(path), endpoint, "{path}");
    }
}

/// `[provider_auth] key_file` takes the seed raw or as hex, and refuses
/// anything else without saying what it held (bead mimid-75nk.13).
#[test]
fn a_key_file_is_32_raw_octets_or_64_hex_characters() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let expected = [0xabu8; 32];

    // Raw octets.
    let raw = read_signing_seed(&write("raw", &expected)).unwrap();
    assert_eq!(*raw, expected);

    // The same key as hex, with and without a trailing newline, so a file
    // written by `echo` works. Upper case too.
    for text in [
        "ab".repeat(32),
        format!("{}\n", "ab".repeat(32)),
        "AB".repeat(32),
    ] {
        let hex = read_signing_seed(&write("hex", text.as_bytes())).unwrap();
        assert_eq!(*hex, expected, "{text:?}");
    }

    // A signer built from either spelling has the same public key, which
    // is what makes the DNS record keep matching after a migration.
    assert_eq!(
        SigningKey::from_seed(&expected).verifying_key().to_bytes(),
        SigningKey::from_seed(&read_signing_seed(&write("again", &expected)).unwrap())
            .verifying_key()
            .to_bytes()
    );

    // Refused: too short, too long, 64 characters that are not hex, and
    // invalid UTF-8 of the wrong length.
    for (name, bytes) in [
        ("short", &b"ab"[..]),
        ("long", &[0u8; 33][..]),
        ("empty", &b""[..]),
        ("not-hex", "zz".repeat(32).as_bytes()),
        ("bad-utf8", &[0xff, 0xfe, 0xfd][..]),
    ] {
        let error = read_signing_seed(&write(name, bytes)).unwrap_err();
        assert!(
            matches!(error, SeedFileError::Shape(_)),
            "{name}: {error:?}"
        );
        // The message says the length, never the contents.
        let message = error.to_string();
        assert!(!message.contains("ab"), "{name}: {message}");
    }

    // A missing file is a read error, not a shape one.
    let missing = read_signing_seed(&dir.path().join("nope")).unwrap_err();
    assert!(matches!(missing, SeedFileError::Read(_)), "{missing:?}");
}

/// The `reason` a refusal shows a peer (bead mimid-75nk.12).
///
/// draft-atwood-mimi-provider-auth-00 §9 allows a problem details body
/// "saying why authentication failed", bounded by "what the source
/// provider needs to fix its configuration". So the split under test is
/// which side's configuration a refusal is about: the source's own DNS,
/// signature or certificate is reported; the target's trust list is not.
#[test]
fn a_refusal_reports_only_the_sources_own_configuration() {
    // The peer's own DNS, signature or certificate: say so.
    for (refusal, reason) in [
        (Refusal::NoCredentials, "no-credentials"),
        (Refusal::NoKeyRecord, "no-key-record"),
        (Refusal::KeyRevoked, "key-revoked"),
        (Refusal::BadKeyRecord("no k"), "unusable-key-record"),
        (Refusal::DnssecBogus, "key-record-dnssec-bogus"),
        (Refusal::NotSecure, "key-record-not-dnssec-secure"),
        (Refusal::NoKeyId, "signature-no-keyid"),
        (Refusal::BadSelector, "keyid-not-a-selector"),
        (Refusal::UnknownKey, "unknown-keyid"),
        (Refusal::NotCovered("from"), "signature-incomplete"),
        (Refusal::Digest, "content-digest-mismatch"),
        // The case that prompted this: one dNSName away from working.
        (
            Refusal::Certificate("no dNSName for the domain"),
            "certificate-rejected",
        ),
        (
            Refusal::CertificatePath("unknown issuer".to_owned()),
            "certificate-path-rejected",
        ),
    ] {
        assert_eq!(
            refusal.public_reason(),
            Some(reason),
            "{refusal:?} should report {reason}"
        );
    }

    // The TARGET's own configuration, and a transient fault: say nothing,
    // so a peer cannot probe our trust list.
    for refusal in [Refusal::NoTrustedKey, Refusal::DnsFailure] {
        assert_eq!(
            refusal.public_reason(),
            None,
            "{refusal:?} must not be disclosed"
        );
    }
}

/// A reason reaches the body, and `type`/`status` stay intact.
#[tokio::test]
async fn the_403_body_carries_the_reason() {
    let body = |response: Response| async {
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
    };

    let response = refuse(Some(&Refusal::Certificate("no dNSName for the domain")));
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers().get("accept-signature").unwrap(),
        ACCEPT_SIGNATURE,
        "the Accept-Signature field is still offered"
    );
    let json = body(response).await;
    assert_eq!(json["reason"], "certificate-rejected");
    assert_eq!(json["status"], 403);
    assert!(
        json["type"]
            .as_str()
            .unwrap()
            .ends_with("provider-authentication"),
        "{json}"
    );

    // A refusal that discloses nothing carries no reason member at all,
    // rather than an empty or null one.
    let json = body(refuse(Some(&Refusal::NoTrustedKey))).await;
    assert_eq!(json.get("reason"), None, "{json}");
    assert_eq!(json["status"], 403);

    // And no refusal at all is still a well-formed problem.
    let json = body(refuse(None)).await;
    assert_eq!(json.get("reason"), None, "{json}");
}
