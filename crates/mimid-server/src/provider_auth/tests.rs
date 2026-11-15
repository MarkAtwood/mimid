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
    auth.authenticate(&InboundRequest {
        from: &from,
        method: &Method::POST,
        uri: &uri,
        headers,
        body,
        now: NOW,
    })
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

    #[test]
    fn mimids_signer_reproduces_the_example_byte_for_byte() {
        let mut headers = HeaderMap::new();
        headers.insert(header::FROM, HeaderValue::from_static("mimi@a.example"));
        a_signer()
            .sign(
                &Method::POST,
                &URI.parse().unwrap(),
                &mut headers,
                BODY,
                CREATED,
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
        let provider = auth
            .authenticate(&InboundRequest {
                from: &from,
                method: &Method::POST,
                uri: &uri,
                headers: &headers,
                body: BODY,
                now: CREATED,
            })
            .unwrap();
        assert_eq!(provider.key_id, "s1");
        assert_eq!(provider.domain, from);
    }
}
