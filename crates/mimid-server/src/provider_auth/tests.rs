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
