//! Oracles: RFC 9421 Appendix B.1.4 (test-key-ed25519), B.2.6 (signing a
//! request with ed25519: signature base, Signature-Input and Signature) and
//! B.4 (the transformations a signature survives or does not), RFC 9421
//! §2.2 (derived component values), and the Content-Digest of the B.2
//! test-request body (RFC 9530 Appendix D).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;

/// B.1.4 test-key-ed25519, JWK `d` and `x`.
const TEST_KEY_D: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const TEST_KEY_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

/// B.2.6 created.
const CREATED: i64 = 1_618_884_473;

fn signing_key() -> SigningKey {
    let d: [u8; 32] = URL_SAFE_NO_PAD
        .decode(TEST_KEY_D)
        .unwrap()
        .try_into()
        .unwrap();
    SigningKey::from_seed(&d)
}

fn verifying_key() -> VerifyingKey {
    let x: [u8; 32] = URL_SAFE_NO_PAD
        .decode(TEST_KEY_X)
        .unwrap()
        .try_into()
        .unwrap();
    VerifyingKey::from_bytes(&x).unwrap()
}

fn headers(fields: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in fields {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

/// B.2 test-request, as an absolute URI and its header fields.
fn test_request() -> (Method, Uri, HeaderMap) {
    (
        Method::POST,
        Uri::from_static("https://example.com/foo?param=Value&Pet=dog"),
        headers(&[
            ("host", "example.com"),
            ("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("content-type", "application/json"),
            (
                "content-digest",
                "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            ),
            ("content-length", "18"),
        ]),
    )
}

const TEST_BODY: &[u8] = br#"{"hello": "world"}"#;

fn b26_params() -> SignatureParams {
    SignatureParams {
        components: [
            "date",
            "@method",
            "@path",
            "@authority",
            "content-type",
            "content-length",
        ]
        .map(str::to_owned)
        .to_vec(),
        created: Some(CREATED),
        keyid: Some("test-key-ed25519".to_owned()),
        ..SignatureParams::default()
    }
}

/// Accepts B.2.6's signature at its `created` time.
fn at_created() -> TimePolicy {
    TimePolicy {
        now: CREATED,
        skew: 60,
        max_age: 300,
    }
}

fn the_test_key(params: &SignatureParams) -> Option<VerifyingKey> {
    (params.keyid.as_deref() == Some("test-key-ed25519")).then(verifying_key)
}

#[test]
fn the_test_key_pairs_up() {
    assert_eq!(signing_key().verifying_key(), verifying_key());
    // Debug shows the public key only.
    let debug = format!("{:?}", signing_key());
    assert!(!debug.contains(&STANDARD.encode(URL_SAFE_NO_PAD.decode(TEST_KEY_D).unwrap())));
}

#[test]
fn b26_signature_base_signature_input_and_signature() {
    let (method, uri, headers) = test_request();
    let parts = RequestParts {
        method: &method,
        uri: &uri,
        headers: &headers,
    };
    let base = signature_base_for(&parts, &b26_params()).unwrap();
    assert_eq!(
        base,
        concat!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n",
            "\"@method\": POST\n",
            "\"@path\": /foo\n",
            "\"@authority\": example.com\n",
            "\"content-type\": application/json\n",
            "\"content-length\": 18\n",
            "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" ",
            "\"content-type\" \"content-length\");created=1618884473",
            ";keyid=\"test-key-ed25519\""
        )
    );
    let (input, signature) = sign(&parts, "sig-b26", &b26_params(), &signing_key()).unwrap();
    assert_eq!(
        input,
        concat!(
            "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" ",
            "\"content-type\" \"content-length\");created=1618884473",
            ";keyid=\"test-key-ed25519\""
        )
    );
    // Ed25519 is deterministic: the RFC's signature, byte for byte.
    assert_eq!(
        signature,
        concat!(
            "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1",
            "u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
        )
    );
}

#[test]
fn b26_verifies_and_a_changed_covered_field_does_not() {
    let (method, uri, mut headers) = test_request();
    sign_headers(
        &method,
        &uri,
        &mut headers,
        "sig-b26",
        &b26_params(),
        &signing_key(),
    )
    .unwrap();
    let parts = RequestParts {
        method: &method,
        uri: &uri,
        headers: &headers,
    };
    let params = verify(&parts, "sig-b26", at_created(), the_test_key).unwrap();
    assert_eq!(params, b26_params());

    let mut changed = headers.clone();
    changed.insert("content-length", HeaderValue::from_static("19"));
    let parts = RequestParts {
        method: &method,
        uri: &uri,
        headers: &changed,
    };
    assert_eq!(
        verify(&parts, "sig-b26", at_created(), the_test_key),
        Err(Error::BadSignature)
    );
}

/// B.4: the signed GET, and the message after each transformation.
fn b4(
    method: Method,
    uri: &'static str,
    fields: &[(&str, &str)],
) -> Result<SignatureParams, Error> {
    let mut headers = headers(fields);
    headers.append(
        SIGNATURE_INPUT,
        HeaderValue::from_static(
            "transform=(\"@method\" \"@path\" \"@authority\" \"accept\");created=1618884473;keyid=\"test-key-ed25519\"",
        ),
    );
    headers.append(
        SIGNATURE,
        HeaderValue::from_static(
            "transform=:ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==:",
        ),
    );
    let uri = Uri::from_static(uri);
    verify(
        &RequestParts {
            method: &method,
            uri: &uri,
            headers: &headers,
        },
        "transform",
        at_created(),
        the_test_key,
    )
}

#[test]
fn b4_transformations_that_keep_the_signature_valid() {
    let original = [
        ("date", "Fri, 15 Jul 2022 14:24:55 GMT"),
        ("accept", "application/json"),
        ("accept", "*/*"),
    ];
    b4(
        Method::GET,
        "https://example.org/demo?name1=Value1&Name2=value2",
        &original,
    )
    .unwrap();
    // A header field and a query parameter added.
    b4(
        Method::GET,
        "https://example.org/demo?name1=Value1&Name2=value2&param=added",
        &[
            ("date", "Fri, 15 Jul 2022 14:24:55 GMT"),
            ("accept", "application/json"),
            ("accept", "*/*"),
            ("accept-language", "en-US,en;q=0.5"),
        ],
    )
    .unwrap();
    // Date removed, Referer added, Accept collapsed onto one line.
    b4(
        Method::GET,
        "https://example.org/demo?name1=Value1&Name2=value2",
        &[
            ("referer", "https://developer.example.org/demo"),
            ("accept", "application/json, */*"),
        ],
    )
    .unwrap();
    // Fields reordered, the Accept lines kept in order.
    b4(
        Method::GET,
        "https://example.org/demo?name1=Value1&Name2=value2",
        &[
            ("accept", "application/json"),
            ("accept", "*/*"),
            ("date", "Fri, 15 Jul 2022 14:24:55 GMT"),
        ],
    )
    .unwrap();
}

#[test]
fn b4_transformations_that_break_the_signature() {
    let accept = [("accept", "application/json"), ("accept", "*/*")];
    // Method and authority changed.
    assert_eq!(
        b4(
            Method::POST,
            "https://example.com/demo?name1=Value1&Name2=value2",
            &accept
        ),
        Err(Error::BadSignature)
    );
    // The two Accept lines swapped.
    assert_eq!(
        b4(
            Method::GET,
            "https://example.org/demo?name1=Value1&Name2=value2",
            &[("accept", "*/*"), ("accept", "application/json")]
        ),
        Err(Error::BadSignature)
    );
}

#[test]
fn derived_components_follow_section_2_2() {
    let headers = HeaderMap::new();
    let value = |method: &Method, uri: &'static str, name: &str| {
        component_value(
            &RequestParts {
                method,
                uri: &Uri::from_static(uri),
                headers: &headers,
            },
            name,
        )
    };
    let post = Method::POST;
    // §2.2.2, §2.2.3, §2.2.4, §2.2.6, §2.2.7.
    let uri = "https://www.example.com/path?param=value";
    assert_eq!(value(&post, uri, "@target-uri").unwrap(), uri);
    assert_eq!(value(&post, uri, "@authority").unwrap(), "www.example.com");
    assert_eq!(value(&post, uri, "@scheme").unwrap(), "https");
    assert_eq!(value(&post, uri, "@path").unwrap(), "/path");
    assert_eq!(
        value(
            &Method::GET,
            "https://www.example.com/path?param=value&foo=bar&baz=bat%2Dman",
            "@query"
        )
        .unwrap(),
        "?param=value&foo=bar&baz=bat%2Dman"
    );
    // An empty query is "?"; a default port is left out, another kept;
    // the host is lowercased.
    assert_eq!(
        value(&post, "https://www.example.com/path", "@query").unwrap(),
        "?"
    );
    assert_eq!(
        value(&post, "https://EXAMPLE.com:443/", "@authority").unwrap(),
        "example.com"
    );
    assert_eq!(
        value(&post, "http://example.com:8080/", "@authority").unwrap(),
        "example.com:8080"
    );
    // A relative URI has no target URI.
    assert!(matches!(
        value(&post, "/path", "@target-uri"),
        Err(Error::BadValue(_))
    ));
}

#[test]
fn signatures_this_module_does_not_take_are_refused() {
    let (method, uri, headers) = test_request();
    let parts = RequestParts {
        method: &method,
        uri: &uri,
        headers: &headers,
    };
    let key = signing_key();
    let with = |components: &[&str]| SignatureParams {
        components: components.iter().map(|c| (*c).to_owned()).collect(),
        ..b26_params()
    };
    assert_eq!(
        sign(&parts, "s", &with(&["@method", "@method"]), &key),
        Err(Error::DuplicateComponent("@method".to_owned()))
    );
    assert_eq!(
        sign(&parts, "s", &with(&["accept"]), &key),
        Err(Error::MissingField("accept".to_owned()))
    );
    assert_eq!(
        sign(&parts, "s", &with(&["@request-target"]), &key),
        Err(Error::Unsupported("@request-target".to_owned()))
    );
    assert_eq!(
        sign(
            &parts,
            "s",
            &SignatureParams {
                alg: Some("rsa-pss-sha512".to_owned()),
                ..b26_params()
            },
            &key
        ),
        Err(Error::Algorithm("rsa-pss-sha512".to_owned()))
    );

    // Received: a component parameter, an unknown signature parameter, a
    // missing label, and a key the caller does not have.
    let received = |input: &'static str| {
        let mut h = headers.clone();
        h.append(SIGNATURE_INPUT, HeaderValue::from_static(input));
        h.append(SIGNATURE, HeaderValue::from_static("s=:AAAA:"));
        verify(
            &RequestParts {
                method: &method,
                uri: &uri,
                headers: &h,
            },
            "s",
            at_created(),
            the_test_key,
        )
    };
    assert_eq!(
        received("s=(\"content-digest\";sf);created=1618884473"),
        Err(Error::Unsupported("content-digest;sf".to_owned()))
    );
    assert_eq!(
        received("s=(\"@method\");created=1618884473;foo=1"),
        Err(Error::Unsupported("foo".to_owned()))
    );
    assert_eq!(
        received("t=(\"@method\");created=1618884473"),
        Err(Error::NoSuchLabel("s".to_owned()))
    );
    assert_eq!(
        received("s=(\"@method\");created=1618884473;keyid=\"other\""),
        Err(Error::UnknownKey)
    );
    assert_eq!(
        received("s=(\"@method\");created=1618884473;alg=\"hmac-sha256\""),
        Err(Error::Algorithm("hmac-sha256".to_owned()))
    );
}

#[test]
fn created_and_expires_are_checked() {
    let (method, uri, mut headers) = test_request();
    let params = SignatureParams {
        expires: Some(CREATED + 100),
        ..b26_params()
    };
    sign_headers(&method, &uri, &mut headers, "s", &params, &signing_key()).unwrap();
    let parts = RequestParts {
        method: &method,
        uri: &uri,
        headers: &headers,
    };
    let at = |now: i64| {
        verify(
            &parts,
            "s",
            TimePolicy {
                now,
                skew: 60,
                max_age: 300,
            },
            the_test_key,
        )
    };
    assert!(at(CREATED).is_ok());
    assert!(at(CREATED - 60).is_ok(), "within the skew");
    assert_eq!(at(CREATED - 61), Err(Error::Time), "created in the future");
    assert_eq!(at(CREATED + 100), Err(Error::Time), "expired");

    let (method, uri, mut headers) = test_request();
    sign_headers(
        &method,
        &uri,
        &mut headers,
        "s",
        &b26_params(),
        &signing_key(),
    )
    .unwrap();
    let parts = RequestParts {
        method: &method,
        uri: &uri,
        headers: &headers,
    };
    let at = |now: i64| {
        verify(
            &parts,
            "s",
            TimePolicy {
                now,
                skew: 60,
                max_age: 300,
            },
            the_test_key,
        )
    };
    assert!(at(CREATED + 300).is_ok());
    assert_eq!(at(CREATED + 301), Err(Error::Time), "too old");

    // created is required.
    let (method, uri, mut headers) = test_request();
    let no_created = SignatureParams {
        created: None,
        ..b26_params()
    };
    sign_headers(
        &method,
        &uri,
        &mut headers,
        "s",
        &no_created,
        &signing_key(),
    )
    .unwrap();
    let parts = RequestParts {
        method: &method,
        uri: &uri,
        headers: &headers,
    };
    assert_eq!(
        verify(&parts, "s", at_created(), the_test_key),
        Err(Error::Time)
    );
}

#[test]
fn content_digest_matches_rfc_9530_and_the_body() {
    let (_, _, headers) = test_request();
    // The B.2 test-request's sha-512 digest is the RFC 9530 value for its body.
    check_content_digest(&headers, TEST_BODY).unwrap();
    assert_eq!(
        check_content_digest(&headers, b"{\"hello\": \"World\"}"),
        Err(Error::Digest)
    );
    assert_eq!(
        check_content_digest(&HeaderMap::new(), TEST_BODY),
        Err(Error::Digest)
    );

    // RFC 9530 Appendix D: sha-256 of {"hello": "world"}.
    assert_eq!(
        content_digest(TEST_BODY),
        "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
    );
    let mut ours = HeaderMap::new();
    ours.insert(CONTENT_DIGEST, content_digest(b"body"));
    check_content_digest(&ours, b"body").unwrap();
    // Only unknown algorithms: nothing was checked.
    let unknown = headers_with_digest("md5=:AAAA:");
    assert_eq!(check_content_digest(&unknown, b"body"), Err(Error::Digest));
}

fn headers_with_digest(value: &'static str) -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert(CONTENT_DIGEST, HeaderValue::from_static(value));
    map
}
