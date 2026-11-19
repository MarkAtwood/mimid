//! draft-ietf-jmap-blobext-03 (`urn:ietf:params:jmap:blob2`) on the JMAP
//! endpoint (bead mimid-1wgh.14.7; decision mimid-1wgh.69): the capability
//! in the Session, `Blob/set` destroy deleting from the store (so the
//! quota frees up and download and `/assets` answer `404`), destroy of
//! another account's blob or an unknown one refused with `notFound`, and
//! the other methods answering as the decision narrows them.
//!
//! Every request goes through the whole JMAP router, as a client's would.
//!
//! Oracles: the draft's text for each response field and error name; the
//! FIPS 180-2 SHA-256 test vector for "abc"; an `expires` computed by
//! hand from the fixed clock and lifetime; status codes as
//! `tests/jmap_blobs.rs` checks them for the RFC 8620 routes.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::{FixedClock, domain, open_hub};
use mimid_server::config::BaseUrl;
use mimid_server::follower::Follower;
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::store::{BearerToken, BlobQuota, Store};
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";
const BASE_URL: &str = "https://mimi.a.example";
const BLOB2: &str = "urn:ietf:params:jmap:blob2";
const CORE: &str = "urn:ietf:params:jmap:core";

/// The fixed clock's reading: uploads and creates are stamped with it.
const NOW_MS: u64 = 1_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    app: Router,
    alice_id: String,
    alice_token: BearerToken,
    bob_id: String,
    bob_token: BearerToken,
}

/// A router with `quota`, the clock at [`NOW_MS`] and a one-hour asset
/// lifetime.
async fn fixture(quota: BlobQuota) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let alice_id = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let alice_token = store.issue_token(&alice_id, 2).await.unwrap();
    let bob_id = store.create_account(&domain(), BOB, 3).await.unwrap();
    let bob_token = store.issue_token(&bob_id, 4).await.unwrap();
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(5)));
    let mut options = JmapOptions::default();
    options.blob_quota = quota;
    options.clock = Arc::new(FixedClock(NOW_MS));
    options.asset_lifetime = Some(3600);
    let app = jmap::router(
        &BaseUrl::try_from(BASE_URL.to_owned()).unwrap(),
        store.clone(),
        Arc::new(hub),
        Arc::new(follower),
        options,
    )
    .unwrap();
    Fixture {
        _dir: dir,
        store,
        app,
        alice_id,
        alice_token,
        bob_id,
        bob_token,
    }
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

fn bearer(token: &BearerToken) -> String {
    format!("Bearer {}", token.expose_secret())
}

/// Uploads `body` to `account_id` with `token`: the status, and the blob
/// id when it was stored.
async fn upload(
    app: &Router,
    token: &BearerToken,
    account_id: &str,
    body: &[u8],
) -> (StatusCode, Option<String>) {
    let request = Request::post(format!("/jmap/upload/{account_id}/"))
        .header(header::AUTHORIZATION, bearer(token))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body.to_vec()))
        .unwrap();
    let (status, body) = send(app, request).await;
    let id = (status == StatusCode::CREATED).then(|| {
        serde_json::from_slice::<Value>(&body).unwrap()["blobId"]
            .as_str()
            .unwrap()
            .to_owned()
    });
    (status, id)
}

async fn get(app: &Router, uri: &str, token: Option<&BearerToken>) -> (StatusCode, Vec<u8>) {
    let mut request = Request::get(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, bearer(token));
    }
    send(app, request.body(Body::empty()).unwrap()).await
}

/// Calls `method` with `args` under `using` as `token`, and returns the
/// one method response: `[name, arguments, callId]`.
async fn call(
    app: &Router,
    token: &BearerToken,
    using: &[&str],
    method: &str,
    args: Value,
) -> Value {
    let body = json!({"using": using, "methodCalls": [[method, args, "c0"]]});
    let request = Request::post("/jmap/api")
        .header(header::AUTHORIZATION, bearer(token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, body) = send(app, request).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let response: Value = serde_json::from_slice(&body).unwrap();
    response["methodResponses"][0].clone()
}

async fn destroy(f: &Fixture, token: &BearerToken, account_id: &str, ids: &[&str]) -> Value {
    let response = call(
        &f.app,
        token,
        &[CORE, BLOB2],
        "Blob/set",
        json!({"accountId": account_id, "destroy": ids}),
    )
    .await;
    assert_eq!(response[0], "Blob/set", "{response}");
    response[1].clone()
}

#[tokio::test]
async fn destroy_frees_the_quota_and_the_asset_is_gone() {
    // Room for one blob.
    let f = fixture(BlobQuota::new(1024, 1024, 1)).await;
    let (status, id) = upload(&f.app, &f.alice_token, &f.alice_id, b"sealed").await;
    assert_eq!(status, StatusCode::CREATED);
    let id = id.unwrap();
    let (status, _) = upload(&f.app, &f.alice_token, &f.alice_id, b"more").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the account is full");
    let (status, body) = get(&f.app, &format!("/assets/{id}"), None).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, &b"sealed"[..]));

    let set = destroy(&f, &f.alice_token, &f.alice_id, &[&id]).await;
    // blobext-03 §4: a standard Foo/set response, oldState and newState
    // null.
    assert_eq!(set["destroyed"], json!([id]), "{set}");
    assert_eq!(set["oldState"], Value::Null);
    assert_eq!(set["newState"], Value::Null);
    assert!(
        set.get("notDestroyed")
            .is_none_or(|v| v.is_null() || v == &json!({})),
        "{set}"
    );

    let (status, _) = get(&f.app, &format!("/assets/{id}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let download = format!("/jmap/download/{}/{id}/x.bin", f.alice_id);
    let (status, _) = get(&f.app, &download, Some(&f.alice_token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = upload(&f.app, &f.alice_token, &f.alice_id, b"more").await;
    assert_eq!(status, StatusCode::CREATED, "the quota has room again");

    // Gone, so a second destroy is notFound.
    let set = destroy(&f, &f.alice_token, &f.alice_id, &[&id]).await;
    assert_eq!(set["notDestroyed"][&id]["type"], "notFound", "{set}");
    f.store.close().await;
}

#[tokio::test]
async fn another_account_cannot_destroy_a_blob() {
    let f = fixture(BlobQuota::default()).await;
    let (_, id) = upload(&f.app, &f.alice_token, &f.alice_id, b"alice's").await;
    let id = id.unwrap();

    // In bob's own account alice's blob does not exist.
    let set = destroy(&f, &f.bob_token, &f.bob_id, &[&id]).await;
    assert_eq!(set["notDestroyed"][&id]["type"], "notFound", "{set}");
    // RFC 8620 §5.3: destroyed is "Id[]|null".
    assert_eq!(set["destroyed"], Value::Null, "{set}");
    // Alice's account is not one bob's token reaches.
    let response = call(
        &f.app,
        &f.bob_token,
        &[CORE, BLOB2],
        "Blob/set",
        json!({"accountId": f.alice_id, "destroy": [id]}),
    )
    .await;
    assert_eq!(response[0], "error");
    assert_eq!(response[1]["type"], "accountNotFound", "{response}");

    let (status, body) = get(&f.app, &format!("/assets/{id}"), None).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, &b"alice's"[..]));
    f.store.close().await;
}

#[tokio::test]
async fn an_unknown_blob_id_is_not_found() {
    let f = fixture(BlobQuota::default()).await;
    // Well-formed (22 base64url characters, 16 octets) but never issued.
    let unknown = "AAECAwQFBgcICQoLDA0ODw";
    let set = destroy(&f, &f.alice_token, &f.alice_id, &[unknown]).await;
    assert_eq!(set["notDestroyed"][unknown]["type"], "notFound", "{set}");
    // Not a blob id mimid issues at all.
    let set = destroy(&f, &f.alice_token, &f.alice_id, &["Zm9v"]).await;
    assert_eq!(set["notDestroyed"]["Zm9v"]["type"], "notFound", "{set}");
    f.store.close().await;
}

#[tokio::test]
async fn the_session_advertises_blob2() {
    let f = fixture(BlobQuota::new(1000, 5000, 10)).await;
    let (status, body) = get(&f.app, "/.well-known/jmap", Some(&f.alice_token)).await;
    assert_eq!(status, StatusCode::OK);
    let session: Value = serde_json::from_slice(&body).unwrap();
    // §2.1: "MUST also include it in the "capabilities" property", whose
    // value "MUST be an empty object".
    assert_eq!(session["capabilities"][BLOB2], json!({}));
    // §2.1: the account object "MUST contain" every property.
    assert_eq!(
        session["accounts"][&f.alice_id]["accountCapabilities"][BLOB2],
        json!({
            "maxSizeBlobSet": 1000,
            "maxDataSources": 64,
            "supportedTypeNames": [],
            "supportedDigestAlgorithms": ["sha-256"],
            "uploadUrl": null,
            "chunkSize": null,
            "supportedImageReadTypes": null,
            "supportedImageWriteTypes": null,
            "supportedArchiveTypes": null,
            "supportedExtractTypes": null,
            "supportedCompressTypes": null,
            "supportedDecompressTypes": null,
            "supportedDeltaTypes": null,
            "supportedPatchTypes": null,
            "maxConvertSize": null,
            "maxArchiveEntries": null,
            "maxImageDimension": null,
        })
    );
    f.store.close().await;
}

#[tokio::test]
async fn blob_methods_need_blob2_in_using() {
    let f = fixture(BlobQuota::default()).await;
    let (_, id) = upload(&f.app, &f.alice_token, &f.alice_id, b"kept").await;
    let id = id.unwrap();
    for method in ["Blob/get", "Blob/set", "Blob/lookup", "Blob/convert"] {
        let response = call(
            &f.app,
            &f.alice_token,
            &[CORE],
            method,
            json!({"accountId": f.alice_id, "ids": [id], "destroy": [id]}),
        )
        .await;
        assert_eq!(response[0], "error", "{method}");
        assert_eq!(response[1]["type"], "unknownMethod", "{method}");
    }
    let (status, _) = get(&f.app, &format!("/assets/{id}"), None).await;
    assert_eq!(status, StatusCode::OK, "nothing was destroyed");
    // RFC 9404's methods and capability are not served.
    let response = call(
        &f.app,
        &f.alice_token,
        &[CORE, BLOB2],
        "Blob/upload",
        json!({"accountId": f.alice_id, "create": {}}),
    )
    .await;
    assert_eq!(response[1]["type"], "unknownMethod", "{response}");
    f.store.close().await;
}

#[tokio::test]
async fn get_create_touch_lookup_and_convert_answer_as_the_decision_says() {
    let f = fixture(BlobQuota::default()).await;
    let (_, id) = upload(&f.app, &f.alice_token, &f.alice_id, b"abc").await;
    let id = id.unwrap();
    // Created at NOW_MS = 1000 s after the epoch, plus 3600 s:
    // 4600 s = 01:16:40.
    let expires = "1970-01-01T01:16:40Z";

    // §5: data, size and a digest of the selected octets.
    let response = call(
        &f.app,
        &f.alice_token,
        &[CORE, BLOB2],
        "Blob/get",
        json!({
            "accountId": f.alice_id,
            "ids": [id, "AAECAwQFBgcICQoLDA0ODw"],
            "properties": ["data:asText", "size", "digest:sha-256"],
        }),
    )
    .await;
    assert_eq!(response[0], "Blob/get", "{response}");
    let blob = &response[1]["list"][0];
    assert_eq!(blob["id"], json!(id));
    assert_eq!(blob["data:asText"], "abc");
    assert_eq!(blob["size"], 3);
    // FIPS 180-2 B.1: SHA-256("abc"), in base64.
    assert_eq!(
        blob["digest:sha-256"],
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(response[1]["notFound"], json!(["AAECAwQFBgcICQoLDA0ODw"]));

    // §4 create from inline data and a range of the upload; then touch.
    let response = call(
        &f.app,
        &f.alice_token,
        &[CORE, BLOB2],
        "Blob/set",
        json!({
            "accountId": f.alice_id,
            "create": {"k1": {"data": [
                {"data:asText": "x-"},
                {"blobId": id, "offset": 1, "length": 2},
            ]}},
            "update": {id.clone(): {"expires": "2099-01-01T00:00:00Z"}},
        }),
    )
    .await;
    let set = &response[1];
    let created = &set["created"]["k1"];
    assert_eq!(created["size"], 4, "{set}");
    assert_eq!(created["type"], "application/octet-stream", "{set}");
    assert_eq!(created["expires"], expires, "{set}");
    // The lifetime is not extended: the expires in force comes back.
    assert_eq!(set["updated"][&id], json!({"expires": expires}), "{set}");
    let new_id = created["id"].as_str().unwrap();
    let (status, body) = get(&f.app, &format!("/assets/{new_id}"), None).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, &b"x-bc"[..]));

    // §2.1: an empty supportedTypeNames means no Blob/lookup.
    let response = call(
        &f.app,
        &f.alice_token,
        &[CORE, BLOB2, "urn:ietf:params:jmap:chat"],
        "Blob/lookup",
        json!({"accountId": f.alice_id, "typeNames": ["Message"], "ids": [id]}),
    )
    .await;
    assert_eq!(response[0], "error");
    assert_eq!(response[1]["type"], "unknownDataType", "{response}");

    // §8: no conversion is offered, so the recipe is refused.
    let response = call(
        &f.app,
        &f.alice_token,
        &[CORE, BLOB2],
        "Blob/convert",
        json!({"accountId": f.alice_id, "create": {"c": {
            "compress": {"blobId": id, "type": "application/gzip"},
        }}}),
    )
    .await;
    assert_eq!(response[0], "Blob/convert", "{response}");
    assert_eq!(
        response[1]["notCreated"]["c"]["type"], "invalidProperties",
        "{response}"
    );
    f.store.close().await;
}
