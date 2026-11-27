//! Attachments through a running daemon (bead mimid-1wgh.14): upload and
//! download (RFC 8620 §6.1, §6.2) against the blob store in
//! `<state_dir>/blobs`, driven over HTTP as a JMAP client drives them, and
//! a file sent by one daemon's client arriving at another's.
//!
//! Oracles: the blobId of "abc" carries SHA-256("abc") from FIPS 180-2
//! Appendix B.1; downloaded octets equal the uploaded ones; the
//! `Content-Disposition` of a non-ASCII name follows RFC 6266 §5's example
//! encoding; the stored file is the uploaded octets, mode 0600.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, BOB, Client, Running, config, server};
use mimid_agent::{BLOBS_DIR, MAX_SIZE_UPLOAD};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// SHA-256("abc"), FIPS 180-2 Appendix B.1.
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// The client's `sentAt` for every Message it posts.
const SENT_AT: &str = "2026-11-17T12:00:00Z";

/// Uploads `content` with `content_type` to `account` with `token`; the
/// status and the JSON answer.
async fn upload(
    client: &Client,
    account: &str,
    token: Option<&str>,
    content_type: &str,
    content: Vec<u8>,
) -> (u16, Value) {
    let url = client.session["uploadUrl"]
        .as_str()
        .unwrap()
        .replace("{accountId}", account);
    let mut request = client
        .http
        .post(url)
        .header("content-type", content_type)
        .body(content);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let body = response.bytes().await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// GETs the download URL of `blob` in `account` named `name` with `accept`.
async fn download(
    client: &Client,
    account: &str,
    blob: &str,
    name: &str,
    accept: &str,
    token: Option<&str>,
) -> reqwest::Response {
    let url = client.session["downloadUrl"]
        .as_str()
        .unwrap()
        .replace("{accountId}", account)
        .replace("{blobId}", blob)
        .replace("{name}", &percent_encode(name))
        .replace("{type}", &percent_encode(accept));
    let mut request = client.http.get(url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().await.unwrap()
}

/// RFC 3986 percent-encoding of everything but unreserved characters.
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// The answer to an upload whose headers announce `len` octets, sent
/// over raw TCP without the body: the daemon answers from the headers, so
/// no client sees its body write cut off.
async fn announced_upload(daemon: &Running, account: &str, len: usize) -> String {
    let mut stream = tokio::net::TcpStream::connect(daemon.addr).await.unwrap();
    let request = format!(
        "POST /jmap/upload/{account}/ HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n\
         Content-Type: application/octet-stream\r\nContent-Length: {len}\r\n\
         Connection: close\r\n\r\n",
        daemon.addr,
        daemon.token()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    answer
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_and_download_through_the_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let daemon = Running::start(&config(&server, ALICE, dir.path(), "from-allowed")).await;
    let client = daemon.client().await;
    let account = client.account.clone();
    let token = daemon.token();

    // The Session states the limits.
    let core = &client.session["capabilities"]["urn:ietf:params:jmap:core"];
    assert_eq!(core["maxSizeUpload"], json!(MAX_SIZE_UPLOAD));
    assert_eq!(core["maxConcurrentUpload"], json!(4));
    let chat =
        &client.session["accounts"][&account]["accountCapabilities"]["urn:ietf:params:jmap:chat"];
    assert_eq!(chat["maxAttachmentBytes"], json!(MAX_SIZE_UPLOAD));
    assert_eq!(chat["maxAttachmentsPerMessage"], json!(8));

    // The blobId of "abc" is its SHA-256.
    let (status, answer) = upload(
        &client,
        &account,
        Some(&token),
        "text/plain; charset=utf-8",
        b"abc".to_vec(),
    )
    .await;
    assert_eq!(status, 201, "{answer}");
    assert_eq!(
        answer,
        json!({
            "accountId": account,
            "blobId": format!("s{SHA256_ABC}"),
            "type": "text/plain; charset=utf-8",
            "size": 3,
        })
    );

    // Every octet value, and a name that needs RFC 8187 encoding.
    let content: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    let (status, answer) = upload(
        &client,
        &account,
        Some(&token),
        "not a type",
        content.clone(),
    )
    .await;
    assert_eq!(status, 201, "{answer}");
    assert_eq!(answer["type"], json!("application/octet-stream"));
    assert_eq!(answer["size"], json!(content.len()));
    let blob = answer["blobId"].as_str().unwrap().to_owned();
    // The same content again: the same blob.
    let (_, again) = upload(
        &client,
        &account,
        Some(&token),
        "image/png",
        content.clone(),
    )
    .await;
    assert_eq!(again["blobId"], json!(blob));

    let response = download(
        &client,
        &account,
        &blob,
        "\u{20ac} rates",
        "image/png",
        Some(&token),
    )
    .await;
    assert_eq!(response.status(), 200);
    let headers = response.headers().clone();
    assert_eq!(headers["content-type"], "image/png");
    assert_eq!(
        headers["content-disposition"],
        "attachment; filename=\"_ rates\"; filename*=UTF-8''%E2%82%AC%20rates"
    );
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["content-security-policy"], "sandbox");
    assert!(
        headers["cache-control"]
            .to_str()
            .unwrap()
            .contains("immutable")
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), content.as_slice());

    // An accept that is not a media type is application/octet-stream.
    for accept in ["", "text/html\r\nX-Evil: 1", "nonsense"] {
        let response = download(&client, &account, &blob, "f", accept, Some(&token)).await;
        assert_eq!(response.status(), 200, "{accept:?}");
        assert_eq!(
            response.headers()["content-type"],
            "application/octet-stream",
            "{accept:?}"
        );
    }

    // The file on disk is the content, 0600, in a 0700 directory.
    let blobs = daemon.state_dir.join(BLOBS_DIR);
    assert_eq!(std::fs::read(blobs.join(&blob)).unwrap(), content);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&blobs), 0o700);
        assert_eq!(mode(&blobs.join(&blob)), 0o600);
    }

    // Refusals: no token, another account, an unknown or malformed blob.
    let (status, _) = upload(&client, &account, None, "text/plain", b"x".to_vec()).await;
    assert_eq!(status, 401);
    let response = download(&client, &account, &blob, "f", "text/plain", None).await;
    assert_eq!(response.status(), 401);
    let (status, problem) = upload(
        &client,
        "a0000000000000000",
        Some(&token),
        "text/plain",
        b"x".to_vec(),
    )
    .await;
    assert_eq!(status, 404, "{problem}");
    assert_eq!(problem["status"], json!(404));
    let response = download(&client, "a0000000000000000", &blob, "f", "", Some(&token)).await;
    assert_eq!(response.status(), 404);
    let unknown = format!("s{}", "0".repeat(64));
    // `%2E%2E` is a dot segment the client's URL parser removes, so that
    // request matches no route: still 404.
    for missing in [unknown.as_str(), "..%2Fagent-token", "sabc", "%2E%2E"] {
        let response = download(&client, &account, missing, "f", "", Some(&token)).await;
        assert_eq!(response.status(), 404, "{missing}");
        if missing != "%2E%2E" {
            assert_eq!(
                response.headers()["content-type"],
                "application/problem+json",
                "{missing}"
            );
        }
    }

    // The largest upload is taken; one octet more is 413 (a body in
    // chunks is the unit test uploads_are_read_up_to_the_cap).
    let (status, answer) = upload(
        &client,
        &account,
        Some(&token),
        "application/octet-stream",
        vec![1u8; MAX_SIZE_UPLOAD],
    )
    .await;
    assert_eq!(status, 201, "{answer}");
    assert_eq!(answer["size"], json!(MAX_SIZE_UPLOAD));
    let answer = announced_upload(&daemon, &account, MAX_SIZE_UPLOAD + 1).await;
    assert!(answer.starts_with("HTTP/1.1 413"), "{answer}");
    let problem: Value = serde_json::from_str(answer.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(problem["type"], json!("urn:ietf:params:jmap:error:limit"));
    assert_eq!(problem["limit"], json!("maxSizeUpload"));
    assert_eq!(problem["status"], json!(413));
    // Nothing of it was stored: the "abc" blob, the binary one, the
    // largest.
    assert_eq!(std::fs::read_dir(&blobs).unwrap().count(), 3);

    // A Message/set create with the uploaded blob is sealed, uploaded to
    // the server and sent; the stored Message keeps the client's
    // Attachment as given.
    let created = client
        .create(
            "Chat",
            json!({"kind": "group", "name": "files", "memberIds": []}),
        )
        .await;
    let chat_id = created["id"].as_str().unwrap().to_owned();
    let answer = client
        .call(
            "Message/set",
            json!({"create": {"m": {
                "chatId": chat_id, "body": "", "sentAt": SENT_AT,
                "attachments": [{
                    "blobId": format!("s{SHA256_ABC}"), "filename": "abc.txt",
                    "contentType": "text/plain", "size": 3, "sha256": SHA256_ABC,
                }],
            }}}),
        )
        .await;
    let attachment = &answer["created"]["m"]["attachments"][0];
    assert_eq!(
        (
            &attachment["blobId"],
            &attachment["sha256"],
            &attachment["size"],
            &attachment["filename"]
        ),
        (
            &json!(format!("s{SHA256_ABC}")),
            &json!(SHA256_ABC),
            &json!(3),
            &json!("abc.txt")
        ),
        "{answer}"
    );
    assert_eq!(client.messages(&chat_id).await.len(), 1);
    daemon.stop().await;
}

/// alice's client uploads a file and sends it in a Message; bob's daemon
/// fetches, decrypts and stores it, and his client downloads exactly the
/// octets alice uploaded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_sent_by_one_daemon_arrives_at_another() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "from-allowed")).await;
    let bob = Running::start(&config(&server, BOB, dir.path(), "any")).await;
    let a = alice.client().await;
    let b = bob.client().await;
    let mut b_events = b.events().await;

    let bob_contact = a.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let chat_a = a
        .create(
            "Chat",
            json!({"kind": "group", "name": "files", "memberIds": [bob_contact]}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    b_events.until_changed("Chat").await;
    let chats = b.get("Chat", None).await;
    let chat_b = chats[0]["id"].as_str().unwrap().to_owned();

    // Every octet value, larger than one HTTP chunk.
    let content: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
    let (status, uploaded) = upload(
        &a,
        &a.account,
        Some(&alice.token()),
        "application/pdf",
        content.clone(),
    )
    .await;
    assert_eq!(status, 201, "{uploaded}");
    let blob = uploaded["blobId"].as_str().unwrap().to_owned();
    let sha256 = blob.strip_prefix('s').unwrap().to_owned();
    let attachment = json!({
        "blobId": blob, "filename": "report.pdf", "contentType": "application/pdf",
        "size": content.len(), "sha256": sha256,
    });
    let sent = a
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "the report", "sentAt": SENT_AT,
                   "attachments": [attachment]}),
        )
        .await;
    let mine = a
        .get("Message", Some(vec![sent["id"].as_str().unwrap()]))
        .await;
    assert_eq!(mine[0]["attachments"], json!([attachment]));

    // bob's daemon stores the message with the file.
    let got = loop {
        b_events.until_changed("Message").await;
        let got = b.messages(&chat_b).await;
        if !got.is_empty() {
            break got;
        }
    };
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0]["body"], json!("the report"));
    assert_eq!(got[0]["senderMsgId"], mine[0]["senderMsgId"]);
    let received = &got[0]["attachments"];
    assert_eq!(received.as_array().map(Vec::len), Some(1), "{got:?}");
    let received = &received[0];
    assert_eq!(received["filename"], json!("report.pdf"));
    assert_eq!(received["contentType"], json!("application/pdf"));
    assert_eq!(received["size"], json!(content.len()));
    // Content addressing: the same plaintext, the same blobId and digest.
    assert_eq!(received["sha256"], json!(sha256));
    assert_eq!(received["blobId"], json!(blob));
    assert_eq!(
        std::fs::read(bob.state_dir.join(BLOBS_DIR).join(&blob)).unwrap(),
        content
    );

    let response = download(
        &b,
        &b.account,
        &blob,
        "report.pdf",
        "application/pdf",
        Some(&bob.token()),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), content.as_slice());

    // An attachment-only message arrives with an empty body.
    a.create(
        "Message",
        json!({"chatId": chat_a, "body": "", "sentAt": SENT_AT,
        "attachments": [{
            "blobId": blob, "filename": "again.pdf", "contentType": "application/pdf",
            "size": content.len(), "sha256": sha256,
        }]}),
    )
    .await;
    let got = loop {
        b_events.until_changed("Message").await;
        let got = b.messages(&chat_b).await;
        if got.len() == 2 {
            break got;
        }
    };
    let only = got
        .iter()
        .find(|m| m["body"] == json!(""))
        .unwrap_or_else(|| panic!("{got:?}"));
    assert_eq!(only["attachments"][0]["filename"], json!("again.pdf"));

    bob.stop().await;
    alice.stop().await;
}
