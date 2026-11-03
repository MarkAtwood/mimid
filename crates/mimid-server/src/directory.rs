//! The MIMI directory document (draft-ietf-mimi-protocol-06 §5.1) and the
//! HTTP router that serves it.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use mimi_protocol::UriTemplate;

use crate::config::BaseUrl;

pub use mimi_protocol::Directory;

/// The well-known path the directory is served at (protocol-06 §5.1). No
/// IANA registration exists for it (decision mimid-1wgh.5.33).
pub const DIRECTORY_PATH: &str = "/.well-known/mimi-protocol-directory";

/// The directory document (protocol-06 §5.1) of a server reachable at
/// `base`, as mimi-protocol's [`Directory`].
///
/// Only endpoints this server routes are listed, since an absent key means
/// the endpoint is not offered (decision mimid-1wgh.5.75); `proxyDownload`
/// is not yet listed (mimid-1wgh.8). The paths follow the §5.1 example,
/// including its `/v1` prefix (decision mimid-1wgh.5.37). Placeholders are
/// served as literal `{name}` text (decision mimid-1wgh.5.38). The example's
/// `update{roomId}` lacks a slash; it is read as `update/{roomId}` (decision
/// mimid-1wgh.5.17). The consent placeholders name domains, as in §5.7, not
/// users as in the §5.1 example (decision mimid-1wgh.5.16).
pub fn directory(base: &BaseUrl) -> Directory {
    let url = |path: &str| {
        // A BaseUrl is a scheme and host with no path, query or braces, so
        // every template here is a valid level-1 template.
        Some(
            UriTemplate::new(&format!("{base}/v1/{path}"))
                .expect("directory templates are valid for any BaseUrl"),
        )
    };
    Directory {
        key_material: url("keyMaterial/{targetUser}"),
        update: url("update/{roomId}"),
        notify: url("notify/{roomId}"),
        submit_message: url("submitMessage/{roomId}"),
        group_info: url("groupInfo/{roomId}"),
        request_consent: url("requestConsent/{targetDomain}"),
        update_consent: url("updateConsent/{requesterDomain}"),
        identifier_query: url("identifierQuery/{domain}"),
        report_abuse: url("reportAbuse/{roomId}"),
        proxy_download: None,
        unknown: Default::default(),
    }
}

/// Builds the server's HTTP router.
pub fn router(directory: Directory) -> Router {
    Router::new()
        .route(DIRECTORY_PATH, get(get_directory))
        .with_state(directory)
}

async fn get_directory(State(directory): State<Directory>) -> Json<Directory> {
    Json(directory)
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    use super::*;

    /// The protocol-06 §5.1 example, copied by hand from the draft text and
    /// limited to the nine endpoints this server routes (decision
    /// mimid-1wgh.5.75), with the `update{roomId}` typo read as
    /// `update/{roomId}` per decision mimid-1wgh.5.17. The consent
    /// placeholders are the §5.7 `{targetDomain}` and `{requesterDomain}`,
    /// not §5.1's user placeholders (decision mimid-1wgh.5.16).
    const SPEC_EXAMPLE: &str = r#"
    {
      "keyMaterial":
         "https://mimi.example.com/v1/keyMaterial/{targetUser}",
      "update": "https://mimi.example.com/v1/update/{roomId}",
      "notify": "https://mimi.example.com/v1/notify/{roomId}",
      "submitMessage":
         "https://mimi.example.com/v1/submitMessage/{roomId}",
      "groupInfo":
         "https://mimi.example.com/v1/groupInfo/{roomId}",
      "requestConsent":
         "https://mimi.example.com/v1/requestConsent/{targetDomain}",
      "updateConsent":
         "https://mimi.example.com/v1/updateConsent/{requesterDomain}",
      "identifierQuery":
         "https://mimi.example.com/v1/identifierQuery/{domain}",
      "reportAbuse":
         "https://mimi.example.com/v1/reportAbuse/{roomId}"
    }
    "#;

    async fn get(uri: &str) -> axum::response::Response {
        let base = BaseUrl::try_from("https://mimi.example.com".to_owned()).unwrap();
        router(directory(&base))
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn serves_routed_endpoints_in_spec_layout() {
        let response = get("/.well-known/mimi-protocol-directory").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let actual: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected: serde_json::Value = serde_json::from_str(SPEC_EXAMPLE).unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn unknown_path_is_not_found() {
        let response = get("/.well-known/mimi-protocol-directory/extra").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
