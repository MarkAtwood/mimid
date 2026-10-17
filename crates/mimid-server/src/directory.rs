//! The MIMI directory document (draft-ietf-mimi-protocol-06 §5.1) and the
//! HTTP router that serves it.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::config::BaseUrl;

/// The well-known path the directory is served at (protocol-06 §5.1). No
/// IANA registration exists for it (decision mimid-1wgh.5.33).
pub const DIRECTORY_PATH: &str = "/.well-known/mimi-protocol-directory";

/// The directory document of protocol-06 §5.1. Each field is a URL template
/// whose `{...}` placeholder the client fills in.
///
/// Field names mirror the spec's JSON keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub key_material: String,
    pub update: String,
    pub notify: String,
    pub submit_message: String,
    pub group_info: String,
    pub request_consent: String,
    pub update_consent: String,
    pub identifier_query: String,
    pub report_abuse: String,
    pub proxy_download: String,
}

impl Directory {
    /// Builds the directory for a server reachable at `base`, using the path
    /// layout of the §5.1 example, including its `/v1` prefix (decision
    /// mimid-1wgh.5.37). Placeholders are served as literal `{name}` text
    /// (decision mimid-1wgh.5.38). The example's `update{roomId}` lacks a
    /// slash; it is read as `update/{roomId}` (decision mimid-1wgh.5.17).
    /// The consent placeholders name domains, as in §5.7, not users as in the
    /// §5.1 example (decision mimid-1wgh.5.16).
    pub fn new(base: &BaseUrl) -> Self {
        let url = |path: &str| format!("{base}/v1/{path}");
        Self {
            key_material: url("keyMaterial/{targetUser}"),
            update: url("update/{roomId}"),
            notify: url("notify/{roomId}"),
            submit_message: url("submitMessage/{roomId}"),
            group_info: url("groupInfo/{roomId}"),
            request_consent: url("requestConsent/{targetDomain}"),
            update_consent: url("updateConsent/{requesterDomain}"),
            identifier_query: url("identifierQuery/{domain}"),
            report_abuse: url("reportAbuse/{roomId}"),
            proxy_download: url("proxyDownload/{downloadUrl}"),
        }
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

    /// The protocol-06 §5.1 example, copied by hand from the draft text, with
    /// its two typos fixed per decision mimid-1wgh.5.17: `update{roomId}`
    /// becomes `update/{roomId}`, and the colon missing after
    /// `"proxyDownload"` is restored. The consent placeholders are the §5.7
    /// `{targetDomain}` and `{requesterDomain}`, not §5.1's user placeholders
    /// (decision mimid-1wgh.5.16).
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
         "https://mimi.example.com/v1/reportAbuse/{roomId}",
      "proxyDownload":
         "https://mimi.example.com/v1/proxyDownload/{downloadUrl}"
    }
    "#;

    async fn get(uri: &str) -> axum::response::Response {
        let base = BaseUrl::try_from("https://mimi.example.com".to_owned()).unwrap();
        router(Directory::new(&base))
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn serves_spec_example_directory() {
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
