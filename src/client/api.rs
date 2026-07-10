//! Core REST API orchestration layer.
//!
//! Sits on top of [`crate::client::transport::HttpTransport`] and is
//! responsible for everything *above* the wire:
//!
//! - Injecting Arlo's full set of browser-mimicking headers, including
//!   the dual-token authorization scheme (Base64 for `ocapi-app`, raw
//!   for `myapi`/`hmsweb`).
//! - Firing the OPTIONS preflight that real Single-Page-Apps emit
//!   ahead of any state-mutating cross-origin request.
//! - Serializing JSON request bodies and surfacing non-2xx responses
//!   as [`ArloError::HttpError`].
//! - Redacting secrets from `debug_mode` body dumps before they reach
//!   the tracing layer.
//!
//! The transport itself only sees a fully-formed [`HttpRequest`] and
//! returns the byte body — auth, retries, and envelope handling all
//! live here.

use crate::client::ArloClient;
use crate::client::transport::{HttpRequest, HttpResponse};
use crate::error::ArloError;
use crate::headers::*;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;
use tracing::{debug, instrument, warn};

/// JSON keys whose values must never reach the debug log when `debug_mode`
/// is enabled. Matched case-insensitively.
const REDACTED_JSON_KEYS: &[&str] = &[
    "password",
    "token",
    "access_token",
    "accesstoken",
    "authorization",
    "otp",
    "factorauthcode",
    "refreshtoken",
];

/// Returns a debug-safe rendering of `raw`. If `raw` is valid JSON, sensitive
/// keys are replaced with `"***"`. Otherwise the raw string is returned
/// unchanged (the keys we redact only ever appear inside JSON bodies).
fn redact_for_log(raw: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(raw) else {
        return raw.to_string();
    };
    redact_in_place(&mut value);
    serde_json::to_string(&value).unwrap_or_else(|_| raw.to_string())
}

fn redact_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if REDACTED_JSON_KEYS
                    .iter()
                    .any(|target| k.eq_ignore_ascii_case(target))
                {
                    *v = Value::String("***".to_string());
                } else {
                    redact_in_place(v);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_in_place(v);
            }
        }
        _ => {}
    }
}

impl ArloClient {
    /// Builds the standard set of Arlo Single-Page-Application headers
    /// for the given URL.
    ///
    /// Handles the dual-token architecture:
    /// - URLs starting with the auth host (`ocapi-app.arlo.com`) get a
    ///   Base64-encoded token in `Authorization`.
    /// - Other URLs (the `myapi.arlo.com` / `hmsweb` family) get the
    ///   raw token.
    pub(crate) fn build_headers(&self, url: &str) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = vec![
            ("Accept".into(), "application/json, text/plain, */*".into()),
            (
                "Accept-Language".into(),
                "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7".into(),
            ),
            ("Origin".into(), ARLO_ORIGIN.into()),
            ("Referer".into(), ARLO_REFERER.into()),
            ("DNT".into(), "1".into()),
            ("Pragma".into(), "no-cache".into()),
            ("Cache-Control".into(), "no-cache".into()),
            ("Source".into(), HEADER_SOURCE.into()),
            ("auth-version".into(), HEADER_AUTH_VERSION.into()),
            ("x-service-version".into(), HEADER_SERVICE_VERSION.into()),
            ("x-user-device-type".into(), HEADER_USER_DEVICE_TYPE.into()),
            ("x-user-device-id".into(), self.auth.device_id.clone()),
            (
                "x-user-device-automation-name".into(),
                HEADER_USER_DEVICE_AUTOMATION_NAME.into(),
            ),
        ];

        if let Some(token) = self.auth.token() {
            let value = if url.starts_with(self.endpoints.auth_host.as_str()) {
                // ocapi-app expects Base64-encoded tokens.
                BASE64_STANDARD.encode(token.as_bytes())
            } else {
                // hmsweb/myapi expects raw tokens.
                token.to_string()
            };
            headers.push(("Authorization".into(), value));
        }

        headers
    }

    /// Executes the OPTIONS preflight that real browsers emit before
    /// state-mutating CORS requests. Failures are logged at WARN but
    /// do not abort the subsequent main request — Arlo's WAF tolerates
    /// occasional preflight blips.
    #[instrument(skip(self))]
    async fn perform_options_preflight(&self, method: &Method, url: &str) -> Result<(), ArloError> {
        let mut headers = self.build_headers(url);
        headers.push((
            "Access-Control-Request-Method".into(),
            method.as_str().to_string(),
        ));
        headers.push((
            "Access-Control-Request-Headers".into(),
            "auth-version,content-type,source,x-service-version,x-user-device-automation-name,x-user-device-id,x-user-device-type"
                .into(),
        ));

        let response = self
            .transport
            .request(HttpRequest {
                method: Method::OPTIONS,
                url: url.to_string(),
                headers,
                body: None,
            })
            .await?;

        if !response.status.is_success() {
            warn!(
                url = %url,
                status = %response.status,
                "OPTIONS preflight returned non-200 status",
            );
        }
        Ok(())
    }

    /// Primary engine to execute requests simulating the Web Dashboard.
    /// It automatically fires the OPTIONS preflight if necessary (e.g., POST/PUT).
    /// Returns the raw response body text on 2xx.
    #[instrument(skip(self, payload), fields(method = %method, url = %url))]
    pub async fn execute_request<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        payload: Option<&T>,
    ) -> Result<String, ArloError> {
        self.execute_request_with_headers(method, url, payload, &[])
            .await
    }

    /// Like [`Self::execute_request`] but appends `extra_headers` to the
    /// standard browser header set on the **main** request (the OPTIONS
    /// preflight is unaffected — Arlo's WAF tolerates a preflight that
    /// doesn't enumerate every actual header). Used by the stream
    /// endpoints, which require an `xcloudId` header derived from the
    /// target [`crate::models::api::Device`].
    #[instrument(skip(self, payload, extra_headers), fields(method = %method, url = %url))]
    pub(crate) async fn execute_request_with_headers<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        payload: Option<&T>,
        extra_headers: &[(String, String)],
    ) -> Result<String, ArloError> {
        // 1. Browser-style CORS preflight for state-mutating requests.
        if matches!(method, Method::POST | Method::PUT | Method::DELETE) {
            self.perform_options_preflight(&method, url).await?;
        }

        // 2. Build headers + body for the actual request.
        let mut headers = self.build_headers(url);
        headers.extend_from_slice(extra_headers);
        let body = if let Some(data) = payload {
            let bytes = serde_json::to_vec(data)?;
            headers.push(("Content-Type".into(), "application/json".into()));
            Some(bytes)
        } else {
            None
        };

        if self.debug_mode {
            let dump = body
                .as_ref()
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(redact_for_log)
                .unwrap_or_default();
            debug!(
                method = %method,
                url = %url,
                payload = %dump,
                "--> Request"
            );
        }

        // 3. Dispatch through the transport.
        let HttpResponse { status, body } = self
            .transport
            .request(HttpRequest {
                method: method.clone(),
                url: url.to_string(),
                headers,
                body,
            })
            .await?;

        if self.debug_mode {
            debug!(
                status = %status,
                body = %redact_for_log(&body),
                "<-- Response"
            );
        }

        if !status.is_success() {
            return Err(ArloError::HttpError { status, body });
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::endpoints::ArloEndpoints;
    use crate::client::transport::test_support::MockTransport;
    use mockito::Server;
    use std::sync::Arc;

    fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn redact_replaces_sensitive_top_level_keys() {
        let input = r#"{"token":"abc","userId":"u1","password":"p"}"#;
        let redacted = redact_for_log(input);
        let parsed: Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(parsed["token"], Value::String("***".into()));
        assert_eq!(parsed["password"], Value::String("***".into()));
        assert_eq!(parsed["userId"], Value::String("u1".into()));
    }

    #[test]
    fn redact_replaces_sensitive_nested_keys() {
        let input = r#"{"meta":{"code":200},"data":{"token":"secret","accessToken":"x","authenticated":1}}"#;
        let redacted = redact_for_log(input);
        let parsed: Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(parsed["data"]["token"], Value::String("***".into()));
        assert_eq!(parsed["data"]["accessToken"], Value::String("***".into()));
        assert_eq!(parsed["data"]["authenticated"], 1);
    }

    #[test]
    fn redact_is_case_insensitive() {
        let input = r#"{"OTP":"123456","FactorAuthCode":"FAC"}"#;
        let redacted = redact_for_log(input);
        let parsed: Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(parsed["OTP"], Value::String("***".into()));
        assert_eq!(parsed["FactorAuthCode"], Value::String("***".into()));
    }

    #[test]
    fn redact_passes_through_non_json() {
        let raw = "Unauthorized";
        assert_eq!(redact_for_log(raw), raw);
    }

    fn test_client(transport: Arc<MockTransport>, endpoints: ArloEndpoints) -> ArloClient {
        ArloClient::with_transport(transport, endpoints)
    }

    #[tokio::test]
    async fn build_headers_uses_base64_token_for_auth_host() {
        let mut client = test_client(Arc::new(MockTransport::new()), ArloEndpoints::default());
        client.auth.set_token("dummy_token".to_string());
        client.auth.device_id = "test_device".to_string();

        let auth_url = format!("{}/api/test", client.endpoints.auth_host);
        let headers = client.build_headers(&auth_url);
        assert_eq!(
            header_value(&headers, "Authorization"),
            Some(BASE64_STANDARD.encode("dummy_token".as_bytes()).as_str())
        );
        assert_eq!(
            header_value(&headers, "x-user-device-id"),
            Some("test_device")
        );
    }

    #[tokio::test]
    async fn build_headers_uses_raw_token_for_api_host() {
        let mut client = test_client(Arc::new(MockTransport::new()), ArloEndpoints::default());
        client.auth.set_token("dummy_token".to_string());

        let api_url = format!("{}/hmsweb/test", client.endpoints.api_host);
        let headers = client.build_headers(&api_url);
        assert_eq!(header_value(&headers, "Authorization"), Some("dummy_token"));
    }

    #[tokio::test]
    async fn build_headers_omits_authorization_when_unauthenticated() {
        let client = test_client(Arc::new(MockTransport::new()), ArloEndpoints::default());
        let headers = client.build_headers("https://example.test/api");
        assert!(header_value(&headers, "Authorization").is_none());
    }

    #[tokio::test]
    async fn execute_request_fires_options_preflight_for_post() {
        let mock = Arc::new(MockTransport::new());
        // FIFO queue: OPTIONS preflight response first, then POST body.
        mock.queue_post(r#"{"success":true}"#);

        let client = test_client(Arc::clone(&mock), ArloEndpoints::default());
        let payload = serde_json::json!({"key": "value"});
        let body = client
            .execute_request(Method::POST, "https://example.test/api", Some(&payload))
            .await
            .unwrap();
        assert_eq!(body, r#"{"success":true}"#);

        let calls = mock.calls();
        assert_eq!(calls.len(), 2, "expected OPTIONS preflight then POST");
        assert_eq!(calls[0].method, Method::OPTIONS);
        assert_eq!(calls[1].method, Method::POST);
        assert_eq!(
            header_value(&calls[1].headers, "Content-Type"),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn execute_request_with_headers_appends_extra_headers_to_main_request_only() {
        // The PR-7 seam used by the stream endpoints (xcloudId header).
        // Extra headers land on the main POST, not the OPTIONS preflight.
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(r#"{"ok":true}"#);

        let client = test_client(Arc::clone(&mock), ArloEndpoints::default());
        let payload = serde_json::json!({"k": "v"});
        let extra = vec![("xcloudId".to_string(), "z1-cloud".to_string())];
        client
            .execute_request_with_headers(
                Method::POST,
                "https://example.test/api",
                Some(&payload),
                &extra,
            )
            .await
            .unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 2, "OPTIONS preflight + POST");
        // Preflight (calls[0]) must NOT carry the extra header.
        assert_eq!(header_value(&calls[0].headers, "xcloudId"), None);
        assert_eq!(calls[0].method, Method::OPTIONS);
        // Main POST (calls[1]) carries both the extra header and the
        // auto-added Content-Type.
        assert_eq!(
            header_value(&calls[1].headers, "xcloudId"),
            Some("z1-cloud")
        );
        assert_eq!(
            header_value(&calls[1].headers, "Content-Type"),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn execute_request_with_headers_no_body_omits_content_type() {
        let mock = Arc::new(MockTransport::new());
        mock.expect_ok("{}");
        let client = test_client(Arc::clone(&mock), ArloEndpoints::default());
        client
            .execute_request_with_headers::<()>(
                Method::GET,
                "https://example.test/api",
                None,
                &[("X-Probe".into(), "1".into())],
            )
            .await
            .unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 1, "GET → no preflight");
        assert_eq!(header_value(&calls[0].headers, "X-Probe"), Some("1"));
        assert_eq!(header_value(&calls[0].headers, "Content-Type"), None);
    }

    #[tokio::test]
    async fn execute_request_skips_preflight_for_get() {
        let mock = Arc::new(MockTransport::new());
        mock.expect_ok(r#"{}"#);

        let client = test_client(Arc::clone(&mock), ArloEndpoints::default());
        client
            .execute_request::<()>(Method::GET, "https://example.test/api", None)
            .await
            .unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, Method::GET);
    }

    #[tokio::test]
    async fn execute_request_returns_http_error_on_non_success() {
        let mock = Arc::new(MockTransport::new());
        mock.expect(HttpResponse {
            status: reqwest::StatusCode::UNAUTHORIZED,
            body: "Unauthorized".into(),
        });

        let client = test_client(Arc::clone(&mock), ArloEndpoints::default());
        let err = client
            .execute_request::<()>(Method::GET, "https://example.test/error", None)
            .await
            .unwrap_err();
        match err {
            ArloError::HttpError { status, body } => {
                assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
                assert_eq!(body, "Unauthorized");
            }
            other => panic!("expected HttpError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redact_handles_arrays_recursively() {
        let input = r#"[{"token":"x"},{"nested":{"password":"y"}},{"keep":1}]"#;
        let redacted = redact_for_log(input);
        let parsed: Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(parsed[0]["token"], Value::String("***".into()));
        assert_eq!(parsed[1]["nested"]["password"], Value::String("***".into()));
        assert_eq!(parsed[2]["keep"], 1);
    }

    #[tokio::test]
    async fn redact_for_log_leaves_non_sensitive_payload_untouched() {
        let input = r#"{"resource":"cameras/C1","action":"set","properties":{"flip":true}}"#;
        let redacted = redact_for_log(input);
        // Round-trips byte-equivalent JSON when nothing matches.
        let a: Value = serde_json::from_str(input).unwrap();
        let b: Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn execute_request_emits_debug_logs_when_debug_mode_on() {
        // Just exercises the `self.debug_mode` branch of execute_request
        // — we don't capture log output here; the redactor itself is
        // covered by its own tests.
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(r#"{"data":"ok"}"#);
        let mut client = test_client(Arc::clone(&mock), ArloEndpoints::default());
        client.debug_mode = true;
        client
            .execute_request(
                Method::POST,
                "https://example.test/api",
                Some(&serde_json::json!({"token":"redact-me"})),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn execute_request_skips_body_when_payload_is_none() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_get(r#"{"ok":true}"#);
        let client = test_client(Arc::clone(&mock), ArloEndpoints::default());
        client
            .execute_request::<()>(Method::GET, "https://example.test/api", None)
            .await
            .unwrap();
        let calls = mock.calls();
        assert!(calls[0].body.is_none());
        assert!(header_value(&calls[0].headers, "Content-Type").is_none());
    }

    #[tokio::test]
    async fn perform_options_preflight_logs_warning_on_non_2xx_but_does_not_fail() {
        // The preflight is best-effort: a 4xx surfaces via tracing but
        // the subsequent main request still fires and succeeds.
        let mock = Arc::new(MockTransport::new());
        // OPTIONS preflight returns 403 (status arrives via expect, not queue_post).
        mock.expect(HttpResponse {
            status: reqwest::StatusCode::FORBIDDEN,
            body: "".into(),
        });
        // Main POST returns 200.
        mock.expect_ok(r#"{"ok":1}"#);

        let client = test_client(Arc::clone(&mock), ArloEndpoints::default());
        let res = client
            .execute_request(
                Method::POST,
                "https://example.test/api",
                Some(&serde_json::json!({"k":"v"})),
            )
            .await;
        assert!(res.is_ok(), "preflight failure must not abort the call");
    }

    #[tokio::test]
    async fn execute_request_works_against_real_reqwest_via_mockito() {
        // Bonus integration-style check: a real `reqwest::Client` driven
        // through the `HttpTransport` trait against a mockito server.
        // Proves the orchestration layer (build_headers + preflight +
        // body serialization) is wire-compatible without booting
        // CloudScraper.
        let mut server = Server::new_async().await;
        let _m_options = server
            .mock("OPTIONS", "/hmsweb/echo")
            .with_status(200)
            .create_async()
            .await;
        let _m_post = server
            .mock("POST", "/hmsweb/echo")
            .with_status(200)
            .with_body(r#"{"echoed":true}"#)
            .create_async()
            .await;

        #[derive(Debug)]
        struct ReqwestTransport(reqwest::Client);
        #[async_trait::async_trait]
        impl crate::client::transport::HttpTransport for ReqwestTransport {
            async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ArloError> {
                let mut b = self.0.request(request.method, &request.url);
                for (k, v) in request.headers {
                    b = b.header(k, v);
                }
                if let Some(body) = request.body {
                    b = b.body(body);
                }
                let resp = b.send().await?;
                let status = resp.status();
                let body = resp.text().await?;
                Ok(HttpResponse { status, body })
            }
        }

        let endpoints = ArloEndpoints::testing(server.url());
        let client = ArloClient::with_transport(
            Arc::new(ReqwestTransport(reqwest::Client::new())),
            endpoints.clone(),
        );

        let url = format!("{}/hmsweb/echo", endpoints.api_host);
        let body = client
            .execute_request(Method::POST, &url, Some(&serde_json::json!({"k":"v"})))
            .await
            .unwrap();
        assert_eq!(body, r#"{"echoed":true}"#);
    }
}
