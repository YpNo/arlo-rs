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
use crate::models::redact::redact_for_log;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use reqwest::Method;
use serde::Serialize;
use tracing::{debug, instrument, warn};

/// `Accept-Language` the web dashboard sends on every request.
const ACCEPT_LANGUAGE: &str = "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7";

/// The custom headers a real preflight asks permission for.
const PREFLIGHT_REQUEST_HEADERS: &str = "auth-version,content-type,source,x-service-version,x-user-device-automation-name,x-user-device-id,x-user-device-type";

/// True when `url` and `base` share scheme, host and port. A prefix
/// comparison would accept `https://ocapi-app.arlo.com.evil.tld/`.
fn same_origin(url: &str, base: &str) -> bool {
    match (url::Url::parse(url), url::Url::parse(base)) {
        (Ok(u), Ok(b)) => u.origin().is_tuple() && u.origin() == b.origin(),
        _ => false,
    }
}

/// Milliseconds since the Unix epoch, as Arlo's `time=` / `timestamp`
/// telemetry parameters expect. Saturates at 0 should the clock be
/// before 1970.
pub(crate) fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

impl ArloClient {
    /// Builds the standard set of Arlo Single-Page-Application headers
    /// for the given URL.
    ///
    /// Handles the dual-token architecture:
    /// - URLs on the auth host origin (`ocapi-app.arlo.com`) get a
    ///   Base64-encoded token in `Authorization`.
    /// - URLs on the API host origin (`myapi.arlo.com` / `hmsweb`) get
    ///   the raw token.
    /// - Any other origin gets no `Authorization` at all: the session
    ///   token never leaves the two Arlo hosts.
    pub(crate) fn build_headers(&self, url: &str) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = vec![
            ("Accept".into(), "application/json, text/plain, */*".into()),
            ("Accept-Language".into(), ACCEPT_LANGUAGE.into()),
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
            if same_origin(url, &self.endpoints.auth_host) {
                // ocapi-app expects Base64-encoded tokens.
                headers.push((
                    "Authorization".into(),
                    BASE64_STANDARD.encode(token.as_bytes()),
                ));
            } else if same_origin(url, &self.endpoints.api_host) {
                // hmsweb/myapi expects raw tokens.
                headers.push(("Authorization".into(), token.to_string()));
            } else {
                warn!(
                    url = %crate::models::redact::redact_userinfo(url),
                    "no Authorization header: URL is not on the Arlo auth or API host"
                );
            }
        }

        headers
    }

    /// The header set of a CORS preflight as Chrome emits it: no
    /// credentials, no custom headers (those are what the preflight asks
    /// permission for), just the request metadata.
    fn build_preflight_headers(method: &Method) -> Vec<(String, String)> {
        vec![
            ("Accept".into(), "*/*".into()),
            ("Accept-Language".into(), ACCEPT_LANGUAGE.into()),
            ("Origin".into(), ARLO_ORIGIN.into()),
            ("Referer".into(), ARLO_REFERER.into()),
            ("DNT".into(), "1".into()),
            (
                "Access-Control-Request-Method".into(),
                method.as_str().to_string(),
            ),
            (
                "Access-Control-Request-Headers".into(),
                PREFLIGHT_REQUEST_HEADERS.into(),
            ),
        ]
    }

    /// Executes the OPTIONS preflight that real browsers emit before
    /// state-mutating CORS requests. Failures are logged at WARN but
    /// do not abort the subsequent main request — Arlo's WAF tolerates
    /// occasional preflight blips.
    #[instrument(skip(self))]
    async fn perform_options_preflight(&self, method: &Method, url: &str) -> Result<(), ArloError> {
        let headers = Self::build_preflight_headers(method);

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

        // 3. Dispatch through the transport, retrying Cloudflare rate
        //    limiting (429 / error 1015) the way the web client's users do:
        //    a short pause, a few attempts.
        let HttpResponse { status, body } = self
            .send_with_rate_limit_retry(HttpRequest {
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

    /// Sends `request`, re-sending it after [`RATE_LIMIT_BACKOFF`] when
    /// the response is a rate limit ([`is_rate_limited`]), at most
    /// [`RATE_LIMIT_ATTEMPTS`] times. Any other response (including other
    /// errors) is returned as-is on the first attempt.
    async fn send_with_rate_limit_retry(
        &self,
        request: HttpRequest,
    ) -> Result<HttpResponse, ArloError> {
        let mut attempt = 1;
        loop {
            let response = self.transport.request(request.clone()).await?;
            if !is_rate_limited(&response) || attempt >= RATE_LIMIT_ATTEMPTS {
                return Ok(response);
            }
            warn!(
                url = %request.url,
                status = %response.status,
                attempt,
                backoff_secs = RATE_LIMIT_BACKOFF.as_secs(),
                "Rate limited by Arlo/Cloudflare; retrying"
            );
            tokio::time::sleep(RATE_LIMIT_BACKOFF).await;
            attempt += 1;
        }
    }
}

/// Maximum number of attempts for a rate-limited request (the first send
/// plus retries). Mirrors the reference Python client's `3 × 3 s` loop.
const RATE_LIMIT_ATTEMPTS: u32 = 3;
/// Pause between rate-limited attempts.
const RATE_LIMIT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(3);
/// Cloudflare's rate-limit error code, embedded in the HTML body it
/// serves (sometimes with an HTTP 403 rather than 429).
const CLOUDFLARE_RATE_LIMIT_CODE: &str = "error code: 1015";

/// True for HTTP 429, or for any response whose body carries Cloudflare's
/// `error code: 1015` rate-limit marker.
fn is_rate_limited(response: &HttpResponse) -> bool {
    response.status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || response.body.contains(CLOUDFLARE_RATE_LIMIT_CODE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::endpoints::ArloEndpoints;
    use crate::client::test_helpers::mocked_client;
    use crate::client::transport::test_support::MockTransport;
    use mockito::Server;
    use reqwest::StatusCode;
    use serde_json::Value;
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
    async fn preflight_carries_no_credentials_or_custom_headers() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(r#"{"success":true}"#);
        let mut client = test_client(Arc::clone(&mock), ArloEndpoints::default());
        client.auth.set_token("dummy_token".to_string());

        let url = format!("{}/hmsweb/users/devices", client.endpoints.api_host);
        client
            .execute_request(Method::PUT, &url, Some(&serde_json::json!({})))
            .await
            .unwrap();

        let calls = mock.calls();
        let preflight = &calls[0].headers;
        assert_eq!(calls[0].method, Method::OPTIONS);
        for absent in [
            "Authorization",
            "x-user-device-id",
            "auth-version",
            "Source",
        ] {
            assert!(
                header_value(preflight, absent).is_none(),
                "preflight must not carry {absent}"
            );
        }
        assert_eq!(
            header_value(preflight, "Access-Control-Request-Method"),
            Some("PUT")
        );
        assert_eq!(header_value(preflight, "Origin"), Some(ARLO_ORIGIN));
        // The main request still authenticates.
        assert_eq!(
            header_value(&calls[1].headers, "Authorization"),
            Some("dummy_token")
        );
    }

    #[tokio::test]
    async fn build_headers_omits_authorization_off_the_arlo_origins() {
        let mut client = test_client(Arc::new(MockTransport::new()), ArloEndpoints::default());
        client.auth.set_token("dummy_token".to_string());

        for url in [
            "https://ocapi-app.arlo.com.evil.tld/api/auth",
            "http://ocapi-app.arlo.com/api/auth",
            "https://ocapi-app.arlo.com:8443/api/auth",
            "https://myapi.arlo.com.evil.tld/hmsweb/x",
            "https://example.test/",
            "not a url",
        ] {
            let headers = client.build_headers(url);
            assert!(
                header_value(&headers, "Authorization").is_none(),
                "token attached to {url}"
            );
        }
        // Same origin, any path.
        let headers = client.build_headers("https://myapi.arlo.com/hmsweb/x?y=1");
        assert_eq!(header_value(&headers, "Authorization"), Some("dummy_token"));
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

    #[test]
    fn now_millis_is_a_plausible_epoch_timestamp() {
        let ms = now_millis();
        // 2020-01-01 .. 2100-01-01
        assert!((1_577_836_800_000..4_102_444_800_000).contains(&ms), "{ms}");
    }

    #[tokio::test(start_paused = true)]
    async fn execute_request_retries_after_rate_limit_then_succeeds() {
        // Paused clock: the 3 s backoff auto-advances, so this runs instantly.
        let mock = Arc::new(MockTransport::new());
        mock.expect(HttpResponse {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: "slow down".into(),
        });
        mock.expect_ok(r#"{"ok":true}"#);
        let client = mocked_client(Arc::clone(&mock));

        let body = client
            .execute_request::<()>(Method::GET, "https://test.example/hmsweb/x", None)
            .await
            .unwrap();
        assert_eq!(body, r#"{"ok":true}"#);
        assert_eq!(mock.calls().len(), 2, "one retry after the 429");
    }

    #[tokio::test(start_paused = true)]
    async fn execute_request_retries_on_cloudflare_1015_body() {
        let mock = Arc::new(MockTransport::new());
        mock.expect(HttpResponse {
            status: StatusCode::FORBIDDEN,
            body: "<html>error code: 1015</html>".into(),
        });
        mock.expect_ok("fine");
        let client = mocked_client(Arc::clone(&mock));

        let body = client
            .execute_request::<()>(Method::GET, "https://test.example/hmsweb/x", None)
            .await
            .unwrap();
        assert_eq!(body, "fine");
        assert_eq!(mock.calls().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn execute_request_gives_up_after_rate_limit_attempts() {
        let mock = Arc::new(MockTransport::new());
        for _ in 0..RATE_LIMIT_ATTEMPTS {
            mock.expect(HttpResponse {
                status: StatusCode::TOO_MANY_REQUESTS,
                body: "".into(),
            });
        }
        let client = mocked_client(Arc::clone(&mock));

        let err = client
            .execute_request::<()>(Method::GET, "https://test.example/hmsweb/x", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ArloError::HttpError { status, .. } if status == StatusCode::TOO_MANY_REQUESTS),
            "{err:?}"
        );
        assert_eq!(mock.calls().len() as u32, RATE_LIMIT_ATTEMPTS);
        assert!(mock.responses_drained());
    }

    #[tokio::test]
    async fn execute_request_does_not_retry_other_failures() {
        let mock = Arc::new(MockTransport::new());
        mock.expect(HttpResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "boom".into(),
        });
        let client = mocked_client(Arc::clone(&mock));

        let err = client
            .execute_request::<()>(Method::GET, "https://test.example/hmsweb/x", None)
            .await
            .unwrap_err();
        assert!(matches!(err, ArloError::HttpError { .. }));
        assert_eq!(mock.calls().len(), 1);
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
