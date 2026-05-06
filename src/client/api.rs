//! Core REST API transport layer.
//!
//! This module houses the primary HTTP request execution engine for `ArloClient`.
//! It is strictly responsible for dynamically injecting browser-accurate headers,
//! managing token Base64 encoding schemes required by the modern `ocapi-app.arlo.com` endpoints,
//! and orchestrating HTTP OPTIONS CORS preflight requests to mimic authentic browser behavior
//! and evade Cloudflare's WAF.
use crate::client::ArloClient;
use crate::error::ArloError;
use crate::headers::*;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use reqwest::{Method, RequestBuilder};
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
    /// Injects standard Arlo Single Page Application (SPA) headers into a `RequestBuilder`.
    ///
    /// This seamlessly handles the dual-token architecture of the Arlo API:
    /// - Requests routed to the newer `ocapi-app` (MFA/Auth) receive a Base64 encoded token.
    /// - Requests routed to the legacy `hmsweb` (Devices/Modes) receive the raw telemetry token.
    fn inject_headers(&self, mut builder: RequestBuilder, url: &str) -> RequestBuilder {
        builder = builder
            .header("Accept", "application/json, text/plain, */*")
            .header("Accept-Language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7")
            .header("Origin", ARLO_ORIGIN)
            .header("Referer", ARLO_REFERER)
            .header("DNT", "1")
            .header("Pragma", "no-cache")
            .header("Cache-Control", "no-cache")
            .header("Source", HEADER_SOURCE)
            .header("auth-version", HEADER_AUTH_VERSION)
            .header("x-service-version", HEADER_SERVICE_VERSION)
            .header("x-user-device-type", HEADER_USER_DEVICE_TYPE)
            .header("x-user-device-id", self.auth.device_id.clone())
            .header(
                "x-user-device-automation-name",
                HEADER_USER_DEVICE_AUTOMATION_NAME,
            );

        // Inject authorization token if we have one
        if let Some(token) = self.auth.token() {
            if url.starts_with(ARLO_AUTH_HOST) {
                // Endpoints targeting `ocapi-app.arlo.com` (MFA, validating tokens) require Base64 encoding.
                let b64_token = BASE64_STANDARD.encode(token.as_bytes());
                builder = builder.header("Authorization", b64_token);
            } else {
                // Secondary validation via `hmsweb` endpoints (API_HOST) expects raw tokens.
                builder = builder.header("Authorization", token);
            }
        }

        builder
    }

    /// Executes an OPTIONS preflight request.
    /// To perfectly emulate a human browser, modern Single Page Applications fire an OPTIONS
    /// preflight before making a CORS POST/PUT/DELETE request.
    #[instrument(skip(self))]
    async fn perform_options_preflight(&self, method: &Method, url: &str) -> Result<(), ArloError> {
        let mut builder = self.reqwest_client.request(Method::OPTIONS, url)
            .header("Access-Control-Request-Method", method.as_str())
            .header("Access-Control-Request-Headers", "auth-version,content-type,source,x-service-version,x-user-device-automation-name,x-user-device-id,x-user-device-type");

        builder = self.inject_headers(builder, url);

        let response = builder.send().await?;
        if !response.status().is_success() {
            warn!(
                "OPTIONS preflight to {} returned non-200 status: {}",
                url,
                response.status()
            );
        }

        Ok(())
    }

    /// Primary engine to execute requests simulating the Web Dashboard.
    /// It automatically fires the OPTIONS preflight if necessary (e.g., POST/PUT).
    /// Returns the raw Response body text.
    #[instrument(skip(self, payload), fields(method = %method, url = %url))]
    pub async fn execute_request<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        payload: Option<&T>,
    ) -> Result<String, ArloError> {
        // 1. Simulate the browser's CORS OPTIONS pre-flight for state-mutating requests
        if method == Method::POST || method == Method::PUT || method == Method::DELETE {
            self.perform_options_preflight(&method, url).await?;
        }

        // 2. Build the actual request
        let mut builder = self.reqwest_client.request(method.clone(), url);
        builder = self.inject_headers(builder, url);

        let mut dump_pay = String::new();
        // 3. Attach payload if it's a POST/PUT
        if let Some(data) = payload {
            builder = builder.json(data);
            if self.debug_mode
                && let Ok(json) = serde_json::to_string(data)
            {
                dump_pay = redact_for_log(&json);
            }
        }

        if self.debug_mode {
            debug!(
                method = %method,
                url = %url,
                payload = %dump_pay,
                "--> Request"
            );
        }

        // 4. Send and consume body
        let response = builder.send().await?;
        let status = response.status();

        let body_str = response.text().await?;

        if self.debug_mode {
            debug!(
                status = %status,
                body = %redact_for_log(&body_str),
                "<-- Response"
            );
        }

        if !status.is_success() {
            return Err(ArloError::HttpError {
                status,
                body: body_str,
            });
        }

        Ok(body_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use reqwest::Method;

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

    #[tokio::test]
    async fn test_inject_headers_auth_encoding() {
        let mut client = ArloClient::new().await.unwrap();
        client.auth.set_token("dummy_token".to_string());
        client.auth.device_id = "test_device".to_string();

        let req_builder = client
            .reqwest_client
            .request(Method::GET, "https://example.com");

        // Test ocapi-app encoding (Base64)
        let auth_url = format!("{}/api/test", ARLO_AUTH_HOST);
        let builder = client.inject_headers(req_builder, &auth_url);
        let request = builder.build().unwrap();

        let auth_header = request
            .headers()
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            auth_header,
            BASE64_STANDARD.encode("dummy_token".as_bytes())
        );
        assert_eq!(
            request
                .headers()
                .get("x-user-device-id")
                .unwrap()
                .to_str()
                .unwrap(),
            "test_device"
        );
    }

    #[tokio::test]
    async fn test_inject_headers_api_raw() {
        let mut client = ArloClient::new().await.unwrap();
        client.auth.set_token("dummy_token".to_string());

        let req_builder = client
            .reqwest_client
            .request(Method::GET, "https://example.com");

        // Test myapi-app raw token
        let api_url = format!("{}/hmsweb/test", ARLO_API_HOST);
        let builder = client.inject_headers(req_builder, &api_url);
        let request = builder.build().unwrap();

        let auth_header = request
            .headers()
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(auth_header, "dummy_token");
    }

    #[tokio::test]
    async fn test_execute_request_with_preflight() {
        let mut server = Server::new_async().await;
        let mut client = ArloClient::new().await.unwrap();

        // Point reqwest to the mock server
        client.reqwest_client = reqwest::Client::builder().build().unwrap();

        let url = format!("{}/test", server.url());

        // Mock OPTIONS preflight
        let _m_options = server
            .mock("OPTIONS", "/test")
            .with_status(200)
            .create_async()
            .await;

        // Mock POST request
        let _m_post = server
            .mock("POST", "/test")
            .match_header("Content-Type", "application/json")
            .with_status(200)
            .with_body("{\"success\": true}")
            .create_async()
            .await;

        let payload = serde_json::json!({"key": "value"});
        let result = client
            .execute_request(Method::POST, &url, Some(&payload))
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "{\"success\": true}");
    }

    #[tokio::test]
    async fn test_execute_request_http_error() {
        let mut server = Server::new_async().await;
        let client = ArloClient::new().await.unwrap();
        let url = format!("{}/error", server.url());

        let _m = server
            .mock("GET", "/error")
            .with_status(401)
            .with_body("Unauthorized")
            .create_async()
            .await;

        let result = client.execute_request::<()>(Method::GET, &url, None).await;

        match result {
            Err(ArloError::HttpError { status, body }) => {
                assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
                assert_eq!(body, "Unauthorized");
            }
            _ => panic!("Expected HttpError"),
        }
    }
}
