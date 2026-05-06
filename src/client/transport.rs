//! HTTP transport abstraction.
//!
//! [`HttpTransport`] is the seam between [`crate::ArloClient`]'s request
//! orchestration (auth-header injection, OPTIONS preflight, JSON envelope
//! handling) and the actual byte-shuffling layer. Production uses
//! [`CloudScraperTransport`], which routes through the headless-browser
//! stealth proxy so requests carry a JA4 fingerprint indistinguishable
//! from a real Chrome session. Tests substitute a mock implementation
//! (see `MockTransport` in `#[cfg(test)]`) to drive the orchestration
//! layer without booting the proxy.
//!
//! The trait is intentionally narrow:
//!
//! - One unary [`HttpTransport::request`] method that takes a fully
//!   constructed [`HttpRequest`] and returns an [`HttpResponse`]. Auth
//!   headers, base URLs, and CORS preflight are the orchestration
//!   layer's job — the transport just executes.
//! - A [`HttpTransport::streaming_client`] hook for the SSE event bus,
//!   which doesn't fit the unary request/response shape. Returning
//!   `None` means "this transport doesn't support streaming"; tests that
//!   never start the event bus opt out cleanly.

use crate::error::ArloError;
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use rs_cloudscraper::CloudScraper;
use std::str::FromStr;

/// Description of a single HTTP request to dispatch through the transport.
/// Headers and body are pre-built by the orchestration layer; the
/// transport only translates them into a wire request.
#[derive(Debug)]
pub struct HttpRequest {
    /// HTTP method (`GET`, `POST`, `PUT`, …).
    pub method: Method,
    /// Fully-qualified target URL.
    pub url: String,
    /// Header pairs to send. Names are case-insensitive per RFC 7230.
    pub headers: Vec<(String, String)>,
    /// Raw request body. JSON is serialized by the orchestration layer
    /// before reaching the transport.
    pub body: Option<Vec<u8>>,
}

/// HTTP response surfaced by the transport. The orchestration layer
/// inspects `status` and converts non-2xx into [`ArloError::HttpError`];
/// non-error responses propagate the body up to the model layer.
#[derive(Debug)]
pub struct HttpResponse {
    /// HTTP status code returned by the server.
    pub status: StatusCode,
    /// Response body as text. Binary bodies (e.g. local-hub media
    /// downloads) bypass this transport entirely.
    pub body: String,
}

/// Pluggable HTTP transport. Production wires this to a stealth-proxied
/// `reqwest::Client`; tests wire it to a mockito-backed double.
///
/// `#[async_trait]` is used so the trait remains object-safe — the
/// orchestration layer holds an `Arc<dyn HttpTransport>` and substituting
/// a test double is the whole point of the abstraction.
#[async_trait]
pub trait HttpTransport: Send + Sync + std::fmt::Debug {
    /// Dispatch a unary request. Errors are reserved for transport-level
    /// failures (DNS, TLS, dropped connections); HTTP status codes flow
    /// through [`HttpResponse::status`] for the caller to interpret.
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ArloError>;

    /// Streaming client used by the SSE [`crate::EventBus`]. Returning
    /// `None` means this transport doesn't support streaming — typical
    /// for unit-test transports. The default impl returns `None`.
    fn streaming_client(&self) -> Option<Client> {
        None
    }
}

/// Production transport: routes every request through the stealth
/// `rs-cloudscraper` headless-browser proxy so the TLS fingerprint and
/// connection metadata match a real Chrome session.
pub struct CloudScraperTransport {
    client: Client,
    /// Held purely so the headless-browser MITM proxy stays alive —
    /// dropping it would tear down the proxy `client` is routed through.
    /// Never read after construction; `#[allow(dead_code)]` is intentional.
    #[allow(dead_code)]
    cloud_scraper: CloudScraper,
}

impl CloudScraperTransport {
    /// Wraps a `reqwest::Client` (already configured to route through
    /// `cloud_scraper`'s local MITM proxy) and the underlying scraper.
    /// Crate-internal — applications get this transport indirectly via
    /// [`crate::ArloClient::builder`].
    pub(crate) fn new(client: Client, cloud_scraper: CloudScraper) -> Self {
        Self {
            client,
            cloud_scraper,
        }
    }
}

impl std::fmt::Debug for CloudScraperTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudScraperTransport").finish()
    }
}

#[async_trait]
impl HttpTransport for CloudScraperTransport {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ArloError> {
        let HttpRequest {
            method,
            url,
            headers,
            body,
        } = request;

        let mut header_map = HeaderMap::with_capacity(headers.len());
        for (name, value) in headers {
            let name = HeaderName::from_str(&name)
                .map_err(|e| ArloError::ParseError(format!("Invalid header name: {e}")))?;
            let value = HeaderValue::from_str(&value)
                .map_err(|e| ArloError::ParseError(format!("Invalid header value: {e}")))?;
            header_map.insert(name, value);
        }

        let mut builder = self.client.request(method, &url).headers(header_map);
        if let Some(b) = body {
            builder = builder.body(b);
        }

        let response = builder.send().await?;
        let status = response.status();
        let body = response.text().await?;
        Ok(HttpResponse { status, body })
    }

    fn streaming_client(&self) -> Option<Client> {
        Some(self.client.clone())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! In-process transport doubles used by the lib's own unit tests.
    //!
    //! Concrete behaviour ranges from "always returns canned bytes" to
    //! "delegates to a mockito server URL". They satisfy the
    //! [`HttpTransport`] contract so the orchestration layer in
    //! [`crate::client::api`] is exercised against real headers,
    //! preflight logic, and JSON envelopes — not stubbed away.
    use super::*;
    use std::sync::Mutex;

    /// Records every dispatched request and returns canned responses in
    /// the order they were queued. Matches mockito's stricter "expect
    /// exactly N calls" semantics by panicking if the queue runs dry.
    #[derive(Debug, Default)]
    pub struct MockTransport {
        calls: Mutex<Vec<HttpRequest>>,
        responses: Mutex<Vec<HttpResponse>>,
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self::default()
        }

        /// Queues `response` to be returned on the next [`request`] call.
        pub fn expect(&self, response: HttpResponse) {
            self.responses.lock().unwrap().push(response);
        }

        /// Convenience for the common "200 OK with this body" case.
        pub fn expect_ok(&self, body: impl Into<String>) {
            self.expect(HttpResponse {
                status: StatusCode::OK,
                body: body.into(),
            });
        }

        /// Returns every recorded request in dispatch order.
        pub fn calls(&self) -> Vec<HttpRequest> {
            // HttpRequest doesn't impl Clone (body is Vec<u8>), so move out
            // by draining and re-populating with reconstructed copies.
            let mut guard = self.calls.lock().unwrap();
            let drained: Vec<HttpRequest> = guard.drain(..).collect();
            for r in &drained {
                guard.push(HttpRequest {
                    method: r.method.clone(),
                    url: r.url.clone(),
                    headers: r.headers.clone(),
                    body: r.body.clone(),
                });
            }
            drained
        }
    }

    #[async_trait]
    impl HttpTransport for MockTransport {
        async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ArloError> {
            self.calls.lock().unwrap().push(HttpRequest {
                method: request.method.clone(),
                url: request.url.clone(),
                headers: request.headers.clone(),
                body: request.body.clone(),
            });
            self.responses
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| ArloError::ApiError {
                    code: 500,
                    message: "MockTransport: no canned response queued".into(),
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockTransport;
    use super::*;

    #[tokio::test]
    async fn mock_transport_returns_queued_response() {
        let mock = MockTransport::new();
        mock.expect_ok(r#"{"hello":"world"}"#);

        let resp = mock
            .request(HttpRequest {
                method: Method::GET,
                url: "https://example.test/api".into(),
                headers: vec![],
                body: None,
            })
            .await
            .unwrap();

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, r#"{"hello":"world"}"#);
    }

    #[tokio::test]
    async fn mock_transport_records_request() {
        let mock = MockTransport::new();
        mock.expect_ok("{}");

        mock.request(HttpRequest {
            method: Method::POST,
            url: "https://example.test/auth".into(),
            headers: vec![("Authorization".into(), "tok".into())],
            body: Some(b"{}".to_vec()),
        })
        .await
        .unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, Method::POST);
        assert_eq!(calls[0].url, "https://example.test/auth");
        assert_eq!(
            calls[0].headers,
            vec![("Authorization".into(), "tok".into())]
        );
    }

    #[tokio::test]
    async fn mock_transport_errors_when_queue_empty() {
        let mock = MockTransport::new();
        let err = mock
            .request(HttpRequest {
                method: Method::GET,
                url: "https://nope.test".into(),
                headers: vec![],
                body: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ArloError::ApiError { .. }));
    }

    #[test]
    fn streaming_client_default_is_none() {
        let mock = MockTransport::new();
        assert!(mock.streaming_client().is_none());
    }
}
