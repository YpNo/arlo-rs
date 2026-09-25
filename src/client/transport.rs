//! HTTP transport abstraction.
//!
//! [`HttpTransport`] is the seam between [`crate::ArloClient`]'s request
//! orchestration (auth-header injection, OPTIONS preflight, JSON envelope
//! handling) and the actual byte-shuffling layer. Two production
//! implementations exist:
//!
//! - [`WreqTransport`] (default): a `wreq` client carrying the Chrome TLS
//!   ClientHello and HTTP/2 fingerprint that `stealthscraper-rs` measured
//!   from a real browser, plus the matching `User-Agent` and
//!   `Sec-CH-UA*` client hints. Arlo's Cloudflare front fingerprints the
//!   TLS/HTTP layer only (no JS challenge), so this is all it takes and no
//!   browser process is involved.
//! - `CloudScraperTransport` (`browser` feature): routes a `reqwest`
//!   client through the `stealthscraper-rs` headless-Chrome MITM proxy.
//!   Kept as an escalation path should Cloudflare ever start serving an
//!   interactive challenge.
//!
//! Tests substitute a mock implementation (see `MockTransport` in
//! `#[cfg(test)]`) to drive the orchestration layer without any network.
//!
//! The trait is intentionally narrow: one unary [`HttpTransport::request`]
//! method that takes a fully constructed [`HttpRequest`] and returns an
//! [`HttpResponse`]. Auth headers, base URLs, and CORS preflight are the
//! orchestration layer's job — the transport just executes.

use crate::client::cookies::PersistentJar;
use crate::error::ArloError;
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use stealthscraper_rs::{BrowserProfile, ClientHints};

/// Description of a single HTTP request to dispatch through the transport.
/// Headers and body are pre-built by the orchestration layer; the
/// transport only translates them into a wire request.
#[derive(Debug, Clone)]
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

/// Pluggable HTTP transport. Production wires this to [`WreqTransport`];
/// tests wire it to a mockito-backed double.
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

    /// Serialised cookie jar, for persisting Arlo's "trusted browser"
    /// state across processes. `None` when the transport keeps no jar or
    /// the jar is empty. The blob is opaque to callers.
    fn export_cookies(&self) -> Option<String> {
        None
    }

    /// Restores a jar previously produced by [`Self::export_cookies`].
    /// Transports without a jar accept and ignore it.
    fn import_cookies(&self, _json: &str) -> Result<(), ArloError> {
        Ok(())
    }
}

/// Converts the orchestration layer's header pairs into a typed map.
fn to_header_map(headers: Vec<(String, String)>) -> Result<HeaderMap, ArloError> {
    let mut header_map = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let name = HeaderName::from_str(&name)
            .map_err(|e| ArloError::ParseError(format!("Invalid header name: {e}")))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|e| ArloError::ParseError(format!("Invalid header value: {e}")))?;
        header_map.insert(name, value);
    }
    Ok(header_map)
}

/// Per-request timeout for the default transport. Arlo's slowest normal
/// call (`devicesupport`, a few hundred KB) completes well inside this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default production transport: a `wreq` client impersonating the
/// Chrome release that `stealthscraper-rs` measured (TLS ClientHello,
/// HTTP/2 SETTINGS/priority/pseudo-header order) — the same emulation its
/// browser proxy egresses through — without any browser process.
///
/// Every request additionally carries the profile's `User-Agent` and the
/// matching `Sec-CH-UA`, `Sec-CH-UA-Mobile` and `Sec-CH-UA-Platform`
/// client hints unless the orchestration layer already set them, so the
/// advertised browser and the fingerprint on the wire never contradict.
/// Cookies live in a [`PersistentJar`] so Arlo's trusted-browser state
/// can be exported with the session cache and restored on the next run.
pub struct WreqTransport {
    client: wreq::Client,
    profile: BrowserProfile,
    hints: Option<ClientHints>,
    jar: Arc<PersistentJar>,
}

impl WreqTransport {
    /// Builds the client for `profile`, routed through `upstream_proxy`
    /// (HTTP or SOCKS URL) when given.
    ///
    /// # Errors
    ///
    /// [`ArloError::ScraperError`] if the proxy URL is invalid or the
    /// client cannot be built.
    pub fn new(profile: BrowserProfile, upstream_proxy: Option<&str>) -> Result<Self, ArloError> {
        let jar = Arc::new(PersistentJar::default());
        let mut builder = wreq::Client::builder()
            // Derive the fingerprint from the profile's own User-Agent so
            // the JA4 signature and the advertised browser agree.
            .emulation(stealthscraper_rs::emulation::for_kind(
                profile.browser_kind(),
            ))
            .cookie_provider(Arc::clone(&jar))
            .timeout(REQUEST_TIMEOUT);
        if let Some(url) = upstream_proxy {
            let proxy = wreq::Proxy::all(url)
                .map_err(|e| ArloError::ScraperError(format!("invalid upstream proxy: {e}")))?;
            builder = builder.proxy(proxy);
        }
        let client = builder
            .build()
            .map_err(|e| ArloError::ScraperError(format!("wreq client build failed: {e}")))?;
        let hints = ClientHints::for_profile(&profile);
        Ok(Self {
            client,
            profile,
            hints,
            jar,
        })
    }

    /// The browser identity this transport presents.
    pub fn profile(&self) -> &BrowserProfile {
        &self.profile
    }

    /// Adds the identity headers the emulation table cannot supply
    /// itself (its captured values belong to the machine the table was
    /// measured on, not to `self.profile`). Orchestration-layer values
    /// win when present.
    fn apply_identity(&self, headers: &mut HeaderMap) {
        use reqwest::header::USER_AGENT;
        if !headers.contains_key(USER_AGENT)
            && let Ok(ua) = HeaderValue::from_str(&self.profile.user_agent)
        {
            headers.insert(USER_AGENT, ua);
        }
        let Some(hints) = &self.hints else {
            return;
        };
        for (name, value) in [
            ("sec-ch-ua", hints.sec_ch_ua()),
            ("sec-ch-ua-mobile", hints.sec_ch_ua_mobile().to_string()),
            ("sec-ch-ua-platform", hints.sec_ch_ua_platform()),
        ] {
            let name = HeaderName::from_static(name);
            if !headers.contains_key(&name)
                && let Ok(value) = HeaderValue::from_str(&value)
            {
                headers.insert(name, value);
            }
        }
    }
}

impl std::fmt::Debug for WreqTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WreqTransport")
            .field("user_agent", &self.profile.user_agent)
            .finish()
    }
}

#[async_trait]
impl HttpTransport for WreqTransport {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ArloError> {
        let HttpRequest {
            method,
            url,
            headers,
            body,
        } = request;

        let mut header_map = to_header_map(headers)?;
        self.apply_identity(&mut header_map);

        let mut builder = self.client.request(method, &url).headers(header_map);
        if let Some(b) = body {
            builder = builder.body(b);
        }

        let response = builder.send().await?;
        let status = response.status();
        let body = response.text().await?;
        Ok(HttpResponse { status, body })
    }

    fn export_cookies(&self) -> Option<String> {
        self.jar.export_json()
    }

    fn import_cookies(&self, json: &str) -> Result<(), ArloError> {
        self.jar.import_json(json)
    }
}

/// Browser-proxy transport (`browser` feature): routes every request
/// through the `stealthscraper-rs` headless-Chrome MITM proxy so the TLS
/// fingerprint and connection metadata match a real Chrome session.
/// Selected with [`crate::ArloClientBuilder::browser`].
#[cfg(feature = "browser")]
pub struct CloudScraperTransport {
    client: reqwest::Client,
    /// Held purely so the headless-browser MITM proxy stays alive —
    /// dropping it would tear down the proxy `client` is routed through.
    /// Never read after construction; `#[allow(dead_code)]` is intentional.
    #[allow(dead_code)]
    cloud_scraper: stealthscraper_rs::CloudScraper,
}

#[cfg(feature = "browser")]
impl CloudScraperTransport {
    /// Wraps a `reqwest::Client` (already configured to route through
    /// `cloud_scraper`'s local MITM proxy) and the underlying scraper.
    /// Crate-internal — applications get this transport indirectly via
    /// [`crate::ArloClient::builder`].
    pub(crate) fn new(
        client: reqwest::Client,
        cloud_scraper: stealthscraper_rs::CloudScraper,
    ) -> Self {
        Self {
            client,
            cloud_scraper,
        }
    }
}

#[cfg(feature = "browser")]
impl std::fmt::Debug for CloudScraperTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudScraperTransport").finish()
    }
}

#[cfg(feature = "browser")]
#[async_trait]
impl HttpTransport for CloudScraperTransport {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ArloError> {
        let HttpRequest {
            method,
            url,
            headers,
            body,
        } = request;

        let mut builder = self
            .client
            .request(method, &url)
            .headers(to_header_map(headers)?);
        if let Some(b) = body {
            builder = builder.body(b);
        }

        let response = builder.send().await?;
        let status = response.status();
        let body = response.text().await?;
        Ok(HttpResponse { status, body })
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
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Records every dispatched request and returns canned responses
    /// **in FIFO order** — queue them in the order the code under test
    /// will consume them. For state-mutating requests (POST/PUT/DELETE)
    /// the orchestration layer issues an OPTIONS preflight first, then
    /// the main request: queue the empty-body OPTIONS response first,
    /// then the main response.
    ///
    /// Use [`MockTransport::queue_post`] / [`MockTransport::queue_get`]
    /// helpers to avoid getting the ordering wrong by hand.
    #[derive(Debug, Default)]
    pub struct MockTransport {
        calls: Mutex<Vec<HttpRequest>>,
        responses: Mutex<VecDeque<HttpResponse>>,
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self::default()
        }

        /// Queues `response` to be returned on the next [`request`] call.
        /// FIFO — first-queued is first-consumed.
        pub fn expect(&self, response: HttpResponse) {
            self.responses.lock().unwrap().push_back(response);
        }

        /// Convenience for the common "200 OK with this body" case.
        pub fn expect_ok(&self, body: impl Into<String>) {
            self.expect(HttpResponse {
                status: StatusCode::OK,
                body: body.into(),
            });
        }

        /// Convenience for "200 OK with no body" — used for OPTIONS
        /// preflight responses.
        pub fn expect_empty(&self) {
            self.expect_ok("");
        }

        /// Queue the response pair for a state-mutating request: an
        /// empty OPTIONS preflight response followed by `body` for the
        /// real call. Equivalent to `expect_empty(); expect_ok(body)`.
        pub fn queue_post(&self, body: impl Into<String>) {
            self.expect_empty();
            self.expect_ok(body);
        }

        /// Queue the single response for a GET (no preflight). Same as
        /// [`Self::expect_ok`]; named for symmetry with `queue_post`.
        pub fn queue_get(&self, body: impl Into<String>) {
            self.expect_ok(body);
        }

        /// Returns every recorded request in dispatch order.
        pub fn calls(&self) -> Vec<HttpRequest> {
            self.calls.lock().unwrap().clone()
        }

        /// True if every queued response was consumed. Useful as a
        /// trailing assertion in tests — kept `pub` even when unused so
        /// new tests can reach for it without having to refactor the
        /// helper module.
        #[allow(dead_code)]
        pub fn responses_drained(&self) -> bool {
            self.responses.lock().unwrap().is_empty()
        }
    }

    #[async_trait]
    impl HttpTransport for MockTransport {
        async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ArloError> {
            self.calls.lock().unwrap().push(request.clone());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| ArloError::ApiError {
                    code: 500,
                    error: None,
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

    // -- WreqTransport against a live mockito server (plain HTTP; the
    //    TLS emulation is exercised only on https, but the header identity
    //    and the request/response plumbing are what we assert here) --
    use mockito::{Matcher, Server};

    #[tokio::test]
    async fn wreq_transport_round_trips_and_sends_profile_identity() {
        let mut server = Server::new_async().await;
        let profile = BrowserProfile::random();
        let ua = profile.user_agent.clone();
        let _m = server
            .mock("POST", "/echo")
            .match_header("user-agent", ua.as_str())
            .match_header("sec-ch-ua", Matcher::Regex("Chromium".into()))
            .match_header("sec-ch-ua-mobile", "?0")
            .match_header("x-custom", "1")
            .match_body("{\"k\":\"v\"}")
            .with_status(201)
            .with_body("created")
            .create_async()
            .await;

        let transport = WreqTransport::new(profile, None).unwrap();
        let resp = transport
            .request(HttpRequest {
                method: Method::POST,
                url: format!("{}/echo", server.url()),
                headers: vec![("x-custom".into(), "1".into())],
                body: Some(b"{\"k\":\"v\"}".to_vec()),
            })
            .await
            .unwrap();

        assert_eq!(resp.status, StatusCode::CREATED);
        assert_eq!(resp.body, "created");
    }

    #[tokio::test]
    async fn wreq_transport_lets_orchestration_headers_win_over_identity() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/ua")
            .match_header("user-agent", "custom/1.0")
            .with_status(200)
            .create_async()
            .await;

        let transport = WreqTransport::new(BrowserProfile::random(), None).unwrap();
        let resp = transport
            .request(HttpRequest {
                method: Method::GET,
                url: format!("{}/ua", server.url()),
                headers: vec![("User-Agent".into(), "custom/1.0".into())],
                body: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn wreq_transport_maps_connection_failure_to_network_error() {
        let transport = WreqTransport::new(BrowserProfile::random(), None).unwrap();
        // Port 9 (discard) on loopback: nothing listens, connect is refused.
        let err = transport
            .request(HttpRequest {
                method: Method::GET,
                url: "http://127.0.0.1:9/".into(),
                headers: vec![],
                body: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ArloError::NetworkError(_)), "{err:?}");
    }

    #[tokio::test]
    async fn wreq_transport_persists_cookies_across_requests_and_exports_them() {
        let mut server = Server::new_async().await;
        let _set = server
            .mock("GET", "/login")
            .with_status(200)
            .with_header("set-cookie", "trust=abc; Path=/")
            .create_async()
            .await;
        let _replay = server
            .mock("GET", "/next")
            .match_header("cookie", "trust=abc")
            .with_status(204)
            .create_async()
            .await;

        let transport = WreqTransport::new(BrowserProfile::random(), None).unwrap();
        assert!(
            transport.export_cookies().is_none(),
            "fresh jar exports nothing"
        );
        let get = |path: &str| HttpRequest {
            method: Method::GET,
            url: format!("{}{path}", server.url()),
            headers: vec![],
            body: None,
        };
        transport.request(get("/login")).await.unwrap();
        let resp = transport.request(get("/next")).await.unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);

        // Round-trip the jar into a brand-new transport.
        let blob = transport.export_cookies().expect("jar exported");
        let fresh = WreqTransport::new(BrowserProfile::random(), None).unwrap();
        fresh.import_cookies(&blob).unwrap();
        let resp = fresh.request(get("/next")).await.unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
    }

    #[test]
    fn wreq_transport_rejects_invalid_upstream_proxy() {
        let err = WreqTransport::new(BrowserProfile::random(), Some("not a url")).unwrap_err();
        assert!(matches!(err, ArloError::ScraperError(_)), "{err:?}");
    }

    #[test]
    fn wreq_transport_debug_does_not_dump_client_internals() {
        let transport = WreqTransport::new(BrowserProfile::random(), None).unwrap();
        let dbg = format!("{transport:?}");
        assert!(dbg.starts_with("WreqTransport"));
        assert!(dbg.contains("Chrome/"));
    }
}
