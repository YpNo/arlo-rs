//! Shared scaffolding for the lib's unit tests.
//!
//! Every `impl ArloClient` method that funnels through the orchestration
//! layer can be exercised by:
//!
//! 1. Constructing a [`MockTransport`].
//! 2. Queueing canned [`HttpResponse`]s in FIFO order — use
//!    [`MockTransport::queue_post`] for state-mutating calls (it queues
//!    the OPTIONS preflight response then the main body).
//! 3. Building an [`ArloClient`] with [`mocked_client`].
//! 4. Calling the method under test and asserting on both the parsed
//!    return value *and* the recorded `MockTransport::calls()`.
//!
//! The fixed test base URL is `https://test.example`; assertions on
//! `calls[i].url` should be tolerant of either the full URL or just the
//! path suffix.

use crate::client::endpoints::ArloEndpoints;
use crate::client::transport::test_support::MockTransport;
use crate::client::ws::test_support::MockWsConnector;
use crate::client::{ArloClient, AuthManager, HttpTransport};
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Stable test base URL pointed at by [`ArloEndpoints::testing`].
pub(crate) const TEST_BASE_URL: &str = "https://test.example";

/// Builds an [`ArloClient`] backed by `mock` with both auth and api
/// hosts set to [`TEST_BASE_URL`]. The client starts with no token —
/// call [`set_test_token`] for tests that need an authenticated path.
pub(crate) fn mocked_client(mock: Arc<MockTransport>) -> ArloClient {
    mocked_client_with_ws(mock, Arc::new(MockWsConnector::new()))
}

/// Like [`mocked_client`] with an explicit scripted WebSocket double for
/// the event-bus / signaling paths.
pub(crate) fn mocked_client_with_ws(
    mock: Arc<MockTransport>,
    ws: Arc<MockWsConnector>,
) -> ArloClient {
    ArloClient {
        transport: mock as Arc<dyn HttpTransport>,
        endpoints: ArloEndpoints::testing(TEST_BASE_URL),
        auth: AuthManager::new(),
        debug_mode: false,
        ws,
        event_bus: OnceCell::new(),
        api_version: crate::client::ApiVersionCell::default(),
    }
}

/// Builds an authenticated client: token + user_id + stable device_id
/// pre-populated so tests don't have to wire the auth flow first.
pub(crate) fn authenticated_mocked_client(mock: Arc<MockTransport>) -> ArloClient {
    let mut client = mocked_client(mock);
    set_test_token(&mut client, "test_token", "U-test", "device-test");
    client
}

/// Convenience to seed auth state on an already-built client.
pub(crate) fn set_test_token(client: &mut ArloClient, token: &str, user_id: &str, device_id: &str) {
    client.auth.set_token(token.to_string());
    client.auth.user_id = Some(user_id.to_string());
    client.auth.device_id = device_id.to_string();
}

/// Header lookup that's tolerant of name case (HTTP headers are
/// case-insensitive per RFC 7230 §3.2).
pub(crate) fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Parses a recorded request body as JSON. Panics on non-UTF-8 / invalid
/// JSON — tests should fail loudly rather than silently when payload
/// shape regresses.
pub(crate) fn parse_body_json(body: Option<&Vec<u8>>) -> serde_json::Value {
    let bytes = body.expect("expected a request body");
    let text = std::str::from_utf8(bytes).expect("body is not valid UTF-8");
    serde_json::from_str(text).expect("body is not valid JSON")
}
