//! Integration test: drives the public `ArloClient` surface through a
//! caller-supplied `HttpTransport` impl, with no live network and no
//! CloudScraper.
//!
//! This test only uses **public** crate items — `ArloClient`,
//! `ArloClientBuilder`, `HttpTransport`, `HttpRequest`, `HttpResponse`,
//! `ArloEndpoints`, `MfaHandler`, `StaticOtpHandler` — proving the seam
//! introduced in PR 4 is genuinely consumable from outside the crate.
//! The downstream streamer app's own test suite will follow exactly
//! this pattern.

use async_trait::async_trait;
use reqwest::{Method, StatusCode};
use rs_arlo::{
    ArloClient, ArloEndpoints, ArloError, HttpRequest, HttpResponse, HttpTransport,
    StaticOtpHandler,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// FIFO mock transport — same shape as the in-crate `MockTransport`,
/// but built using only public items so an external consumer could
/// copy it verbatim into their own test suite.
#[derive(Debug, Default)]
struct PublicMockTransport {
    calls: Mutex<Vec<(Method, String)>>,
    responses: Mutex<VecDeque<HttpResponse>>,
}

impl PublicMockTransport {
    fn new() -> Self {
        Self::default()
    }

    fn queue_ok(&self, body: impl Into<String>) {
        self.responses.lock().unwrap().push_back(HttpResponse {
            status: StatusCode::OK,
            body: body.into(),
        });
    }

    /// Queue OPTIONS preflight + main body for a state-mutating call.
    fn queue_post(&self, body: impl Into<String>) {
        self.queue_ok("");
        self.queue_ok(body);
    }

    fn calls(&self) -> Vec<(Method, String)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpTransport for PublicMockTransport {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, ArloError> {
        self.calls
            .lock()
            .unwrap()
            .push((request.method.clone(), request.url.clone()));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| ArloError::Timeout("PublicMockTransport: queue empty".into()))
    }
}

/// Drives the full public flow: `authenticate_with_handler` (with a
/// `StaticOtpHandler`) → `get_devices` → `get_locations` →
/// `take_snapshot` → `logout`.
///
/// Every interaction goes through the `HttpTransport` trait — no
/// CloudScraper, no live network, no in-crate `MockTransport`.
#[tokio::test]
async fn public_api_full_authenticated_flow_via_static_otp() {
    let mock = Arc::new(PublicMockTransport::new());

    // -- authenticate_with_handler() sequence --
    // login (POST: OPTIONS + body)
    mock.queue_post(
        r#"{"meta":{"code":200},"data":{"token":"preliminary","userId":"U-1","authenticated":1}}"#,
    );
    // get_factors (GET)
    mock.queue_ok(
        r#"{"meta":{"code":200},"data":{"items":[
            {"factorId":"F1","factorType":"EMAIL","factorRole":"PRIMARY"}
        ]}}"#,
    );
    // start_auth (POST: OPTIONS + body)
    mock.queue_post(r#"{"meta":{"code":200},"data":{"factorAuthCode":"FAC-1"}}"#);
    // finish_auth (POST: OPTIONS + body)
    mock.queue_post(
        r#"{"meta":{"code":200},"data":{"token":"final","userId":"U-1","authenticated":1}}"#,
    );
    // validate_access_token (GET)
    mock.queue_ok("{}");
    // start_pairing_factor (POST: OPTIONS + body)
    mock.queue_post("{}");
    // validate_session_v3 (GET)
    mock.queue_ok(r#"{"meta":{"code":200},"data":{"userId":"U-1","token":"final"}}"#);
    // device_support_v2 (GET)
    mock.queue_ok(r#"{"meta":{"code":200},"data":{}}"#);

    // -- post-auth surface --
    // get_devices (GET)
    mock.queue_ok(
        r#"[{"deviceId":"C1","parentId":"B1","deviceType":"camera","deviceName":"Cam1","uniqueId":"u1","state":"provisioned"}]"#,
    );
    // get_locations (GET)
    mock.queue_ok(r#"{"success":true,"data":[{"id":"loc-1","name":"Home"}]}"#);
    // take_snapshot (POST: OPTIONS + body)
    mock.queue_post("{}");
    // logout (PUT: OPTIONS + body)
    mock.queue_post("{}");

    let mut client = ArloClient::with_transport(
        Arc::clone(&mock) as Arc<dyn HttpTransport>,
        ArloEndpoints::testing("https://test.example"),
    );

    let cfg = make_test_config();
    let handler = StaticOtpHandler::new("123456");
    client
        .authenticate_with_handler(&cfg, handler)
        .await
        .expect("authentication should succeed");
    assert!(client.is_authenticated());
    assert_eq!(client.user_id(), Some("U-1"));

    let devices = client.get_devices().await.expect("get_devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, "C1");

    let locations = client.get_locations().await.expect("get_locations");
    assert_eq!(locations.len(), 1);
    assert_eq!(locations[0].name, "Home");

    client.take_snapshot("C1").await.expect("take_snapshot");
    client.logout().await.expect("logout");
    assert!(!client.is_authenticated());

    // Sanity: every queued response was consumed; no surprise extras.
    let calls = mock.calls();
    let expected_method_sequence = vec![
        Method::OPTIONS, // login
        Method::POST,
        Method::GET,     // get_factors
        Method::OPTIONS, // start_auth
        Method::POST,
        Method::OPTIONS, // finish_auth
        Method::POST,
        Method::GET,     // validate_access_token
        Method::OPTIONS, // start_pairing_factor
        Method::POST,
        Method::GET,     // validate_session_v3
        Method::GET,     // device_support_v2
        Method::GET,     // get_devices
        Method::GET,     // get_locations
        Method::OPTIONS, // take_snapshot
        Method::POST,
        Method::OPTIONS, // logout
        Method::PUT,
    ];
    assert_eq!(
        calls.iter().map(|(m, _)| m.clone()).collect::<Vec<_>>(),
        expected_method_sequence
    );
}

fn make_test_config() -> rs_arlo::config::ArloConfig {
    rs_arlo::config::ArloConfig {
        credentials: Some(rs_arlo::config::CredentialsConfig {
            email: Some("user@example.test".into()),
            password: Some("p".into()),
        }),
        mfa: Some(rs_arlo::config::MfaConfig {
            preferred_method: Some("EMAIL".into()),
            imap: None,
        }),
        client: None,
        streaming: None,
    }
}

/// Confirms `ArloClient::builder()` is reachable from outside the crate
/// with the full public configuration surface, even though we don't
/// actually `.build()` (that would boot CloudScraper).
#[test]
fn public_builder_compiles_with_all_setters() {
    let _builder = ArloClient::builder()
        .user_agent("integration-test")
        .headless(true)
        .upstream_proxy("http://127.0.0.1:8080")
        .debug_mode(false)
        .session_cache(".arlo_session.json")
        .endpoints(ArloEndpoints::testing("https://test.example"));
}

/// `ArloEndpoints::testing(url)` collapses both hosts to the given URL
/// — sanity-checked from the public surface.
#[test]
fn public_endpoints_testing_collapses_hosts() {
    let e = ArloEndpoints::testing("https://my.test/");
    assert_eq!(e.auth_host, "https://my.test");
    assert_eq!(e.api_host, "https://my.test");
}
