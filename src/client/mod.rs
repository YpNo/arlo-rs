pub mod api;
pub mod auth;
pub mod auth_imap;
pub mod builder;
pub mod cookies;
pub mod devices;
pub mod endpoints;
/// S3 Video chunk parsing and media decryption logic.
pub mod library;
pub mod livestream;
pub mod local_hub;
pub mod mfa;
pub mod ratls;
pub mod transport;
pub mod ws;

#[cfg(test)]
#[allow(dead_code)] // helper utilities; not all are used by every dependent test module
pub(crate) mod test_helpers;

use crate::config::{ApiVersion, ArloConfig, ClientConfig};
use crate::error::ArloError;
use crate::events::{EventBus, MqttParams};
use crate::models::auth::SessionToken;
pub use auth::AuthManager;
pub use builder::ArloClientBuilder;
pub use endpoints::ArloEndpoints;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::sync::OnceCell;
use tracing::{info, instrument};
pub use transport::HttpTransport;
pub use ws::{TungsteniteConnector, WsConnector};

/// Lock-free holder for the per-client [`ApiVersion`]: read on every
/// versioned call, written once when a V3 endpoint answers 403/404 (pin
/// to `Legacy`). An enum with two variants needs no `RwLock`, and this
/// cannot be poisoned.
#[derive(Debug)]
pub(crate) struct ApiVersionCell(AtomicU8);

impl ApiVersionCell {
    const LEGACY: u8 = 0;
    const V3: u8 = 1;

    pub(crate) fn new(version: ApiVersion) -> Self {
        let cell = Self(AtomicU8::new(Self::V3));
        cell.set(version);
        cell
    }

    pub(crate) fn get(&self) -> ApiVersion {
        match self.0.load(Ordering::Relaxed) {
            Self::LEGACY => ApiVersion::Legacy,
            _ => ApiVersion::V3,
        }
    }

    pub(crate) fn set(&self, version: ApiVersion) {
        let raw = match version {
            ApiVersion::Legacy => Self::LEGACY,
            ApiVersion::V3 => Self::V3,
        };
        self.0.store(raw, Ordering::Relaxed);
    }
}

impl Default for ApiVersionCell {
    fn default() -> Self {
        Self::new(ApiVersion::default())
    }
}

/// Core REST API manager for the Arlo ecosystem.
///
/// `ArloClient` orchestrates auth-header injection, CORS preflight, and
/// JSON envelope handling, then delegates the actual HTTP byte-shuffling
/// to a pluggable [`HttpTransport`]. The default production transport is
/// a `wreq` client carrying a measured Chrome TLS/HTTP2 fingerprint (see
/// [`crate::client::transport::WreqTransport`]); tests substitute
/// lightweight mocks.
pub struct ArloClient {
    /// The HTTP transport. Production wires this to a
    /// [`crate::client::transport::WreqTransport`] (or the browser-proxy
    /// transport under the `browser` feature); tests use a
    /// `MockTransport` to dispatch requests without any network.
    pub(crate) transport: Arc<dyn HttpTransport>,
    /// Base hosts the client points at. Defaults to production URLs;
    /// the builder's [`ArloClientBuilder::endpoints`] overrides them.
    pub(crate) endpoints: ArloEndpoints,
    /// Secure state storage for tokens and user IDs. Access externally via
    /// [`ArloClient::is_authenticated`] / [`ArloClient::user_id`] /
    /// [`ArloClient::device_id`].
    pub(crate) auth: AuthManager,
    /// When enabled, dumps all HTTP payloads matching traces to stdout.
    pub(crate) debug_mode: bool,
    /// Opens the MQTT event-bus and WebRTC-signaling WebSockets.
    /// Production wires [`TungsteniteConnector`]; tests a scripted double.
    pub(crate) ws: Arc<dyn WsConnector>,
    /// Lazy MQTT event bus. First [`Self::events`] call boots it; the bus
    /// is dropped (and its task aborted) when the client is dropped.
    pub(crate) event_bus: OnceCell<EventBus>,
    /// Tracks the detected API version for fallback logic.
    pub(crate) api_version: ApiVersionCell,
}

impl ArloClient {
    /// Returns a programmatic builder. Prefer this over
    /// [`ArloClient::from_config`] when secrets aren't loaded from TOML.
    pub fn builder() -> ArloClientBuilder {
        ArloClientBuilder::default()
    }

    /// Builds a new ArloClient using default profiles. Equivalent to
    /// `ArloClient::builder().build().await`.
    #[instrument]
    pub async fn new() -> Result<Self, ArloError> {
        Self::builder().build().await
    }

    /// Builds the ArloClient with precise overrides for the underlying
    /// stealth browser. Retained as a thin shim over the builder for
    /// callers that already hold a [`ClientConfig`] (typically the TOML
    /// loader).
    #[instrument(skip(config))]
    pub async fn with_config(config: &ClientConfig) -> Result<Self, ArloError> {
        builder::bootstrap(builder::BootstrapConfig::from(config)).await
    }

    /// Constructs a client backed by a caller-supplied transport, skipping
    /// the default transport bootstrap entirely.
    ///
    /// This is the entry point for unit tests that want to drive the
    /// orchestration layer (auth-header injection, OPTIONS preflight,
    /// JSON envelope handling) against a mock HTTP backend. It is also
    /// useful for callers whose environment already provides a
    /// stealth-routed `reqwest::Client` and doesn't need a second proxy.
    pub fn with_transport(transport: Arc<dyn HttpTransport>, endpoints: ArloEndpoints) -> Self {
        Self::with_transports(transport, Arc::new(TungsteniteConnector), endpoints)
    }

    /// Like [`Self::with_transport`], additionally injecting the
    /// [`WsConnector`] used for the MQTT event bus and WebRTC signaling
    /// sockets — the second seam a test double can occupy.
    pub fn with_transports(
        transport: Arc<dyn HttpTransport>,
        ws: Arc<dyn WsConnector>,
        endpoints: ArloEndpoints,
    ) -> Self {
        Self {
            transport,
            endpoints,
            auth: AuthManager::new(),
            debug_mode: false,
            ws,
            event_bus: OnceCell::new(),
            api_version: ApiVersionCell::default(),
        }
    }

    /// Enables full HTTP intercept payload logging.
    pub fn with_debug(mut self, enabled: bool) -> Self {
        self.debug_mode = enabled;
        self
    }

    /// Returns `true` if the client currently holds a session token.
    ///
    /// Holding a token does not by itself prove the session is still valid —
    /// call [`ArloClient::validate_session_v3`] to round-trip against the
    /// server when freshness matters.
    pub fn is_authenticated(&self) -> bool {
        self.auth.has_token()
    }

    /// Returns the Arlo-assigned user ID once authenticated, otherwise `None`.
    pub fn user_id(&self) -> Option<&str> {
        self.auth.user_id.as_deref()
    }

    /// Returns the per-instance device-tracking UUID. Stable for the lifetime
    /// of the cached session.
    pub fn device_id(&self) -> &str {
        &self.auth.device_id
    }

    /// Internal helper: returns the active `user_id` or an
    /// [`ArloError::AuthError`] if the client isn't authenticated.
    /// Used by every `notify`-style method that needs to stamp the
    /// `from: "{user_id}_web"` field.
    pub(crate) fn require_user_id(&self) -> Result<&str, ArloError> {
        self.auth.user_id.as_deref().ok_or_else(|| {
            ArloError::AuthError("Operation requires an authenticated session".into())
        })
    }

    /// Returns a reference to the event bus, booting it on first call.
    ///
    /// Connects to Arlo's MQTT-over-WebSocket broker (the v3 successor
    /// to the now-403 SSE channel) and broadcasts parsed
    /// [`crate::models::events::ArloEvent`]s to any receiver obtained
    /// via [`EventBus::subscribe`].
    ///
    /// First call resolves the broker URL from `session/v3` (`mqttUrl`)
    /// and the device list to build the subscription topics, so it
    /// performs two REST round-trips before the listener spawns.
    ///
    /// # Errors
    ///
    /// [`ArloError::AuthError`] if not authenticated or the account's
    /// `session/v3` does not advertise an `mqttUrl`; transport/parse
    /// errors from the `session/v3` and devices calls propagate.
    pub async fn events(&self) -> Result<&EventBus, ArloError> {
        self.event_bus
            .get_or_try_init(|| async {
                if !self.auth.has_token() {
                    return Err(ArloError::AuthError(
                        "Cannot start event bus without an active session".into(),
                    ));
                }
                // A watch, not a copy: after a re-authentication the next
                // CONNECT carries the new token.
                let token = self.auth.token_rx();
                let user_id = self.auth.user_id.clone().ok_or_else(|| {
                    ArloError::AuthError("event bus requires an authenticated userId".into())
                })?;

                // `mqttUrl` is delivered by session/v3 (also doubles as a
                // session-freshness check before we open the socket).
                let session = self.validate_session_v3().await?;
                let mqtt_url = session.mqtt_url.ok_or_else(|| {
                    ArloError::AuthError(
                        "session/v3 returned no mqttUrl — account not on the v3 event bus".into(),
                    )
                })?;
                // The access token becomes the MQTT password: never dial a
                // host Arlo did not name, and never over plaintext.
                let mqtt_url =
                    crate::models::validate::arlo_wss_url("session/v3 mqttUrl", &mqtt_url, None)?
                        .to_string();

                // Subscribe to the web client's fine-grained per-resource
                // topics keyed by each device's xCloudId (the broad
                // `d/<xCloudId>/out/#` wildcard is owner-only) plus the
                // user inbox.
                let devices = self.get_devices().await?;
                let with_xcloud = devices.iter().filter(|d| d.x_cloud_id.is_some()).count();
                let topics = crate::events::subscription_topics(&devices, &user_id);
                info!(
                    device_count = devices.len(),
                    with_xcloud,
                    topic_count = topics.len(),
                    "resolved MQTT event-bus subscription (no xCloud ⇒ legacy get_devices, no camera events)"
                );

                EventBus::start(
                    MqttParams {
                        mqtt_url,
                        user_id,
                        token,
                        topics,
                    },
                    Arc::clone(&self.ws),
                )
                .await
            })
            .await
    }

    /// Re-attaches a previously-issued session token to a fresh client.
    ///
    /// Use this when the access token, `user_id`, and `device_id` are
    /// persisted outside the process — for example a vault, an env var, or
    /// the application's own database — instead of via
    /// [`ArloClientBuilder::session_cache`]. The returned client validates
    /// the token against the session-v3 endpoint before returning, so a
    /// stale token surfaces immediately as an [`ArloError::AuthError`].
    ///
    /// To capture the state for later re-attachment, call
    /// [`ArloClient::session_token`] on a live, authenticated client.
    #[instrument(skip(session))]
    pub async fn reattach(session: SessionToken) -> Result<Self, ArloError> {
        let mut client = Self::builder().build().await?;
        client.auth.set_token(session.access_token().to_string());
        client.auth.user_id = Some(session.user_id().to_string());
        client.auth.device_id = session.device_id().to_string();

        client
            .validate_session_v3()
            .await
            .map_err(|e| ArloError::AuthError(format!("reattach: token rejected: {e}")))?;

        info!(user_id = %session.user_id(), "Re-attached existing Arlo session");
        Ok(client)
    }

    /// Snapshots the current session as a [`SessionToken`] for persistence
    /// outside this process. Returns [`ArloError::AuthError`] if the
    /// client isn't authenticated yet.
    pub fn session_token(&self) -> Result<SessionToken, ArloError> {
        let token = self
            .auth
            .token()
            .ok_or_else(|| ArloError::AuthError("No active session to snapshot".into()))?;
        let user_id = self
            .auth
            .user_id
            .as_deref()
            .ok_or_else(|| ArloError::AuthError("Session has no user_id".into()))?;
        Ok(SessionToken::new(token, user_id, &self.auth.device_id))
    }

    /// Hydrates the client configuration from a TOML file. Internally a
    /// thin shim over [`ArloClient::builder`] — application code that
    /// doesn't depend on TOML should call the builder directly.
    #[instrument(skip(path))]
    pub async fn from_config(path: &str) -> Result<Self, ArloError> {
        let config = ArloConfig::load_from_file(path)?;
        let client_conf = config.client.clone().unwrap_or_default();

        let mut client = Self::with_config(&client_conf).await?;
        if let Some(ver) = client_conf.api_version {
            client.api_version.set(ver);
        }
        if let Some(ref cache_path) = client_conf.session_cache_path {
            builder::apply_session_cache(&mut client, cache_path).await;
        }
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_helpers::{
        TEST_BASE_URL, authenticated_mocked_client, mocked_client, set_test_token,
    };
    use crate::client::transport::test_support::MockTransport;

    #[tokio::test]
    async fn is_authenticated_reflects_token_state() {
        let mock = Arc::new(MockTransport::new());
        let mut client = mocked_client(mock);
        assert!(!client.is_authenticated());
        set_test_token(&mut client, "tok", "U-x", "dev-x");
        assert!(client.is_authenticated());
    }

    #[tokio::test]
    async fn user_id_returns_none_until_set() {
        let mock = Arc::new(MockTransport::new());
        let mut client = mocked_client(mock);
        assert_eq!(client.user_id(), None);
        set_test_token(&mut client, "tok", "U-1", "dev-1");
        assert_eq!(client.user_id(), Some("U-1"));
    }

    #[tokio::test]
    async fn device_id_is_stable_uuid_or_overridden() {
        let mock = Arc::new(MockTransport::new());
        let client_a = mocked_client(Arc::clone(&mock));
        // Fresh AuthManager generates a UUID (36 chars).
        assert_eq!(client_a.device_id().len(), 36);

        let mut client_b = mocked_client(mock);
        set_test_token(&mut client_b, "t", "U", "stable-id-42");
        assert_eq!(client_b.device_id(), "stable-id-42");
    }

    #[tokio::test]
    async fn with_debug_setter_toggles_flag() {
        let mock = Arc::new(MockTransport::new());
        let client = mocked_client(mock).with_debug(true);
        assert!(client.debug_mode);
        let client = client.with_debug(false);
        assert!(!client.debug_mode);
    }

    #[tokio::test]
    async fn require_user_id_errors_when_not_authenticated() {
        let mock = Arc::new(MockTransport::new());
        let client = mocked_client(mock);
        let err = client.require_user_id().unwrap_err();
        assert!(matches!(err, ArloError::AuthError(_)));
    }

    #[tokio::test]
    async fn require_user_id_returns_id_when_authenticated() {
        let mock = Arc::new(MockTransport::new());
        let client = authenticated_mocked_client(mock);
        assert_eq!(client.require_user_id().unwrap(), "U-test");
    }

    #[tokio::test]
    async fn events_errors_when_not_authenticated() {
        let mock = Arc::new(MockTransport::new());
        let client = mocked_client(mock);
        let err = client.events().await.unwrap_err();
        assert!(matches!(err, ArloError::AuthError(_)));
    }

    #[tokio::test]
    async fn events_errors_without_an_active_session() {
        // No token cached → the bus can't authenticate the MQTT CONNECT.
        let mock = Arc::new(MockTransport::new());
        let client = mocked_client(mock);
        let err = client.events().await.unwrap_err();
        assert!(matches!(err, ArloError::AuthError(_)));
    }

    #[tokio::test]
    async fn session_token_round_trips_through_accessor() {
        let mock = Arc::new(MockTransport::new());
        let client = authenticated_mocked_client(mock);
        let token = client.session_token().expect("token");
        assert_eq!(token.user_id(), "U-test");
        assert_eq!(token.device_id(), "device-test");
        assert_eq!(token.access_token(), "test_token");
    }

    #[tokio::test]
    async fn session_token_errors_when_not_authenticated() {
        let mock = Arc::new(MockTransport::new());
        let client = mocked_client(mock);
        assert!(matches!(
            client.session_token(),
            Err(ArloError::AuthError(_))
        ));
    }

    #[tokio::test]
    async fn from_config_errors_on_missing_file() {
        let res = ArloClient::from_config("/path/that/does/not/exist.toml").await;
        assert!(res.is_err(), "missing config should fail before bootstrap");
    }

    #[tokio::test]
    async fn test_base_url_constant_is_used_consistently() {
        // Compile-time guarantee that the const re-exports correctly.
        assert!(TEST_BASE_URL.starts_with("https://"));
    }
}

#[cfg(test)]
mod api_version_cell_tests {
    use super::*;

    #[test]
    fn defaults_to_v3_and_round_trips_both_variants() {
        let cell = ApiVersionCell::default();
        assert_eq!(cell.get(), ApiVersion::V3);
        cell.set(ApiVersion::Legacy);
        assert_eq!(cell.get(), ApiVersion::Legacy);
        cell.set(ApiVersion::V3);
        assert_eq!(cell.get(), ApiVersion::V3);
        assert_eq!(
            ApiVersionCell::new(ApiVersion::Legacy).get(),
            ApiVersion::Legacy
        );
    }
}
