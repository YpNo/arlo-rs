/// Pure REST API calls that don't fit into devices or auth cleanly.
pub mod api;
/// All authentication protocols, multi-factor challenges, and session caching.
pub mod auth;
/// Automated secure polling of IMAP mailboxes for MFA text extraction.
pub mod auth_imap;
/// Programmatic builder for [`ArloClient`].
pub mod builder;
/// Camera streaming, topology tracking, mode adjustments, and actuations.
pub mod devices;
/// Runtime-configurable Arlo host endpoints (auth + api hosts).
pub mod endpoints;
/// S3 Video chunk parsing and media decryption logic.
pub mod library;
/// Direct LAN client for an Arlo SmartHub with pinned-leaf TLS.
pub mod local_hub;
/// Pluggable Multi-Factor-Authentication handler trait + bundled impls.
pub mod mfa;
/// Raw token spoofing for connecting natively to local hubs bypassing Cloudflare.
pub mod ratls;
/// HTTP transport abstraction (production CloudScraper impl + test doubles).
pub mod transport;

#[cfg(test)]
#[allow(dead_code)] // helper utilities; not all are used by every dependent test module
pub(crate) mod test_helpers;

use crate::config::{ArloConfig, ClientConfig};
use crate::error::ArloError;
use crate::events::EventBus;
use crate::models::auth::SessionToken;
pub use auth::AuthManager;
pub use builder::ArloClientBuilder;
pub use endpoints::ArloEndpoints;
use std::sync::Arc;
use tokio::sync::OnceCell;
use tracing::{info, instrument};
pub use transport::HttpTransport;

/// Core REST API manager for the Arlo ecosystem.
///
/// `ArloClient` orchestrates auth-header injection, CORS preflight, and
/// JSON envelope handling, then delegates the actual HTTP byte-shuffling
/// to a pluggable [`HttpTransport`]. Production transports route through
/// the `rs-cloudscraper` headless-browser proxy to forge a JA4 TLS
/// fingerprint indistinguishable from a real Chrome session; tests
/// substitute lightweight mocks.
pub struct ArloClient {
    /// The HTTP transport. Production wires this to a
    /// [`crate::client::transport::CloudScraperTransport`]; tests use a
    /// `MockTransport` to dispatch requests without booting the proxy.
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
    /// Lazy SSE event bus. First [`Self::events`] call boots it; the bus
    /// is dropped (and its tasks aborted) when the client is dropped.
    pub(crate) event_bus: OnceCell<EventBus>,
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
    /// the heavyweight `rs-cloudscraper` bootstrap entirely.
    ///
    /// This is the entry point for unit tests that want to drive the
    /// orchestration layer (auth-header injection, OPTIONS preflight,
    /// JSON envelope handling) against a mock HTTP backend. It is also
    /// useful for callers whose environment already provides a
    /// stealth-routed `reqwest::Client` and doesn't need a second proxy.
    pub fn with_transport(transport: Arc<dyn HttpTransport>, endpoints: ArloEndpoints) -> Self {
        Self {
            transport,
            endpoints,
            auth: AuthManager::new(),
            debug_mode: false,
            event_bus: OnceCell::new(),
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

    /// Returns a reference to the SSE event bus, booting it on first call.
    ///
    /// The bus subscribes to Arlo's `/hmsweb/client/subscribe` SSE stream
    /// and broadcasts parsed [`crate::models::events::ArloEvent`]s to any
    /// receiver obtained via [`EventBus::subscribe`]. Returns
    /// [`ArloError::AuthError`] if no access token is yet held.
    pub async fn events(&self) -> Result<&EventBus, ArloError> {
        self.event_bus
            .get_or_try_init(|| async {
                let token = self.auth.token().ok_or_else(|| {
                    ArloError::AuthError(
                        "Cannot start SSE event bus without an active session".into(),
                    )
                })?;
                let streaming = self.transport.streaming_client().ok_or_else(|| {
                    ArloError::AuthError(
                        "The active transport does not support streaming (SSE event bus unavailable)"
                            .into(),
                    )
                })?;
                EventBus::start(
                    streaming,
                    self.endpoints.api_host.clone(),
                    token.to_string(),
                    self.auth.device_id.clone(),
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
        let client_conf = config.client.clone().unwrap_or(ClientConfig {
            debug_mode: None,
            user_agent: None,
            session_cache_path: None,
            headless: None,
            upstream_proxy: None,
        });

        let mut client = Self::with_config(&client_conf).await?;
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
    async fn events_errors_when_transport_does_not_support_streaming() {
        // MockTransport's default streaming_client() returns None.
        let mock = Arc::new(MockTransport::new());
        let client = authenticated_mocked_client(mock);
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
