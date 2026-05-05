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
/// Pluggable Multi-Factor-Authentication handler trait + bundled impls.
pub mod mfa;
/// S3 Video chunk parsing and media decryption logic.
pub mod library;
/// Raw token spoofing for connecting natively to local hubs bypassing Cloudflare.
pub mod ratls;

use crate::config::{ArloConfig, ClientConfig};
use crate::error::ArloError;
use crate::events::EventBus;
pub use auth::AuthManager;
pub use builder::ArloClientBuilder;
use reqwest::Client;
use rs_cloudscraper::CloudScraper;
use tokio::sync::OnceCell;
use tracing::instrument;

/// Core REST API manager for the Arlo ecosystem.
///
/// `ArloClient` wraps a `reqwest::Client` that is configured to proxy its connection
/// identically through a headless `rs-cloudscraper` browser. This ensures that the user's
/// TLS footprint and fingerprint remain identical to a human operator, bypassing Cloudflare.
pub struct ArloClient {
    /// The tunneled HTTP client used to execute requests.
    pub(crate) reqwest_client: Client,
    /// Held purely so the headless-browser MITM proxy stays alive — dropping
    /// it would tear down the proxy that `reqwest_client` is routed through.
    /// Never read after construction; `#[allow(dead_code)]` is intentional.
    #[allow(dead_code)]
    pub(crate) cloud_scraper: CloudScraper,
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
                EventBus::start(
                    self.reqwest_client.clone(),
                    token.to_string(),
                    self.auth.device_id.clone(),
                )
                .await
            })
            .await
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
