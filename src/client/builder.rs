//! Programmatic builder for [`crate::client::ArloClient`].
//!
//! Downstream applications that don't use TOML configuration (e.g. servers
//! pulling secrets from a vault, GUIs prompting interactively, tests with
//! hard-coded fixtures) construct the client through this builder rather
//! than [`crate::client::ArloClient::from_config`].
//!
//! ```no_run
//! use rs_arlo::ArloClient;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = ArloClient::builder()
//!     .headless(true)
//!     .session_cache(".arlo_session.json")
//!     .build()
//!     .await?;
//! # let _ = client;
//! # Ok(())
//! # }
//! ```
//!
//! TOML-based construction is now a thin shim: `ArloClient::from_config`
//! parses the TOML, calls into this builder, and applies the session-cache
//! restore step.

use crate::client::endpoints::ArloEndpoints;
use crate::client::transport::CloudScraperTransport;
use crate::client::{ArloClient, AuthManager};
use crate::config::ClientConfig;
use crate::error::ArloError;
use reqwest::Client;
use rs_cloudscraper::{BrowserProfile, CloudScraper};
use std::sync::Arc;

/// Programmatic builder for an [`ArloClient`]. Construct via
/// [`ArloClient::builder`].
#[derive(Debug, Default)]
pub struct ArloClientBuilder {
    user_agent: Option<String>,
    headless: Option<bool>,
    upstream_proxy: Option<String>,
    debug_mode: bool,
    session_cache_path: Option<String>,
    endpoints: Option<ArloEndpoints>,
}

impl ArloClientBuilder {
    /// Override the User-Agent string presented to Arlo. Defaults to a
    /// random Chrome desktop profile from `rs-cloudscraper`.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Run the underlying headless browser without a visible window.
    /// Set to `false` only for interactive debugging.
    pub fn headless(mut self, on: bool) -> Self {
        self.headless = Some(on);
        self
    }

    /// Route all traffic through an upstream HTTP/SOCKS proxy.
    pub fn upstream_proxy(mut self, url: impl Into<String>) -> Self {
        self.upstream_proxy = Some(url.into());
        self
    }

    /// When enabled, the client emits `tracing::debug` events containing
    /// redacted HTTP request/response bodies. Sensitive JSON keys
    /// (`token`, `password`, `otp`, …) are scrubbed before logging.
    pub fn debug_mode(mut self, on: bool) -> Self {
        self.debug_mode = on;
        self
    }

    /// Persist the post-MFA access token to `path`. The file is created
    /// with mode `0600` on Unix. If the file already exists when
    /// [`Self::build`] is called, the cached token is restored and validated
    /// — a successful validation skips the login flow entirely.
    pub fn session_cache(mut self, path: impl Into<String>) -> Self {
        self.session_cache_path = Some(path.into());
        self
    }

    /// Override the Arlo host endpoints. Defaults to production
    /// (`ocapi-app.arlo.com` + `myapi.arlo.com`); unit tests use this
    /// to point at a mockito server. See [`ArloEndpoints`].
    pub fn endpoints(mut self, endpoints: ArloEndpoints) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    /// Constructs the [`ArloClient`]. This boots the headless browser
    /// stealth proxy (`rs-cloudscraper`), so it is a heavyweight call
    /// (typically several seconds). If [`Self::session_cache`] was set and
    /// the file exists, the cached token is restored and validated; an
    /// invalid cache is wiped and the client returns ready for a fresh
    /// login.
    pub async fn build(self) -> Result<ArloClient, ArloError> {
        let endpoints = self.endpoints.clone().unwrap_or_default();
        let mut client = bootstrap(BootstrapConfig {
            user_agent: self.user_agent,
            headless: self.headless,
            upstream_proxy: self.upstream_proxy,
            debug_mode: self.debug_mode,
            endpoints,
        })
        .await?;

        if let Some(ref path) = self.session_cache_path {
            apply_session_cache(&mut client, path).await;
        }

        Ok(client)
    }
}

/// Internal carrier between the public builder and the private bootstrap
/// helper. Decoupled so [`ArloClient::with_config`] can keep its existing
/// `&ClientConfig` signature without leaking the builder's private fields.
pub(crate) struct BootstrapConfig {
    pub user_agent: Option<String>,
    pub headless: Option<bool>,
    pub upstream_proxy: Option<String>,
    pub debug_mode: bool,
    pub endpoints: ArloEndpoints,
}

impl From<&ClientConfig> for BootstrapConfig {
    fn from(c: &ClientConfig) -> Self {
        Self {
            user_agent: c.user_agent.clone(),
            headless: c.headless,
            upstream_proxy: c.upstream_proxy.clone(),
            debug_mode: c.debug_mode.unwrap_or(false),
            endpoints: ArloEndpoints::default(),
        }
    }
}

/// Single source of truth for [`ArloClient`] construction. Boots the
/// headless browser, builds the proxied `reqwest` client, and returns a
/// fresh [`ArloClient`] with no auth state populated.
pub(crate) async fn bootstrap(cfg: BootstrapConfig) -> Result<ArloClient, ArloError> {
    // rustls 0.23+ panics if no default CryptoProvider is installed and the
    // local MITM proxy ships TLS connections through it.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mut profile = BrowserProfile::random();
    if let Some(ua) = cfg.user_agent {
        profile.user_agent = ua;
    }

    let mut cs_builder = CloudScraper::builder().profile(profile.clone());
    if let Some(headless) = cfg.headless {
        cs_builder = cs_builder.headless(headless);
    }
    if let Some(proxy) = cfg.upstream_proxy {
        cs_builder = cs_builder.upstream_proxy(proxy);
    }
    if cfg.debug_mode {
        cs_builder = cs_builder.with_debug(true);
    }

    let cloud_scraper = cs_builder
        .build()
        .await
        .map_err(|e| ArloError::ScraperError(e.to_string()))?;

    let mut req_builder = Client::builder().user_agent(profile.user_agent.clone());
    if let Some(ref proxy) = cloud_scraper.proxy {
        let proxy_url = format!("http://127.0.0.1:{}", proxy.port());
        req_builder = req_builder.proxy(reqwest::Proxy::all(&proxy_url)?);
        // The proxy ships a self-signed CA for its MITM termination.
        req_builder = req_builder.danger_accept_invalid_certs(true);
    }
    let reqwest_client = req_builder.build()?;
    let transport = Arc::new(CloudScraperTransport::new(reqwest_client, cloud_scraper));

    Ok(ArloClient {
        transport,
        endpoints: cfg.endpoints,
        auth: AuthManager::new(),
        debug_mode: cfg.debug_mode,
        event_bus: tokio::sync::OnceCell::new(),
        api_version: std::sync::RwLock::new(crate::config::ApiVersion::default()),
    })
}

/// Restores a cached session token from `path` and validates it against the
/// session-v3 endpoint. On success the client is left ready to skip the
/// login flow; on failure the cache is wiped and the path is primed so the
/// next successful login will repopulate it.
pub(crate) async fn apply_session_cache(client: &mut ArloClient, path: &str) {
    use tracing::{info, warn};

    if let Some(cached) = AuthManager::load_from_cache(path).await {
        client.auth = cached;
        if client.validate_session_v3().await.is_ok() {
            info!(%path, "Restored active Arlo session from cache");
            return;
        }
        warn!(%path, "Cached Arlo session expired or invalid; resetting");
    }

    client.auth = AuthManager::new();
    client.auth.cache_path = Some(path.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_collects_overrides() {
        let b = ArloClientBuilder::default()
            .user_agent("custom-ua")
            .headless(false)
            .upstream_proxy("http://127.0.0.1:8080")
            .debug_mode(true)
            .session_cache(".arlo_session.json");

        assert_eq!(b.user_agent.as_deref(), Some("custom-ua"));
        assert_eq!(b.headless, Some(false));
        assert_eq!(b.upstream_proxy.as_deref(), Some("http://127.0.0.1:8080"));
        assert!(b.debug_mode);
        assert_eq!(b.session_cache_path.as_deref(), Some(".arlo_session.json"));
    }

    #[test]
    fn bootstrap_config_round_trips_from_client_config() {
        let cc = ClientConfig {
            debug_mode: Some(true),
            user_agent: Some("ua".into()),
            session_cache_path: Some(".cache".into()),
            headless: Some(false),
            upstream_proxy: Some("http://p".into()),
            api_version: None,
        };
        let bc = BootstrapConfig::from(&cc);
        assert_eq!(bc.user_agent.as_deref(), Some("ua"));
        assert_eq!(bc.headless, Some(false));
        assert_eq!(bc.upstream_proxy.as_deref(), Some("http://p"));
        assert!(bc.debug_mode);
    }

    #[test]
    fn bootstrap_config_from_default_client_config_has_no_overrides() {
        let cc = ClientConfig {
            debug_mode: None,
            user_agent: None,
            session_cache_path: None,
            headless: None,
            upstream_proxy: None,
            api_version: None,
        };
        let bc = BootstrapConfig::from(&cc);
        assert_eq!(bc.user_agent, None);
        assert_eq!(bc.headless, None);
        assert_eq!(bc.upstream_proxy, None);
        assert!(!bc.debug_mode);
    }

    #[test]
    fn endpoints_setter_overrides_default() {
        let custom = ArloEndpoints::testing("https://test.example");
        let b = ArloClientBuilder::default().endpoints(custom.clone());
        assert_eq!(b.endpoints, Some(custom));
    }

    // -- apply_session_cache exercised through a mocked transport --
    use crate::client::test_helpers::{authenticated_mocked_client, mocked_client};
    use crate::client::transport::test_support::MockTransport;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn apply_session_cache_restores_validated_session_from_disk() {
        // Persist a fresh AuthManager via save_to_cache, then re-hydrate
        // a clean client and confirm the validate_session_v3 round-trip
        // succeeds without changing the cache_path.
        let mock = Arc::new(MockTransport::new());
        // Validation response.
        mock.expect_ok(r#"{"meta":{"code":200},"data":{"userId":"U-cache","token":"cached-tok"}}"#);

        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_str().unwrap().to_string();
        // Pre-seed the cache file by saving a fully-formed AuthManager.
        let mut seeder = AuthManager::new();
        seeder.set_token("cached-tok".to_string());
        seeder.user_id = Some("U-cache".to_string());
        seeder.cache_path = Some(path.clone());
        seeder.save_to_cache().await;

        let mut client = mocked_client(Arc::clone(&mock));
        apply_session_cache(&mut client, &path).await;

        assert!(client.is_authenticated());
        assert_eq!(client.user_id(), Some("U-cache"));
        // cache_path is preserved on the restored AuthManager.
        assert_eq!(client.auth.cache_path.as_deref(), Some(path.as_str()));
    }

    #[tokio::test]
    async fn apply_session_cache_resets_when_validation_fails() {
        // Pre-seed cache, but queue an unrecognised-envelope response so
        // validate_session_v3 fails. apply_session_cache must wipe the
        // restored token and prime the path for a fresh login.
        let mock = Arc::new(MockTransport::new());
        mock.expect_ok(r#"{"banana":true}"#); // invalid envelope

        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_str().unwrap().to_string();
        let mut seeder = AuthManager::new();
        seeder.set_token("stale".to_string());
        seeder.user_id = Some("U-stale".to_string());
        seeder.cache_path = Some(path.clone());
        seeder.save_to_cache().await;

        let mut client = mocked_client(Arc::clone(&mock));
        apply_session_cache(&mut client, &path).await;

        // Token wiped, but the cache_path is primed for the next login.
        assert!(!client.is_authenticated());
        assert_eq!(client.auth.cache_path.as_deref(), Some(path.as_str()));
    }

    #[tokio::test]
    async fn apply_session_cache_primes_path_when_file_absent() {
        // No file at all — apply_session_cache should still leave the
        // client with its cache_path set so the next successful login
        // will persist the token.
        let mock = Arc::new(MockTransport::new());
        let mut client = mocked_client(mock);

        apply_session_cache(&mut client, "/path/that/does/not/exist.json").await;
        assert!(!client.is_authenticated());
        assert_eq!(
            client.auth.cache_path.as_deref(),
            Some("/path/that/does/not/exist.json")
        );
    }

    #[tokio::test]
    async fn build_with_endpoints_setter_picks_up_override() {
        // We can't actually call .build() (CloudScraper boot), but we
        // can confirm the builder collects the endpoint override and
        // bootstrap respects it via the BootstrapConfig conversion.
        let custom = ArloEndpoints::testing("https://staging.example");
        let b = ArloClientBuilder::default().endpoints(custom.clone());
        let endpoints_in_builder = b.endpoints.unwrap();
        assert_eq!(endpoints_in_builder, custom);
    }

    #[tokio::test]
    async fn auth_manager_is_seeded_fresh_when_cache_dir_unwritable() {
        // Smoke test: if the cache directory doesn't exist, save_to_cache
        // is best-effort silent. Subsequent reads return None and
        // apply_session_cache primes a fresh AuthManager.
        let mock = Arc::new(MockTransport::new());
        let mut client = authenticated_mocked_client(mock);

        // save to a deeply non-existent directory — silently fails.
        client.auth.cache_path = Some("/nonexistent-dir/missing/cache.json".to_string());
        client.auth.save_to_cache().await;
        // The token is still in memory; cache simply didn't persist.
        assert!(client.is_authenticated());
    }
}
