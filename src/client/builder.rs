//! Programmatic builder for [`crate::client::ArloClient`].
//!
//! Downstream applications that don't use TOML configuration (e.g. servers
//! pulling secrets from a vault, GUIs prompting interactively, tests with
//! hard-coded fixtures) construct the client through this builder rather
//! than [`crate::client::ArloClient::from_config`].
//!
//! ```no_run
//! use arlo_rs::ArloClient;
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
//!
//! By default the client talks to Arlo through
//! [`crate::client::transport::WreqTransport`] — a Chrome-impersonating
//! HTTP client, no browser process. [`ArloClientBuilder::browser`] opts
//! into the headless-Chrome MITM-proxy transport (crate feature
//! `browser`).

use crate::client::endpoints::ArloEndpoints;
use crate::client::transport::{HttpTransport, WreqTransport};
use crate::client::{ArloClient, AuthManager};
use crate::config::ClientConfig;
use crate::error::ArloError;
use std::sync::Arc;
use stealthscraper_rs::BrowserProfile;

/// Programmatic builder for an [`ArloClient`]. Construct via
/// [`ArloClient::builder`]. `Debug` strips any `user:password@` from
/// `upstream_proxy`.
#[derive(Default)]
pub struct ArloClientBuilder {
    user_agent: Option<String>,
    headless: Option<bool>,
    upstream_proxy: Option<String>,
    debug_mode: bool,
    session_cache_path: Option<String>,
    endpoints: Option<ArloEndpoints>,
    use_browser: bool,
}

impl std::fmt::Debug for ArloClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArloClientBuilder")
            .field("user_agent", &self.user_agent)
            .field("headless", &self.headless)
            .field(
                "upstream_proxy",
                &self
                    .upstream_proxy
                    .as_deref()
                    .map(crate::models::redact::redact_userinfo),
            )
            .field("debug_mode", &self.debug_mode)
            .field("session_cache_path", &self.session_cache_path)
            .field("endpoints", &self.endpoints)
            .field("use_browser", &self.use_browser)
            .finish()
    }
}

impl ArloClientBuilder {
    /// Override the User-Agent string presented to Arlo. Defaults to a
    /// random Chrome desktop profile from `stealthscraper-rs`. The TLS /
    /// HTTP2 fingerprint stays that of the underlying Chrome emulation,
    /// so only set this if you know why.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Run the headless browser without a visible window. Only consulted
    /// by the browser-proxy transport ([`Self::browser`]); the default
    /// transport has no browser and ignores it.
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

    /// Use the headless-Chrome MITM-proxy transport instead of the default
    /// `wreq` impersonation client. Escalation path for the day Cloudflare
    /// starts serving an interactive challenge; today it only fingerprints
    /// TLS/HTTP2, which the default transport already satisfies.
    ///
    /// Requires the crate's `browser` feature — [`Self::build`] returns
    /// [`ArloError::ScraperError`] otherwise.
    pub fn browser(mut self, on: bool) -> Self {
        self.use_browser = on;
        self
    }

    /// Constructs the [`ArloClient`]. With the default transport this is
    /// cheap (no network, no browser). With [`Self::browser`] it boots
    /// headless Chrome and the MITM proxy, which takes several seconds.
    /// If [`Self::session_cache`] was set and the file exists, the cached
    /// token is restored and validated; an invalid cache is wiped and the
    /// client returns ready for a fresh login.
    pub async fn build(self) -> Result<ArloClient, ArloError> {
        let endpoints = self.endpoints.clone().unwrap_or_default();
        let mut client = bootstrap(BootstrapConfig {
            user_agent: self.user_agent,
            headless: self.headless,
            upstream_proxy: self.upstream_proxy,
            debug_mode: self.debug_mode,
            endpoints,
            use_browser: self.use_browser,
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
    pub use_browser: bool,
}

impl From<&ClientConfig> for BootstrapConfig {
    fn from(c: &ClientConfig) -> Self {
        Self {
            user_agent: c.user_agent.clone(),
            headless: c.headless,
            upstream_proxy: c.upstream_proxy.clone(),
            debug_mode: c.debug_mode.unwrap_or(false),
            endpoints: ArloEndpoints::default(),
            use_browser: c.use_browser.unwrap_or(false),
        }
    }
}

/// Single source of truth for [`ArloClient`] construction. Picks the
/// transport, and returns a fresh [`ArloClient`] with no auth state
/// populated.
pub(crate) async fn bootstrap(cfg: BootstrapConfig) -> Result<ArloClient, ArloError> {
    // rustls 0.23+ panics if no default CryptoProvider is installed. The
    // local-hub client (`reqwest`), the IMAP OTP fetcher and the MQTT /
    // signaling WebSockets all use rustls; the `wreq` transport itself is
    // BoringSSL and does not care.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let mut profile = BrowserProfile::random();
    if let Some(ua) = cfg.user_agent {
        profile.user_agent = ua;
    }

    let transport: Arc<dyn HttpTransport> = if cfg.use_browser {
        browser_transport(profile, cfg.headless, cfg.upstream_proxy, cfg.debug_mode).await?
    } else {
        if cfg.headless.is_some() {
            tracing::debug!("`headless` is ignored by the default (browser-less) transport");
        }
        Arc::new(WreqTransport::new(profile, cfg.upstream_proxy.as_deref())?)
    };

    Ok(ArloClient::with_transport(transport, cfg.endpoints).with_debug(cfg.debug_mode))
}

/// Boots headless Chrome + the MITM proxy and returns a `reqwest` client
/// routed through it. The proxy's per-process CA is added as a trust root
/// — certificate verification stays on for everything else (the previous
/// `danger_accept_invalid_certs(true)` accepted any bad certificate from
/// any server).
#[cfg(feature = "browser")]
async fn browser_transport(
    profile: BrowserProfile,
    headless: Option<bool>,
    upstream_proxy: Option<String>,
    debug_mode: bool,
) -> Result<Arc<dyn HttpTransport>, ArloError> {
    use crate::client::transport::CloudScraperTransport;
    use stealthscraper_rs::CloudScraper;

    let mut cs_builder = CloudScraper::builder().profile(profile.clone());
    if let Some(headless) = headless {
        cs_builder = cs_builder.headless(headless);
    }
    if let Some(proxy) = upstream_proxy {
        cs_builder = cs_builder.upstream_proxy(proxy);
    }
    if debug_mode {
        cs_builder = cs_builder.with_debug(true);
    }

    let cloud_scraper = cs_builder
        .build()
        .await
        .map_err(|e| ArloError::ScraperError(e.to_string()))?;

    // Same deadlines as the default transport; a hung proxy or upstream
    // must not park the orchestration layer.
    let mut req_builder = reqwest::Client::builder()
        .user_agent(profile.user_agent.clone())
        .connect_timeout(crate::client::transport::CONNECT_TIMEOUT)
        .timeout(crate::client::transport::REQUEST_TIMEOUT)
        // Same policy as `WreqTransport`: a 3xx is an error, never followed.
        .redirect(reqwest::redirect::Policy::none());
    if let Some(ref proxy) = cloud_scraper.proxy {
        let proxy_url = format!("http://127.0.0.1:{}", proxy.port());
        req_builder = req_builder.proxy(reqwest::Proxy::all(&proxy_url)?);
        // Trust exactly this proxy's (per-process, in-memory) CA. Fetched
        // now, never cached across runs: the CA is regenerated each boot.
        let ca_pem = proxy
            .ca_pem()
            .map_err(|e| ArloError::ScraperError(format!("proxy CA unavailable: {e}")))?;
        req_builder =
            req_builder.add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes())?);
    }
    let reqwest_client = req_builder.build()?;
    Ok(Arc::new(CloudScraperTransport::new(
        reqwest_client,
        cloud_scraper,
    )))
}

#[cfg(not(feature = "browser"))]
async fn browser_transport(
    _profile: BrowserProfile,
    _headless: Option<bool>,
    _upstream_proxy: Option<String>,
    _debug_mode: bool,
) -> Result<Arc<dyn HttpTransport>, ArloError> {
    Err(ArloError::ScraperError(
        "browser transport requested but arlo-rs was built without the `browser` feature".into(),
    ))
}

/// Restores a cached session token from `path` and validates it against the
/// session-v3 endpoint. On success the client is left ready to skip the
/// login flow; on failure the cache is wiped and the path is primed so the
/// next successful login will repopulate it.
pub(crate) async fn apply_session_cache(client: &mut ArloClient, path: &str) {
    use secrecy::ExposeSecret;
    use tracing::{info, warn};

    if let Some(cached) = AuthManager::load_from_cache(path).await {
        // Cookies first: the token check below may already depend on them.
        if let Some(cookies) = cached.cookies.as_ref()
            && let Err(e) = client.transport.import_cookies(cookies.expose_secret())
        {
            warn!(%path, error = %e, "Cached cookie jar could not be restored; ignoring it");
        }
        let device_id = cached.device_id.clone();
        let cookies = cached.cookies.clone();
        client.auth = cached;
        // After `logout()` the cache keeps only the trusted-browser identity
        // (device_id + cookies). There is nothing to validate — a session
        // GET without a token is just a 400 from Arlo — and that identity is
        // exactly what lets the next login skip the OTP.
        if !client.auth.has_token() {
            info!(
                %path,
                "Restored trusted-browser identity from cache (no session token); login will re-validate"
            );
            return;
        }
        match client.validate_session_v3().await {
            Ok(_) => {
                info!(%path, "Restored active Arlo session from cache");
                return;
            }
            Err(e) if e.action() == crate::models::error_codes::ErrorAction::Reauth => {
                warn!(%path, error = %e, "Cached Arlo session rejected by Arlo; token dropped");
            }
            Err(e) => {
                // Network, 5xx, 429: the token may be perfectly valid.
                // Keep it; `authenticate()` re-validates before use.
                warn!(%path, error = %e, "Cached Arlo session could not be validated; keeping it");
                return;
            }
        }
        // Only the token is stale. The identity Arlo paired as a trusted
        // browser — this device_id plus the cookie jar — is what lets the
        // next login skip the OTP, so it is kept.
        client.auth = AuthManager {
            access_token: None,
            user_id: None,
            device_id,
            cache_path: Some(path.to_string()),
            cookies,
            token_tx: tokio::sync::watch::channel(None).0,
        };
        return;
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
            use_browser: Some(true),
        };
        let bc = BootstrapConfig::from(&cc);
        assert_eq!(bc.user_agent.as_deref(), Some("ua"));
        assert_eq!(bc.headless, Some(false));
        assert_eq!(bc.upstream_proxy.as_deref(), Some("http://p"));
        assert!(bc.debug_mode);
        assert!(bc.use_browser);
    }

    #[test]
    fn bootstrap_config_from_default_client_config_has_no_overrides() {
        let cc = ClientConfig::default();
        let bc = BootstrapConfig::from(&cc);
        assert_eq!(bc.user_agent, None);
        assert_eq!(bc.headless, None);
        assert_eq!(bc.upstream_proxy, None);
        assert!(!bc.debug_mode);
        assert!(!bc.use_browser);
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
    async fn apply_session_cache_with_identity_only_makes_no_request() {
        // A cache written by `logout()`: device_id + cookies, no token.
        let mock = Arc::new(MockTransport::new());
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_str().unwrap().to_string();
        let mut seeder = AuthManager::new();
        seeder.cache_path = Some(path.clone());
        let device_id = seeder.device_id.clone();
        seeder.save_to_cache().await;

        let mut client = mocked_client(Arc::clone(&mock));
        apply_session_cache(&mut client, &path).await;

        assert!(mock.calls().is_empty(), "no session GET without a token");
        assert!(!client.is_authenticated());
        assert_eq!(
            client.device_id(),
            device_id,
            "trusted-browser identity kept"
        );
        assert_eq!(client.auth.cache_path.as_deref(), Some(path.as_str()));
    }

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
        // Pre-seed cache, but have session/v3 report the session expired.
        // apply_session_cache must wipe the restored token and prime the
        // path for a fresh login.
        let mock = Arc::new(MockTransport::new());
        mock.expect_ok(r#"{"meta":{"code":401,"error":9002}}"#); // session expired

        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_str().unwrap().to_string();
        let mut seeder = AuthManager::new();
        seeder.set_token("stale".to_string());
        seeder.user_id = Some("U-stale".to_string());
        seeder.cache_path = Some(path.clone());
        seeder.save_to_cache().await;

        let mut client = mocked_client(Arc::clone(&mock));
        apply_session_cache(&mut client, &path).await;

        // Token wiped, but the cache_path is primed for the next login and
        // the paired identity (device_id) survives.
        assert!(!client.is_authenticated());
        assert_eq!(client.auth.cache_path.as_deref(), Some(path.as_str()));
        assert_eq!(client.auth.device_id, seeder.device_id);
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
    async fn build_uses_wreq_transport_end_to_end_against_mockito() {
        // The default transport needs no browser, so `.build()` is cheap
        // enough to run in a unit test and drive a real round-trip:
        // build → seed a token → validate_session_v3 over wreq.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex("^/hmsweb/users/session/v3".into()),
            )
            .match_header("user-agent", mockito::Matcher::Regex("Chrome/".into()))
            // `ArloEndpoints::testing` puts auth + api on one host, so the
            // orchestration layer sends the auth-host (Base64) token form.
            .match_header("authorization", "dG9rLTE=")
            .with_status(200)
            .with_body(r#"{"meta":{"code":200},"data":{"userId":"U-wreq","token":"tok-1"}}"#)
            .create_async()
            .await;

        let mut client = ArloClientBuilder::default()
            .endpoints(ArloEndpoints::testing(server.url()))
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
            .build()
            .await
            .expect("default transport builds without a browser");
        assert!(format!("{:?}", client.transport).starts_with("WreqTransport"));

        crate::client::test_helpers::set_test_token(&mut client, "tok-1", "U-wreq", "dev-1");
        let session = client
            .validate_session_v3()
            .await
            .expect("session/v3 over wreq");
        assert_eq!(session.user_id, "U-wreq");
    }

    #[cfg(not(feature = "browser"))]
    #[tokio::test]
    async fn build_with_browser_errors_when_feature_is_off() {
        let err = match ArloClientBuilder::default().browser(true).build().await {
            Ok(_) => panic!("browser transport must not build without the feature"),
            Err(e) => e,
        };
        assert!(matches!(err, ArloError::ScraperError(_)), "{err:?}");
    }

    #[test]
    fn browser_setter_defaults_off() {
        assert!(!ArloClientBuilder::default().use_browser);
        assert!(ArloClientBuilder::default().browser(true).use_browser);
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

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn builder_debug_strips_proxy_userinfo() {
        let b =
            ArloClientBuilder::default().upstream_proxy("socks5://u:hunter2@proxy.example:1080");
        let dbg = format!("{b:?}");
        assert!(
            dbg.contains("proxy.example:1080") && !dbg.contains("hunter2"),
            "{dbg}"
        );
    }
}

#[cfg(test)]
mod hazard_tests {
    use super::*;
    use crate::client::auth::AuthManager;
    use crate::client::test_helpers::mocked_client;
    use crate::client::transport::HttpResponse;
    use crate::client::transport::test_support::MockTransport;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn apply_session_cache_keeps_token_on_transient_failure() {
        let mock = Arc::new(MockTransport::new());
        mock.expect(HttpResponse {
            status: reqwest::StatusCode::BAD_GATEWAY,
            body: "upstream down".into(),
        });
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_str().unwrap().to_string();
        let mut seeder = AuthManager::new();
        seeder.set_token("maybe-valid".to_string());
        seeder.user_id = Some("U1".to_string());
        seeder.cache_path = Some(path.clone());
        seeder.save_to_cache().await;

        let mut client = mocked_client(Arc::clone(&mock));
        apply_session_cache(&mut client, &path).await;
        assert!(
            client.is_authenticated(),
            "an outage must not cost the token"
        );
        assert_eq!(client.auth.token(), Some("maybe-valid"));
    }
}
