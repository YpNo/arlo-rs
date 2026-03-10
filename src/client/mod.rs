/// Pure REST API calls that don't fit into devices or auth cleanly.
pub mod api;
/// All authentication protocols, multi-factor challenges, and session caching.
pub mod auth;
/// Automated secure polling of IMAP mailboxes for MFA text extraction.
pub mod auth_imap;
/// Camera streaming, topology tracking, mode adjustments, and actuations.
pub mod devices;
/// S3 Video chunk parsing and media decryption logic.
pub mod library;
/// Raw token spoofing for connecting natively to local hubs bypassing Cloudflare.
pub mod ratls;

use crate::config::{ArloConfig, ClientConfig};
use crate::error::ArloError;
pub use auth::AuthManager;
use reqwest::Client;
use rs_cloudscraper::{BrowserProfile, CloudScraper};

/// Core REST API manager for the Arlo ecosystem.
///
/// `ArloClient` wraps a `reqwest::Client` that is configured to proxy its connection
/// identically through a headless `rs-cloudscraper` browser. This ensures that the user's
/// TLS footprint and fingerprint remain identical to a human operator, bypassing Cloudflare.
pub struct ArloClient {
    /// The tunneled HTTP client used to execute requests
    pub reqwest_client: Client,
    /// The underlying headless browser MITM engine
    pub cloud_scraper: CloudScraper,
    /// Secure state storage for tokens and user IDs
    pub auth: AuthManager,
    /// When enabled, dumps all HTTP payloads matching traces to stdout
    pub debug_mode: bool,
}

impl ArloClient {
    /// Builds a new ArloClient using default profiles
    pub async fn new() -> Result<Self, ArloError> {
        let config = ClientConfig {
            debug_mode: None,
            user_agent: None,
            session_cache_path: None,
            headless: None,
            upstream_proxy: None,
        };
        Self::with_config(&config).await
    }

    /// Builds the ArloClient bridging precise overrides to the headless browser engine.
    pub async fn with_config(config: &ClientConfig) -> Result<Self, ArloError> {
        let mut profile = BrowserProfile::random();
        if let Some(ref ua) = config.user_agent {
            profile.user_agent = ua.clone();
        }

        // 1. Initialize the stealth proxy and headless browser
        let mut builder = CloudScraper::builder().profile(profile.clone());

        if let Some(headless) = config.headless {
            builder = builder.headless(headless);
        }

        if let Some(ref proxy) = config.upstream_proxy {
            builder = builder.upstream_proxy(proxy.clone());
        }

        if let Some(debug) = config.debug_mode {
            builder = builder.with_debug(debug);
        }

        let cloud_scraper = builder
            .build()
            .await
            .map_err(|e| ArloError::ScraperError(e.to_string()))?;

        // 2. Configure our reqwest HTTP client to route through the CloudScraper's proxy
        let mut req_builder = Client::builder().user_agent(profile.user_agent.clone());

        if let Some(ref proxy) = cloud_scraper.proxy {
            let proxy_url = format!("http://127.0.0.1:{}", proxy.port());
            req_builder = req_builder.proxy(reqwest::Proxy::all(&proxy_url)?);
            req_builder = req_builder.danger_accept_invalid_certs(true); // Since it's a local MITM
        }

        let reqwest_client = req_builder.build()?;

        Ok(Self {
            reqwest_client,
            cloud_scraper,
            auth: AuthManager::new(),
            debug_mode: false,
        })
    }

    /// Enables full HTTP intercept payload logging.
    pub fn with_debug(mut self, enabled: bool) -> Self {
        self.debug_mode = enabled;
        self
    }

    /// Automatically hydrates the client configuration from a TOML file.
    /// This establishes the background proxy and sets debug modes according to the config.
    pub async fn from_config(path: &str) -> Result<Self, ArloError> {
        let config = ArloConfig::load_from_file(path)?;

        let client_conf = config.client.as_ref().cloned().unwrap_or(ClientConfig {
            debug_mode: None,
            user_agent: None,
            session_cache_path: None,
            headless: None,
            upstream_proxy: None,
        });

        // Optionally set a custom User-Agent if defined
        let mut builder = Self::with_config(&client_conf).await?;

        let session_cache_path = config
            .client
            .as_ref()
            .and_then(|c| c.session_cache_path.clone());
        if let Some(ref path) = session_cache_path {
            if let Some(cached_auth) = AuthManager::load_from_cache(path) {
                builder.auth = cached_auth;

                // Immediately validate if the token is still active
                if builder.validate_session_v3().await.is_ok() {
                    log::info!(
                        "Successfully restored active Arlo session from cache: {}",
                        path
                    );
                    return Ok(builder); // Skip redundant login overrides!
                } else {
                    log::warn!(
                        "Cached Arlo session expired or invalid. Falling back to fresh login..."
                    );
                    builder.auth = AuthManager::new();
                    builder.auth.cache_path = Some(path.clone());
                }
            } else {
                // Prime the empty auth manager with the preferred save path
                builder.auth.cache_path = Some(path.clone());
            }
        }

        // We can immediately trigger login if credentials are provided in the config
        if let Some(creds) = config.credentials
            && let (Some(email), Some(pass)) = (creds.email, creds.password)
        {
            // Ignore the error if it fails since they may need to handle MFA via CLI
            // but let's at least try the base login.
            let _ = builder.login(&email, &pass).await;
        }

        Ok(builder)
    }

    /// Automatically scans an IMAP mailbox for arriving Arlo MFA OTP codes based
    /// on the configuration defined. Spawns as a non-blocking background thread.
    pub async fn fetch_imap_otp(
        &self,
        imap_config: &crate::config::ImapConfig,
    ) -> Result<String, ArloError> {
        crate::client::auth_imap::fetch_otp(imap_config).await
    }
}
