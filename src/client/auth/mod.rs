//! Advanced Authentication State Machine & MFA Orchestrator.
//!
//! This module manages the complex, multi-stage OAuth flow required to authenticate against
//! modern Arlo Cloud infrastructure (`ocapi-app.arlo.com`). It natively handles:
//! - Initial credential payload submission (Base64 encoded)
//! - Parsing and triggering dynamic 2FA/MFA Email and Push challenges
//! - Orchestrating the backend continuation chain (Trust Devices, V3 Session Verification)
//!   required to generate a persistent telemetry token.
//!
//! Layout:
//! - [`AuthManager`] (this file): token + cookie-jar + `device_id` state and
//!   the `0600` session cache.
//! - `ceremony`: the raw `ocapi-app` endpoint calls (`login`, `getFactors`,
//!   `startAuth`, `finishAuth`, …, `session/v3`, `devicesupport`).
//! - `flow`: `authenticate*` orchestration, the trusted-browser fast path
//!   and the post-MFA continuation chain.
//! - `push`: the PUSH-factor polling ceremony.
//! - `session`: legacy `login/v2` and `logout`.

mod ceremony;
mod flow;
mod push;
mod session;

use crate::client::ArloClient;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::instrument;

/// Internal credentials caching layer.
///
/// Persists `access_token`, `user_id`, and generating unique `device_id`s
/// mimicking the telemetry logged by single-page Arlo Web Dashboards. The
/// access token is held in a `SecretString` so it isn't accidentally
/// formatted via `Debug` and is zeroized on drop.
#[derive(Debug, Default)]
pub struct AuthManager {
    /// Optional OAuth token, populated after successful MFA validations.
    pub(crate) access_token: Option<SecretString>,
    /// Secure user verification identifier assigned by Arlo.
    pub(crate) user_id: Option<String>,
    /// Static randomly generated hardware signature for the current instance.
    pub(crate) device_id: String,
    /// Absolute or relative path to the persistent cache disk JSON.
    pub(crate) cache_path: Option<String>,
    /// Serialised transport cookie jar — Arlo binds "trust this browser"
    /// to these cookies plus `device_id`. Opaque here; produced and
    /// consumed by [`crate::HttpTransport::export_cookies`] /
    /// [`crate::HttpTransport::import_cookies`]. Secret because the jar
    /// carries session-bearing values.
    pub(crate) cookies: Option<SecretString>,
}

#[derive(Serialize, Deserialize)]
struct AuthCacheSchema {
    access_token: Option<String>,
    user_id: Option<String>,
    device_id: String,
    /// Added after the first cache format; absent in older files.
    #[serde(default)]
    cookies: Option<String>,
}

/// Writes `bytes` to `path` with owner-only permissions (`0600`) on Unix.
/// On non-Unix the file is written with the platform default permissions.
/// Failures are intentionally swallowed — caching is best-effort.
async fn write_owner_only(path: &str, bytes: &[u8]) {
    #[cfg(unix)]
    {
        use tokio::io::AsyncWriteExt;

        let open_res = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .await;
        if let Ok(mut file) = open_res {
            let _ = file.write_all(bytes).await;
            let _ = file.flush().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = fs::write(path, bytes).await;
    }
}

impl std::fmt::Debug for AuthCacheSchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCacheSchema")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("cookies", &self.cookies.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl AuthManager {
    /// Creates a fresh authentication manager with a blank state and a randomly generated tracking device UUID.
    pub fn new() -> Self {
        Self {
            access_token: None,
            user_id: None,
            // Generate a random UUID for the device
            device_id: uuid::Uuid::new_v4().to_string(),
            cache_path: None,
            cookies: None,
        }
    }

    /// Returns the raw access token as `&str`. Use sparingly — every call
    /// site should be auditable for accidental logging or HTTP-body leaks.
    pub(crate) fn token(&self) -> Option<&str> {
        self.access_token.as_ref().map(|s| s.expose_secret())
    }

    /// True if an access token is currently held.
    pub(crate) fn has_token(&self) -> bool {
        self.access_token.is_some()
    }

    /// Replaces the held access token. The previous value is dropped (and
    /// zeroized by `secrecy`'s `ZeroizeOnDrop`).
    pub(crate) fn set_token(&mut self, token: String) {
        self.access_token = Some(SecretString::from(token));
    }

    /// Drops the held access token (zeroized by `secrecy`).
    pub(crate) fn clear_token(&mut self) {
        self.access_token = None;
    }

    /// Loads the authentication state from a JSON file path if it exists
    #[instrument(skip(path))]
    pub async fn load_from_cache(path: &str) -> Option<Self> {
        if let Ok(contents) = fs::read_to_string(path).await
            && let Ok(schema) = serde_json::from_str::<AuthCacheSchema>(&contents)
        {
            return Some(Self {
                access_token: schema.access_token.map(SecretString::from),
                user_id: schema.user_id,
                device_id: schema.device_id,
                cache_path: Some(path.to_string()),
                cookies: schema.cookies.map(SecretString::from),
            });
        }
        None
    }

    /// Flushes the active session tokens to the configured disk path.
    ///
    /// On Unix the cache file is created/truncated with mode `0600` so only
    /// the owning user can read the persisted access token.
    #[instrument(skip(self))]
    pub async fn save_to_cache(&self) {
        let Some(ref path) = self.cache_path else {
            return;
        };
        let schema = AuthCacheSchema {
            access_token: self
                .access_token
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            user_id: self.user_id.clone(),
            device_id: self.device_id.clone(),
            cookies: self.cookies.as_ref().map(|c| c.expose_secret().to_string()),
        };
        let Ok(json) = serde_json::to_string_pretty(&schema) else {
            return;
        };
        write_owner_only(path, json.as_bytes()).await;
    }
}

impl ArloClient {
    /// Snapshots the transport's cookie jar into the auth state and writes
    /// the session cache (best-effort). Every token change goes through
    /// here so the cache always carries the cookies that were current
    /// when the token was issued.
    pub(crate) async fn persist_session(&mut self) {
        if let Some(blob) = self.transport.export_cookies() {
            self.auth.cookies = Some(SecretString::from(blob));
        }
        self.auth.save_to_cache().await;
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Fixtures shared by the auth submodules' tests.

    pub(crate) fn auth_response(token: &str, user_id: &str) -> String {
        format!(
            r#"{{"meta":{{"code":200}},"data":{{"token":"{token}","userId":"{user_id}","authenticated":1}}}}"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    #[test]
    fn test_auth_manager_initialization() {
        let manager = AuthManager::new();
        assert!(!manager.has_token());
        assert!(manager.user_id.is_none());
        assert!(manager.cache_path.is_none());
        // Device ID should be a generated UUID
        assert!(!manager.device_id.is_empty());
        assert_eq!(manager.device_id.len(), 36);
    }

    fn token_str(m: &AuthManager) -> Option<&str> {
        m.token()
    }

    #[tokio::test]
    async fn test_auth_manager_cache_persistence() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp cache file");
        let cache_path = temp_file.path().to_str().unwrap().to_string();

        let mut manager = AuthManager::new();
        manager.set_token("dummy_token_123".to_string());
        manager.user_id = Some("user_001".to_string());
        manager.cache_path = Some(cache_path.clone());

        // Save to disk
        manager.save_to_cache().await;

        // Load back from disk into a fresh instance
        let loaded_manager = AuthManager::load_from_cache(&cache_path)
            .await
            .expect("Failed to load cache from disk");

        assert_eq!(token_str(&loaded_manager), Some("dummy_token_123"));
        assert_eq!(loaded_manager.user_id.unwrap(), "user_001");
        assert_eq!(loaded_manager.device_id, manager.device_id); // Device ID should persist exactly
    }

    #[tokio::test]
    async fn test_auth_manager_load_from_missing_file() {
        let result =
            AuthManager::load_from_cache("/path/that/definitely/does/not/exist.json").await;
        assert!(result.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_session_cache_is_owner_only_on_unix() {
        let temp_file = NamedTempFile::new().unwrap();
        let cache_path = temp_file.path().to_str().unwrap().to_string();
        // Drop the NamedTempFile guard so save_to_cache re-creates the file with our mode.
        drop(temp_file);

        let mut manager = AuthManager::new();
        manager.set_token("sensitive_token".into());
        manager.cache_path = Some(cache_path.clone());
        manager.save_to_cache().await;

        let mode = std::fs::metadata(&cache_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "session cache must be readable only by owner");
    }

    // ---------------------------------------------------------------
    // Full auth-flow coverage (PR 6).
    //
    // Each test queues canned MockTransport responses, calls a single
    // `impl ArloClient` method, and asserts on both the parsed result
    // and the recorded HTTP call (URL path, headers, body shape).
    // ---------------------------------------------------------------
}
