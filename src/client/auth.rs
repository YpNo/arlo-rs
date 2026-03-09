use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
use crate::headers::{ARLO_API_HOST, ARLO_AUTH_HOST};
use crate::models::auth::*;
use crate::models::auth_advanced::*;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::fs;

/// Internal credentials caching layer.
///
/// Persists `access_token`, `user_id`, and generating unique `device_id`s
/// mimicking the telemetry logged by single-page Arlo Web Dashboards.
#[derive(Debug, Default)]
pub struct AuthManager {
    /// Optional OAuth token, populated after successful MFA validations
    pub access_token: Option<String>,
    /// Secure user verification identifier assigned by Arlo
    pub user_id: Option<String>,
    /// Static randomly generated hardware signature for the current instance
    pub device_id: String,
    /// Absolute or relative path to the persistent cache disk JSON
    pub cache_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthCacheSchema {
    access_token: Option<String>,
    user_id: Option<String>,
    device_id: String,
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
        }
    }

    /// Loads the authentication state from a JSON file path if it exists
    pub fn load_from_cache(path: &str) -> Option<Self> {
        if let Ok(contents) = fs::read_to_string(path) {
            if let Ok(schema) = serde_json::from_str::<AuthCacheSchema>(&contents) {
                return Some(Self {
                    access_token: schema.access_token,
                    user_id: schema.user_id,
                    device_id: schema.device_id,
                    cache_path: Some(path.to_string()),
                });
            }
        }
        None
    }

    /// Flushes the active session tokens to the configured disk path
    pub fn save_to_cache(&self) {
        if let Some(ref path) = self.cache_path {
            let schema = AuthCacheSchema {
                access_token: self.access_token.clone(),
                user_id: self.user_id.clone(),
                device_id: self.device_id.clone(),
            };
            if let Ok(json) = serde_json::to_string_pretty(&schema) {
                let _ = fs::write(path, json);
            }
        }
    }
}

impl ArloClient {
    /// Step 1: Initiates the authentication flow with Arlo.
    /// This returns an initial token that must be used to execute the MFA process.
    pub async fn login(
        &mut self,
        email: &str,
        password: &str,
    ) -> Result<AuthResponseData, ArloError> {
        let url = format!("{}{}", ARLO_AUTH_HOST, AUTH_LOGIN);
        let payload = AuthRequest {
            email: email.to_string(),
            password: password.to_string(),
            language: "en".to_string(),
            env_source: "prod".to_string(),
        };

        let body_str = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;
        let base_response: BaseResponse<AuthResponseData> = serde_json::from_str(&body_str)?;

        if base_response.meta.code != 200 {
            return Err(ArloError::AuthError(
                base_response
                    .meta
                    .message
                    .unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        let auth_data = base_response
            .data
            .ok_or_else(|| ArloError::AuthError("No auth data returned from server".to_string()))?;

        // Cache the preliminary token so subsequent factor requests get authorized.
        self.auth.access_token = Some(auth_data.token.clone());
        self.auth.user_id = Some(auth_data.user_id.clone());
        self.auth.save_to_cache();

        Ok(auth_data)
    }

    /// Step 2: Retrieves the available 2FA factors for the account
    pub async fn get_factors(&self) -> Result<Vec<FactorData>, ArloError> {
        let url = format!("{}{}", ARLO_AUTH_HOST, AUTH_GET_FACTORS);

        // Pass a dummy () for options that have no payload
        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;

        let base_response: BaseResponse<AuthStartResponse> = serde_json::from_str(&body_str)?;

        if base_response.meta.code != 200 {
            return Err(ArloError::AuthError(
                base_response
                    .meta
                    .message
                    .unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        let data = base_response.data.ok_or_else(|| {
            ArloError::AuthError("No factor data returned from server".to_string())
        })?;

        Ok(data.factors)
    }

    /// Step 3: Starts the MFA flow by requesting an OTP on the specified factor (e.g. Email / Push)
    pub async fn start_auth(&self, factor_id: &str) -> Result<(), ArloError> {
        let url = format!("{}{}", ARLO_AUTH_HOST, AUTH_START_AUTH);
        let payload = FactorRequest {
            factor_id: factor_id.to_string(),
        };

        let body_str = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;

        let base_response: BaseResponse<()> = serde_json::from_str(&body_str)?;

        if base_response.meta.code != 200 {
            return Err(ArloError::AuthError(
                base_response
                    .meta
                    .message
                    .unwrap_or_else(|| "Failed to trigger MFA".to_string()),
            ));
        }

        Ok(())
    }

    /// Step 4: Validates the OTP and solidifies the session token for devices
    pub async fn finish_auth(
        &mut self,
        factor_id: &str,
        otp: &str,
    ) -> Result<AuthResponseData, ArloError> {
        let url = format!("{}{}", ARLO_AUTH_HOST, AUTH_FINISH_AUTH);
        let payload = VerifyFactorRequest {
            factor_id: factor_id.to_string(),
            otp: otp.to_string(),
        };

        let body_str = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;
        let base_response: BaseResponse<AuthResponseData> = serde_json::from_str(&body_str)?;

        if base_response.meta.code != 200 {
            return Err(ArloError::AuthError(
                base_response
                    .meta
                    .message
                    .unwrap_or_else(|| "Failed to verify OTP".to_string()),
            ));
        }

        let auth_data = base_response.data.ok_or_else(|| {
            ArloError::AuthError("No auth data returned after completing MFA".to_string())
        })?;

        // Cache the finalized token
        self.auth.access_token = Some(auth_data.token.clone());
        self.auth.save_to_cache();

        Ok(auth_data)
    }

    /// Step 5: (Optional) Validate an existing token against the V3 session endpoint
    pub async fn validate_session_v3(&self) -> Result<SessionV3Response, ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, AUTH_SESSION_V3);

        // This is a GET request to verify if the token is still alive
        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;

        let base_response: BaseResponse<SessionV3Response> = serde_json::from_str(&body_str)?;

        if base_response.meta.code != 200 {
            return Err(ArloError::AuthError(
                base_response
                    .meta
                    .message
                    .unwrap_or_else(|| "Failed to validate session v3".to_string()),
            ));
        }

        let session_data = base_response
            .data
            .ok_or_else(|| ArloError::AuthError("No session data returned".to_string()))?;

        Ok(session_data)
    }

    /// Retrieve Details of a Specific 2FA Factor (Requested by workfile.md)
    pub async fn get_factor_id(&self) -> Result<(), ArloError> {
        let url = format!("{}{}", ARLO_AUTH_HOST, AUTH_GET_FACTOR_ID);

        let _body_str = self.execute_request::<()>(Method::GET, &url, None).await?;

        // According to trace, body structure often discarded/ignored for this specific check,
        // we just ensure a 200 OK.
        Ok(())
    }

    /// Fallback login using the legacy V2 endpoint
    pub async fn login_v2(
        &mut self,
        email: &str,
        password: &str,
    ) -> Result<AuthResponseData, ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, AUTH_LOGIN_V2);

        let payload = AuthRequest {
            email: email.to_string(),
            password: password.to_string(),
            language: "en".to_string(),
            env_source: "prod".to_string(),
        };

        let body_str = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;
        let base_response: BaseResponse<AuthResponseData> = serde_json::from_str(&body_str)?;

        if base_response.meta.code != 200 {
            return Err(ArloError::AuthError(
                base_response
                    .meta
                    .message
                    .unwrap_or_else(|| "Failed V2 login".to_string()),
            ));
        }

        let auth_data = base_response.data.ok_or_else(|| {
            ArloError::AuthError("No auth data returned from V2 server".to_string())
        })?;

        self.auth.access_token = Some(auth_data.token.clone());
        self.auth.user_id = Some(auth_data.user_id.clone());
        self.auth.save_to_cache();

        Ok(auth_data)
    }

    /// Log the current active session out securely
    pub async fn logout(&mut self) -> Result<(), ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, AUTH_LOGOUT);

        let _body_str = self.execute_request::<()>(Method::PUT, &url, None).await?;

        // Wipe local session state
        self.auth.access_token = None;
        self.auth.user_id = None;
        self.auth.save_to_cache();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_auth_manager_initialization() {
        let manager = AuthManager::new();
        assert!(manager.access_token.is_none());
        assert!(manager.user_id.is_none());
        assert!(manager.cache_path.is_none());
        // Device ID should be a generated UUID
        assert!(!manager.device_id.is_empty());
        assert_eq!(manager.device_id.len(), 36);
    }

    #[test]
    fn test_auth_manager_cache_persistence() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp cache file");
        let cache_path = temp_file.path().to_str().unwrap().to_string();

        let mut manager = AuthManager::new();
        manager.access_token = Some("dummy_token_123".to_string());
        manager.user_id = Some("user_001".to_string());
        manager.cache_path = Some(cache_path.clone());

        // Save to disk
        manager.save_to_cache();

        // Load back from disk into a fresh instance
        let loaded_manager =
            AuthManager::load_from_cache(&cache_path).expect("Failed to load cache from disk");

        assert_eq!(loaded_manager.access_token.unwrap(), "dummy_token_123");
        assert_eq!(loaded_manager.user_id.unwrap(), "user_001");
        assert_eq!(loaded_manager.device_id, manager.device_id); // Device ID should persist exactly
    }

    #[test]
    fn test_auth_manager_load_from_missing_file() {
        let result = AuthManager::load_from_cache("/path/that/definitely/does/not/exist.json");
        assert!(result.is_none());
    }
}
