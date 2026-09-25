use crate::error::ArloError;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub password: String,
    pub language: String,
    #[serde(rename = "EnvSource")]
    pub env_source: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaseResponse<T> {
    pub meta: Meta,
    pub data: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Meta {
    pub code: u32,
    pub error: Option<u32>,
    pub message: Option<String>,
}

impl Meta {
    /// True when the envelope reports success (`code == 200`).
    pub fn is_success(&self) -> bool {
        self.code == 200
    }

    /// Converts a failed envelope into [`ArloError::ApiError`], keeping
    /// `code` and `error` for [`ArloError::action`] and choosing the best
    /// message: Arlo's own, else the official web-client text for
    /// `error`, else `fallback`.
    pub fn into_error(self, fallback: &str) -> ArloError {
        let message = self
            .message
            .filter(|m| !m.is_empty())
            .or_else(|| {
                self.error
                    .and_then(crate::models::error_codes::message_for)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| fallback.to_string());
        ArloError::ApiError {
            code: self.code as i32,
            error: self.error,
            message,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponseData {
    pub token: String,
    pub user_id: String,
    pub authenticated: u64,
    pub mfa: Option<bool>,
    pub auth_completed: Option<bool>,
    #[serde(rename = "MFA_State")]
    pub mfa_state: Option<String>,
    /// Present on a successful `finishAuth`. This is the code that must
    /// be fed to `startPairingFactor` to remember the browser — it is
    /// **not** the same value as the MFA `factorAuthCode`.
    pub browser_auth_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorData {
    pub factor_id: String,
    pub factor_type: String,
    pub factor_nickname: Option<String>,
    pub factor_role: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthStartResponse {
    pub items: Vec<FactorData>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorRequest {
    pub factor_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyFactorRequest {
    pub factor_auth_code: String,
    pub otp: String,
    pub is_browser_trusted: bool,
}

/// `POST /api/startAuth` body for the **push** flow. Mirrors the Arlo
/// web client exactly: an empty `factorType` lets Arlo dispatch the
/// account's PRIMARY second factor (push, when push is primary) and
/// return its `factorAuthCode` in one round-trip.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartAuthUserRequest {
    pub factor_type: String,
    pub user_id: String,
}

/// `POST /api/finishAuth` body for the **push** flow. Note the absence
/// of an `otp` field — push approval carries no code; the web client
/// sends only these two keys and polls.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishAuthPushRequest {
    pub factor_auth_code: String,
    pub is_browser_trusted: bool,
}

/// `data` payload of a successful `POST /api/startAuth`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartAuthData {
    pub factor_auth_code: String,
    #[serde(default)]
    pub factors: Vec<SecondFactor>,
}

/// One entry of `StartAuthData::factors`. Only the discriminating
/// fields are modelled; Arlo sends more (display name, etc.).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecondFactor {
    pub factor_type: String,
    pub factor_role: Option<String>,
}

/// Represents the asynchronous state of an authentication attempt.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// The session is fully established and validated. Ready to use.
    Success,
    /// MFA is required. The flow is paused. The user must provide the OTP to `submit_mfa()`
    MfaRequired {
        factor_id: String,
        factor_auth_code: String,
        provider: String,
    },
}

/// Re-attachment payload for [`crate::ArloClient::reattach`].
///
/// Carries the persistent state needed to bypass login on a subsequent
/// process start: the access token (held in a [`SecretString`] so it is
/// zeroized on drop), the Arlo-assigned `user_id`, and the per-instance
/// `device_id` UUID. The `device_id` field matters because Arlo binds the
/// "Trust this browser" pairing to it — reusing the same UUID across
/// restarts is what extends a session token's lifetime from ~2 hours to
/// ~14 days.
///
/// Construct via [`SessionToken::new`] from a vault, env var, or any other
/// out-of-process secret store. To capture the current state from a live
/// client, use [`crate::ArloClient::session_token`].
pub struct SessionToken {
    pub(crate) access_token: SecretString,
    pub(crate) user_id: String,
    pub(crate) device_id: String,
}

impl SessionToken {
    /// Builds a session token from raw components. The access token is
    /// wrapped in a [`SecretString`] for zeroize-on-drop semantics.
    pub fn new(
        access_token: impl Into<String>,
        user_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Self {
        Self {
            access_token: SecretString::from(access_token.into()),
            user_id: user_id.into(),
            device_id: device_id.into(),
        }
    }

    /// Exposes the raw access token. Use sparingly — every call site is
    /// auditable for accidental logging or HTTP-body leaks.
    pub fn access_token(&self) -> &str {
        self.access_token.expose_secret()
    }

    /// The Arlo-assigned user ID this token is bound to.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The per-instance device-tracking UUID. Reusing the same UUID across
    /// restarts is what keeps Arlo's "Trust this browser" pairing alive.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionToken")
            .field("access_token", &"***")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_round_trips_components() {
        let t = SessionToken::new("tok", "user-1", "dev-uuid");
        assert_eq!(t.access_token(), "tok");
        assert_eq!(t.user_id(), "user-1");
        assert_eq!(t.device_id(), "dev-uuid");
    }

    #[test]
    fn session_token_debug_redacts_access_token() {
        let t = SessionToken::new("super-secret-token", "u", "d");
        let dump = format!("{t:?}");
        assert!(!dump.contains("super-secret-token"));
        assert!(dump.contains("***"));
        assert!(dump.contains("u"));
        assert!(dump.contains("d"));
    }
}
