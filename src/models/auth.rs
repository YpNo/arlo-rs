use crate::error::ArloError;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// `POST /api/auth` body. `Debug` redacts the (Base64) `password`.
#[derive(Serialize, Deserialize)]
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
        // Arlo's text is wire input: control characters stripped and
        // length-capped before it can reach a log line.
        let message = self
            .message
            .filter(|m| !m.is_empty())
            .map(|m| crate::models::redact::excerpt(&m))
            .or_else(|| {
                self.error
                    .and_then(crate::models::error_codes::message_for)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| fallback.to_string());
        ArloError::ApiError {
            code: i32::try_from(self.code).unwrap_or(i32::MAX),
            error: self.error,
            message,
        }
    }
}

/// Session payload of `auth` / `finishAuth`. `Debug` redacts the `token`,
/// which is held as a [`SecretString`] (zeroized on drop).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponseData {
    pub token: SecretString,
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

/// `POST /api/finishAuth` body (OTP flow). `Debug` redacts the `otp`.
#[derive(Serialize, Deserialize)]
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
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishAuthPushRequest {
    pub factor_auth_code: String,
    pub is_browser_trusted: bool,
}

/// `data` payload of a successful `POST /api/startAuth`. The
/// `factor_auth_code` alone yields a session once the factor is
/// approved, so it is a [`SecretString`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartAuthData {
    pub factor_auth_code: SecretString,
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

impl std::fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRequest")
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .field("language", &self.language)
            .field("env_source", &self.env_source)
            .finish()
    }
}

impl std::fmt::Debug for AuthResponseData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthResponseData")
            .field("token", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("authenticated", &self.authenticated)
            .field("mfa", &self.mfa)
            .field("auth_completed", &self.auth_completed)
            .field("mfa_state", &self.mfa_state)
            .field(
                "browser_auth_code",
                &self.browser_auth_code.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl std::fmt::Debug for VerifyFactorRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyFactorRequest")
            .field("factor_auth_code", &"[REDACTED]")
            .field("otp", &"[REDACTED]")
            .field("is_browser_trusted", &self.is_browser_trusted)
            .finish()
    }
}

/// Represents the asynchronous state of an authentication attempt.
/// `Debug` redacts `factor_auth_code`: in the push flow that code alone
/// yields the session token once the user approves.
#[derive(Clone)]
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

impl std::fmt::Debug for AuthResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthResult::Success => f.write_str("Success"),
            AuthResult::MfaRequired {
                factor_id,
                provider,
                ..
            } => f
                .debug_struct("MfaRequired")
                .field("factor_id", factor_id)
                .field("factor_auth_code", &"[REDACTED]")
                .field("provider", provider)
                .finish(),
        }
    }
}

impl std::fmt::Debug for FinishAuthPushRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinishAuthPushRequest")
            .field("factor_auth_code", &"[REDACTED]")
            .field("is_browser_trusted", &self.is_browser_trusted)
            .finish()
    }
}

impl std::fmt::Debug for StartAuthData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartAuthData")
            .field("factor_auth_code", &"[REDACTED]")
            .field("factors", &self.factors)
            .finish()
    }
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

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn debug_never_prints_secrets() {
        let req = AuthRequest {
            email: "e@x".into(),
            password: "cGFzcw==".into(),
            language: "en".into(),
            env_source: "prod".into(),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("e@x") && !dbg.contains("cGFzcw=="), "{dbg}");

        let data: AuthResponseData = serde_json::from_str(
            r#"{"token":"SECRET-TOKEN","userId":"U","authenticated":1,"browserAuthCode":"BAC"}"#,
        )
        .unwrap();
        let dbg = format!("{data:?}");
        assert!(
            !dbg.contains("SECRET-TOKEN") && !dbg.contains("BAC"),
            "{dbg}"
        );

        let v = VerifyFactorRequest {
            factor_auth_code: "FAC".into(),
            otp: "123456".into(),
            is_browser_trusted: true,
        };
        let dbg = format!("{v:?}");
        assert!(!dbg.contains("123456") && !dbg.contains("FAC"), "{dbg}");
    }

    #[test]
    fn factor_auth_code_is_redacted_everywhere_it_travels() {
        let result = AuthResult::MfaRequired {
            factor_id: "F1".into(),
            factor_auth_code: "FAC-SECRET".into(),
            provider: "EMAIL".into(),
        };
        let dbg = format!("{result:?}");
        assert!(
            dbg.contains("F1") && dbg.contains("EMAIL") && !dbg.contains("FAC-SECRET"),
            "{dbg}"
        );
        assert_eq!(format!("{:?}", AuthResult::Success), "Success");

        let data: StartAuthData =
            serde_json::from_str(r#"{"factorAuthCode":"FAC-SECRET","factors":[]}"#).unwrap();
        assert!(!format!("{data:?}").contains("FAC-SECRET"));

        let push = FinishAuthPushRequest {
            factor_auth_code: "FAC-SECRET".into(),
            is_browser_trusted: true,
        };
        let dbg = format!("{push:?}");
        assert!(
            dbg.contains("is_browser_trusted: true") && !dbg.contains("FAC-SECRET"),
            "{dbg}"
        );
    }

    #[test]
    fn into_error_strips_control_characters_from_arlo_message() {
        let meta = Meta {
            code: 401,
            error: Some(9017),
            message: Some("bad\n\x1b[31mline".into()),
        };
        let text = meta.into_error("fallback").to_string();
        assert!(!text.contains('\n') && !text.contains('\x1b'), "{text}");
        assert!(text.contains("bad") && text.contains("line"), "{text}");
    }
}
