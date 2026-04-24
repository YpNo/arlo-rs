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
