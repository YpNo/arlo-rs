use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CertCreateRequest {
    pub name: String,
    pub cn: String,
    pub o: String,
    pub c: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CertCreateData {
    pub certificate: String,
    pub serial_number: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CertCreateResponse {
    pub success: bool,
    pub data: Option<CertCreateData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RatlsTokenRequest {
    pub device_id: String,
}

/// RATLS bearer token for the local hub. `Debug` redacts the `token`.
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RatlsTokenData {
    pub token: String,
    pub exp: String,
    pub cert_serial_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RatlsTokenResponse {
    pub success: bool,
    pub data: Option<RatlsTokenData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HmslsListResponse {
    pub success: Option<bool>,
    // Varies depending on hub payload, we parse generic values back or define strictly later
    pub data: Option<serde_json::Value>,
}

impl std::fmt::Debug for RatlsTokenData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatlsTokenData")
            .field("token", &"[REDACTED]")
            .field("exp", &self.exp)
            .field("cert_serial_number", &self.cert_serial_number)
            .finish()
    }
}
