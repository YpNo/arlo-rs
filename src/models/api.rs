use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub device_id: String,
    pub parent_id: String,
    pub device_type: String,
    pub device_name: String,
    pub unique_id: String,
    pub state: String,
    pub mac_address: String,
    pub firm_version: String,
    pub hw_version: String,
    pub model_id: String,
    pub presigned_last_image_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesResponse {
    pub data: Vec<Device>,
    pub success: bool,
}

pub struct StreamResponse {
    pub url: String,
}

/// Dynamic payload received over SSE when `startStream` succeeds
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArloStreamPayload {
    pub url: String,
}
