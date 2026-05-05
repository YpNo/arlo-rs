use serde::{Deserialize, Serialize};

/// Represents a physical Arlo device (Camera, Base Station, Doorbell, Chime).
/// The fields present in the API response vary drastically depending on the physical 
/// `device_type` (e.g. cameras have MAC addresses, but chimes may not).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    /// Internal Arlo tracking ID (typically the serial number).
    pub device_id: String,
    /// The parent Base Station or Hub this device is attached to (same as `device_id` if it IS a hub).
    pub parent_id: String,
    /// Type classifier (e.g. `"camera"`, `"basestation"`, `"doorbell"`, `"chime"`).
    pub device_type: String,
    /// Human-readable name configured by the user.
    pub device_name: String,
    /// Compound globally unique ID assigned by Arlo Cloud.
    pub unique_id: String,
    /// Current provision state (e.g., `"provisioned"`).
    pub state: String,
    
    /// Hardware MAC Address. Omitted by Arlo on certain bridge devices or chimes.
    pub mac_address: Option<String>,
    
    /// Firmware revision string. Parsed from either `firmwareVersion` or `firm_version`.
    /// May be omitted if the device is offline or for non-camera types.
    #[serde(alias = "firmwareVersion")]
    pub firm_version: Option<String>,
    
    /// Hardware revision identifier string.
    pub hw_version: Option<String>,
    
    /// Manufacturer model identifier (e.g. `"VMC4041PA"` for Arlo Pro 4).
    pub model_id: Option<String>,
    
    /// An ephemeral AWS S3 pre-signed URL to the latest captured thumbnail.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmbientSensorData {
    pub timestamp: u64,
    pub temperature: Option<f32>,
    pub humidity: Option<f32>,
    pub air_quality: Option<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmbientSensorHistoryResponse {
    pub success: bool,
    pub properties: Option<AmbientSensorHistoryProperties>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AmbientSensorHistoryProperties {
    pub payload: Option<Vec<String>>,
}
