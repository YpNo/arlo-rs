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

/// Live-stream URL returned by [`crate::ArloClient::start_stream`].
///
/// Wraps the RTSPS / HLS / DASH URL Arlo asynchronously delivers over SSE
/// after a successful `/startStream` POST. Use [`StreamUrl::as_str`] to
/// hand the URL to `ffmpeg`, a player, or a transcoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamUrl(pub String);

impl StreamUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for StreamUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_url_as_str_returns_inner_slice() {
        let s = StreamUrl("rtsps://camera/stream".into());
        assert_eq!(s.as_str(), "rtsps://camera/stream");
    }

    #[test]
    fn stream_url_into_inner_consumes_to_owned_string() {
        let s = StreamUrl("https://hls/play.m3u8".into());
        let owned: String = s.into_inner();
        assert_eq!(owned, "https://hls/play.m3u8");
    }

    #[test]
    fn stream_url_display_emits_inner_string() {
        let s = StreamUrl("dash://manifest.mpd".into());
        assert_eq!(format!("{s}"), "dash://manifest.mpd");
    }

    #[test]
    fn stream_url_clone_and_partial_eq() {
        let a = StreamUrl("rtsp://a".into());
        let b = a.clone();
        assert_eq!(a, b);
    }
}
