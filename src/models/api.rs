use serde::{Deserialize, Serialize};

/// Represents a physical Arlo device (Camera, Base Station, Doorbell, Chime).
/// The fields present in the API response vary drastically depending on the physical
/// `device_type` (e.g. cameras have MAC addresses, but chimes may not).
///
/// `Debug` redacts `presigned_last_image_url`: a presigned S3 URL is a
/// bearer capability for as long as it is valid.
#[derive(Serialize, Deserialize)]
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

    /// Cloud-zone identifier. The struct's `rename_all = "camelCase"`
    /// maps this to the wire key `xCloudId`. Required as the `xcloudId`
    /// request header by the modern stream/SIP endpoints. Present on
    /// every device in `/hmsweb/v2/users/devices` since the 2025 v3
    /// migration; absent on the older `/hmsweb/users/devices` payload.
    pub x_cloud_id: Option<String>,

    /// Monotonic revision counter for this device's automation/mode
    /// state (wire key `automationRevision`). Reading it from the
    /// device list avoids an extra `activeMode` GET inside
    /// [`crate::ArloClient::set_mode`].
    pub automation_revision: Option<u64>,

    /// MQTT topics the broker's ACL grants this account for the device
    /// (wire key `allowedMqttTopics`, present on `/hmsweb/v2/users/devices`
    /// since the v3 migration; empty on the legacy list). When any device
    /// carries them they are the authoritative subscription set.
    #[serde(default)]
    pub allowed_mqtt_topics: Vec<String>,

    /// Free-form connectivity object (signal strength, online state, …).
    /// Shape varies by device class, so it's surfaced as raw JSON until
    /// a concrete consumer needs typed access.
    pub connectivity: Option<serde_json::Value>,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("device_id", &self.device_id)
            .field("parent_id", &self.parent_id)
            .field("device_type", &self.device_type)
            .field("device_name", &self.device_name)
            .field("unique_id", &self.unique_id)
            .field("state", &self.state)
            .field("mac_address", &self.mac_address)
            .field("firm_version", &self.firm_version)
            .field("hw_version", &self.hw_version)
            .field("model_id", &self.model_id)
            .field(
                "presigned_last_image_url",
                &self.presigned_last_image_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("x_cloud_id", &self.x_cloud_id)
            .field("automation_revision", &self.automation_revision)
            .field("allowed_mqtt_topics", &self.allowed_mqtt_topics)
            .field("connectivity", &self.connectivity)
            .finish()
    }
}

impl Device {
    /// True when this device hosts its own stream (no separate base
    /// station) — i.e. `parent_id == device_id`. Modern cameras
    /// (Arlo Pro 4, Essential, …) are self-hosted; older cameras hang
    /// off a `VMB*` base station whose ID is the `parent_id`.
    ///
    /// Stream/mode calls send `to: parent_id`, so callers that only
    /// have a camera ID can use this to decide whether the two are
    /// interchangeable.
    pub fn is_self_hosted(&self) -> bool {
        self.parent_id == self.device_id
    }
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

    #[test]
    fn device_deserializes_v2_payload_with_new_fields() {
        // Trimmed shape from the May-2026 /hmsweb/v2/users/devices HAR.
        let json = r#"{
            "deviceId": "A0A0000PA0E00",
            "parentId": "A0A0000PA0E00",
            "deviceType": "camera",
            "deviceName": "outdoor-camera",
            "uniqueId": "UXXX-000-00000000_A0A0000PA0E00",
            "state": "provisioned",
            "modelId": "VMC4041PA",
            "xCloudId": "z1-cloud-abc",
            "automationRevision": 1778155346339,
            "connectivity": { "signalStrength": 4, "connected": true }
        }"#;
        let dev: Device = serde_json::from_str(json).unwrap();
        assert_eq!(dev.x_cloud_id.as_deref(), Some("z1-cloud-abc"));
        assert_eq!(dev.automation_revision, Some(1778155346339));
        assert_eq!(dev.connectivity.unwrap()["signalStrength"], 4);
    }

    #[test]
    fn device_deserializes_legacy_payload_without_new_fields() {
        // Legacy /hmsweb/users/devices omits xCloudId/automationRevision.
        let json = r#"{
            "deviceId": "C1",
            "parentId": "B1",
            "deviceType": "camera",
            "deviceName": "Cam1",
            "uniqueId": "U1",
            "state": "provisioned"
        }"#;
        let dev: Device = serde_json::from_str(json).unwrap();
        assert_eq!(dev.x_cloud_id, None);
        assert_eq!(dev.automation_revision, None);
        assert_eq!(dev.connectivity, None);
    }

    fn device_with_parent(device_id: &str, parent_id: &str) -> Device {
        let json = format!(
            r#"{{"deviceId":"{device_id}","parentId":"{parent_id}",
                 "deviceType":"camera","deviceName":"n","uniqueId":"u",
                 "state":"provisioned"}}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn is_self_hosted_true_when_parent_equals_device() {
        let dev = device_with_parent("CAM-1", "CAM-1");
        assert!(dev.is_self_hosted());
    }

    #[test]
    fn is_self_hosted_false_when_behind_base_station() {
        let dev = device_with_parent("CAM-1", "VMB4500-BASE");
        assert!(!dev.is_self_hosted());
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn device_debug_redacts_presigned_url() {
        let device: Device = serde_json::from_str(
            r#"{"deviceId":"D1","parentId":"D1","deviceType":"camera","deviceName":"Front",
                "uniqueId":"U_D1","state":"provisioned",
                "presignedLastImageUrl":"https://s3.example/x?X-Amz-Signature=SIG"}"#,
        )
        .unwrap();
        let dbg = format!("{device:?}");
        assert!(
            dbg.contains("Front") && !dbg.contains("SIG") && !dbg.contains("s3.example"),
            "{dbg}"
        );
    }
}
