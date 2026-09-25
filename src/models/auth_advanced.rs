use serde::{Deserialize, Serialize};

/// `session/v3` payload. `Debug` redacts the `token`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionV3Response {
    pub user_id: String,
    pub token: String,
    pub valid_for: Option<u64>,
    /// WebSocket URL of the MQTT event broker for this account/region,
    /// e.g. `wss://mqtt-cluster-z1-1.arloxcld.com:8084`. Present since
    /// the v3 migration; the modern event bus connects here (the legacy
    /// SSE `/hmsweb/client/subscribe` now returns 403). The `/mqtt`
    /// path is appended by the bus.
    pub mqtt_url: Option<String>,
}

impl std::fmt::Debug for SessionV3Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionV3Response")
            .field("user_id", &self.user_id)
            .field("token", &"[REDACTED]")
            .field("valid_for", &self.valid_for)
            .field("mqtt_url", &self.mqtt_url)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_session_v3_with_mqtt_url() {
        // Shape captured from a live v3 session/v3 response body.
        let json = r#"{"userId":"UXXX-000-00000000","token":"tok",
            "validFor":3600,"mqttUrl":"wss://mqtt-cluster-z1-1.arloxcld.com:8084"}"#;
        let s: SessionV3Response = serde_json::from_str(json).expect("parses");
        assert_eq!(
            s.mqtt_url.as_deref(),
            Some("wss://mqtt-cluster-z1-1.arloxcld.com:8084")
        );
    }

    #[test]
    fn session_v3_mqtt_url_optional() {
        let json = r#"{"userId":"U","token":"t"}"#;
        let s: SessionV3Response = serde_json::from_str(json).expect("parses");
        assert!(s.mqtt_url.is_none());
    }
}
