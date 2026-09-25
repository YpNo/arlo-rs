//! Ambient sensor history (temperature / humidity / air quality): the
//! zlib-compressed, base64-encoded statistics payload decoder.

use crate::client::ArloClient;
use crate::error::ArloError;
use crate::models::api::{AmbientSensorData, AmbientSensorHistoryResponse};
use base64::{Engine as _, engine::general_purpose};
use flate2::read::ZlibDecoder;
use reqwest::Method;
use std::io::Read;
use tracing::instrument;

impl ArloClient {
    /// Fetches and decodes the `ambientSensors/history` metrics for Arlo Baby monitors.
    /// Arlo compresses this historical telemetry using zlib and packages it as an array
    /// of Base64 strings, which requires careful byte-shifting to extract values.
    #[instrument(skip(self))]
    pub async fn get_ambient_sensor_history(
        &self,
        camera_id: &str,
    ) -> Result<Option<AmbientSensorData>, ArloError> {
        let url = format!(
            "{}/hmsweb/users/devices/cameras/{}/ambientSensors/history",
            self.endpoints.api_host, camera_id
        );

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;
        let response: AmbientSensorHistoryResponse = serde_json::from_str(&body_str)?;

        if !response.success {
            return Err(ArloError::ApiError {
                code: 500,
                error: None,
                message: "Failed to fetch ambient sensor history".to_string(),
            });
        }

        let payload_chunks = match response.properties.and_then(|p| p.payload) {
            Some(chunks) if !chunks.is_empty() => chunks,
            _ => return Ok(None),
        };

        // Reconstruct the full base64 string
        let base64_combined = payload_chunks.join("");

        // Decode base64
        let compressed_data = general_purpose::STANDARD
            .decode(&base64_combined)
            .map_err(|e| ArloError::ParseError(format!("Base64 decode failed: {}", e)))?;

        // Decompress via zlib
        let mut decoder = ZlibDecoder::new(&compressed_data[..]);
        let mut raw_bytes = Vec::new();
        decoder
            .read_to_end(&mut raw_bytes)
            .map_err(|e| ArloError::ParseError(format!("Zlib decompression failed: {}", e)))?;

        // Parse binary statistics (based strictly on Arlo's frontend decoding)
        // Each entry is exactly 22 bytes long.
        let mut latest_point: Option<AmbientSensorData> = None;
        let mut i = 0;

        while i + 22 <= raw_bytes.len() {
            let timestamp_val = Self::parse_statistic(&raw_bytes[i..i + 4], 0);
            let temp_val = Self::parse_statistic(&raw_bytes[i + 8..i + 10], 1);
            let hum_val = Self::parse_statistic(&raw_bytes[i + 14..i + 16], 1);
            let air_val = Self::parse_statistic(&raw_bytes[i + 20..i + 22], 1);

            if let Some(timestamp_raw) = timestamp_val {
                latest_point = Some(AmbientSensorData {
                    timestamp: (timestamp_raw * 1000.0) as u64,
                    temperature: temp_val,
                    humidity: hum_val,
                    air_quality: air_val,
                });
            }

            i += 22;
        }

        Ok(latest_point)
    }

    /// Internal helper method to process Arlo's archaic metric byte-shifting payload formats.
    fn parse_statistic(data: &[u8], scale: u8) -> Option<f32> {
        let mut val: u32 = 0;
        for &byte in data {
            val = (val << 8) + (byte as u32);
        }

        if val == 32768 {
            return None;
        }

        if scale == 0 {
            Some(val as f32)
        } else {
            Some((val as f32) / ((scale as f32) * 10.0))
        }
    }

    // --- Arlo Baby MediaPlayer Controls ---
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::devices::test_support::*;
    use crate::client::test_helpers::authenticated_mocked_client;
    use crate::error::ArloError;

    #[tokio::test]
    async fn test_parse_ambient_sensor_history_logic() {
        // We can test the static parse_statistic helper directly
        assert_eq!(ArloClient::parse_statistic(&[0, 0, 0, 100], 0), Some(100.0));
        assert_eq!(ArloClient::parse_statistic(&[0, 200], 1), Some(20.0));
        assert_eq!(ArloClient::parse_statistic(&[128, 0], 1), None); // 32768 (0x8000) is None
    }

    // -----------------------------------------------------------------
    // Device-facing API coverage (PR 6).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn get_ambient_sensor_history_returns_none_for_empty_payload() {
        let mock = arc_mock();
        mock.queue_get(r#"{"success":true,"properties":{"payload":[]}}"#);
        let client = authenticated_mocked_client(mock);
        let res = client.get_ambient_sensor_history("CAM-1").await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn get_ambient_sensor_history_errors_on_non_success() {
        let mock = arc_mock();
        mock.queue_get(r#"{"success":false}"#);
        let client = authenticated_mocked_client(mock);
        assert!(matches!(
            client.get_ambient_sensor_history("CAM-1").await,
            Err(ArloError::ApiError { .. })
        ));
    }
}
