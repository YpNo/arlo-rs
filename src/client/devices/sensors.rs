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

/// Largest base64 payload accepted for one history response. A day of
/// 22-byte samples at one per minute is ~42 KB compressed and encoded.
const MAX_AMBIENT_HISTORY_B64: usize = 1024 * 1024;
/// Largest inflated statistics buffer (≈190 k samples). zlib inflates up
/// to ~1000:1, so the compressed size alone is no bound.
const MAX_AMBIENT_HISTORY_RAW: usize = 4 * 1024 * 1024;

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

/// Reassembles, decodes and inflates the chunked base64+zlib statistics
/// payload and returns the most recent sample. Both stages are capped.
fn decode_ambient_history(
    payload_chunks: &[String],
) -> Result<Option<AmbientSensorData>, ArloError> {
    // Reconstruct the full base64 string
    let base64_combined = payload_chunks.join("");
    if base64_combined.len() > MAX_AMBIENT_HISTORY_B64 {
        return Err(ArloError::ParseError(
            "ambient history payload exceeds size limit".into(),
        ));
    }

    // Decode base64
    let compressed_data = general_purpose::STANDARD
        .decode(&base64_combined)
        .map_err(|e| ArloError::ParseError(format!("Base64 decode failed: {}", e)))?;

    // Decompress via zlib, one byte past the cap so overflow is detectable.
    let mut decoder =
        ZlibDecoder::new(&compressed_data[..]).take(MAX_AMBIENT_HISTORY_RAW as u64 + 1);
    let mut raw_bytes = Vec::new();
    decoder
        .read_to_end(&mut raw_bytes)
        .map_err(|e| ArloError::ParseError(format!("Zlib decompression failed: {}", e)))?;
    if raw_bytes.len() > MAX_AMBIENT_HISTORY_RAW {
        return Err(ArloError::ParseError(
            "ambient history inflates past the size limit".into(),
        ));
    }

    // Parse binary statistics (based strictly on Arlo's frontend decoding)
    // Each entry is exactly 22 bytes long.
    let mut latest_point: Option<AmbientSensorData> = None;
    let mut i = 0;

    while i + 22 <= raw_bytes.len() {
        let timestamp_val = parse_statistic(&raw_bytes[i..i + 4], 0);
        let temp_val = parse_statistic(&raw_bytes[i + 8..i + 10], 1);
        let hum_val = parse_statistic(&raw_bytes[i + 14..i + 16], 1);
        let air_val = parse_statistic(&raw_bytes[i + 20..i + 22], 1);

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
            self.endpoints.api_host,
            crate::models::validate::id_segment("camera_id", camera_id)?
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
        decode_ambient_history(&payload_chunks)
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
        assert_eq!(parse_statistic(&[0, 0, 0, 100], 0), Some(100.0));
        assert_eq!(parse_statistic(&[0, 200], 1), Some(20.0));
        assert_eq!(parse_statistic(&[128, 0], 1), None); // 32768 (0x8000) is None
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

#[cfg(test)]
mod bound_tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    fn zlib_b64(raw: &[u8]) -> String {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(raw).unwrap();
        general_purpose::STANDARD.encode(enc.finish().unwrap())
    }

    #[test]
    fn decompression_bomb_is_rejected_at_the_cap() {
        // 5 MiB of zeros compresses to a few KB; it must not inflate whole.
        let bomb = zlib_b64(&vec![0u8; MAX_AMBIENT_HISTORY_RAW + 1024 * 1024]);
        let err = decode_ambient_history(&[bomb]).unwrap_err().to_string();
        assert!(err.contains("size limit"), "{err}");
    }

    #[test]
    fn oversized_base64_is_rejected_before_decoding() {
        let huge = "A".repeat(MAX_AMBIENT_HISTORY_B64 + 1);
        assert!(decode_ambient_history(&[huge]).is_err());
    }

    #[test]
    fn small_valid_payload_still_decodes() {
        // One 22-byte sample: ts=1700000000 (BE u32) at 0, temp 21.5 at 8, hum 40.0 at 14, air 12.0 at 20.
        let mut raw = vec![0u8; 22];
        raw[0..4].copy_from_slice(&1_700_000_000u32.to_be_bytes());
        raw[8..10].copy_from_slice(&215u16.to_be_bytes());
        raw[14..16].copy_from_slice(&400u16.to_be_bytes());
        raw[20..22].copy_from_slice(&120u16.to_be_bytes());
        let point = decode_ambient_history(&[zlib_b64(&raw)])
            .unwrap()
            .expect("one sample");
        assert_eq!(point.temperature, Some(21.5));
        assert_eq!(point.humidity, Some(40.0));
    }
}
