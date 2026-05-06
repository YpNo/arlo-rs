//! Device Management, Streaming & Hardware Actuation.
//!
//! This module houses the core logic for enumerating Arlo hardware (Cameras, Base Stations)
//! and triggering physical state changes via the Arlo V3 APIs. This includes parsing ambient
//! sensor history (temperature/humidity payload decoders), initiating asynchronous video streams,
//! spawning local `FFmpeg` proxy listeners, and managing Base Station arm/disarm toggles.

use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
// Endpoints come from self.endpoints (PR 4 transport refactor).
use crate::models::api::{AmbientSensorData, AmbientSensorHistoryResponse, Device, StreamUrl};
use base64::{Engine as _, engine::general_purpose};
use flate2::read::ZlibDecoder;
use reqwest::Method;
use serde_json::json;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, instrument, warn};

/// Maximum time we wait for Arlo's SSE-side stream-URL response after the
/// `/startStream` POST returns 200. Empirically the URL lands within 1–3 s.
const STREAM_URL_TIMEOUT: Duration = Duration::from_secs(30);

impl ArloClient {
    /// Discovers all devices attached to the user's Arlo account.
    ///
    /// Tolerates Arlo's three response shapes via
    /// [`crate::models::envelope::unwrap_envelope_array`]: a bare array,
    /// `{ success: true, data: [...] }`, or
    /// `{ success: true, data: { devices: [...] } }`.
    #[instrument(skip(self))]
    pub async fn get_devices(&self) -> Result<Vec<Device>, ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_DEVICES);
        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;
        let arr = crate::models::envelope::unwrap_envelope_array(&body_str, "devices")?;
        serde_json::from_value(arr).map_err(|e| {
            ArloError::ParseError(format!(
                "Failed to parse devices array: {e}. Body: {body_str}"
            ))
        })
    }

    /// Triggers a live video stream on the specified camera and returns
    /// the playable URL.
    ///
    /// Arlo's `/startStream` endpoint is asynchronous: the POST itself only
    /// confirms acceptance, while the actual RTSPS / HLS / DASH URL arrives
    /// later as an SSE event correlated by `transId`. This method handles
    /// the full round-trip — it subscribes to the event bus *before*
    /// issuing the POST (closing the race where the SSE response could land
    /// faster than the subscription) and then awaits the matching event up
    /// to [`STREAM_URL_TIMEOUT`]. Returns [`ArloError::Timeout`] if no URL
    /// arrives in time, or [`ArloError::AuthError`] if the client isn't
    /// authenticated yet.
    #[instrument(skip(self))]
    pub async fn start_stream(&self, camera_id: &str) -> Result<StreamUrl, ArloError> {
        let user_id = self
            .auth
            .user_id
            .as_deref()
            .ok_or_else(|| ArloError::AuthError("Cannot start stream before login".into()))?;
        let trans_id = uuid::Uuid::new_v4().to_string();

        // Attach SSE listener BEFORE the POST.
        let bus = self.events().await?;
        let mut rx = bus.subscribe();

        let url = format!("{}{}", self.endpoints.api_host, API_START_STREAM);
        let payload = json!({
            "to": camera_id,
            "from": format!("{}_web", user_id),
            "resource": format!("cameras/{}", camera_id),
            "action": "set",
            "publishResponse": true,
            "transId": trans_id,
            "properties": {
                "activityState": "startUserStream",
                "cameraId": camera_id
            }
        });
        self.execute_request(Method::POST, &url, Some(&payload))
            .await?;

        // Drain the broadcast channel until we see our own transId carrying
        // a stream URL, or the per-call timeout expires.
        let deadline = tokio::time::Instant::now() + STREAM_URL_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(ArloError::Timeout(format!(
                    "startStream({camera_id}) did not receive a URL within {STREAM_URL_TIMEOUT:?}"
                )));
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(event)) => {
                    debug!(?event, "SSE event during startStream wait");
                    if !event_matches_trans_id(&event, &trans_id) {
                        continue;
                    }
                    if let Some(found) = extract_stream_url(&event) {
                        return Ok(StreamUrl(found));
                    }
                }
                Ok(Err(RecvError::Lagged(n))) => {
                    warn!(skipped = n, "Event bus lagged during startStream wait");
                    continue;
                }
                Ok(Err(RecvError::Closed)) => {
                    return Err(ArloError::ApiError {
                        code: 500,
                        message: "SSE bus closed before startStream URL arrived".into(),
                    });
                }
                Err(_elapsed) => {
                    return Err(ArloError::Timeout(format!(
                        "startStream({camera_id}) did not receive a URL within {STREAM_URL_TIMEOUT:?}"
                    )));
                }
            }
        }
    }

    /// Helper utility to bind a returned stream URL to a local FFmpeg daemon.
    /// This is highly resilient for recording specific Arlo RTSPS/Dash encodings to disk safely.
    pub fn spawn_ffmpeg_recorder(
        stream_url: &str,
        output_file: &str,
        user_agent: Option<&str>,
        debug: bool,
    ) -> Result<Child, ArloError> {
        let mut cmd = Command::new("ffmpeg");

        // Suppress overwhelming ffmpeg outputs unless debugging
        if !debug {
            cmd.arg("-hide_banner").arg("-loglevel").arg("error");
        }

        // Trick Cloudflare/Arlo into thinking FFmpeg is our browser matching the scraper payload
        if let Some(ua) = user_agent {
            cmd.arg("-user_agent").arg(ua);
        }

        let child = cmd
            .arg("-y") // Overwrite output safely
            .arg("-i")
            .arg(stream_url)
            .arg("-c")
            .arg("copy") // Avoid CPU-bound re-encoding
            .arg(output_file)
            .stdout(Stdio::piped())
            .stderr(if debug {
                Stdio::inherit()
            } else {
                Stdio::piped()
            })
            .spawn()
            .map_err(ArloError::IoError)?;

        Ok(child)
    }

    /// Sets the mode of a Base Station (e.g., "mode1" = armed, "mode0" = disarmed).
    /// Defaults to V3 locations-based mode setting unless a V2 Base Station is detected.
    #[instrument(skip(self))]
    pub async fn set_mode(
        &self,
        base_station_id: &str,
        mode: &str,
        model_id: Option<&str>,
    ) -> Result<(), ArloError> {
        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();

        let is_v2 = model_id.is_some_and(|m| m.starts_with("VMB"));

        if is_v2 {
            // V2 activeAutomations array format
            let url = format!("{}{}", self.endpoints.api_host, API_SET_MODE);
            let timestamp = chrono::Utc::now().timestamp_millis() as u64;

            let payload = json!({
                "activeAutomations": [
                    {
                        "deviceId": base_station_id,
                        "timestamp": timestamp,
                        "activeModes": [mode],
                        "inactiveModes": []
                    }
                ]
            });

            self.execute_request(Method::POST, &url, Some(&payload))
                .await?;
        } else {
            // Default to V3 format (via put/notify to activeMode or modes)
            // Note: In V3, modes are usually tied to 'locations', but this is the simplest direct translation of the original.
            let url = format!("{}{}", self.endpoints.api_host, API_SET_MODE);

            let payload = json!({
                "active": mode,
                "from": format!("{}_web", user_id),
                "to": base_station_id,
                "resource": "modes",
                "action": "set",
                "publishResponse": true,
                "transId": trans_id,
            });

            self.execute_request(Method::POST, &url, Some(&payload))
                .await?;
        }

        Ok(())
    }

    /// Fetches user geographic locations required by v3 automation routing.
    ///
    /// The location ID is required for many automation and mode setting endpoints (like `set_mode`).
    ///
    /// **Implementation Note:** Similar to `get_devices`, this endpoint implements dynamic
    /// JSON parsing to gracefully handle instances where Arlo omits the wrapper or wraps the
    /// `locations` array deeply inside a `data` object.
    #[instrument(skip(self))]
    pub async fn get_locations(
        &self,
    ) -> Result<Vec<crate::models::automation::Location>, ArloError> {
        let user_id = self.require_user_id()?;
        let endpoint_path = API_LOCATIONS.replace("{user_id}", user_id);
        let url = format!("{}{}", self.endpoints.api_host, endpoint_path);

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;
        let arr = crate::models::envelope::unwrap_envelope_array(&body_str, "locations")?;
        serde_json::from_value(arr).map_err(|e| {
            ArloError::ParseError(format!(
                "Failed to parse locations array: {e}. Body: {body_str}"
            ))
        })
    }

    /// Fetches all available modes under the v3 Automation framework for a specific location
    #[instrument(skip(self))]
    pub async fn get_automation_modes(
        &self,
        location_id: &str,
    ) -> Result<Vec<crate::models::automation::AutomationMode>, ArloError> {
        let url = format!(
            "{}{}{}?locationId={}",
            self.endpoints.api_host, API_AUTOMATION_MODES, "", location_id
        );

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;

        let response: crate::models::automation::ModesResponse = serde_json::from_str(&body_str)?;

        if !response.success {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Failed to fetch automation v3 modes".to_string(),
            });
        }

        Ok(response.data)
    }

    /// Retrieves legacy v2 automation definitions
    #[instrument(skip(self))]
    pub async fn get_automation_definitions(&self) -> Result<serde_json::Value, ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_AUTOMATION_DEFINITIONS);

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;

        let response: crate::models::automation::AutomationDefinitionsResponse =
            serde_json::from_str(&body_str)?;

        if !response.success {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Failed to fetch automation definitions".to_string(),
            });
        }

        Ok(response.data)
    }

    /// Retrieves emergency service locations
    pub async fn get_emergency_locations(&self) -> Result<serde_json::Value, ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_EMERGENCY_LOCATIONS);

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;

        let response: crate::models::automation::EmergencyLocationsResponse =
            serde_json::from_str(&body_str)?;

        if !response.success {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Failed to fetch emergency locations".to_string(),
            });
        }

        Ok(response.data)
    }

    /// Generic notification action generator to mimic human IoT commands
    #[instrument(skip(self, properties))]
    pub async fn notify(
        &self,
        device_id: &str,
        action: &str,
        properties: Option<serde_json::Value>,
    ) -> Result<(), ArloError> {
        let url = format!("{}{}{}", self.endpoints.api_host, API_NOTIFY, device_id);

        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();

        let payload = json!({
            "action": action,
            "resource": format!("cameras/{}", device_id),
            "publishResponse": true,
            "properties": properties.unwrap_or(json!({})),
            "from": format!("{}_web", user_id),
            "to": device_id,
            "transId": trans_id,
        });

        self.execute_request(Method::POST, &url, Some(&payload))
            .await?;

        Ok(())
    }

    /// Triggers a thumbnail snapshot from the specified camera
    pub async fn take_snapshot(&self, camera_id: &str) -> Result<(), ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_TAKE_SNAPSHOT);
        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();

        let payload = json!({
            "to": camera_id,
            "from": format!("{}_web", user_id),
            "resource": format!("cameras/{}", camera_id),
            "action": "set",
            "publishResponse": true,
            "transId": trans_id,
            "properties": {
                "activityState": "fullFrameSnapshot"
            }
        });

        self.execute_request(Method::POST, &url, Some(&payload))
            .await?;
        Ok(())
    }

    /// Triggers a high-resolution, full-frame snapshot from the specified camera
    pub async fn full_frame_snapshot(&self, camera_id: &str) -> Result<(), ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_FULL_SNAPSHOT);
        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();

        let payload = json!({
            "to": camera_id,
            "from": format!("{}_web", user_id),
            "resource": format!("cameras/{}", camera_id),
            "action": "set",
            "publishResponse": true,
            "transId": trans_id,
            "properties": {
                "activityState": "fullFrameSnapshot"
            }
        });

        self.execute_request(Method::POST, &url, Some(&payload))
            .await?;
        Ok(())
    }

    /// Starts manual video recording on the specified camera
    pub async fn start_record(&self, camera_id: &str) -> Result<(), ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_START_RECORD);
        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();

        let payload = json!({
            "to": camera_id,
            "from": format!("{}_web", user_id),
            "resource": format!("cameras/{}", camera_id),
            "action": "set",
            "publishResponse": true,
            "transId": trans_id,
            "properties": {
                "activityState": "startRecord"
            }
        });

        self.execute_request(Method::POST, &url, Some(&payload))
            .await?;
        Ok(())
    }

    /// Stops manual video recording on the specified camera
    pub async fn stop_record(&self, camera_id: &str) -> Result<(), ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_STOP_RECORD);
        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();

        let payload = json!({
            "to": camera_id,
            "from": format!("{}_web", user_id),
            "resource": format!("cameras/{}", camera_id),
            "action": "set",
            "publishResponse": true,
            "transId": trans_id,
            "properties": {
                "activityState": "stopRecord"
            }
        });

        self.execute_request(Method::POST, &url, Some(&payload))
            .await?;
        Ok(())
    }

    /// Reboots the specified device remotely
    pub async fn restart_device(&self, device_id: &str) -> Result<(), ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_RESTART);
        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();

        let payload = json!({
            "to": device_id,
            "from": format!("{}_web", user_id),
            "resource": format!("cameras/{}", device_id),
            "action": "set",
            "publishResponse": true,
            "transId": trans_id,
            "properties": {}
        });

        self.execute_request(Method::POST, &url, Some(&payload))
            .await?;
        Ok(())
    }

    /// Turns on the siren for a camera or base station
    /// Note: The `device_id` must match the parent ID (Base Station) for older models,
    /// or the camera ID for newer ones.
    pub async fn siren_on(
        &self,
        device_id: &str,
        duration: u32,
        volume: u32,
    ) -> Result<(), ArloError> {
        self.notify(
            device_id,
            "set",
            Some(json!({
                "sirenState": "on",
                "duration": duration,
                "volume": volume,
                "pattern": "alarm"
            })),
        )
        .await
    }

    /// Turns off the siren for a camera or base station
    pub async fn siren_off(&self, device_id: &str) -> Result<(), ArloError> {
        self.notify(
            device_id,
            "set",
            Some(json!({
                "sirenState": "off"
            })),
        )
        .await
    }

    /// Turns on the camera (deactivates the privacy shield)
    pub async fn turn_on(&self, camera_id: &str) -> Result<(), ArloError> {
        self.notify(
            camera_id,
            "set",
            Some(json!({
                "privacyActive": false
            })),
        )
        .await
    }

    /// Turns off the camera (activates the privacy shield)
    pub async fn turn_off(&self, camera_id: &str) -> Result<(), ArloError> {
        self.notify(
            camera_id,
            "set",
            Some(json!({
                "privacyActive": true
            })),
        )
        .await
    }

    /// Controls the spotlight on compatible cameras
    pub async fn set_spotlight(
        &self,
        camera_id: &str,
        enabled: bool,
        brightness: Option<u8>,
    ) -> Result<(), ArloError> {
        let mut properties = json!({ "enabled": enabled });
        if let Some(b) = brightness {
            // Arlo spotlight intensity is strangely mapped to 1-100 internally
            let intensity = ((b as f32 / 255.0) * 100.0) as u8;
            properties["intensity"] = json!(intensity);
        }

        self.notify(
            camera_id,
            "set",
            Some(json!({
                "spotlight": properties
            })),
        )
        .await
    }

    /// Controls the floodlight on compatible cameras (e.g., Pro 3 Floodlight)
    pub async fn set_floodlight(
        &self,
        camera_id: &str,
        enabled: bool,
        brightness: Option<u8>,
    ) -> Result<(), ArloError> {
        let mut properties = json!({ "on": enabled });
        if let Some(b) = brightness {
            let percentage = ((b as f32 / 255.0) * 100.0) as u8;
            properties["brightness1"] = json!(percentage);
            properties["brightness2"] = json!(percentage);
        }

        self.notify(
            camera_id,
            "set",
            Some(json!({
                "floodlight": properties
            })),
        )
        .await
    }

    /// Sets the nightlight properties on compatible devices (e.g., Arlo Baby)
    /// Brightness is 0-255. RGB values are 0-255. Temperature is Kelvin string ("3500").
    pub async fn set_nightlight(
        &self,
        camera_id: &str,
        enabled: bool,
        brightness: Option<u8>,
        rgb: Option<(u8, u8, u8)>,
        temperature: Option<&str>,
        mode: Option<&str>,
    ) -> Result<(), ArloError> {
        let mut properties = json!({ "enabled": enabled });

        if let Some(b) = brightness {
            properties["brightness"] = json!(b);
        }
        if let Some(m) = mode {
            properties["mode"] = json!(m);
        }
        if let Some((r, g, b)) = rgb {
            properties["rgb"] = json!({ "red": r, "green": g, "blue": b });
        }
        if let Some(temp) = temperature {
            properties["temperature"] = json!(temp);
        }

        self.notify(
            camera_id,
            "set",
            Some(json!({
                "nightLight": properties
            })),
        )
        .await
    }

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

    /// Plays a specific audio track on the Arlo Baby monitor, or resumes playback if no track is provided.
    pub async fn play_track(
        &self,
        camera_id: &str,
        track_id: Option<&str>,
        position: u32,
    ) -> Result<(), ArloError> {
        let (action, properties) = if let Some(t_id) = track_id {
            (
                "playTrack",
                Some(json!({
                    "trackId": t_id,
                    "position": position
                })),
            )
        } else {
            ("play", None)
        };

        self.notify_custom_resource(camera_id, "audioPlayback/player", action, properties)
            .await
    }

    /// Pauses the currently playing audio track on the Arlo Baby monitor.
    pub async fn pause_track(&self, camera_id: &str) -> Result<(), ArloError> {
        self.notify_custom_resource(camera_id, "audioPlayback/player", "pause", None)
            .await
    }

    /// Skips to the next audio track in the playlist.
    pub async fn next_track(&self, camera_id: &str) -> Result<(), ArloError> {
        self.notify_custom_resource(camera_id, "audioPlayback/player", "nextTrack", None)
            .await
    }

    /// Skips to the previous audio track in the playlist.
    pub async fn previous_track(&self, camera_id: &str) -> Result<(), ArloError> {
        self.notify_custom_resource(camera_id, "audioPlayback/player", "prevTrack", None)
            .await
    }

    /// Sets the speaker volume and mute status for the device.
    pub async fn set_volume(
        &self,
        camera_id: &str,
        mute: bool,
        volume: u8,
    ) -> Result<(), ArloError> {
        self.notify(
            camera_id,
            "set",
            Some(json!({
                "speaker": {
                    "mute": mute,
                    "volume": volume.min(100) // Caps at 100
                }
            })),
        )
        .await
    }

    /// Sets the camera brightness via the Arlo `set` notify endpoint.
    ///
    /// `brightness` value typically expects a range between `-2` and `2` depending on the
    /// camera model.
    pub async fn set_camera_brightness(
        &self,
        camera_id: &str,
        brightness: i8,
    ) -> Result<(), ArloError> {
        self.notify(
            camera_id,
            "set",
            Some(json!({
                "brightness": brightness
            })),
        )
        .await
    }

    /// Sets the camera's power management profile.
    ///
    /// Known expected values for `mode` include:
    /// - `1`: Best Video (Higher drain)
    /// - `2`: Optimized (Default)
    /// - `3`: Best Battery Life (Lower quality/fps)
    pub async fn set_power_save_mode(&self, camera_id: &str, mode: u8) -> Result<(), ArloError> {
        self.notify(
            camera_id,
            "set",
            Some(json!({
                "powerSaveMode": mode
            })),
        )
        .await
    }

    /// Flips or inverts the camera image vertically/horizontally.
    ///
    /// Useful if the camera is physically mounted upside down on a ceiling or soffit.
    pub async fn set_image_invert(&self, camera_id: &str, flip: bool) -> Result<(), ArloError> {
        self.notify(
            camera_id,
            "set",
            Some(json!({
                "flip": flip
            })),
        )
        .await
    }

    /// Internal generic notification action generator that allows overriding the `resource` field.
    /// This is strictly required because MediaPlayer hits `audioPlayback/player` instead of `cameras/{id}`.
    async fn notify_custom_resource(
        &self,
        device_id: &str,
        resource: &str,
        action: &str,
        properties: Option<serde_json::Value>,
    ) -> Result<(), ArloError> {
        let url = format!("{}{}{}", self.endpoints.api_host, API_NOTIFY, device_id);

        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();

        let payload = json!({
            "action": action,
            "resource": resource,
            "publishResponse": true,
            "properties": properties.unwrap_or(json!({})),
            "from": format!("{}_web", user_id),
            "to": device_id,
            "transId": trans_id,
        });

        self.execute_request(Method::POST, &url, Some(&payload))
            .await?;

        Ok(())
    }
}

/// True if `event` carries the same `transId` we sent on the `/startStream`
/// POST. Tolerant of Arlo wrapping the field in nested objects: most
/// responses put it at the top level, but we also peek inside `properties`
/// just in case.
fn event_matches_trans_id(event: &crate::models::events::ArloEvent, trans_id: &str) -> bool {
    if event.trans_id.as_deref() == Some(trans_id) {
        return true;
    }
    if let Some(props) = event.properties.as_ref()
        && props.get("transId").and_then(|v| v.as_str()) == Some(trans_id)
    {
        return true;
    }
    false
}

/// Extracts the playable stream URL from a stream-response SSE event.
/// Arlo has used both `properties.url` and `properties.streamUrl` in the
/// wild; check both before declaring no match.
fn extract_stream_url(event: &crate::models::events::ArloEvent) -> Option<String> {
    let props = event.properties.as_ref()?;
    if let Some(s) = props.get("url").and_then(|v| v.as_str()) {
        return Some(s.to_string());
    }
    if let Some(s) = props.get("streamUrl").and_then(|v| v.as_str()) {
        return Some(s.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::events::ArloEvent;
    use serde_json::Value;

    fn make_event(trans_id: Option<&str>, properties: Value) -> ArloEvent {
        ArloEvent {
            action: "is".into(),
            resource: "cameras/C1".into(),
            publish_response: None,
            properties: Some(properties),
            source: None,
            trans_id: trans_id.map(String::from),
        }
    }

    #[test]
    fn trans_id_matches_top_level() {
        let ev = make_event(Some("tid-1"), json!({}));
        assert!(event_matches_trans_id(&ev, "tid-1"));
        assert!(!event_matches_trans_id(&ev, "other"));
    }

    #[test]
    fn trans_id_matches_inside_properties() {
        let ev = make_event(None, json!({ "transId": "tid-nested" }));
        assert!(event_matches_trans_id(&ev, "tid-nested"));
    }

    #[test]
    fn trans_id_no_match_when_absent() {
        let ev = make_event(None, json!({}));
        assert!(!event_matches_trans_id(&ev, "anything"));
    }

    #[test]
    fn stream_url_extracted_from_url_key() {
        let ev = make_event(Some("t"), json!({ "url": "rtsps://camera/stream" }));
        assert_eq!(
            extract_stream_url(&ev).as_deref(),
            Some("rtsps://camera/stream")
        );
    }

    #[test]
    fn stream_url_extracted_from_stream_url_key() {
        let ev = make_event(Some("t"), json!({ "streamUrl": "https://hls/idx.m3u8" }));
        assert_eq!(
            extract_stream_url(&ev).as_deref(),
            Some("https://hls/idx.m3u8")
        );
    }

    #[test]
    fn stream_url_returns_none_when_absent() {
        let ev = make_event(Some("t"), json!({ "activityState": "idle" }));
        assert_eq!(extract_stream_url(&ev), None);
    }

    #[tokio::test]
    async fn get_devices_returns_parsed_array_through_mocked_transport() {
        // Replaces the previous "test_get_devices_dynamic_parsing" smoke test
        // that swapped reqwest::Client directly. PR 4 lets us drive the full
        // get_devices() path against a mocked transport — including the
        // envelope unwrapper.
        use crate::ArloEndpoints;
        use crate::client::transport::test_support::MockTransport;
        use std::sync::Arc;

        let mock = Arc::new(MockTransport::new());
        mock.expect_ok(
            r#"[{"deviceId":"C1","parentId":"B1","deviceType":"camera","deviceName":"Cam1","uniqueId":"U1","state":"provisioned"}]"#,
        );

        let mut client = ArloClient::with_transport(
            Arc::clone(&mock) as _,
            ArloEndpoints::testing("https://test.example"),
        );
        client.auth.set_token("dummy".to_string());

        let devices = client.get_devices().await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "C1");
    }

    #[tokio::test]
    async fn test_parse_ambient_sensor_history_logic() {
        // We can test the static parse_statistic helper directly
        assert_eq!(ArloClient::parse_statistic(&[0, 0, 0, 100], 0), Some(100.0));
        assert_eq!(ArloClient::parse_statistic(&[0, 200], 1), Some(20.0));
        assert_eq!(ArloClient::parse_statistic(&[128, 0], 1), None); // 32768 (0x8000) is None
    }
}
