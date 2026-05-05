//! Device Management, Streaming & Hardware Actuation.
//!
//! This module houses the core logic for enumerating Arlo hardware (Cameras, Base Stations)
//! and triggering physical state changes via the Arlo V3 APIs. This includes parsing ambient
//! sensor history (temperature/humidity payload decoders), initiating asynchronous video streams,
//! spawning local `FFmpeg` proxy listeners, and managing Base Station arm/disarm toggles.

use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
use crate::headers::ARLO_API_HOST;
use crate::models::api::{AmbientSensorData, AmbientSensorHistoryResponse, Device};
use base64::{Engine as _, engine::general_purpose};
use flate2::read::ZlibDecoder;
use reqwest::Method;
use serde_json::json;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use tracing::instrument;

impl ArloClient {
    /// Discovers all devices attached to the user's Arlo account.
    ///
    /// **Implementation Note:** Arlo's backend APIs for device retrieval are known to be
    /// inconsistent regarding their JSON wrappers across different accounts. This method 
    /// dynamically unwraps payloads shaped as raw arrays `[ ... ]`, or wrapped objects like
    /// `{ success: true, data: [ ... ] }` and `{ data: { devices: [ ... ] } }`.
    #[instrument(skip(self))]
    pub async fn get_devices(&self) -> Result<Vec<Device>, ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, API_DEVICES);

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;

        // Dynamically parse the wrapper
        let parsed: serde_json::Value = serde_json::from_str(&body_str)?;

        let is_success = if let Some(success) = parsed.get("success").and_then(|s| s.as_bool()) {
            success
        } else if let Some(code) = parsed
            .get("meta")
            .and_then(|m| m.get("code"))
            .and_then(|c| c.as_u64())
        {
            code == 200
        } else {
            parsed.is_array()
        };

        if !is_success {
            return Err(ArloError::AuthError(format!(
                "Failed to fetch devices. Payload: {}",
                body_str
            )));
        }

        let data_array = if parsed.is_array() {
            Some(&parsed)
        } else if let Some(data) = parsed.get("data") {
            if data.is_array() {
                Some(data)
            } else if data.is_object() {
                data.get("devices").filter(|d| d.is_array())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(array) = data_array {
            let devices: Vec<Device> = serde_json::from_value(array.clone()).map_err(|e| {
                ArloError::ParseError(format!(
                    "Failed to parse devices array: {}. Body: {}",
                    e, body_str
                ))
            })?;
            Ok(devices)
        } else {
            Ok(vec![])
        }
    }

    /// Triggers a video stream on the specified camera.
    /// Note: Arlo responds asynchronously via the SSE Event Manager with the actual stream URL.
    #[instrument(skip(self))]
    pub async fn start_stream(&self, camera_id: &str) -> Result<(), ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, API_START_STREAM);

        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
        let trans_id = uuid::Uuid::new_v4().to_string();

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

        Ok(())
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
        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
        let trans_id = uuid::Uuid::new_v4().to_string();

        let is_v2 = model_id.is_some_and(|m| m.starts_with("VMB"));

        if is_v2 {
            // V2 activeAutomations array format
            let url = format!("{}{}", ARLO_API_HOST, API_SET_MODE);
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
            let url = format!("{}{}", ARLO_API_HOST, API_SET_MODE);

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
        let user_id = self
            .auth
            .user_id
            .as_deref()
            .ok_or_else(|| ArloError::AuthError("User ID not found in session".to_string()))?;

        // Dynamically replace the {user_id} token
        let endpoint_path = API_LOCATIONS.replace("{user_id}", user_id);
        let url = format!("{}{}", ARLO_API_HOST, endpoint_path);

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;

        // Dynamically parse the wrapper
        let parsed: serde_json::Value = serde_json::from_str(&body_str)?;

        let is_success = if let Some(success) = parsed.get("success").and_then(|s| s.as_bool()) {
            success
        } else if let Some(code) = parsed
            .get("meta")
            .and_then(|m| m.get("code"))
            .and_then(|c| c.as_u64())
        {
            code == 200
        } else {
            // Some endpoints don't have wrappers and just return the array
            parsed.is_array()
        };

        if !is_success {
            return Err(ArloError::ApiError {
                code: 500,
                message: format!("Failed to fetch user locations. Payload: {}", body_str),
            });
        }

        // Extract the location data depending on where it lives
        let data_array = if parsed.is_array() {
            Some(&parsed)
        } else if let Some(data) = parsed.get("data") {
            if data.is_array() {
                Some(data)
            } else if data.is_object() {
                // Sometimes Arlo responds with { data: { locations: [...] } }
                data.get("locations").filter(|l| l.is_array())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(array) = data_array {
            let locations: Vec<crate::models::automation::Location> =
                serde_json::from_value(array.clone()).map_err(|e| {
                    ArloError::ParseError(format!(
                        "Failed to parse locations array: {}. Body: {}",
                        e, body_str
                    ))
                })?;
            Ok(locations)
        } else {
            Ok(vec![]) // Empty if no locations array was found.
        }
    }

    /// Fetches all available modes under the v3 Automation framework for a specific location
    #[instrument(skip(self))]
    pub async fn get_automation_modes(
        &self,
        location_id: &str,
    ) -> Result<Vec<crate::models::automation::AutomationMode>, ArloError> {
        let url = format!(
            "{}{}{}?locationId={}",
            ARLO_API_HOST, API_AUTOMATION_MODES, "", location_id
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
        let url = format!("{}{}", ARLO_API_HOST, API_AUTOMATION_DEFINITIONS);

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
        let url = format!("{}{}", ARLO_API_HOST, API_EMERGENCY_LOCATIONS);

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
        let url = format!("{}{}{}", ARLO_API_HOST, API_NOTIFY, device_id);

        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
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
        let url = format!("{}{}", ARLO_API_HOST, API_TAKE_SNAPSHOT);
        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
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
        let url = format!("{}{}", ARLO_API_HOST, API_FULL_SNAPSHOT);
        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
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
        let url = format!("{}{}", ARLO_API_HOST, API_START_RECORD);
        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
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
        let url = format!("{}{}", ARLO_API_HOST, API_STOP_RECORD);
        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
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
        let url = format!("{}{}", ARLO_API_HOST, API_RESTART);
        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
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
            ARLO_API_HOST, camera_id
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
        let url = format!("{}{}{}", ARLO_API_HOST, API_NOTIFY, device_id);

        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
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

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_get_devices_dynamic_parsing() {
        let mut server = Server::new_async().await;
        let mut client = ArloClient::new().await.unwrap();
        // Overwrite reqwest client to point to mockito
        client.reqwest_client = reqwest::Client::new();
        
        // Mock Raw array response
        let _m1 = server.mock("GET", "/hmsweb/users/devices")
            .with_body("[{\"deviceId\": \"C1\", \"parentId\": \"B1\", \"deviceType\": \"camera\", \"deviceName\": \"Cam1\", \"uniqueId\": \"U1\", \"state\": \"provisioned\"}]")
            .create_async()
            .await;

        let url = format!("{}/hmsweb/users/devices", server.url());
        let body_str = client.execute_request::<()>(Method::GET, &url, None).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(parsed.is_array());
    }

    #[tokio::test]
    async fn test_parse_ambient_sensor_history_logic() {
        // We can test the static parse_statistic helper directly
        assert_eq!(ArloClient::parse_statistic(&[0, 0, 0, 100], 0), Some(100.0));
        assert_eq!(ArloClient::parse_statistic(&[0, 200], 1), Some(20.0));
        assert_eq!(ArloClient::parse_statistic(&[128, 0], 1), None); // 32768 (0x8000) is None
    }
}
