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
        let is_v3 = *self.api_version.read().unwrap() == crate::config::ApiVersion::V3;

        let url_primary = if is_v3 {
            format!("{}{}", self.endpoints.api_host, API_DEVICES_V2)
        } else {
            format!("{}{}", self.endpoints.api_host, API_DEVICES)
        };

        let res = self
            .execute_request::<()>(Method::GET, &url_primary, None)
            .await;

        let body_str = match res {
            Ok(body) => body,
            Err(ArloError::HttpError { status, .. })
                if is_v3
                    && (status == reqwest::StatusCode::FORBIDDEN
                        || status == reqwest::StatusCode::NOT_FOUND) =>
            {
                warn!(
                    "get_devices v2 returned {}. Pinning client to Legacy and retrying.",
                    status
                );
                *self.api_version.write().unwrap() = crate::config::ApiVersion::Legacy;
                let url_fallback = format!("{}{}", self.endpoints.api_host, API_DEVICES);
                self.execute_request::<()>(Method::GET, &url_fallback, None)
                    .await?
            }
            Err(e) => return Err(e),
        };

        let arr = crate::models::envelope::unwrap_envelope_array(&body_str, "devices")?;
        serde_json::from_value(arr).map_err(|e| {
            ArloError::ParseError(format!(
                "Failed to parse devices array: {e}. Body: {body_str}"
            ))
        })
    }

    /// Returns the URL of an **already-active** live stream for `device`,
    /// or `Ok(None)` if nothing is currently streaming.
    ///
    /// This is a synchronous peek (`action: "get"` on `/startStream`):
    /// it does **not** trigger a new stream and the URL — if any —
    /// comes back in the POST response itself, not over SSE. Use it to
    /// pick up a stream a user started from the Arlo mobile app.
    ///
    /// Mirrors pyaarlo's `_get_stream_url`: `to` is the device's
    /// `parent_id` (the base station — equals `device_id` for
    /// self-hosted cameras), and an `xcloudId` header derived from
    /// `device.x_cloud_id` is attached. The returned URL is rewritten
    /// `rtsp://` → `rtsps://`.
    #[instrument(skip(self), fields(device = %device.device_id))]
    pub async fn get_stream_url(&self, device: &Device) -> Result<Option<StreamUrl>, ArloError> {
        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();
        let url = format!("{}{}", self.endpoints.api_host, API_START_STREAM);

        let payload = json!({
            "action": "get",
            "from": format!("{user_id}_web"),
            "to": device.parent_id,
            "resource": format!("cameras/{}", device.device_id),
            "publishResponse": true,
            "responseUrl": "",
            "transId": trans_id,
            "properties": { "cameraId": device.device_id },
        });

        let body = self
            .execute_request_with_headers(
                Method::POST,
                &url,
                Some(&payload),
                &xcloud_header(device),
            )
            .await?;

        let parsed: serde_json::Value = serde_json::from_str(&body)?;
        Ok(extract_post_response_stream_url(&parsed)
            .map(|raw| StreamUrl(rewrite_rtsp_to_rtsps(&raw))))
    }

    /// Triggers a live stream for `device` and returns its playable URL,
    /// **reusing an already-active stream when one exists** (e.g. opened
    /// from the Arlo mobile app).
    ///
    /// Cheap peek first via [`Self::get_stream_url`]; on a miss, defers
    /// to [`Self::force_start_stream`] (fresh `startUserStream` +
    /// SSE-correlated URL). Use `force_start_stream` directly to skip
    /// the reuse check.
    #[instrument(skip(self), fields(device = %device.device_id))]
    pub async fn start_stream(&self, device: &Device) -> Result<StreamUrl, ArloError> {
        if let Some(existing) = self.get_stream_url(device).await? {
            debug!(device = %device.device_id, "Reusing already-active stream");
            return Ok(existing);
        }
        self.force_start_stream(device).await
    }

    /// Always issues a fresh `startUserStream` regardless of any
    /// already-active stream, and awaits the SSE-correlated URL.
    ///
    /// Arlo's `/startStream` (`action: "set"`) is asynchronous: the
    /// POST only confirms acceptance; the real RTSPS / HLS / DASH URL
    /// arrives later as an SSE event correlated by `transId`. This
    /// subscribes to the event bus *before* the POST (closing the race
    /// where the SSE response could beat the subscription) and waits up
    /// to [`STREAM_URL_TIMEOUT`]. Returns [`ArloError::Timeout`] if no
    /// URL arrives in time, or [`ArloError::AuthError`] if not yet
    /// authenticated.
    #[instrument(skip(self), fields(device = %device.device_id))]
    pub async fn force_start_stream(&self, device: &Device) -> Result<StreamUrl, ArloError> {
        let user_id = self
            .auth
            .user_id
            .as_deref()
            .ok_or_else(|| ArloError::AuthError("Cannot start stream before login".into()))?
            .to_string();
        let camera_id = &device.device_id;
        let trans_id = uuid::Uuid::new_v4().to_string();

        // Attach SSE listener BEFORE the POST.
        let bus = self.events().await?;
        let mut rx = bus.subscribe();

        let url = format!("{}{}", self.endpoints.api_host, API_START_STREAM);
        let payload = json!({
            "to": device.parent_id,
            "from": format!("{user_id}_web"),
            "resource": format!("cameras/{camera_id}"),
            "action": "set",
            "publishResponse": true,
            "transId": trans_id,
            "properties": {
                "activityState": "startUserStream",
                "cameraId": camera_id
            }
        });
        self.execute_request_with_headers(
            Method::POST,
            &url,
            Some(&payload),
            &xcloud_header(device),
        )
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
                        return Ok(StreamUrl(rewrite_rtsp_to_rtsps(&found)));
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

    /// Sets the mode of a Base Station (e.g., `"armed"`, `"disarmed"`,
    /// or a user-defined mode UUID).
    ///
    /// **Default path is V3 (`/hmsweb/automation/v3/activeMode`).**
    /// Falls back to the legacy `/hmsweb/users/devices/automation/active`
    /// path on 403/404, or unconditionally when:
    /// - `model_id` starts with `"VMB"` (older base stations that
    ///   never supported v3), or
    /// - the per-instance `api_version` is pinned to
    ///   [`crate::config::ApiVersion::Legacy`].
    ///
    /// ## V3 payload shape
    ///
    /// Per the May-2026 Arlo portal HAR and
    /// <https://github.com/twrecked/pyaarlo/issues/195>, every V3
    /// activeMode PUT wraps the target mode in the `"custom"` envelope:
    ///
    /// ```jsonc
    /// { "mode": "custom",
    ///   "custom": { "<device_id>": "<mode_name_or_uuid>" } }
    /// ```
    ///
    /// Both predefined modes (`"armed"`, `"disarmed"`) and user-defined
    /// mode UUIDs are valid values inside `custom.<device_id>`.
    ///
    /// ## Single-device scope (known limitation)
    ///
    /// In the wild, the `custom` map can cover every device at the
    /// location. This implementation only sets the mode for
    /// `base_station_id`; siblings keep their prior mode. A multi-device
    /// signature (`set_modes(&[(device_id, mode), …])`) is on the
    /// roadmap once we have a real multi-camera test account.
    /// TODO(streamer-app): expose a `set_modes` batch API.
    #[instrument(skip(self))]
    pub async fn set_mode(
        &self,
        base_station_id: &str,
        mode: &str,
        model_id: Option<&str>,
    ) -> Result<(), ArloError> {
        let is_v3 = *self.api_version.read().unwrap() == crate::config::ApiVersion::V3;
        let is_v2_model = model_id.is_some_and(|m| m.starts_with("VMB"));

        if is_v3 && !is_v2_model {
            match self.try_set_mode_v3(base_station_id, mode).await {
                Ok(()) => return Ok(()),
                Err(SetModeV3Outcome::Fallback) => {
                    // Already logged + api_version downgraded inside the helper.
                }
                Err(SetModeV3Outcome::Error(e)) => return Err(e),
            }
        }

        // ----- Legacy path -----
        self.set_mode_legacy(base_station_id, mode, is_v2_model)
            .await
    }

    /// Inner V3 attempt. Returns:
    /// - `Ok(())` if the PUT succeeded.
    /// - `Err(SetModeV3Outcome::Fallback)` if the V3 endpoints returned
    ///   403/404 or the location couldn't be resolved — caller continues
    ///   on the legacy path with `api_version` already pinned to Legacy.
    /// - `Err(SetModeV3Outcome::Error(_))` to bubble up real transport
    ///   / parse errors.
    async fn try_set_mode_v3(
        &self,
        base_station_id: &str,
        mode: &str,
    ) -> Result<(), SetModeV3Outcome> {
        let locations = match self.get_locations().await {
            Ok(l) => l,
            Err(_) => return Err(SetModeV3Outcome::Fallback),
        };
        let Some(loc) = locations.first() else {
            return Err(SetModeV3Outcome::Fallback);
        };

        let get_url = format!(
            "{}{}?locationId={}",
            self.endpoints.api_host, API_AUTOMATION_ACTIVE_MODE, loc.id
        );

        let revision = match self
            .execute_request::<()>(Method::GET, &get_url, None)
            .await
        {
            Ok(body) => match extract_active_mode_revision(&body, &loc.id) {
                Some(r) => r,
                None => {
                    warn!(
                        "V3 activeMode GET succeeded but revision could not be extracted; \
                         falling back to legacy."
                    );
                    *self.api_version.write().unwrap() = crate::config::ApiVersion::Legacy;
                    return Err(SetModeV3Outcome::Fallback);
                }
            },
            Err(ArloError::HttpError { status, .. })
                if status == reqwest::StatusCode::FORBIDDEN
                    || status == reqwest::StatusCode::NOT_FOUND =>
            {
                warn!(
                    "V3 activeMode GET returned {}. Pinning client to Legacy.",
                    status
                );
                *self.api_version.write().unwrap() = crate::config::ApiVersion::Legacy;
                return Err(SetModeV3Outcome::Fallback);
            }
            Err(e) => return Err(SetModeV3Outcome::Error(e)),
        };

        let put_url = format!(
            "{}{}?locationId={}&revision={}",
            self.endpoints.api_host, API_AUTOMATION_ACTIVE_MODE, loc.id, revision
        );
        // V3 wire shape — always `{"mode":"custom","custom":{<id>:<mode>}}`.
        // The leaf value is the mode name (`"armed"`/`"disarmed"`) or a
        // user-defined mode UUID; Arlo accepts both.
        let payload = json!({
            "mode": "custom",
            "custom": { base_station_id: mode },
        });

        match self
            .execute_request(Method::PUT, &put_url, Some(&payload))
            .await
        {
            Ok(_) => Ok(()),
            Err(ArloError::HttpError { status, .. })
                if status == reqwest::StatusCode::FORBIDDEN
                    || status == reqwest::StatusCode::NOT_FOUND =>
            {
                warn!(
                    "V3 activeMode PUT returned {}. Pinning client to Legacy.",
                    status
                );
                *self.api_version.write().unwrap() = crate::config::ApiVersion::Legacy;
                Err(SetModeV3Outcome::Fallback)
            }
            Err(e) => Err(SetModeV3Outcome::Error(e)),
        }
    }

    /// Legacy `set_mode` path retained for backward compatibility.
    /// Two payload shapes:
    /// - V2 base stations (`VMB*` models) use the `activeAutomations`
    ///   array format on `/hmsweb/users/devices/automation/active`.
    /// - Everything else uses the notify-style payload on the same path.
    async fn set_mode_legacy(
        &self,
        base_station_id: &str,
        mode: &str,
        is_v2_model: bool,
    ) -> Result<(), ArloError> {
        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();
        let url = format!("{}{}", self.endpoints.api_host, API_SET_MODE);

        let payload = if is_v2_model {
            let timestamp = chrono::Utc::now().timestamp_millis() as u64;
            json!({
                "activeAutomations": [{
                    "deviceId": base_station_id,
                    "timestamp": timestamp,
                    "activeModes": [mode],
                    "inactiveModes": []
                }]
            })
        } else {
            json!({
                "active": mode,
                "from": format!("{user_id}_web"),
                "to": base_station_id,
                "resource": "modes",
                "action": "set",
                "publishResponse": true,
                "transId": trans_id,
            })
        };

        self.execute_request(Method::POST, &url, Some(&payload))
            .await?;
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

/// Outcome of a `set_mode` V3 attempt.
///
/// `Fallback` means the caller should continue on the legacy path with
/// `api_version` already pinned to [`crate::config::ApiVersion::Legacy`].
/// `Error` propagates a real transport/parse failure straight to the
/// caller of `set_mode`.
enum SetModeV3Outcome {
    Fallback,
    Error(ArloError),
}

/// Extracts the `revision` from a v3 `activeMode` GET response.
///
/// The wire shape (verified May-2026 HAR) keys `data` by automation
/// UUID — typically the `locationId` is one of the keys, but Arlo also
/// returns sibling automation UUIDs:
///
/// ```jsonc
/// { "success": true, "data": {
///     "<location_id>": { "properties": {…}, "revision": 1778… },
///     "<sibling_uuid>": { "properties": {…}, "revision": 1778… }
/// }}
/// ```
///
/// Strategy: prefer the exact `data.<location_id>.revision`. If Arlo
/// has issued a different keying (e.g. an automation UUID that isn't
/// the location ID), fall back to the **first** child object's
/// `revision`. Returns `None` if no revision can be found.
fn extract_active_mode_revision(body: &str, location_id: &str) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let data = value.get("data")?;

    if let Some(rev) = data
        .get(location_id)
        .and_then(|v| v.get("revision"))
        .and_then(|v| v.as_u64())
    {
        return Some(rev);
    }
    // Fallback: scan any keyed object for a `revision` field.
    data.as_object()?
        .values()
        .find_map(|v| v.get("revision").and_then(|r| r.as_u64()))
}

/// Builds the `xcloudId` header pair for stream requests, mirroring
/// pyaarlo. If the device has no `xCloudId` (legacy `/users/devices`
/// payload) the header is omitted entirely — Arlo tolerates its
/// absence on the legacy stream path.
pub(crate) fn xcloud_header(device: &Device) -> Vec<(String, String)> {
    match device.x_cloud_id.as_deref() {
        Some(id) if !id.is_empty() => vec![("xcloudId".to_string(), id.to_string())],
        _ => Vec::new(),
    }
}

/// Rewrites a leading `rtsp://` to `rtsps://` (TLS), matching the Arlo
/// web client. Leaves `rtsps://`, `https://` (HLS/DASH), and anything
/// else untouched. `strip_prefix` guarantees we only touch the exact
/// `rtsp://` scheme, never `rtsps://`.
fn rewrite_rtsp_to_rtsps(url: &str) -> String {
    match url.strip_prefix("rtsp://") {
        Some(rest) => format!("rtsps://{rest}"),
        None => url.to_string(),
    }
}

/// Extracts a stream URL from a synchronous `action: "get"` /startStream
/// response. Tolerant of the same envelope variants as the rest of the
/// API: a bare `{"url": …}`, `{"data": {"url": …}}`, or
/// `{"success": true, "data": {"url": …}}`. An empty or missing `url`
/// means "no active stream" → `None`.
fn extract_post_response_stream_url(value: &serde_json::Value) -> Option<String> {
    let pick = |v: &serde_json::Value| -> Option<String> {
        v.get("url")
            .and_then(|u| u.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };
    if let Some(u) = pick(value) {
        return Some(u);
    }
    pick(value.get("data")?)
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

    // -----------------------------------------------------------------
    // Device-facing API coverage (PR 6).
    // -----------------------------------------------------------------

    use crate::client::test_helpers::{authenticated_mocked_client, parse_body_json};
    use crate::client::transport::test_support::MockTransport;
    use std::sync::Arc;

    fn arc_mock() -> Arc<MockTransport> {
        Arc::new(MockTransport::new())
    }

    #[tokio::test]
    async fn get_devices_handles_wrapped_data_array() {
        let mock = arc_mock();
        mock.queue_get(
            r#"{"success":true,"data":[
                {"deviceId":"C1","parentId":"B1","deviceType":"camera","deviceName":"Cam1","uniqueId":"U1","state":"provisioned"}
            ]}"#,
        );
        let client = authenticated_mocked_client(mock);
        let devices = client.get_devices().await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "C1");
    }

    #[tokio::test]
    async fn get_devices_handles_double_wrapped_data_devices_array() {
        let mock = arc_mock();
        mock.queue_get(
            r#"{"success":true,"data":{"devices":[
                {"deviceId":"D2","parentId":"B1","deviceType":"basestation","deviceName":"Hub","uniqueId":"U2","state":"provisioned"}
            ]}}"#,
        );
        let client = authenticated_mocked_client(mock);
        let devices = client.get_devices().await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_type, "basestation");
    }

    #[tokio::test]
    async fn get_locations_returns_parsed_locations() {
        let mock = arc_mock();
        mock.queue_get(
            r#"{"success":true,"data":[
                {"id":"loc-1","name":"Home","longitude":-1.23,"latitude":4.56}
            ]}"#,
        );
        let client = authenticated_mocked_client(Arc::clone(&mock));
        let locs = client.get_locations().await.unwrap();
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].id, "loc-1");
        // URL templating fills in {user_id}.
        assert!(mock.calls()[0].url.contains("/U-test/locations"));
    }

    #[tokio::test]
    async fn get_locations_handles_nested_locations_key() {
        let mock = arc_mock();
        mock.queue_get(
            r#"{"success":true,"data":{"locations":[
                {"id":"loc-1","name":"Home"}
            ]}}"#,
        );
        let client = authenticated_mocked_client(mock);
        let locs = client.get_locations().await.unwrap();
        assert_eq!(locs.len(), 1);
    }

    #[tokio::test]
    async fn get_locations_errors_when_unauthenticated() {
        let mock = arc_mock();
        // Don't queue a response — request shouldn't reach the transport.
        let client = crate::client::test_helpers::mocked_client(Arc::clone(&mock));
        let err = client.get_locations().await.unwrap_err();
        assert!(matches!(err, ArloError::AuthError(_)));
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn get_automation_modes_returns_typed_modes() {
        let mock = arc_mock();
        mock.queue_get(
            r#"{"success":true,"data":[
                {"id":"mode1","name":"Armed","features":{"alarm":true}}
            ]}"#,
        );
        let client = authenticated_mocked_client(mock);
        let modes = client.get_automation_modes("loc-1").await.unwrap();
        assert_eq!(modes.len(), 1);
        assert_eq!(modes[0].name, "Armed");
    }

    #[tokio::test]
    async fn get_automation_modes_errors_on_failure() {
        let mock = arc_mock();
        mock.queue_get(r#"{"success":false,"data":[]}"#);
        let client = authenticated_mocked_client(mock);
        assert!(matches!(
            client.get_automation_modes("loc-1").await,
            Err(ArloError::ApiError { .. })
        ));
    }

    #[tokio::test]
    async fn get_automation_definitions_returns_raw_value() {
        let mock = arc_mock();
        mock.queue_get(r#"{"success":true,"data":{"foo":"bar"}}"#);
        let client = authenticated_mocked_client(mock);
        let v = client.get_automation_definitions().await.unwrap();
        assert_eq!(v["foo"], "bar");
    }

    #[tokio::test]
    async fn get_emergency_locations_returns_raw_value() {
        let mock = arc_mock();
        mock.queue_get(r#"{"success":true,"data":["address-1"]}"#);
        let client = authenticated_mocked_client(mock);
        let v = client.get_emergency_locations().await.unwrap();
        assert!(v.is_array());
    }

    #[tokio::test]
    async fn set_mode_legacy_v3_path_emits_notify_payload() {
        let mock = arc_mock();
        mock.queue_post("{}");

        let client = authenticated_mocked_client(Arc::clone(&mock));
        *client.api_version.write().unwrap() = crate::config::ApiVersion::Legacy;
        client.set_mode("base-1", "mode1", None).await.unwrap();

        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["active"], "mode1");
        assert_eq!(body["to"], "base-1");
        assert_eq!(body["from"], "U-test_web");
        assert_eq!(body["resource"], "modes");
        assert_eq!(body["action"], "set");
    }

    #[tokio::test]
    async fn set_mode_v3_active_mode_emits_put_payload() {
        // Verifies the V3 happy path using the **real** wire shape from
        // the May-2026 portal HAR:
        //   - `data` is keyed by automation UUID (typically the location
        //     ID); `revision` is one nested level down.
        //   - PUT body always wraps in `{"mode":"custom","custom":{…}}`.
        let mock = arc_mock();
        // 1. get_locations -> bare array data
        mock.queue_get(r#"{"meta":{"code":200},"data":[{"id":"loc-123","name":"Home"}]}"#);
        // 2. GET activeMode -> data keyed by location UUID, with revision nested
        mock.queue_get(
            r#"{"meta":{"code":200},"data":{
                "loc-123": {"properties":{"mode":"custom","custom":{"base-1":"disarmed"}},"revision":42},
                "sibling-uuid": {"properties":{"mode":"standby"},"revision":99}
            }}"#,
        );
        // 3. PUT activeMode -> OPTIONS preflight + PUT body
        mock.queue_post(r#"{"meta":{"code":200}}"#);

        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_mode("base-1", "armed", None).await.unwrap();

        let calls = mock.calls();
        assert_eq!(
            calls.len(),
            4,
            "GET locations, GET activeMode, OPTIONS, PUT"
        );

        assert!(calls[0].url.contains("/locations"));
        assert!(calls[1].url.contains("/activeMode?locationId=loc-123"));
        let put_call = &calls[3];
        assert_eq!(put_call.method, Method::PUT);
        assert!(
            put_call
                .url
                .contains("/activeMode?locationId=loc-123&revision=42"),
            "PUT URL must carry the location's revision: {}",
            put_call.url
        );
        let body = parse_body_json(put_call.body.as_ref());
        // The mandatory v3 `custom` envelope — never the bare `{"mode": …}`.
        assert_eq!(body["mode"], "custom");
        assert_eq!(body["custom"]["base-1"], "armed");
    }

    #[tokio::test]
    async fn set_mode_v3_emits_custom_envelope_for_user_defined_uuid() {
        // Same wire shape regardless of whether `mode` is a predefined
        // name ("armed"/"disarmed") or a 36-char user-defined UUID.
        let mock = arc_mock();
        mock.queue_get(r#"{"meta":{"code":200},"data":[{"id":"loc-x","name":"Home"}]}"#);
        mock.queue_get(
            r#"{"meta":{"code":200},"data":{"loc-x":{"properties":{"mode":"custom"},"revision":5}}}"#,
        );
        mock.queue_post(r#"{"meta":{"code":200}}"#);

        let custom_mode_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client
            .set_mode("base-x", custom_mode_uuid, None)
            .await
            .unwrap();

        let body = parse_body_json(mock.calls()[3].body.as_ref());
        assert_eq!(body["mode"], "custom");
        assert_eq!(body["custom"]["base-x"], custom_mode_uuid);
    }

    #[tokio::test]
    async fn set_mode_v3_pins_legacy_on_404_and_runs_legacy_path() {
        // The V3 activeMode GET returns 404 → api_version flips to
        // Legacy → set_mode falls through to the legacy notify-style
        // POST. Confirms the fallback works end-to-end.
        let mock = arc_mock();
        mock.queue_get(r#"{"meta":{"code":200},"data":[{"id":"loc-1","name":"Home"}]}"#);
        // GET activeMode 404
        mock.expect(crate::client::transport::HttpResponse {
            status: reqwest::StatusCode::NOT_FOUND,
            body: "".into(),
        });
        // Legacy POST (preflight + body)
        mock.queue_post("{}");

        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_mode("base-1", "armed", None).await.unwrap();

        // Per-client api_version is now Legacy.
        assert_eq!(
            *client.api_version.read().unwrap(),
            crate::config::ApiVersion::Legacy
        );
        let calls = mock.calls();
        // get_locations(GET) + activeMode(GET 404) + legacy(OPTIONS + POST) = 4
        assert_eq!(calls.len(), 4);
        let legacy_body = parse_body_json(calls[3].body.as_ref());
        assert_eq!(legacy_body["resource"], "modes");
        assert_eq!(legacy_body["action"], "set");
    }

    #[test]
    fn extract_active_mode_revision_prefers_exact_location_match() {
        let body = r#"{"data":{
            "loc-A":{"revision":100},
            "loc-B":{"revision":200}
        }}"#;
        assert_eq!(
            super::extract_active_mode_revision(body, "loc-A"),
            Some(100)
        );
        assert_eq!(
            super::extract_active_mode_revision(body, "loc-B"),
            Some(200)
        );
    }

    #[test]
    fn extract_active_mode_revision_falls_back_to_any_sibling() {
        // Arlo sometimes keys data by an automation UUID that isn't the
        // location ID we passed. Helper should still find a revision.
        let body = r#"{"data":{
            "some-other-uuid":{"revision":777}
        }}"#;
        assert_eq!(
            super::extract_active_mode_revision(body, "loc-missing"),
            Some(777)
        );
    }

    #[test]
    fn extract_active_mode_revision_returns_none_when_absent() {
        assert_eq!(super::extract_active_mode_revision(r#"{}"#, "x"), None);
        assert_eq!(
            super::extract_active_mode_revision(r#"{"data":null}"#, "x"),
            None
        );
        assert_eq!(
            super::extract_active_mode_revision(r#"{"data":{"x":{}}}"#, "x"),
            None
        );
    }

    #[tokio::test]
    async fn set_mode_v2_path_emits_active_automations_array() {
        let mock = arc_mock();
        mock.queue_post("{}");

        let client = authenticated_mocked_client(Arc::clone(&mock));
        client
            .set_mode("base-1", "mode1", Some("VMB4500"))
            .await
            .unwrap();

        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert!(body["activeAutomations"].is_array());
        assert_eq!(body["activeAutomations"][0]["deviceId"], "base-1");
        assert_eq!(body["activeAutomations"][0]["activeModes"][0], "mode1");
    }

    /// Asserts the standard `notify`-style payload shape that every
    /// camera-control command emits: `to`, `from`, `resource`,
    /// `action`, `publishResponse`, `transId`, plus `properties`
    /// matching `expected_props`.
    fn assert_notify_payload(
        body: &Value,
        camera_id: &str,
        expected_action: &str,
        expected_props: &Value,
    ) {
        assert_eq!(body["to"], camera_id);
        assert_eq!(body["from"], "U-test_web");
        assert_eq!(body["resource"], format!("cameras/{camera_id}"));
        assert_eq!(body["action"], expected_action);
        assert_eq!(body["publishResponse"], true);
        assert!(body["transId"].is_string());
        assert_eq!(&body["properties"], expected_props);
    }

    #[tokio::test]
    async fn take_snapshot_emits_full_frame_snapshot_property() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.take_snapshot("CAM-1").await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_notify_payload(
            &body,
            "CAM-1",
            "set",
            &json!({"activityState":"fullFrameSnapshot"}),
        );
    }

    #[tokio::test]
    async fn full_frame_snapshot_emits_same_property() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.full_frame_snapshot("CAM-1").await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["activityState"], "fullFrameSnapshot");
    }

    #[tokio::test]
    async fn start_record_emits_start_record_property() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.start_record("CAM-1").await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["activityState"], "startRecord");
    }

    #[tokio::test]
    async fn stop_record_emits_stop_record_property() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.stop_record("CAM-1").await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["activityState"], "stopRecord");
    }

    #[tokio::test]
    async fn restart_device_emits_empty_properties() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.restart_device("CAM-1").await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert!(body["properties"].as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn notify_routes_through_options_then_post_with_payload() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client
            .notify("CAM-1", "set", Some(json!({"motionDetected":false})))
            .await
            .unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].method, Method::OPTIONS);
        assert_eq!(calls[1].method, Method::POST);
        let body = parse_body_json(calls[1].body.as_ref());
        assert_eq!(body["properties"]["motionDetected"], false);
    }

    #[tokio::test]
    async fn siren_on_emits_alarm_pattern() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.siren_on("BS-1", 30, 8).await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["sirenState"], "on");
        assert_eq!(body["properties"]["duration"], 30);
        assert_eq!(body["properties"]["volume"], 8);
        assert_eq!(body["properties"]["pattern"], "alarm");
    }

    #[tokio::test]
    async fn siren_off_emits_off_state() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.siren_off("BS-1").await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["sirenState"], "off");
    }

    #[tokio::test]
    async fn turn_on_disables_privacy_shield() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.turn_on("CAM-1").await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["privacyActive"], false);
    }

    #[tokio::test]
    async fn turn_off_enables_privacy_shield() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.turn_off("CAM-1").await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["privacyActive"], true);
    }

    #[tokio::test]
    async fn set_spotlight_with_brightness_remaps_to_intensity_0_100() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client
            .set_spotlight("CAM-1", true, Some(255))
            .await
            .unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        let spot = &body["properties"]["spotlight"];
        assert_eq!(spot["enabled"], true);
        assert_eq!(spot["intensity"], 100); // 255 → 100%
    }

    #[tokio::test]
    async fn set_spotlight_without_brightness_omits_intensity() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_spotlight("CAM-1", false, None).await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        let spot = &body["properties"]["spotlight"];
        assert_eq!(spot["enabled"], false);
        assert!(spot.get("intensity").is_none());
    }

    #[tokio::test]
    async fn set_floodlight_dual_brightness_fields() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client
            .set_floodlight("CAM-1", true, Some(128))
            .await
            .unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        let flood = &body["properties"]["floodlight"];
        assert_eq!(flood["on"], true);
        assert_eq!(flood["brightness1"], flood["brightness2"]);
        assert!(flood["brightness1"].as_u64().unwrap() <= 100);
    }

    #[tokio::test]
    async fn set_nightlight_combines_optional_fields() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client
            .set_nightlight(
                "CAM-1",
                true,
                Some(200),
                Some((10, 20, 30)),
                Some("3500"),
                Some("rainbow"),
            )
            .await
            .unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        let nl = &body["properties"]["nightLight"];
        assert_eq!(nl["enabled"], true);
        assert_eq!(nl["brightness"], 200);
        assert_eq!(nl["mode"], "rainbow");
        assert_eq!(nl["temperature"], "3500");
        assert_eq!(nl["rgb"]["red"], 10);
        assert_eq!(nl["rgb"]["green"], 20);
        assert_eq!(nl["rgb"]["blue"], 30);
    }

    #[tokio::test]
    async fn set_volume_clamps_to_100() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_volume("CAM-1", false, 250).await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        let speaker = &body["properties"]["speaker"];
        assert_eq!(speaker["mute"], false);
        assert_eq!(speaker["volume"], 100);
    }

    #[tokio::test]
    async fn set_camera_brightness_passes_signed_value() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_camera_brightness("CAM-1", -2).await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["brightness"], -2);
    }

    #[tokio::test]
    async fn set_power_save_mode_sends_mode_value() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_power_save_mode("CAM-1", 3).await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["powerSaveMode"], 3);
    }

    #[tokio::test]
    async fn set_image_invert_sends_flip_flag() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_image_invert("CAM-1", true).await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["properties"]["flip"], true);
    }

    #[tokio::test]
    async fn play_track_with_track_id_emits_play_track_action() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client
            .play_track("BABY-1", Some("track-9"), 42)
            .await
            .unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["resource"], "audioPlayback/player");
        assert_eq!(body["action"], "playTrack");
        assert_eq!(body["properties"]["trackId"], "track-9");
        assert_eq!(body["properties"]["position"], 42);
    }

    #[tokio::test]
    async fn play_track_without_track_id_resumes_with_play_action() {
        let mock = arc_mock();
        mock.queue_post("{}");
        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.play_track("BABY-1", None, 0).await.unwrap();
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["action"], "play");
        // properties is the default empty object
        assert!(body["properties"].as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pause_next_prev_track_emit_correct_actions() {
        for (op, expected) in [
            ("pause", "pause"),
            ("next", "nextTrack"),
            ("prev", "prevTrack"),
        ] {
            let mock = arc_mock();
            mock.queue_post("{}");
            let client = authenticated_mocked_client(Arc::clone(&mock));
            match op {
                "pause" => client.pause_track("BABY-1").await.unwrap(),
                "next" => client.next_track("BABY-1").await.unwrap(),
                "prev" => client.previous_track("BABY-1").await.unwrap(),
                _ => unreachable!(),
            }
            let body = parse_body_json(mock.calls()[1].body.as_ref());
            assert_eq!(body["resource"], "audioPlayback/player");
            assert_eq!(body["action"], expected);
        }
    }

    /// Builds a `Device` fixture. `parent` defaults to `device_id`
    /// (self-hosted) when `None`; `x_cloud` controls the optional
    /// `xCloudId` field.
    fn make_device(device_id: &str, parent: Option<&str>, x_cloud: Option<&str>) -> Device {
        let parent_id = parent.unwrap_or(device_id);
        let xc = x_cloud
            .map(|x| format!(r#","xCloudId":"{x}""#))
            .unwrap_or_default();
        let json = format!(
            r#"{{"deviceId":"{device_id}","parentId":"{parent_id}",
                 "deviceType":"camera","deviceName":"Cam","uniqueId":"u",
                 "state":"provisioned"{xc}}}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[tokio::test]
    async fn start_stream_errors_before_login() {
        let mock = arc_mock();
        let client = crate::client::test_helpers::mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-1", None, None);
        // No user_id set — get_stream_url short-circuits before any HTTP.
        let err = client.start_stream(&dev).await.unwrap_err();
        assert!(matches!(err, ArloError::AuthError(_)));
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn get_stream_url_returns_url_with_action_get_and_xcloud_header() {
        let mock = arc_mock();
        // Synchronous get response — URL in the POST body itself.
        mock.queue_post(r#"{"url":"rtsp://stream.example/cam.sdp"}"#);

        let client = authenticated_mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-9", Some("BASE-9"), Some("z1-cloud"));
        let got = client.get_stream_url(&dev).await.unwrap();

        // rtsp:// rewritten to rtsps://
        assert_eq!(
            got.as_ref().map(|s| s.as_str()),
            Some("rtsps://stream.example/cam.sdp")
        );

        let calls = mock.calls();
        assert_eq!(calls.len(), 2, "OPTIONS preflight + POST");
        let post = &calls[1];
        let body = parse_body_json(post.body.as_ref());
        assert_eq!(body["action"], "get");
        assert_eq!(body["to"], "BASE-9"); // parent_id, not device_id
        assert_eq!(body["resource"], "cameras/CAM-9");
        assert_eq!(body["properties"]["cameraId"], "CAM-9");
        assert_eq!(body["responseUrl"], "");
        // xcloudId header derived from the device.
        let xc = post
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("xcloudId"))
            .map(|(_, v)| v.as_str());
        assert_eq!(xc, Some("z1-cloud"));
    }

    #[tokio::test]
    async fn get_stream_url_returns_none_when_no_active_stream() {
        let mock = arc_mock();
        // Arlo returns an envelope with no `url` when nothing is streaming.
        mock.queue_post(r#"{"success":true,"data":{}}"#);
        let client = authenticated_mocked_client(mock);
        let dev = make_device("CAM-1", None, None);
        assert_eq!(client.get_stream_url(&dev).await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_stream_url_unwraps_data_url_envelope() {
        let mock = arc_mock();
        mock.queue_post(r#"{"success":true,"data":{"url":"rtsps://already/secure"}}"#);
        let client = authenticated_mocked_client(mock);
        let dev = make_device("CAM-1", None, None);
        let got = client.get_stream_url(&dev).await.unwrap();
        // Already rtsps:// — left untouched.
        assert_eq!(
            got.map(|s| s.into_inner()),
            Some("rtsps://already/secure".to_string())
        );
    }

    #[tokio::test]
    async fn get_stream_url_omits_xcloud_header_when_device_lacks_it() {
        let mock = arc_mock();
        mock.queue_post(r#"{"url":"rtsp://x/y"}"#);
        let client = authenticated_mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-1", None, None); // no xCloudId
        client.get_stream_url(&dev).await.unwrap();
        let post = &mock.calls()[1];
        assert!(
            !post
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("xcloudId")),
            "xcloudId header must be omitted when device.x_cloud_id is None"
        );
    }

    #[tokio::test]
    async fn start_stream_reuses_active_stream_without_touching_sse() {
        // get_stream_url returns Some → start_stream returns it directly,
        // never subscribing to the event bus (which would fail here since
        // MockTransport has no streaming client).
        let mock = arc_mock();
        mock.queue_post(r#"{"url":"rtsp://live/now"}"#);
        let client = authenticated_mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-1", None, None);

        let url = client.start_stream(&dev).await.unwrap();
        assert_eq!(url.as_str(), "rtsps://live/now");
        // Exactly one peek round-trip (OPTIONS + POST). No SSE bus boot.
        assert_eq!(mock.calls().len(), 2);
    }

    #[tokio::test]
    async fn start_stream_falls_back_to_force_when_no_active_stream() {
        // get_stream_url → None, then force_start_stream boots the event
        // bus, whose first step is a session/v3 round-trip. MockTransport
        // has no canned response for it, so the call errors — but only
        // *after* progressing past the 2-call peek, which is what proves
        // start_stream didn't stop at the empty peek.
        let mock = arc_mock();
        mock.queue_post(r#"{"success":true,"data":{}}"#); // empty peek
        let client = authenticated_mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-1", None, None);

        assert!(client.start_stream(&dev).await.is_err());
        assert!(
            mock.calls().len() > 2,
            "force fallback must progress past the 2-call peek (event-bus boot), got {} calls",
            mock.calls().len()
        );
    }

    #[test]
    fn rewrite_rtsp_to_rtsps_only_touches_plain_rtsp() {
        assert_eq!(super::rewrite_rtsp_to_rtsps("rtsp://h/p"), "rtsps://h/p");
        assert_eq!(super::rewrite_rtsp_to_rtsps("rtsps://h/p"), "rtsps://h/p");
        assert_eq!(
            super::rewrite_rtsp_to_rtsps("https://h/p.m3u8"),
            "https://h/p.m3u8"
        );
        assert_eq!(super::rewrite_rtsp_to_rtsps(""), "");
    }

    #[test]
    fn extract_post_response_stream_url_handles_all_envelopes() {
        use serde_json::json;
        assert_eq!(
            super::extract_post_response_stream_url(&json!({"url":"rtsp://a"})),
            Some("rtsp://a".to_string())
        );
        assert_eq!(
            super::extract_post_response_stream_url(&json!({"data":{"url":"rtsp://b"}})),
            Some("rtsp://b".to_string())
        );
        assert_eq!(
            super::extract_post_response_stream_url(
                &json!({"success":true,"data":{"url":"rtsp://c"}})
            ),
            Some("rtsp://c".to_string())
        );
        assert_eq!(
            super::extract_post_response_stream_url(&json!({"data":{"url":""}})),
            None
        );
        assert_eq!(
            super::extract_post_response_stream_url(&json!({"success":true,"data":{}})),
            None
        );
        assert_eq!(super::extract_post_response_stream_url(&json!({})), None);
    }

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
