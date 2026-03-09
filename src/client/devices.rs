use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
use crate::headers::ARLO_API_HOST;
use crate::models::api::{Device, DevicesResponse};
use reqwest::Method;
use serde_json::json;
use std::process::{Child, Command, Stdio};

impl ArloClient {
    /// Discovers all devices attached to the user's Arlo account.
    pub async fn get_devices(&self) -> Result<Vec<Device>, ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, API_DEVICES);

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;

        let devices_response: DevicesResponse = serde_json::from_str(&body_str)?;

        if !devices_response.success {
            return Err(ArloError::AuthError("Failed to fetch devices".to_string()));
        }

        Ok(devices_response.data)
    }

    /// Triggers a video stream on the specified camera.
    /// Note: Arlo responds asynchronously via the SSE Event Manager with the actual stream URL.
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
    pub async fn set_mode(&self, base_station_id: &str, mode: &str) -> Result<(), ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, API_SET_MODE);

        let user_id = self.auth.user_id.as_deref().unwrap_or("unknown_user");
        let trans_id = uuid::Uuid::new_v4().to_string();

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

        Ok(())
    }

    /// Fetches user geographic locations required by v3 automation routing
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

        let response: crate::models::automation::LocationsResponse =
            serde_json::from_str(&body_str)?;

        if !response.success {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Failed to fetch user locations".to_string(),
            });
        }

        Ok(response.data)
    }

    /// Fetches all available modes under the v3 Automation framework for a specific location
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
}
