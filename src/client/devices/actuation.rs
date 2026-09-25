//! `notify`-style device commands: snapshots, manual recording, restart,
//! siren, privacy shield, spotlight / floodlight / nightlight, brightness,
//! power-save and image flip.

use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
use reqwest::Method;
use serde_json::json;
use tracing::instrument;

impl ArloClient {
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
    pub(super) async fn notify_custom_resource(
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

#[cfg(test)]
mod tests {
    use crate::client::devices::test_support::*;
    use crate::client::test_helpers::{authenticated_mocked_client, parse_body_json};
    use reqwest::Method;
    use serde_json::json;
    use std::sync::Arc;

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
}
