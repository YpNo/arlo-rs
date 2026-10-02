//! Device Management, Streaming & Hardware Actuation.
//!
//! This module houses the core logic for enumerating Arlo hardware (Cameras, Base Stations)
//! and triggering physical state changes via the Arlo V3 APIs. This includes parsing ambient
//! sensor history (temperature/humidity payload decoders), initiating asynchronous video streams,
//! and managing Base Station arm/disarm toggles.
//!
//! Layout: `get_devices` and the shared `xcloudId` header helper live
//! here; `stream` (legacy `/startStream` + event-bus correlation),
//! `modes` (v3 automation / locations / legacy mode paths), `actuation`
//! (`notify`-style commands: snapshots, recording, sirens, lights, …),
//! `media` (audio playback) and `sensors` (ambient history) are
//! submodules, each an `impl ArloClient` block.

mod actuation;
mod media;
mod modes;
mod sensors;
mod stream;

pub use stream::{IOS_APP_USER_AGENT_LEGACY, PYAARLO_IOS_APP_VERSION, ios_app_user_agent};

use crate::client::ArloClient;
use crate::endpoints::{API_DEVICES, API_DEVICES_V2};
use crate::error::ArloError;
use crate::models::api::Device;
use reqwest::Method;
use tracing::{instrument, warn};

impl ArloClient {
    /// Discovers all devices attached to the user's Arlo account.
    ///
    /// Tolerates Arlo's three response shapes via
    /// `unwrap_envelope_array` (crate-internal): a bare array,
    /// `{ success: true, data: [...] }`, or
    /// `{ success: true, data: { devices: [...] } }`.
    #[instrument(skip(self))]
    pub async fn get_devices(&self) -> Result<Vec<Device>, ArloError> {
        let is_v3 = self.api_version.get() == crate::config::ApiVersion::V3;

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
            // Only a 404 says the v2 endpoint does not exist for this
            // account. A 403 is an expired session or a Cloudflare block
            // and must surface as such (`action() == Reauth`), not pin the
            // client to the legacy list for its lifetime.
            Err(ArloError::HttpError { status, .. })
                if is_v3 && status == reqwest::StatusCode::NOT_FOUND =>
            {
                warn!(
                    "get_devices v2 returned {}. Pinning client to Legacy and retrying.",
                    status
                );
                self.api_version.set(crate::config::ApiVersion::Legacy);
                let url_fallback = format!("{}{}", self.endpoints.api_host, API_DEVICES);
                self.execute_request::<()>(Method::GET, &url_fallback, None)
                    .await?
            }
            Err(e) => return Err(e),
        };

        let arr = crate::models::envelope::unwrap_envelope_array(&body_str, "devices")?;
        serde_json::from_value(arr).map_err(|e| {
            ArloError::ParseError(format!(
                "Failed to parse devices array: {e}; body: {}",
                crate::models::redact::excerpt(&body_str)
            ))
        })
    }
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

#[cfg(test)]
pub(crate) mod test_support {
    //! Fixtures shared by the devices submodules' tests.
    use crate::client::transport::test_support::MockTransport;
    use serde_json::Value;
    use std::sync::Arc;

    pub(crate) fn arc_mock() -> Arc<MockTransport> {
        Arc::new(MockTransport::new())
    }

    /// Asserts the standard `notify`-style payload shape that every
    /// camera-control command emits: `to`, `from`, `resource`,
    /// `action`, `publishResponse`, `transId`, plus `properties`
    /// matching `expected_props`.
    pub(crate) fn assert_notify_payload(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArloEndpoints;
    use crate::client::devices::test_support::*;
    use crate::client::test_helpers::authenticated_mocked_client;
    use crate::client::transport::test_support::MockTransport;
    use std::sync::Arc;

    #[tokio::test]
    async fn get_devices_returns_parsed_array_through_mocked_transport() {
        // Replaces the previous "test_get_devices_dynamic_parsing" smoke test
        // that swapped reqwest::Client directly. PR 4 lets us drive the full
        // get_devices() path against a mocked transport — including the
        // envelope unwrapper.

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
}

#[cfg(test)]
mod hazard_tests {
    use crate::client::test_helpers::authenticated_mocked_client;
    use crate::client::transport::HttpResponse;
    use crate::client::transport::test_support::MockTransport;
    use crate::models::error_codes::ErrorAction;
    use std::sync::Arc;

    #[tokio::test]
    async fn a_403_on_the_v2_device_list_surfaces_and_does_not_pin_legacy() {
        let mock = Arc::new(MockTransport::new());
        mock.expect(HttpResponse {
            status: reqwest::StatusCode::FORBIDDEN,
            body: r#"{"meta":{"code":403,"error":9002}}"#.into(),
        });
        let client = authenticated_mocked_client(mock.clone());
        let err = client.get_devices().await.expect_err("403 surfaces");
        assert_eq!(err.action(), ErrorAction::Reauth);
        assert_eq!(client.api_version.get(), crate::config::ApiVersion::V3);
        assert_eq!(mock.calls().len(), 1, "no legacy retry");
    }
}
