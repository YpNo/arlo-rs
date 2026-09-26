//! Arm/disarm and automation: v3 `activeMode` with the legacy fallbacks,
//! locations, the v3 mode catalogue and mode-by-name resolution.

use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
use crate::models::automation::CUSTOM_MODE_SENTINEL;
use reqwest::Method;
use serde_json::json;
use tracing::{instrument, warn};

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

impl ArloClient {
    /// Sets the mode of a Base Station (e.g., `"armed"`, `"disarmed"`,
    /// or a user-defined mode UUID).
    ///
    /// **Default path is V3 (`/hmsweb/automation/v3/activeMode`).**
    /// Falls back to the legacy `/hmsweb/users/devices/automation/active`
    /// path on 404, or unconditionally when:
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
        let is_v3 = self.api_version.get() == crate::config::ApiVersion::V3;
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
    ///   404 or the location couldn't be resolved — caller continues
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
            self.endpoints.api_host,
            API_AUTOMATION_ACTIVE_MODE,
            crate::models::validate::id_segment("locationId", &loc.id)
                .map_err(SetModeV3Outcome::Error)?
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
                    self.api_version.set(crate::config::ApiVersion::Legacy);
                    return Err(SetModeV3Outcome::Fallback);
                }
            },
            Err(ArloError::HttpError { status, .. })
                if status == reqwest::StatusCode::NOT_FOUND =>
            {
                warn!(
                    "V3 activeMode GET returned {}. Pinning client to Legacy.",
                    status
                );
                self.api_version.set(crate::config::ApiVersion::Legacy);
                return Err(SetModeV3Outcome::Fallback);
            }
            Err(e) => return Err(SetModeV3Outcome::Error(e)),
        };

        let put_url = format!(
            "{}{}?locationId={}&revision={}",
            self.endpoints.api_host,
            API_AUTOMATION_ACTIVE_MODE,
            crate::models::validate::id_segment("locationId", &loc.id)
                .map_err(SetModeV3Outcome::Error)?,
            revision
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
                if status == reqwest::StatusCode::NOT_FOUND =>
            {
                warn!(
                    "V3 activeMode PUT returned {}. Pinning client to Legacy.",
                    status
                );
                self.api_version.set(crate::config::ApiVersion::Legacy);
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
            let timestamp = crate::client::api::now_millis() as u64;
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
        let user_id = crate::models::validate::id_segment("userId", user_id)?;
        let endpoint_path = API_LOCATIONS.replace("{user_id}", user_id);
        let url = format!("{}{}", self.endpoints.api_host, endpoint_path);

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;
        let arr = crate::models::envelope::unwrap_envelope_array(&body_str, "locations")?;
        serde_json::from_value(arr).map_err(|e| {
            ArloError::ParseError(format!(
                "Failed to parse locations array: {e}; body: {}",
                crate::models::redact::excerpt(&body_str)
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
            "{}{}?locationId={}",
            self.endpoints.api_host,
            API_AUTOMATION_MODES,
            crate::models::validate::id_segment("locationId", location_id)?
        );

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;
        let data = crate::models::envelope::unwrap_envelope(&body_str)?;
        if data.is_null() {
            return Ok(Vec::new());
        }
        serde_json::from_value(data)
            .map_err(|e| ArloError::ParseError(format!("Failed to parse automation modes: {e}")))
    }

    /// Fetches the v3 mode catalogue of a location —
    /// `GET /hmsweb/automation/v3?locationId=…&revisions=false` — parsed
    /// into an [`AutomationConfig`] (standard mode ids plus the
    /// name ↔ uuid map of every gateway's custom modes).
    ///
    /// [`AutomationConfig`]: crate::models::automation::AutomationConfig
    #[instrument(skip(self))]
    pub async fn get_automation_config(
        &self,
        location_id: &str,
    ) -> Result<crate::models::automation::AutomationConfig, ArloError> {
        let url = format!(
            "{}{}?locationId={}&revisions=false",
            self.endpoints.api_host,
            API_AUTOMATION_V3,
            crate::models::validate::id_segment("locationId", location_id)?
        );
        let body = self.execute_request::<()>(Method::GET, &url, None).await?;
        let data = crate::models::envelope::unwrap_envelope(&body)?;
        Ok(crate::models::automation::AutomationConfig::from_value(
            &data,
        ))
    }

    /// The location whose gateways include `device_id`
    /// ([`Location::hosts_device`]), or the account's first location when
    /// Arlo lists no gateways (single-location accounts).
    ///
    /// [`Location::hosts_device`]: crate::models::automation::Location::hosts_device
    pub async fn location_for_device(
        &self,
        device_id: &str,
    ) -> Result<crate::models::automation::Location, ArloError> {
        let locations = self.get_locations().await?;
        locations
            .iter()
            .find(|l| l.hosts_device(device_id))
            .or_else(|| locations.first())
            .cloned()
            .ok_or_else(|| ArloError::DeviceNotFound(format!("no location for {device_id}")))
    }

    /// Switches `device_id`'s location to the mode called `mode_name` on
    /// the v3 automation API, resolving names the way the Arlo app does:
    /// a standard mode (`standby`, `armHome`, `armAway`, case-insensitive)
    /// is sent as `{"mode": <id>}`; anything else is looked up among the
    /// gateway's custom modes (by name or uuid) and sent as
    /// `{"mode":"custom","custom":{<deviceId>: <uuid>}}`. Base stations
    /// delegate to their location, so `device_id` may be a base station
    /// or a self-hosted camera.
    ///
    /// # Errors
    ///
    /// [`ArloError::DeviceNotFound`] when `mode_name` is neither a
    /// standard mode nor a custom mode of that gateway; transport and
    /// envelope errors propagate.
    #[instrument(skip(self))]
    pub async fn set_mode_by_name(
        &self,
        device_id: &str,
        mode_name: &str,
    ) -> Result<(), ArloError> {
        let location = self.location_for_device(device_id).await?;
        let config = self.get_automation_config(&location.id).await?;
        let payload = if let Some(id) = config.standard_mode_id(mode_name) {
            json!({ "mode": id })
        } else if let Some(uuid) = config.custom_mode_id(device_id, mode_name) {
            json!({ "mode": CUSTOM_MODE_SENTINEL, "custom": { device_id: uuid } })
        } else {
            return Err(ArloError::DeviceNotFound(format!(
                "mode '{mode_name}' is not defined for {device_id} at location {}",
                location.name
            )));
        };

        let get_url = format!(
            "{}{}?locationId={}",
            self.endpoints.api_host,
            API_AUTOMATION_ACTIVE_MODE,
            crate::models::validate::id_segment("locationId", &location.id)?
        );
        let body = self
            .execute_request::<()>(Method::GET, &get_url, None)
            .await?;
        let revision = extract_active_mode_revision(&body, &location.id).ok_or_else(|| {
            ArloError::ParseError("activeMode response carries no revision".into())
        })?;
        let put_url = format!(
            "{}{}?locationId={}&revision={}",
            self.endpoints.api_host,
            API_AUTOMATION_ACTIVE_MODE,
            crate::models::validate::id_segment("locationId", &location.id)?,
            revision
        );
        self.execute_request(Method::PUT, &put_url, Some(&payload))
            .await?;
        Ok(())
    }

    /// Retrieves legacy v2 automation definitions
    #[instrument(skip(self))]
    pub async fn get_automation_definitions(&self) -> Result<serde_json::Value, ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_AUTOMATION_DEFINITIONS);

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;
        crate::models::envelope::unwrap_envelope(&body_str)
    }

    /// Retrieves emergency service locations
    pub async fn get_emergency_locations(&self) -> Result<serde_json::Value, ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_EMERGENCY_LOCATIONS);

        let body_str = self.execute_request::<()>(Method::GET, &url, None).await?;
        crate::models::envelope::unwrap_envelope(&body_str)
    }
}

#[cfg(test)]
mod tests {
    use crate::client::devices::test_support::*;
    use crate::client::test_helpers::{authenticated_mocked_client, parse_body_json};
    use crate::error::ArloError;
    use reqwest::Method;
    use std::sync::Arc;

    fn location_with_gateway() -> &'static str {
        r#"{"success":true,"data":[{"id":"L1","name":"Home","gatewayDeviceIds":["U-test_BASE1"]}]}"#
    }

    fn automation_config() -> &'static str {
        r#"{"success":true,"data":{
            "modes":{"properties":{"standby":{},"armAway":{}}},
            "customModes":{"properties":{"U-test_BASE1":{"uuid-night":{"name":"Night"}}}}
        }}"#
    }

    #[tokio::test]
    async fn set_mode_by_name_resolves_custom_uuid_and_puts_with_revision() {
        let mock = arc_mock();
        mock.queue_get(location_with_gateway()); // get_locations
        mock.queue_get(automation_config()); // automation config
        mock.queue_get(
            r#"{"success":true,"data":{"L1":{"properties":{"mode":"standby"},"revision":42}}}"#,
        ); // activeMode GET
        mock.queue_post(r#"{"success":true}"#); // PUT

        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_mode_by_name("BASE1", "night").await.unwrap();

        let calls = mock.calls();
        let put = calls
            .iter()
            .find(|c| c.method == Method::PUT)
            .expect("activeMode PUT");
        assert!(
            put.url.contains("locationId=L1") && put.url.contains("revision=42"),
            "{}",
            put.url
        );
        let body = parse_body_json(put.body.as_ref());
        assert_eq!(body["mode"], "custom");
        assert_eq!(body["custom"]["BASE1"], "uuid-night");
    }

    #[tokio::test]
    async fn set_mode_by_name_sends_plain_mode_for_standard_names() {
        let mock = arc_mock();
        mock.queue_get(location_with_gateway());
        mock.queue_get(automation_config());
        mock.queue_get(r#"{"success":true,"data":{"L1":{"revision":7}}}"#);
        mock.queue_post("{}");

        let client = authenticated_mocked_client(Arc::clone(&mock));
        client.set_mode_by_name("BASE1", "ARMAWAY").await.unwrap();

        let calls = mock.calls();
        let put = calls.iter().find(|c| c.method == Method::PUT).expect("PUT");
        let body = parse_body_json(put.body.as_ref());
        assert_eq!(body["mode"], "armAway");
        assert!(body.get("custom").is_none());
    }

    #[tokio::test]
    async fn set_mode_by_name_errors_before_any_put_for_unknown_mode() {
        let mock = arc_mock();
        mock.queue_get(location_with_gateway());
        mock.queue_get(automation_config());

        let client = authenticated_mocked_client(Arc::clone(&mock));
        let err = client
            .set_mode_by_name("BASE1", "Vacation")
            .await
            .unwrap_err();
        assert!(matches!(err, ArloError::DeviceNotFound(_)), "{err:?}");
        assert!(mock.calls().iter().all(|c| c.method == Method::GET));
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
        client.api_version.set(crate::config::ApiVersion::Legacy);
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
        assert_eq!(client.api_version.get(), crate::config::ApiVersion::Legacy);
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
}
