use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub id: String,
    pub name: String,
    pub longitude: Option<f64>,
    pub latitude: Option<f64>,
    /// Gateways (base stations / self-hosted cameras) attached to this
    /// location. Entries may be prefixed `"<userId>_<deviceId>"`; use
    /// [`Location::hosts_device`] to match.
    #[serde(default)]
    pub gateway_device_ids: Vec<String>,
}

impl Location {
    /// True when `device_id` is one of this location's gateways, matching
    /// either the bare id or the `"<userId>_<deviceId>"` form Arlo uses.
    pub fn hosts_device(&self, device_id: &str) -> bool {
        self.gateway_device_ids
            .iter()
            .any(|g| g == device_id || g.ends_with(&format!("_{device_id}")))
    }
}

/// Mode catalogue of a location, parsed from
/// `GET /hmsweb/automation/v3?locationId=…&revisions=false`.
///
/// Standard modes (`standby`, `armHome`, `armAway`, …) are the keys of
/// `modes.properties`; user-defined modes live under
/// `customModes.properties.<deviceId>.<uuid>.name`. Names such as `""`
/// or `__DEFAULT_DISARMED__` (migrated v2 modes) fall back to the uuid
/// itself, mirroring the reference client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AutomationConfig {
    /// Standard mode ids (sorted; JSON object order is not preserved).
    pub standard_modes: Vec<String>,
    /// Custom modes, one entry per `(device, uuid)`.
    pub custom_modes: Vec<CustomMode>,
}

/// One user-defined mode of a gateway device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomMode {
    /// Gateway the mode belongs to (bare or `"<userId>_<deviceId>"`).
    pub device_id: String,
    /// The uuid Arlo expects in `activeMode` PUTs.
    pub id: String,
    /// Display name, or the uuid when Arlo sent a sentinel name.
    pub name: String,
}

/// Value of `mode` in an `activeMode` payload that selects custom modes.
pub const CUSTOM_MODE_SENTINEL: &str = "custom";

impl AutomationConfig {
    /// Parses the `data` object of the automation-config response.
    pub fn from_value(data: &Value) -> Self {
        let standard_modes = data
            .get("modes")
            .and_then(|m| m.get("properties"))
            .and_then(|p| p.as_object())
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();

        let mut custom_modes = Vec::new();
        if let Some(devices) = data
            .get("customModes")
            .and_then(|c| c.get("properties"))
            .and_then(|p| p.as_object())
        {
            for (device_id, modes) in devices {
                let Some(modes) = modes.as_object() else {
                    continue;
                };
                for (uuid, mode) in modes {
                    let name = mode
                        .get("name")
                        .and_then(|n| n.as_str())
                        .filter(|n| !n.is_empty() && *n != "__DEFAULT_DISARMED__")
                        .unwrap_or(uuid);
                    custom_modes.push(CustomMode {
                        device_id: device_id.clone(),
                        id: uuid.clone(),
                        name: name.to_string(),
                    });
                }
            }
        }
        Self {
            standard_modes,
            custom_modes,
        }
    }

    /// The canonical id of a standard mode matching `name`
    /// (case-insensitively), if any.
    pub fn standard_mode_id(&self, name: &str) -> Option<&str> {
        self.standard_modes
            .iter()
            .find(|m| m.eq_ignore_ascii_case(name))
            .map(String::as_str)
    }

    /// The uuid of `device_id`'s custom mode called `name`
    /// (case-insensitive). `name` may also already be the uuid. The
    /// device matches on the bare id or its `"<userId>_<deviceId>"` form.
    pub fn custom_mode_id(&self, device_id: &str, name: &str) -> Option<&str> {
        self.custom_modes
            .iter()
            .filter(|m| device_matches(&m.device_id, device_id))
            .find(|m| m.name.eq_ignore_ascii_case(name) || m.id == name)
            .map(|m| m.id.as_str())
    }

    /// The display name of `device_id`'s custom mode `uuid`.
    pub fn custom_mode_name(&self, device_id: &str, uuid: &str) -> Option<&str> {
        self.custom_modes
            .iter()
            .filter(|m| device_matches(&m.device_id, device_id))
            .find(|m| m.id == uuid)
            .map(|m| m.name.as_str())
    }
}

/// Matches a wire device key (bare or `"<userId>_<deviceId>"`) against a
/// bare device id.
fn device_matches(wire: &str, device_id: &str) -> bool {
    wire == device_id || wire.ends_with(&format!("_{device_id}"))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LocationsResponse {
    pub success: bool,
    #[serde(default)]
    pub data: Vec<Location>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AutomationMode {
    pub id: String,
    pub name: String,
    pub features: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ModesResponse {
    pub success: bool,
    #[serde(default)]
    pub data: Vec<AutomationMode>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AutomationDefinitionsResponse {
    pub success: bool,
    #[serde(default)]
    pub data: Value, // Complex legacy definitions blob
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EmergencyLocationsResponse {
    pub success: bool,
    #[serde(default)]
    pub data: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> AutomationConfig {
        AutomationConfig::from_value(&json!({
            "modes": {"properties": {"standby": {}, "armHome": {}, "armAway": {}}},
            "customModes": {"properties": {
                "U1_BASE1": {
                    "uuid-night": {"name": "Night"},
                    "uuid-legacy": {"name": "__DEFAULT_DISARMED__"},
                    "uuid-empty": {"name": ""}
                },
                "BASE2": {"uuid-away2": {"name": "Away 2"}}
            }}
        }))
    }

    #[test]
    fn parses_standard_and_custom_modes_with_sentinel_names() {
        let c = config();
        assert_eq!(c.standard_modes, vec!["armAway", "armHome", "standby"]);
        assert_eq!(c.custom_modes.len(), 4);
        assert_eq!(
            c.custom_mode_name("BASE1", "uuid-legacy"),
            Some("uuid-legacy")
        );
        assert_eq!(
            c.custom_mode_name("BASE1", "uuid-empty"),
            Some("uuid-empty")
        );
    }

    #[test]
    fn resolves_names_case_insensitively_and_through_user_prefix() {
        let c = config();
        assert_eq!(c.standard_mode_id("ARMAWAY"), Some("armAway"));
        assert_eq!(c.custom_mode_id("BASE1", "night"), Some("uuid-night"));
        assert_eq!(c.custom_mode_id("U1_BASE1", "Night"), Some("uuid-night"));
        assert_eq!(c.custom_mode_id("BASE1", "uuid-night"), Some("uuid-night"));
        assert_eq!(c.custom_mode_id("BASE2", "Night"), None);
        assert_eq!(c.custom_mode_id("BASE1", "nope"), None);
    }

    #[test]
    fn empty_payload_yields_empty_config() {
        assert_eq!(
            AutomationConfig::from_value(&json!({})),
            AutomationConfig::default()
        );
    }

    #[test]
    fn location_hosts_device_matches_bare_and_prefixed_ids() {
        let loc: Location = serde_json::from_str(
            r#"{"id":"L1","name":"Home","gatewayDeviceIds":["U1_BASE1","BASE2"]}"#,
        )
        .unwrap();
        assert!(loc.hosts_device("BASE1"));
        assert!(loc.hosts_device("BASE2"));
        assert!(!loc.hosts_device("BASE3"));
        let bare: Location = serde_json::from_str(r#"{"id":"L2","name":"x"}"#).unwrap();
        assert!(bare.gateway_device_ids.is_empty());
    }
}
