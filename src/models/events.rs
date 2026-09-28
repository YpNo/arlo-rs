use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One SSE event broadcast by the [`crate::events::EventBus`]. Fields map
/// directly to Arlo's wire format; missing optionals reflect inconsistencies
/// in Arlo's payloads (e.g. `publishResponse` is sometimes elided).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArloEvent {
    /// e.g. `"is"`, `"set"`, `"notify"`, `"redirect"`. Empty when the
    /// payload has none: `mediaUploadNotification` (a new recording or
    /// snapshot, carrying a fresh `presignedLastImageUrl`) is published
    /// without an `action` and used to be dropped as undecodable.
    #[serde(default)]
    pub action: String,
    /// e.g. `"cameras/<deviceId>"`, `"modes"`, `"subscriptions/<userId>"`.
    pub resource: String,
    /// True on the request side, sometimes omitted on responses.
    #[serde(default)]
    pub publish_response: Option<bool>,
    /// Free-form payload — its shape depends on `resource` and `action`.
    pub properties: Option<Value>,
    /// Origin device or service. The wire field is `from`.
    #[serde(rename = "from")]
    pub source: Option<String>,
    /// Correlation ID echoed back on responses to a previously issued
    /// `notify`-style command. Used by [`crate::ArloClient::start_stream`]
    /// to tie an asynchronous SSE stream-URL response to its triggering
    /// POST.
    pub trans_id: Option<String>,
    /// Top-level `activeMode` carried by v3 `feedNotification` events —
    /// the *name* of the mode the location just switched to.
    #[serde(default, rename = "activeMode")]
    pub active_mode: Option<String>,
}

impl ArloEvent {
    /// The mode this event announces, if it is a mode change: the
    /// top-level `activeMode` of a v3 `feedNotification`, or
    /// `properties.activeMode` / `properties.active` of a legacy `modes`
    /// event. Returns a mode name (v3) or id (legacy) as sent by Arlo.
    pub fn active_mode_change(&self) -> Option<&str> {
        if self.resource == "feedNotification" {
            return self.active_mode.as_deref();
        }
        if self.resource == "modes" || self.resource.starts_with("modes/") {
            let props = self.properties.as_ref()?;
            return props
                .get("activeMode")
                .or_else(|| props.get("active"))
                .and_then(|v| v.as_str());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_notification_exposes_top_level_active_mode() {
        let ev: ArloEvent = serde_json::from_str(
            r#"{"action":"is","resource":"feedNotification","activeMode":"Night"}"#,
        )
        .unwrap();
        assert_eq!(ev.active_mode_change(), Some("Night"));
    }

    #[test]
    fn media_upload_notification_without_action_decodes() {
        // Shape captured live on 2026-09-28 (values synthetic).
        let ev: ArloEvent = serde_json::from_str(
            r#"{"resource":"mediaUploadNotification","deviceId":"C1","uniqueId":"U_C1",
                "ownerId":"U","createdDate":"20260928","mediaObjectCount":1,
                "presignedLastImageUrl":"https://example.invalid/x.jpg"}"#,
        )
        .unwrap();
        assert_eq!(ev.action, "");
        assert_eq!(ev.resource, "mediaUploadNotification");
    }

    #[test]
    fn legacy_modes_event_reads_properties() {
        let ev: ArloEvent = serde_json::from_str(
            r#"{"action":"is","resource":"modes","properties":{"active":"mode1"}}"#,
        )
        .unwrap();
        assert_eq!(ev.active_mode_change(), Some("mode1"));
        let ev: ArloEvent =
            serde_json::from_str(r#"{"action":"is","resource":"cameras/C1"}"#).unwrap();
        assert_eq!(ev.active_mode_change(), None);
    }
}
