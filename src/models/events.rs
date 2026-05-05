use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One SSE event broadcast by the [`crate::events::EventBus`]. Fields map
/// directly to Arlo's wire format; missing optionals reflect inconsistencies
/// in Arlo's payloads (e.g. `publishResponse` is sometimes elided).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArloEvent {
    /// e.g. `"is"`, `"set"`, `"notify"`, `"redirect"`.
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
}
