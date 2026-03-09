use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArloEvent {
    pub action: String,
    pub resource: String,
    pub publish_response: bool,
    pub properties: Option<Value>,
    #[serde(rename = "from")]
    pub source: Option<String>,
}
