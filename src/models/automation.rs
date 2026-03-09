use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub id: String,
    pub name: String,
    pub longitude: Option<f64>,
    pub latitude: Option<f64>,
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
