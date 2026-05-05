use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionV3Response {
    pub user_id: String,
    pub token: String,
    pub valid_for: Option<u64>,
}
