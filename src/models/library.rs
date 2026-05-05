use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LibraryQuery {
    pub date_from: String,
    pub date_to: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MediaItem {
    pub owner_id: String,
    pub unique_id: String,
    pub device_id: String,
    pub created_date: String,
    pub presigned_content_url: String,
    pub presigned_thumbnail_url: String,
    pub media_duration_second: Option<u32>,
    pub content_type: String,
    pub reason: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LibraryResponse {
    pub success: bool,
    #[serde(default)]
    pub data: Vec<MediaItem>,
}
