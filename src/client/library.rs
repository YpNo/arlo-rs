use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
// Endpoints come from self.endpoints (PR 4 transport refactor).
use crate::models::library::{LibraryQuery, LibraryResponse, MediaItem};
use reqwest::Method;

impl ArloClient {
    /// Queries the Arlo Cloud DVR Media Library for recordings between two dates.
    /// Dates must typically be formatted as "YYYYMMDD".
    pub async fn get_library(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<Vec<MediaItem>, ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, API_LIBRARY);

        let payload = LibraryQuery {
            date_from: date_from.to_string(),
            date_to: date_to.to_string(),
        };

        let body_str = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;

        let response: LibraryResponse = serde_json::from_str(&body_str)?;

        if !response.success {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Failed to fetch media library recordings".to_string(),
            });
        }

        Ok(response.data)
    }
}
