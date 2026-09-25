use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
// Endpoints (api host) come from self.endpoints — PR 4 transport refactor.
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
                error: None,
                message: "Failed to fetch media library recordings".to_string(),
            });
        }

        Ok(response.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_helpers::{authenticated_mocked_client, parse_body_json};
    use crate::client::transport::test_support::MockTransport;
    use std::sync::Arc;

    #[tokio::test]
    async fn get_library_returns_parsed_items() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(
            r#"{"success":true,"data":[
                {"ownerId":"O1","uniqueId":"U1","deviceId":"C1",
                 "createdDate":"20260507","presignedContentUrl":"https://s3/c.mp4",
                 "presignedThumbnailUrl":"https://s3/t.jpg",
                 "mediaDurationSecond":12,"contentType":"video/mp4","reason":"motionDetected"}
            ]}"#,
        );

        let client = authenticated_mocked_client(Arc::clone(&mock));
        let items = client.get_library("20260501", "20260507").await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].device_id, "C1");
        assert_eq!(items[0].reason, "motionDetected");

        // Verify wire payload sends the date range.
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["dateFrom"], "20260501");
        assert_eq!(body["dateTo"], "20260507");
    }

    #[tokio::test]
    async fn get_library_errors_on_non_success() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(r#"{"success":false,"data":[]}"#);
        let client = authenticated_mocked_client(mock);
        let err = client.get_library("a", "b").await.unwrap_err();
        assert!(matches!(err, ArloError::ApiError { .. }));
    }

    #[tokio::test]
    async fn get_library_errors_on_malformed_response() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(r#"{"completely":"different"}"#);
        let client = authenticated_mocked_client(mock);
        // Missing `success` field — serde fails up-front.
        assert!(client.get_library("a", "b").await.is_err());
    }
}
