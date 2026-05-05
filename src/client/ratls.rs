use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
use crate::headers::ARLO_API_HOST;
use crate::models::ratls::*;
use reqwest::Method;

impl ArloClient {
    /// Generates a security certificate required to bypass the cloud and connect
    /// securely and locally to a Base Station.
    pub async fn create_local_connection_cert(
        &self,
        device_id: &str,
    ) -> Result<CertCreateData, ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, API_RATLS_CERT);

        let payload = CertCreateRequest {
            name: format!("arlo-{}", device_id),
            cn: "Unknown".to_string(), // Spoofed to match iOS traces
            o: "Arlo".to_string(),
            c: "US".to_string(),
        };

        let body_str = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;

        let response: CertCreateResponse = serde_json::from_str(&body_str)?;

        if !response.success {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Failed to create RATLS certificate".to_string(),
            });
        }

        response.data.ok_or_else(|| ArloError::ApiError {
            code: 500,
            message: "No cert data returned".to_string(),
        })
    }

    /// Requests a session token directly from the cloud that is used to authorize
    /// local LAN traffic with the Base Station.
    pub async fn get_ratls_token(&self, device_id: &str) -> Result<RatlsTokenData, ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, API_RATLS_TOKEN);

        let payload = RatlsTokenRequest {
            device_id: device_id.to_string(),
        };

        let body_str = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;

        let response: RatlsTokenResponse = serde_json::from_str(&body_str)?;

        if !response.success {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Failed to retrieve RATLS token".to_string(),
            });
        }

        response.data.ok_or_else(|| ArloError::ApiError {
            code: 500,
            message: "No token data returned".to_string(),
        })
    }

    /// Checks connectivity of the local SmartHub interface natively (Requires Base Station Internal IP logic)
    /// NOTE: Because this routes to the SmartHub directly on the LAN (`https://<HUB_IP>/hmsls/...`),
    /// this specific endpoint ignores `cloud_scraper` and bypasses proxy routines dynamically.
    pub async fn check_local_connectivity(
        &self,
        hub_ip: &str,
        token: &str,
    ) -> Result<String, ArloError> {
        // Build a raw reqwest bypassing Cloudflare/Scraper entirely to hit the LAN IP
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // RATLS certs are self-signed
            .build()?;

        let url = format!("https://{}{}", hub_ip, API_HMSLS_CONNECTIVITY);

        let response = client
            .get(&url)
            .header("Authorization", token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Local Base Station connectivity failed".to_string(),
            });
        }

        Ok(response.text().await?)
    }

    /// Lists local media directly via the Base Station Hub
    pub async fn list_local_media(
        &self,
        hub_ip: &str,
        token: &str,
        date_from: &str,
        date_to: &str,
    ) -> Result<serde_json::Value, ArloError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        let url = format!(
            "https://{}{}?dateFrom={}&dateTo={}",
            hub_ip, API_HMSLS_LIST, date_from, date_to
        );

        let response = client
            .get(&url)
            .header("Authorization", token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Failed to list local RATLS media".to_string(),
            });
        }

        let body_str = response.text().await?;
        let parsed: HmslsListResponse = serde_json::from_str(&body_str)?;
        Ok(parsed.data.unwrap_or_else(|| serde_json::json!([])))
    }

    /// Downloads media directly from the Base station hub
    pub async fn download_local_media(
        &self,
        hub_ip: &str,
        token: &str,
        url_path: &str,
    ) -> Result<Vec<u8>, ArloError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        // Clean any leading slashes on url_path
        let url = format!("https://{}/{}", hub_ip, url_path.trim_start_matches('/'));

        let response = client
            .get(&url)
            .header("Authorization", token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ArloError::ApiError {
                code: 500,
                message: "Failed to download local RATLS media".to_string(),
            });
        }

        Ok(response.bytes().await?.to_vec())
    }
}
