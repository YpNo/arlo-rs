//! RATLS (Remote-Access TLS) cloud-side helpers.
//!
//! Two endpoints in the Arlo cloud back the local-LAN flow:
//! - `/security/cert/create` — returns the certificate that the SmartHub
//!   will present on the LAN. We pin against this cert instead of
//!   blindly trusting any TLS handshake.
//! - `/ratls/token` — returns a short-lived bearer token the SmartHub
//!   accepts on its `/hmsls/*` endpoints.
//!
//! Application code shouldn't usually call these directly — invoke
//! [`crate::ArloClient::local_hub`] instead, which composes both calls
//! and returns a ready-to-use [`crate::client::local_hub::LocalHubClient`]
//! with TLS pinned to the returned cert.

use crate::client::ArloClient;
use crate::client::local_hub::LocalHubClient;
use crate::endpoints::*;
use crate::error::ArloError;
use crate::headers::ARLO_API_HOST;
use crate::models::ratls::*;
use reqwest::Method;
use tracing::instrument;

impl ArloClient {
    /// Generates a security certificate required to bypass the cloud and
    /// connect locally to a SmartHub. The returned certificate is what
    /// the SmartHub will present on the LAN — we pin TLS against it.
    pub async fn create_local_connection_cert(
        &self,
        device_id: &str,
    ) -> Result<CertCreateData, ArloError> {
        let url = format!("{}{}", ARLO_API_HOST, API_RATLS_CERT);
        let payload = CertCreateRequest {
            name: format!("arlo-{device_id}"),
            cn: "Unknown".to_string(),
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

    /// Requests a bearer token authorising the LAN-direct `/hmsls/*`
    /// endpoints on the SmartHub for `device_id`.
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

    /// Composes [`Self::create_local_connection_cert`] +
    /// [`Self::get_ratls_token`] and returns a [`LocalHubClient`] whose
    /// TLS layer is pinned against the cert Arlo issued for `device_id`.
    ///
    /// `hub_ip` is the LAN address (typically discovered via mDNS or
    /// stored in the application's own configuration) — Arlo's cloud does
    /// not return it. SNI is intentionally ignored by the pinned-leaf
    /// verifier, so the IP can be any reachable form (numeric or
    /// hostname).
    #[instrument(skip(self))]
    pub async fn local_hub(
        &self,
        device_id: &str,
        hub_ip: &str,
    ) -> Result<LocalHubClient, ArloError> {
        let cert = self.create_local_connection_cert(device_id).await?;
        let token = self.get_ratls_token(device_id).await?;
        LocalHubClient::new(&cert.certificate, hub_ip, &token.token)
    }
}
