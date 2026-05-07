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
// Endpoints come from self.endpoints (PR 4 transport refactor).
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
        let url = format!("{}{}", self.endpoints.api_host, API_RATLS_CERT);
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
        let url = format!("{}{}", self.endpoints.api_host, API_RATLS_TOKEN);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_helpers::{authenticated_mocked_client, parse_body_json};
    use crate::client::transport::test_support::MockTransport;
    use std::sync::Arc;

    /// Minimal self-signed PEM certificate copied verbatim from
    /// `local_hub::tests::SAMPLE_CERT_PEM`. Used as the cloud-issued
    /// certificate Arlo would return on `/security/cert/create`. The
    /// pinned-leaf verifier accepts any well-formed PEM here — we don't
    /// open a real TLS connection in this test.
    const PINNED_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBhTCCASugAwIBAgIUcDdqPKL5e7wMpQX+Tw7SWxxSlzowCgYIKoZIzj0EAwIw\n\
EjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAw\n\
MDBaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n\
AAS4dEPHc/B5n9pVYaUdU1JL2P2oH9MzPJgU6GhO8r+jJFmBkOtRCqCK2hY3sOxy\n\
LKy3bhPwXqbiPkoH3W3dLqWso2gwZjAdBgNVHQ4EFgQUL/0eJp0pPv6X1JSgGmgL\n\
mQzd5K0wHwYDVR0jBBgwFoAUL/0eJp0pPv6X1JSgGmgLmQzd5K0wDwYDVR0TAQH/\n\
BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNHADBEAiAh\n\
Sl/2gKR6QqZ3UKt/Tn6gwOWzLnQI3JxgRC3qAVi24wIgGBmuQDg/oM4l0MUL1xRH\n\
nIYANCqJYEogTQfBuZJ8KB8=\n\
-----END CERTIFICATE-----\n";

    #[tokio::test]
    async fn create_local_connection_cert_returns_typed_data() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(
            r#"{"success":true,"data":{"certificate":"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----","serialNumber":"01:02"}}"#,
        );
        let client = authenticated_mocked_client(Arc::clone(&mock));
        let data = client.create_local_connection_cert("dev-1").await.unwrap();
        assert!(data.certificate.contains("BEGIN CERTIFICATE"));
        assert_eq!(data.serial_number, "01:02");

        // Wire payload spoofs the iOS-style cert request shape.
        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["name"], "arlo-dev-1");
        assert_eq!(body["cn"], "Unknown");
        assert_eq!(body["o"], "Arlo");
        assert_eq!(body["c"], "US");
    }

    #[tokio::test]
    async fn create_local_connection_cert_errors_on_failure() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(r#"{"success":false,"data":null}"#);
        let client = authenticated_mocked_client(mock);
        assert!(matches!(
            client.create_local_connection_cert("dev-1").await,
            Err(ArloError::ApiError { .. })
        ));
    }

    #[tokio::test]
    async fn create_local_connection_cert_errors_when_data_missing() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(r#"{"success":true,"data":null}"#);
        let client = authenticated_mocked_client(mock);
        assert!(matches!(
            client.create_local_connection_cert("dev-1").await,
            Err(ArloError::ApiError { .. })
        ));
    }

    #[tokio::test]
    async fn get_ratls_token_returns_typed_data() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(
            r#"{"success":true,"data":{"token":"ratls-tok","exp":"2026-12-31T00:00:00Z","certSerialNumber":"01:02"}}"#,
        );
        let client = authenticated_mocked_client(Arc::clone(&mock));
        let data = client.get_ratls_token("dev-1").await.unwrap();
        assert_eq!(data.token, "ratls-tok");
        assert_eq!(data.cert_serial_number.as_deref(), Some("01:02"));

        let body = parse_body_json(mock.calls()[1].body.as_ref());
        assert_eq!(body["device_id"], "dev-1");
    }

    #[tokio::test]
    async fn get_ratls_token_errors_on_failure() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(r#"{"success":false,"data":null}"#);
        let client = authenticated_mocked_client(mock);
        assert!(matches!(
            client.get_ratls_token("dev-1").await,
            Err(ArloError::ApiError { .. })
        ));
    }

    #[tokio::test]
    async fn local_hub_composes_cert_then_token_then_lan_client() {
        let mock = Arc::new(MockTransport::new());
        // create_local_connection_cert (POST → OPTIONS + body)
        mock.queue_post(format!(
            r#"{{"success":true,"data":{{"certificate":{cert:?},"serialNumber":"01"}}}}"#,
            cert = PINNED_PEM
        ));
        // get_ratls_token (POST → OPTIONS + body)
        mock.queue_post(
            r#"{"success":true,"data":{"token":"ratls-tok","exp":"2026-12-31T00:00:00Z"}}"#,
        );

        let client = authenticated_mocked_client(Arc::clone(&mock));
        let lan = client.local_hub("dev-1", "192.168.1.42").await.unwrap();
        // We don't poke at LocalHubClient internals here — the full
        // pinned-TLS path is covered in client/local_hub.rs. We just
        // confirm the composition succeeded and both cloud calls fired.
        let _ = lan;
        assert_eq!(mock.calls().len(), 4, "2 OPTIONS + 2 POST");
    }
}
