//! Direct LAN client for an Arlo SmartHub (RATLS).
//!
//! Replaces the previous "blindly disable TLS verification" approach with
//! a [`reqwest::Client`] whose TLS layer pins the SmartHub's leaf
//! certificate. The pinned certificate is the one returned by
//! [`crate::ArloClient::create_local_connection_cert`] — Arlo's cloud is
//! the source of truth for what cert the SmartHub will present, so
//! trusting only that exact byte-for-byte certificate gives MITM
//! resistance equivalent to (and simpler than) full chain validation.
//!
//! The streamer application typically obtains a [`LocalHubClient`] via
//! [`crate::ArloClient::local_hub`], then calls
//! [`LocalHubClient::list_media`] / [`LocalHubClient::download_media`].
//!
//! # Behaviour on cert mismatch
//!
//! If the certificate Arlo returned does *not* match what the SmartHub
//! actually presents on the LAN (e.g. Arlo handed us the signing CA
//! instead of the leaf), every TLS handshake will fail closed with
//! [`ArloError::NetworkError`]. That is the intended failure mode: a
//! mismatched cert is exactly the situation cert pinning is meant to
//! catch.

use crate::endpoints::*;
use crate::error::ArloError;
use crate::models::ratls::HmslsListResponse;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;

/// LAN-direct client for a single Arlo SmartHub. TLS to the hub is pinned
/// against the certificate retrieved from the cloud.
pub struct LocalHubClient {
    http: reqwest::Client,
    hub_ip: String,
    token: String,
}

impl std::fmt::Debug for LocalHubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalHubClient")
            .field("hub_ip", &self.hub_ip)
            .field("token", &"***")
            .finish()
    }
}

impl LocalHubClient {
    /// Builds a client pinned to `cert_pem` for connections to `hub_ip`,
    /// authenticating with `token`. Crate-internal — applications obtain a
    /// [`LocalHubClient`] via [`crate::ArloClient::local_hub`].
    pub(crate) fn new(cert_pem: &str, hub_ip: &str, token: &str) -> Result<Self, ArloError> {
        let pinned = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(|e| {
            ArloError::ApiError {
                code: 500,
                message: format!("Failed to parse SmartHub cert as PEM: {e}"),
            }
        })?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinnedLeafVerifier {
            pinned: pinned.into_owned(),
            provider: provider.clone(),
        });

        let tls_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ArloError::ApiError {
                code: 500,
                message: format!("rustls protocol-version setup failed: {e}"),
            })?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .build()?;

        Ok(Self {
            http,
            hub_ip: hub_ip.to_string(),
            token: token.to_string(),
        })
    }

    /// IP address (or hostname) the client is pinned to. Useful for
    /// logging and tests; does not authenticate the connection by itself.
    pub fn hub_ip(&self) -> &str {
        &self.hub_ip
    }

    /// `GET /hmsls/connectivity` — round-trips a heartbeat against the
    /// SmartHub to confirm the LAN path is healthy.
    pub async fn check_connectivity(&self) -> Result<String, ArloError> {
        let url = format!("https://{}{}", self.hub_ip, API_HMSLS_CONNECTIVITY);
        let response = self
            .http
            .get(&url)
            .header("Authorization", &self.token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ArloError::ApiError {
                code: response.status().as_u16() as i32,
                message: "Local SmartHub connectivity check failed".into(),
            });
        }
        Ok(response.text().await?)
    }

    /// `GET /hmsls/list?dateFrom=…&dateTo=…` — lists media stored locally
    /// on the SmartHub for the given inclusive date window. Dates are
    /// `YYYYMMDD`.
    pub async fn list_media(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<serde_json::Value, ArloError> {
        let url = format!(
            "https://{}{}?dateFrom={}&dateTo={}",
            self.hub_ip, API_HMSLS_LIST, date_from, date_to
        );
        let response = self
            .http
            .get(&url)
            .header("Authorization", &self.token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ArloError::ApiError {
                code: response.status().as_u16() as i32,
                message: "Failed to list local SmartHub media".into(),
            });
        }
        let body = response.text().await?;
        let parsed: HmslsListResponse = serde_json::from_str(&body)?;
        Ok(parsed.data.unwrap_or_else(|| serde_json::json!([])))
    }

    /// `GET /<url_path>` — downloads a media artefact from the SmartHub.
    /// `url_path` is typically the `mediaUrl` field returned by
    /// [`Self::list_media`]. Leading slashes are normalized.
    pub async fn download_media(&self, url_path: &str) -> Result<Vec<u8>, ArloError> {
        let url = format!(
            "https://{}/{}",
            self.hub_ip,
            url_path.trim_start_matches('/')
        );
        let response = self
            .http
            .get(&url)
            .header("Authorization", &self.token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ArloError::ApiError {
                code: response.status().as_u16() as i32,
                message: "Failed to download local SmartHub media".into(),
            });
        }
        Ok(response.bytes().await?.to_vec())
    }
}

/// rustls verifier that accepts exactly one leaf certificate, byte-for-
/// byte equal to the one the cloud returned. Hostname/SNI is intentionally
/// ignored: SmartHub certs are issued to a device serial / UUID, not the
/// LAN IP we connect to, so pinning the leaf is the right granularity.
#[derive(Debug)]
struct PinnedLeafVerifier {
    pinned: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedLeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "SmartHub presented a certificate that does not match the pinned cloud-issued certificate".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal self-signed test cert in PEM. Generated with rcgen-like
    /// defaults; just enough to exercise the parser path. We don't make
    /// any TLS connections in these tests — those need integration.
    const SAMPLE_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
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

    #[test]
    fn new_builds_client_for_valid_pem() {
        let client = LocalHubClient::new(SAMPLE_CERT_PEM, "192.168.1.42", "token-abc");
        assert!(client.is_ok(), "valid PEM should construct client");
        let client = client.unwrap();
        assert_eq!(client.hub_ip(), "192.168.1.42");
    }

    #[test]
    fn new_rejects_garbage_pem() {
        let err = LocalHubClient::new("not a cert", "192.168.1.42", "tok").unwrap_err();
        match err {
            ArloError::ApiError { message, .. } => {
                assert!(
                    message.contains("PEM"),
                    "error should mention PEM: {message}"
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_empty_pem() {
        assert!(LocalHubClient::new("", "192.168.1.42", "tok").is_err());
    }
}
