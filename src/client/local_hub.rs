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
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;

/// LAN-direct client for a single Arlo SmartHub. TLS to the hub is pinned
/// against the certificate retrieved from the cloud.
pub struct LocalHubClient {
    http: reqwest::Client,
    hub_ip: String,
    token: SecretString,
}

/// The SmartHub presented a leaf certificate other than the pinned one.
/// `Debug` prints the same text as `Display`: rustls renders
/// `CertificateError::Other` through `Debug`, and that is what reaches
/// the operator.
#[derive(Clone, Copy)]
struct PinMismatch;

const PIN_MISMATCH_MESSAGE: &str =
    "SmartHub presented a certificate that does not match the pinned cloud-issued certificate";

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(PIN_MISMATCH_MESSAGE)
    }
}

impl std::fmt::Debug for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(PIN_MISMATCH_MESSAGE)
    }
}

impl std::error::Error for PinMismatch {}

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
                error: None,
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
                error: None,
                message: format!("rustls protocol-version setup failed: {e}"),
            })?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .connect_timeout(HUB_CONNECT_TIMEOUT)
            .timeout(HUB_REQUEST_TIMEOUT)
            // A hub has no legitimate redirect; following one could resend
            // the RATLS bearer to another host or over cleartext.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            http,
            hub_ip: hub_ip.to_string(),
            token: SecretString::from(token),
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
        use crate::client::transport::{MAX_RESPONSE_BYTES, read_reqwest_body};
        let response = self
            .http
            .get(&url)
            .header("Authorization", self.token.expose_secret())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ArloError::ApiError {
                code: response.status().as_u16() as i32,
                error: None,
                message: "Local SmartHub connectivity check failed".into(),
            });
        }
        let body = read_reqwest_body(response, MAX_RESPONSE_BYTES).await?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    /// `GET /hmsls/list?dateFrom=…&dateTo=…` — lists media stored locally
    /// on the SmartHub for the given inclusive date window. Dates are
    /// `YYYYMMDD`.
    pub async fn list_media(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<serde_json::Value, ArloError> {
        use crate::client::transport::{MAX_RESPONSE_BYTES, read_reqwest_body};
        use crate::models::validate::date_yyyymmdd;
        let url = format!(
            "https://{}{}?dateFrom={}&dateTo={}",
            self.hub_ip,
            API_HMSLS_LIST,
            date_yyyymmdd("dateFrom", date_from)?,
            date_yyyymmdd("dateTo", date_to)?
        );
        let response = self
            .http
            .get(&url)
            .header("Authorization", self.token.expose_secret())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ArloError::ApiError {
                code: response.status().as_u16() as i32,
                error: None,
                message: "Failed to list local SmartHub media".into(),
            });
        }
        let body = read_reqwest_body(response, MAX_RESPONSE_BYTES).await?;
        let parsed: HmslsListResponse = serde_json::from_slice(&body)?;
        Ok(parsed.data.unwrap_or_else(|| serde_json::json!([])))
    }

    /// `GET /<url_path>` — downloads a media artefact from the SmartHub.
    /// `url_path` is typically the `mediaUrl` field returned by
    /// [`Self::list_media`]. Leading slashes are normalized.
    ///
    /// The whole artefact is buffered, capped at [`MAX_HUB_MEDIA_BYTES`].
    pub async fn download_media(&self, url_path: &str) -> Result<Vec<u8>, ArloError> {
        use crate::client::transport::read_reqwest_body;
        use crate::models::validate::hub_media_path;
        let url = format!(
            "https://{}/{}",
            self.hub_ip,
            hub_media_path(url_path.trim_start_matches('/'))?
        );
        let response = self
            .http
            .get(&url)
            .header("Authorization", self.token.expose_secret())
            // Media is the one call that legitimately outlives the
            // request timeout; the byte cap below is the other bound.
            .timeout(HUB_MEDIA_TIMEOUT)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ArloError::ApiError {
                code: response.status().as_u16() as i32,
                error: None,
                message: "Failed to download local SmartHub media".into(),
            });
        }
        read_reqwest_body(response, MAX_HUB_MEDIA_BYTES).await
    }
}

/// TCP + TLS deadline for the LAN hub (a few ms away when it is up).
const HUB_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole-request deadline for the small hub calls.
const HUB_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Whole-request deadline for a media download.
const HUB_MEDIA_TIMEOUT: Duration = Duration::from_secs(600);

/// Largest media artefact [`LocalHubClient::download_media`] will buffer.
/// Hub recordings are minutes of 1080p at most; this is a hard stop
/// against a hub that never ends the response.
pub const MAX_HUB_MEDIA_BYTES: usize = 512 * 1024 * 1024;

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
            // `InvalidCertificate`, not `General`: `ArloError::action`
            // classifies a certificate failure as `Fatal`, and a pin
            // mismatch must never be retried through.
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(PinMismatch))),
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

    // --- PinnedLeafVerifier: the cert-pinning security boundary ---
    //
    // These exercise the verifier logic directly (no TLS handshake
    // needed). It's the single most security-critical piece of code in
    // the crate, so it gets explicit positive + negative coverage.

    fn pinned_verifier(pem: &str) -> PinnedLeafVerifier {
        let pinned = CertificateDer::from_pem_slice(pem.as_bytes())
            .unwrap()
            .into_owned();
        PinnedLeafVerifier {
            pinned,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    #[test]
    fn verifier_accepts_byte_identical_pinned_cert() {
        let v = pinned_verifier(SAMPLE_CERT_PEM);
        let presented = CertificateDer::from_pem_slice(SAMPLE_CERT_PEM.as_bytes())
            .unwrap()
            .into_owned();
        let name = ServerName::try_from("hub.local").unwrap();
        let res = v.verify_server_cert(&presented, &[], &name, &[], UnixTime::now());
        assert!(res.is_ok(), "exact pinned cert must be accepted");
    }

    #[test]
    fn verifier_rejects_any_other_cert() {
        let v = pinned_verifier(SAMPLE_CERT_PEM);
        // Arbitrary non-matching DER bytes — the SmartHub presenting
        // anything other than the pinned cloud-issued cert must fail
        // closed (the MITM-resistance guarantee).
        let other = CertificateDer::from(vec![0x30u8, 0x82, 0x01, 0x00, 0xde, 0xad]);
        let name = ServerName::try_from("hub.local").unwrap();
        let res = v.verify_server_cert(&other, &[], &name, &[], UnixTime::now());
        let err = res.expect_err("mismatched cert must be rejected");
        assert!(
            err.to_string().contains("does not match the pinned"),
            "error should explain the pin mismatch: {err}"
        );
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "pin mismatch must be a certificate error so it classifies Fatal: {err:?}"
        );
        // As reqwest/tokio-rustls surface it: wrapped in an io::Error.
        let io = std::io::Error::new(std::io::ErrorKind::InvalidData, err);
        assert_eq!(
            ArloError::NetworkError(Box::new(io)).action(),
            crate::models::error_codes::ErrorAction::Fatal
        );
    }

    #[test]
    fn verifier_advertises_supported_schemes() {
        let v = pinned_verifier(SAMPLE_CERT_PEM);
        assert!(
            !v.supported_verify_schemes().is_empty(),
            "verifier must advertise the provider's signature schemes"
        );
    }
}
