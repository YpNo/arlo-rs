#![allow(missing_docs)]
use crate::models::error_codes::{ErrorAction, classify};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArloError {
    #[error("Authentication failed: {0}")]
    AuthError(String),

    /// Failure reported by Arlo's response envelope (`meta.code`,
    /// `meta.error`, `meta.message`) or an unrecognised envelope. Use
    /// [`ArloError::action`] to decide what to do about it.
    #[error("API Error [{code}{}]: {message}", fmt_arlo_code(.error))]
    ApiError {
        code: i32,
        error: Option<u32>,
        message: String,
    },

    /// `body` is kept whole for callers that inspect it (rate-limit
    /// markers, Arlo envelopes); `Display` shows only a redacted,
    /// length-capped excerpt.
    #[error("HTTP Request Failed: {status} - {}", crate::models::redact::excerpt(.body))]
    HttpError {
        status: reqwest::StatusCode,
        body: String,
    },

    /// Transport-level failure (DNS, TLS, connect, timeout, body read)
    /// from whichever HTTP client backs the [`crate::HttpTransport`] —
    /// `wreq` for the default transport, `reqwest` for the local-hub
    /// client and the browser-proxy transport. Boxed so both map into
    /// the same variant; the concrete error stays reachable through
    /// [`std::error::Error::source`].
    #[error("Network error: {0}")]
    NetworkError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("CloudScraper Initialization error: {0}")]
    ScraperError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Parsing error: {0}")]
    ParseError(String),

    #[error("I/O Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Timed out: {0}")]
    Timeout(String),
}

impl From<reqwest::Error> for ArloError {
    fn from(e: reqwest::Error) -> Self {
        ArloError::NetworkError(Box::new(e))
    }
}

impl From<stealthscraper_rs::wreq::Error> for ArloError {
    fn from(e: stealthscraper_rs::wreq::Error) -> Self {
        ArloError::NetworkError(Box::new(e))
    }
}

/// True when a transport failure is a TLS / certificate verification
/// failure anywhere in its source chain: a `rustls` certificate error
/// (local-hub client, WebSockets), a `wreq` TLS-kind error, or a
/// BoringSSL verification message (`certificate verify failed`). Such a
/// failure is an active interception or a rotated pinned certificate, not
/// a transient condition to retry.
fn is_tls_failure(err: &(dyn std::error::Error + 'static)) -> bool {
    if err
        .downcast_ref::<stealthscraper_rs::wreq::Error>()
        .is_some_and(stealthscraper_rs::wreq::Error::is_tls)
    {
        return true;
    }
    if matches!(
        err.downcast_ref::<rustls::Error>(),
        Some(rustls::Error::InvalidCertificate(_))
    ) {
        return true;
    }
    let text = err.to_string().to_ascii_lowercase();
    if text.contains("certificate verify failed") || text.contains("certificate_verify_failed") {
        return true;
    }
    // `io::Error::source` returns its inner error's source, skipping the
    // inner error itself (where rustls puts the certificate error).
    if err
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::get_ref)
        .is_some_and(|inner| is_tls_failure(inner))
    {
        return true;
    }
    err.source().is_some_and(is_tls_failure)
}

/// True when `body` is a JSON object with Arlo's `meta` or `success` key.
fn looks_like_arlo_envelope(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.as_object()
                .map(|o| o.contains_key("meta") || o.contains_key("success"))
        })
        .unwrap_or(false)
}

/// Renders the Arlo-specific `meta.error` suffix of an `ApiError` display.
fn fmt_arlo_code(error: &Option<u32>) -> String {
    error.map(|e| format!("/{e}")).unwrap_or_default()
}

impl ArloError {
    /// The action a caller should take about this error, per Arlo's own
    /// error-code table (see [`crate::models::error_codes`]).
    ///
    /// Envelope failures classify by their Arlo code, HTTP failures by
    /// status (401/403 ⇒ re-authenticate, 429/5xx ⇒ retry), a TLS /
    /// certificate failure is [`ErrorAction::Fatal`], other transport
    /// failures and timeouts are retryable, and everything local
    /// (parsing, configuration, missing device) is
    /// [`ErrorAction::Unclassified`].
    pub fn action(&self) -> ErrorAction {
        match self {
            ArloError::ApiError { code, error, .. } => classify(*code, *error),
            ArloError::HttpError { status, body } => {
                let code = i32::from(status.as_u16());
                // A 401/403 means "re-authenticate" only when Arlo said so;
                // a Cloudflare block page is a 403 too, and discarding a
                // valid token on it just repeats the ceremony against the
                // same blocked edge.
                if (code == 401 || code == 403) && !looks_like_arlo_envelope(body) {
                    ErrorAction::Unclassified
                } else {
                    classify(code, None)
                }
            }
            ArloError::NetworkError(e) if is_tls_failure(e.as_ref()) => ErrorAction::Fatal,
            ArloError::NetworkError(_) | ArloError::Timeout(_) => ErrorAction::Retry,
            ArloError::AuthError(_)
            | ArloError::ScraperError(_)
            | ArloError::SerializationError(_)
            | ArloError::DeviceNotFound(_)
            | ArloError::ParseError(_)
            | ArloError::IoError(_) => ErrorAction::Unclassified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_display_includes_the_arlo_code_when_present() {
        let e = ArloError::ApiError {
            code: 400,
            error: Some(9017),
            message: "locked".into(),
        };
        assert_eq!(e.to_string(), "API Error [400/9017]: locked");
        let e = ArloError::ApiError {
            code: 500,
            error: None,
            message: "x".into(),
        };
        assert_eq!(e.to_string(), "API Error [500]: x");
    }

    #[test]
    fn action_classifies_each_family() {
        let lockout = ArloError::ApiError {
            code: 400,
            error: Some(9017),
            message: String::new(),
        };
        assert_eq!(lockout.action(), ErrorAction::Fatal);
        let forbidden = ArloError::HttpError {
            status: reqwest::StatusCode::FORBIDDEN,
            body: r#"{"meta":{"code":403,"message":"nope"}}"#.into(),
        };
        assert_eq!(forbidden.action(), ErrorAction::Reauth);
        let cloudflare = ArloError::HttpError {
            status: reqwest::StatusCode::FORBIDDEN,
            body: "<html><title>Attention Required! | Cloudflare</title></html>".into(),
        };
        assert_eq!(cloudflare.action(), ErrorAction::Unclassified);
        assert_eq!(ArloError::Timeout("t".into()).action(), ErrorAction::Retry);
        assert_eq!(
            ArloError::ParseError("p".into()).action(),
            ErrorAction::Unclassified
        );
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn http_error_display_is_capped_and_single_line() {
        let body = format!("<html>{}\n</html>", "x".repeat(10_000));
        let err = ArloError::HttpError {
            status: reqwest::StatusCode::FORBIDDEN,
            body: body.clone(),
        };
        let text = err.to_string();
        assert!(text.starts_with("HTTP Request Failed: 403"), "{text}");
        assert!(
            text.len() < 400 && !text.contains('\n'),
            "len {}",
            text.len()
        );
        // The full body stays available to code that needs it.
        if let ArloError::HttpError { body: kept, .. } = err {
            assert_eq!(kept, body);
        }
    }

    #[derive(Debug)]
    struct BoringLike;
    impl std::fmt::Display for BoringLike {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("error:1000007d:SSL routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED")
        }
    }
    impl std::error::Error for BoringLike {}

    #[test]
    fn network_error_with_rustls_certificate_failure_is_fatal() {
        let inner = rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName);
        let io = std::io::Error::new(std::io::ErrorKind::InvalidData, inner);
        let err = ArloError::NetworkError(Box::new(io));
        assert_eq!(err.action(), ErrorAction::Fatal);
    }

    #[test]
    fn network_error_with_boringssl_verify_failure_is_fatal() {
        let err = ArloError::NetworkError(Box::new(BoringLike));
        assert_eq!(err.action(), ErrorAction::Fatal);
    }

    #[test]
    fn network_error_without_tls_failure_stays_retryable() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err = ArloError::NetworkError(Box::new(io));
        assert_eq!(err.action(), ErrorAction::Retry);
    }
}
