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

    #[error("HTTP Request Failed: {status} - {body}")]
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

impl From<wreq::Error> for ArloError {
    fn from(e: wreq::Error) -> Self {
        ArloError::NetworkError(Box::new(e))
    }
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
    /// status (401/403 ⇒ re-authenticate, 429/5xx ⇒ retry), transport
    /// failures and timeouts are retryable, and everything local
    /// (parsing, configuration, missing device) is
    /// [`ErrorAction::Unclassified`].
    pub fn action(&self) -> ErrorAction {
        match self {
            ArloError::ApiError { code, error, .. } => classify(*code, *error),
            ArloError::HttpError { status, .. } => classify(i32::from(status.as_u16()), None),
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
            body: String::new(),
        };
        assert_eq!(forbidden.action(), ErrorAction::Reauth);
        assert_eq!(ArloError::Timeout("t".into()).action(), ErrorAction::Retry);
        assert_eq!(
            ArloError::ParseError("p".into()).action(),
            ErrorAction::Unclassified
        );
    }
}
