#![allow(missing_docs)]
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArloError {
    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("API Error [{code}]: {message}")]
    ApiError { code: i32, message: String },

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
