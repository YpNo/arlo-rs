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

    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

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
