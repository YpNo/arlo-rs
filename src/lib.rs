#![warn(missing_docs)]
//! The `arlo-rs` library provides asynchronous, programmatic access to the Arlo security camera ecosystem.
//!
//! Because Arlo does not provide an official API, this library rigorously emulates the behavior of the
//! Arlo Web Dashboard. It circumvents Cloudflare bot protections by tunneling all traffic through a local
//! headless browser proxy managed by `rs-cloudscraper`.
//!
//! # Architecture
//!
//! 1. **`ArloClient`**: The core interactive REST client. It uses a custom `reqwest` builder configured
//!    to proxy traffic seamlessly.
//! 2. **`EventManager`**: An Actor-pattern `tokio` background task that subscribes to Arlo's Server-Sent Events (SSE).
//!    It parses JSON event chunks and broadcasts strictly-typed `ArloEvent` enums down a channel.
//!
//! # Example
//! ```no_run
//! use arlo_rs::ArloClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     let mut client = ArloClient::builder()
//!         .session_cache(".arlo_session.json")
//!         .build()
//!         .await
//!         .unwrap();
//!
//!     client.login("user@example.com", "password").await.unwrap();
//!     let devices = client.get_devices().await.unwrap();
//!     println!("Found {} devices.", devices.len());
//! }
//! ```

/// Core client orchestration and endpoints interaction wrappers.
pub mod client;
/// Serialization definitions for loading TOML configurations.
pub mod config;
/// Static Arlo API URL properties.
pub mod endpoints;
/// Unified strictly-typed error structures.
pub mod error;
pub mod events;
/// Hardcoded request headers and domain constants.
pub mod headers;
/// Pure data structures matching HTTP payload architectures.
pub mod models;

pub use client::endpoints::ArloEndpoints;
pub use client::local_hub::LocalHubClient;
pub use client::mfa::{
    ImapMfaHandler, MfaChallenge, MfaHandler, StaticOtpHandler, StdinMfaHandler,
};
pub use client::transport::{HttpRequest, HttpResponse, HttpTransport};
pub use client::{ArloClient, ArloClientBuilder};
pub use error::ArloError;
pub use events::{ConnectionState, EventBus};
pub use models::auth::SessionToken;
