#![warn(missing_docs)]
//! The `rs-arlo` library provides asynchronous, programmatic access to the Arlo security camera ecosystem.
//!
//! Because Arlo does not provide an official API, this library rigorously emulates the behavior of the
//! Arlo Web Dashboard. It circumvents Cloudflare bot protections by tunneling all traffic through a local
//! headless browser proxy managed by `rs-cloudscraper`.
//!
//! # Architecture
//!
//! 1. **`ArloClient`**: The core interactive REST client. It uses a custom `reqwest` builder configured
//! to proxy traffic seamlessly.
//! 2. **`EventManager`**: An Actor-pattern `tokio` background task that subscribes to Arlo's Server-Sent Events (SSE).
//! It parses JSON event chunks and broadcasts strictly-typed `ArloEvent` enums down a channel.
//!
//! # Exampe usage
//! ```no_run
//! use rs_arlo::client::ArloClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     let mut client = ArloClient::new().await.unwrap();
//!     client.login("user@example.com", "password").await.unwrap();
//!     
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
/// Subscription event router interpreting SSE responses async.
pub mod events;
/// Hardcoded request headers and domain constants.
pub mod headers;
/// Pure data structures matching HTTP payload architectures.
pub mod models;

pub use client::ArloClient;
pub use error::ArloError;
