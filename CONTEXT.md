# Arlo Rust Library (rs-arlo) - Technical Context

This document provides a comprehensive technical overview of the `rs-arlo` library for AI agents and developers.

## 1. Project Mission & Core Strategy
`rs-arlo` is a high-fidelity, asynchronous Rust library for interacting with the Arlo security camera ecosystem. Since Arlo lacks an official API, this library **emulates the Arlo Web Dashboard** exactly.

### Core Strategy:
- **Stealth**: All traffic is routed through a local headless-browser proxy (`rs-cloudscraper`) to forge JA4 TLS fingerprints and bypass Cloudflare bot detection.
- **Hexagonal Architecture**: Business logic (Domain) is strictly decoupled from I/O (Infrastructure) via traits, enabling 100% unit-testability without booting a browser.
- **Protocol Fidelity**: Every undocumented header, telemetry ping, and the complex 6-step OAuth ceremony is mirrored.

---

## 2. Architecture & Design Patterns

### Hexagonal Seams
- **`HttpTransport`**: The primary seam. 
    - `CloudScraperTransport` (Prod): Routes through the stealth proxy.
    - `MockTransport` (Test): Canned responses, no network I/O.
- **`MfaHandler`**: Pluggable OTP source.
    - `ImapMfaHandler`: Automated extraction from an inbox.
    - `StdinMfaHandler`: Interactive CLI prompt.

### Layering
- **Domain (Pure)**: `src/models/`, `src/error.rs`, `src/events/ConnectionState`.
- **Application (Orchestration)**: `src/client/auth.rs`, `src/client/devices.rs`, `src/events/mod.rs`.
- **Infrastructure (Adapters)**: `src/client/transport.rs`, `src/client/auth_imap.rs`, `src/client/local_hub.rs`.

---

## 3. The Authentication "Ceremony" (6 Steps)
Arlo's modern authentication is a strictly ordered sequence:
1. **`login`**: Submit Base64-encoded credentials to `ocapi-app.arlo.com/api/auth`.
2. **`get_factors`**: Retrieve list of MFA options (Email, SMS, Push).
3. **`start_auth`**: Trigger the OTP dispatch for a specific factor.
4. **`finish_auth`**: Submit the 6-digit OTP to get a temporary token.
5. **`validate_access_token`**: Initial token check.
6. **`validate_session_v3`**: Final validation against `myapi.arlo.com/hmsweb/users/session/v3` to get the telemetry token.

**Persistence**: Session state (token, user_id, device_id) is snapshotted into `SessionToken` and cached as `0600` JSON files.

---

## 4. Subsystem Deep-Dive

### SSE Event Bus (`src/events/`)
The `EventBus` is a lazy-initialized singleton that owns two background tasks:
1. **Listener**: Maintains a persistent connection to `/hmsweb/client/subscribe`. Uses `SseFramer` to handle WHATWG-compliant chunked SSE data.
2. **Pinger**: Sends a keep-alive ping to `session/v3` every 10 minutes to prevent token expiration.
- **Broadcasting**: Events are sent via `tokio::sync::broadcast`; connection state via `tokio::sync::watch`.

### Local Hub / RATLS (`src/client/local_hub.rs`)
Direct SmartHub communication (LAN) uses **Remote Authenticated TLS (RATLS)**:
- **Cert Pinning**: The cloud returns a leaf certificate for the hub. `LocalHubClient` uses `rustls` with a custom `PinnedLeafVerifier` to trust **only** that exact certificate, ignoring CA chains and hostnames.
- **Token Spoofing**: Requests to the local hub use special headers to bypass Cloudflare-style checks locally.

### Media Library (`src/client/library.rs`)
Handles S3 chunk parsing and media decryption. Arlo video chunks are often encrypted; this module contains the logic to assemble and decrypt them into playable streams.

---

## 5. Development Standards

### Quality & Security Gates
- **Zero-Warning**: Must pass `cargo clippy` and `cargo fmt`.
- **Memory Safety**: `unsafe` is strictly forbidden.
- **Zero-Leak**: Tokens must be wrapped in `secrecy::SecretString` to prevent accidental logging.
- **Edition 2024**: Always use the latest Rust idioms.

### Instrumentation
- **Tracing**: Use `tracing` for all logging. Critical async paths must use `#[tracing::instrument(skip(sensitive_fields))]`.
- **Logging**: The `log` crate is legacy; new code should only use `tracing`.

### Testing
- **Unit Tests**: Must use `ArloClient::with_transport()` to avoid booting the `rs-cloudscraper` browser.
- **Mocking**: Use `mockito` for endpoint-level mocks and `MockTransport` for trait-level mocks.

---

## 6. Workspace Dependencies
- **`rs-cloudscraper`** (Local path `../rs-cloudscraper`): The stealth browser engine.
- **`imap-rs`** (Local path `../imap-rs/`): Provides `imap-client`, `imap-core`, and `imap-tls` for MFA automation.

## 7. Error Handling
Library uses `thiserror` with 9 primary variants:
- `AuthError`, `ApiError`, `HttpError`, `NetworkError`, `ScraperError`, `SerializationError`, `DeviceNotFound`, `ParseError`, `IoError`, `Timeout`.
- **Rule**: Never use `anyhow` in `src/`. Only for tests and examples.
