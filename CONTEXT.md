# Arlo Rust Library (arlo-rs) - Technical Context

This document provides a comprehensive technical overview of the `arlo-rs` library for AI agents and developers.

## 1. Project Mission & Core Strategy
`arlo-rs` is a high-fidelity, asynchronous Rust library for interacting with the Arlo security camera ecosystem. Since Arlo lacks an official API, this library **emulates the Arlo Web Dashboard** exactly.

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
    - Host URLs are injected via `ArloEndpoints` (prod defaults, or
      `ArloEndpoints::testing(base_url)` to point at a mock server).
- **`MfaHandler`**: Pluggable OTP source.
    - `ImapMfaHandler`: Automated extraction from an inbox.
    - `StdinMfaHandler`: Interactive CLI prompt.
    - `StaticOtpHandler`: Pre-baked OTP for tests.

### API Versioning & Backward Compatibility
Arlo runs a **V3 migration in parallel with the legacy endpoints**.
`ClientConfig.api_version` (per-client, `RwLock<ApiVersion>`) defaults
to `V3`. Every V3-capable call (`get_devices`, `device_support`,
`set_mode`, `logout`) auto-falls-back to its legacy counterpart on a
`403`/`404`, then **pins the client to `Legacy` for the rest of the
session** to skip further failed probes. No legacy endpoint constant
is ever removed — un-migrated accounts still depend on them. Users on
old accounts can pin `[client].api_version = "legacy"` to skip the V3
probe round-trips entirely.

### Layering
- **Domain (Pure)**: `src/models/`, `src/error.rs`, `src/events/ConnectionState`.
- **Application (Orchestration)**: `src/client/auth.rs`, `src/client/devices.rs`, `src/events/mod.rs`.
- **Infrastructure (Adapters)**: `src/client/transport.rs`, `src/client/auth_imap.rs`, `src/client/local_hub.rs`.

---

## 3. The Authentication "Ceremony"
Arlo's modern authentication is a strictly ordered sequence, driven by
`authenticate_with_handler` (the `MfaHandler` supplies the OTP):
1. **`login`**: Submit Base64-encoded credentials to `ocapi-app.arlo.com/api/auth`.
2. **`get_factors`**: Retrieve list of MFA options (Email, SMS, Push).
3. **`start_auth`**: Trigger the OTP dispatch for a specific factor.
4. **`finish_auth`**: Submit the 6-digit OTP to get a temporary token.
5. **`validate_access_token`**: Initial token check.
6. **`start_pairing_factor`** *(optional)*: "Trust this browser" grant.
7. **`validate_session_v3`**: Validation against `myapi.arlo.com/hmsweb/users/session/v3` for the telemetry token.
8. **`device_support`**: Final telemetry call (V3 with Legacy fallback).

**Logout** is `DELETE /hmsweb/user/{user_id}/client/smart/devices/logout
?clientId={device_id}&eventId=FE!{uuid}&time={ms}` (V3), with the legacy
`PUT /hmsweb/logout` as the auto-fallback. Local session state is wiped
regardless of the HTTP outcome.

**Persistence**: Session state (token, user_id, device_id) is snapshotted into `SessionToken` and cached as `0600` JSON files. `ArloClient::reattach(SessionToken)` rehydrates a session out-of-process.

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

### Live Streaming (`src/client/devices.rs`)
Three entry points, all `&Device`-typed (the stream POST targets
`device.parent_id` and attaches an `xcloudId` header derived from
`device.x_cloud_id`; `Device::is_self_hosted()` reports
`parent_id == device_id`):
- **`get_stream_url`**: synchronous peek (`action:"get"` on
  `/startStream`) — returns an already-active stream (e.g. one opened
  from the Arlo mobile app) or `None`. URL in the POST body, no SSE.
- **`force_start_stream`**: always issues a fresh `startUserStream`
  (`action:"set"`); the real URL arrives over SSE and is correlated by
  `transId`.
- **`start_stream`**: peeks via `get_stream_url`, falls back to
  `force_start_stream`. All returned URLs are rewritten
  `rtsp://` → `rtsps://`.

> **Future direction (de-scoped, not implemented):** Arlo's web portal
> has moved live video to **SIP-over-WSS** (`sipInfo/v2` →
> `wss://livestream-z1-prod.arlo.com:7443/`, `Sec-WebSocket-Protocol:
> sip`). `arlo-rs` keeps the legacy `/startStream` + SSE path for
> backward compatibility. A `LiveStreamWss` adapter is tracked future
> work — see `workfile.md` and `CHANGELOG.md`.

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
- **Tracing**: `tracing` is the *only* logging facade. Critical async paths use `#[tracing::instrument(skip(sensitive_fields))]`.
- **`log` / `env_logger` fully removed** (PR 5). Examples use `tracing-subscriber` with a `RUST_LOG`-driven `EnvFilter` (default `warn,arlo_rs=info`). Do not reintroduce `log`.

### Testing
- **Unit Tests**: Must use `ArloClient::with_transport()` to avoid booting the `rs-cloudscraper` browser.
- **Mocking**: Use `mockito` for endpoint-level mocks and `MockTransport` for trait-level mocks.

---

## 6. Workspace Dependencies
- **`rs-cloudscraper`** (Local path `../rs-cloudscraper`): The stealth browser engine.
- **`imap-rs`** (Local path `../imap-rs/`): Provides `imap-client`, `imap-core`, and `imap-tls` for MFA automation.

## 7. Error Handling
Library uses `thiserror` with 10 variants:
- `AuthError`, `ApiError`, `HttpError`, `NetworkError`, `ScraperError`, `SerializationError`, `DeviceNotFound`, `ParseError`, `IoError`, `Timeout`.
- `Timeout` is used by `start_stream`/`force_start_stream` when the SSE-correlated URL doesn't arrive within `STREAM_URL_TIMEOUT` (30 s).
- **Rule**: Never use `anyhow` in `src/`. Only for tests and examples.
