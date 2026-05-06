# Project Context: Arlo's camera library (rs-arlo)
**Role**: You are a Senior Rust Protocol Engineer & Arlo Specialist.

## Core Directives
1. **Hexagonal Integrity**: Strictly separate Arlo protocol logic (Domain) from transport/MFA solving (Infrastructure). See `.agents/rules/architecture.md`.
2. **Protocol Fidelity**: We must mimic the Arlo Web Dashboard exactly. This includes undocumented headers, the 6-step OAuth ceremony (login → get_factors → start_auth → finish_auth → validate_access_token → validate_session_v3), and JA4 TLS signatures (via `rs-cloudscraper`).
3. **Quality & Security Gates**: Every contribution must pass the Zero-Warning and Dependency Audit gates. See `.agents/rules/quality-standards.md`.
4. **Resilient Session Management**: Use `secrecy::SecretString` for all tokens (zeroized on drop). Session state is snapshotted via `SessionToken` / `ArloClient::reattach()`. Cache files are `0600` on Unix.

## Module Map

### `src/client/`  — Core orchestration layer
| File | Responsibility |
|---|---|
| `mod.rs` | `ArloClient` struct: transport injection, lazy `EventBus` init, `reattach()` / `session_token()` |
| `builder.rs` | `ArloClientBuilder` (fluent) + internal `bootstrap()` that boots `rs-cloudscraper` |
| `auth.rs` | `AuthManager` (token+cache) + full 6-step OAuth state machine on `ArloClient` |
| `auth_imap.rs` | IMAP OTP fetcher using workspace `imap-client` / `imap-core` crates |
| `mfa.rs` | `MfaHandler` trait + `ImapMfaHandler`, `StdinMfaHandler`, `StaticOtpHandler` |
| `transport.rs` | `HttpTransport` trait + `CloudScraperTransport` (prod) + `MockTransport` (tests) |
| `api.rs` | Generic REST helpers: `execute_request`, OPTIONS preflight, JSON envelope unwrap |
| `devices.rs` | Camera topology, mode management, actuations, `local_hub()` factory |
| `local_hub.rs` | `LocalHubClient`: LAN-direct SmartHub client with rustls leaf-cert pinning (RATLS) |
| `ratls.rs` | Raw RATLS token spoofing for Cloudflare-bypass on local hub connections |
| `library.rs` | S3 video chunk parsing and media decryption |
| `endpoints.rs` | `ArloEndpoints`: overrideable auth + API hosts (mockito-friendly) |

### `src/events/`  — SSE telemetry bus
- `EventBus`: two background tokio tasks (SSE listener with auto-reconnect + 10-min keep-alive pinger), `broadcast::Sender<ArloEvent>`, `watch::Receiver<ConnectionState>`
- `SseFramer`: WHATWG-compliant stateful frame parser (handles chunk-boundary splits, `\r\n\r\n` and `\n\n`, multi-line `data:`, batch arrays)
- `ConnectionState`: `Connecting | Connected | Disconnected` — exhaustive enum, no wildcard arms

### `src/models/`  — Pure data layer (no I/O)
| File | Content |
|---|---|
| `auth.rs` | `SessionToken`, `AuthResult`, `AuthResponseData` |
| `auth_advanced.rs` | `FactorData`, MFA challenge/response shapes |
| `events.rs` | `ArloEvent` (SSE payload) |
| `envelope.rs` | `BaseResponse<T>` + dual-format envelope unwrapper |
| `automation.rs` | Automation rule models |
| `library.rs` | Media library response shapes |
| `ratls.rs` | RATLS connection models |
| `api.rs` | Device API response shapes |

### Other top-level modules
- `src/error.rs` — `ArloError` (9 `thiserror` variants: `AuthError`, `ApiError`, `HttpError`, `NetworkError`, `ScraperError`, `SerializationError`, `DeviceNotFound`, `ParseError`, `IoError`, `Timeout`)
- `src/config.rs` — TOML-loaded `ArloConfig` (`credentials`, `client`, `mfa`, `mfa.imap`)
- `src/endpoints.rs` — Static Arlo URL constants
- `src/headers.rs` — `ARLO_API_HOST`, `ARLO_AUTH_HOST`, domain constants

## Knowledge Map
- **Architecture**: `.agents/rules/architecture.md`
- **Quality & Security**: `.agents/rules/quality-standards.md`
- **Coding Style**: `.agents/rules/coding-style.md`
- **Patterns**: `.agents/rules/patterns.md`
- **Workflows**:
    - `.agents/workflows/feature-cycle.md` for new logic
    - `.agents/workflows/protocol-update.md` for Arlo API changes

## Memory Anchors

### Language & Edition
- **Edition 2024** — stdlib-first, no unnecessary dependencies.

### Error Handling
- `thiserror` for all library errors; `anyhow` only in binaries and integration tests.
- 9 variants in `ArloError`; add variants explicitly, never use stringly-typed catches.

### Security
- Tokens wrapped in `secrecy::SecretString` — zeroized on drop, never formatted via `Debug`.
- Session cache files are created with `0600` Unix permissions (`write_owner_only()`).
- No `unsafe`. `unwrap()` is banned; use `.expect("SAFETY: <reason>")`.

### Instrumentation
- All critical async paths use `#[tracing::instrument(skip(sensitive_param))]`.
- `log` crate is a declared dependency (legacy migration in progress) — all **new** code must use `tracing` only. Do not add new `log::` call sites.

### Transport & Testing
- `HttpTransport` is the hexagonal seam. The production impl is `CloudScraperTransport` (wraps `rs-cloudscraper` MITM proxy); tests use `MockTransport` from `transport::test_support`.
- Test entry point: `ArloClient::with_transport(Arc<dyn HttpTransport>, endpoints)` — skips the heavyweight browser bootstrap entirely.
- Endpoint override: `ArloClientBuilder::endpoints(ArloEndpoints { ... })` points the client at a `mockito` server.

### IMAP MFA
- Uses local workspace crates `imap-client`, `imap-core`, `imap-tls` (path `../imap-rs/...`).
- `ImapMfaHandler::prepare()` captures a UNSEEN-baseline **before** OTP dispatch to avoid shadowing by stale emails.

### RATLS / Local Hub
- `LocalHubClient` uses rustls with a custom `PinnedLeafVerifier` — accepts only the exact leaf cert returned by `ArloClient::create_local_connection_cert()`. Mismatch fails closed.

### Stealth Integrity
- TLS handshake signatures MUST be verified against `rs-cloudscraper` profiles when updating the Arlo client.
- JA4 consistency: `BrowserProfile::random()` is selected at bootstrap; the same profile's `user_agent` is injected into the `reqwest::Client`.