# Changelog

All notable changes to `rs-arlo` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### TODO before publishing to crates.io
- Swap `rs-cloudscraper` from the `path = "../rs-cloudscraper"` dev
  dependency to `git = "...", tag = "v0.2.0"` once the upstream tag is
  verified to match this crate's call sites. Path dependencies block
  `cargo publish`.

## [0.1.0] - Initial public-API freeze

This release sequence (PR 1 → PR 5) lifted `rs-arlo` from a half-broken
prototype to a production-ready library suitable for downstream
streaming applications.

### Added
- **Async-native IMAP MFA handling** built on the sibling `imap-rs`
  workspace (PR 1). No more `tokio::task::spawn_blocking` /
  `std::thread::sleep` polling — the OTP poller stays on the runtime.
- **`secrecy::SecretString` access tokens** (PR 2). The token is
  zeroized on drop and never reaches `Debug` output.
- **`ArloClient::builder()`** for programmatic construction without
  TOML (PR 2). `from_config` becomes a thin shim.
- **`MfaHandler` trait** with two-phase lifecycle (`prepare`,
  `provide_otp`) plus shipped impls: `ImapMfaHandler`,
  `StdinMfaHandler`, `StaticOtpHandler` (PR 2).
- **`start_stream(id) → Result<StreamUrl, ArloError>`** correlates the
  SSE response to the POST via `transId`, removing the need for
  consumers to wire their own SSE plumbing (PR 2).
- **`EventBus`** replaces the previous `EventManager`: clonable
  `subscribe()`, proper `\n\n` SSE frame parsing, `Drop` aborts
  background tasks, and a `watch::Receiver<ConnectionState>` for
  consumers that need to react to reconnects (PR 2 → PR 3).
- **`ArloClient::reattach(SessionToken)`** + `session_token()` for
  out-of-process session persistence (PR 3).
- **Local SmartHub client** (`LocalHubClient`) with rustls leaf-cert
  pinning derived from the RATLS-issued cert — replaces blanket
  `danger_accept_invalid_certs(true)` (PR 3).
- **`HttpTransport` trait + `ArloEndpoints`** (PR 4). Production wires
  `CloudScraperTransport`; tests substitute `MockTransport` and
  `ArloEndpoints::testing(...)` to drive the orchestration layer
  without booting the headless-browser proxy.
- **`ArloClient::with_transport(transport, endpoints)`** test/advanced
  constructor that skips the heavyweight CloudScraper bootstrap
  entirely (PR 4).
- **`tracing-subscriber`-driven examples** with sensible default
  filters (`warn,rs_arlo=info`) (PR 5).
- **`rust-toolchain.toml`** pinning Rust 1.95.0 to match the sibling
  `imap-rs` workspace (PR 5).
- **CHANGELOG.md** itself (this file) (PR 5).

### Changed
- **DRY-up of envelope parsing** — the four near-identical
  `success` / `meta.code == 200` blocks collapsed into a single
  `models::envelope::unwrap_envelope[_array]` helper (PR 3).
- **`notify`-style commands** (`take_snapshot`, `start_record`,
  `stop_record`, `restart_device`, …) now route through the existing
  `notify()` orchestrator instead of rebuilding the payload manually
  six times (PR 3).
- **Public field lockdown** on `ArloClient`: `auth`, `reqwest_client`,
  `cloud_scraper`, `debug_mode` are now `pub(crate)`. External access
  is via `is_authenticated()`, `user_id()`, `device_id()`, and
  `events()` (PR 2).
- **OPTIONS preflight, header injection, and JSON envelope handling**
  moved above the wire layer; the transport just executes (PR 4).
- **Examples migrated from `log` + `env_logger` to
  `tracing-subscriber`** (PR 5).

### Fixed
- **Build was broken** at the start of PR 1 — `auth_imap.rs` referenced
  `imap_client::ClientBuilder` which the new async crate doesn't expose.
- **Config / session secrets unprotected**: `config.toml`,
  `.arlo_session.json`, and `*.har` traces are now in `.gitignore`;
  the on-disk session cache is written `0600` on Unix; sensitive JSON
  keys are scrubbed from `debug_mode` body dumps before they reach
  the tracing layer (PR 1).
- **SSE frames straddling chunk boundaries** were silently dropped by
  the per-chunk `\n` splitter. Replaced with a stateful framer that
  splits on `\n\n` / `\r\n\r\n` per WHATWG (PR 2).
- **Dropped `EventManager` leaked tasks** — both background tasks
  (SSE listener and keep-alive ping) are now aborted in `Drop` (PR 2).
- **`unwrap_or("unknown_user")`** in eight `notify`-style methods
  silently sent meaningless `from: "unknown_user_web"` requests when
  the client wasn't yet authenticated. Replaced with an explicit
  `ArloError::AuthError` (PR 3).
- **Abandoned tests** with the comment
  `// This will fail because of hardcoded host` are now real tests
  exercising `validate_session_v3` and `get_devices` against a mocked
  transport with overridden endpoints (PR 4).

### Removed
- **`native-tls`** unused dependency (`reqwest` is configured for
  `rustls`) (PR 5).
- **`log`** and **`env_logger`** removed from `[dependencies]` /
  `[dev-dependencies]` (PR 5). The codebase uses `tracing` end-to-end.

### Security
- All token-sensitive HTTP headers and JSON keys (`token`,
  `accessToken`, `password`, `otp`, `factorAuthCode`,
  `authorization`, `refreshToken`) are recursively redacted from
  `debug_mode` body dumps (PR 1).
- The session cache file is written with mode `0600` on Unix (PR 1).
- Access tokens live in `secrecy::SecretString` and are zeroized on
  drop (PR 2).
- The local SmartHub client pins the leaf certificate Arlo issued for
  the device, instead of accepting any self-signed cert (PR 3).
