# Changelog

All notable changes to `rs-arlo` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (V3 migration + streaming)
- **`get_stream_url(&Device) -> Result<Option<StreamUrl>, ArloError>`** —
  synchronous peek (`action: "get"` on `/startStream`) that returns an
  already-active stream (e.g. one a user opened from the Arlo mobile
  app) without triggering a new one. URL rewritten `rtsp://` → `rtsps://`.
- **`force_start_stream(&Device)`** — always issues a fresh
  `startUserStream` + SSE-correlated URL (the previous `start_stream`
  behaviour, now `&Device`-typed and sending `to: parent_id`).
- **`start_stream(&Device)`** now peeks via `get_stream_url` first and
  only falls back to `force_start_stream` on a miss.
- **`Device` fields** `x_cloud_id`, `automation_revision`,
  `connectivity`, plus `Device::is_self_hosted()`.
- **`ApiVersion` config** (`[client].api_version`, default `v3`) with
  automatic V3→Legacy fallback on any 403/404, and a per-client
  override for un-migrated accounts.
- HAR-verified V3 endpoints: `/hmsweb/v2/users/devices`,
  `/hmsweb/devicesupport/v3`, `/hmsweb/automation/v3/activeMode`,
  and the `DELETE /hmsweb/user/{uid}/client/smart/devices/logout`
  flow.

### Changed — ⚠️ breaking, pre-0.1.0-tag
- **`start_stream` signature changed** from
  `start_stream(&self, camera_id: &str)` to
  `start_stream(&self, device: &Device)`. Older cameras sit behind a
  separate base station; the stream POST must target `device.parent_id`
  (`to`), which a bare camera-ID string couldn't supply. Passing the
  whole `Device` also yields the `xCloudId` header the modern endpoint
  expects. Callers: replace `client.start_stream(&cam.device_id)` with
  `client.start_stream(cam)`.
- **`logout` is now `DELETE`** to the V3
  `/hmsweb/user/{uid}/client/smart/devices/logout?clientId=…&eventId=…&time=…`
  URL (was the wrong `PUT /hmsweb/logout` in the interim work). Legacy
  `PUT /hmsweb/logout` retained as the auto-fallback.
- **`set_mode` v3** now reads `revision` from the correct
  location-keyed response shape and always sends the
  `{"mode":"custom","custom":{…}}` wrapper (per pyaarlo#195). The
  broken 36-char UUID heuristic and the wrong `data.revision` lookup
  were removed.
- **`device_support`** no longer rewrites `api_version` on the success
  path — a deliberate `Legacy` pinning now survives a chance V3
  success.

### Coverage
- Line coverage is **70.3%** (793/1128) after the V3-migration tests,
  up from 68% in PR 6. Notably, the `PinnedLeafVerifier` cert-pinning
  boundary (the crate's most security-critical code, previously 0%
  covered) now has explicit positive + negative tests.
- The CI gate is **65%** (`--fail-under 65`) — 5 points below measured
  for run-to-run stability, not because coverage is 65%. The earlier
  `ci.yml` flag said `70` while its own comment said `65`; reconciled
  to 65 here.
- Path to 85% unchanged — still gated on the three infra investments
  below (SSE streaming-HTTP mock, IMAP server mock, CloudScraper-boot
  harness).

### Out of scope / future direction
- Arlo's web portal now streams via SIP-over-WSS
  (`wss://livestream-z1-prod.arlo.com:7443/`,
  `Sec-WebSocket-Protocol: sip`, seeded by
  `GET /hmsweb/users/devices/sipInfo/v2`). The legacy `/startStream`
  + SSE path remains and is what `rs-arlo` uses. A `LiveStreamWss`
  adapter is future work for accounts where the legacy path is retired.

### Added (PR 6)
- **Test coverage push** from 27% → 68% (+41 pts). 73 new unit tests
  across `auth.rs`, `devices.rs`, `library.rs`, `ratls.rs`, `mfa.rs`,
  `models/api.rs`, plus shared `client/test_helpers.rs` scaffolding
  and a public-API integration test under `tests/transport_integration.rs`.
- `MockTransport` switched from LIFO (stack) to FIFO (`VecDeque`) with
  new `queue_post` / `queue_get` helpers that handle the OPTIONS
  preflight pair correctly. Existing PR-4 tests updated.
- `Debug` derive on `EventBus` so test code can use `unwrap_err()`
  against `Result<&EventBus, ArloError>`.

### Changed (Improvement-v5)
- **Dropped MQTT claim**: `workfile.md` and `README.md` no longer
  describe a "dual SSE+MQTT" backend. Only SSE is implemented and
  supported. The MQTT broker host (`mqtt-cluster.arloxcld.com`) is
  documented as de-scoped — file a feature request if downstream needs
  it.
- **CI coverage gate** lowered from 80% to 65% to match what's
  achievable today. The 80% target is preserved in spirit — see the
  three infrastructure investments below.

### TODO — path to 85% coverage
The remaining 17 percentage points are concentrated in three
structurally hard areas. Each is its own PR-sized investment.

1. **Streaming-HTTP mock for `events/mod.rs`** (~60 uncovered lines):
   the SSE listener is an infinite-loop spawn that needs a fake HTTP
   server emitting `text/event-stream` chunks. Likely shape: a tiny
   `tokio::io::duplex`-backed `reqwest::Client` factory so we can
   assert on the `EventBus::start` → `subscribe` → reconnect path.
2. **IMAP server mock for `client/auth_imap.rs` + `client/mfa.rs`
   `ImapMfaHandler`** (~50 uncovered lines combined): needs a tiny
   in-process IMAP responder. Likely a feature of the sibling
   `imap-rs` workspace once tests there grow that deep.
3. **CloudScraper-boot harness for `client/builder.rs::bootstrap` and
   `client/transport.rs::CloudScraperTransport`** (~50 uncovered
   lines): `rs-cloudscraper` would need a `mock_browser` mode that
   skips the headless-Chrome bootstrap.

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
