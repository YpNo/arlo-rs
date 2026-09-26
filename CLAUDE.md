# Project Context: Arlo's camera library (arlo-rs)
**Role**: You are a Senior Rust Protocol Engineer & Arlo Specialist.

## Core Directives
1. **Hexagonal Integrity**: Strictly separate Arlo protocol logic (Domain) from transport/MFA solving (Infrastructure). See `.agents/rules/architecture.md`.
2. **Protocol Fidelity**: We must mimic the Arlo Web Dashboard exactly. This includes undocumented headers, the 6-step OAuth ceremony (login → get_factors → start_auth → finish_auth → validate_access_token → validate_session_v3), and JA4 TLS signatures (Chrome emulation from `stealthscraper-rs`, driven through `wreq`).
3. **Quality & Security Gates**: Every contribution must pass the Zero-Warning and Dependency Audit gates. See `.agents/rules/quality-standards.md`.
4. **Resilient Session Management**: Use `secrecy::SecretString` for all tokens (zeroized on drop). Session state is snapshotted via `SessionToken` / `ArloClient::reattach()`. Cache files are `0600` on Unix, written temp-file-then-rename (`auth::write_owner_only`), never through a symlink; every cache failure is logged at WARN. Cache files also carry the cookie jar; on a stale token keep `device_id` + cookies (that is the trusted-browser identity) and drop only the token.

## Module Map

### `src/client/` — Core orchestration layer
| File | Responsibility |
|---|---|
| `mod.rs` | `ArloClient` struct: transport injection, lazy `EventBus` init, `reattach()` / `session_token()` |
| `builder.rs` | `ArloClientBuilder` (fluent) + internal `bootstrap()`: default `WreqTransport`, or the headless-Chrome proxy with `.browser(true)` (`browser` feature) |
| `auth/` | `mod.rs`: `AuthManager` (token + cookies + `device_id` + `0600` cache), `persist_session()`. `ceremony.rs`: the raw `ocapi` calls (`login` … `session/v3`, `devicesupport`, `getFactorId`, trusted `startAuth`). `flow.rs`: `authenticate*`, trusted-browser fast path, `complete_session` (pairing with `browserAuthCode`). `push.rs`: PUSH polling. `session.rs`: `login_v2`, `logout` |
| `auth_imap.rs` | IMAP OTP fetcher over the `imap-rs-client` / `imap-rs-tls` crates; OTP regexes on `regex-lite` |
| `mfa.rs` | `MfaHandler` trait + `ImapMfaHandler`, `StdinMfaHandler`, `StaticOtpHandler` |
| `transport.rs` | `HttpTransport` trait (+ `export_cookies`/`import_cookies`) + `WreqTransport` (prod default) + `CloudScraperTransport` (`browser` feature) + `MockTransport` (tests) |
| `cookies.rs` | `PersistentJar`: `wreq` cookie store with JSON export/import — Arlo's "trusted browser" state |
| `ws.rs` | `WsConnector` port (+ `TungsteniteConnector` adapter, `MockWsConnector` in tests) — the seam the MQTT bus and WebRTC signaling open sockets through |
| `api.rs` | Generic REST helpers: `execute_request`, OPTIONS preflight, 429/1015 rate-limit retry, JSON envelope unwrap |
| `devices/` | `mod.rs`: `get_devices`, `xcloud_header`. `stream.rs`: legacy `/startStream` trio + URL helpers. `modes.rs`: v3 `activeMode` (+ legacy fallback on 404 only), locations, `pick_location` (gateway match, first only when no gateways anywhere, else `DeviceNotFound`), `AutomationConfig`, `set_mode_by_name`. `actuation.rs`: `notify`-style commands. `media.rs`: audio playback. `sensors.rs`: ambient history decoder |
| `local_hub.rs` | `LocalHubClient`: LAN-direct SmartHub client with rustls leaf-cert pinning (RATLS) |
| `ratls.rs` | Raw RATLS token spoofing for Cloudflare-bypass on local hub connections |
| `library.rs` | `get_library`: cloud DVR media-library listing between two dates (`LibraryQuery` → `MediaItem`s) |
| `endpoints.rs` | `ArloEndpoints`: overrideable auth + API hosts (mockito-friendly) |

### `src/events/` — MQTT-over-WSS telemetry bus
- `EventBus` (`mod.rs`): one reconnecting background task, `broadcast::Sender<ArloEvent>`, `watch::Receiver<ConnectionState>`; `dispatch_payload` routes single events and batches
- `mqtt.rs`: MQTT 3.1.1 over the `WsConnector` seam — `CONNECT` (`user_<uid>_<rand>` / `<uid>` / `<token>`), `SUBSCRIBE` to `allowedMqttTopics` (fallback: hand-built `d/<xCloudId>/out/…` set) + `u/<uid>/in/#`, `PINGREQ` every 30 s, `PUBLISH` → `ArloEvent`
- `ConnectionState`: `Connecting | Connected | Disconnected` — exhaustive enum, no wildcard arms. Liveness: backoff `next_backoff` (jittered, capped), `IDLE_TIMEOUT` half-open detection, SUBACK all-rejected ⇒ session error, decode error ⇒ reconnect. The token is a `watch::Receiver` from `AuthManager::token_rx()`, read at every CONNECT — never replace `client.auth` after `events()` has started, and never copy the token into `MqttParams`

### `src/models/` — Pure data layer (no I/O)
`auth.rs` (+ `Meta::into_error`), `auth_advanced.rs`, `events.rs` (`ArloEvent::active_mode_change`), `envelope.rs`, `validate.rs` (`arlo_wss_url`, `id_segment`, `date_yyyymmdd`, `hub_media_path`, `mqtt_filter_ok` — fail-closed checks on cloud-supplied hosts, ids and filters; `StreamUrl::parse` and `SipInfo::validate` build on it), `redact.rs` (`redact_for_log`, `excerpt`, `redact_userinfo` — the one place the log/error redaction policy lives), `error_codes.rs` (`ErrorAction`, `classify`, official messages — branch on `ArloError::action()`, never on raw codes), `automation.rs` (`AutomationConfig`, `Location::hosts_device`), `library.rs`, `ratls.rs`, `sip.rs`, `api.rs`

### Other modules
- `src/error.rs` — `ArloError` (10 `thiserror` variants) + `action()` classifier
- `src/config.rs` — TOML `ArloConfig` (`credentials`, `client`, `mfa`, `mfa.imap`)
- `src/endpoints.rs` — Static Arlo URL constants
- `src/headers.rs` — Host constants

## Knowledge Map
- **Architecture**: `.agents/rules/architecture.md`
- **Quality & Security**: `.agents/rules/quality-standards.md`
- **Coding Style**: `.agents/rules/coding-style.md`
- **Patterns**: `.agents/rules/patterns.md`
- **Workflows**:
    - `.agents/workflows/feature-cycle.md` for new logic
    - `.agents/workflows/protocol-update.md` for Arlo API changes

## Memory Anchors
- **Edition 2024** & stdlib-first preference.
- **Error Handling**: `thiserror` for library boundaries; `anyhow` only in binaries/integration tests.
- **Instrumentation**: `log` crate present (legacy migration in progress) — all **new** code must use `tracing` only; never add new `log::` call sites.
- **Safety**: No `unsafe` — enforced by `[lints.rust] unsafe_code = "forbid"` in Cargo.toml (tests and examples included). `unwrap()` banned; use `.expect("SAFETY: <reason>")`.
- **Tokens**: `secrecy::SecretString` (re-exported as `arlo_rs::secrecy`) wraps every secret the crate holds — access tokens, `AuthResponseData::token`, `SessionV3Response::token`, `StartAuthData::factor_auth_code`, `SipCallInfo::password`, the config passwords, the local-hub bearer — zeroized on drop, exposed only at the single wire-write site, never formatted via `Debug`. Structs holding one do not derive `Serialize`. Wire DTOs whose secret must stay a plain `String` for serde (`AuthRequest`, `VerifyFactorRequest`, `FinishAuthPushRequest`, `AuthResult`, `MfaChallenge`, `RatlsTokenData`, `IceServer`, `Device`, `Location`, `AuthCacheSchema`, `HttpRequest`/`HttpResponse`, `ArloClientBuilder`) implement `Debug` by hand and print `[REDACTED]` for the secret field — keep it that way when adding fields. Never put an upstream body into an error or log line: use `models::redact::excerpt` (redacted, control-stripped, 256-byte cap) or `redact_for_log`.
- **Shared state**: `api_version` is an `ApiVersionCell` (atomic), never a lock; no `.unwrap()` on lock guards anywhere in `src/`.
- **Testing**: Use `ArloClient::with_transport(Arc<dyn HttpTransport>, endpoints)` + `MockTransport` from `transport::test_support` (and `with_transports(..)` + `ws::test_support::MockWsConnector` for the event bus / signaling); use `ArloClientBuilder::endpoints()` to point at a `mockito` server. `ArloClientBuilder::build()` is cheap (no browser) and may be pointed at `mockito`; never use `.browser(true)` in unit tests.
- **IMAP MFA**: `ImapMfaHandler::prepare()` captures the UNSEEN-baseline (UIDs) **before** OTP dispatch. Uses the published `imap-rs-client` / `imap-rs-tls` crates. The mailbox is untrusted input: the IMAP `FROM` key is only a substring match, so `auth_imap` re-checks the parsed `From:` address (headers-only PEEK first), selects by UID newest-first with the UID verified on each FETCH, and skips messages over 512 KiB or 16 MIME parts. Keep those checks when touching the fetch loop; `imap-rs-client` has no `UID FETCH`, hence the SEARCH/UID SEARCH pairing in `seq_for_uid`.
- **Dependencies**: stdlib first — epoch millis come from `client::api::now_millis()` (no `chrono`), patterns from `regex-lite`, cert types from `rustls::pki_types`. `tokio` is on a narrow feature list; do not re-enable `full`. Run `cargo deny check` after any manifest change (the duplicate skip list is curated per crate).
- **RATLS / Local Hub**: `LocalHubClient` uses a custom rustls `PinnedLeafVerifier` — fails closed on cert mismatch.
- **Error verdicts**: branch on `ArloError::action()`. A TLS/certificate failure in a `NetworkError` source chain is `Fatal`, never `Retry`. Drop a cached token only on `Reauth`; propagate `Fatal` (lockout) and `Retry` (transport) from the trusted-browser probe rather than continuing the ceremony; pin `api_version = Legacy` on 404 only, never 403; use `Meta::into_error` / `unwrap_envelope` / `check_envelope_status` so Arlo's own code travels with the error — never fabricate a code.
- **Deadlines**: no `.await` on the network without one. HTTP: `transport::{CONNECT_TIMEOUT, REQUEST_TIMEOUT}` on both transports; WebSocket dial: `ws::CONNECT_TIMEOUT`; MQTT handshake: `mqtt::HANDSHAKE_TIMEOUT`; signaling: `livestream::SIGNALING_TIMEOUT`; hub: `local_hub::HUB_*_TIMEOUT`; IMAP: `auth_imap::{BASELINE_BUDGET, OTP_TOTAL_BUDGET}`. Test a new wait with `MockWsConnector` (no script = hangs) under `#[tokio::test(start_paused = true)]`.
- **Trust boundary**: Arlo responses are input, not truth. No HTTP client follows redirects (`Policy::none()` on all three); `Authorization` is attached only when the URL's origin equals `auth_host` or `api_host` (`api::same_origin`), and the OPTIONS preflight carries no credentials or custom headers (`build_preflight_headers`). Text Arlo sends goes through `redact::excerpt` before an error or prompt. A host from a response is dialed only through `models::validate::arlo_wss_url`; an id goes into a URL only through `id_segment`; a stream URL exists only via `StreamUrl::parse`; bodies are read through the capped readers in `transport.rs` (`MAX_RESPONSE_BYTES`) — never `.text()`/`.bytes()` directly.
- **Stealth Integrity**: Arlo's Cloudflare gate is TLS/HTTP2-fingerprint only (no JS challenge). `WreqTransport` is built from `stealthscraper_rs::impersonation_client(&profile)` — never build a `wreq` client any other way, and never depend on `wreq` directly (use the `stealthscraper_rs::wreq` re-export so client and emulation cannot drift). `BrowserProfile::random()` is selected at bootstrap; the builder already installs the `User-Agent`, `Sec-CH-UA*` and `Accept-Language` defaults from that same profile, and per-request headers from the orchestration layer win over them.

<!-- rtk-instructions v2 -->
## RTK (Rust Token Killer) - Token-Optimized Commands

### Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

### RTK Commands by Workflow

#### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

#### Test (60-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

#### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

#### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

#### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

#### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%)
rtk find <pattern>      # Find grouped by directory (70%)
```

#### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

#### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

#### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

#### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

### Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->