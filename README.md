# arlo-rs

[![Rust CI](https://github.com/YpNo/arlo-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/YpNo/arlo-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/arlo-rs.svg)](https://crates.io/crates/arlo-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`arlo-rs` is a robust, asynchronous Rust client for the Arlo camera ecosystem. It natively fully replaces legacy Python implementations by dynamically adapting strictly to Arlo's constantly updating telemetry metrics and undocumented headers.

Arlo's Cloudflare front admits clients by their TLS and HTTP/2 fingerprint and serves no JavaScript challenge, so `arlo-rs` talks to it through a `wreq` client that reproduces a real Chrome's ClientHello, HTTP/2 SETTINGS and client hints (measured by `stealthscraper-rs`) — no browser process, ~10 MB of RSS instead of a Chrome. A headless-Chrome MITM-proxy transport stays available behind the `browser` cargo feature as an escalation path.

---

## 🚀 Features

- **Cloudflare Bypass without a browser**: every REST request carries a measured Chrome JA4 TLS + HTTP/2 fingerprint and matching `User-Agent` / `Sec-CH-UA` client hints via `wreq`; rate limits (429 / Cloudflare 1015) are retried automatically. Opt into headless Chrome with the `browser` feature + `ArloClientBuilder::browser(true)` only if Cloudflare ever starts challenging.
- **MFA Support**: Integrated Multi-Factor Authentication (Email, Push, SMS) with persistent JSON disk caching to prevent 2FA lockouts.
- **Event bus over MQTT**: a reconnecting MQTT-over-WebSocket listener (the v3 successor to Arlo's SSE channel) broadcasts typed `ArloEvent`s on a `tokio::sync::broadcast` channel, subscribing to the exact topics the broker grants the account.
- **Camera Actuation**: Instantly toggle modes, trigger sirens, trigger snapshots, or start manual recordings with simple Rust methods.
- **Local Storage Access (RATLS)**: Issue specialized x509 certificates to bypass the cloud entirely and download videos natively off local Arlo SmartHubs over your LAN.
- **Live video**: v3 WebRTC signaling (`sipInfo/v2` + the `hmswebsocketproxy` offer/answer exchange) for the consumer's WebRTC stack, plus the legacy `/startStream` RTSPS path for un-migrated cameras.
- **Modes by name**: arm/disarm through the v3 automation API, resolving user-defined mode names to their UUIDs the way the Arlo app does.

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
arlo-rs = "0.2.0"
```

### Build prerequisites

`arlo-rs` links BoringSSL (through `stealthscraper-rs` → `wreq`), which is
built from source by `btls-sys` and needs a C/C++ toolchain, CMake and
`libclang` (for `bindgen`). The Rust toolchain is pinned in
`rust-toolchain.toml` (1.98.1, also the declared `rust-version`; `rustup` picks it up automatically). On
Debian / Ubuntu:

```bash
sudo apt-get install -y build-essential cmake libclang-dev
```

Without `libclang` the build stops inside `btls-sys` with
`Unable to find libclang`. If your `libclang` lives in a non-standard
place, point `LIBCLANG_PATH` at its directory. No browser binary is
required: the default transport has no Chrome. Only the opt-in `browser`
feature needs a Chrome/Chromium at runtime.

## 💻 Configuration

Two ways to configure the client:

**Programmatic (recommended for libraries / servers):**

```rust
let client = arlo_rs::ArloClient::builder()
    .session_cache(".arlo_session.json")
    .build()
    .await?;
```

**TOML file (convenient for local CLI tooling and the bundled examples):**
copy `config.toml.example` to `config.toml` in your project root:

```toml
[credentials]
email = "your_email@example.com"
password = "your-secure-password"

[client]
debug_mode = false
session_cache_path = ".arlo_session.json"
# use_browser = false  # true = headless-Chrome proxy transport (needs the `browser` feature)
# headless = true      # only consulted when use_browser = true
```

> ⚠️ **Never commit `config.toml` or `.arlo_session.json`.** Both are in
> `.gitignore` and contain credentials / session tokens. Treat them like
> a `.env` — rotate any secret that ends up in a working copy a teammate
> could see.

## 🔐 Multi-Factor Authentication (MFA)

Arlo enforces strict MFA on all accounts. `arlo-rs` provides flexible tools to handle these challenges interactively or programmatically:

1. **Push Notifications**: The easiest method if you have the Arlo app installed on your smartphone. `ArloClient::authenticate_with_push()` triggers the prompt and polls until you tap "Approve" (no OTP string is involved); the lower-level `start_auth()` / `finish_auth()` pair is available for custom flows.
2. **Email OTP**: Arlo sends a One-Time Password to your registered email address. This method is ideal for fully automated headless servers: the built-in `ImapMfaHandler` polls your mailbox over IMAP, verifies the sender, parses the 6-digit OTP from the Arlo email and submits it, with provider shortcuts (`"gmail"`, `"outlook"`, `"yahoo"`) so hosts need not be configured by hand. Any other OTP source (a bot, a webhook, a prompt) plugs in through the `MfaHandler` trait.
3. **SMS OTP**: Similar to Email, Arlo sends a text message to your registered phone number. You must retrieve this code and provide it to the client (`StdinMfaHandler` or your own `MfaHandler`).

Once a login is paired as a trusted browser, later logins on the same `device_id` + cookie jar (both kept in the session cache) complete without a second factor.

To avoid repeated MFA prompts, `arlo-rs` automatically serializes successful session tokens to the file specified in `session_cache_path` (e.g., `.arlo_session.json`). On subsequent startups, `ArloClient::from_config()` will instantly hydrate and validate this cached token without requiring user interaction.

> 🔒 Keep `config.toml` readable by you only (`chmod 600 config.toml`): it
> holds your Arlo password and IMAP app-password, and the library logs a
> warning at startup when other users can read it.

## 🧪 Scenarios & Examples

Three runnable examples live in `examples/`. Configure your `config.toml`
first (see above), then:

### `simple` — Authentication & Device Listing
Walks the full login flow: cache hydration, MFA dispatch via
`MfaHandler` (auto-picks `ImapMfaHandler` if `[mfa.imap]` is enabled,
else falls back to `StdinMfaHandler`), and a top-level dump of every
location and device on the account.

```bash
RUST_LOG=arlo_rs=info cargo run --example simple
```

### `advanced` — Streaming & Actuation
Reattaches to the cached session and demonstrates the legacy
`start_stream(&device)` path returning a playable RTSPS URL — the library
correlates the event-bus response internally. v3 cameras stream over
WebRTC instead (`sip_info` + `webrtc_negotiate`; media plane in the
consumer).

```bash
RUST_LOG=arlo_rs=info cargo run --example advanced
```

### `imap` — IMAP OTP Extraction Debugger
Connects to the configured IMAP server, grabs the most recent UNSEEN
Arlo email, and prints the OTP-extraction trace. Useful when retuning
the regex layer against a new Arlo email template.

```bash
RUST_LOG=arlo_rs=info cargo run --example imap
```

## 🛠️ Development & Cargo Commands

When contributing or debugging the `arlo-rs` library, you can use these essential `cargo` commands:

- **Check for compilation errors without building binaries:**
  ```bash
  cargo check --examples
  ```
- **Automatically format the codebase to standard Rust style:**
  ```bash
  cargo fmt
  ```
- **Run the Rust linter to catch common mistakes and improve performance:**
  ```bash
  cargo clippy --all-targets --all-features
  ```
- **Generate and open the highly-detailed HTML documentation locally:**
  ```bash
  cargo doc --no-deps --open
  ```
- **Audit dependencies (advisories, licenses, bans, duplicates):**
  ```bash
  cargo audit --deny warnings && cargo deny check
  ```

## 🧱 Architecture

`arlo-rs` is laid out hexagonally:

- **Domain** (`src/models/`): pure data — Arlo envelopes, events,
  automation, the error-code table, cloud-input validation and the
  log-redaction policy. No I/O.
- **Application** (`src/client/`): the `ArloClient` orchestration — the
  6-step auth ceremony, MFA handlers, device/mode/stream use cases, the
  session cache — written against two ports, `HttpTransport` and
  `WsConnector`.
- **Infrastructure**: `WreqTransport` (Chrome-impersonating HTTP via
  `stealthscraper-rs`), the `tokio-tungstenite` WebSocket connector behind
  the MQTT event bus and WebRTC signaling, the rustls-pinned local-hub
  client, and the IMAP OTP fetcher.

Arlo responses are treated as untrusted input: hosts, ids and stream URLs
are validated before use, bodies are size-capped, every network wait has
a deadline, and errors carry Arlo's own code so callers branch on
`ArloError::action()`. The rustdoc (`cargo doc --no-deps --open`) is the
API reference; `CLAUDE.md` carries the module map and design rules.

## ✅ Testing

- `cargo test --all-features` runs the unit and integration suites with no
  network: the orchestration layer is driven through `MockTransport` and
  `MockWsConnector` (or `mockito` for the real HTTP client). Timeout paths
  run under tokio's paused clock, so the suite finishes in seconds.
- CI enforces a coverage floor with `cargo tarpaulin --fail-under 72`
  (measured 78 % in September 2026; Codecov mirrors the same number). The
  IMAP fetcher, the local-hub request methods and the opt-in browser
  transport are the uncovered paths.
- **Live-account smoke test** (opt-in: it is `#[ignore]` and needs both a
  valid `config.toml` and `ARLO_E2E=1`, because it triggers a real second
  factor):
  ```bash
  ARLO_E2E=1 RUST_LOG=info cargo test --test e2e_arlo_api -- --ignored --nocapture
  ```

## 🔁 CI/CD

`.github/workflows/ci.yml` runs on every push and pull request: `cargo
fmt --check`, `clippy -D warnings`, tests, `cargo doc -D warnings`,
`cargo-deny` (licenses, bans, sources, advisories), `cargo audit`,
gitleaks secret scanning, coverage, and SonarQube (skipped on forks).
Every job has a timeout and every action is pinned to a commit SHA;
tools are installed at exact, checksum-verified versions.

Releases are driven by [release-plz](https://release-plz.dev) from the
last two jobs of the same workflow, so they run only after every gate is
green on `main`: `release-pr` keeps a "chore: release" pull request up to
date (version bump derived from the Conventional Commits since the last
tag, `CHANGELOG.md` section generated), and once `main` carries a version
that is not on crates.io yet, `release` publishes the crate, tags
`v<version>` and creates the GitHub release with the changelog as its
body. Configuration lives in `release-plz.toml`. Renovate keeps
dependencies and action digests current (three-day release age, weekly
lockfile maintenance, OSV alerts).

## 🔒 Security

- Secrets (`config.toml`, `.arlo_session.json`) are gitignored, written
  `0600`, and never logged: tokens and passwords live in
  `secrecy::SecretString`, `Debug` prints `[REDACTED]`, and upstream
  bodies reach error messages only as redacted, capped excerpts.
- The session token is sent only to the Arlo auth and API origins, no
  HTTP client follows redirects, TLS verification is never disabled (the
  local-hub client pins the hub's leaf certificate), and a certificate
  failure is classified as fatal rather than retried.
- Dependencies are audited on every push and weekly (`cargo audit`,
  `cargo deny`).
- To report a vulnerability, please open a
  [private security advisory](https://github.com/YpNo/arlo-rs/security/advisories/new)
  rather than a public issue — see [SECURITY.md](SECURITY.md).

## 📝 Changelog

Versioned with [Semantic Versioning](https://semver.org) and recorded in
[CHANGELOG.md](CHANGELOG.md) (Keep-a-Changelog format).

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Format and Lint your code (`cargo fmt` and `cargo clippy`)
4. Run the test suite (`cargo test`)
5. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
6. Push to the Branch (`git push origin feature/AmazingFeature`)
7. Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## ⚠️ Disclaimer

This library is engineered strictly for educational forensics and legitimate personal software integrations. The authors accept absolutely no responsibility for the misuse of this tool. This project is not affiliated, associated, authorized, endorsed by, or in any way officially connected with Arlo Technologies, Inc.
