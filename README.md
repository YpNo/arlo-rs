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
arlo-rs = "0.1.0"
```

### Build prerequisites

`arlo-rs` links BoringSSL (through `stealthscraper-rs` → `wreq`), which is
built from source by `boring-sys2` and needs a C/C++ toolchain, CMake and
`libclang` (for `bindgen`). On Debian / Ubuntu:

```bash
sudo apt-get install -y build-essential cmake libclang-dev
```

Without `libclang` the build stops inside `boring-sys2` with
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

1. **Push Notifications (Default)**: The easiest method if you have the Arlo app installed on your smartphone. When `start_auth()` is called with a Push factor, Arlo sends a notification to your phone. You simply tap "Approve", and the `finish_auth()` call (which does not require an OTP string for push) will succeed.
2. **Email OTP**: Arlo sends a One-Time Password to your registered email address. This method is ideal for fully automated headless servers. You can configure a background worker to connect to your mailbox via IMAP, parse the 6-digit OTP from the incoming Arlo email, and automatically supply it to `finish_auth()`. `arlo-rs` includes built-in fast IMAP polling natively (`client.fetch_imap_otp()`) which supports easy provider shortcuts (`"gmail"`, `"outlook"`, `"yahoo"`) so you don't even need to configure hosts manually!
3. **SMS OTP**: Similar to Email, Arlo sends a text message to your registered phone number. You must retrieve this code and provide it to the client.

To avoid repeated MFA prompts, `arlo-rs` automatically serializes successful session tokens to the file specified in `session_cache_path` (e.g., `.arlo_session.json`). On subsequent startups, `ArloClient::from_config()` will instantly hydrate and validate this cached token without requiring user interaction.

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
- **Run the E2E Integration tests (requires valid config.toml credentials):**
  ```bash
  RUST_LOG=info cargo test --test e2e_arlo_api -- --nocapture
  ```

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
