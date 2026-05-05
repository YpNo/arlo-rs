# rs-arlo

[![Rust CI](https://github.com/YpNo/rs-arlo/actions/workflows/ci.yml/badge.svg)](https://github.com/YpNo/rs-arlo/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rs-arlo.svg)](https://crates.io/crates/rs-arlo)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`rs-arlo` is a robust, asynchronous Rust client for the Arlo camera ecosystem. It natively fully replaces legacy Python implementations by dynamically adapting strictly to Arlo's constantly updating telemetry metrics and undocumented headers.

Powered by `rs-cloudscraper`, this library natively bridges Cloudflare's advanced bot-protection by launching a stealthy headless Chrome proxy and shaping perfect JA4 TLS signatures for all REST API interactions.

---

## 🚀 Features

- **Cloudflare Bypass**: Native integration with `rs-cloudscraper` tunnels all REST and Streaming requests through a locally forged JA4 TLS profile that identically maps to legitimate Chrome Desktop sessions.
- **MFA Support**: Integrated Multi-Factor Authentication (Email, Push, SMS) with persistent JSON disk caching to prevent 2FA lockouts.
- **Asynchronous Actor System**: Decoupled `tokio::sync::broadcast` tasks handle background Server-Sent Events (SSE) keep-alives and device topology states natively without thread-locking.
- **Camera Actuation**: Instantly toggle modes, trigger sirens, trigger snapshots, or start manual recordings with simple Rust methods.
- **Local Storage Access (RATLS)**: Issue specialized x509 certificates to bypass the cloud entirely and download videos natively off local Arlo SmartHubs over your LAN.
- **Stream Redirection**: Plugs directly into FFmpeg or native browser decoders by fetching authorized RTSP/HLS stream URLs instantly.

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rs-arlo = "0.1.0"
```

## 💻 Configuration

Before executing the client, you must provide your base preferences. 
Copy `config.toml.example` to `config.toml` in your project root:

```toml
[credentials]
email = "your_email@example.com"
password = "your-secure-password"

[client]
debug_mode = false
session_cache_path = ".arlo_session.json"
headless = true # Set to false to visibly debug the browser automation
```

## 🔐 Multi-Factor Authentication (MFA)

Arlo enforces strict MFA on all accounts. `rs-arlo` provides flexible tools to handle these challenges interactively or programmatically:

1. **Push Notifications (Default)**: The easiest method if you have the Arlo app installed on your smartphone. When `start_auth()` is called with a Push factor, Arlo sends a notification to your phone. You simply tap "Approve", and the `finish_auth()` call (which does not require an OTP string for push) will succeed.
2. **Email OTP**: Arlo sends a One-Time Password to your registered email address. This method is ideal for fully automated headless servers. You can configure a background worker to connect to your mailbox via IMAP, parse the 6-digit OTP from the incoming Arlo email, and automatically supply it to `finish_auth()`. `rs-arlo` includes built-in fast IMAP polling natively (`client.fetch_imap_otp()`) which supports easy provider shortcuts (`"gmail"`, `"outlook"`, `"yahoo"`) so you don't even need to configure hosts manually!
3. **SMS OTP**: Similar to Email, Arlo sends a text message to your registered phone number. You must retrieve this code and provide it to the client.

To avoid repeated MFA prompts, `rs-arlo` automatically serializes successful session tokens to the file specified in `session_cache_path` (e.g., `.arlo_session.json`). On subsequent startups, `ArloClient::from_config()` will instantly hydrate and validate this cached token without requiring user interaction.

## 🧪 Scenarios & Examples

To help you validate your deployment and bypass functionality, we've bundled two fully automated testing scenarios in the `examples/` directory. Be sure to configure your `config.toml` first!

### Scenario 1: Authentication & Device Listing (`demo1.rs`)
This scenario walks you through the initial login process, queries Arlo for your requested 2FA Factor (Push/Email), caches the active token so you don't get prompted repeatedly, and then discovers all attached Hubs and Cameras dynamically. If you enabled IMAP in the config, it will automatically poll your inbox and extract the 6-digit OTP to complete the login seamlessly without user interaction!

```bash
RUST_LOG=info cargo run --example demo1
```

### Scenario 2: Streaming & Actuation (`demo2.rs`)
Once authenticated and verified by Scenario 1, this script re-attaches to the API using your cached session token (`.arlo_session.json`). It isolates the first camera on your account, requests an authorized live stream URL (containing dynamic AES tokens), and seamlessly initiates the Arlo state machine.

```bash
RUST_LOG=info cargo run --example demo2
```

## 🛠️ Development & Cargo Commands

When contributing or debugging the `rs-arlo` library, you can use these essential `cargo` commands:

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
