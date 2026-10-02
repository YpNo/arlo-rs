//! Manual end-to-end smoke test: authenticate via IMAP-automated MFA,
//! list the cameras on the account, and log out.
//!
//! ## ⚠️ Hits your live Arlo account
//!
//! This binary opens a real authenticated session against
//! `ocapi-app.arlo.com` / `myapi.arlo.com` and dispatches a real OTP
//! email. Don't wire it into CI — it's a manual smoke test.
//!
//! ## Prerequisites
//!
//! `config.toml` (next to `Cargo.toml`) must contain:
//!
//! ```toml
//! [credentials]
//! email    = "you@example.com"
//! password = "your-arlo-password"
//!
//! [mfa]
//! preferred_method = "EMAIL"   # IMAP automation only works with EMAIL
//!
//! [mfa.imap]
//! enabled  = true              # MUST be true for this script
//! provider = "gmail"           # or "outlook" / "yahoo" / explicit host
//! username = "you@example.com"
//! password = "your-app-password"   # use an app-password, not your real one
//! # delete_after_read = false
//!
//! [client]
//! session_cache_path = ".arlo_session.json"
//! # use_browser      = false   # default: browser-less wreq transport
//! ```
//!
//! ## Run it
//!
//! ```bash
//! RUST_LOG=arlo_rs=info cargo run --example list_cameras
//! ```
//!
//! Expected behaviour:
//! 1. Loads `config.toml`.
//! 2. Builds the browser-less `wreq` transport (instant; no Chrome needed).
//! 3. Either restores the cached session or runs the full
//!    `login → factors → start_auth → IMAP fetch → finish_auth → trust →
//!    validate_session_v3 → device_support_v2` flow.
//! 4. Fetches the device list and prints every camera-class device
//!    with its name, model, firmware, parent base-station, and online
//!    state.
//! 5. Logs out cleanly.

use arlo_rs::{ArloClient, ImapMfaHandler};

mod common;
use common::{CACHE_PATH, load_and_validate_config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init_tracing_with("warn,arlo_rs=info");

    println!("=== arlo-rs manual smoke test: list cameras ===\n");

    // ---- 1. Validate config ----
    let config = match load_and_validate_config() {
        Ok(c) => c,
        Err(why) => {
            eprintln!("✗ {why}");
            std::process::exit(2);
        }
    };
    let imap_cfg = config
        .mfa
        .as_ref()
        .and_then(|m| m.imap.clone())
        .expect("validated above");

    // ---- 2. Build client (programmatic — exercises the public builder) ----
    println!("→ Building client + restoring cached session...");
    let mut client = ArloClient::builder()
        .session_cache(CACHE_PATH)
        .build()
        .await?;

    // ---- 3. Authenticate ----
    if client.is_authenticated() {
        println!("✓ Restored a valid session from `{CACHE_PATH}` — skipping MFA.");
    } else {
        println!("→ No valid cached session. Running full IMAP-automated MFA flow...");
        println!("  (Arlo will email an OTP; ImapMfaHandler polls your inbox for it.)");
        client
            .authenticate_with_handler(&config, ImapMfaHandler::new(imap_cfg))
            .await?;
        println!("✓ Authenticated; session cached to `{CACHE_PATH}`.");
    }
    common::print_identity(&client);

    // ---- 4. List cameras ----
    println!("→ Fetching device list...");
    let devices = client.get_devices().await?;
    common::print_camera_devices(&devices);

    // ---- 5. Logout ----
    println!("→ Logging out...");
    client.logout().await?;
    println!("✓ Logged out cleanly.\n");

    Ok(())
}
