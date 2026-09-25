//! Manual end-to-end smoke test: authenticate via **PUSH** MFA, list
//! the cameras on the account, and log out.
//!
//! ## ⚠️ Hits your live Arlo account
//!
//! This binary opens a real authenticated session against
//! `ocapi-app.arlo.com` / `myapi.arlo.com` and triggers a real push
//! approval prompt on the phone signed into your Arlo mobile app.
//! Don't wire it into CI — it's a manual smoke test.
//!
//! ## What it verifies
//!
//! The `ArloClient::authenticate_with_push` flow, reproducing the Arlo
//! web client's PingOne push ceremony: `startAuth {factorType:"",
//! userId}` (sends the prompt) → poll `finishAuth {factorAuthCode,
//! isBrowserTrusted}` (no OTP); each poll is HTTP 200 with the state in
//! `meta` (`error:9233` = pending, `code:200`+token = approved) → pair
//! with `browserAuthCode` → continuation chain.
//!
//! ## Prerequisites
//!
//! 1. The Arlo mobile app installed and signed in on your phone, with
//!    push 2FA enabled on the account.
//! 2. `config.toml` (next to `Cargo.toml`) containing:
//!
//! ```toml
//! [credentials]
//! email    = "you@example.com"
//! password = "your-arlo-password"
//!
//! [mfa]
//! preferred_method = "push"    # MUST be "push" for this script
//!
//! [client]
//! session_cache_path = ".arlo_session_push.json"
//! # use_browser      = false   # default: browser-less wreq transport
//! ```
//!
//! No `[mfa.imap]` block is needed — push has no inbox to poll.
//!
//! ## Run it
//!
//! ```bash
//! RUST_LOG=arlo_rs=info cargo run --example push_login
//! ```
//!
//! Then **watch your phone** and tap "Approve" within the timeout
//! (default 120 s, polled every 3 s).
//!
//! Expected behaviour:
//! 1. Loads `config.toml`.
//! 2. Builds the browser-less `wreq` transport (instant; no Chrome needed).
//! 3. Either restores the cached session or runs
//!    `login → startAuth → [push prompt] → poll finishAuth → trust
//!    (browserAuthCode) → validate_session_v3 → device_support_v2`.
//! 4. Prints every camera-class device.
//! 5. Logs out cleanly.
//!
//! Tell me: did step 3 complete after you approved on the phone, did it
//! time out, or did it error — and paste the `RUST_LOG=info` lines
//! around "Awaiting push approval" / "finishAuth" if it failed.

use arlo_rs::ArloClient;
use arlo_rs::config::ArloConfig;
use std::path::Path;

const CONFIG_PATH: &str = "config.toml";
const CACHE_PATH: &str = ".arlo_session_push.json";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    println!("=== arlo-rs manual smoke test: PUSH login ===\n");

    // ---- 1. Validate config ----
    let config = match load_and_validate_config() {
        Ok(c) => c,
        Err(why) => {
            eprintln!("✗ {why}");
            std::process::exit(2);
        }
    };

    // ---- 2. Build client (programmatic — exercises the public builder) ----
    println!("→ Building client + restoring cached session...");
    let mut client = ArloClient::builder()
        .session_cache(CACHE_PATH)
        .build()
        .await?;

    // ---- 3. Authenticate via PUSH ----
    if client.is_authenticated() {
        println!("✓ Restored a valid session from `{CACHE_PATH}` — skipping MFA.");
        println!("  (Delete `{CACHE_PATH}` to force a fresh push login.)");
    } else {
        let interval = ArloClient::DEFAULT_PUSH_POLL_INTERVAL;
        let timeout = ArloClient::DEFAULT_PUSH_TIMEOUT;
        println!(
            "→ No cached session. Triggering a PUSH prompt — \
             APPROVE IT ON YOUR PHONE within {timeout:?} (polling every {interval:?})..."
        );
        client
            .authenticate_with_push(&config, interval, timeout)
            .await?;
        println!("✓ Push approved; session cached to `{CACHE_PATH}`.");
    }
    println!(
        "  user_id  : {}\n  device_id: {}\n",
        client.user_id().unwrap_or("<missing>"),
        client.device_id()
    );

    // ---- 4. Prove the session works: list cameras ----
    println!("→ Fetching device list...");
    let devices = client.get_devices().await?;
    let cameras: Vec<_> = devices
        .iter()
        .filter(|d| {
            matches!(
                d.device_type.as_str(),
                "camera" | "arloq" | "arlobridge" | "doorbell" | "chime"
            )
        })
        .collect();

    if cameras.is_empty() {
        println!("ℹ  No camera-class devices found on this account.");
    } else {
        println!("✓ {} camera(s) found:\n", cameras.len());
        for (i, cam) in cameras.iter().enumerate() {
            println!("  [{}] {}", i + 1, cam.device_name);
            println!("       device_id : {}", cam.device_id);
            println!("       parent_id : {}", cam.parent_id);
            println!("       type      : {}", cam.device_type);
            println!("       state     : {}", cam.state);
            if let Some(model) = &cam.model_id {
                println!("       model     : {model}");
            }
            println!();
        }
    }

    // ---- 5. Logout ----
    println!("→ Logging out...");
    client.logout().await?;
    println!("✓ Logged out cleanly.\n");
    println!("=== PUSH login smoke test PASSED ===");

    Ok(())
}

/// Loads `config.toml` and refuses to proceed unless the fields this
/// example needs are present. Friendlier than letting the auth flow
/// fail mid-stream with a generic message.
fn load_and_validate_config() -> Result<ArloConfig, String> {
    if !Path::new(CONFIG_PATH).exists() {
        return Err(format!(
            "`{CONFIG_PATH}` not found. Copy `config.toml.example` and fill it in \
             (see this file's header for the minimal push layout)."
        ));
    }
    let config = ArloConfig::load_from_file(CONFIG_PATH)
        .map_err(|e| format!("Failed to parse `{CONFIG_PATH}`: {e}"))?;

    let creds = config
        .credentials
        .as_ref()
        .ok_or_else(|| "Missing `[credentials]` block in config.toml".to_string())?;
    if creds.email.as_deref().unwrap_or("").is_empty() {
        return Err("`[credentials].email` is empty in config.toml".to_string());
    }
    if creds.password.as_deref().unwrap_or("").is_empty() {
        return Err("`[credentials].password` is empty in config.toml".to_string());
    }

    let preferred = config
        .mfa
        .as_ref()
        .and_then(|m| m.preferred_method.as_deref())
        .unwrap_or("");
    if !preferred.eq_ignore_ascii_case("push") {
        return Err(format!(
            "`[mfa].preferred_method` must be \"push\" for this example \
             (found {preferred:?}). Use `examples/simple` or \
             `manual_examples/list_cameras` for the email/IMAP flow."
        ));
    }

    Ok(config)
}

/// `tracing` subscriber matching the other examples. Defaults to INFO
/// for `arlo_rs`, WARN elsewhere; `RUST_LOG` overrides.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,arlo_rs=info"));
    fmt().with_env_filter(filter).init();
}
