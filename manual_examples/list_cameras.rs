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
//! headless           = true
//! ```
//!
//! ## Run it
//!
//! ```bash
//! RUST_LOG=rs_arlo=info cargo run --example list_cameras
//! ```
//!
//! Expected behaviour:
//! 1. Loads `config.toml`.
//! 2. Boots the stealth proxy (~5–10 s on cold start).
//! 3. Either restores the cached session or runs the full
//!    `login → factors → start_auth → IMAP fetch → finish_auth → trust →
//!    validate_session_v3 → device_support_v2` flow.
//! 4. Fetches the device list and prints every camera-class device
//!    with its name, model, firmware, parent base-station, and online
//!    state.
//! 5. Logs out cleanly.

use rs_arlo::config::ArloConfig;
use rs_arlo::{ArloClient, ImapMfaHandler};
use std::path::Path;

const CONFIG_PATH: &str = "config.toml";
const CACHE_PATH: &str = ".arlo_session.json";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    println!("=== rs-arlo manual smoke test: list cameras ===\n");

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
    println!("→ Booting stealth proxy + restoring cache (this can take a few seconds)...");
    let mut client = ArloClient::builder()
        .session_cache(CACHE_PATH)
        .headless(true)
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
    println!(
        "  user_id  : {}\n  device_id: {}\n",
        client.user_id().unwrap_or("<missing>"),
        client.device_id()
    );

    // ---- 4. List cameras ----
    println!("→ Fetching device list...");
    let devices = client.get_devices().await?;
    let cameras: Vec<_> = devices
        .iter()
        .filter(|d| matches!(d.device_type.as_str(), "camera" | "arloq" | "arlobridge" | "doorbell" | "chime"))
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
            if let Some(fw) = &cam.firm_version {
                println!("       firmware  : {fw}");
            }
            if let Some(mac) = &cam.mac_address {
                println!("       mac       : {mac}");
            }
            if cam.presigned_last_image_url.is_some() {
                println!("       thumbnail : (presigned URL available)");
            }
            println!();
        }
    }

    // ---- 5. Logout ----
    println!("→ Logging out...");
    client.logout().await?;
    println!("✓ Logged out cleanly.\n");

    Ok(())
}

/// Loads `config.toml` and refuses to proceed unless every field this
/// example needs is present and non-empty. Friendlier than letting the
/// auth flow fail mid-stream with a generic message.
fn load_and_validate_config() -> Result<ArloConfig, String> {
    if !Path::new(CONFIG_PATH).exists() {
        return Err(format!(
            "`{CONFIG_PATH}` not found. Copy `config.toml.example` and fill it in."
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

    let imap = config
        .mfa
        .as_ref()
        .and_then(|m| m.imap.as_ref())
        .ok_or_else(|| {
            "Missing `[mfa.imap]` block — this example requires IMAP-automated MFA"
                .to_string()
        })?;
    if !imap.enabled.unwrap_or(false) {
        return Err(
            "`[mfa.imap].enabled` must be `true` for this example. \
             Either enable it or use `examples/simple` for the interactive flow."
                .to_string(),
        );
    }
    if imap.username.as_deref().unwrap_or("").is_empty() {
        return Err("`[mfa.imap].username` is empty in config.toml".to_string());
    }
    if imap.password.as_deref().unwrap_or("").is_empty() {
        return Err(
            "`[mfa.imap].password` is empty in config.toml — use an app-password \
             (regular passwords don't work for IMAP on most providers)"
                .to_string(),
        );
    }
    if imap.host.as_deref().unwrap_or("").is_empty()
        && imap.provider.as_deref().unwrap_or("").is_empty()
    {
        return Err(
            "`[mfa.imap]` needs either `host` or `provider` (gmail / outlook / yahoo)"
                .to_string(),
        );
    }

    Ok(config)
}

/// `tracing` subscriber matching the other examples. Defaults to INFO
/// for `rs_arlo`, WARN elsewhere; `RUST_LOG` overrides.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,rs_arlo=info"));
    fmt().with_env_filter(filter).init();
}
