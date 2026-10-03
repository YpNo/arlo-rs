//! Scaffolding shared by the manual examples (`list_cameras`,
//! `push_login`, `peek_stream_url`, `probe_rtsps_setup`): tracing, config
//! load and validation, session restore or IMAP-automated MFA, camera
//! selection, and the event helpers that print property **keys** and
//! never values (values can carry credentials).
//!
//! Each probe pulls what it needs; what it leaves is dead code there.
#![allow(dead_code, reason = "each probe uses a subset of the shared helpers")]

use arlo_rs::config::ArloConfig;
use arlo_rs::models::api::Device;
use arlo_rs::models::events::ArloEvent;
use arlo_rs::secrecy::{ExposeSecret, SecretString};
use arlo_rs::{ArloClient, ImapMfaHandler};
use std::path::Path;

pub const CONFIG_PATH: &str = "config.toml";
pub const CACHE_PATH: &str = ".arlo_session.json";
/// `activityState` while the mobile app views a camera.
pub const USER_STREAM_ACTIVE: &str = "userStreamActive";

/// `RUST_LOG`-driven tracing, `arlo_rs=warn` by default (the probes print
/// their own report; the library's warnings are enough).
pub fn init_tracing() {
    init_tracing_with("arlo_rs=warn");
}

/// `RUST_LOG`-driven tracing with `default` as the filter when unset.
pub fn init_tracing_with(default: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default)),
        )
        .init();
}

/// `ARLO_PROBE_SECS`, or `default` when unset or unparsable.
pub fn window_secs(default: u64) -> u64 {
    std::env::var("ARLO_PROBE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// `config.toml` with credentials and IMAP-automated email MFA, or why not.
pub fn load_and_validate_config() -> Result<ArloConfig, String> {
    let config = load_config()?;
    require_credentials(&config)?;
    require_imap(&config)?;
    Ok(config)
}

/// `config.toml`, parsed, or why not.
pub fn load_config() -> Result<ArloConfig, String> {
    if !Path::new(CONFIG_PATH).exists() {
        return Err(format!(
            "`{CONFIG_PATH}` not found. Copy `config.toml.example` and fill it in."
        ));
    }
    ArloConfig::load_from_file(CONFIG_PATH)
        .map_err(|e| format!("Failed to parse `{CONFIG_PATH}`: {e}"))
}

/// A `[credentials]` block with a non-empty email and password.
pub fn require_credentials(config: &ArloConfig) -> Result<(), String> {
    let creds = config
        .credentials
        .as_ref()
        .ok_or_else(|| "Missing `[credentials]` block in config.toml".to_string())?;
    if creds.email.as_deref().unwrap_or("").is_empty() {
        return Err("`[credentials].email` is empty in config.toml".to_string());
    }
    if secret_is_empty(creds.password.as_ref()) {
        return Err("`[credentials].password` is empty in config.toml".to_string());
    }
    Ok(())
}

/// An enabled `[mfa.imap]` block with a mailbox, an app password and a
/// host or provider: what the IMAP-automated examples need.
pub fn require_imap(config: &ArloConfig) -> Result<(), String> {
    let imap = config
        .mfa
        .as_ref()
        .and_then(|m| m.imap.as_ref())
        .ok_or_else(|| {
            "Missing `[mfa.imap]` block — this example requires IMAP-automated MFA".to_string()
        })?;
    if !imap.enabled.unwrap_or(false) {
        return Err("`[mfa.imap].enabled` must be `true` for this example. \
             Either enable it or use `examples/simple` for the interactive flow."
            .to_string());
    }
    if imap.username.as_deref().unwrap_or("").is_empty() {
        return Err("`[mfa.imap].username` is empty in config.toml".to_string());
    }
    if secret_is_empty(imap.password.as_ref()) {
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
            "`[mfa.imap]` needs either `host` or `provider` (gmail / outlook / yahoo)".to_string(),
        );
    }
    Ok(())
}

fn secret_is_empty(secret: Option<&SecretString>) -> bool {
    secret.is_none_or(|p| p.expose_secret().is_empty())
}

/// Restore the cached session or run the IMAP-automated MFA.
pub async fn authenticate(config: &ArloConfig) -> Result<ArloClient, Box<dyn std::error::Error>> {
    let mut client = ArloClient::builder()
        .session_cache(CACHE_PATH)
        .build()
        .await?;
    if client.is_authenticated() {
        println!("✓ Restored a valid session from `{CACHE_PATH}`.");
        return Ok(client);
    }
    println!("→ No valid cached session; running IMAP-automated MFA...");
    let imap_cfg = config
        .mfa
        .as_ref()
        .and_then(|m| m.imap.clone())
        .ok_or("validated config lost its [mfa.imap] block")?;
    client
        .authenticate_with_handler(config, ImapMfaHandler::new(imap_cfg))
        .await?;
    println!("✓ Authenticated.");
    Ok(client)
}

/// Print the session's identity: the `device_id` is the trusted-browser
/// identity, and a prefix is enough to recognise it in a bug report.
pub fn print_identity(client: &ArloClient) {
    println!(
        "  user_id  : {}\n  device_id: {}…\n",
        client.user_id().unwrap_or("<missing>"),
        client.device_id().chars().take(8).collect::<String>()
    );
}

/// Print the account's camera-class devices (cameras, bridges, doorbells,
/// chimes), ids and state; never a presigned URL, only that one exists.
pub fn print_camera_devices(devices: &[Device]) {
    let cameras: Vec<&Device> = devices
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
        return;
    }
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
        if cam.presigned_last_image_url.is_some() {
            println!("       thumbnail : (presigned URL available)");
        }
        println!();
    }
}

/// The devices a live view can come from.
pub fn streamable_cameras(devices: &[Device]) -> Vec<&Device> {
    devices
        .iter()
        .filter(|d| matches!(d.device_type.as_str(), "camera" | "arloq" | "doorbell"))
        .collect()
}

/// Sorted property names of a bus event.
pub fn property_keys(event: &ArloEvent) -> Vec<&str> {
    let mut keys: Vec<&str> = event
        .properties
        .as_ref()
        .and_then(|p| p.as_object())
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    keys
}

/// Whether the URL joins a user's own view (`watchalong=true`).
pub fn is_watchalong(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| {
        u.query_pairs()
            .any(|(k, v)| k == "watchalong" && v == "true")
    })
}

/// The event's `activityState`, if any.
pub fn activity_state(event: &ArloEvent) -> Option<&str> {
    event
        .properties
        .as_ref()?
        .get("activityState")
        .and_then(|v| v.as_str())
}
