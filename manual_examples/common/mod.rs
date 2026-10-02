//! Scaffolding shared by the live-account probes (`peek_stream_url`,
//! `probe_rtsps_setup`): config load, session restore or IMAP-automated
//! MFA, camera selection, and the event helpers that print property
//! **keys** and never values (values can carry credentials).
//!
//! Each probe pulls what it needs; what it leaves is dead code there.
#![allow(dead_code, reason = "each probe uses a subset of the shared helpers")]

use arlo_rs::config::ArloConfig;
use arlo_rs::models::api::Device;
use arlo_rs::models::events::ArloEvent;
use arlo_rs::{ArloClient, ImapMfaHandler};
use std::path::Path;

pub const CONFIG_PATH: &str = "config.toml";
pub const CACHE_PATH: &str = ".arlo_session.json";
/// `activityState` while the mobile app views a camera.
pub const USER_STREAM_ACTIVE: &str = "userStreamActive";

/// `RUST_LOG`-driven tracing, `arlo_rs=warn` by default.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("arlo_rs=warn")),
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

/// `config.toml` with IMAP-automated email MFA enabled, or why not.
pub fn load_and_validate_config() -> Result<ArloConfig, String> {
    if !Path::new(CONFIG_PATH).exists() {
        return Err(format!(
            "`{CONFIG_PATH}` not found. Copy `config.toml.example` and fill it in."
        ));
    }
    let config = ArloConfig::load_from_file(CONFIG_PATH)
        .map_err(|e| format!("Failed to parse `{CONFIG_PATH}`: {e}"))?;
    let imap_ok = config
        .mfa
        .as_ref()
        .and_then(|m| m.imap.as_ref())
        .is_some_and(|i| i.enabled.unwrap_or(false));
    if !imap_ok {
        return Err("this probe needs `[mfa.imap].enabled = true` (see list_cameras)".to_string());
    }
    Ok(config)
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
