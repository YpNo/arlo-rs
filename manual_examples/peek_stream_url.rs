//! Manual probe: while you watch a camera in the Arlo mobile app, does
//! `GET /startStream` (action `get`) return the app's stream URL, and
//! what does the event bus say?
//!
//! ## ⚠️ Hits your live Arlo account
//!
//! Same prerequisites as `list_cameras` (`config.toml` with IMAP-automated
//! email MFA). Run it, then open a live view of a camera in the app, keep
//! it open ~20 s, close it, and wait for the probe to finish:
//!
//! ```bash
//! RUST_LOG=arlo_rs=info cargo run --example peek_stream_url
//! ARLO_PROBE_SHOW_URL=1 cargo run --example peek_stream_url   # print full URLs
//! ARLO_PROBE_SECS=120 cargo run --example peek_stream_url      # longer window
//! ```
//!
//! Every 5 s it peeks each camera's active stream URL (redacted unless
//! `ARLO_PROBE_SHOW_URL=1`) and prints every bus event as
//! `resource / sorted property keys / activityState` — never property
//! values, which can carry credentials.

use arlo_rs::config::ArloConfig;
use arlo_rs::models::events::ArloEvent;
use arlo_rs::{ArloClient, ImapMfaHandler};
use std::path::Path;
use std::time::Duration;

const CONFIG_PATH: &str = "config.toml";
const CACHE_PATH: &str = ".arlo_session.json";
const PEEK_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_WINDOW_SECS: u64 = 90;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("arlo_rs=warn")),
        )
        .init();
    println!("=== arlo-rs manual probe: peek the app's stream URL + bus events ===\n");

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
    let show_url = std::env::var("ARLO_PROBE_SHOW_URL").is_ok_and(|v| v == "1");
    let window_secs = std::env::var("ARLO_PROBE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_WINDOW_SECS);

    let mut client = ArloClient::builder()
        .session_cache(CACHE_PATH)
        .build()
        .await?;
    if client.is_authenticated() {
        println!("✓ Restored a valid session from `{CACHE_PATH}`.");
    } else {
        println!("→ No valid cached session; running IMAP-automated MFA...");
        client
            .authenticate_with_handler(&config, ImapMfaHandler::new(imap_cfg))
            .await?;
        println!("✓ Authenticated.");
    }

    let devices = client.get_devices().await?;
    let cameras: Vec<_> = devices
        .iter()
        .filter(|d| matches!(d.device_type.as_str(), "camera" | "arloq" | "doorbell"))
        .collect();
    println!(
        "✓ {} camera(s). Probing for {window_secs} s — open a live view in the app now.\n",
        cameras.len()
    );

    // Bus events, redacted, printed as they arrive.
    let bus = client.events().await?;
    let mut rx = bus.subscribe();
    let printer = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => print_event(&event),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    println!("  [bus] lagged, {n} events skipped");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(window_secs);
    let mut last: Vec<Option<String>> = vec![None; cameras.len()];
    while tokio::time::Instant::now() < deadline {
        for (i, cam) in cameras.iter().enumerate() {
            let peek = client.get_stream_url(cam).await;
            let shown = match &peek {
                Ok(Some(url)) if show_url => Some(url.as_str().to_string()),
                Ok(Some(url)) => Some(url.redacted()),
                Ok(None) => None,
                Err(e) => Some(format!("error: {e}")),
            };
            if shown != last[i] {
                match &shown {
                    Some(v) => println!("  [peek] {} ({}): {v}", cam.device_name, cam.device_id),
                    None => println!(
                        "  [peek] {} ({}): no active stream",
                        cam.device_name, cam.device_id
                    ),
                }
                last[i] = shown;
            }
        }
        tokio::time::sleep(PEEK_INTERVAL).await;
    }
    printer.abort();

    println!("\n→ Logging out...");
    client.logout().await?;
    println!("✓ Done.");
    Ok(())
}

fn print_event(event: &ArloEvent) {
    let mut keys: Vec<&str> = event
        .properties
        .as_ref()
        .and_then(|p| p.as_object())
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    let activity = event
        .properties
        .as_ref()
        .and_then(|p| p.get("activityState"))
        .and_then(|v| v.as_str());
    println!(
        "  [bus] action={} resource={} from={:?} keys={:?} activityState={:?}",
        event.action, event.resource, event.source, keys, activity
    );
}

fn load_and_validate_config() -> Result<ArloConfig, String> {
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
