//! Manual probe: what does `get_stream_url` return while you watch a
//! camera in the Arlo mobile app?
//!
//! ## ⚠️ Hits your live Arlo account
//!
//! `get_stream_url` (`action: "get"` on `/startStream`) is **not** a
//! passive read: on an idle camera it hands out a fresh web session and
//! reaches the camera (live capture, 2026-09-28). This probe therefore
//! never polls. It queries a camera once, and only after the bus reported
//! `activityState == "userStreamActive"` for it: a user view is running
//! and the camera is awake anyway. During a user view the query returns a
//! `watchalong=true` URL that joins the user's session.
//!
//! Same prerequisites as `list_cameras` (`config.toml` with IMAP-automated
//! email MFA). Start the probe, then open a live view of a camera in the
//! app, keep it open ~20 s, close it:
//!
//! ```bash
//! cargo run --example peek_stream_url
//! ARLO_PROBE_SHOW_URL=1 cargo run --example peek_stream_url   # full URL + playback hint
//! ARLO_PROBE_SECS=180 cargo run --example peek_stream_url      # longer window
//! ```
//!
//! Bus events are printed as `resource / sorted property keys /
//! activityState`, never property values, which can carry credentials.

use arlo_rs::config::ArloConfig;
use arlo_rs::models::api::Device;
use arlo_rs::models::events::ArloEvent;
use arlo_rs::{ArloClient, ImapMfaHandler};
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

const CONFIG_PATH: &str = "config.toml";
const CACHE_PATH: &str = ".arlo_session.json";
const DEFAULT_WINDOW_SECS: u64 = 90;
/// A query made in the same instant the user's session is created can
/// return a fresh session instead of the watch-along; one retry after
/// this delay settles it.
const RETRY_DELAY: Duration = Duration::from_secs(2);
const USER_STREAM_ACTIVE: &str = "userStreamActive";
const ACTIVITY_IDLE: &str = "idle";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("arlo_rs=warn")),
        )
        .init();
    println!("=== arlo-rs manual probe: pick up the app's live view ===\n");

    let config = match load_and_validate_config() {
        Ok(c) => c,
        Err(why) => {
            eprintln!("✗ {why}");
            std::process::exit(2);
        }
    };
    let show_url = std::env::var("ARLO_PROBE_SHOW_URL").is_ok_and(|v| v == "1");
    let window_secs = std::env::var("ARLO_PROBE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_WINDOW_SECS);

    let client = authenticate(&config).await?;
    let devices = client.get_devices().await?;
    let cameras: Vec<&Device> = devices
        .iter()
        .filter(|d| matches!(d.device_type.as_str(), "camera" | "arloq" | "doorbell"))
        .collect();
    println!(
        "✓ {} camera(s). Listening for {window_secs} s — open a live view in the app now.\n",
        cameras.len()
    );

    let bus = client.events().await?;
    let mut rx = bus.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(window_secs);
    let mut in_view: HashSet<String> = HashSet::new();
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            msg = rx.recv() => match msg {
                Ok(event) => {
                    print_event(&event);
                    on_view_event(&client, &cameras, &event, &mut in_view, show_url).await;
                }
                Err(RecvError::Lagged(n)) => println!("  [bus] lagged, {n} events skipped"),
                Err(RecvError::Closed) => break,
            },
        }
    }

    println!("\n→ Logging out...");
    let mut client = client;
    client.logout().await?;
    println!("✓ Done.");
    Ok(())
}

async fn authenticate(config: &ArloConfig) -> Result<ArloClient, Box<dyn std::error::Error>> {
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

/// Query a camera once when a user view starts; forget it when the view
/// ends. Never queries a camera the bus has not reported as streaming.
async fn on_view_event(
    client: &ArloClient,
    cameras: &[&Device],
    event: &ArloEvent,
    in_view: &mut HashSet<String>,
    show_url: bool,
) {
    let Some(id) = event.resource.strip_prefix("cameras/") else {
        return;
    };
    match activity_state(event) {
        Some(USER_STREAM_ACTIVE) if in_view.insert(id.to_string()) => {
            if let Some(cam) = cameras.iter().find(|d| d.device_id == id) {
                pick_up_view(client, cam, show_url).await;
            }
        }
        Some(ACTIVITY_IDLE) if in_view.remove(id) => {
            println!("  [view] {id}: user view ended");
        }
        _ => {}
    }
}

async fn pick_up_view(client: &ArloClient, cam: &Device, show_url: bool) {
    let mut result = client.get_stream_url(cam).await;
    if matches!(&result, Ok(Some(u)) if !is_watchalong(u.as_str())) {
        println!(
            "  [view] {}: first URL is a fresh session, not a watch-along; retrying once",
            cam.device_name
        );
        tokio::time::sleep(RETRY_DELAY).await;
        result = client.get_stream_url(cam).await;
    }
    match result {
        Ok(Some(url)) => {
            let shown = if show_url {
                url.as_str().to_string()
            } else {
                url.redacted()
            };
            println!(
                "  [view] {} ({}): watchalong={} {shown}",
                cam.device_name,
                cam.device_id,
                is_watchalong(url.as_str())
            );
            if show_url {
                println!(
                    "         test playback now: gst-discoverer-1.0 -v '{}'",
                    url.as_str()
                );
            } else {
                println!(
                    "         rerun with ARLO_PROBE_SHOW_URL=1 for the full URL and a playback test"
                );
            }
        }
        Ok(None) => println!(
            "  [view] {}: no URL returned although the camera reports a user view",
            cam.device_name
        ),
        Err(e) => println!("  [view] {}: query failed: {e}", cam.device_name),
    }
}

fn is_watchalong(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| {
        u.query_pairs()
            .any(|(k, v)| k == "watchalong" && v == "true")
    })
}

fn activity_state(event: &ArloEvent) -> Option<&str> {
    event
        .properties
        .as_ref()?
        .get("activityState")
        .and_then(|v| v.as_str())
}

fn print_event(event: &ArloEvent) {
    let mut keys: Vec<&str> = event
        .properties
        .as_ref()
        .and_then(|p| p.as_object())
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    println!(
        "  [bus] action={} resource={} from={:?} keys={} activityState={:?}",
        event.action,
        event.resource,
        event.source,
        keys.len(),
        activity_state(event)
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
