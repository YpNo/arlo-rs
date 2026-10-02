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
//! Bus events are printed as `resource / property-key count /
//! activityState`, never property values, which can carry credentials.
//!
//! ## Manifest fetch test
//!
//! Right after a watch-along URL is obtained, the probe fetches its DASH
//! manifest three ways, each on a fresh watch-along URL (a fresh
//! `egressToken`), so a single-use token cannot confound the result:
//!
//! | variant       | TLS stack                   | headers                                  |
//! |---------------|-----------------------------|------------------------------------------|
//! | `plain`       | plain wreq                  | GStreamer-like `User-Agent` only         |
//! | `web-headers` | plain wreq                  | browser UA + `Origin`/`Referer` my.arlo.com |
//! | `browser`     | Chrome TLS/HTTP2 emulation  | profile UA + `Origin`/`Referer`          |
//!
//! For each: HTTP status, `Content-Type`, `Server`, size; on success a
//! summary of the manifest attributes (type, update period, codecs,
//! resolution, segment timing — never URLs, which carry the token) and
//! whether the same URL can be fetched a second time (a live DASH
//! manifest is refreshed with the same URL).

use arlo_rs::ArloClient;
use arlo_rs::models::api::{Device, StreamUrl};
use arlo_rs::models::events::ArloEvent;
use std::collections::HashSet;
use std::time::Duration;
use stealthscraper_rs::{BrowserProfile, impersonation_client, wreq};
use tokio::sync::broadcast::error::RecvError;

mod common;
use common::{
    USER_STREAM_ACTIVE, activity_state, authenticate, is_watchalong, load_and_validate_config,
    property_keys, streamable_cameras,
};

const DEFAULT_WINDOW_SECS: u64 = 90;
/// A query made in the same instant the user's session is created can
/// return a fresh session instead of the watch-along; one retry after
/// this delay settles it.
const RETRY_DELAY: Duration = Duration::from_secs(2);
const ACTIVITY_IDLE: &str = "idle";
const ARLO_WEB_ORIGIN: &str = "https://my.arlo.com";
const ARLO_WEB_REFERER: &str = "https://my.arlo.com/";
/// What GStreamer's `souphttpsrc` sends, to reproduce its request.
const GST_LIKE_UA: &str = "GStreamer souphttpsrc libsoup/3.6";
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_SNIPPET_CHARS: usize = 200;
/// Manifest attributes worth reporting; URLs (BaseURL, media,
/// initialization) are deliberately absent — they carry the token.
const MPD_ATTRS: [&str; 14] = [
    "type",
    "profiles",
    "minimumUpdatePeriod",
    "minBufferTime",
    "maxSegmentDuration",
    "suggestedPresentationDelay",
    "timeShiftBufferDepth",
    "mimeType",
    "codecs",
    "width",
    "height",
    "frameRate",
    "bandwidth",
    "timescale",
];

#[derive(Clone, Copy)]
enum Variant {
    Plain,
    WebHeaders,
    Browser,
}

impl Variant {
    const ALL: [Self; 3] = [Self::Plain, Self::WebHeaders, Self::Browser];

    const fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::WebHeaders => "web-headers",
            Self::Browser => "browser",
        }
    }
}

struct FetchOutcome {
    status: u16,
    content_type: String,
    server: String,
    body: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init_tracing();
    println!("=== arlo-rs manual probe: pick up the app's live view ===\n");

    let config = match load_and_validate_config() {
        Ok(c) => c,
        Err(why) => {
            eprintln!("✗ {why}");
            std::process::exit(2);
        }
    };
    let show_url = std::env::var("ARLO_PROBE_SHOW_URL").is_ok_and(|v| v == "1");
    let window_secs = common::window_secs(DEFAULT_WINDOW_SECS);

    let client = authenticate(&config).await?;
    let devices = client.get_devices().await?;
    let cameras = streamable_cameras(&devices);
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
    let Some(url) = query_watchalong(client, cam).await else {
        return;
    };
    let shown = if show_url {
        url.as_str().to_string()
    } else {
        url.redacted()
    };
    println!(
        "  [view] {} ({}): watchalong=true {shown}",
        cam.device_name, cam.device_id
    );
    test_manifest(client, cam, url).await;
}

/// Query once (retrying once after [`RETRY_DELAY`] if the first answer is
/// a fresh session); only a watch-along URL is returned — fetching a fresh
/// session would be ours to pay for.
async fn query_watchalong(client: &ArloClient, cam: &Device) -> Option<StreamUrl> {
    let mut result = client.get_stream_url(cam).await;
    if matches!(&result, Ok(Some(u)) if !is_watchalong(u.as_str())) {
        println!(
            "  [view] {}: answer is a fresh session, not a watch-along; retrying once",
            cam.device_name
        );
        tokio::time::sleep(RETRY_DELAY).await;
        result = client.get_stream_url(cam).await;
    }
    match result {
        Ok(Some(url)) if is_watchalong(url.as_str()) => Some(url),
        Ok(Some(_)) => {
            println!(
                "  [view] {}: still not a watch-along; not fetching it",
                cam.device_name
            );
            None
        }
        Ok(None) => {
            println!(
                "  [view] {}: no URL returned although the camera reports a user view",
                cam.device_name
            );
            None
        }
        Err(e) => {
            println!("  [view] {}: query failed: {e}", cam.device_name);
            None
        }
    }
}

/// Fetch the manifest once per [`Variant`], each on a fresh watch-along
/// URL so a single-use token cannot decide the outcome.
async fn test_manifest(client: &ArloClient, cam: &Device, first: StreamUrl) {
    let profile = BrowserProfile::random();
    let mut next = Some(first);
    for variant in Variant::ALL {
        let url = match next.take() {
            Some(u) => u,
            None => match query_watchalong(client, cam).await {
                Some(u) => u,
                None => {
                    println!(
                        "  [mpd] no fresh watch-along for `{}`; stopping",
                        variant.label()
                    );
                    return;
                }
            },
        };
        fetch_and_report(variant, &profile, url.as_str()).await;
    }
}

async fn fetch_and_report(variant: Variant, profile: &BrowserProfile, url: &str) {
    let http = match build_http(variant, profile) {
        Ok(c) => c,
        Err(e) => {
            println!("  [mpd] {:<11} client build failed: {e}", variant.label());
            return;
        }
    };
    let outcome = match fetch(&http, variant, profile, url).await {
        Ok(o) => o,
        Err(e) => {
            println!("  [mpd] {:<11} request failed: {e}", variant.label());
            return;
        }
    };
    println!(
        "  [mpd] {:<11} HTTP {} content-type={} server={} bytes={}",
        variant.label(),
        outcome.status,
        outcome.content_type,
        outcome.server,
        outcome.body.len()
    );
    if !(200..300).contains(&outcome.status) {
        println!("         body: {}", snippet(&outcome.body));
        return;
    }
    print_mpd_summary(&outcome.body);
    match fetch(&http, variant, profile, url).await {
        Ok(again) => println!("         refetch same URL: HTTP {}", again.status),
        Err(e) => println!("         refetch same URL failed: {e}"),
    }
}

fn build_http(variant: Variant, profile: &BrowserProfile) -> Result<wreq::Client, wreq::Error> {
    let builder = match variant {
        Variant::Plain | Variant::WebHeaders => wreq::Client::builder(),
        Variant::Browser => impersonation_client(profile),
    };
    builder.timeout(FETCH_TIMEOUT).build()
}

async fn fetch(
    http: &wreq::Client,
    variant: Variant,
    profile: &BrowserProfile,
    url: &str,
) -> Result<FetchOutcome, wreq::Error> {
    let req = http.get(url);
    let req = match variant {
        Variant::Plain => req.header("user-agent", GST_LIKE_UA),
        Variant::WebHeaders => req
            .header("user-agent", profile.user_agent.as_str())
            .header("origin", ARLO_WEB_ORIGIN)
            .header("referer", ARLO_WEB_REFERER)
            .header("accept", "*/*"),
        Variant::Browser => req
            .header("origin", ARLO_WEB_ORIGIN)
            .header("referer", ARLO_WEB_REFERER)
            .header("accept", "*/*"),
    };
    let resp = req.send().await?;
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string()
    };
    let status = resp.status().as_u16();
    let content_type = header("content-type");
    let server = header("server");
    let body = resp.text().await?;
    Ok(FetchOutcome {
        status,
        content_type,
        server,
        body,
    })
}

fn print_mpd_summary(body: &str) {
    for attr in MPD_ATTRS {
        let values = attr_values(body, attr);
        if !values.is_empty() {
            println!("         {attr}: {}", values.join(", "));
        }
    }
    println!(
        "         adaptation sets: {}, representations: {}",
        body.matches("<AdaptationSet").count(),
        body.matches("<Representation").count()
    );
}

/// Distinct values of `name="…"` attributes, in document order.
fn attr_values(body: &str, name: &str) -> Vec<String> {
    let needle = format!(" {name}=\"");
    let mut out: Vec<String> = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find(&needle) {
        let after = &rest[i + needle.len()..];
        let Some(end) = after.find('"') else {
            break;
        };
        let value = after[..end].to_string();
        if !out.contains(&value) {
            out.push(value);
        }
        rest = &after[end..];
    }
    out
}

/// First characters of an error body on one line (error pages carry no
/// token; they are the gateway's own text).
fn snippet(body: &str) -> String {
    body.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(BODY_SNIPPET_CHARS)
        .collect()
}

fn print_event(event: &ArloEvent) {
    let keys = property_keys(event);
    println!(
        "  [bus] action={} resource={} from={:?} keys={} activityState={:?}",
        event.action,
        event.resource,
        event.source,
        keys.len(),
        activity_state(event)
    );
}
