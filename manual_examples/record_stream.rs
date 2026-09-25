//! Manual smoke test: open the legacy live stream of the first camera and
//! pipe it to `ffmpeg` for a fixed duration.
//!
//! ## ⚠️ Hits your live Arlo account
//!
//! Requires a valid cached session in `.arlo_session.json` (run
//! `cargo run --example list_cameras` first) and an `ffmpeg` binary on
//! `PATH`. The legacy `/startStream` path serves `rtsps://` URLs only on
//! cameras that have not been migrated to v3 live (WebRTC); on v3 cameras
//! the call times out or 502s — use the streamer's `webrtcbin` pipeline
//! instead.
//!
//! ```bash
//! RUST_LOG=arlo_rs=info cargo run --example record_stream -- out.mp4 30
//! ```

use arlo_rs::ArloClient;
use std::process::{Command, Stdio};

const CACHE_PATH: &str = ".arlo_session.json";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,arlo_rs=info")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let output = args
        .next()
        .unwrap_or_else(|| "arlo-recording.mp4".to_string());
    let seconds: u32 = args.next().as_deref().unwrap_or("30").parse()?;

    let client = ArloClient::builder()
        .session_cache(CACHE_PATH)
        .build()
        .await?;
    if !client.is_authenticated() {
        eprintln!("✗ No valid cached session in `{CACHE_PATH}`; run `list_cameras` first.");
        std::process::exit(2);
    }

    let devices = client.get_devices().await?;
    let camera = devices
        .iter()
        .find(|d| d.device_type == "camera")
        .ok_or("no camera on this account")?;
    println!(
        "→ Starting stream for {} ({})",
        camera.device_name, camera.device_id
    );
    let url = client.start_stream(camera).await?;
    println!("✓ Stream URL received; recording {seconds}s to `{output}` with ffmpeg");

    // `-c copy` avoids re-encoding; `-t` bounds the recording.
    let status = Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-y"])
        .args([
            "-i",
            url.as_str(),
            "-t",
            &seconds.to_string(),
            "-c",
            "copy",
            &output,
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    println!("ffmpeg exited with {status}");
    Ok(())
}
