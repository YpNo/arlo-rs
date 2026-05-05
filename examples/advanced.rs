//! Scenario 2: streaming + actuation.
//!
//! Demonstrates the new `start_stream` correlation flow from PR 2 — the
//! call returns a `StreamUrl` directly instead of `()`, removing the need
//! for the consumer to wire its own SSE plumbing.

use rs_arlo::ArloClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    println!("=== Scenario 2: Stream & Actuation ===");

    let config_path = "config.toml";
    if !std::path::Path::new(config_path).exists() {
        eprintln!("Error: config.toml not found. Run examples/simple first to seed it.");
        return Ok(());
    }

    println!("Initializing Arlo client...");
    let mut client = ArloClient::from_config(config_path).await?;
    if !client.is_authenticated() {
        eprintln!(
            "Error: this scenario requires an active session. Run examples/simple first to cache one."
        );
        return Ok(());
    }

    println!("Fetching devices to find a camera...");
    let devices = client.get_devices().await?;
    let camera = devices.iter().find(|d| {
        d.device_type == "camera" || d.device_type == "arloq" || d.device_type == "arlobridge"
    });

    let Some(cam) = camera else {
        println!("No cameras found on this account.");
        return Ok(());
    };
    println!("Found camera: {} (ID: {})", cam.device_name, cam.device_id);

    println!("\nRequesting stream URL (this may take a few seconds — the URL");
    println!("arrives over SSE; the library handles the correlation for you)...");
    match client.start_stream(&cam.device_id).await {
        Ok(stream_url) => {
            println!(">>> Stream URL: {stream_url}");
            println!("    Hand this to ffmpeg, a player, or a transcoder.");
        }
        Err(e) => println!("Failed to obtain stream URL: {e}"),
    }

    println!("\nTaking a snapshot...");
    if let Err(e) = client.take_snapshot(&cam.device_id).await {
        println!("Failed to request snapshot: {e}");
    }

    println!("\nLogging out...");
    client.logout().await?;
    println!("Done.");
    Ok(())
}
