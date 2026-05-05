use rs_arlo::client::ArloClient;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Scenario 2: Stream & Actuation ===");

    let config_path = "config.toml";
    if !std::path::Path::new(config_path).exists() {
        eprintln!("Error: config.toml not found. Please set up your configuration.");
        return Ok(());
    }

    println!("Initializing Arlo Client...");
    let mut client = ArloClient::from_config(config_path).await?;

    if client.auth.access_token.is_none() {
        eprintln!(
            "Error: This scenario requires an active session. Please run scenario1_auth_list first to cache your session."
        );
        return Ok(());
    }

    println!("Fetching Devices to find a camera...");
    let devices = client.get_devices().await?;

    // Find the first camera device
    let camera = devices.iter().find(|d| {
        d.device_type == "camera" || d.device_type == "arloq" || d.device_type == "arlobridge"
    });

    if let Some(cam) = camera {
        println!("Found Camera: {} (ID: {})", cam.device_name, cam.device_id);

        println!("\nRequesting Stream URL...");
        let stream_req = client.start_stream(&cam.device_id).await;

        match stream_req {
            Ok(_) => println!(
                ">>> Stream requested successfully! Note: Arlo returns streams asynchronously via SSE. The Events manager is needed to parse the actual URL."
            ),
            Err(e) => println!("Failed to request stream: {}", e),
        }

        println!("\nTaking a Snapshot...");
        let snap_res = client.take_snapshot(&cam.device_id).await;
        match snap_res {
            Ok(_) => println!(
                "Snapshot requested successfully! Check your Arlo cloud library in a moment."
            ),
            Err(e) => println!("Failed to request snapshot: {}", e),
        }

        // Wait a few seconds to let Arlo process the snapshot/stream
        println!("Waiting 5 seconds for Arlo to process requests...");
        tokio::time::sleep(Duration::from_secs(5)).await;
    } else {
        println!("No cameras found on this account.");
    }

    println!("\nDisconnecting...");
    client.logout().await?;
    println!("Logged out successfully.");

    Ok(())
}
