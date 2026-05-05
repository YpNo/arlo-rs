//! Scenario 1: authentication + device listing.
//!
//! Demonstrates the new public surface from PR 2:
//! - `ArloClient::builder()` for programmatic configuration
//! - `MfaHandler` trait — picks `ImapMfaHandler` if `[mfa.imap]` is set,
//!   else falls back to `StdinMfaHandler`
//! - `client.is_authenticated()` accessor

use rs_arlo::config::ArloConfig;
use rs_arlo::{ArloClient, ImapMfaHandler, StdinMfaHandler};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    println!("=== Scenario 1: Authentication & Device Listing ===");

    let config_path = "config.toml";
    if !std::path::Path::new(config_path).exists() {
        eprintln!(
            "Error: config.toml not found. Copy config.toml.example to config.toml first."
        );
        return Ok(());
    }
    let config = ArloConfig::load_from_file(config_path)?;
    let mut client = ArloClient::from_config(config_path).await?;

    if client.is_authenticated() {
        println!("Restored an active session from cache. Skipping MFA flow.");
    } else {
        println!("Initiating authentication sequence...");
        // Pick the strongest available MFA handler.
        let imap_cfg = config.mfa.as_ref().and_then(|m| m.imap.clone());
        match imap_cfg {
            Some(cfg) if cfg.enabled.unwrap_or(false) => {
                println!("Using IMAP-automated MFA handler.");
                client
                    .authenticate_with_handler(&config, ImapMfaHandler::new(cfg))
                    .await?;
            }
            _ => {
                println!("Using interactive stdin MFA handler.");
                client
                    .authenticate_with_handler(&config, StdinMfaHandler::new())
                    .await?;
            }
        }
        println!("Authentication complete; session cached.");
    }

    println!("\nFetching locations...");
    for loc in client.get_locations().await? {
        println!("Location: {} (ID: {})", loc.name, loc.id);
    }

    println!("\nFetching devices...");
    for dev in client.get_devices().await? {
        println!(
            "Device: {} (Type: {}, State: {:?})",
            dev.device_name, dev.device_type, dev.state
        );
    }

    println!("\nLogging out...");
    client.logout().await?;
    println!("Done.");
    Ok(())
}
