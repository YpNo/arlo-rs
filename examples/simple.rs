use rs_arlo::client::ArloClient;
use rs_arlo::config::ArloConfig;
use rs_arlo::models::auth::AuthResult;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    println!("=== Scenario 1: Authentication & Device Listing ===");

    // We assume the user has a `config.toml` set up
    let config_path = "config.toml";
    if !std::path::Path::new(config_path).exists() {
        eprintln!(
            "Error: config.toml not found. Please copy config.toml.example to config.toml and configure your credentials."
        );
        return Ok(());
    }

    let config = ArloConfig::load_from_file(config_path)?;
    let mut client = ArloClient::from_config(config_path).await?;

    println!("Initiating Authentication Sequence...");
    match client.authenticate(&config).await? {
        AuthResult::Success => {
            println!("Successfully authenticated! (Session loaded from cache or IMAP automated)");
        }
        AuthResult::MfaRequired {
            factor_id: _,
            factor_auth_code,
            provider,
        } => {
            println!(
                "MFA challenge required via {}. Please check your device/inbox.",
                provider
            );
            print!("Enter the OTP received: ");
            io::stdout().flush()?;

            let mut otp = String::new();
            io::stdin().read_line(&mut otp)?;
            let otp = otp.trim();

            println!("Submitting MFA OTP & validating backend session...");
            client.submit_mfa(&factor_auth_code, otp).await?;
            println!("Authentication complete and session safely cached!");
        }
    }

    println!("\nFetching Locations...");
    let locations = client.get_locations().await?;
    for loc in &locations {
        println!("Location: {} (ID: {})", loc.name, loc.id);
    }

    println!("\nFetching Devices...");
    let devices = client.get_devices().await?;
    for dev in &devices {
        println!(
            "Device: {} (Type: {}, State: {:?})",
            dev.device_name, dev.device_type, dev.state
        );
    }

    println!("\nDisconnecting (Logging out)...");
    client.logout().await?;
    println!("Successfully logged out and cleared session.");

    Ok(())
}
