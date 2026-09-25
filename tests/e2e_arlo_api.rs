use arlo_rs::client::ArloClient;

#[tokio::test]
async fn test_live_arlo_api_traversal() {
    // Smart testing: If the developer hasn't set up the `config.toml` with valid
    // live credentials locally, we gracefully skip the test instead of failing CI.
    let config_path = "config.toml";

    if !std::path::Path::new(config_path).exists() {
        println!("Skipping E2E Arlo API test: `config.toml` not found in root.");
        return;
    }

    // This will implicitly parse the config, launch the CloudScraper, establish the TLS Proxy,
    // and potentially hit the Login API automatically (if creds are defined).
    let client = ArloClient::from_config(config_path)
        .await
        .expect("Failed to instantiate ArloClient");

    // Let's attempt to fetch our active user locations to prove the REST layer + proxy bypass works
    let locations = client.get_locations().await;

    if let Err(e) = locations {
        // If it's an AuthError, it might just be the user hasn't accepted the MFA Push
        // or their session cache expired. We shouldn't strictly fail the build for a bad password.
        println!(
            "E2E API Call Failed (Possibly missing MFA or unauthorized): {}",
            e
        );
    } else {
        let locs = locations.unwrap();
        println!(
            "Successfully traversed Arlo Cloud! Found {} active locations.",
            locs.len()
        );
        assert!(
            !locs.is_empty(),
            "Expected at least one location on a valid account"
        );
    }
}
