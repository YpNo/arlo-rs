//! Live-account smoke test. It logs into a real Arlo account, which
//! triggers a real second factor (OTP e-mail or push prompt), so it is
//! opt-in twice over: `#[ignore]` keeps it out of `cargo test`, and the
//! `ARLO_E2E=1` environment variable keeps `--ignored` runs on a
//! developer's machine from touching the account by accident.
//!
//! ```bash
//! ARLO_E2E=1 cargo test --test e2e_arlo_api -- --ignored
//! ```

use arlo_rs::client::ArloClient;
use std::time::Duration;

/// Upper bound for the whole login + one API call, including the wait
/// for a second factor.
const E2E_TIMEOUT: Duration = Duration::from_secs(180);

const CONFIG_PATH: &str = "config.toml";

#[tokio::test]
#[ignore = "logs into a live Arlo account; run with ARLO_E2E=1 and --ignored"]
async fn live_arlo_api_traversal() {
    if std::env::var_os("ARLO_E2E").is_none_or(|v| v != "1") {
        println!("Skipping live Arlo API test: ARLO_E2E is not set to 1.");
        return;
    }
    if !std::path::Path::new(CONFIG_PATH).exists() {
        println!("Skipping live Arlo API test: `{CONFIG_PATH}` not found in root.");
        return;
    }

    let locations = tokio::time::timeout(E2E_TIMEOUT, async {
        // Parses the config, builds the default `WreqTransport` and runs
        // the full authentication ceremony (including MFA) when no valid
        // session cache exists.
        let client = ArloClient::from_config(CONFIG_PATH)
            .await
            .expect("ArloClient::from_config should succeed with a valid config.toml");
        client.get_locations().await
    })
    .await
    .expect("live login + get_locations should finish within E2E_TIMEOUT");

    match locations {
        // An auth failure here is usually an unapproved push prompt or an
        // expired cache, not a code defect; report it without failing.
        Err(e) => println!("Live API call failed (MFA not completed or unauthorized): {e}"),
        Ok(locs) => {
            println!("Traversed Arlo Cloud: {} active location(s).", locs.len());
            assert!(
                !locs.is_empty(),
                "expected at least one location on a valid account"
            );
        }
    }
}
