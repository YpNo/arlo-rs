use rs_arlo::config::ArloConfig;

#[tokio::main]
async fn main() -> Result<(), rs_arlo::error::ArloError> {
    env_logger::init();

    println!("=== Arlo IMAP Extraction Debugger (demo3) ===");

    // Load config to grab IMAP credentials
    let config = match ArloConfig::load_from_file("config.toml") {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to load config.toml: {}", e);
            return Ok(());
        }
    };

    if let Some(imap_config) = config.mfa.and_then(|m| m.imap) {
        let mut host = imap_config.host.clone().unwrap_or_default();
        if host.is_empty()
            && let Some(ref provider) = imap_config.provider
        {
            match provider.to_lowercase().as_str() {
                "gmail" => host = "imap.gmail.com".to_string(),
                "outlook" | "hotmail" => host = "outlook.office365.com".to_string(),
                "yahoo" => host = "imap.mail.yahoo.com".to_string(),
                _ => {}
            }
        }
        let port = imap_config.port.unwrap_or(993);
        let user = imap_config.username.clone().unwrap();
        let pass = imap_config.password.clone().unwrap();

        println!("Connecting to IMAP Server: {}:{}", host, port);
        println!("Username: {}", user);
        println!("Polling for UNSEEN Arlo emails...");

        // We bypass the "baseline" algorithm entirely here to force it to read an *existing* unread email
        let result = tokio::task::spawn_blocking(move || {
            let client_builder = imap::ClientBuilder::new(host.as_str(), port);
            let client = client_builder.connect().unwrap();
            let mut session = client.login(user, pass).unwrap();

            session.select("INBOX").unwrap();

            // Direct fetch of ALL unseen Arlo emails (simulating the timeout drop)
            let seqs = session.search("UNSEEN FROM arlo.com").unwrap();

            if seqs.is_empty() {
                return Err("No UNSEEN emails from arlo.com found right now. Make sure the email is marked as Unread in your inbox!".to_string());
            }

            println!("Found {} UNSEEN Arlo emails. Grabbing the most recent...", seqs.len());
            let latest_seq = seqs.iter().max().unwrap();

            println!("Fetching raw payload for Sequence ID {}...", latest_seq);
            let messages = session.fetch(latest_seq.to_string(), "RFC822").unwrap();
            let message = messages.iter().next().unwrap();
            let body = message.body().unwrap();

            let parsed_mail = mailparse::parse_mail(body).unwrap();
            let raw_text = rs_arlo::client::auth_imap::extract_text(&parsed_mail);

            println!("\n=== RAW EXTRACTED TEXT ENGINE ===");
            println!("{}", raw_text);
            println!("=================================\n");

            // Regex Extraction
            let re_h1 = regex::Regex::new(r"(?is)<h1[^>]*>\s*(\d{6})\s*</h1>").unwrap();
            let re_fallback = regex::Regex::new(r"(?m)(?:^|[^#=&\w])(\d{6})(?:[^0-9]|$)").unwrap();

            let otp = if let Some(caps) = re_h1.captures(&raw_text) {
                caps.get(1).map(|m| m.as_str().to_string())
            } else if let Some(caps) = re_fallback.captures(&raw_text) {
                caps.get(1).map(|m| m.as_str().to_string())
            } else {
                None
            };

            Ok(otp.unwrap_or_else(|| "Failed to regex OTP from the text payload above!".to_string()))
        }).await.unwrap();

        match result {
            Ok(otp) => println!("SUCCESS! Final Extracted OTP: {}", otp),
            Err(e) => println!("DEBUG FAILED: {}", e),
        }
    } else {
        println!("No [imap] section found in config.toml!");
    }

    Ok(())
}
