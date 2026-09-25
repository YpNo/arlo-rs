//! IMAP OTP-extraction debugger.
//!
//! Bypasses the Arlo flow entirely and just connects to the IMAP server
//! configured in `config.toml`, grabs the most recent UNSEEN Arlo email, and
//! prints the extracted text + parsed OTP. Useful when the regex layer needs
//! to be retuned against a new Arlo email template.

use arlo_rs::client::auth_imap::{extract_otp, extract_text};
use arlo_rs::config::ArloConfig;
use imap_client::credentials::Password;
use imap_client::search::{SearchKey, SearchQuery};

#[tokio::main]
async fn main() -> Result<(), arlo_rs::error::ArloError> {
    // Explicitly install the ring crypto provider as the process-wide default.
    // This resolves the ambiguity panic in rustls 0.23+ when multiple providers
    // (like aws-lc-rs from reqwest) are present in the build.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,arlo_rs=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    println!("=== Arlo IMAP Extraction Debugger ===");

    let config = match ArloConfig::load_from_file("config.toml") {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to load config.toml: {e}");
            return Ok(());
        }
    };

    let Some(imap_cfg) = config.mfa.and_then(|m| m.imap) else {
        println!("No [mfa.imap] section found in config.toml");
        return Ok(());
    };

    let mut host = imap_cfg.host.clone().unwrap_or_default();
    if host.is_empty()
        && let Some(ref provider) = imap_cfg.provider
    {
        host = match provider.to_lowercase().as_str() {
            "gmail" => "imap.gmail.com".to_string(),
            "outlook" | "hotmail" => "outlook.office365.com".to_string(),
            "yahoo" => "imap.mail.yahoo.com".to_string(),
            _ => String::new(),
        };
    }
    if host.is_empty() {
        println!("Could not resolve IMAP host (set imap.host or imap.provider).");
        return Ok(());
    }
    let port = imap_cfg.port.unwrap_or(993);
    let user = imap_cfg.username.clone().unwrap_or_default();
    let pass = imap_cfg.password.clone().unwrap_or_default();

    println!("Connecting to IMAP Server: {host}:{port}");
    println!("Username: {user}");
    println!("Polling for UNSEEN Arlo emails...");

    let unauth = imap_tls::connect_tls(&host, port).await.map_err(|e| {
        arlo_rs::error::ArloError::AuthError(format!("IMAP TLS connect failed: {e}"))
    })?;
    let auth = unauth
        .login(&user, Password::new(pass))
        .await
        .map_err(|e| arlo_rs::error::ArloError::AuthError(format!("IMAP login failed: {e}")))?;
    let mut selected = auth.select("INBOX").await.map_err(|e| {
        arlo_rs::error::ArloError::AuthError(format!("Failed to select INBOX: {e}"))
    })?;

    let query = SearchQuery::new(SearchKey::And(vec![
        SearchKey::Unseen,
        SearchKey::From("arlo.com".into()),
    ]));
    let seqs = selected
        .search(query)
        .await
        .map_err(|e| arlo_rs::error::ArloError::AuthError(format!("IMAP SEARCH failed: {e}")))?;

    if seqs.is_empty() {
        println!("No UNSEEN Arlo emails found. Mark an Arlo email as Unread and re-run.");
        let _ = selected.logout().await;
        return Ok(());
    }

    let latest = *seqs.iter().max().unwrap();
    println!(
        "Found {} UNSEEN Arlo email(s). Fetching seq {latest}...",
        seqs.len()
    );

    let fetched = selected
        .fetch(&latest.to_string(), "RFC822")
        .await
        .map_err(|e| arlo_rs::error::ArloError::AuthError(format!("IMAP FETCH failed: {e}")))?;

    let body_bytes = fetched
        .into_iter()
        .find_map(|f| f.body)
        .ok_or_else(|| arlo_rs::error::ArloError::AuthError("Empty IMAP body".into()))?;

    let parsed = mailparse::parse_mail(&body_bytes)
        .map_err(|e| arlo_rs::error::ArloError::AuthError(format!("MIME parsing failed: {e}")))?;
    let raw_text = extract_text(&parsed);

    println!("\n=== RAW EXTRACTED TEXT ===\n{raw_text}\n==========================\n");

    match extract_otp(&raw_text) {
        Some(otp) => println!("SUCCESS — Extracted OTP: {otp}"),
        None => println!("FAILURE — Regexes did not match. Inspect the text above."),
    }

    let _ = selected.logout().await;
    Ok(())
}
