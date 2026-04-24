//! IMAP-based Multi-Factor Authentication (MFA) Automation.
//!
//! This module provides a non-blocking background thread worker capable of logging into an
//! email inbox via IMAP to silently extract Arlo 6-digit OTP codes. It is designed to navigate
//! Quoted-Printable HTML trees using `mailparse` and safely extract the OTP without triggering
//! false positives against CSS styling markers or HTML artifacts.
use crate::config::ImapConfig;
use crate::error::ArloError;
use mailparse::ParsedMail;
use regex::Regex;

/// Recursively extracts the plain text payload from a multi-part email body.
/// Favors `text/plain`, but attempts a naive HTML strip fallback.
pub fn extract_text(parsed: &ParsedMail) -> String {
    if parsed.ctype.mimetype.starts_with("text/") {
        parsed.get_body().unwrap_or_default()
    } else if parsed.ctype.mimetype.starts_with("multipart/") {
        parsed
            .subparts
            .iter()
            .map(extract_text)
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        String::new()
    }
}

fn get_imap_host_and_port(config: &ImapConfig) -> Result<(String, u16), ArloError> {
    let mut actual_host = config.host.clone();
    let actual_port = config.port.unwrap_or(993);

    if let Some(ref provider) = config.provider {
        match provider.to_lowercase().as_str() {
            "gmail" if actual_host.is_none() => {
                actual_host = Some("imap.gmail.com".into());
            }
            "outlook" | "hotmail" if actual_host.is_none() => {
                actual_host = Some("outlook.office365.com".into());
            }
            "yahoo" if actual_host.is_none() => {
                actual_host = Some("imap.mail.yahoo.com".into());
            }
            _ => {} // Fallback to explicitly defined host
        }
    }

    let host = actual_host
        .ok_or_else(|| ArloError::AuthError("IMAP host or supported provider missing".into()))?;

    Ok((host, actual_port))
}

/// Captures the baseline of unread Arlo emails BEFORE initiating the API authentication trace.
/// This prevents race conditions where the MFA email arrives instantly before IMAP can log in.
pub async fn get_baseline(
    config: &ImapConfig,
) -> Result<std::collections::HashSet<u32>, ArloError> {
    let (host, port) = get_imap_host_and_port(config)?;
    let username = config
        .username
        .clone()
        .ok_or_else(|| ArloError::AuthError("IMAP username missing".into()))?;
    let password = config
        .password
        .clone()
        .ok_or_else(|| ArloError::AuthError("IMAP password missing".into()))?;

    tokio::task::spawn_blocking(move || {
        let client_builder = imap::ClientBuilder::new(host.as_str(), port);
        let client = client_builder
            .connect()
            .map_err(|e| ArloError::AuthError(format!("Failed to connect to IMAP: {}", e)))?;

        let mut session = client
            .login(username, password)
            .map_err(|(e, _)| ArloError::AuthError(format!("IMAP Login Failed: {}", e)))?;

        session
            .select("INBOX")
            .map_err(|e| ArloError::AuthError(format!("Failed to select INBOX: {}", e)))?;

        let baseline_seqs = session.search("UNSEEN FROM arlo.com").unwrap_or_default();

        Ok(baseline_seqs.into_iter().collect())
    })
    .await
    .unwrap_or_else(|e| Err(ArloError::AuthError(format!("Task spawn failed: {}", e))))
}

/// Safely polls a secure IMAP server to extract Arlo One-Time Passwords (OTPs)
/// without blocking the asynchronous tokio executor.
///
/// This execution leverages `tokio::task::spawn_blocking` because the underlying
/// IMAP client relies on synchronous network I/O which would otherwise stall the runtime.
pub async fn fetch_otp(
    config: &ImapConfig,
    baseline_set: std::collections::HashSet<u32>,
) -> Result<String, ArloError> {
    let (host, port) = get_imap_host_and_port(config)?;
    let username = config
        .username
        .clone()
        .ok_or_else(|| ArloError::AuthError("IMAP username missing".into()))?;
    let password = config
        .password
        .clone()
        .ok_or_else(|| ArloError::AuthError("IMAP password missing".into()))?;
    let delete_after_read = config.delete_after_read.unwrap_or(false);

    // Bounce our synchronous network I/O into a blocking worker thread pool to avoid tokio stalls.
    tokio::task::spawn_blocking(move || {
        let client_builder = imap::ClientBuilder::new(host.as_str(), port);
        let client = client_builder
            .connect()
            .map_err(|e| ArloError::AuthError(format!("Failed to connect to IMAP: {}", e)))?;

        let mut session = client
            .login(username, password)
            .map_err(|(e, _)| ArloError::AuthError(format!("IMAP Login Failed: {}", e)))?;

        session
            .select("INBOX")
            .map_err(|e| ArloError::AuthError(format!("Failed to select INBOX: {}", e)))?;

        // Search specifically for unread emails from Arlo.
        // This is highly targeted to accelerate search speeds.
        // We will retry up to 6 times (30 seconds) waiting for Arlo's dispatch to hit the inbox
        let mut retry_count = 0;

        let new_seq = loop {
            let current_seqs = session
                .search("UNSEEN FROM arlo.com")
                .map_err(|e| ArloError::AuthError(format!("IMAP Search failed: {}", e)))?;

            let current_set: std::collections::HashSet<u32> = current_seqs.into_iter().collect();
            let new_emails: Vec<u32> = current_set.difference(&baseline_set).copied().collect();

            if !new_emails.is_empty() {
                // Return the highest sequence number among the newly arrived emails
                break *new_emails.iter().max().unwrap();
            }

            if retry_count >= 6 {
                return Err(ArloError::AuthError(
                    "Timed out waiting for new Arlo MFA email to arrive in Inbox (30 seconds)"
                        .into(),
                ));
            }

            std::thread::sleep(std::time::Duration::from_secs(5));
            retry_count += 1;
        };

        // Fetch the most recent chronologically
        let latest_seq = new_seq;

        let messages = session
            .fetch(latest_seq.to_string(), "RFC822")
            .map_err(|e| ArloError::AuthError(format!("Failed to fetch email payload: {}", e)))?;

        let message = messages
            .iter()
            .next()
            .ok_or_else(|| ArloError::AuthError("Empty message slice returned".into()))?;

        // Extract raw bytes and parse the MIME tree
        let body_bytes = message
            .body()
            .ok_or_else(|| ArloError::AuthError("Empty IMAP email body".into()))?;

        let parsed_mail = mailparse::parse_mail(body_bytes)
            .map_err(|e| ArloError::AuthError(format!("MIME Parsing Failed: {}", e)))?;

        // Arlo emails typically do not have a text/plain block, they only send text/html.
        // We need to parse the raw HTML and gracefully degrade.

        let content = extract_text(&parsed_mail);

        // Arlo places the OTP code inside an <h1> block in the HTML, usually styled with color :#1B5A8F
        // Example: <h1 style="font-size:30px;line-height:36px;font-family:'Arial', sans-serif;font-weight:normal;color:#1B5A8F;margin: 0 0 20px;">\n308076\n</h1>
        // This regex looks for <h1> tags containing exactly 6 digits, optionally surrounded by whitespace
        let re_h1 = Regex::new(r"(?is)<h1[^>]*>\s*(\d{6})\s*</h1>").unwrap();

        // Fallback: look for 6 digits that aren't preceded immediately by #, =, or ampersands (to avoid CSS, quoted-printable artifacts, and HTML entities)
        let re_fallback = Regex::new(r"(?m)(?:^|[^#=&\w])(\d{6})(?:[^0-9]|$)").unwrap();

        let mut otp = None;
        if let Some(caps) = re_h1.captures(&content) {
            otp = Some(caps[1].to_string());
        } else if let Some(caps) = re_fallback.captures(&content) {
            otp = Some(caps[1].to_string());
        }

        let otp = otp.ok_or_else(|| {
            ArloError::AuthError(format!(
                "Regex failed to extract a 6-digit OTP from Arlo email. Content length: {}",
                content.len()
            ))
        })?;

        // Safely wipe the challenge artifact out of the mailbox
        if delete_after_read {
            session
                .store(format!("{}", latest_seq), "+FLAGS (\\Deleted)")
                .map_err(|e| {
                    ArloError::AuthError(format!("Failed to flag email for deletion: {}", e))
                })?;
            session
                .expunge()
                .map_err(|e| ArloError::AuthError(format!("Failed to expunge INBOX: {}", e)))?;
        }

        let _ = session.logout();

        Ok(otp)
    })
    .await
    .map_err(|e| ArloError::AuthError(format!("IMAP thread panicked: {}", e)))?
}
