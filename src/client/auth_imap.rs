use crate::config::ImapConfig;
use crate::error::ArloError;
use regex::Regex;

/// Safely polls a secure IMAP server to extract Arlo One-Time Passwords (OTPs)
/// without blocking the asynchronous tokio executor.
pub async fn fetch_otp(config: &ImapConfig) -> Result<String, ArloError> {
    let mut actual_host = config.host.clone();
    let actual_port = config.port.unwrap_or(993);

    if let Some(ref provider) = config.provider {
        match provider.to_lowercase().as_str() {
            "gmail" => {
                if actual_host.is_none() {
                    actual_host = Some("imap.gmail.com".into());
                }
            }
            "outlook" | "hotmail" => {
                if actual_host.is_none() {
                    actual_host = Some("outlook.office365.com".into());
                }
            }
            "yahoo" => {
                if actual_host.is_none() {
                    actual_host = Some("imap.mail.yahoo.com".into());
                }
            }
            _ => {} // Fallback to explicitly defined host
        }
    }

    let host = actual_host
        .ok_or_else(|| ArloError::AuthError("IMAP host or supported provider missing".into()))?;
    let port = actual_port;
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
        let query = "UNSEEN FROM \"arlo\"";
        let seqs = session
            .search(query)
            .map_err(|e| ArloError::AuthError(format!("IMAP Search failed: {}", e)))?;

        if seqs.is_empty() {
            return Err(ArloError::AuthError(
                "No new Arlo MFA emails found in Inbox".into(),
            ));
        }

        // Fetch the most recent chronologically
        let latest_seq = seqs.iter().max().unwrap();

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

        // Recursion to flatten HTML or text components
        fn extract_text(p: &mailparse::ParsedMail) -> String {
            if p.ctype.mimetype.starts_with("text/") {
                p.get_body().unwrap_or_default()
            } else if p.ctype.mimetype.starts_with("multipart/") {
                p.subparts
                    .iter()
                    .map(extract_text)
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                String::new()
            }
        }

        let content = extract_text(&parsed_mail);

        // Arlo sends 6 digit pins. Fallback parsing logic ensures it correctly isolates words.
        let re_explicit =
            Regex::new(r"(?i)(?:code|verification|OTP|password|One-Time)[\s:]*(\d{6})").unwrap();
        let re_fallback = Regex::new(r"\b(\d{6})\b").unwrap();

        let mut otp = None;
        if let Some(caps) = re_explicit.captures(&content) {
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
