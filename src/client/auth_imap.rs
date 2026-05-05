//! IMAP-based Multi-Factor Authentication (MFA) Automation.
//!
//! This module provides an asynchronous IMAP poller that logs into the user's
//! mailbox to silently extract Arlo's 6-digit OTP. It is built on top of the
//! sibling `imap-rs` crates (`imap-client` / `imap-tls`) and therefore stays
//! fully on the Tokio runtime — no `spawn_blocking`, no synchronous I/O.
//!
//! Two entry points:
//! - [`get_baseline`] — capture the set of UNSEEN Arlo emails *before* the
//!   Arlo API is asked to dispatch a fresh OTP. This guards against the race
//!   where an old email's OTP is mistakenly returned.
//! - [`fetch_otp`] — poll the inbox until a new Arlo email lands, fetch its
//!   body, extract the 6-digit code, and (optionally) flag/expunge it.

use crate::config::ImapConfig;
use crate::error::ArloError;
use imap_client::credentials::Password;
use imap_client::flags::{Flag, StoreAction};
use imap_client::search::{SearchKey, SearchQuery};
use mailparse::ParsedMail;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, instrument};

/// Maximum time we wait for the Arlo OTP email to land in the inbox.
const OTP_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Delay between mailbox searches while waiting for the OTP email.
const OTP_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Arlo formats the OTP inside an `<h1>` block. Match exactly 6 digits there.
static OTP_RE_H1: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<h1[^>]*>\s*(\d{6})\s*</h1>").expect("static regex"));
/// Fallback: 6 digits not preceded by `#`, `=`, `&`, or word chars (avoids
/// CSS hex colours, quoted-printable artefacts, and HTML entities).
static OTP_RE_FALLBACK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[^#=&\w])(\d{6})(?:[^0-9]|$)").expect("static regex"));

/// Recursively extracts the plain-text payload from a multi-part MIME tree.
/// Concatenates every `text/*` part — Arlo's emails are typically `text/html`
/// only, so HTML markup is preserved for the regex layer downstream.
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

/// Extracts a 6-digit Arlo OTP from an extracted email body. Returns `None`
/// if neither the `<h1>` nor the loose-digit fallback regex match.
pub fn extract_otp(content: &str) -> Option<String> {
    if let Some(caps) = OTP_RE_H1.captures(content) {
        return Some(caps[1].to_string());
    }
    OTP_RE_FALLBACK.captures(content).map(|c| c[1].to_string())
}

fn resolve_host_and_port(config: &ImapConfig) -> Result<(String, u16), ArloError> {
    let mut host = config.host.clone();
    let port = config.port.unwrap_or(993);

    if let Some(ref provider) = config.provider
        && host.is_none()
    {
        host = match provider.to_lowercase().as_str() {
            "gmail" => Some("imap.gmail.com".into()),
            "outlook" | "hotmail" => Some("outlook.office365.com".into()),
            "yahoo" => Some("imap.mail.yahoo.com".into()),
            _ => None,
        };
    }

    let host = host.ok_or_else(|| {
        ArloError::AuthError("IMAP host or supported provider missing".into())
    })?;

    Ok((host, port))
}

fn require_credentials(config: &ImapConfig) -> Result<(String, String), ArloError> {
    let username = config
        .username
        .clone()
        .ok_or_else(|| ArloError::AuthError("IMAP username missing".into()))?;
    let password = config
        .password
        .clone()
        .ok_or_else(|| ArloError::AuthError("IMAP password missing".into()))?;
    Ok((username, password))
}

/// Build the `UNSEEN FROM "arlo.com"` search predicate used both at baseline
/// capture and during OTP polling.
fn arlo_unseen_query() -> SearchQuery {
    SearchQuery::new(SearchKey::And(vec![
        SearchKey::Unseen,
        SearchKey::From("arlo.com".into()),
    ]))
}

/// Captures the baseline set of UNSEEN Arlo emails *before* the API dispatch
/// is triggered. Without this, a race exists where the Arlo email arrives
/// faster than we can connect, and we'd return an OTP we already had.
#[instrument(skip(config))]
pub async fn get_baseline(config: &ImapConfig) -> Result<HashSet<u32>, ArloError> {
    let (host, port) = resolve_host_and_port(config)?;
    let (username, password) = require_credentials(config)?;

    let unauth = imap_tls::connect_tls(&host, port)
        .await
        .map_err(|e| ArloError::AuthError(format!("IMAP TLS connect failed: {e}")))?;

    let auth = unauth
        .login(&username, Password::new(password))
        .await
        .map_err(|e| ArloError::AuthError(format!("IMAP login failed: {e}")))?;

    let mut selected = auth
        .select("INBOX")
        .await
        .map_err(|e| ArloError::AuthError(format!("Failed to select INBOX: {e}")))?;

    let baseline: HashSet<u32> = selected
        .search(arlo_unseen_query())
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();

    debug!(baseline_size = baseline.len(), "Captured IMAP baseline");

    let _ = selected.logout().await;
    Ok(baseline)
}

/// Polls the inbox until a new Arlo email lands, then extracts and returns
/// the 6-digit OTP. Optionally flags-and-expunges the message after read.
#[instrument(skip(config, baseline_set))]
pub async fn fetch_otp(
    config: &ImapConfig,
    baseline_set: HashSet<u32>,
) -> Result<String, ArloError> {
    let (host, port) = resolve_host_and_port(config)?;
    let (username, password) = require_credentials(config)?;
    let delete_after_read = config.delete_after_read.unwrap_or(false);

    let unauth = imap_tls::connect_tls(&host, port)
        .await
        .map_err(|e| ArloError::AuthError(format!("IMAP TLS connect failed: {e}")))?;

    let auth = unauth
        .login(&username, Password::new(password))
        .await
        .map_err(|e| ArloError::AuthError(format!("IMAP login failed: {e}")))?;

    let mut selected = auth
        .select("INBOX")
        .await
        .map_err(|e| ArloError::AuthError(format!("Failed to select INBOX: {e}")))?;

    // Wait for a fresh Arlo email — anything not already in the baseline.
    let deadline = tokio::time::Instant::now() + OTP_FETCH_TIMEOUT;
    let new_seq = loop {
        let current: HashSet<u32> = selected
            .search(arlo_unseen_query())
            .await
            .map_err(|e| ArloError::AuthError(format!("IMAP SEARCH failed: {e}")))?
            .into_iter()
            .collect();

        let new_seqs: Vec<u32> = current.difference(&baseline_set).copied().collect();
        if let Some(&max) = new_seqs.iter().max() {
            break max;
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(ArloError::AuthError(
                "Timed out waiting for Arlo MFA email (30s)".into(),
            ));
        }
        tokio::time::sleep(OTP_POLL_INTERVAL).await;
    };

    let fetched = selected
        .fetch(&new_seq.to_string(), "RFC822")
        .await
        .map_err(|e| ArloError::AuthError(format!("IMAP FETCH failed: {e}")))?;

    let body_bytes = fetched
        .into_iter()
        .find_map(|f| f.body)
        .ok_or_else(|| ArloError::AuthError("Empty IMAP email body".into()))?;

    let parsed = mailparse::parse_mail(&body_bytes)
        .map_err(|e| ArloError::AuthError(format!("MIME parsing failed: {e}")))?;
    let content = extract_text(&parsed);

    let otp = extract_otp(&content).ok_or_else(|| {
        ArloError::AuthError(format!(
            "Failed to extract 6-digit OTP from Arlo email (content len={})",
            content.len()
        ))
    })?;

    if delete_after_read {
        let _ = selected
            .store(&new_seq.to_string(), StoreAction::Add, &[Flag::Deleted])
            .await
            .map_err(|e| ArloError::AuthError(format!("Failed to flag for deletion: {e}")))?;
        let _ = selected
            .expunge()
            .await
            .map_err(|e| ArloError::AuthError(format!("Failed to expunge INBOX: {e}")))?;
    }

    let _ = selected.logout().await;
    Ok(otp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_otp_matches_h1_block() {
        let html = r#"<html><body>
            <h1 style="color:#1B5A8F;font-size:30px;">
                308076
            </h1>
        </body></html>"#;
        assert_eq!(extract_otp(html).as_deref(), Some("308076"));
    }

    #[test]
    fn extract_otp_falls_back_to_loose_digits() {
        // No <h1> wrapper — must use fallback regex.
        let body = "Your Arlo verification code is 425901. It expires in 5 minutes.";
        assert_eq!(extract_otp(body).as_deref(), Some("425901"));
    }

    #[test]
    fn extract_otp_ignores_css_hex_and_html_entities() {
        // 6-digit-looking CSS colours and HTML entities must not trip the fallback regex.
        let body = "<div style=\"color:#abc123\">no code here &#123456; either</div>";
        assert_eq!(extract_otp(body), None);
    }

    #[test]
    fn extract_otp_returns_none_when_absent() {
        assert_eq!(extract_otp("Hello, no code in this email."), None);
    }

    #[test]
    fn extract_otp_prefers_h1_over_other_digits() {
        let html = "Reference 999999. <h1>123456</h1> tail 888888.";
        assert_eq!(extract_otp(html).as_deref(), Some("123456"));
    }

    #[test]
    fn arlo_unseen_query_renders_expected_imap_predicate() {
        let rendered = arlo_unseen_query().build();
        assert!(rendered.contains("UNSEEN"));
        assert!(rendered.contains("FROM \"arlo.com\""));
    }

    #[test]
    fn resolve_host_and_port_uses_provider_shortcut() {
        let cfg = ImapConfig {
            enabled: Some(true),
            provider: Some("gmail".into()),
            host: None,
            port: None,
            username: Some("u".into()),
            password: Some("p".into()),
            delete_after_read: None,
        };
        let (host, port) = resolve_host_and_port(&cfg).unwrap();
        assert_eq!(host, "imap.gmail.com");
        assert_eq!(port, 993);
    }

    #[test]
    fn resolve_host_and_port_explicit_host_wins() {
        let cfg = ImapConfig {
            enabled: Some(true),
            provider: Some("gmail".into()),
            host: Some("custom.example.com".into()),
            port: Some(143),
            username: Some("u".into()),
            password: Some("p".into()),
            delete_after_read: None,
        };
        let (host, port) = resolve_host_and_port(&cfg).unwrap();
        assert_eq!(host, "custom.example.com");
        assert_eq!(port, 143);
    }

    #[test]
    fn resolve_host_and_port_errors_when_unresolvable() {
        let cfg = ImapConfig {
            enabled: Some(true),
            provider: Some("unknown-provider".into()),
            host: None,
            port: None,
            username: Some("u".into()),
            password: Some("p".into()),
            delete_after_read: None,
        };
        assert!(resolve_host_and_port(&cfg).is_err());
    }
}
