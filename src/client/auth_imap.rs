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
use mailparse::{MailAddr, MailHeaderMap, ParsedMail};
use regex_lite::Regex;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, instrument, warn};

/// Maximum time we wait for the Arlo OTP email to land in the inbox.
const OTP_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Delay between mailbox searches while waiting for the OTP email.
const OTP_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Wall-clock budget for one whole [`fetch_otp`] call — connect, login,
/// polling and fetch. Every IMAP command has its own 30 s timeout in the
/// client crate, so without this the worst case is minutes, not 30 s.
const OTP_TOTAL_BUDGET: Duration = Duration::from_secs(90);
/// Same for [`get_baseline`], which is a connect, a login and one search.
const BASELINE_BUDGET: Duration = Duration::from_secs(45);

/// Domain Arlo's one-time-code mail is sent from. The IMAP `FROM` search
/// key is only a substring match on the header, so the address is
/// re-checked here: the domain must be exactly this or a subdomain.
const OTP_SENDER_DOMAIN: &str = "arlo.com";
/// Largest message a candidate may be; Arlo's code mails are tens of KB.
const MAX_OTP_MAIL_BYTES: usize = 512 * 1024;
/// Most `multipart/` parts a candidate may declare. `mailparse` recurses
/// once per part with no depth limit of its own, so a planted message
/// with thousands of nested parts would overflow the stack.
const MAX_OTP_MAIL_PARTS: usize = 16;

/// Arlo formats the OTP inside an `<h1>` block. Match exactly 6 digits there.
static OTP_RE_H1: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<h1[^>]*>\s*(\d{6})\s*</h1>")
        .expect("SAFETY: static regex literal, validated by the unit tests")
});
/// Newer templates put the code on a line of its own in the `text/plain`
/// part (the reference client's `^\W*(\d{6})\W*$` per-line match).
static OTP_RE_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\W*(\d{6})\W*$")
        .expect("SAFETY: static regex literal, validated by the unit tests")
});
/// Fallback: 6 digits not preceded by `#`, `=`, `&`, or word chars (avoids
/// CSS hex colours, quoted-printable artefacts, and HTML entities).
static OTP_RE_FALLBACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:^|[^#=&\w])(\d{6})(?:[^0-9]|$)")
        .expect("SAFETY: static regex literal, validated by the unit tests")
});

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

/// Extracts a 6-digit Arlo OTP from an extracted email body, trying the
/// `<h1>` block, then a bare-digits line, then the loose-digit fallback.
/// Returns `None` if none match.
pub fn extract_otp(content: &str) -> Option<String> {
    if let Some(caps) = OTP_RE_H1.captures(content) {
        return Some(caps[1].to_string());
    }
    if let Some(caps) = OTP_RE_LINE.captures(content) {
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

    let host =
        host.ok_or_else(|| ArloError::AuthError("IMAP host or supported provider missing".into()))?;

    Ok((host, port))
}

fn require_credentials(config: &ImapConfig) -> Result<(String, SecretString), ArloError> {
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
/// capture and during OTP polling. `FROM` is a substring match, so it is
/// only a coarse filter; [`sender_is_arlo`] is the real check.
fn arlo_unseen_query() -> SearchQuery {
    SearchQuery::new(SearchKey::And(vec![
        SearchKey::Unseen,
        SearchKey::From(OTP_SENDER_DOMAIN.into()),
    ]))
}

/// True when `addr` (`local@domain`) is under [`OTP_SENDER_DOMAIN`].
fn sender_domain_ok(addr: &str) -> bool {
    let Some((_, domain)) = addr.rsplit_once('@') else {
        return false;
    };
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    d == OTP_SENDER_DOMAIN || d.ends_with(&format!(".{OTP_SENDER_DOMAIN}"))
}

/// True when every address in a `From:` header value is Arlo's. The
/// display name is ignored on purpose: `"arlo.com" <x@evil.example>` is
/// exactly the spoof the IMAP substring search lets through.
fn sender_is_arlo(from_header: &str) -> bool {
    let Ok(list) = mailparse::addrparse(from_header) else {
        return false;
    };
    let mut seen_any = false;
    for entry in list.iter() {
        match entry {
            MailAddr::Single(single) => {
                seen_any = true;
                if !sender_domain_ok(&single.addr) {
                    return false;
                }
            }
            MailAddr::Group(group) => {
                for single in &group.addrs {
                    seen_any = true;
                    if !sender_domain_ok(&single.addr) {
                        return false;
                    }
                }
            }
        }
    }
    seen_any
}

/// Sender check on a raw header block (or a whole message).
fn header_block_is_from_arlo(raw: &[u8]) -> bool {
    mailparse::parse_mail(raw)
        .ok()
        .and_then(|m| m.headers.get_first_value("From"))
        .is_some_and(|from| sender_is_arlo(&from))
}

/// Size and nesting bounds a message must satisfy before it is parsed.
fn mail_within_bounds(raw: &[u8]) -> bool {
    if raw.len() > MAX_OTP_MAIL_BYTES {
        return false;
    }
    let needle = b"multipart/";
    let parts = raw
        .windows(needle.len())
        .filter(|w| w.eq_ignore_ascii_case(needle))
        .count();
    parts <= MAX_OTP_MAIL_PARTS
}

/// UIDs present now but not at baseline, newest first. UIDs are assigned
/// in arrival order, so the largest is the most recent mail.
fn newest_first(current: &HashSet<u32>, baseline: &HashSet<u32>) -> Vec<u32> {
    let mut fresh: Vec<u32> = current.difference(baseline).copied().collect();
    fresh.sort_unstable_by(|a, b| b.cmp(a));
    fresh
}

/// Maps a UID to its current sequence number from a `SEARCH` and a
/// `UID SEARCH` of the same query issued back to back: both lists are in
/// mailbox order, so the i-th entries correspond. `None` when the lists
/// disagree in length (a renumbering happened in between) or the UID is
/// gone; the caller then re-searches.
fn seq_for_uid(seqs: &[u32], uids: &[u32], uid: u32) -> Option<u32> {
    if seqs.len() != uids.len() {
        return None;
    }
    let mut seqs = seqs.to_vec();
    seqs.sort_unstable();
    let mut sorted_uids = uids.to_vec();
    sorted_uids.sort_unstable();
    let i = sorted_uids.iter().position(|&u| u == uid)?;
    seqs.get(i).copied()
}

async fn open_inbox(
    config: &ImapConfig,
) -> Result<
    imap_client::session::Session<imap_client::session::Selected, imap_client::Tls>,
    ArloError,
> {
    let (host, port) = resolve_host_and_port(config)?;
    let (username, password) = require_credentials(config)?;

    let unauth = imap_tls::connect_tls(&host, port)
        .await
        .map_err(|e| ArloError::AuthError(format!("IMAP TLS connect failed: {e}")))?;

    let auth = unauth
        .login(
            &username,
            Password::new(password.expose_secret().to_owned()),
        )
        .await
        .map_err(|e| ArloError::AuthError(format!("IMAP login failed: {e}")))?;

    auth.select("INBOX")
        .await
        .map_err(|e| ArloError::AuthError(format!("Failed to select INBOX: {e}")))
}

/// Captures the baseline set of UNSEEN Arlo emails (by UID) *before* the
/// API dispatch is triggered. Without this, a race exists where the Arlo
/// email arrives faster than we can connect, and we'd return an OTP we
/// already had. A failed search is an error, not an empty baseline: an
/// empty baseline would make every old code look new.
#[instrument(skip(config))]
pub async fn get_baseline(config: &ImapConfig) -> Result<HashSet<u32>, ArloError> {
    tokio::time::timeout(BASELINE_BUDGET, get_baseline_inner(config))
        .await
        .map_err(|_| {
            ArloError::Timeout(format!(
                "IMAP baseline capture exceeded {BASELINE_BUDGET:?}"
            ))
        })?
}

async fn get_baseline_inner(config: &ImapConfig) -> Result<HashSet<u32>, ArloError> {
    let mut selected = open_inbox(config).await?;
    let baseline: HashSet<u32> = selected
        .uid_search(arlo_unseen_query())
        .await
        .map_err(|e| ArloError::AuthError(format!("IMAP baseline SEARCH failed: {e}")))?
        .into_iter()
        .collect();

    debug!(baseline_size = baseline.len(), "Captured IMAP baseline");

    let _ = selected.logout().await;
    Ok(baseline)
}

/// Polls the inbox until a new Arlo email lands, then extracts and returns
/// the 6-digit OTP. Optionally flags-and-expunges the message after read.
///
/// Candidates are examined newest first; a message whose `From:` address
/// is not Arlo's, or that is too large or too deeply nested, is skipped
/// (and not re-examined), so a third party mailing the inbox during the
/// window cannot choose the code that gets submitted.
#[instrument(skip(config, baseline_set))]
pub async fn fetch_otp(
    config: &ImapConfig,
    baseline_set: HashSet<u32>,
) -> Result<String, ArloError> {
    tokio::time::timeout(OTP_TOTAL_BUDGET, fetch_otp_inner(config, baseline_set))
        .await
        .map_err(|_| ArloError::Timeout(format!("IMAP OTP fetch exceeded {OTP_TOTAL_BUDGET:?}")))?
}

async fn fetch_otp_inner(
    config: &ImapConfig,
    mut baseline_set: HashSet<u32>,
) -> Result<String, ArloError> {
    let delete_after_read = config.delete_after_read.unwrap_or(false);
    let mut selected = open_inbox(config).await?;

    // Wait for a fresh Arlo email — anything not already in the baseline.
    let deadline = tokio::time::Instant::now() + OTP_FETCH_TIMEOUT;
    let (uid, body_bytes) = loop {
        // Force a session refresh (essential for Gmail to see new mail in an open session).
        let _ = selected.noop().await;

        let current: HashSet<u32> = selected
            .uid_search(arlo_unseen_query())
            .await
            .map_err(|e| ArloError::AuthError(format!("IMAP SEARCH failed: {e}")))?
            .into_iter()
            .collect();

        let mut accepted = None;
        for uid in newest_first(&current, &baseline_set) {
            // UID -> sequence number, resolved immediately before use and
            // verified on the FETCH reply, so an EXPUNGE elsewhere cannot
            // make us read a different message.
            let seqs = selected
                .search(arlo_unseen_query())
                .await
                .map_err(|e| ArloError::AuthError(format!("IMAP SEARCH failed: {e}")))?;
            let uids = selected
                .uid_search(arlo_unseen_query())
                .await
                .map_err(|e| ArloError::AuthError(format!("IMAP SEARCH failed: {e}")))?;
            let Some(seq) = seq_for_uid(&seqs, &uids, uid) else {
                debug!(uid, "mailbox renumbered mid-poll; re-searching");
                continue;
            };

            // Headers only (PEEK keeps it unseen): decide on the sender
            // before downloading a body a stranger controls.
            let head = selected
                .fetch(&seq.to_string(), "(UID BODY.PEEK[HEADER])")
                .await
                .map_err(|e| ArloError::AuthError(format!("IMAP FETCH failed: {e}")))?;
            let Some(headers) = head
                .into_iter()
                .find(|f| f.uid == Some(uid))
                .and_then(|f| f.body)
            else {
                debug!(uid, "FETCH returned a different message; re-searching");
                continue;
            };
            if !header_block_is_from_arlo(&headers) {
                warn!(uid, "ignoring unseen mail: From address is not Arlo's");
                baseline_set.insert(uid);
                continue;
            }

            let full = selected
                .fetch(&seq.to_string(), "(UID RFC822)")
                .await
                .map_err(|e| ArloError::AuthError(format!("IMAP FETCH failed: {e}")))?;
            let Some(body) = full
                .into_iter()
                .find(|f| f.uid == Some(uid))
                .and_then(|f| f.body)
            else {
                debug!(uid, "FETCH returned a different message; re-searching");
                continue;
            };
            if !mail_within_bounds(&body) {
                warn!(
                    uid,
                    bytes = body.len(),
                    "ignoring unseen mail: too large or too deeply nested to be Arlo's"
                );
                baseline_set.insert(uid);
                continue;
            }
            accepted = Some((uid, body));
            break;
        }
        if let Some(found) = accepted {
            break found;
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(ArloError::AuthError(format!(
                "Timed out waiting for Arlo MFA email ({OTP_FETCH_TIMEOUT:?})"
            )));
        }
        tokio::time::sleep(OTP_POLL_INTERVAL).await;
    };

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
        selected
            .uid_store(&uid.to_string(), StoreAction::Add, &[Flag::Deleted])
            .await
            .map_err(|e| ArloError::AuthError(format!("Failed to flag for deletion: {e}")))?;
        selected
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
    fn extract_otp_matches_bare_digit_line_in_plain_text() {
        let text = "Your Arlo verification code is below.\n\n  467266  \n\nThis code expires.";
        assert_eq!(extract_otp(text).as_deref(), Some("467266"));
    }

    #[test]
    fn extract_text_decodes_latin1_quoted_printable_plain_part() {
        // 2026 Arlo template: ISO-8859-1 body, `©` as =A9, code on its own
        // line in the text/plain part, HTML part with the h1 (pyaarlo #197).
        let raw = concat!(
            "From: do_not_reply@arlo.com\r\n",
            "To: you@example.com\r\n",
            "Subject: Your Arlo code\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"b1\"\r\n",
            "\r\n",
            "--b1\r\n",
            "Content-Type: text/plain; charset=iso-8859-1\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "Your verification code:\r\n",
            "\r\n",
            "467266\r\n",
            "\r\n",
            "=A9 2026 Arlo Technologies\r\n",
            "--b1\r\n",
            "Content-Type: text/html; charset=iso-8859-1\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "<html><body><h1>467266 </h1><p>=A9 2026 Arlo</p></body></html>\r\n",
            "--b1--\r\n",
        );
        let parsed = mailparse::parse_mail(raw.as_bytes()).expect("fixture parses");
        let text = extract_text(&parsed);
        assert!(text.contains("\u{a9} 2026"), "charset decoded: {text}");
        assert_eq!(extract_otp(&text).as_deref(), Some("467266"));
    }

    #[test]
    fn extract_text_handles_plain_only_email() {
        let raw = concat!(
            "From: do_not_reply@arlo.com\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Code:\r\n123456\r\n",
        );
        let parsed = mailparse::parse_mail(raw.as_bytes()).expect("fixture parses");
        assert_eq!(
            extract_otp(&extract_text(&parsed)).as_deref(),
            Some("123456")
        );
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

#[cfg(test)]
mod candidate_tests {
    use super::*;

    #[test]
    fn sender_check_ignores_display_names_and_lookalike_domains() {
        for ok in [
            "Arlo <do_not_reply@arlo.com>",
            "noreply@mail.arlo.com",
            "\"Arlo Support\" <support@ARLO.COM>",
        ] {
            assert!(sender_is_arlo(ok), "{ok}");
        }
        for bad in [
            "\"arlo.com\" <x@evil.example>",
            "Arlo <x@arlo.com.evil.example>",
            "Arlo <x@notarlo.com>",
            "Arlo <do_not_reply@arlo.com>, Eve <e@evil.example>",
            "",
            "not an address",
        ] {
            assert!(!sender_is_arlo(bad), "{bad}");
        }
    }

    #[test]
    fn header_block_check_reads_the_from_header() {
        let ok = b"From: Arlo <do_not_reply@arlo.com>\r\nSubject: code\r\n\r\n";
        assert!(header_block_is_from_arlo(ok));
        let spoof = b"From: \"do_not_reply@arlo.com\" <x@evil.example>\r\nSubject: code\r\n\r\n";
        assert!(!header_block_is_from_arlo(spoof));
        assert!(!header_block_is_from_arlo(b"Subject: no sender\r\n\r\n"));
    }

    #[test]
    fn bounds_reject_oversized_and_over_nested_messages() {
        assert!(mail_within_bounds(b"From: a@arlo.com\r\n\r\nbody"));
        assert!(!mail_within_bounds(&vec![b'x'; MAX_OTP_MAIL_BYTES + 1]));
        let mut nested = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n".to_vec();
        for _ in 0..MAX_OTP_MAIL_PARTS + 1 {
            nested.extend_from_slice(b"--b\r\nContent-Type: MULTIPART/mixed; boundary=b\r\n\r\n");
        }
        assert!(!mail_within_bounds(&nested));
    }

    #[test]
    fn candidates_are_newest_first_and_exclude_baseline() {
        let baseline: HashSet<u32> = [10, 11].into_iter().collect();
        let current: HashSet<u32> = [10, 11, 12, 15, 13].into_iter().collect();
        assert_eq!(newest_first(&current, &baseline), vec![15, 13, 12]);
    }

    #[test]
    fn uid_to_sequence_mapping_requires_consistent_lists() {
        assert_eq!(seq_for_uid(&[3, 7, 9], &[100, 250, 300], 250), Some(7));
        assert_eq!(seq_for_uid(&[9, 3, 7], &[300, 100, 250], 300), Some(9));
        assert_eq!(seq_for_uid(&[3, 7], &[100, 250, 300], 250), None);
        assert_eq!(seq_for_uid(&[3, 7, 9], &[100, 250, 300], 999), None);
    }
}
