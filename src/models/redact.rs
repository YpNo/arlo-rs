//! Secret-aware rendering of wire data for logs and error messages.
//!
//! Pure string/JSON helpers: no I/O, no transport types. Everything that
//! turns an upstream body, header or URL into text a human might read
//! goes through here, so the redaction policy lives in one place.

use serde_json::Value;

/// JSON keys whose values must never reach a log line or an error
/// message. Matched case-insensitively and exactly; see
/// [`is_sensitive_key`] for the pattern rules layered on top.
const REDACTED_JSON_KEYS: &[&str] = &[
    "password",
    "token",
    "access_token",
    "accesstoken",
    "authorization",
    "otp",
    "factorauthcode",
    "browserauthcode",
    "refreshtoken",
    "credential",
    "cookie",
    "set-cookie",
    "url",
    "streamurl",
];

/// Longest excerpt of a body that an error message may carry.
const EXCERPT_MAX_BYTES: usize = 256;

/// True when a JSON key names a secret-bearing value: an exact hit in
/// [`REDACTED_JSON_KEYS`], anything ending in `token` / `password` /
/// `credential` (`mqttToken`, `sipPassword`, …), or any presigned S3
/// capability URL (`presignedLastImageUrl`, `presignedContentUrl`, …).
fn is_sensitive_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    REDACTED_JSON_KEYS.contains(&k.as_str())
        || k.ends_with("token")
        || k.ends_with("password")
        || k.ends_with("credential")
        || k.starts_with("presigned")
}

/// Returns a log-safe rendering of `raw`. If `raw` is valid JSON,
/// sensitive keys are replaced with `"***"`. Otherwise the raw string is
/// returned unchanged (the keys we redact only ever appear inside JSON
/// bodies).
pub(crate) fn redact_for_log(raw: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(raw) else {
        return raw.to_string();
    };
    redact_in_place(&mut value);
    serde_json::to_string(&value).unwrap_or_else(|_| raw.to_string())
}

fn redact_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_sensitive_key(k) {
                    *v = Value::String("***".to_string());
                } else {
                    redact_in_place(v);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_in_place(v);
            }
        }
        _ => {}
    }
}

/// The form of an upstream body that may be embedded in an error
/// message: redacted, stripped of control characters (so it cannot forge
/// log lines), and capped at [`EXCERPT_MAX_BYTES`] with the original
/// length noted. Never put a raw body into an error; use this.
pub(crate) fn excerpt(raw: &str) -> String {
    let redacted = redact_for_log(raw);
    let clean: String = redacted
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if clean.len() <= EXCERPT_MAX_BYTES {
        return clean;
    }
    let mut cut = EXCERPT_MAX_BYTES;
    while !clean.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}… ({} bytes total)", &clean[..cut], raw.len())
}

/// A URL with any `user:password@` userinfo removed, for `Debug` output
/// of proxy settings. Unparseable input is fully redacted rather than
/// echoed.
pub(crate) fn redact_userinfo(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            if u.username().is_empty() && u.password().is_none() {
                return u.to_string();
            }
            // Setting fails only for cannot-be-a-base URLs, which carry
            // no userinfo in the first place.
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.to_string()
        }
        Err(_) => "[REDACTED]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_exact_suffix_and_presigned_keys() {
        let input = r#"{"browserAuthCode":"b","credential":"c","presignedLastImageUrl":"p","url":"u","streamUrl":"s","mqttToken":"m","sipPassword":"q","meta":{"code":200},"deviceId":"D1"}"#;
        let out = redact_for_log(input);
        for leaked in [
            "\"b\"", "\"c\"", "\"p\"", "\"u\"", "\"s\"", "\"m\"", "\"q\"",
        ] {
            assert!(!out.contains(leaked), "{leaked} survived: {out}");
        }
        assert!(
            out.contains(r#""code":200"#),
            "meta.code must survive: {out}"
        );
        assert!(out.contains(r#""deviceId":"D1""#));
    }

    #[test]
    fn excerpt_redacts_json_and_caps_length() {
        let body = format!(r#"{{"token":"SECRET","pad":"{}"}}"#, "x".repeat(1000));
        let out = excerpt(&body);
        assert!(!out.contains("SECRET"), "{out}");
        assert!(out.len() < EXCERPT_MAX_BYTES + 40, "len {}", out.len());
        assert!(out.ends_with("bytes total)"), "{out}");
    }

    #[test]
    fn excerpt_strips_control_characters_from_non_json() {
        let body = "<html>\n<body>\u{1b}[31mblocked\u{1b}[0m\r\n</body></html>";
        let out = excerpt(body);
        assert!(
            !out.contains('\n') && !out.contains('\r') && !out.contains('\u{1b}'),
            "{out}"
        );
        assert!(out.contains("blocked"));
    }

    #[test]
    fn excerpt_keeps_short_bodies_whole() {
        assert_eq!(
            excerpt(r#"{"meta":{"code":400}}"#),
            r#"{"meta":{"code":400}}"#
        );
        assert_eq!(excerpt("<html>nope</html>"), "<html>nope</html>");
    }

    #[test]
    fn redact_userinfo_drops_credentials_only() {
        assert_eq!(
            redact_userinfo("http://user:pass@proxy.example:8080"),
            "http://proxy.example:8080/"
        );
        assert_eq!(
            redact_userinfo("socks5://proxy.example:1080"),
            "socks5://proxy.example:1080"
        );
        assert_eq!(redact_userinfo("not a url"), "[REDACTED]");
    }
}
