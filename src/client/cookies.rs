//! Persistent cookie jar for the default transport.
//!
//! Arlo binds "trust this browser" to cookies set by `ocapi-app.arlo.com`
//! during pairing (together with the `x-user-device-id` header). A fresh
//! jar on every process start therefore means an OTP on every token
//! expiry. [`PersistentJar`] is a `wreq` cookie store whose contents can
//! be exported to, and restored from, a JSON string that the session cache
//! carries alongside the access token.
//!
//! Infrastructure adapter: it knows about `wreq` and `cookie_store`, and
//! nothing about Arlo.

use crate::error::ArloError;
use std::sync::RwLock;
use wreq::header::HeaderValue;

/// A `wreq` cookie store backed by `cookie_store`, with JSON import /
/// export. Session cookies (no `Expires` / `Max-Age`) are exported too —
/// Arlo's trust cookies are session-scoped, and the reference client
/// persists them the same way.
#[derive(Debug, Default)]
pub struct PersistentJar(RwLock<cookie_store::CookieStore>);

impl PersistentJar {
    /// Serialises every cookie (including session cookies) as JSON.
    /// Returns `None` when the jar is empty, so callers can skip writing
    /// an empty blob.
    pub fn export_json(&self) -> Option<String> {
        let store = self.0.read().unwrap_or_else(|e| e.into_inner());
        store.iter_unexpired().next()?;
        let mut buf = Vec::new();
        cookie_store::serde::json::save_incl_expired_and_nonpersistent(&store, &mut buf).ok()?;
        String::from_utf8(buf).ok()
    }

    /// Replaces the jar's contents with cookies previously produced by
    /// [`Self::export_json`]. Expired cookies in the blob are dropped.
    pub fn import_json(&self, json: &str) -> Result<(), ArloError> {
        let loaded = cookie_store::serde::json::load_all(json.as_bytes())
            .map_err(|e| ArloError::ParseError(format!("cookie jar blob: {e}")))?;
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = loaded;
        Ok(())
    }

    /// Number of unexpired cookies held. Test / diagnostics aid.
    pub fn len(&self) -> usize {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter_unexpired()
            .count()
    }

    /// True when no unexpired cookie is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl wreq::cookie::CookieStore for PersistentJar {
    fn set_cookies(&self, url: &wreq::Url, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>) {
        let cookies = cookie_headers.filter_map(|value| {
            wreq::cookie::Cookie::parse(value)
                .ok()
                .map(|c| c.into_owned().into_inner())
        });
        self.0
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .store_response_cookies(cookies, url);
    }

    fn cookies(&self, url: &wreq::Url) -> Option<HeaderValue> {
        let store = self.0.read().unwrap_or_else(|e| e.into_inner());
        let header = store
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if header.is_empty() {
            return None;
        }
        HeaderValue::from_str(&header).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wreq::cookie::CookieStore as _;

    fn url(s: &str) -> wreq::Url {
        wreq::Url::parse(s).unwrap()
    }

    #[test]
    fn stores_response_cookies_and_replays_them_by_scope() {
        let jar = PersistentJar::default();
        let set = [
            HeaderValue::from_static("trust=abc; Path=/; Secure; HttpOnly"),
            HeaderValue::from_static("other=1; Domain=elsewhere.example"),
        ];
        jar.set_cookies(&url("https://ocapi-app.arlo.com/api/auth"), &mut set.iter());

        let sent = jar.cookies(&url("https://ocapi-app.arlo.com/api/getFactorId"));
        assert_eq!(
            sent.as_ref().and_then(|v| v.to_str().ok()),
            Some("trust=abc")
        );
        assert!(jar.cookies(&url("https://myapi.arlo.com/hmsweb")).is_none());
    }

    #[test]
    fn export_import_round_trip_keeps_session_cookies() {
        let jar = PersistentJar::default();
        let set = [HeaderValue::from_static("trust=abc; Path=/")]; // session cookie
        jar.set_cookies(&url("https://ocapi-app.arlo.com/"), &mut set.iter());
        let blob = jar.export_json().expect("non-empty jar exports");

        let restored = PersistentJar::default();
        restored.import_json(&blob).unwrap();
        assert_eq!(restored.len(), 1);
        let sent = restored.cookies(&url("https://ocapi-app.arlo.com/api/x"));
        assert_eq!(
            sent.as_ref().and_then(|v| v.to_str().ok()),
            Some("trust=abc")
        );
    }

    #[test]
    fn empty_jar_exports_none_and_bad_blob_is_a_parse_error() {
        let jar = PersistentJar::default();
        assert!(jar.is_empty());
        assert!(jar.export_json().is_none());
        assert!(matches!(
            jar.import_json("not json").unwrap_err(),
            ArloError::ParseError(_)
        ));
    }
}
