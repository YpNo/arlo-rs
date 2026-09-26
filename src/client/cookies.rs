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
use cookie_store::RawCookie;
use std::sync::RwLock;
use stealthscraper_rs::wreq;
use url::Url;
use wreq::cookie::Cookies;
use wreq::header::HeaderValue;
use wreq::{Uri, Version};

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
        let loaded = cookie_store::serde::json::load(json.as_bytes())
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

/// `wreq` addresses requests by `http::Uri`; `cookie_store` scopes cookies
/// by `url::Url`. The conversion cannot fail for a URI `wreq` has already
/// connected to, but a malformed one simply matches no cookie.
fn to_url(uri: &Uri) -> Option<Url> {
    Url::parse(&uri.to_string()).ok()
}

impl wreq::cookie::CookieStore for PersistentJar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri) {
        let Some(url) = to_url(uri) else {
            return;
        };
        let cookies = cookie_headers.filter_map(|value| {
            let text = std::str::from_utf8(value.as_bytes()).ok()?;
            RawCookie::parse(text).ok().map(RawCookie::into_owned)
        });
        self.0
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .store_response_cookies(cookies, &url);
    }

    // Chrome sends one combined `Cookie` field on HTTP/2 as well as on
    // HTTP/1.1 (splitting per pair is a Firefox habit), so the version is
    // deliberately ignored — the emulated browser must not change shape.
    fn cookies(&self, uri: &Uri, _version: Version) -> Cookies {
        let Some(url) = to_url(uri) else {
            return Cookies::Empty;
        };
        let store = self.0.read().unwrap_or_else(|e| e.into_inner());
        let header = store
            .get_request_values(&url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if header.is_empty() {
            return Cookies::Empty;
        }
        HeaderValue::from_str(&header).map_or(Cookies::Empty, Cookies::Compressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wreq::cookie::CookieStore as _;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    /// The single `Cookie` field value a jar produced for `uri`, if any.
    fn sent(jar: &PersistentJar, uri: &Uri) -> Option<String> {
        match jar.cookies(uri, Version::HTTP_2) {
            Cookies::Compressed(v) => v.to_str().ok().map(str::to_owned),
            Cookies::Empty => None,
            other => panic!("unexpected cookie shape: {other:?}"),
        }
    }

    #[test]
    fn stores_response_cookies_and_replays_them_by_scope() {
        let jar = PersistentJar::default();
        let set = [
            HeaderValue::from_static("trust=abc; Path=/; Secure; HttpOnly"),
            HeaderValue::from_static("other=1; Domain=elsewhere.example"),
        ];
        jar.set_cookies(&mut set.iter(), &uri("https://ocapi-app.arlo.com/api/auth"));

        assert_eq!(
            sent(&jar, &uri("https://ocapi-app.arlo.com/api/getFactorId")).as_deref(),
            Some("trust=abc")
        );
        assert!(sent(&jar, &uri("https://myapi.arlo.com/hmsweb")).is_none());
    }

    #[test]
    fn export_import_round_trip_keeps_session_cookies() {
        let jar = PersistentJar::default();
        let set = [HeaderValue::from_static("trust=abc; Path=/")]; // session cookie
        jar.set_cookies(&mut set.iter(), &uri("https://ocapi-app.arlo.com/"));
        let blob = jar.export_json().expect("non-empty jar exports");

        let restored = PersistentJar::default();
        restored.import_json(&blob).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(
            sent(&restored, &uri("https://ocapi-app.arlo.com/api/x")).as_deref(),
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

#[cfg(test)]
mod expiry_tests {
    use super::*;
    use wreq::cookie::CookieStore as _;

    #[test]
    fn import_drops_expired_cookies_but_keeps_session_cookies() {
        let jar = PersistentJar::default();
        let set = [
            HeaderValue::from_static("short=1; Path=/; Max-Age=1"),
            HeaderValue::from_static("session=2; Path=/"),
        ];
        jar.set_cookies(
            &mut set.iter(),
            &"https://ocapi-app.arlo.com/".parse().unwrap(),
        );
        let blob = jar.export_json().expect("two cookies exported");
        assert_eq!(jar.len(), 2);

        std::thread::sleep(std::time::Duration::from_millis(1200));
        let restored = PersistentJar::default();
        restored.import_json(&blob).unwrap();
        assert_eq!(restored.len(), 1, "the Max-Age=1 cookie must not come back");
    }
}
