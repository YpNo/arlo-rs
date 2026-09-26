//! Runtime-configurable Arlo host endpoints.
//!
//! The path constants in [`crate::endpoints`] (e.g. `AUTH_LOGIN`,
//! `API_DEVICES`) are tied to Arlo's API and don't change between
//! deployments. The *base hosts* — `ocapi-app.arlo.com` for auth and
//! `myapi.arlo.com` for the device API — are constant in production but
//! must be overrideable so unit tests can point the client at a mockito
//! server. [`ArloEndpoints`] carries those two URLs.
//!
//! Construct via [`ArloEndpoints::default`] for production or
//! [`ArloEndpoints::testing`] when wiring against a mock server.

use crate::headers::{ARLO_API_HOST, ARLO_AUTH_HOST};

/// Base hosts the [`crate::ArloClient`] talks to. Defaults match the
/// production Arlo deployment; tests override them via
/// [`crate::ArloClientBuilder::endpoints`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArloEndpoints {
    /// Auth host (default `https://ocapi-app.arlo.com`). Used for the
    /// MFA flow and session validation.
    pub auth_host: String,
    /// Device API host (default `https://myapi.arlo.com`). Used for
    /// device discovery, streaming control, modes, and the SSE bus.
    pub api_host: String,
}

impl Default for ArloEndpoints {
    fn default() -> Self {
        Self {
            auth_host: ARLO_AUTH_HOST.to_string(),
            api_host: ARLO_API_HOST.to_string(),
        }
    }
}

/// True for an `https://` base, or plain `http://` to a loopback host
/// (a mockito server in tests). Anything else would carry the bearer
/// token in cleartext.
fn is_secure_base(url: &str) -> bool {
    let Ok(u) = url::Url::parse(url) else {
        return false;
    };
    match u.scheme() {
        "https" => true,
        "http" => match u.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            None => false,
        },
        _ => false,
    }
}

impl ArloEndpoints {
    /// Logs at WARN for every host that is not `https://` (loopback
    /// `http://` excepted): the client attaches the session token to
    /// requests on these hosts, so a cleartext override leaks it.
    pub(crate) fn warn_if_insecure(&self) {
        for (name, host) in [("auth_host", &self.auth_host), ("api_host", &self.api_host)] {
            if !is_secure_base(host) {
                tracing::warn!(
                    endpoint = name,
                    host = %crate::models::redact::redact_userinfo(host),
                    "endpoint override is not https; the session token would travel in cleartext"
                );
            }
        }
    }

    /// Convenience for unit tests: point both hosts at the same base
    /// URL (typically a mockito server). Trailing slashes are stripped
    /// because every callsite already prefixes its path with `/`.
    /// Accepts `http://`; production code should never call this.
    pub fn testing(base_url: impl Into<String>) -> Self {
        let base = base_url.into();
        let trimmed = base.trim_end_matches('/').to_string();
        Self {
            auth_host: trimmed.clone(),
            api_host: trimmed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_production_hosts() {
        let e = ArloEndpoints::default();
        assert_eq!(e.auth_host, "https://ocapi-app.arlo.com");
        assert_eq!(e.api_host, "https://myapi.arlo.com");
    }

    #[test]
    fn testing_collapses_both_hosts_to_base_url() {
        let e = ArloEndpoints::testing("http://127.0.0.1:1234");
        assert_eq!(e.auth_host, "http://127.0.0.1:1234");
        assert_eq!(e.api_host, "http://127.0.0.1:1234");
    }

    #[test]
    fn testing_strips_trailing_slash() {
        let e = ArloEndpoints::testing("http://localhost:9999/");
        assert_eq!(e.auth_host, "http://localhost:9999");
        assert_eq!(e.api_host, "http://localhost:9999");
    }

    #[test]
    fn is_secure_base_accepts_https_and_loopback_http_only() {
        assert!(is_secure_base("https://ocapi-app.arlo.com"));
        assert!(is_secure_base("http://127.0.0.1:1234"));
        assert!(is_secure_base("http://[::1]:1234"));
        assert!(is_secure_base("http://localhost:9999"));
        assert!(!is_secure_base("http://myapi.arlo.com"));
        assert!(!is_secure_base("http://10.0.0.5"));
        assert!(!is_secure_base("ftp://127.0.0.1"));
        assert!(!is_secure_base("not a url"));
    }
}
