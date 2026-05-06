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

impl ArloEndpoints {
    /// Convenience for unit tests: point both hosts at the same base
    /// URL (typically a mockito server). Trailing slashes are stripped
    /// because every callsite already prefixes its path with `/`.
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
}
