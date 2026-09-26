//! Pluggable Multi-Factor-Authentication (MFA) OTP source.
//!
//! Arlo's MFA flow is a two-step ceremony:
//!
//! 1. The library asks Arlo to dispatch an OTP via the user's preferred
//!    factor (email, SMS, push). Before triggering dispatch, any handler
//!    that needs to observe a *fresh* arrival (e.g. an IMAP poller) must
//!    capture a baseline of "what was already in the inbox".
//! 2. After dispatch, the handler retrieves the 6-digit OTP and returns
//!    it. The library forwards it to Arlo to finalize the session.
//!
//! [`MfaHandler`] models exactly this two-step lifecycle so the downstream
//! application can plug in any OTP source — an IMAP mailbox, a Slack bot,
//! a webhook, a CLI prompt, a static fixture in tests — without forking
//! the auth state machine.
//!
//! Two impls ship in the box:
//! - [`ImapMfaHandler`] polls the user's mailbox, parses the OTP from the
//!   Arlo email, and is the recommended option for headless servers.
//! - [`StdinMfaHandler`] prints the challenge details and reads the OTP
//!   from `stdin` — useful for local CLI tooling and `examples/simple.rs`.
//!
//! A trivial [`StaticOtpHandler`] is also exposed for testing; it returns a
//! pre-baked OTP without I/O.

use crate::client::auth_imap;
use crate::config::ImapConfig;
use crate::error::ArloError;
use crate::models::auth::AuthResult;
use std::collections::HashSet;
use std::io::{self, Write};

/// Context handed to [`MfaHandler::provide_otp`]. Mirrors the
/// [`AuthResult::MfaRequired`] payload but as a plain struct so handlers
/// don't have to pattern-match.
#[derive(Clone)]
pub struct MfaChallenge {
    /// Arlo factor identifier (UUID-ish).
    pub factor_id: String,
    /// Server-issued correlation token, echoed back to `finishAuth`.
    pub factor_auth_code: String,
    /// Factor type as Arlo reports it: `"EMAIL"`, `"SMS"`, `"PUSH"`, …
    pub provider: String,
}

impl std::fmt::Debug for MfaChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaChallenge")
            .field("factor_id", &self.factor_id)
            .field("factor_auth_code", &"[REDACTED]")
            .field("provider", &self.provider)
            .finish()
    }
}

impl MfaChallenge {
    pub(crate) fn from_auth_result(result: &AuthResult) -> Option<Self> {
        match result {
            AuthResult::MfaRequired {
                factor_id,
                factor_auth_code,
                provider,
            } => Some(Self {
                factor_id: factor_id.clone(),
                factor_auth_code: factor_auth_code.clone(),
                provider: provider.clone(),
            }),
            AuthResult::Success => None,
        }
    }
}

/// Implement this trait to plug a custom OTP source into the MFA flow.
///
/// Both methods are `async` and take `&mut self`, so handlers may carry
/// state between phases (e.g. the IMAP impl stashes its inbox baseline
/// in `prepare`).
#[allow(async_fn_in_trait)]
pub trait MfaHandler {
    /// Called *before* Arlo dispatches the OTP. Stash any baseline state
    /// here. Default impl is a no-op for handlers that don't need to
    /// observe pre-dispatch inbox state.
    async fn prepare(&mut self) -> Result<(), ArloError> {
        Ok(())
    }

    /// Called *after* Arlo has been asked to dispatch the OTP. Returns the
    /// 6-digit code (or the corresponding push-approval value) to forward
    /// to `finishAuth`.
    async fn provide_otp(&mut self, challenge: &MfaChallenge) -> Result<String, ArloError>;
}

// -----------------------------------------------------------------------
// ImapMfaHandler
// -----------------------------------------------------------------------

/// Polls the user's IMAP mailbox for the Arlo OTP email.
///
/// Captures a UNSEEN-baseline in `prepare()` so a stale Arlo email already
/// in the inbox can't shadow the freshly dispatched code. The actual
/// connection logic lives in [`crate::client::auth_imap`].
pub struct ImapMfaHandler {
    config: ImapConfig,
    baseline: Option<HashSet<u32>>,
}

impl ImapMfaHandler {
    /// Wraps an [`ImapConfig`] (host/credentials) into a handler.
    pub fn new(config: ImapConfig) -> Self {
        Self {
            config,
            baseline: None,
        }
    }
}

impl MfaHandler for ImapMfaHandler {
    async fn prepare(&mut self) -> Result<(), ArloError> {
        if !self.config.enabled.unwrap_or(false) {
            return Err(ArloError::AuthError(
                "IMAP MFA handler invoked but [mfa.imap].enabled is false".into(),
            ));
        }
        self.baseline = Some(auth_imap::get_baseline(&self.config).await?);
        Ok(())
    }

    async fn provide_otp(&mut self, _challenge: &MfaChallenge) -> Result<String, ArloError> {
        let baseline = self.baseline.take().ok_or_else(|| {
            ArloError::AuthError("ImapMfaHandler::provide_otp called before prepare()".into())
        })?;
        auth_imap::fetch_otp(&self.config, baseline).await
    }
}

// -----------------------------------------------------------------------
// StdinMfaHandler
// -----------------------------------------------------------------------

/// Interactive CLI handler. Prints the challenge details on stdout and
/// reads the OTP from stdin. Use only in interactive command-line tools.
#[derive(Debug, Default)]
pub struct StdinMfaHandler;

impl StdinMfaHandler {
    /// Constructs a fresh stdin-prompt handler. Equivalent to `default()`.
    pub fn new() -> Self {
        Self
    }
}

impl MfaHandler for StdinMfaHandler {
    async fn provide_otp(&mut self, challenge: &MfaChallenge) -> Result<String, ArloError> {
        let provider = challenge.provider.clone();
        // stdio is intentionally synchronous — interactive prompts have no
        // benefit from async, and `tokio::io::stdin` introduces subtle
        // line-buffering surprises.
        tokio::task::spawn_blocking(move || {
            println!("\nMFA challenge dispatched via {provider}.");
            print!("Enter the OTP: ");
            io::stdout().flush().ok();
            let mut buf = String::new();
            io::stdin()
                .read_line(&mut buf)
                .map_err(|e| ArloError::AuthError(format!("Failed to read OTP from stdin: {e}")))?;
            Ok(buf.trim().to_string())
        })
        .await
        .map_err(|e| ArloError::AuthError(format!("OTP prompt task failed: {e}")))?
    }
}

// -----------------------------------------------------------------------
// StaticOtpHandler (test fixture)
// -----------------------------------------------------------------------

/// Returns a pre-set OTP without performing I/O. Intended for tests.
#[derive(Debug, Clone)]
pub struct StaticOtpHandler {
    otp: String,
    prepared: bool,
}

impl StaticOtpHandler {
    /// Construct a handler that always returns `otp` from `provide_otp`.
    pub fn new(otp: impl Into<String>) -> Self {
        Self {
            otp: otp.into(),
            prepared: false,
        }
    }

    /// True after `prepare()` has been called at least once. Useful in
    /// tests asserting the auth state machine respects the two-phase
    /// contract.
    pub fn was_prepared(&self) -> bool {
        self.prepared
    }
}

impl MfaHandler for StaticOtpHandler {
    async fn prepare(&mut self) -> Result<(), ArloError> {
        self.prepared = true;
        Ok(())
    }

    async fn provide_otp(&mut self, _challenge: &MfaChallenge) -> Result<String, ArloError> {
        Ok(self.otp.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_challenge() -> MfaChallenge {
        MfaChallenge {
            factor_id: "f-1".into(),
            factor_auth_code: "code-1".into(),
            provider: "EMAIL".into(),
        }
    }

    #[tokio::test]
    async fn static_handler_returns_seeded_otp() {
        let mut h = StaticOtpHandler::new("123456");
        h.prepare().await.unwrap();
        assert!(h.was_prepared());
        let otp = h.provide_otp(&dummy_challenge()).await.unwrap();
        assert_eq!(otp, "123456");
    }

    #[tokio::test]
    async fn imap_handler_errors_when_disabled() {
        let cfg = ImapConfig {
            enabled: Some(false),
            provider: Some("gmail".into()),
            host: None,
            port: None,
            username: Some("u".into()),
            password: Some("p".into()),
            delete_after_read: None,
        };
        let mut h = ImapMfaHandler::new(cfg);
        let err = h.prepare().await.unwrap_err();
        assert!(matches!(err, ArloError::AuthError(_)));
    }

    #[tokio::test]
    async fn imap_handler_errors_when_provide_called_before_prepare() {
        let cfg = ImapConfig {
            enabled: Some(true),
            provider: Some("gmail".into()),
            host: None,
            port: None,
            username: Some("u".into()),
            password: Some("p".into()),
            delete_after_read: None,
        };
        let mut h = ImapMfaHandler::new(cfg);
        let err = h.provide_otp(&dummy_challenge()).await.unwrap_err();
        assert!(matches!(err, ArloError::AuthError(_)));
    }

    #[test]
    fn challenge_from_auth_result_extracts_mfa_required() {
        let result = AuthResult::MfaRequired {
            factor_id: "f".into(),
            factor_auth_code: "fac".into(),
            provider: "EMAIL".into(),
        };
        let c = MfaChallenge::from_auth_result(&result).unwrap();
        assert_eq!(c.factor_id, "f");
        assert_eq!(c.factor_auth_code, "fac");
        assert_eq!(c.provider, "EMAIL");
    }

    #[test]
    fn challenge_from_auth_result_returns_none_on_success() {
        assert!(MfaChallenge::from_auth_result(&AuthResult::Success).is_none());
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn challenge_debug_redacts_factor_auth_code() {
        let c = MfaChallenge {
            factor_id: "F1".into(),
            factor_auth_code: "FAC-SECRET".into(),
            provider: "PUSH".into(),
        };
        let dbg = format!("{c:?}");
        assert!(
            dbg.contains("F1") && dbg.contains("PUSH") && !dbg.contains("FAC-SECRET"),
            "{dbg}"
        );
    }
}
