//! `authenticate*` orchestration: cached-session reuse, the trusted-browser
//! fast path, factor selection, OTP hand-off through an `MfaHandler`, and the
//! post-MFA continuation chain shared with the push flow.

use crate::client::ArloClient;
use crate::error::ArloError;
use crate::models::auth::*;
use tracing::{debug, info, instrument, warn};

impl ArloClient {
    /// High-level automated authentication state machine orchestrator.
    /// This resolves the cache session if it exists, triggers login automatically using the config,
    /// pulls dynamic 2FA factors, and can independently resolve IMAP OTP codes.
    /// Returns `AuthResult::Success` if a session is actively verified.
    /// Returns `AuthResult::MfaRequired` if manual OTP entry is demanded.
    #[instrument(skip(self, config))]
    pub async fn authenticate(
        &mut self,
        config: &crate::config::ArloConfig,
    ) -> Result<AuthResult, ArloError> {
        // 1. Silent Cached Session Verification
        if self.auth.has_token() {
            if self.validate_session_v3().await.is_ok() {
                // The underlying cache token successfully unlocked the active hub session.
                return Ok(AuthResult::Success);
            } else {
                // Token expired or invalidated downstream. Delete it.
                warn!("Cached token failed v3 session validation. Re-authenticating.");
                self.auth.clear_token();
            }
        }

        // 2. Extract Base Credentials
        let creds = config.credentials.as_ref().ok_or_else(|| {
            ArloError::AuthError("Missing [credentials] block in TOML configuration".to_string())
        })?;
        let email = creds.email.as_ref().ok_or_else(|| {
            ArloError::AuthError("Missing 'email' in configuration credentials".to_string())
        })?;
        let password = creds.password.as_ref().ok_or_else(|| {
            ArloError::AuthError("Missing 'password' in configuration credentials".to_string())
        })?;

        // 3. Initiate Standard Login Target
        let login_data = self.login(email, password).await?;
        if login_data.auth_completed == Some(true) {
            info!("Arlo reports authentication complete without a second factor");
            self.complete_session(None).await?;
            return Ok(AuthResult::Success);
        }

        // 3b. Trusted-browser fast path: once a previous session paired
        //     this device_id + cookie jar, `getFactorId` hands back a
        //     BROWSER factor and `startAuth` on it yields a full token
        //     with no OTP at all.
        if self.try_trusted_browser_login().await? {
            return Ok(AuthResult::Success);
        }

        // 4. Factor Resolution Targeting
        let factors = self.get_factors().await?;
        if factors.is_empty() {
            return Err(ArloError::AuthError(
                "No 2FA factors found for this account".to_string(),
            ));
        }

        let preferred = config
            .mfa
            .as_ref()
            .and_then(|m| m.preferred_method.as_deref())
            .unwrap_or("EMAIL");

        let selected_factor = factors
            .into_iter()
            .find(|f| f.factor_type.eq_ignore_ascii_case(preferred))
            .ok_or_else(|| {
                ArloError::AuthError(format!(
                    "Preferred 2FA method '{}' is not registered on the account",
                    preferred
                ))
            })?;

        // 5. Trigger MFA Challenge Dispatch
        let factor_auth_code = self.start_auth(&selected_factor.factor_id).await?;

        // 6. Manual User Involvement Necessary. Pause execution by returning Context Struct.
        Ok(AuthResult::MfaRequired {
            factor_id: selected_factor.factor_id.clone(),
            factor_auth_code,
            provider: selected_factor.factor_type.clone(),
        })
    }

    /// Drives the full MFA flow with a pluggable [`MfaHandler`].
    ///
    /// [`MfaHandler`]: crate::client::mfa::MfaHandler
    /// [`MfaHandler::prepare`]: crate::client::mfa::MfaHandler::prepare
    /// [`MfaHandler::provide_otp`]: crate::client::mfa::MfaHandler::provide_otp
    ///
    /// Fully end-to-end: captures any pre-dispatch state via
    /// [`MfaHandler::prepare`], runs [`Self::authenticate`] to trigger the
    /// OTP, retrieves the OTP via [`MfaHandler::provide_otp`], and
    /// finalises the session with [`Self::submit_mfa`]. Returns
    /// [`AuthResult::Success`] when the cached session is already valid
    /// (no MFA needed) or once MFA completes successfully.
    #[instrument(skip(self, config, handler))]
    pub async fn authenticate_with_handler<H: crate::client::mfa::MfaHandler>(
        &mut self,
        config: &crate::config::ArloConfig,
        mut handler: H,
    ) -> Result<AuthResult, ArloError> {
        // Phase 1: let the handler establish any pre-dispatch baseline.
        info!("Preparing MFA handler before OTP dispatch");
        handler.prepare().await?;

        // Phase 2: run the state machine to trigger the OTP dispatch.
        let res = self.authenticate(config).await?;
        let challenge = match crate::client::mfa::MfaChallenge::from_auth_result(&res) {
            Some(c) => c,
            None => return Ok(AuthResult::Success),
        };

        // Phase 3: handler retrieves the OTP, we forward it to Arlo.
        info!(provider = %challenge.provider, "Awaiting OTP from MFA handler");
        let otp = handler.provide_otp(&challenge).await?;
        self.submit_mfa(&challenge.factor_auth_code, &otp).await?;
        Ok(AuthResult::Success)
    }

    /// Backwards-compatible shorthand: drives the MFA flow with the IMAP
    /// handler configured in `[mfa.imap]`. New code should call
    /// [`Self::authenticate_with_handler`] with an explicit
    /// [`crate::client::mfa::ImapMfaHandler`].
    #[instrument(skip(self, config))]
    pub async fn authenticate_with_imap(
        &mut self,
        config: &crate::config::ArloConfig,
    ) -> Result<AuthResult, ArloError> {
        let imap = config
            .mfa
            .as_ref()
            .and_then(|m| m.imap.as_ref())
            .ok_or_else(|| ArloError::AuthError("Missing [mfa.imap] configuration block".into()))?
            .clone();
        let handler = crate::client::mfa::ImapMfaHandler::new(imap);
        self.authenticate_with_handler(config, handler).await
    }

    /// Primary Continuation Function: Executed when manual interaction is requested and fulfilled.
    /// This seamlessly runs the full backend REST validation chain required to actually load the Dashboard.
    pub async fn submit_mfa(&mut self, factor_auth_code: &str, otp: &str) -> Result<(), ArloError> {
        let data = self.finish_auth(factor_auth_code, otp).await?;
        self.complete_session(data.browser_auth_code.as_deref())
            .await
    }

    /// The trusted-browser fast path (reference client, 0.8.0.15+):
    /// `POST /api/getFactorId {factorType:"BROWSER", factorData:"", userId}`
    /// succeeds only when Arlo recognises this `device_id` + cookie jar
    /// from an earlier pairing; its `factorId` then goes to
    /// `POST /api/startAuth {factorId, factorType:"BROWSER", userId}`,
    /// whose response already carries the final token. Returns
    /// `Ok(false)` — with the reason logged — whenever the browser is not
    /// trusted, so the caller continues with the OTP ceremony.
    async fn try_trusted_browser_login(&mut self) -> Result<bool, ArloError> {
        let Some(user_id) = self.auth.user_id.clone() else {
            return Ok(false);
        };
        let factor_id = match self.get_factor_id().await {
            Ok(id) => id,
            Err(e) => {
                debug!(error = %e, "Browser not trusted by Arlo; running the OTP ceremony");
                return Ok(false);
            }
        };
        if let Err(e) = self.start_auth_trusted(&factor_id, &user_id).await {
            warn!(error = %e, "Trusted-browser startAuth rejected; falling back to the OTP ceremony");
            return Ok(false);
        }
        info!("Trusted browser accepted by Arlo — no OTP required");
        self.complete_session(None).await?;
        Ok(true)
    }

    /// Post-`finishAuth` continuation chain shared by every MFA path
    /// (OTP submit, push-approval polling and the trusted fast path):
    /// token validation, the "trust this browser" pairing when a
    /// `browserAuthCode` is available, the mandatory V3 session
    /// validation, the trailing telemetry call, and a cache write so the
    /// cookies Arlo set during pairing are persisted with the token.
    ///
    /// `pairing_code` is the `browserAuthCode` an approved `finishAuth`
    /// returned (`None` when Arlo sent none, or when the browser is
    /// already trusted). Pairing failures are logged, not fatal.
    pub(super) async fn complete_session(
        &mut self,
        pairing_code: Option<&str>,
    ) -> Result<(), ArloError> {
        self.validate_access_token().await?;
        if let Some(code) = pairing_code {
            match self.start_pairing_factor(code).await {
                Ok(()) => info!("Browser paired with Arlo; future logins can skip the OTP"),
                Err(e) => {
                    warn!(error = %e, "startPairingFactor failed; the next login will need an OTP")
                }
            }
        } else {
            debug!("No browserAuthCode to pair with; pairing skipped");
        }
        self.validate_session_v3().await?;
        let _ = self.device_support().await; // Secondary check to complete validation emulation
        self.persist_session().await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::auth::test_support::*;
    use crate::client::test_helpers::{
        authenticated_mocked_client, mocked_client, parse_body_json,
    };
    use crate::client::transport::test_support::MockTransport;
    use crate::error::ArloError;
    use crate::models::auth::AuthResult;
    use reqwest::Method;
    use std::sync::Arc;

    #[tokio::test]
    async fn authenticate_returns_success_when_cached_token_valid() {
        // session_v3 succeeds → cached path returns Success without
        // touching login/get_factors/start_auth.
        let mock = Arc::new(MockTransport::new());
        mock.queue_get(r#"{"meta":{"code":200},"data":{"userId":"U1","token":"cached"}}"#);

        let mut client = authenticated_mocked_client(Arc::clone(&mock));
        let cfg = crate::config::ArloConfig {
            credentials: None,
            mfa: None,
            client: None,
            streaming: None,
        };
        let res = client.authenticate(&cfg).await.unwrap();
        assert!(matches!(res, AuthResult::Success));
        // Only one call (the v3 validation) — no login.
        assert_eq!(mock.calls().len(), 1);
    }

    #[tokio::test]
    async fn authenticate_runs_full_login_when_no_cached_token() {
        // No token → expects login → get_factors → start_auth → MfaRequired.
        let mock = Arc::new(MockTransport::new());
        // 1. login (POST: OPTIONS + body)
        mock.queue_post(auth_response("preliminary", "U1"));
        // getFactorId (POST: OPTIONS + body) — browser not trusted yet.
        mock.queue_post(r#"{"meta":{"code":400,"error":9204}}"#);
        // 2. get_factors (GET)
        mock.queue_get(
            r#"{"meta":{"code":200},"data":{"items":[
                {"factorId":"F1","factorType":"EMAIL","factorRole":"PRIMARY"}
            ]}}"#,
        );
        // 3. start_auth (POST: OPTIONS + body)
        mock.queue_post(r#"{"meta":{"code":200},"data":{"factorAuthCode":"FAC-9"}}"#);

        let mut client = mocked_client(mock);
        let cfg = crate::config::ArloConfig {
            credentials: Some(crate::config::CredentialsConfig {
                email: Some("u@example.com".into()),
                password: Some("p".into()),
            }),
            mfa: Some(crate::config::MfaConfig {
                preferred_method: Some("EMAIL".into()),
                imap: None,
            }),
            client: None,
            streaming: None,
        };

        let res = client.authenticate(&cfg).await.unwrap();
        match res {
            AuthResult::MfaRequired {
                factor_id,
                factor_auth_code,
                provider,
            } => {
                assert_eq!(factor_id, "F1");
                assert_eq!(factor_auth_code, "FAC-9");
                assert_eq!(provider, "EMAIL");
            }
            other => panic!("expected MfaRequired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_errors_when_preferred_factor_not_available() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(auth_response("preliminary", "U1"));
        // getFactorId (POST: OPTIONS + body) — browser not trusted yet.
        mock.queue_post(r#"{"meta":{"code":400,"error":9204}}"#);
        mock.queue_get(
            r#"{"meta":{"code":200},"data":{"items":[
                {"factorId":"F1","factorType":"PUSH","factorRole":"PRIMARY"}
            ]}}"#,
        );

        let mut client = mocked_client(mock);
        let cfg = crate::config::ArloConfig {
            credentials: Some(crate::config::CredentialsConfig {
                email: Some("u".into()),
                password: Some("p".into()),
            }),
            mfa: Some(crate::config::MfaConfig {
                preferred_method: Some("EMAIL".into()), // only PUSH is registered
                imap: None,
            }),
            client: None,
            streaming: None,
        };
        assert!(matches!(
            client.authenticate(&cfg).await,
            Err(ArloError::AuthError(_))
        ));
    }

    #[tokio::test]
    async fn authenticate_errors_when_no_factors_registered() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(auth_response("preliminary", "U1"));
        // getFactorId (POST: OPTIONS + body) — browser not trusted yet.
        mock.queue_post(r#"{"meta":{"code":400,"error":9204}}"#);
        mock.queue_get(r#"{"meta":{"code":200},"data":{"items":[]}}"#);

        let mut client = mocked_client(mock);
        let cfg = crate::config::ArloConfig {
            credentials: Some(crate::config::CredentialsConfig {
                email: Some("u".into()),
                password: Some("p".into()),
            }),
            mfa: None,
            client: None,
            streaming: None,
        };
        assert!(matches!(
            client.authenticate(&cfg).await,
            Err(ArloError::AuthError(_))
        ));
    }

    #[tokio::test]
    async fn authenticate_errors_when_credentials_missing() {
        let mock = Arc::new(MockTransport::new());
        let mut client = mocked_client(mock);
        let cfg = crate::config::ArloConfig {
            credentials: None,
            mfa: None,
            client: None,
            streaming: None,
        };
        assert!(matches!(
            client.authenticate(&cfg).await,
            Err(ArloError::AuthError(_))
        ));
    }

    #[tokio::test]
    async fn authenticate_with_handler_runs_full_flow_with_static_otp() {
        // login → factors → start_auth → finish_auth → validate_access_token
        // → start_pairing_factor → validate_session_v3 → device_support_v2.
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(auth_response("preliminary", "U1")); // login
        mock.queue_post(r#"{"meta":{"code":400,"error":9204}}"#); // getFactorId: untrusted
        mock.queue_get(
            r#"{"meta":{"code":200},"data":{"items":[
                {"factorId":"F1","factorType":"EMAIL","factorRole":"PRIMARY"}
            ]}}"#,
        );
        mock.queue_post(r#"{"meta":{"code":200},"data":{"factorAuthCode":"FAC-9"}}"#); // start_auth
        mock.queue_post(
            r#"{"meta":{"code":200},"data":{"token":"final","userId":"U1","authenticated":1,"browserAuthCode":"BAC-1"}}"#,
        ); // finish_auth (with the pairing code)
        mock.queue_get("{}"); // validate_access_token
        mock.queue_post("{}"); // start_pairing_factor (with BAC-1)
        mock.queue_get(r#"{"meta":{"code":200},"data":{"userId":"U1","token":"final"}}"#); // validate_session_v3
        mock.queue_get(r#"{"meta":{"code":200},"data":{}}"#); // device_support_v2

        let mut client = mocked_client(mock);
        let cfg = crate::config::ArloConfig {
            credentials: Some(crate::config::CredentialsConfig {
                email: Some("u".into()),
                password: Some("p".into()),
            }),
            mfa: Some(crate::config::MfaConfig {
                preferred_method: Some("EMAIL".into()),
                imap: None,
            }),
            client: None,
            streaming: None,
        };
        let handler = crate::client::mfa::StaticOtpHandler::new("123456");
        let res = client
            .authenticate_with_handler(&cfg, handler)
            .await
            .unwrap();
        assert!(matches!(res, AuthResult::Success));
        assert!(client.is_authenticated());
    }

    #[tokio::test]
    async fn authenticate_skips_otp_when_browser_is_trusted() {
        // login → getFactorId 200 → startAuth(BROWSER) 200 with token →
        // validate_access_token → validate_session_v3 → device_support.
        // No getFactors, no OTP, no pairing.
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(auth_response("preliminary", "U1")); // login
        mock.queue_post(r#"{"meta":{"code":200},"data":{"factorId":"BF-1"}}"#); // getFactorId
        mock.queue_post(r#"{"meta":{"code":200},"data":{"token":"trusted","userId":"U1"}}"#); // startAuth
        mock.queue_get("{}"); // validate_access_token
        mock.queue_get(r#"{"meta":{"code":200},"data":{"userId":"U1","token":"trusted"}}"#); // session/v3
        mock.queue_get(r#"{"meta":{"code":200},"data":{}}"#); // device_support

        let mut client = mocked_client(Arc::clone(&mock));
        let cfg = crate::config::ArloConfig {
            credentials: Some(crate::config::CredentialsConfig {
                email: Some("u".into()),
                password: Some("p".into()),
            }),
            mfa: None,
            client: None,
            streaming: None,
        };
        let res = client.authenticate(&cfg).await.unwrap();
        assert!(matches!(res, AuthResult::Success));
        assert_eq!(client.auth.token(), Some("trusted"));

        let calls = mock.calls();
        assert!(calls.iter().any(|c| c.url.ends_with("/api/getFactorId")));
        assert!(!calls.iter().any(|c| c.url.contains("/api/getFactors")));
        let start = calls
            .iter()
            .find(|c| c.url.ends_with("/api/startAuth") && c.method == Method::POST)
            .expect("startAuth sent");
        let body = parse_body_json(start.body.as_ref());
        assert_eq!(body["factorType"], "BROWSER");
        assert_eq!(body["factorId"], "BF-1");
        assert!(mock.responses_drained());
    }

    #[tokio::test]
    async fn authenticate_with_imap_errors_when_imap_block_missing() {
        let mock = Arc::new(MockTransport::new());
        let mut client = mocked_client(mock);
        let cfg = crate::config::ArloConfig {
            credentials: None,
            mfa: Some(crate::config::MfaConfig {
                preferred_method: None,
                imap: None,
            }),
            client: None,
            streaming: None,
        };
        assert!(matches!(
            client.authenticate_with_imap(&cfg).await,
            Err(ArloError::AuthError(_))
        ));
    }
}
