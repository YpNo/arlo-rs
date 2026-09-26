//! The PUSH-factor ceremony: `startAuth` with an empty `factorType` dispatches
//! the account's primary factor, then `finishAuth` is polled until the user
//! approves in the Arlo app.

use crate::client::ArloClient;
use crate::endpoints::{AUTH_FINISH_AUTH, AUTH_START_AUTH};
use crate::error::ArloError;
use crate::models::auth::{
    AuthResponseData, AuthResult, BaseResponse, FinishAuthPushRequest, StartAuthData,
    StartAuthUserRequest,
};
use crate::models::error_codes::{ErrorAction, classify_arlo_error};
use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use std::time::{Duration, Instant};
use tracing::{info, instrument, warn};

/// Outcome of a single push `finishAuth` poll.
enum PushOutcome {
    /// User hasn't approved yet — keep polling.
    Pending,
    /// Approved; carries the finalized session payload (token already
    /// cached) including the `browserAuthCode` used for pairing.
    Approved(AuthResponseData),
}

impl ArloClient {
    /// Default cadence between `finishAuth` polls while waiting for the
    /// user to approve the prompt in their Arlo mobile app. Matches the
    /// Arlo web client's observed ~5 s cadence.
    pub const DEFAULT_PUSH_POLL_INTERVAL: Duration = Duration::from_secs(5);

    /// Default ceiling on the whole push-approval wait. Matches Arlo's
    /// own `MFA_Config.timeout.PUSH` (120 s).
    pub const DEFAULT_PUSH_TIMEOUT: Duration = Duration::from_secs(120);

    /// Drives the MFA flow for the **PUSH** factor.
    ///
    /// Reproduces the Arlo web client's push ceremony (verified against
    /// a live HAR capture):
    ///
    /// 1. `login` → preliminary token + `userId`.
    /// 2. `POST /api/startAuth {factorType:"", userId}` — Arlo dispatches
    ///    the account's PRIMARY second factor and returns its PingOne
    ///    push `factorAuthCode` plus the factor list.
    /// 3. Poll `POST /api/finishAuth {factorAuthCode, isBrowserTrusted}`
    ///    (**no `otp`**). Every poll is HTTP 200; the body carries the
    ///    state in `meta`: `code:400 error:9233` ("Authentication is not
    ///    finished yet") ⇒ still pending; `code:200` + `data.token` ⇒
    ///    approved (and `data.browserAuthCode` is the value to pair
    ///    with). Polls every `poll_interval` until approval or
    ///    `timeout` ([`ArloError::Timeout`]).
    /// 4. Shared continuation chain, pairing with `browserAuthCode`.
    ///
    /// Requires PUSH to be the account's PRIMARY factor (empty
    /// `factorType` dispatches the primary one); errors otherwise.
    #[instrument(skip(self, config))]
    pub async fn authenticate_with_push(
        &mut self,
        config: &crate::config::ArloConfig,
        poll_interval: Duration,
        timeout: Duration,
    ) -> Result<AuthResult, ArloError> {
        // 1. Reuse a still-valid cached session; only Arlo's own verdict
        //    discards it (see `authenticate`).
        if self.auth.has_token() {
            match self.validate_session_v3().await {
                Ok(_) => return Ok(AuthResult::Success),
                Err(e) if e.action() == ErrorAction::Reauth => {
                    warn!(error = %e, "Cached token rejected by Arlo; re-authenticating via push");
                    self.auth.clear_token();
                }
                Err(e) => return Err(e),
            }
        }
        let poll_interval = poll_interval.max(Self::MIN_POLL_INTERVAL);

        // 2. Credentials → preliminary token + userId.
        let creds = config.credentials.as_ref().ok_or_else(|| {
            ArloError::AuthError("Missing [credentials] block in TOML configuration".into())
        })?;
        let email = creds
            .email
            .as_ref()
            .ok_or_else(|| ArloError::AuthError("Missing 'email' in credentials".into()))?;
        let password = creds
            .password
            .as_ref()
            .ok_or_else(|| ArloError::AuthError("Missing 'password' in credentials".into()))?;
        let login_data = self.login(email, password.expose_secret()).await?;
        if login_data.auth_completed == Some(true) {
            info!("Arlo reports authentication complete without a second factor");
            self.complete_session(None).await?;
            return Ok(AuthResult::Success);
        }
        if self.try_trusted_browser_login().await? {
            return Ok(AuthResult::Success);
        }
        let user_id = self
            .auth
            .user_id
            .clone()
            .ok_or_else(|| ArloError::AuthError("login did not return a userId".into()))?;

        // 3. startAuth dispatches the push and returns its factorAuthCode.
        let factor_auth_code = self.start_auth_push(&user_id).await?;

        // 4. Poll finishAuth until the user taps Approve on their phone.
        info!("Awaiting push approval in the Arlo mobile app");
        // `checked_add`: `Duration::MAX` is the usual "no deadline" idiom
        // and plain `+` panics on it.
        let deadline = Instant::now().checked_add(timeout);
        let approved = loop {
            match self.finish_auth_push(&factor_auth_code).await? {
                PushOutcome::Approved(data) => break data,
                PushOutcome::Pending => {
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Err(ArloError::Timeout(format!(
                            "push approval not granted within {timeout:?}"
                        )));
                    }
                    tokio::time::sleep(poll_interval).await;
                }
            }
        };

        // 5. Continuation — pair with the browserAuthCode the approved
        //    finishAuth handed back (the push factorAuthCode is not a
        //    pairing code).
        self.complete_session(approved.browser_auth_code.as_deref())
            .await?;
        Ok(AuthResult::Success)
    }

    /// Floor for `poll_interval`: Arlo rate-limits `finishAuth`.
    const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);

    /// `POST /api/startAuth {factorType:"", userId}` → the push
    /// `factorAuthCode`. An empty `factorType` makes Arlo dispatch the
    /// account's PRIMARY factor; errors if no PUSH factor is registered.
    #[instrument(skip(self))]
    async fn start_auth_push(&mut self, user_id: &str) -> Result<SecretString, ArloError> {
        let url = format!("{}{}", self.endpoints.auth_host, AUTH_START_AUTH);
        let payload = StartAuthUserRequest {
            factor_type: String::new(),
            user_id: user_id.to_string(),
        };
        let body = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;
        let resp: BaseResponse<StartAuthData> = serde_json::from_str(&body)?;
        if !resp.meta.is_success() {
            return Err(resp.meta.into_error("startAuth failed"));
        }
        let data = resp
            .data
            .ok_or_else(|| ArloError::AuthError("startAuth returned no data".into()))?;
        if !data
            .factors
            .iter()
            .any(|f| f.factor_type.eq_ignore_ascii_case("PUSH"))
        {
            return Err(ArloError::AuthError(
                "No PUSH factor registered on this Arlo account".into(),
            ));
        }
        Ok(data.factor_auth_code)
    }

    /// One push `finishAuth` poll (no `otp`). Maps Arlo's
    /// HTTP-200-with-`meta` envelope to a tri-state: approved (token
    /// cached), still pending (`meta.error == 9233`), or a hard error.
    #[instrument(skip(self, factor_auth_code))]
    async fn finish_auth_push(
        &mut self,
        factor_auth_code: &SecretString,
    ) -> Result<PushOutcome, ArloError> {
        let url = format!("{}{}", self.endpoints.auth_host, AUTH_FINISH_AUTH);
        let payload = FinishAuthPushRequest {
            factor_auth_code: factor_auth_code.expose_secret().to_string(),
            is_browser_trusted: true,
        };
        let body = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;
        let resp: BaseResponse<AuthResponseData> = serde_json::from_str(&body)?;

        if resp.meta.code == 200 {
            let data = resp
                .data
                .ok_or_else(|| ArloError::AuthError("finishAuth 200 but no data".into()))?;
            // Cache the finalized token, mirroring finish_auth().
            self.auth.set_token(data.token.clone());
            self.persist_session().await;
            return Ok(PushOutcome::Approved(data));
        }
        if resp
            .meta
            .error
            .is_some_and(|e| classify_arlo_error(e) == ErrorAction::AuthPending)
        {
            return Ok(PushOutcome::Pending);
        }
        Err(resp.meta.into_error("finishAuth failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::auth::test_support::*;
    use crate::client::test_helpers::{mocked_client, parse_body_json};
    use crate::client::transport::test_support::MockTransport;
    use crate::error::ArloError;
    use crate::models::auth::AuthResult;
    use std::sync::Arc;

    fn push_cfg() -> crate::config::ArloConfig {
        crate::config::ArloConfig {
            credentials: Some(crate::config::CredentialsConfig {
                email: Some("u".into()),
                password: Some("p".into()),
            }),
            mfa: None,
            client: None,
            streaming: None,
        }
    }

    /// `startAuth` success body — PUSH is the PRIMARY factor.
    fn start_auth_push_ok() -> &'static str {
        r#"{"meta":{"code":200},"data":{"_type":"MultiFactorAuthCode",
            "factorAuthCode":"FAC-P","authCompleted":false,
            "factors":[
              {"_type":"SecondFactor","factorId":"FP","factorType":"PUSH","factorRole":"PRIMARY"},
              {"_type":"SecondFactor","factorId":"FE","factorType":"EMAIL","factorRole":"SECONDARY"}
            ]}}"#
    }

    // Real Arlo pending body: HTTP 200, meta.code 400, error 9233.
    const FINISH_PENDING: &str =
        r#"{"meta":{"code":400,"error":9233,"message":"Authentication is not finished yet"}}"#;

    // Real Arlo approved body: meta.code 200 + data with token + browserAuthCode.
    const FINISH_APPROVED: &str = r#"{"meta":{"code":200},"data":{"_type":"AccessTokenV2",
        "token":"final","userId":"U1","authenticated":1,"authCompleted":true,
        "browserAuthCode":"BAC-1"}}"#;

    #[tokio::test(start_paused = true)]
    async fn authenticate_with_push_polls_finish_auth_until_approved() {
        // login → startAuth(push) → finishAuth(pending) →
        // finishAuth(approved) → continuation chain.
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(auth_response("preliminary", "U1")); // login
        mock.queue_post(r#"{"meta":{"code":400,"error":9204}}"#); // getFactorId: not trusted
        mock.queue_post(start_auth_push_ok()); // startAuth
        mock.queue_post(FINISH_PENDING); // finishAuth #1: pending
        mock.queue_post(FINISH_PENDING); // finishAuth #2: pending
        mock.queue_post(FINISH_APPROVED); // finishAuth #3: approved
        mock.queue_get("{}"); // validate_access_token
        mock.queue_post("{}"); // start_pairing_factor (pairs with BAC-1)
        mock.queue_get(r#"{"meta":{"code":200},"data":{"userId":"U1","token":"final"}}"#); // session_v3
        mock.queue_get(r#"{"meta":{"code":200},"data":{}}"#); // device_support_v2

        let mut client = mocked_client(mock.clone());
        let res = client
            .authenticate_with_push(
                &push_cfg(),
                Duration::from_millis(1),
                Duration::from_secs(5),
            )
            .await
            .expect("push approval completes");

        assert!(matches!(res, AuthResult::Success));
        assert!(client.is_authenticated());

        // finishAuth must carry {factorAuthCode,isBrowserTrusted} and NO otp.
        let finish = mock
            .calls()
            .into_iter()
            .find(|c| c.url.contains("/api/finishAuth") && c.body.is_some())
            .expect("a finishAuth POST with a body was made");
        let body = parse_body_json(finish.body.as_ref());
        assert_eq!(body["factorAuthCode"], "FAC-P");
        assert_eq!(body["isBrowserTrusted"], true);
        assert!(
            body.get("otp").is_none(),
            "push finishAuth must not send otp"
        );
    }

    #[tokio::test]
    async fn authenticate_with_push_times_out_when_never_approved() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(auth_response("preliminary", "U1")); // login
        mock.queue_post(r#"{"meta":{"code":400,"error":9204}}"#); // getFactorId: not trusted
        mock.queue_post(start_auth_push_ok()); // startAuth
        mock.queue_post(FINISH_PENDING); // finishAuth: still pending

        let mut client = mocked_client(mock);
        // Zero timeout: the first pending response is already past the
        // deadline, so the loop bails without sleeping.
        let err = client
            .authenticate_with_push(
                &push_cfg(),
                Duration::from_millis(1),
                Duration::from_millis(0),
            )
            .await
            .expect_err("never approved → timeout");

        assert!(matches!(err, ArloError::Timeout(_)));
    }

    #[tokio::test]
    async fn authenticate_with_push_errors_when_no_push_factor_registered() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(auth_response("preliminary", "U1")); // login
        mock.queue_post(r#"{"meta":{"code":400,"error":9204}}"#); // getFactorId: not trusted
        mock.queue_post(
            r#"{"meta":{"code":200},"data":{"factorAuthCode":"FAC-E",
               "factors":[{"factorType":"EMAIL","factorRole":"PRIMARY"}]}}"#,
        ); // startAuth: only EMAIL

        let mut client = mocked_client(mock);
        let err = client
            .authenticate_with_push(
                &push_cfg(),
                Duration::from_millis(1),
                Duration::from_secs(5),
            )
            .await
            .expect_err("no PUSH factor → error");

        assert!(matches!(err, ArloError::AuthError(m) if m.contains("PUSH")));
    }
}

#[cfg(test)]
mod hazard_tests {
    use super::*;
    use crate::client::auth::test_support::*;
    use crate::client::test_helpers::mocked_client;
    use crate::client::transport::test_support::MockTransport;
    use crate::models::auth::AuthResult;
    use std::sync::Arc;

    fn push_cfg() -> crate::config::ArloConfig {
        crate::config::ArloConfig {
            credentials: Some(crate::config::CredentialsConfig {
                email: Some("u".into()),
                password: Some("p".into()),
            }),
            mfa: None,
            client: None,
            streaming: None,
        }
    }

    #[tokio::test]
    async fn push_flow_uses_the_trusted_browser_before_dispatching_a_push() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(auth_response("preliminary", "U1")); // login
        mock.queue_post(r#"{"meta":{"code":200},"data":{"factorId":"BF-1"}}"#); // getFactorId
        mock.queue_post(r#"{"meta":{"code":200},"data":{"token":"trusted","userId":"U1"}}"#); // startAuth(BROWSER)
        mock.queue_get("{}"); // validate_access_token
        mock.queue_get(r#"{"meta":{"code":200},"data":{"userId":"U1","token":"trusted"}}"#); // session/v3
        mock.queue_get(r#"{"meta":{"code":200},"data":{}}"#); // device_support
        let mut client = mocked_client(mock.clone());
        let res = client
            .authenticate_with_push(&push_cfg(), Duration::from_secs(1), Duration::MAX)
            .await
            .expect("trusted path completes");
        assert!(matches!(res, AuthResult::Success));
        assert!(
            !mock
                .calls()
                .iter()
                .any(|c| c.url.contains("/api/finishAuth")),
            "no push polled"
        );
        assert!(mock.responses_drained());
    }
}
