//! Legacy `login/v2` and the v3 `logout` (with its legacy fallback).

use crate::client::ArloClient;
use crate::endpoints::*;
use crate::error::ArloError;
use crate::models::auth::*;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use reqwest::Method;
use tracing::{instrument, warn};

impl ArloClient {
    /// Fallback login using the legacy V2 endpoint
    #[instrument(skip(self, email, password))]
    pub async fn login_v2(
        &mut self,
        email: &str,
        password: &str,
    ) -> Result<AuthResponseData, ArloError> {
        let url = format!("{}{}", self.endpoints.api_host, AUTH_LOGIN_V2);

        let b64_password = BASE64_STANDARD.encode(password.as_bytes());
        let payload = AuthRequest {
            email: email.to_string(),
            password: b64_password,
            language: "en".to_string(),
            env_source: "prod".to_string(),
        };

        let body_str = self
            .execute_request(Method::POST, &url, Some(&payload))
            .await?;
        let base_response: BaseResponse<AuthResponseData> = serde_json::from_str(&body_str)?;

        if base_response.meta.code != 200 {
            return Err(ArloError::AuthError(
                base_response
                    .meta
                    .message
                    .unwrap_or_else(|| "Failed V2 login".to_string()),
            ));
        }

        let auth_data = base_response.data.ok_or_else(|| {
            ArloError::AuthError("No auth data returned from V2 server".to_string())
        })?;

        self.auth.set_token(auth_data.token.clone());
        self.auth.user_id = Some(auth_data.user_id.clone());
        self.persist_session().await;

        Ok(auth_data)
    }

    /// Log the current active session out securely.
    ///
    /// V3 logout (verified against the May-2026 portal HAR):
    /// `DELETE /hmsweb/user/{user_id}/client/smart/devices/logout
    ///         ?clientId={x-user-device-id}&eventId=FE!{uuid}&time={ms}`
    ///
    /// The `clientId` query parameter equals the `x-user-device-id`
    /// header value — i.e. our locally-generated `AuthManager::device_id`.
    /// `eventId` and `time` are the same telemetry params other v3 GETs
    /// (`validate_session_v3`, `device_support`) emit.
    ///
    /// Falls back to the legacy `PUT /hmsweb/logout` when:
    /// - the client has no `user_id` yet (rare, only if invoked before
    ///   any auth call), or
    /// - the per-instance `api_version` is pinned to [`ApiVersion::Legacy`](crate::config::ApiVersion::Legacy).
    ///
    /// The local session state (token, user_id) is wiped **regardless**
    /// of the HTTP outcome — a network-level logout failure must not
    /// leave the client believing it's still logged in.
    #[instrument(skip(self))]
    pub async fn logout(&mut self) -> Result<(), ArloError> {
        let api_version = self.api_version.get();
        let use_legacy =
            api_version == crate::config::ApiVersion::Legacy || self.auth.user_id.is_none();

        let logout_attempt = if use_legacy {
            let url = format!("{}{}", self.endpoints.api_host, AUTH_LOGOUT);
            self.execute_request::<()>(Method::PUT, &url, None).await
        } else {
            // V3 path — `unwrap()` of user_id is safe because `use_legacy`
            // is true whenever it's `None`.
            let uid = self
                .auth
                .user_id
                .as_deref()
                .expect("SAFETY: user_id checked non-None just above");
            let event_id = format!("FE!{}", uuid::Uuid::new_v4());
            let time_ms = crate::client::api::now_millis();
            let url = format!(
                "{}/hmsweb/user/{}/client/smart/devices/logout?clientId={}&eventId={}&time={}",
                self.endpoints.api_host, uid, self.auth.device_id, event_id, time_ms
            );
            self.execute_request::<()>(Method::DELETE, &url, None).await
        };

        // V3 → Legacy auto-fallback on 403/404, mirroring get_devices /
        // device_support. We don't retry inside the fallback branch
        // because the local state is being wiped anyway.
        if let Err(ArloError::HttpError { status, .. }) = &logout_attempt
            && !use_legacy
            && (*status == reqwest::StatusCode::FORBIDDEN
                || *status == reqwest::StatusCode::NOT_FOUND)
        {
            warn!(
                "v3 logout returned {}. Pinning client to Legacy and continuing local wipe.",
                status
            );
            self.api_version.set(crate::config::ApiVersion::Legacy);
        }

        // Wipe local session state regardless of HTTP outcome.
        self.auth.clear_token();
        self.auth.user_id = None;
        self.persist_session().await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::auth::test_support::*;
    use crate::client::test_helpers::{authenticated_mocked_client, mocked_client};
    use crate::client::transport::test_support::MockTransport;
    use std::sync::Arc;

    #[tokio::test]
    async fn login_v2_targets_legacy_endpoint() {
        let mock = Arc::new(MockTransport::new());
        mock.queue_post(auth_response("legacy-tok", "U2"));

        let mut client = mocked_client(Arc::clone(&mock));
        client.login_v2("u", "p").await.unwrap();

        let calls = mock.calls();
        assert!(calls[1].url.contains("/hmsweb/login/v2"));
        assert_eq!(client.auth.token(), Some("legacy-tok"));
    }

    #[tokio::test]
    async fn logout_v3_uses_delete_with_telemetry_query() {
        let mock = Arc::new(MockTransport::new());
        // DELETE goes through the same OPTIONS preflight as POST/PUT.
        mock.queue_post("{}");

        let mut client = authenticated_mocked_client(Arc::clone(&mock));
        assert!(client.is_authenticated());
        client.logout().await.unwrap();
        assert!(!client.is_authenticated());
        assert_eq!(client.user_id(), None);

        let calls = mock.calls();
        assert_eq!(calls.len(), 2, "OPTIONS preflight + DELETE main call");
        // Both calls hit the v3 URL; the DELETE one carries the wire body.
        let main = &calls[1];
        assert_eq!(main.method, reqwest::Method::DELETE);
        assert!(
            main.url
                .contains("/hmsweb/user/U-test/client/smart/devices/logout"),
            "expected v3 logout URL, got {}",
            main.url
        );
        assert!(main.url.contains("clientId=device-test"));
        assert!(
            main.url.contains("eventId=FE!"),
            "telemetry eventId param missing: {}",
            main.url
        );
        assert!(main.url.contains("time="));
    }

    #[tokio::test]
    async fn logout_falls_back_to_legacy_when_pinned_legacy() {
        let mock = Arc::new(MockTransport::new());
        // PUT /hmsweb/logout (legacy) — preflight + main.
        mock.queue_post("{}");

        let mut client = authenticated_mocked_client(Arc::clone(&mock));
        client.api_version.set(crate::config::ApiVersion::Legacy);

        client.logout().await.unwrap();
        let calls = mock.calls();
        let main = &calls[1];
        assert_eq!(main.method, reqwest::Method::PUT);
        assert!(
            main.url.ends_with("/hmsweb/logout"),
            "legacy URL expected, got {}",
            main.url
        );
    }

    #[tokio::test]
    async fn logout_wipes_local_state_even_when_http_call_fails() {
        let mock = Arc::new(MockTransport::new());
        // OPTIONS preflight then a 500 on the DELETE.
        mock.expect_ok(""); // preflight
        mock.expect(crate::client::transport::HttpResponse {
            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            body: "boom".into(),
        });

        let mut client = authenticated_mocked_client(mock);
        assert!(client.is_authenticated());
        // logout must succeed at the API surface regardless of HTTP outcome.
        client.logout().await.unwrap();
        assert!(!client.is_authenticated());
        assert_eq!(client.user_id(), None);
    }

    #[tokio::test]
    async fn logout_pins_legacy_on_v3_404() {
        let mock = Arc::new(MockTransport::new());
        mock.expect_ok(""); // OPTIONS preflight
        mock.expect(crate::client::transport::HttpResponse {
            status: reqwest::StatusCode::NOT_FOUND,
            body: "".into(),
        });

        let mut client = authenticated_mocked_client(Arc::clone(&mock));
        client.logout().await.unwrap();
        // V3 → Legacy auto-downgrade fires.
        assert_eq!(client.api_version.get(), crate::config::ApiVersion::Legacy);
    }
}
