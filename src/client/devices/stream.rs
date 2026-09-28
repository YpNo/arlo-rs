//! Legacy live-stream entry points (`/startStream`): the `get` query
//! (not side-effect free, see [`ArloClient::get_stream_url`]), forced
//! start with event-bus correlation by `transId`, and the URL helpers. v3 cameras use the WebRTC signaling in
//! `crate::client::livestream` instead.

use super::xcloud_header;
use crate::client::ArloClient;
use crate::endpoints::API_START_STREAM;
use crate::error::ArloError;
use crate::models::api::{Device, StreamUrl};
use reqwest::Method;
use serde_json::json;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, instrument, warn};

/// Maximum time we wait for Arlo's event-bus stream-URL response after the
/// `/startStream` POST returns 200. Empirically the URL lands within 1–3 s.
const STREAM_URL_TIMEOUT: Duration = Duration::from_secs(30);

impl ArloClient {
    /// Asks `/startStream` (`action: "get"`) for the URL of the stream
    /// `device` is serving, or `Ok(None)` when none is returned. The URL
    /// comes back in the POST response itself, not over the event bus.
    ///
    /// **Not a passive read.** Observed live on 2026-09-28: on an idle
    /// camera the call hands out a fresh web session and the camera then
    /// publishes its full state on the event bus, i.e. the request
    /// reaches the camera; repeated calls on an idle camera alternate
    /// between a fresh session and `None` as those sessions lapse. While
    /// a user watches the camera in the Arlo app, the call returns a URL
    /// carrying `watchalong=true` that joins that view. Call it only once
    /// the bus has reported `activityState == "userStreamActive"` for the
    /// camera, never on a timer: polling it wakes battery cameras.
    ///
    /// The request identifies as the web client (`from: <user>_web`), so
    /// the URL is the web client's `https://…/*.mpd` MPEG-DASH egress,
    /// not RTSP.
    ///
    /// Mirrors pyaarlo's `_get_stream_url`: `to` is the device's
    /// `parent_id` (the base station — equals `device_id` for
    /// self-hosted cameras), and an `xcloudId` header derived from
    /// `device.x_cloud_id` is attached. The returned URL is rewritten
    /// `rtsp://` → `rtsps://`.
    #[instrument(skip(self), fields(device = %device.device_id))]
    pub async fn get_stream_url(&self, device: &Device) -> Result<Option<StreamUrl>, ArloError> {
        let user_id = self.require_user_id()?;
        let trans_id = uuid::Uuid::new_v4().to_string();
        let url = format!("{}{}", self.endpoints.api_host, API_START_STREAM);

        let payload = json!({
            "action": "get",
            "from": format!("{user_id}_web"),
            "to": device.parent_id,
            "resource": format!("cameras/{}", device.device_id),
            "publishResponse": true,
            "responseUrl": "",
            "transId": trans_id,
            "properties": { "cameraId": device.device_id },
        });

        let body = self
            .execute_request_with_headers(
                Method::POST,
                &url,
                Some(&payload),
                &xcloud_header(device),
            )
            .await?;

        let parsed: serde_json::Value = serde_json::from_str(&body)?;
        extract_post_response_stream_url(&parsed)
            .map(|raw| StreamUrl::parse(&raw))
            .transpose()
    }

    /// Triggers a live stream for `device` and returns its playable URL,
    /// **reusing an already-active stream when one exists** (e.g. opened
    /// from the Arlo mobile app).
    ///
    /// Queries [`Self::get_stream_url`] first; on a miss, defers to
    /// [`Self::force_start_stream`] (fresh `startUserStream` +
    /// SSE-correlated URL). Because the `get` query can itself hand out
    /// a fresh web session on an idle camera, the returned URL may be
    /// that session rather than one from `startUserStream`. Use
    /// `force_start_stream` directly to skip the query.
    #[instrument(skip(self), fields(device = %device.device_id))]
    pub async fn start_stream(&self, device: &Device) -> Result<StreamUrl, ArloError> {
        if let Some(existing) = self.get_stream_url(device).await? {
            debug!(device = %device.device_id, "Reusing already-active stream");
            return Ok(existing);
        }
        self.force_start_stream(device).await
    }

    /// Always issues a fresh `startUserStream` regardless of any
    /// already-active stream, and awaits the SSE-correlated URL.
    ///
    /// Arlo's `/startStream` (`action: "set"`) is asynchronous: the
    /// POST only confirms acceptance; the real RTSPS / HLS / DASH URL
    /// arrives later as an SSE event correlated by `transId`. This
    /// subscribes to the event bus *before* the POST (closing the race
    /// where the SSE response could beat the subscription) and waits up
    /// to `STREAM_URL_TIMEOUT` (30 s). Returns [`ArloError::Timeout`] if no
    /// URL arrives in time, or [`ArloError::AuthError`] if not yet
    /// authenticated.
    #[instrument(skip(self), fields(device = %device.device_id))]
    pub async fn force_start_stream(&self, device: &Device) -> Result<StreamUrl, ArloError> {
        let user_id = self
            .auth
            .user_id
            .as_deref()
            .ok_or_else(|| ArloError::AuthError("Cannot start stream before login".into()))?
            .to_string();
        let camera_id = &device.device_id;
        let trans_id = uuid::Uuid::new_v4().to_string();

        // Attach SSE listener BEFORE the POST.
        let bus = self.events().await?;
        let mut rx = bus.subscribe();

        let url = format!("{}{}", self.endpoints.api_host, API_START_STREAM);
        let payload = json!({
            "to": device.parent_id,
            "from": format!("{user_id}_web"),
            "resource": format!("cameras/{camera_id}"),
            "action": "set",
            "publishResponse": true,
            "transId": trans_id,
            "properties": {
                "activityState": "startUserStream",
                "cameraId": camera_id
            }
        });
        self.execute_request_with_headers(
            Method::POST,
            &url,
            Some(&payload),
            &xcloud_header(device),
        )
        .await?;

        // Drain the broadcast channel until we see our own transId carrying
        // a stream URL, or the per-call timeout expires.
        let deadline = tokio::time::Instant::now() + STREAM_URL_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(ArloError::Timeout(format!(
                    "startStream({camera_id}) did not receive a URL within {STREAM_URL_TIMEOUT:?}"
                )));
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(event)) => {
                    // Identifiers only: `properties` carries credential-bearing
                    // stream and presigned URLs and must not be dumped.
                    debug!(
                        action = %event.action,
                        resource = %event.resource,
                        trans_id = ?event.trans_id,
                        "bus event during startStream wait"
                    );
                    if !event_matches_trans_id(&event, &trans_id) {
                        continue;
                    }
                    if let Some(found) = extract_stream_url(&event) {
                        return StreamUrl::parse(&found);
                    }
                    // Arlo answers a failed startStream on the bus with the
                    // same transId and an error instead of a URL. Surface
                    // it now rather than as a generic timeout in 30 s.
                    if let Some(err) = stream_error_from_event(&event) {
                        return Err(err);
                    }
                }
                Ok(Err(RecvError::Lagged(n))) => {
                    warn!(skipped = n, "Event bus lagged during startStream wait");
                    continue;
                }
                Ok(Err(RecvError::Closed)) => {
                    return Err(ArloError::ApiError {
                        code: 500,
                        error: None,
                        message: "SSE bus closed before startStream URL arrived".into(),
                    });
                }
                Err(_elapsed) => {
                    return Err(ArloError::Timeout(format!(
                        "startStream({camera_id}) did not receive a URL within {STREAM_URL_TIMEOUT:?}"
                    )));
                }
            }
        }
    }
}

/// Extracts a stream URL from a synchronous `action: "get"` /startStream
/// response. Tolerant of the same envelope variants as the rest of the
/// API: a bare `{"url": …}`, `{"data": {"url": …}}`, or
/// `{"success": true, "data": {"url": …}}`. An empty or missing `url`
/// means "no active stream" → `None`.
fn extract_post_response_stream_url(value: &serde_json::Value) -> Option<String> {
    let pick = |v: &serde_json::Value| -> Option<String> {
        v.get("url")
            .and_then(|u| u.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };
    if let Some(u) = pick(value) {
        return Some(u);
    }
    pick(value.get("data")?)
}

/// True if `event` carries the same `transId` we sent on the `/startStream`
/// POST. Tolerant of Arlo wrapping the field in nested objects: most
/// responses put it at the top level, but we also peek inside `properties`
/// just in case.
fn event_matches_trans_id(event: &crate::models::events::ArloEvent, trans_id: &str) -> bool {
    if event.trans_id.as_deref() == Some(trans_id) {
        return true;
    }
    if let Some(props) = event.properties.as_ref()
        && props.get("transId").and_then(|v| v.as_str()) == Some(trans_id)
    {
        return true;
    }
    false
}

/// The error a device or base station reported for our `startStream`,
/// when `event` (already matched on `transId`) is an error echo:
/// `action:"error"`, or `properties.error` / `properties.code` present.
/// The Arlo code goes into `ApiError::error` so [`ArloError::action`]
/// classifies it (`2059`/`2222` are the "base station not responding"
/// family). `None` for anything that is not an error.
fn stream_error_from_event(event: &crate::models::events::ArloEvent) -> Option<ArloError> {
    let props = event.properties.as_ref();
    let error_obj = props.and_then(|p| p.get("error")).filter(|e| e.is_object());
    let is_error = event.action == "error"
        || props.is_some_and(|p| p.get("error").is_some() || p.get("code").is_some());
    if !is_error {
        return None;
    }
    // Field lookup: an `error` object wins, then the properties themselves.
    let field = |name: &str| -> Option<&serde_json::Value> {
        error_obj
            .and_then(|e| e.get(name))
            .or_else(|| props.and_then(|p| p.get(name)))
    };
    let arlo_code = field("code")
        .or_else(|| field("error"))
        .and_then(|v| v.as_u64())
        .and_then(|c| u32::try_from(c).ok());
    let message = field("message")
        .and_then(|m| m.as_str())
        .map(crate::models::redact::excerpt)
        .unwrap_or_else(|| "startStream rejected by the device".to_string());
    Some(ArloError::ApiError {
        code: 500,
        error: arlo_code,
        message,
    })
}

/// Extracts the playable stream URL from a stream-response SSE event.
/// Arlo has used both `properties.url` and `properties.streamUrl` in the
/// wild; check both before declaring no match.
fn extract_stream_url(event: &crate::models::events::ArloEvent) -> Option<String> {
    let props = event.properties.as_ref()?;
    if let Some(s) = props.get("url").and_then(|v| v.as_str()) {
        return Some(s.to_string());
    }
    if let Some(s) = props.get("streamUrl").and_then(|v| v.as_str()) {
        return Some(s.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::devices::test_support::*;
    use crate::client::test_helpers::{authenticated_mocked_client, parse_body_json};
    use crate::error::ArloError;
    use crate::models::api::Device;
    use crate::models::events::ArloEvent;
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn make_event(trans_id: Option<&str>, properties: Value) -> ArloEvent {
        ArloEvent {
            action: "is".into(),
            resource: "cameras/C1".into(),
            publish_response: None,
            properties: Some(properties),
            source: None,
            trans_id: trans_id.map(String::from),
            active_mode: None,
        }
    }

    #[test]
    fn trans_id_matches_top_level() {
        let ev = make_event(Some("tid-1"), json!({}));
        assert!(event_matches_trans_id(&ev, "tid-1"));
        assert!(!event_matches_trans_id(&ev, "other"));
    }

    #[test]
    fn trans_id_matches_inside_properties() {
        let ev = make_event(None, json!({ "transId": "tid-nested" }));
        assert!(event_matches_trans_id(&ev, "tid-nested"));
    }

    #[test]
    fn trans_id_no_match_when_absent() {
        let ev = make_event(None, json!({}));
        assert!(!event_matches_trans_id(&ev, "anything"));
    }

    #[test]
    fn stream_url_extracted_from_url_key() {
        let ev = make_event(Some("t"), json!({ "url": "rtsps://camera/stream" }));
        assert_eq!(
            extract_stream_url(&ev).as_deref(),
            Some("rtsps://camera/stream")
        );
    }

    #[test]
    fn stream_url_extracted_from_stream_url_key() {
        let ev = make_event(Some("t"), json!({ "streamUrl": "https://hls/idx.m3u8" }));
        assert_eq!(
            extract_stream_url(&ev).as_deref(),
            Some("https://hls/idx.m3u8")
        );
    }

    #[test]
    fn stream_url_returns_none_when_absent() {
        let ev = make_event(Some("t"), json!({ "activityState": "idle" }));
        assert_eq!(extract_stream_url(&ev), None);
    }

    /// Builds a `Device` fixture. `parent` defaults to `device_id`
    /// (self-hosted) when `None`; `x_cloud` controls the optional
    /// `xCloudId` field.
    fn make_device(device_id: &str, parent: Option<&str>, x_cloud: Option<&str>) -> Device {
        let parent_id = parent.unwrap_or(device_id);
        let xc = x_cloud
            .map(|x| format!(r#","xCloudId":"{x}""#))
            .unwrap_or_default();
        let json = format!(
            r#"{{"deviceId":"{device_id}","parentId":"{parent_id}",
                 "deviceType":"camera","deviceName":"Cam","uniqueId":"u",
                 "state":"provisioned"{xc}}}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[tokio::test]
    async fn start_stream_errors_before_login() {
        let mock = arc_mock();
        let client = crate::client::test_helpers::mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-1", None, None);
        // No user_id set — get_stream_url short-circuits before any HTTP.
        let err = client.start_stream(&dev).await.unwrap_err();
        assert!(matches!(err, ArloError::AuthError(_)));
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn get_stream_url_returns_url_with_action_get_and_xcloud_header() {
        let mock = arc_mock();
        // Synchronous get response — URL in the POST body itself.
        mock.queue_post(r#"{"url":"rtsp://stream.example/cam.sdp"}"#);

        let client = authenticated_mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-9", Some("BASE-9"), Some("z1-cloud"));
        let got = client.get_stream_url(&dev).await.unwrap();

        // rtsp:// rewritten to rtsps://
        assert_eq!(
            got.as_ref().map(|s| s.as_str()),
            Some("rtsps://stream.example/cam.sdp")
        );

        let calls = mock.calls();
        assert_eq!(calls.len(), 2, "OPTIONS preflight + POST");
        let post = &calls[1];
        let body = parse_body_json(post.body.as_ref());
        assert_eq!(body["action"], "get");
        assert_eq!(body["to"], "BASE-9"); // parent_id, not device_id
        assert_eq!(body["resource"], "cameras/CAM-9");
        assert_eq!(body["properties"]["cameraId"], "CAM-9");
        assert_eq!(body["responseUrl"], "");
        // xcloudId header derived from the device.
        let xc = post
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("xcloudId"))
            .map(|(_, v)| v.as_str());
        assert_eq!(xc, Some("z1-cloud"));
    }

    #[tokio::test]
    async fn get_stream_url_returns_none_when_no_active_stream() {
        let mock = arc_mock();
        // Arlo returns an envelope with no `url` when nothing is streaming.
        mock.queue_post(r#"{"success":true,"data":{}}"#);
        let client = authenticated_mocked_client(mock);
        let dev = make_device("CAM-1", None, None);
        assert_eq!(client.get_stream_url(&dev).await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_stream_url_unwraps_data_url_envelope() {
        let mock = arc_mock();
        mock.queue_post(r#"{"success":true,"data":{"url":"rtsps://already/secure"}}"#);
        let client = authenticated_mocked_client(mock);
        let dev = make_device("CAM-1", None, None);
        let got = client.get_stream_url(&dev).await.unwrap();
        // Already rtsps:// — left untouched.
        assert_eq!(
            got.map(|s| s.into_inner()),
            Some("rtsps://already/secure".to_string())
        );
    }

    #[tokio::test]
    async fn get_stream_url_omits_xcloud_header_when_device_lacks_it() {
        let mock = arc_mock();
        mock.queue_post(r#"{"url":"rtsp://x/y"}"#);
        let client = authenticated_mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-1", None, None); // no xCloudId
        client.get_stream_url(&dev).await.unwrap();
        let post = &mock.calls()[1];
        assert!(
            !post
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("xcloudId")),
            "xcloudId header must be omitted when device.x_cloud_id is None"
        );
    }

    #[tokio::test]
    async fn start_stream_reuses_active_stream_without_touching_sse() {
        // get_stream_url returns Some → start_stream returns it directly,
        // never subscribing to the event bus (which would fail here since
        // MockTransport has no streaming client).
        let mock = arc_mock();
        mock.queue_post(r#"{"url":"rtsp://live/now"}"#);
        let client = authenticated_mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-1", None, None);

        let url = client.start_stream(&dev).await.unwrap();
        assert_eq!(url.as_str(), "rtsps://live/now");
        // Exactly one peek round-trip (OPTIONS + POST). No SSE bus boot.
        assert_eq!(mock.calls().len(), 2);
    }

    #[tokio::test]
    async fn start_stream_falls_back_to_force_when_no_active_stream() {
        // get_stream_url → None, then force_start_stream boots the event
        // bus, whose first step is a session/v3 round-trip. MockTransport
        // has no canned response for it, so the call errors — but only
        // *after* progressing past the 2-call peek, which is what proves
        // start_stream didn't stop at the empty peek.
        let mock = arc_mock();
        mock.queue_post(r#"{"success":true,"data":{}}"#); // empty peek
        let client = authenticated_mocked_client(Arc::clone(&mock));
        let dev = make_device("CAM-1", None, None);

        assert!(client.start_stream(&dev).await.is_err());
        assert!(
            mock.calls().len() > 2,
            "force fallback must progress past the 2-call peek (event-bus boot), got {} calls",
            mock.calls().len()
        );
    }

    #[test]
    fn rewrite_rtsp_to_rtsps_only_touches_plain_rtsp() {
        assert_eq!(
            crate::models::api::rewrite_rtsp_to_rtsps("rtsp://h/p"),
            "rtsps://h/p"
        );
        assert_eq!(
            crate::models::api::rewrite_rtsp_to_rtsps("rtsps://h/p"),
            "rtsps://h/p"
        );
        assert_eq!(
            crate::models::api::rewrite_rtsp_to_rtsps("https://h/p.m3u8"),
            "https://h/p.m3u8"
        );
        assert_eq!(crate::models::api::rewrite_rtsp_to_rtsps(""), "");
    }

    #[test]
    fn extract_post_response_stream_url_handles_all_envelopes() {
        assert_eq!(
            super::extract_post_response_stream_url(&json!({"url":"rtsp://a"})),
            Some("rtsp://a".to_string())
        );
        assert_eq!(
            super::extract_post_response_stream_url(&json!({"data":{"url":"rtsp://b"}})),
            Some("rtsp://b".to_string())
        );
        assert_eq!(
            super::extract_post_response_stream_url(
                &json!({"success":true,"data":{"url":"rtsp://c"}})
            ),
            Some("rtsp://c".to_string())
        );
        assert_eq!(
            super::extract_post_response_stream_url(&json!({"data":{"url":""}})),
            None
        );
        assert_eq!(
            super::extract_post_response_stream_url(&json!({"success":true,"data":{}})),
            None
        );
        assert_eq!(super::extract_post_response_stream_url(&json!({})), None);
    }
}

#[cfg(test)]
mod error_echo_tests {
    use super::*;
    use crate::models::events::ArloEvent;
    use serde_json::{Value, json};

    fn event(action: &str, properties: Value) -> ArloEvent {
        ArloEvent {
            action: action.into(),
            resource: "cameras/C1".into(),
            publish_response: None,
            properties: Some(properties),
            source: None,
            trans_id: Some("t-1".into()),
            active_mode: None,
        }
    }

    #[test]
    fn error_echoes_become_classified_api_errors() {
        let e = stream_error_from_event(&event(
            "error",
            json!({"code": 2059, "message": "Base station is not responding."}),
        ))
        .expect("error echo");
        assert!(
            matches!(
                &e,
                ArloError::ApiError {
                    error: Some(2059),
                    ..
                }
            ),
            "{e}"
        );
        assert_eq!(
            e.to_string(),
            "API Error [500/2059]: Base station is not responding."
        );

        let nested = stream_error_from_event(&event(
            "is",
            json!({"error": {"code": 2222, "message": "busy\nline"}}),
        ))
        .expect("nested error object");
        assert!(matches!(
            &nested,
            ArloError::ApiError {
                error: Some(2222),
                ..
            }
        ));
        assert!(
            !nested.to_string().contains('\n'),
            "control characters stripped"
        );

        assert!(stream_error_from_event(&event("error", json!({}))).is_some());
    }

    #[test]
    fn url_and_ordinary_events_are_not_errors() {
        assert!(stream_error_from_event(&event("is", json!({"url": "rtsps://h/p"}))).is_none());
        assert!(stream_error_from_event(&event("is", json!({"activityState": "idle"}))).is_none());
    }
}
