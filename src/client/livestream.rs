//! v3 WebRTC live-stream **signaling** (signaling-only).
//!
//! Two steps, both reverse-engineered from a live `my.arlo.com` capture:
//!
//! 1. `GET /hmsweb/users/devices/sipInfo/v2` (normal authed REST, with
//!    the `xcloudId` header) → [`SipInfo`]: the SIP callee URI, per-call
//!    `password`, and the ICE (STUN/TURN) servers.
//! 2. A WebSocket to `wss://<domain>:7443/` (subprotocol `sip`,
//!    `Origin: https://my.arlo.com`) that tunnels **HTTP requests**:
//!    `POST /hmswebsocketproxy/initiateOffer` carrying the WebRTC SDP
//!    offer → `HTTP/1.1 200 OK` carrying the SDP answer;
//!    `POST /hmswebsocketproxy/sessionDisconnected` on teardown.
//!
//! This module owns **only** the REST fetch and the pure HTTP-over-WS
//! framing (fully unit-tested against the captured bytes) plus a thin
//! async transport. The WebRTC media plane — offer generation,
//! ICE/DTLS/SRTP, the inbound H.264 — lives in the **consumer** (the
//! streamer's GStreamer `webrtcbin`): Arlo's gateway is non-bundled
//! `FreeSWITCH`, which the pure-Rust `webrtc` stack cannot negotiate.
//! The caller generates the offer SDP, hands it to
//! [`ArloClient::webrtc_negotiate`], and applies the returned answer.

use futures_util::{SinkExt, StreamExt};
use reqwest::Method;
use serde_json::json;
use tracing::{debug, info, instrument};

use crate::client::ArloClient;
use crate::client::devices::xcloud_header;
use crate::client::ws::{BoxWsStream, WsMessage as Message};
use crate::endpoints::API_SIP_INFO;
use crate::error::ArloError;
use crate::models::api::Device;
use crate::models::envelope::unwrap_envelope;
use crate::models::sip::SipInfo;

/// `Origin` the Arlo web client sends on the signaling WS upgrade.
const WS_ORIGIN: &str = "https://my.arlo.com";

/// Negotiated SDP answer + the session id the gateway echoed back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingAnswer {
    /// The gateway's WebRTC SDP answer (`FreeSWITCH`; H.264 sendonly).
    pub answer_sdp: String,
    /// Session id echoed by the gateway; needed for teardown.
    pub session_id: String,
}

impl ArloClient {
    /// Fetches [`SipInfo`] for `device` (WebRTC live signaling coords).
    ///
    /// # Errors
    ///
    /// [`ArloError::AuthError`] if unauthenticated; transport / parse
    /// errors from the `sipInfo/v2` call propagate.
    #[instrument(skip(self), fields(device = %device.device_id))]
    pub async fn sip_info(&self, device: &Device) -> Result<SipInfo, ArloError> {
        let user_id = self.require_user_id()?;
        let model = device.model_id.as_deref().unwrap_or_default();
        let unique_id = format!("{user_id}_{}", device.device_id);
        let event_id = format!("FE!{}", uuid::Uuid::new_v4());
        let ts = crate::client::api::now_millis();
        let url = format!(
            "{}{}?cameraId={}&modelId={}&uniqueId={}&eventId={}&time={}",
            self.endpoints.api_host, API_SIP_INFO, device.device_id, model, unique_id, event_id, ts,
        );

        // `sipInfo/v2` reads the camera id from a **required request
        // header** (Spring `@RequestHeader cameraId`) — the query param
        // alone yields HTTP 400 "header 'cameraId' not present".
        let mut headers = xcloud_header(device);
        headers.push(("cameraId".to_string(), device.device_id.clone()));
        let body = self
            .execute_request_with_headers::<()>(Method::GET, &url, None, &headers)
            .await?;
        let data = unwrap_envelope(&body)?;
        serde_json::from_value(data)
            .map_err(|e| ArloError::ParseError(format!("Failed to parse sipInfo: {e}")))
    }

    /// Opens the signaling WS, sends the WebRTC `offer_sdp` (generated
    /// by the consumer's `webrtcbin`), and returns the gateway's
    /// answer. The returned [`SignalingSocket`] keeps the WS open so the
    /// caller can [`SignalingSocket::disconnect`] when the WebRTC
    /// session ends.
    ///
    /// # Errors
    ///
    /// [`ArloError::ScraperError`] on WS/transport failure;
    /// [`ArloError::AuthError`] if the gateway rejects the offer.
    #[instrument(skip(self, sip, offer_sdp), fields(device = %sip.sip_call_info.device_id))]
    pub async fn webrtc_negotiate(
        &self,
        sip: &SipInfo,
        offer_sdp: &str,
    ) -> Result<(SignalingAnswer, SignalingSocket), ArloError> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let camera_id = sip.sip_call_info.device_id.clone();

        // Arlo's upgrade extras: `Origin` + the `sip` subprotocol.
        let mut ws = self
            .ws
            .connect(&sip.sip_call_info.ws_url(), WS_ORIGIN, "sip")
            .await?;
        info!("livestream signaling WS connected");

        let frame = build_initiate_offer(sip, &session_id, &camera_id, offer_sdp);
        ws.send(Message::Text(frame.into()))
            .await
            .map_err(|e| ArloError::ScraperError(format!("initiateOffer send: {e}")))?;

        let answer = loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) => break parse_answer(t.as_str())?,
                Some(Ok(Message::Binary(b))) => {
                    break parse_answer(&String::from_utf8_lossy(&b))?;
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = ws.send(Message::Pong(p)).await;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    return Err(ArloError::ScraperError(format!("signaling read: {e}")));
                }
                None => {
                    return Err(ArloError::ScraperError(
                        "signaling WS closed before answer".into(),
                    ));
                }
            }
        };

        Ok((
            answer,
            SignalingSocket {
                ws,
                sip: sip.clone(),
                session_id,
                camera_id,
            },
        ))
    }
}

/// An open signaling WS held for the lifetime of a WebRTC session.
pub struct SignalingSocket {
    ws: BoxWsStream,
    sip: SipInfo,
    session_id: String,
    camera_id: String,
}

impl SignalingSocket {
    /// Sends `sessionDisconnected` and closes the WS. Best-effort —
    /// errors are logged, not propagated (teardown must not fail a
    /// shutdown path).
    #[instrument(skip(self))]
    pub async fn disconnect(mut self) {
        let frame = build_session_disconnected(&self.sip, &self.session_id, &self.camera_id);
        if let Err(e) = self.ws.send(Message::Text(frame.into())).await {
            debug!(error = %e, "sessionDisconnected send failed (ignored)");
        }
        let _ = self.ws.close().await;
    }
}

/// Wraps a JSON body in the literal HTTP/1.1 request the
/// `hmswebsocketproxy` Express endpoint expects, as one WS text frame.
fn http_frame(path: &str, host: &str, json_body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: keep-alive\r\n\
         Accept: */*\r\n\
         \r\n\
         {json_body}",
        len = json_body.len(),
    )
}

/// `sipCallInfo` subset the envelope carries (note `domain` is the
/// `:7443` WS host and `port` is the string `"7443"` — distinct from
/// the SIP `:443` in the `sipInfo/v2` response).
fn envelope_sip_call_info(sip: &SipInfo) -> serde_json::Value {
    json!({
        "calleeUri": sip.sip_call_info.callee_uri,
        "id": sip.sip_call_info.id,
        "password": sip.sip_call_info.password,
        "domain": sip.sip_call_info.ws_domain(),
        "port": "7443",
    })
}

/// `POST /hmswebsocketproxy/initiateOffer` frame carrying the SDP offer.
fn build_initiate_offer(
    sip: &SipInfo,
    session_id: &str,
    camera_id: &str,
    offer_sdp: &str,
) -> String {
    let body = json!({
        "sipCallInfo": envelope_sip_call_info(sip),
        "payload": {
            "sessionId": session_id,
            "cameraId": camera_id,
            "offer": { "format": "SDP", "value": offer_sdp },
        },
    })
    .to_string();
    http_frame(
        "/hmswebsocketproxy/initiateOffer",
        &sip.sip_call_info.ws_domain(),
        &body,
    )
}

/// `POST /hmswebsocketproxy/sessionDisconnected` teardown frame.
fn build_session_disconnected(sip: &SipInfo, session_id: &str, camera_id: &str) -> String {
    let body = json!({
        "sipCallInfo": envelope_sip_call_info(sip),
        "payload": { "sessionId": session_id, "cameraId": camera_id },
    })
    .to_string();
    http_frame(
        "/hmswebsocketproxy/sessionDisconnected",
        &sip.sip_call_info.ws_domain(),
        &body,
    )
}

/// Parses an `HTTP/1.1 200 OK` signaling response frame into the SDP
/// answer + session id. Errors on non-200, `success:false`, or a
/// missing answer.
fn parse_answer(frame: &str) -> Result<SignalingAnswer, ArloError> {
    let (head, body) = frame
        .split_once("\r\n\r\n")
        .ok_or_else(|| ArloError::ParseError("signaling frame has no body".into()))?;
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200") {
        return Err(ArloError::AuthError(format!(
            "signaling rejected: {status}"
        )));
    }
    let v: serde_json::Value = serde_json::from_str(body.trim())
        .map_err(|e| ArloError::ParseError(format!("signaling body not JSON: {e}")))?;
    if v.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(ArloError::AuthError(format!(
            "signaling success!=true: {body}"
        )));
    }
    let data = v.get("data").unwrap_or(&serde_json::Value::Null);
    let answer_sdp = data
        .pointer("/payload/answer/value")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ArloError::ParseError("signaling answer missing".into()))?
        .to_string();
    let session_id = data
        .get("sessionId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(SignalingAnswer {
        answer_sdp,
        session_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::sip::SipInfo;

    const SIP_DATA: &str = r#"{
      "sipCallInfo":{"id":"Conference_X","calleeUri":"sip:CAM_1_abc@livestream-z1-prod.arlo.com:443",
        "domain":"livestream-z1-prod.arlo.com","port":443,"conferenceId":null,
        "password":"PW123","deviceId":"A0A0000YA0D00","callId":"abc"},
      "iceServers":{"uSessionId":"u!1","data":[
        {"port":"19302","domain":"relay03-z1-prod.ar.arlo.com","type":"stun"}]}
    }"#;

    fn sip() -> SipInfo {
        serde_json::from_str(SIP_DATA).expect("sip parses")
    }

    #[tokio::test]
    async fn sip_info_sends_camera_id_and_xcloud_headers() {
        use crate::client::test_helpers::{authenticated_mocked_client, header_value};
        use crate::client::transport::test_support::MockTransport;
        use std::sync::Arc;

        let device: crate::models::api::Device = serde_json::from_str(
            r#"{"deviceId":"A0A0000YA0D00","parentId":"A0A0000YA0D00","deviceType":"camera",
                "deviceName":"liv","uniqueId":"u","state":"provisioned","modelId":"VMC4041PA",
                "xCloudId":"RXXXXXXX-0000-000-000000000"}"#,
        )
        .unwrap();

        let mock = Arc::new(MockTransport::new());
        mock.queue_get(format!(r#"{{"data":{SIP_DATA},"success":true}}"#));
        let client = authenticated_mocked_client(Arc::clone(&mock));

        let sip = client.sip_info(&device).await.expect("sipInfo parses");
        assert_eq!(sip.sip_call_info.device_id, "A0A0000YA0D00");

        // The whole point of the fix: cameraId must be a request header,
        // not just the query param (server returns 400 otherwise).
        let calls = mock.calls();
        let req = calls.last().expect("a request was made");
        assert_eq!(
            header_value(&req.headers, "cameraId"),
            Some("A0A0000YA0D00")
        );
        assert_eq!(
            header_value(&req.headers, "xcloudId"),
            Some("RXXXXXXX-0000-000-000000000")
        );
        assert!(req.url.contains("cameraId=A0A0000YA0D00"));
    }

    #[test]
    fn initiate_offer_frame_matches_captured_shape() {
        let frame = build_initiate_offer(
            &sip(),
            "sess-1",
            "A0A0000YA0D00",
            "v=0\r\no=- 1 2 IN IP4 0\r\n",
        );
        let (head, body) = frame.split_once("\r\n\r\n").expect("has body");

        assert!(head.starts_with("POST /hmswebsocketproxy/initiateOffer HTTP/1.1\r\n"));
        assert!(head.contains("Host: livestream-z1-prod.arlo.com:7443\r\n"));
        assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())));

        let j: serde_json::Value = serde_json::from_str(body).expect("body json");
        assert_eq!(
            j["sipCallInfo"]["calleeUri"],
            "sip:CAM_1_abc@livestream-z1-prod.arlo.com:443"
        );
        assert_eq!(j["sipCallInfo"]["password"], "PW123");
        assert_eq!(
            j["sipCallInfo"]["domain"],
            "livestream-z1-prod.arlo.com:7443"
        );
        assert_eq!(j["sipCallInfo"]["port"], "7443");
        assert_eq!(j["payload"]["cameraId"], "A0A0000YA0D00");
        assert_eq!(j["payload"]["sessionId"], "sess-1");
        assert_eq!(j["payload"]["offer"]["format"], "SDP");
        assert_eq!(
            j["payload"]["offer"]["value"],
            "v=0\r\no=- 1 2 IN IP4 0\r\n"
        );
    }

    #[test]
    fn session_disconnected_frame_omits_offer() {
        let frame = build_session_disconnected(&sip(), "sess-1", "A0A0000YA0D00");
        let (head, body) = frame.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /hmswebsocketproxy/sessionDisconnected HTTP/1.1"));
        let j: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(j["payload"]["sessionId"], "sess-1");
        assert_eq!(j["payload"]["cameraId"], "A0A0000YA0D00");
        assert!(j["payload"].get("offer").is_none());
    }

    #[tokio::test]
    async fn webrtc_negotiate_drives_the_signaling_exchange_over_the_ws_port() {
        use crate::client::test_helpers::{mocked_client_with_ws, set_test_token};
        use crate::client::transport::test_support::MockTransport;
        use crate::client::ws::test_support::MockWsConnector;
        use std::sync::Arc;

        let answer_frame = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
            {\"data\":{\"payload\":{\"answer\":{\"format\":\"SDP\",\"value\":\"v=0\\r\\nanswer\"}},\"sessionId\":\"sess-1\"},\"success\":true}";
        let ws = Arc::new(MockWsConnector::new());
        ws.script(vec![
            Message::Ping(vec![1].into()),
            Message::Text(answer_frame.into()),
        ]);
        ws.release();
        let mut client = mocked_client_with_ws(Arc::new(MockTransport::new()), ws.clone());
        set_test_token(&mut client, "tok", "U1", "dev");

        let (answer, socket) = client
            .webrtc_negotiate(&sip(), "v=0\r\noffer")
            .await
            .expect("negotiation succeeds");
        assert_eq!(answer.session_id, "sess-1");
        assert!(answer.answer_sdp.starts_with("v=0"));

        let (url, origin, proto) = ws.connects().first().cloned().expect("connected");
        assert_eq!(url, "wss://livestream-z1-prod.arlo.com:7443/");
        assert_eq!(origin, WS_ORIGIN);
        assert_eq!(proto, "sip");

        socket.disconnect().await;
        let sent = ws.sent();
        let texts: Vec<&str> = sent
            .iter()
            .filter_map(|m| match m {
                Message::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert!(texts[0].starts_with("POST /hmswebsocketproxy/initiateOffer HTTP/1.1"));
        assert!(
            texts[0].contains("v=0\\r\\noffer"),
            "offer SDP carried: {}",
            texts[0]
        );
        assert!(texts[0].contains("\"cameraId\":\"A0A0000YA0D00\""));
        assert!(texts[1].starts_with("POST /hmswebsocketproxy/sessionDisconnected HTTP/1.1"));
        assert!(
            matches!(sent[1], Message::Pong(_)),
            "ping answered before the answer frame"
        );
    }

    #[test]
    fn parse_answer_extracts_sdp_and_session() {
        // Shape from the captured 200 OK signaling frame.
        let frame = "HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nContent-Type: application/json\r\n\r\n\
            {\"data\":{\"payload\":{\"answer\":{\"format\":\"SDP\",\"value\":\"v=0\\r\\no=FreeSWITCH 1 2 IN IP6 ::1\\r\\n\"}},\"sessionId\":\"5ceb0289-82be-44bc-aa56-864f9471e37f\"},\"success\":true}";
        let a = parse_answer(frame).expect("parses");
        assert!(a.answer_sdp.starts_with("v=0"));
        assert!(a.answer_sdp.contains("FreeSWITCH"));
        assert_eq!(a.session_id, "5ceb0289-82be-44bc-aa56-864f9471e37f");
    }

    #[test]
    fn parse_answer_rejects_non_200() {
        let frame = "HTTP/1.1 500 Internal Server Error\r\n\r\n{\"success\":false}";
        assert!(matches!(parse_answer(frame), Err(ArloError::AuthError(_))));
    }

    #[test]
    fn parse_answer_rejects_success_false() {
        let frame = "HTTP/1.1 200 OK\r\n\r\n{\"success\":false,\"data\":{}}";
        assert!(matches!(parse_answer(frame), Err(ArloError::AuthError(_))));
    }
}
