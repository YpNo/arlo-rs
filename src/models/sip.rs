//! Models for the v3 WebRTC live-stream signaling info returned by
//! `GET /hmsweb/users/devices/sipInfo/v2`.
//!
//! Shapes verified against a live `my.arlo.com` capture. The response
//! is enveloped (`{ "data": { … }, "success": true }`); these structs
//! model the unwrapped `data`. Unknown sibling fields (`from`, `to`,
//! `transId`, …) are ignored.

use serde::{Deserialize, Serialize};

/// Unwrapped `data` of a `sipInfo/v2` response.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SipInfo {
    pub sip_call_info: SipCallInfo,
    pub ice_servers: IceServers,
}

/// SIP call coordinates for the `livestream-*` gateway. `Debug` redacts
/// the per-call `password`.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SipCallInfo {
    /// Conference id (`Conference_<ts>_<callId>_<userId>_<deviceId>_caller`).
    pub id: String,
    /// `sip:<deviceId>_<ts>_<callId>@<domain>:443`.
    pub callee_uri: String,
    /// Gateway host, e.g. `livestream-z1-prod.arlo.com`. The WebRTC
    /// signaling WSS is `wss://<domain>:7443/`.
    pub domain: String,
    /// SIP port from the response (443). Note the signaling WSS uses
    /// 7443; see [`SipCallInfo::ws_domain`].
    pub port: u16,
    /// Per-call shared secret echoed back in the signaling envelope.
    pub password: String,
    pub device_id: String,
    pub call_id: String,
    #[serde(default)]
    pub conference_id: Option<String>,
}

impl SipCallInfo {
    /// `<domain>:7443` — the value the `hmswebsocketproxy` envelope and
    /// the WSS `Host` header expect (distinct from the SIP `port`).
    #[must_use]
    pub fn ws_domain(&self) -> String {
        format!("{}:7443", self.domain)
    }

    /// `wss://<domain>:7443/` — the signaling WebSocket URL.
    #[must_use]
    pub fn ws_url(&self) -> String {
        format!("wss://{}:7443/", self.domain)
    }
}

/// ICE (STUN/TURN) servers for the WebRTC peer connection.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IceServers {
    #[serde(default)]
    pub u_session_id: Option<String>,
    pub data: Vec<IceServer>,
}

/// One ICE server. `port` is a **string** on the wire (`"19302"`,
/// `"443"`). STUN entries omit `transport`/`username`/`credential`.
/// `Debug` redacts the TURN `credential`.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IceServer {
    /// `"stun"` or `"turn"`.
    #[serde(rename = "type")]
    pub kind: String,
    pub domain: String,
    pub port: String,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub credential: Option<String>,
}

impl std::fmt::Debug for IceServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceServer")
            .field("kind", &self.kind)
            .field("domain", &self.domain)
            .field("port", &self.port)
            .field("transport", &self.transport)
            .field("username", &self.username)
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl IceServer {
    /// `stun:host:port` / `turn:host:port?transport=tcp` URL form.
    #[must_use]
    pub fn url(&self) -> String {
        match self.transport.as_deref() {
            Some(t) => format!("{}:{}:{}?transport={t}", self.kind, self.domain, self.port),
            None => format!("{}:{}:{}", self.kind, self.domain, self.port),
        }
    }
}

impl std::fmt::Debug for SipCallInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SipCallInfo")
            .field("id", &self.id)
            .field("callee_uri", &self.callee_uri)
            .field("domain", &self.domain)
            .field("port", &self.port)
            .field("password", &"[REDACTED]")
            .field("device_id", &self.device_id)
            .field("call_id", &self.call_id)
            .field("conference_id", &self.conference_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `data` object in the exact shape of a live sipInfo/v2 capture;
    // every identifier and secret is synthetic.
    const SAMPLE: &str = r#"{
      "from":"UXXX-000-00000000_server","to":"UXXX-000-00000000",
      "action":"is","resource":"sipDetails","transId":"da2b5172",
      "sipCallInfo":{
        "id":"Conference_1700000000000_0123456789abcdef0123456789abcdefD_UXXX-000-00000000_A0A0000YA0D00_caller",
        "calleeUri":"sip:A0A0000YA0D00_1700000000000_0123456789abcdef0123456789abcdefD@livestream-z1-prod.arlo.com:443",
        "domain":"livestream-z1-prod.arlo.com","port":443,"conferenceId":null,
        "password":"0123456789abcdef0123456789abcdef",
        "deviceId":"A0A0000YA0D00","callId":"0123456789abcdef0123456789abcdefD"},
      "iceServers":{
        "uSessionId":"UXXX-000-00000000!A0000000!1700000000074",
        "data":[
          {"port":"19302","domain":"relay03-z1-prod.ar.arlo.com","type":"stun"},
          {"credential":"dGVzdC1jcmVkZW50aWFsLXZhbHVl","port":"443","domain":"relay03-z1-prod.ar.arlo.com","transport":"tcp","type":"turn","username":"1700000010:UXXX-000-00000000"},
          {"credential":"dGVzdC1jcmVkZW50aWFsLXZhbHVl","port":"443","domain":"relay03-z1-prod.ar.arlo.com","transport":"udp","type":"turn","username":"1700000010:UXXX-000-00000000"}
        ]}
    }"#;

    #[test]
    fn parses_live_sip_info_capture() {
        let s: SipInfo = serde_json::from_str(SAMPLE).expect("parses");
        assert_eq!(s.sip_call_info.device_id, "A0A0000YA0D00");
        assert_eq!(s.sip_call_info.port, 443);
        assert_eq!(s.sip_call_info.password, "0123456789abcdef0123456789abcdef");
        assert!(s.sip_call_info.callee_uri.starts_with("sip:A0A0000YA0D00_"));
        assert_eq!(s.sip_call_info.conference_id, None);

        assert_eq!(s.ice_servers.data.len(), 3);
        let stun = &s.ice_servers.data[0];
        assert_eq!(stun.kind, "stun");
        assert_eq!(stun.url(), "stun:relay03-z1-prod.ar.arlo.com:19302");
        let turn = &s.ice_servers.data[1];
        assert_eq!(turn.kind, "turn");
        assert_eq!(turn.transport.as_deref(), Some("tcp"));
        assert_eq!(
            turn.url(),
            "turn:relay03-z1-prod.ar.arlo.com:443?transport=tcp"
        );
        assert!(turn.username.is_some() && turn.credential.is_some());
    }

    #[test]
    fn derives_ws_url_on_port_7443() {
        let s: SipInfo = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(
            s.sip_call_info.ws_domain(),
            "livestream-z1-prod.arlo.com:7443"
        );
        assert_eq!(
            s.sip_call_info.ws_url(),
            "wss://livestream-z1-prod.arlo.com:7443/"
        );
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn ice_server_debug_redacts_turn_credential() {
        let ice = IceServer {
            kind: "turn".into(),
            domain: "relay.example".into(),
            port: "443".into(),
            transport: Some("tcp".into()),
            username: Some("1:U".into()),
            credential: Some("TURN-SECRET".into()),
        };
        let dbg = format!("{ice:?}");
        assert!(
            dbg.contains("relay.example") && !dbg.contains("TURN-SECRET"),
            "{dbg}"
        );
    }
}
