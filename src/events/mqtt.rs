//! MQTT-over-WebSocket event listener — the v3 replacement for the
//! legacy SSE `/hmsweb/client/subscribe` channel (which now 403s).
//!
//! Wire protocol reverse-engineered from a live `my.arlo.com` capture:
//!
//! - WSS to `<mqttUrl>/mqtt`, `Sec-WebSocket-Protocol: mqtt`, header
//!   `Origin: https://my.arlo.com`.
//! - MQTT 3.1.1, clean session, keep-alive 60 s. `CONNECT` carries
//!   `clientId = user_<userId>_<rand>`, `username = <userId>`,
//!   `password = <accessToken>`.
//! - `SUBSCRIBE` (QoS 0) to the web client's fine-grained per-resource
//!   topics keyed by `xCloudId` (see [`subscription_topics`]) plus
//!   `u/<userId>/in/#`. The broad `d/<xCloudId>/out/#` wildcard is
//!   owner-only (shared accounts get SUBACK `0x80`).
//! - Inbound `PUBLISH` payloads are JSON identical in shape to the old
//!   SSE events, so [`super::dispatch_payload`] is reused verbatim.

use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use mqttbytes::QoS;
use mqttbytes::v4::{Connect, Login, Packet, Subscribe, SubscribeFilter};
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{Instrument, error, info, info_span, warn};

use crate::error::ArloError;
use crate::models::api::Device;
use crate::models::events::ArloEvent;

use super::{ConnectionState, dispatch_payload};

/// Per-device resource sub-topics the Arlo web client subscribes to
/// (besides the device-class topic). The broker's ACL grants these
/// individually to shared users; the broad `out/#` wildcard is
/// **owner-only** (SUBACK `0x80` for non-owners).
const PER_DEVICE_RESOURCES: [&str; 14] = [
    "wifi",
    "subscriptions",
    "audioPlayback",
    "modes",
    "basestation",
    "siren",
    "devices",
    "storage",
    "schedule",
    "diagnostics",
    "automationRevisionUpdate",
    "audio",
    "activeAutomations",
    "lte",
];

/// Wire resource segment for a device's own events
/// (`d/<xc>/out/<class>/<deviceId>/#`). `None` for device types whose
/// events only surface under the generic `basestation` topic.
fn device_class(device_type: &str) -> Option<&'static str> {
    match device_type {
        "camera" => Some("cameras"),
        "doorbell" => Some("doorbells"),
        "chime" => Some("chimes"),
        _ => None,
    }
}

/// Builds the MQTT subscription filters, replicating the Arlo web
/// client's **fine-grained** topic set (verified against a live shared-
/// account HAR where all 61 filters were SUBACK-granted):
///
/// - `d/<xCloudId>/out/<class>/<deviceId>/#` per device (`cameras`/
///   `doorbells`/`chimes`) — this carries motion / `is` events.
/// - `d/<xCloudId>/out/<resource>/#` for each [`PER_DEVICE_RESOURCES`].
/// - `u/<userId>/in/#`.
///
/// IMPORTANT: device events publish on the device's **`xCloudId`**, not
/// its `deviceId`, and the broad `d/<xCloudId>/out/#` wildcard is
/// rejected for shared (non-owner) accounts — only these explicit
/// sub-topics are authorized. Result is sorted + deduped for a stable
/// SUBSCRIBE packet.
pub(crate) fn subscription_topics(devices: &[Device], user_id: &str) -> Vec<String> {
    // Preferred: the broker's own ACL grant per device (`allowedMqttTopics`
    // on the v2 device list) — authoritative for owner and shared
    // accounts alike, as the reference client subscribes.
    let mut topics: Vec<String> = devices
        .iter()
        .flat_map(|d| d.allowed_mqtt_topics.iter().cloned())
        .collect();
    if topics.is_empty() {
        topics = hand_built_topics(devices);
    }
    topics.push(format!("u/{user_id}/in/#"));
    topics.sort();
    topics.dedup();
    topics
}

/// Fallback topic set for device lists without `allowedMqttTopics`
/// (legacy endpoint), replicating the web client's fine-grained
/// subscriptions verified against a shared-account HAR.
fn hand_built_topics(devices: &[Device]) -> Vec<String> {
    let mut topics: Vec<String> = Vec::new();
    for d in devices {
        let Some(xcloud) = d.x_cloud_id.as_deref() else {
            continue;
        };
        if let Some(class) = device_class(&d.device_type) {
            topics.push(format!("d/{xcloud}/out/{class}/{}/#", d.device_id));
        }
        for res in PER_DEVICE_RESOURCES {
            topics.push(format!("d/{xcloud}/out/{res}/#"));
        }
    }
    topics
}

/// Backoff between reconnect attempts. Mirrors the old SSE listener.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);
/// MQTT `CONNECT` keep-alive, in seconds (matches the web client).
const KEEP_ALIVE_SECS: u16 = 60;
/// Send a `PINGREQ` at half the keep-alive so the broker never times us out.
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// Hard cap on a single decoded MQTT packet (defensive; events are tiny).
const MAX_PACKET_BYTES: usize = 256 * 1024;
/// Origin the Arlo web client sends on the WS upgrade.
const WS_ORIGIN: &str = "https://my.arlo.com";

/// Everything the listener needs, resolved once by `ArloClient::events`.
#[derive(Debug, Clone)]
pub(crate) struct MqttParams {
    /// Broker base, e.g. `wss://mqtt-cluster-z1-1.arloxcld.com:8084`
    /// (from `session/v3`'s `mqttUrl`). `/mqtt` is appended here.
    pub mqtt_url: String,
    pub user_id: String,
    pub access_token: String,
    /// Topic filters to subscribe, built by [`subscription_topics`]
    /// (fine-grained per-resource, keyed by `xCloudId`, + user inbox).
    pub topics: Vec<String>,
}

/// Spawns the reconnecting MQTT listener. Public API parity with the
/// old `spawn_sse_listener`: it never returns; `Drop` on the owning
/// `EventBus` aborts it.
pub(crate) fn spawn_mqtt_listener(
    params: MqttParams,
    sender: broadcast::Sender<ArloEvent>,
    state_tx: watch::Sender<ConnectionState>,
) -> JoinHandle<()> {
    tokio::spawn(
        async move {
            loop {
                let _ = state_tx.send(ConnectionState::Connecting);
                match run_session(&params, &sender, &state_tx).await {
                    Ok(()) => warn!("MQTT stream ended; reconnecting"),
                    Err(e) => error!(error = %e, "MQTT connection error"),
                }
                let _ = state_tx.send(ConnectionState::Disconnected);
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
        }
        .instrument(info_span!("mqtt_listener")),
    )
}

/// One full connect → subscribe → pump cycle. Returns `Ok(())` on a
/// clean stream end (triggers reconnect), `Err` on a hard failure.
async fn run_session(
    params: &MqttParams,
    sender: &broadcast::Sender<ArloEvent>,
    state_tx: &watch::Sender<ConnectionState>,
) -> Result<(), ArloError> {
    let url = format!("{}/mqtt", params.mqtt_url.trim_end_matches('/'));
    info!(%url, "Connecting to MQTT-over-WSS event bus");

    let request = build_ws_request(&url)?;
    let (mut ws, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| ArloError::ScraperError(format!("WSS connect failed: {e}")))?;

    // -- MQTT CONNECT --
    ws.send(Message::Binary(encode(&connect_packet(params))?.into()))
        .await
        .map_err(|e| ArloError::ScraperError(format!("CONNECT send failed: {e}")))?;

    let mut rx_buf = BytesMut::new();
    wait_for_connack(&mut ws, &mut rx_buf).await?;
    let _ = state_tx.send(ConnectionState::Connected);
    info!("MQTT connected");

    // -- SUBSCRIBE --
    info!(
        topic_count = params.topics.len(),
        topics = ?params.topics,
        "MQTT SUBSCRIBE (fine-grained per-resource; broad out/# is owner-only)"
    );
    ws.send(Message::Binary(
        encode(&subscribe_packet(&params.topics))?.into(),
    ))
    .await
    .map_err(|e| ArloError::ScraperError(format!("SUBSCRIBE send failed: {e}")))?;

    // -- Pump: inbound PUBLISH ↔ periodic PINGREQ --
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ping.tick() => {
                let mut b = BytesMut::new();
                mqttbytes::v4::PingReq
                    .write(&mut b)
                    .map_err(|e| ArloError::ScraperError(format!("PINGREQ encode: {e}")))?;
                if ws.send(Message::Binary(b.into())).await.is_err() {
                    return Ok(()); // socket gone → reconnect
                }
            }
            msg = ws.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        rx_buf.extend_from_slice(&data);
                        drain_packets(&mut rx_buf, sender);
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = ws.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => {} // text/pong/frame — Arlo only sends binary
                    Some(Err(e)) => {
                        return Err(ArloError::ScraperError(format!("WSS read: {e}")));
                    }
                }
            }
        }
    }
}

/// Builds the WS upgrade request with Arlo's non-standard extras: the
/// `Origin` header and the `mqtt` subprotocol. The standard handshake
/// headers (`Sec-WebSocket-Key`, etc.) are filled by tungstenite.
fn build_ws_request(
    url: &str,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, ArloError> {
    let mut req = url
        .into_client_request()
        .map_err(|e| ArloError::ScraperError(format!("bad mqtt url '{url}': {e}")))?;
    let headers = req.headers_mut();
    headers.insert(
        ORIGIN,
        WS_ORIGIN
            .parse()
            .map_err(|_| ArloError::ScraperError("invalid Origin".into()))?,
    );
    headers.insert(
        SEC_WEBSOCKET_PROTOCOL,
        "mqtt"
            .parse()
            .map_err(|_| ArloError::ScraperError("invalid subprotocol".into()))?,
    );
    Ok(req)
}

/// MQTT 3.1.1 `CONNECT`: clientId `user_<uid>_<rand>`, username `<uid>`,
/// password `<accessToken>`, clean session, 60 s keep-alive.
fn connect_packet(p: &MqttParams) -> Connect {
    let rand = uuid::Uuid::new_v4().as_u128() % 10_000_000_000;
    let mut c = Connect::new(format!("user_{}_{rand}", p.user_id));
    c.keep_alive = KEEP_ALIVE_SECS;
    c.clean_session = true;
    c.login = Some(Login {
        username: p.user_id.clone(),
        password: p.access_token.clone(),
    });
    c
}

fn subscribe_packet(topics: &[String]) -> Subscribe {
    let filters: Vec<SubscribeFilter> = topics
        .iter()
        .map(|t| SubscribeFilter::new(t.clone(), QoS::AtMostOnce))
        .collect();
    Subscribe::new_many(filters)
}

fn encode<P: MqttWritable>(packet: &P) -> Result<BytesMut, ArloError> {
    let mut buf = BytesMut::new();
    packet
        .write_to(&mut buf)
        .map_err(|e| ArloError::ScraperError(format!("MQTT encode: {e}")))?;
    Ok(buf)
}

/// Tiny seam so `encode` works for both `Connect` and `Subscribe`
/// without leaking `mqttbytes::Error` into our signatures.
trait MqttWritable {
    fn write_to(&self, buf: &mut BytesMut) -> Result<usize, mqttbytes::Error>;
}
impl MqttWritable for Connect {
    fn write_to(&self, buf: &mut BytesMut) -> Result<usize, mqttbytes::Error> {
        self.write(buf)
    }
}
impl MqttWritable for Subscribe {
    fn write_to(&self, buf: &mut BytesMut) -> Result<usize, mqttbytes::Error> {
        self.write(buf)
    }
}

async fn wait_for_connack<S>(ws: &mut S, rx_buf: &mut BytesMut) -> Result<(), ArloError>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    while let Some(msg) = ws.next().await {
        let msg = msg.map_err(|e| ArloError::ScraperError(format!("WSS read: {e}")))?;
        if let Message::Binary(data) = msg {
            rx_buf.extend_from_slice(&data);
            while let Some(packet) = next_packet(rx_buf)? {
                if let Packet::ConnAck(ack) = packet {
                    if ack.code == mqttbytes::v4::ConnectReturnCode::Success {
                        return Ok(());
                    }
                    return Err(ArloError::AuthError(format!(
                        "MQTT CONNECT refused: {:?}",
                        ack.code
                    )));
                }
            }
        }
    }
    Err(ArloError::ScraperError("WSS closed before CONNACK".into()))
}

/// Decode and route every complete packet currently buffered.
fn drain_packets(rx_buf: &mut BytesMut, sender: &broadcast::Sender<ArloEvent>) {
    loop {
        match next_packet(rx_buf) {
            Ok(Some(Packet::Publish(p))) => {
                info!(topic = %p.topic, bytes = p.payload.len(), "MQTT event received");
                match std::str::from_utf8(&p.payload) {
                    Ok(json) => dispatch_payload(json, sender),
                    Err(_) => warn!(topic = %p.topic, "non-UTF8 MQTT payload; dropped"),
                }
            }
            Ok(Some(Packet::SubAck(ack))) => {
                info!(codes = ?ack.return_codes, "MQTT SUBACK");
            }
            Ok(Some(_)) => {}  // PingResp / etc. — nothing to route
            Ok(None) => break, // need more bytes
            Err(e) => {
                error!(error = %e, "MQTT decode error; clearing buffer");
                rx_buf.clear();
                break;
            }
        }
    }
}

/// `Ok(None)` means "need more bytes"; other decode errors propagate.
fn next_packet(rx_buf: &mut BytesMut) -> Result<Option<Packet>, ArloError> {
    match mqttbytes::v4::read(rx_buf, MAX_PACKET_BYTES) {
        Ok(p) => Ok(Some(p)),
        Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
        Err(e) => Err(ArloError::ScraperError(format!("MQTT decode: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> MqttParams {
        MqttParams {
            mqtt_url: "wss://mqtt-cluster-z1-1.arloxcld.com:8084".into(),
            user_id: "UXXX-000-00000000".into(),
            access_token: "TOK".into(),
            topics: vec![
                "d/A0A0000YA0D00/out/#".into(),
                "u/UXXX-000-00000000/in/#".into(),
            ],
        }
    }

    #[test]
    fn connect_packet_matches_web_client_shape() {
        let c = connect_packet(&params());
        assert!(c.client_id.starts_with("user_UXXX-000-00000000_"));
        assert!(c.clean_session);
        assert_eq!(c.keep_alive, 60);
        let login = c.login.expect("login present");
        assert_eq!(login.username, "UXXX-000-00000000");
        assert_eq!(login.password, "TOK");
    }

    #[test]
    fn connect_packet_round_trips_through_mqtt_codec() {
        let mut buf = encode(&connect_packet(&params())).expect("encode");
        // First byte 0x10 = CONNECT control packet.
        assert_eq!(buf[0] & 0xF0, 0x10);
        let pkt = mqttbytes::v4::read(&mut buf, MAX_PACKET_BYTES).expect("decode");
        assert!(matches!(pkt, Packet::Connect(_)));
    }

    #[test]
    fn subscribe_packet_carries_all_topics_qos0() {
        let mut buf = encode(&subscribe_packet(&params().topics)).expect("encode");
        assert_eq!(buf[0] & 0xF0, 0x80); // SUBSCRIBE
        let pkt = mqttbytes::v4::read(&mut buf, MAX_PACKET_BYTES).expect("decode");
        let Packet::Subscribe(s) = pkt else {
            panic!("expected SUBSCRIBE");
        };
        let paths: Vec<_> = s.filters.iter().map(|f| f.path.clone()).collect();
        assert!(paths.contains(&"d/A0A0000YA0D00/out/#".to_string()));
        assert!(paths.contains(&"u/UXXX-000-00000000/in/#".to_string()));
        assert!(s.filters.iter().all(|f| f.qos == QoS::AtMostOnce));
    }

    #[test]
    fn drain_routes_publish_payload_as_arlo_event() {
        // Exact PUBLISH bytes from the live HAR capture (topic +
        // JSON body identical in shape to the old SSE events).
        let topic = "d/RXXXXXXX-0000-000-000000000/out/basestation/is";
        let json = r#"{"from":"A0A0000YA0D00","to":"UXXX-000-00000000","transId":"f2a1985","action":"is","resource":"basestation","properties":{"connectionState":"available"}}"#;
        let publish = mqttbytes::v4::Publish::new(topic, QoS::AtMostOnce, json);
        let mut buf = BytesMut::new();
        publish.write(&mut buf).expect("encode publish");

        let (tx, mut rx) = broadcast::channel::<ArloEvent>(8);
        drain_packets(&mut buf, &tx);

        let ev = rx.try_recv().expect("an event was routed");
        assert_eq!(ev.action, "is");
        assert_eq!(ev.resource, "basestation");
        assert_eq!(ev.source.as_deref(), Some("A0A0000YA0D00"));
        assert_eq!(ev.trans_id.as_deref(), Some("f2a1985"));
    }

    #[test]
    fn subscription_topics_prefer_the_brokers_allowed_list() {
        let devices: Vec<Device> = serde_json::from_str(
            r#"[
            {"deviceId":"A","parentId":"A","deviceType":"camera","deviceName":"a",
             "uniqueId":"u1","state":"provisioned","xCloudId":"XC-A",
             "allowedMqttTopics":["d/XC-A/out/cameras/A/#","d/XC-A/out/wifi/#"]},
            {"deviceId":"B","parentId":"B","deviceType":"doorbell","deviceName":"b",
             "uniqueId":"u2","state":"provisioned","xCloudId":"XC-B"}
        ]"#,
        )
        .expect("devices parse");

        let topics = subscription_topics(&devices, "U1");
        // Exactly the granted topics plus the user inbox — the hand-built
        // set (which would add 14 resources per device) is not mixed in.
        assert_eq!(
            topics,
            vec![
                "d/XC-A/out/cameras/A/#".to_string(),
                "d/XC-A/out/wifi/#".to_string(),
                "u/U1/in/#".to_string(),
            ]
        );
    }

    #[test]
    fn subscription_topics_use_xcloud_id_not_device_id() {
        // Shapes from the live /v2/users/devices capture.
        let devices: Vec<Device> = serde_json::from_str(
            r#"[
            {"deviceId":"A0A0000YA0D00","parentId":"A0A0000YA0D00","deviceType":"camera",
             "deviceName":"liv","uniqueId":"u1","state":"provisioned",
             "xCloudId":"RXXXXXXX-0000-000-000000000"},
            {"deviceId":"ABT00AK0000B0","parentId":"ABT00AK0000B0","deviceType":"doorbell",
             "deviceName":"door","uniqueId":"u2","state":"provisioned",
             "xCloudId":"XXXXXXX-0000-000-000000000"},
            {"deviceId":"NOXCLOUD","parentId":"NOXCLOUD","deviceType":"chime",
             "deviceName":"c","uniqueId":"u3","state":"provisioned"}
        ]"#,
        )
        .expect("devices parse");

        let topics = subscription_topics(&devices, "UXXX-000-00000000");

        // Device-class topic carries motion/`is` events (xCloudId for the
        // broker key, deviceId inside the resource path).
        assert!(
            topics
                .contains(&"d/RXXXXXXX-0000-000-000000000/out/cameras/A0A0000YA0D00/#".to_string())
        );
        assert!(
            topics.contains(
                &"d/XXXXXXX-0000-000-000000000/out/doorbells/ABT00AK0000B0/#".to_string()
            )
        );
        // Fine-grained per-resource topics (a sample).
        assert!(topics.contains(&"d/RXXXXXXX-0000-000-000000000/out/basestation/#".to_string()));
        assert!(topics.contains(&"d/RXXXXXXX-0000-000-000000000/out/wifi/#".to_string()));
        assert!(topics.contains(&"u/UXXX-000-00000000/in/#".to_string()));
        // The broad owner-only wildcard must NOT be used (shared-user 0x80).
        assert!(
            !topics
                .iter()
                .any(|t| t == "d/RXXXXXXX-0000-000-000000000/out/#")
        );
        // The xCloudId is the broker key, never the deviceId, at topic root.
        assert!(!topics.iter().any(|t| t.starts_with("d/A0A0000YA0D00/")));
        // A device without an xCloudId contributes nothing.
        assert!(!topics.iter().any(|t| t.contains("NOXCLOUD")));
    }

    #[test]
    fn next_packet_returns_none_on_partial_buffer() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x30, 0x7f]); // PUBLISH header claiming 127 bytes
        assert!(next_packet(&mut buf).expect("no hard error").is_none());
    }
}
