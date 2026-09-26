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
use mqttbytes::v4::{Connect, Login, Packet, Subscribe, SubscribeFilter, SubscribeReasonCode};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tracing::{Instrument, debug, error, info, info_span, warn};

use crate::client::ws::{WsConnector, WsMessage as Message};
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
    // The broker enforces authorization; this only drops filters that are
    // malformed or outside the namespaces this client has any business in.
    topics.retain(|t| {
        let ok = crate::models::validate::mqtt_filter_ok(t, user_id);
        if !ok {
            warn!(filter = ?t, "dropping malformed MQTT topic filter from device list");
        }
        ok
    });
    topics.sort();
    topics.dedup();
    topics.truncate(MAX_TOPIC_FILTERS);
    topics
}

/// Upper bound on the SUBSCRIBE list; a real account has a few dozen.
const MAX_TOPIC_FILTERS: usize = 256;

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

/// Deadline for each half of the broker handshake: the WebSocket dial and
/// the wait for CONNACK. A broker that accepts the upgrade and never
/// answers CONNECT would otherwise park the listener in `Connecting`
/// forever, with no reconnect.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Reconnect backoff: starts here, doubles per consecutive failure with
/// ±20 % jitter, and is capped at [`RECONNECT_BACKOFF_MAX`]. A refused
/// CONNACK jumps straight to the cap: a revoked token does not become
/// valid by asking every five seconds (that was ~17 000 failed broker
/// logins a day), and a token refresh wakes the loop early anyway.
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(5);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(300);
/// Consecutive failures after which the backoff has reached the cap.
const BACKOFF_CAP_FAILURES: u32 = 6;
/// Inbound silence after which the socket is presumed half-open. The
/// broker answers every PINGREQ, so 1.5 × keep-alive of nothing means the
/// path is dead even though `ws.next()` still pends.
const IDLE_TIMEOUT: Duration = Duration::from_secs((KEEP_ALIVE_SECS as u64) * 3 / 2);
/// Packet identifier of our single SUBSCRIBE (MQTT-2.3.1-1 forbids 0).
const SUBSCRIBE_PKID: u16 = 1;
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
    /// MQTT password, read at every CONNECT so a re-authenticated token
    /// is used on the next reconnect. `None` while logged out.
    pub token: watch::Receiver<Option<SecretString>>,
    /// Topic filters to subscribe, built by [`subscription_topics`]
    /// (fine-grained per-resource, keyed by `xCloudId`, + user inbox).
    pub topics: Vec<String>,
}

/// Spawns the reconnecting MQTT listener. Public API parity with the
/// old `spawn_sse_listener`: it never returns; `Drop` on the owning
/// `EventBus` aborts it.
pub(crate) fn spawn_mqtt_listener(
    params: MqttParams,
    ws: Arc<dyn WsConnector>,
    sender: broadcast::Sender<ArloEvent>,
    state_tx: watch::Sender<ConnectionState>,
) -> JoinHandle<()> {
    tokio::spawn(
        async move {
            let mut failures: u32 = 0;
            let mut refused_logged = false;
            let mut token_rx = params.token.clone();
            loop {
                let _ = state_tx.send(ConnectionState::Connecting);
                token_rx.mark_unchanged();
                let outcome = run_session(&params, ws.as_ref(), &sender, &state_tx).await;
                let was_connected = *state_tx.borrow() == ConnectionState::Connected;
                let _ = state_tx.send(ConnectionState::Disconnected);

                let mut refused = false;
                match outcome {
                    Ok(()) if was_connected => {
                        failures = 0;
                        refused_logged = false;
                        warn!("MQTT stream ended; reconnecting");
                    }
                    Ok(()) => {
                        failures = failures.saturating_add(1);
                        warn!("MQTT stream ended before it was connected; reconnecting");
                    }
                    Err(ArloError::AuthError(e)) => {
                        refused = true;
                        failures = failures.max(BACKOFF_CAP_FAILURES);
                        if !refused_logged {
                            error!(
                                error = %e,
                                "MQTT broker refused the session; retrying at the maximum backoff until the token is refreshed"
                            );
                            refused_logged = true;
                        }
                    }
                    Err(e) => {
                        failures = failures.saturating_add(1);
                        error!(error = %e, failures, "MQTT connection error");
                    }
                }

                let delay = next_backoff(failures);
                if refused {
                    // Sleep the full backoff, or reconnect as soon as a
                    // re-authentication publishes a new token.
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        changed = token_rx.changed() => {
                            if changed.is_ok() {
                                info!("access token refreshed; reconnecting the event bus now");
                            }
                        }
                    }
                } else {
                    tokio::time::sleep(delay).await;
                }
            }
        }
        .instrument(info_span!("mqtt_listener")),
    )
}

/// Exponential backoff with ±20 % jitter: `MIN · 2^failures`, capped at
/// [`RECONNECT_BACKOFF_MAX`]. Jitter keeps a fleet of clients from
/// reconnecting in lockstep after a broker restart.
fn next_backoff(failures: u32) -> Duration {
    let exp = failures.min(BACKOFF_CAP_FAILURES);
    let base = RECONNECT_BACKOFF_MIN
        .saturating_mul(1u32 << exp)
        .min(RECONNECT_BACKOFF_MAX);
    // 0.8 ..= 1.2, from the same CSPRNG the client ids come from.
    let jitter = 0.8 + (uuid::Uuid::new_v4().as_u128() % 401) as f64 / 1000.0;
    base.mul_f64(jitter).min(RECONNECT_BACKOFF_MAX)
}

/// One full connect → subscribe → pump cycle. Returns `Ok(())` on a
/// clean stream end (triggers reconnect), `Err` on a hard failure.
async fn run_session(
    params: &MqttParams,
    connector: &dyn WsConnector,
    sender: &broadcast::Sender<ArloEvent>,
    state_tx: &watch::Sender<ConnectionState>,
) -> Result<(), ArloError> {
    let url = format!("{}/mqtt", params.mqtt_url.trim_end_matches('/'));
    info!(%url, "Connecting to MQTT-over-WSS event bus");

    // Arlo's non-standard upgrade extras: `Origin` + the `mqtt` subprotocol.
    let mut ws = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connector.connect(&url, WS_ORIGIN, "mqtt"),
    )
    .await
    .map_err(|_| ArloError::Timeout(format!("MQTT WSS dial exceeded {HANDSHAKE_TIMEOUT:?}")))??;

    // -- MQTT CONNECT --
    ws.send(Message::Binary(encode(&connect_packet(params)?)?.into()))
        .await
        .map_err(|e| ArloError::ScraperError(format!("CONNECT send failed: {e}")))?;

    let mut rx_buf = BytesMut::new();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, wait_for_connack(&mut ws, &mut rx_buf))
        .await
        .map_err(|_| {
            ArloError::Timeout(format!(
                "MQTT CONNACK not received within {HANDSHAKE_TIMEOUT:?}"
            ))
        })??;
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
    let mut last_rx = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = ping.tick() => {
                if last_rx.elapsed() > IDLE_TIMEOUT {
                    warn!(
                        idle_secs = last_rx.elapsed().as_secs(),
                        "no inbound MQTT traffic (not even PINGRESP); socket presumed half-open, reconnecting"
                    );
                    return Ok(());
                }
                let mut b = BytesMut::new();
                mqttbytes::v4::PingReq
                    .write(&mut b)
                    .map_err(|e| ArloError::ScraperError(format!("PINGREQ encode: {e}")))?;
                if ws.send(Message::Binary(b.into())).await.is_err() {
                    return Ok(()); // socket gone → reconnect
                }
            }
            msg = ws.next() => {
                if matches!(msg, Some(Ok(_))) {
                    last_rx = tokio::time::Instant::now();
                }
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if rx_buf.len() + data.len() > MAX_PACKET_BYTES {
                            return Err(ArloError::ScraperError(
                                "MQTT frame exceeds MAX_PACKET_BYTES".into(),
                            ));
                        }
                        rx_buf.extend_from_slice(&data);
                        drain_packets(&mut rx_buf, sender, &params.topics)?;
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

/// MQTT 3.1.1 `CONNECT`: clientId `user_<uid>_<rand>`, username `<uid>`,
/// password `<accessToken>`, clean session, 60 s keep-alive.
fn connect_packet(p: &MqttParams) -> Result<Connect, ArloError> {
    let token = p.token.borrow().clone().ok_or_else(|| {
        ArloError::AuthError("no access token for MQTT CONNECT (logged out)".into())
    })?;
    let rand = uuid::Uuid::new_v4().as_u128() % 10_000_000_000;
    let mut c = Connect::new(format!("user_{}_{rand}", p.user_id));
    c.keep_alive = KEEP_ALIVE_SECS;
    c.clean_session = true;
    c.login = Some(Login {
        username: p.user_id.clone(),
        password: token.expose_secret().to_string(),
    });
    Ok(c)
}

fn subscribe_packet(topics: &[String]) -> Subscribe {
    let filters: Vec<SubscribeFilter> = topics
        .iter()
        .map(|t| SubscribeFilter::new(t.clone(), QoS::AtMostOnce))
        .collect();
    let mut subscribe = Subscribe::new_many(filters);
    subscribe.pkid = SUBSCRIBE_PKID;
    subscribe
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
    S: StreamExt<Item = Result<Message, crate::client::ws::WsError>> + Unpin,
{
    while let Some(msg) = ws.next().await {
        let msg = msg.map_err(|e| ArloError::ScraperError(format!("WSS read: {e}")))?;
        if let Message::Binary(data) = msg {
            if rx_buf.len() + data.len() > MAX_PACKET_BYTES {
                return Err(ArloError::ScraperError(
                    "MQTT frame exceeds MAX_PACKET_BYTES".into(),
                ));
            }
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

/// Decode and route every complete packet currently buffered. A decode
/// error ends the session (the stream is desynchronised; a clean
/// reconnect is the only recovery), and a SUBACK that rejects every
/// filter is an [`ArloError::AuthError`]: `Connected` with no
/// subscriptions would deliver nothing, silently.
fn drain_packets(
    rx_buf: &mut BytesMut,
    sender: &broadcast::Sender<ArloEvent>,
    topics: &[String],
) -> Result<(), ArloError> {
    loop {
        match next_packet(rx_buf)? {
            Some(Packet::Publish(p)) => {
                debug!(topic = ?p.topic, bytes = p.payload.len(), "MQTT event received");
                match std::str::from_utf8(&p.payload) {
                    Ok(json) => dispatch_payload(json, sender),
                    Err(_) => warn!(topic = ?p.topic, "non-UTF8 MQTT payload; dropped"),
                }
            }
            Some(Packet::SubAck(ack)) => {
                if ack.pkid != SUBSCRIBE_PKID {
                    warn!(pkid = ack.pkid, "SUBACK for a packet id we never sent");
                }
                let rejected: Vec<&str> = ack
                    .return_codes
                    .iter()
                    .zip(topics)
                    .filter(|(code, _)| matches!(code, SubscribeReasonCode::Failure))
                    .map(|(_, topic)| topic.as_str())
                    .collect();
                if !rejected.is_empty() {
                    warn!(?rejected, "broker rejected MQTT subscriptions");
                }
                if !ack.return_codes.is_empty() && rejected.len() == ack.return_codes.len() {
                    return Err(ArloError::AuthError(
                        "broker rejected every MQTT subscription".into(),
                    ));
                }
                info!(
                    granted = ack.return_codes.len() - rejected.len(),
                    "MQTT SUBACK"
                );
            }
            Some(_) => {}          // PingResp / etc. — nothing to route
            None => return Ok(()), // need more bytes
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
            token: watch::channel(Some(SecretString::from("TOK"))).1,
            topics: vec![
                "d/A0A0000YA0D00/out/#".into(),
                "u/UXXX-000-00000000/in/#".into(),
            ],
        }
    }

    #[test]
    fn connect_packet_matches_web_client_shape() {
        let c = connect_packet(&params()).expect("token present");
        assert!(c.client_id.starts_with("user_UXXX-000-00000000_"));
        assert!(c.clean_session);
        assert_eq!(c.keep_alive, 60);
        let login = c.login.expect("login present");
        assert_eq!(login.username, "UXXX-000-00000000");
        assert_eq!(login.password, "TOK");
    }

    #[test]
    fn connect_packet_round_trips_through_mqtt_codec() {
        let mut buf = encode(&connect_packet(&params()).expect("token present")).expect("encode");
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
        drain_packets(&mut buf, &tx, &[]).expect("drains cleanly");

        let ev = rx.try_recv().expect("an event was routed");
        assert_eq!(ev.action, "is");
        assert_eq!(ev.resource, "basestation");
        assert_eq!(ev.source.as_deref(), Some("A0A0000YA0D00"));
        assert_eq!(ev.trans_id.as_deref(), Some("f2a1985"));
    }

    fn packet_bytes(
        write: impl FnOnce(&mut BytesMut) -> Result<usize, mqttbytes::Error>,
    ) -> Message {
        let mut buf = BytesMut::new();
        write(&mut buf).expect("SAFETY: test packet encodes");
        Message::Binary(buf.freeze())
    }

    #[tokio::test]
    async fn listener_connects_subscribes_and_routes_publish_over_the_ws_port() {
        use crate::client::ws::test_support::MockWsConnector;
        use mqttbytes::v4::{ConnAck, ConnectReturnCode, Publish, SubAck, SubscribeReasonCode};
        use std::time::Duration;

        let ws = Arc::new(MockWsConnector::new());
        ws.script(vec![
            packet_bytes(|b| ConnAck::new(ConnectReturnCode::Success, false).write(b)),
            packet_bytes(|b| {
                SubAck::new(1, vec![SubscribeReasonCode::Success(QoS::AtMostOnce)]).write(b)
            }),
            packet_bytes(|b| {
                Publish::new(
                    "d/XC/out/cameras/A0A0000YA0D00/motionDetected",
                    QoS::AtMostOnce,
                    r#"{"action":"is","resource":"cameras/A0A0000YA0D00","properties":{"motionDetected":true}}"#,
                )
                .write(b)
            }),
            Message::Close(None),
        ]);

        let bus = super::super::EventBus::start(params(), ws.clone())
            .await
            .expect("bus starts");
        let mut rx = bus.subscribe();
        ws.release(); // frames replay only once we are subscribed

        let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("event within 5 s")
            .expect("event routed");
        assert_eq!(event.resource, "cameras/A0A0000YA0D00");

        // Handshake extras + the two MQTT control packets we send.
        let (url, origin, proto) = ws.connects().first().cloned().expect("one connect");
        assert_eq!(url, "wss://mqtt-cluster-z1-1.arloxcld.com:8084/mqtt");
        assert_eq!(origin, WS_ORIGIN);
        assert_eq!(proto, "mqtt");
        let sent = ws.sent();
        let decode = |m: &Message| match m {
            Message::Binary(b) => {
                let mut buf = BytesMut::from(&b[..]);
                mqttbytes::v4::read(&mut buf, MAX_PACKET_BYTES)
                    .expect("SAFETY: test packet decodes")
            }
            other => panic!("expected binary frame, got {other:?}"),
        };
        assert!(
            matches!(decode(&sent[0]), Packet::Connect(c) if c.login.as_ref().is_some_and(|l| l.password == "TOK"))
        );
        assert!(matches!(decode(&sent[1]), Packet::Subscribe(s) if s.filters.len() == 2));
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

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn malformed_allowed_topics_are_dropped() {
        let device: Device = serde_json::from_str(
            r##"{"deviceId":"A0A0000YA0D00","parentId":"A0A0000YA0D00","deviceType":"camera",
                "deviceName":"n","uniqueId":"u","state":"provisioned",
                "allowedMqttTopics":["#","d/x/out/../#","d/x\u0000/out/#","u/OTHER/in/#",
                                     "d/RXXXXXXX-0000-000-000000000/out/cameras/A0A0000YA0D00/#"]}"##,
        )
        .unwrap();
        let topics = subscription_topics(&[device], "UXXX-000-00000000");
        assert_eq!(
            topics,
            vec![
                "d/RXXXXXXX-0000-000-000000000/out/cameras/A0A0000YA0D00/#".to_string(),
                "u/UXXX-000-00000000/in/#".to_string(),
            ]
        );
    }
}

#[cfg(test)]
mod handshake_timeout_tests {
    use super::*;
    use crate::client::ws::test_support::MockWsConnector;
    use std::sync::Arc;

    fn params() -> MqttParams {
        MqttParams {
            mqtt_url: "wss://mqtt-cluster-z1-1.arloxcld.com:8084".into(),
            user_id: "UXXX-000-00000000".into(),
            token: watch::channel(Some(SecretString::from("TOK"))).1,
            topics: vec!["u/UXXX-000-00000000/in/#".into()],
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_broker_times_out_instead_of_parking_the_listener() {
        // No scripted frames: the socket accepts CONNECT and never answers.
        let ws = Arc::new(MockWsConnector::new());
        let (sender, _rx) = broadcast::channel(8);
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connecting);

        let params = params();
        let (result, ()) = tokio::join!(
            run_session(&params, ws.as_ref(), &sender, &state_tx),
            async { ws.release() }
        );
        let err = result.expect_err("must time out");
        assert!(matches!(err, ArloError::Timeout(_)), "{err}");
        assert_eq!(ws.connects().len(), 1);
        assert_eq!(*state_rx.borrow(), ConnectionState::Connecting);
    }
}

#[cfg(test)]
mod liveness_tests {
    use super::*;
    use crate::client::ws::test_support::MockWsConnector;
    use mqttbytes::v4::{ConnAck, ConnectReturnCode, SubAck};

    fn packet_bytes(
        write: impl FnOnce(&mut BytesMut) -> Result<usize, mqttbytes::Error>,
    ) -> Message {
        let mut b = BytesMut::new();
        write(&mut b).expect("SAFETY: test packet encodes");
        Message::Binary(b.freeze())
    }

    fn params_with(token: watch::Receiver<Option<SecretString>>) -> MqttParams {
        MqttParams {
            mqtt_url: "wss://mqtt-cluster-z1-1.arloxcld.com:8084".into(),
            user_id: "UXXX-000-00000000".into(),
            token,
            topics: vec![
                "u/UXXX-000-00000000/in/#".into(),
                "d/X/out/basestation/#".into(),
            ],
        }
    }

    #[test]
    fn connect_packet_reads_the_latest_token_and_refuses_when_logged_out() {
        let (tx, rx) = watch::channel(Some(SecretString::from("TOK")));
        let p = params_with(rx);
        assert_eq!(connect_packet(&p).unwrap().login.unwrap().password, "TOK");
        tx.send_replace(Some(SecretString::from("TOK-2")));
        assert_eq!(connect_packet(&p).unwrap().login.unwrap().password, "TOK-2");
        tx.send_replace(None);
        assert!(matches!(connect_packet(&p), Err(ArloError::AuthError(_))));
    }

    #[test]
    fn subscribe_packet_has_a_nonzero_packet_id() {
        assert_eq!(
            subscribe_packet(&["d/X/out/#".to_string()]).pkid,
            SUBSCRIBE_PKID
        );
    }

    #[test]
    fn backoff_grows_with_jitter_and_caps() {
        for _ in 0..20 {
            let first = next_backoff(0);
            assert!(
                first >= Duration::from_secs(4) && first <= Duration::from_secs(6),
                "{first:?}"
            );
            assert!(next_backoff(BACKOFF_CAP_FAILURES) <= RECONNECT_BACKOFF_MAX);
            assert!(next_backoff(u32::MAX) <= RECONNECT_BACKOFF_MAX);
        }
        assert!(next_backoff(3) > next_backoff(0) * 3);
    }

    #[test]
    fn drain_fails_the_session_when_every_filter_is_rejected_or_bytes_are_garbage() {
        let (tx, _rx) = broadcast::channel(8);
        let topics = vec!["a/#".to_string(), "b/#".to_string()];
        let mut buf = BytesMut::new();
        SubAck::new(
            SUBSCRIBE_PKID,
            vec![SubscribeReasonCode::Failure, SubscribeReasonCode::Failure],
        )
        .write(&mut buf)
        .unwrap();
        assert!(matches!(
            drain_packets(&mut buf, &tx, &topics),
            Err(ArloError::AuthError(_))
        ));

        let mut buf = BytesMut::new();
        SubAck::new(
            SUBSCRIBE_PKID,
            vec![
                SubscribeReasonCode::Success(QoS::AtMostOnce),
                SubscribeReasonCode::Failure,
            ],
        )
        .write(&mut buf)
        .unwrap();
        assert!(
            drain_packets(&mut buf, &tx, &topics).is_ok(),
            "one granted filter keeps the session"
        );

        // Reserved packet type 15 with a complete (zero) remaining length.
        let mut garbage = BytesMut::from(&[0xF0u8, 0x00][..]);
        assert!(
            drain_packets(&mut garbage, &tx, &topics).is_err(),
            "decode error ends the session"
        );
    }

    #[tokio::test]
    async fn a_refused_connack_is_an_auth_error() {
        let ws = Arc::new(MockWsConnector::new());
        ws.script(vec![packet_bytes(|b| {
            ConnAck::new(ConnectReturnCode::NotAuthorized, false).write(b)
        })]);
        ws.release();
        let (sender, _rx) = broadcast::channel(8);
        let (state_tx, _state_rx) = watch::channel(ConnectionState::Connecting);
        let p = params_with(watch::channel(Some(SecretString::from("stale"))).1);
        let err = run_session(&p, ws.as_ref(), &sender, &state_tx)
            .await
            .unwrap_err();
        assert!(matches!(err, ArloError::AuthError(_)), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_half_open_socket_is_noticed_by_the_idle_deadline() {
        let ws = Arc::new(MockWsConnector::new());
        ws.script_then_hang(vec![
            packet_bytes(|b| ConnAck::new(ConnectReturnCode::Success, false).write(b)),
            packet_bytes(|b| {
                SubAck::new(
                    SUBSCRIBE_PKID,
                    vec![SubscribeReasonCode::Success(QoS::AtMostOnce); 2],
                )
                .write(b)
            }),
        ]);
        ws.release();
        let (sender, _rx) = broadcast::channel(8);
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connecting);
        let p = params_with(watch::channel(Some(SecretString::from("TOK"))).1);
        let started = tokio::time::Instant::now();
        run_session(&p, ws.as_ref(), &sender, &state_tx)
            .await
            .expect("idle deadline ends the session cleanly");
        assert_eq!(
            *state_rx.borrow(),
            ConnectionState::Connected,
            "it did connect"
        );
        assert!(started.elapsed() >= IDLE_TIMEOUT, "{:?}", started.elapsed());
        assert!(
            started.elapsed() < IDLE_TIMEOUT + PING_INTERVAL * 2,
            "{:?}",
            started.elapsed()
        );
    }
}

#[cfg(test)]
mod robustness_tests {
    //! `mqttbytes` is the accepted unmaintained crate on the trust boundary
    //! (see deny.toml). These tests replace a fuzz target: broker bytes of
    //! any shape must yield a packet or an error, never a panic.
    use super::*;
    use mqttbytes::v4::{PingResp, Publish};

    /// xorshift64*: deterministic pseudo-random bytes with no dev-dependency.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() >> 56) as u8).collect()
        }
    }

    /// Drains a buffer the way the pump does: until the decoder needs more
    /// bytes or reports an error. Returns the number of packets decoded.
    fn drain(bytes: &[u8]) -> Result<usize, ArloError> {
        let mut buf = BytesMut::from(bytes);
        let mut decoded = 0;
        while next_packet(&mut buf)?.is_some() {
            decoded += 1;
        }
        Ok(decoded)
    }

    fn real_stream() -> Vec<u8> {
        let mut buf = BytesMut::new();
        Publish::new(
            "d/XC1/out/cameras/state",
            QoS::AtMostOnce,
            br#"{"resource":"cameras/A0A0000YA0D00","action":"is","properties":{"batteryLevel":97}}"#
                .to_vec(),
        )
        .write(&mut buf)
        .expect("publish encodes");
        subscribe_packet(&["u/U1/in/#".to_string()])
            .write(&mut buf)
            .expect("subscribe encodes");
        PingResp.write(&mut buf).expect("pingresp encodes");
        buf.to_vec()
    }

    #[test]
    fn decoder_never_panics_on_random_bytes() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        for _ in 0..4000 {
            let len = (rng.next() % 600) as usize;
            let _ = drain(&rng.bytes(len));
        }
        // Every fixed-header byte, with remaining-length varints at the
        // edges (0, 1, 127, continuation bit set, all ones).
        for first in 0u8..=255 {
            for second in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                let mut bytes = vec![first, second];
                bytes.extend(rng.bytes(8));
                let _ = drain(&bytes);
                // A declared length beyond MAX_PACKET_BYTES must be an
                // error, not an allocation.
                let oversized = [first, 0xff, 0xff, 0xff, 0x7f];
                let _ = drain(&oversized);
            }
        }
    }

    #[test]
    fn decoder_never_panics_on_truncated_or_corrupted_real_packets() {
        let whole = real_stream();
        assert_eq!(drain(&whole).expect("well-formed stream"), 3);

        // Every prefix: "need more bytes" or a clean error, never a panic.
        for cut in 0..whole.len() {
            let _ = drain(&whole[..cut]);
        }

        // Single-byte corruption at every offset, with several patterns.
        for idx in 0..whole.len() {
            for mask in [0x01u8, 0x80, 0xff, 0x7f] {
                let mut corrupted = whole.clone();
                corrupted[idx] ^= mask;
                let _ = drain(&corrupted);
            }
        }
    }
}
