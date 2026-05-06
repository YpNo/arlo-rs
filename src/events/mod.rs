//! Server-Sent Events (SSE) telemetry bus.
//!
//! [`EventBus`] owns two background tokio tasks — an SSE listener that
//! reconnects on disconnect, and a 10-minute keep-alive pinger — and
//! broadcasts parsed [`ArloEvent`]s on a `tokio::sync::broadcast` channel.
//! Consumers obtain receivers via [`EventBus::subscribe`]; each call yields
//! an independent receiver.
//!
//! Lifecycle:
//! - [`EventBus::start`] (crate-internal) is invoked lazily by
//!   [`crate::ArloClient::events`] on first use.
//! - [`Drop`] aborts both background tasks, so dropping the owning
//!   [`crate::ArloClient`] cleans up the listener.
//!
//! SSE parsing follows the WHATWG spec strictly: frames are terminated by
//! `\n\n` (or `\r\n\r\n`); within a frame, `data:` lines are concatenated
//! with `\n`. The previous implementation split per chunk on `\n` and lost
//! events that straddled a chunk boundary.

use crate::endpoints::*;
use crate::error::ArloError;
use crate::headers::ARLO_API_HOST;
use crate::models::events::ArloEvent;
use reqwest::Client;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tracing::{Instrument, debug, error, info, info_span, instrument, warn};

/// Default capacity of the broadcast channel. Slow consumers exceeding this
/// backlog observe `RecvError::Lagged` and skip ahead.
const BROADCAST_CAPACITY: usize = 256;
/// How often to ping the session-v3 endpoint to keep the token live.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(600);
/// Backoff between SSE reconnect attempts.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

/// Lifecycle of the SSE listener as observed by callers.
///
/// Modelled exhaustively so consumers can `match` on it without a wildcard
/// arm — adding a new variant is a deliberate breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state after [`EventBus::start`] returns and during every
    /// reconnect attempt.
    Connecting,
    /// The HTTP request to `/subscribe` returned 2xx and we are reading
    /// the chunked SSE body.
    Connected,
    /// The chunk loop ended (server hung up, network blip, …) or the
    /// initial connection errored. The listener will sleep
    /// [`RECONNECT_BACKOFF`] and transition back to `Connecting`.
    Disconnected,
}

/// SSE telemetry bus. See module docs.
pub struct EventBus {
    sender: broadcast::Sender<ArloEvent>,
    state_rx: watch::Receiver<ConnectionState>,
    sse_handle: JoinHandle<()>,
    ping_handle: JoinHandle<()>,
}

impl EventBus {
    /// Connects to Arlo's SSE stream and spawns the listener + keep-alive
    /// background tasks. Crate-internal — applications obtain a bus via
    /// [`crate::ArloClient::events`].
    #[instrument(skip(client, access_token, device_id))]
    pub(crate) async fn start(
        client: Client,
        access_token: String,
        device_id: String,
    ) -> Result<Self, ArloError> {
        let (sender, _initial_rx) = broadcast::channel(BROADCAST_CAPACITY);
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connecting);

        let sse_handle = spawn_sse_listener(
            client.clone(),
            access_token.clone(),
            device_id.clone(),
            sender.clone(),
            state_tx,
        );
        let ping_handle = spawn_keep_alive(client, access_token, device_id);

        Ok(Self {
            sender,
            state_rx,
            sse_handle,
            ping_handle,
        })
    }

    /// Returns a fresh receiver. Each call yields an independent
    /// `broadcast::Receiver`; the first event delivered to it is the next
    /// one published *after* the call.
    pub fn subscribe(&self) -> broadcast::Receiver<ArloEvent> {
        self.sender.subscribe()
    }

    /// Returns a clone of the connection-state watch receiver. Callers can
    /// `await receiver.changed()` to wake on every transition or read
    /// `*receiver.borrow()` for the current value. Streamer applications
    /// use this to pause publishing while the bus is `Disconnected`.
    pub fn connection_state(&self) -> watch::Receiver<ConnectionState> {
        self.state_rx.clone()
    }
}

impl Drop for EventBus {
    fn drop(&mut self) {
        self.sse_handle.abort();
        self.ping_handle.abort();
    }
}

fn spawn_sse_listener(
    client: Client,
    token: String,
    device_id: String,
    sender: broadcast::Sender<ArloEvent>,
    state_tx: watch::Sender<ConnectionState>,
) -> JoinHandle<()> {
    tokio::spawn(
        async move {
            let url = format!(
                "{}{}?token={}",
                ARLO_API_HOST,
                API_SUBSCRIBE,
                urlencoding::encode(&token)
            );
            info!(%url, "Connecting to SSE stream");

            loop {
                let _ = state_tx.send(ConnectionState::Connecting);
                match client
                    .get(&url)
                    .header("Accept", "text/event-stream")
                    .header("Authorization", &token)
                    .header("x-user-device-id", &device_id)
                    .header("x-service-version", "v3")
                    .send()
                    .await
                {
                    Ok(mut response) => {
                        info!(status = %response.status(), "SSE connected");
                        let _ = state_tx.send(ConnectionState::Connected);
                        let mut framer = SseFramer::default();
                        while let Ok(Some(chunk)) = response.chunk().await {
                            let text = String::from_utf8_lossy(&chunk);
                            for payload in framer.push(&text) {
                                dispatch_payload(&payload, &sender);
                            }
                        }
                        warn!("SSE stream ended; reconnecting");
                    }
                    Err(e) => {
                        error!(error = %e, "SSE connection error");
                    }
                }

                let _ = state_tx.send(ConnectionState::Disconnected);
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
        }
        .instrument(info_span!("sse_listener")),
    )
}

fn spawn_keep_alive(client: Client, token: String, device_id: String) -> JoinHandle<()> {
    tokio::spawn(
        async move {
            let url = format!("{}{}", ARLO_API_HOST, AUTH_SESSION_V3);
            loop {
                tokio::time::sleep(KEEP_ALIVE_INTERVAL).await;
                debug!(%url, "Sending keep-alive ping");
                match client
                    .get(&url)
                    .header("Authorization", &token)
                    .header("x-user-device-id", &device_id)
                    .header("x-service-version", "v3")
                    .send()
                    .await
                {
                    Err(e) => warn!(error = %e, "Keep-alive ping failed"),
                    Ok(resp) if !resp.status().is_success() => {
                        warn!(status = %resp.status(), "Keep-alive ping non-success")
                    }
                    Ok(_) => {}
                }
            }
        }
        .instrument(info_span!("keep_alive_ping")),
    )
}

/// Routes a single decoded SSE `data:` payload through the broadcast
/// channel. Accepts both single-event objects and arrays (Arlo batches
/// occasionally).
fn dispatch_payload(payload: &str, sender: &broadcast::Sender<ArloEvent>) {
    if let Ok(event) = serde_json::from_str::<ArloEvent>(payload) {
        let _ = sender.send(event);
        return;
    }
    if let Ok(events) = serde_json::from_str::<Vec<ArloEvent>>(payload) {
        for event in events {
            let _ = sender.send(event);
        }
    }
}

/// Stateful SSE frame parser. Accumulates partial chunks across reads and
/// emits the joined `data:` payload of each complete event.
#[derive(Default)]
struct SseFramer {
    buf: String,
}

impl SseFramer {
    /// Append `chunk` to the internal buffer and drain every complete
    /// frame. A frame is terminated by `\n\n` or `\r\n\r\n`. Within a frame,
    /// every line starting with `data:` (with an optional leading space)
    /// contributes one line of the returned payload, joined with `\n`.
    /// Frames with no `data:` line are skipped.
    fn push(&mut self, chunk: &str) -> Vec<String> {
        self.buf.push_str(chunk);
        let mut payloads = Vec::new();

        loop {
            let separator = locate_frame_terminator(&self.buf);
            let Some((idx, term_len)) = separator else {
                break;
            };
            let raw_frame = self.buf[..idx].to_string();
            self.buf.drain(..idx + term_len);

            let mut data_lines: Vec<&str> = Vec::new();
            for line in raw_frame.split('\n') {
                let line = line.trim_end_matches('\r');
                let Some(rest) = line.strip_prefix("data:") else {
                    continue;
                };
                data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
            }
            if !data_lines.is_empty() {
                payloads.push(data_lines.join("\n"));
            }
        }

        payloads
    }
}

/// Returns `(index, terminator_len)` for the first frame separator in
/// `buf`, preferring `\r\n\r\n` over `\n\n` if both are present at the
/// same position. Bytes are ASCII so the index is always a UTF-8 boundary.
fn locate_frame_terminator(buf: &str) -> Option<(usize, usize)> {
    let crlf = buf.find("\r\n\r\n").map(|i| (i, 4));
    let lf = buf.find("\n\n").map(|i| (i, 2));
    match (crlf, lf) {
        (Some(c), Some(l)) if c.0 <= l.0 => Some(c),
        (_, Some(l)) => Some(l),
        (Some(c), None) => Some(c),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::events::ArloEvent;

    #[test]
    fn parses_single_event() {
        let json = "{\"action\":\"is\",\"resource\":\"cameras/C1\",\"publishResponse\":false,\"properties\":{\"motionDetected\":true}}";
        let ev: ArloEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.resource, "cameras/C1");
        assert_eq!(ev.publish_response, Some(false));
    }

    #[test]
    fn parses_event_without_publish_response() {
        let json = "{\"action\":\"is\",\"resource\":\"modes\"}";
        let ev: ArloEvent = serde_json::from_str(json).unwrap();
        assert!(ev.publish_response.is_none());
    }

    #[test]
    fn parses_event_with_trans_id() {
        let json = "{\"action\":\"is\",\"resource\":\"cameras/C1\",\"transId\":\"web!abc-123\"}";
        let ev: ArloEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.trans_id.as_deref(), Some("web!abc-123"));
    }

    #[test]
    fn parses_batch() {
        let json = "[{\"action\":\"is\",\"resource\":\"cameras/C1\"},{\"action\":\"is\",\"resource\":\"cameras/C2\"}]";
        let events: Vec<ArloEvent> = serde_json::from_str(json).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn framer_emits_complete_frame() {
        let mut f = SseFramer::default();
        let out = f.push("data: hello\n\n");
        assert_eq!(out, vec!["hello".to_string()]);
    }

    #[test]
    fn framer_handles_chunk_boundaries() {
        let mut f = SseFramer::default();
        // The frame terminator straddles two chunks — the previous \n-only
        // splitter would have lost the event. Each push must wait for the
        // full \n\n before emitting.
        assert!(f.push("data: hel").is_empty());
        assert!(f.push("lo\n").is_empty());
        let out = f.push("\nleftover");
        assert_eq!(out, vec!["hello".to_string()]);
        // The leftover "leftover" stays buffered for the next frame.
        assert!(f.push("\n\n").is_empty()); // not prefixed with "data:" — skipped.
        let out = f.push("data: world\n\n");
        assert_eq!(out, vec!["world".to_string()]);
    }

    #[test]
    fn framer_handles_crlf_terminator() {
        let mut f = SseFramer::default();
        let out = f.push("data: hi\r\n\r\n");
        assert_eq!(out, vec!["hi".to_string()]);
    }

    #[test]
    fn framer_concatenates_multiline_data() {
        let mut f = SseFramer::default();
        let out = f.push("data: line1\ndata: line2\n\n");
        assert_eq!(out, vec!["line1\nline2".to_string()]);
    }

    #[test]
    fn framer_drains_multiple_frames_in_one_chunk() {
        let mut f = SseFramer::default();
        let out = f.push("data: a\n\ndata: b\n\ndata: c\n\n");
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn framer_skips_frames_without_data_line() {
        let mut f = SseFramer::default();
        let out = f.push(": comment\n\nevent: ping\n\n");
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn connection_state_watch_observes_full_lifecycle() {
        // Mirror what the SSE listener publishes, without touching the network.
        let (tx, mut rx) = watch::channel(ConnectionState::Connecting);
        assert_eq!(*rx.borrow(), ConnectionState::Connecting);

        tx.send(ConnectionState::Connected).unwrap();
        rx.changed().await.unwrap();
        assert_eq!(*rx.borrow(), ConnectionState::Connected);

        tx.send(ConnectionState::Disconnected).unwrap();
        rx.changed().await.unwrap();
        assert_eq!(*rx.borrow(), ConnectionState::Disconnected);

        tx.send(ConnectionState::Connecting).unwrap();
        rx.changed().await.unwrap();
        assert_eq!(*rx.borrow(), ConnectionState::Connecting);
    }
}
