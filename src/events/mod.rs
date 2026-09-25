//! Telemetry event bus.
//!
//! [`EventBus`] owns a single background task: a reconnecting
//! **MQTT-over-WebSocket** listener that broadcasts parsed
//! [`ArloEvent`]s on a `tokio::sync::broadcast` channel. Consumers
//! obtain receivers via [`EventBus::subscribe`]; each call yields an
//! independent receiver.
//!
//! Under the v3 Arlo API the legacy SSE channel
//! (`/hmsweb/client/subscribe`) returns **403**; the modern client
//! receives all device events over MQTT (`wss://mqtt-cluster-*`). The
//! wire details live in the crate-internal `mqtt` submodule; this module only owns lifecycle and
//! the JSON→[`ArloEvent`] routing (shared, since MQTT `PUBLISH`
//! payloads have the same shape the SSE frames did).
//!
//! Lifecycle:
//! - `EventBus::start` (crate-internal) is invoked lazily by
//!   [`crate::ArloClient::events`] on first use.
//! - [`Drop`] aborts the background task, so dropping the owning
//!   [`crate::ArloClient`] cleans up the listener.

mod mqtt;

pub(crate) use mqtt::{MqttParams, subscription_topics};

use crate::error::ArloError;
use crate::models::events::ArloEvent;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

/// Default capacity of the broadcast channel. Slow consumers exceeding
/// this backlog observe `RecvError::Lagged` and skip ahead.
const BROADCAST_CAPACITY: usize = 256;

/// Lifecycle of the event listener as observed by callers.
///
/// Modelled exhaustively so consumers can `match` on it without a
/// wildcard arm — adding a new variant is a deliberate breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state after the bus starts (crate-internal `EventBus::start`) and during every
    /// reconnect attempt (WSS dial + MQTT `CONNECT`).
    Connecting,
    /// `CONNACK` accepted; we are subscribed and pumping events.
    Connected,
    /// The socket dropped / errored. The listener sleeps the reconnect
    /// backoff and transitions back to `Connecting`.
    Disconnected,
}

/// Telemetry event bus. See module docs.
#[derive(Debug)]
pub struct EventBus {
    sender: broadcast::Sender<ArloEvent>,
    state_rx: watch::Receiver<ConnectionState>,
    listener_handle: JoinHandle<()>,
}

impl EventBus {
    /// Spawns the reconnecting MQTT-over-WSS listener. Crate-internal —
    /// applications obtain a bus via [`crate::ArloClient::events`].
    pub(crate) async fn start(params: MqttParams) -> Result<Self, ArloError> {
        let (sender, _initial_rx) = broadcast::channel(BROADCAST_CAPACITY);
        let (state_tx, state_rx) = watch::channel(ConnectionState::Connecting);
        let listener_handle = mqtt::spawn_mqtt_listener(params, sender.clone(), state_tx);
        Ok(Self {
            sender,
            state_rx,
            listener_handle,
        })
    }

    /// Returns a fresh receiver. Each call yields an independent
    /// `broadcast::Receiver`; the first event delivered to it is the
    /// next one published *after* the call.
    pub fn subscribe(&self) -> broadcast::Receiver<ArloEvent> {
        self.sender.subscribe()
    }

    /// Returns a clone of the connection-state watch receiver. Callers
    /// can `await receiver.changed()` to wake on every transition or
    /// read `*receiver.borrow()` for the current value. Streamer
    /// applications use this to pause publishing while `Disconnected`.
    pub fn connection_state(&self) -> watch::Receiver<ConnectionState> {
        self.state_rx.clone()
    }
}

impl Drop for EventBus {
    fn drop(&mut self) {
        self.listener_handle.abort();
    }
}

/// Routes one decoded JSON payload (an MQTT `PUBLISH` body) through the
/// broadcast channel. Accepts both single-event objects and arrays
/// (Arlo batches occasionally). Shared with the listener in [`mqtt`].
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn dispatch_routes_single_and_batch() {
        let (tx, mut rx) = broadcast::channel::<ArloEvent>(8);
        dispatch_payload(r#"{"action":"is","resource":"cameras/C1"}"#, &tx);
        dispatch_payload(
            r#"[{"action":"is","resource":"cameras/C2"},{"action":"is","resource":"cameras/C3"}]"#,
            &tx,
        );
        assert_eq!(rx.try_recv().unwrap().resource, "cameras/C1");
        assert_eq!(rx.try_recv().unwrap().resource, "cameras/C2");
        assert_eq!(rx.try_recv().unwrap().resource, "cameras/C3");
    }

    #[tokio::test]
    async fn connection_state_watch_observes_full_lifecycle() {
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
