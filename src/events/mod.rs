//! Server-Sent Events (SSE) Telemetry & Actor Model.
//!
//! This module implements the asynchronous Actor pattern used to safely monitor Arlo's
//! continuous `hmsweb` telemetry stream without blocking the main REST executing thread.
//! It establishes a resilient WebSocket/SSE connection, parses the raw JSON blobs into
//! strictly-typed `ArloEvent` enums, and broadcasts them system-wide using Tokio sync channels.
use crate::endpoints::*;
use crate::error::ArloError;
use crate::headers::ARLO_API_HOST;
use crate::models::events::ArloEvent;
use reqwest::Client;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{info, error, warn, debug, instrument, info_span, Instrument};

/// Subscription Engine interpreting Arlo's Server-Sent Events (SSE) telemetry.
///
/// The `EventManager` sits on a detached `tokio` thread and monitors `hmsweb` telemetry.
/// It acts as a router, translating JSON payloads into structured `ArloEvent` enumerations
/// and buffering them onto a reliable asynchronous multi-producer/multi-consumer broadcast channel.
pub struct EventManager {
    token: String,
    device_id: String,
    client: Client, // Reqwest client tunneled through the CloudScraper MITM proxy
    /// A subscribable `tokio` receiver yielding parsed Arlo events in real-time.
    pub receiver: broadcast::Receiver<ArloEvent>,
    _sender: broadcast::Sender<ArloEvent>,
    _loop_handle: Option<JoinHandle<()>>,
    _ping_handle: Option<JoinHandle<()>>,
}

impl EventManager {
    /// Connects to the Arlo SSE endpoint and spawns a background tokio task to process events.
    #[instrument(skip(client, access_token, device_id))]
    pub async fn start(
        client: Client,
        access_token: String,
        device_id: String,
    ) -> Result<Self, ArloError> {
        let (tx, rx) = broadcast::channel(100);

        let mut manager = Self {
            token: access_token,
            device_id,
            client: client.clone(),
            receiver: rx,
            _sender: tx.clone(),
            _loop_handle: None,
            _ping_handle: None,
        };

        // Spawn background SSE listener
        let token_clone = manager.token.clone();
        let client_clone = manager.client.clone();
        let device_id_clone = manager.device_id.clone();

        let handle = tokio::spawn(async move {
            let subscribe_url = format!(
                "{}{}?token={}",
                ARLO_API_HOST,
                API_SUBSCRIBE,
                urlencoding::encode(&token_clone)
            );

            info!("Connecting to SSE Stream: {}", subscribe_url);

            loop {
                // Initialize the connection
                let out = client_clone
                    .get(&subscribe_url)
                    .header("Accept", "text/event-stream")
                    .header("Authorization", &token_clone)
                    .header("x-user-device-id", &device_id_clone)
                    .header("x-service-version", "v3")
                    .send()
                    .await;

                match out {
                    Ok(mut response) => {
                        info!("SSE Connected (Status: {})", response.status());
                        while let Ok(Some(chunk)) = response.chunk().await {
                            let text = String::from_utf8_lossy(&chunk);
                            for line in text.lines() {
                                if line.starts_with("data: ") {
                                    let json_str = line.trim_start_matches("data: ");
                                    if let Ok(event) = serde_json::from_str::<ArloEvent>(json_str) {
                                        // Broadcast the parsed event to any open receivers
                                        let _ = tx.send(event);
                                    } else if let Ok(values) =
                                        serde_json::from_str::<Vec<ArloEvent>>(json_str)
                                    {
                                        // Arlo occasionally batches events as a JSON array
                                        for event in values {
                                            let _ = tx.send(event);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("SSE connection error: {}. Reconnecting in 5s...", e);
                    }
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }.instrument(info_span!("sse_listener")));

        manager._loop_handle = Some(handle);

        // Spawn the Ping/KeepAlive Loop
        let ping_token = manager.token.clone();
        let ping_client = manager.client.clone();
        let ping_device = manager.device_id.clone();

        let ping_handle = tokio::spawn(async move {
            let session_url = format!("{}{}", ARLO_API_HOST, AUTH_SESSION_V3);
            loop {
                // Arlo tokens expire if idle. Ping every 10 minutes to maintain session state.
                tokio::time::sleep(Duration::from_secs(600)).await;

                debug!("Sending Keep-Alive Ping to {}", session_url);
                let out = ping_client
                    .get(&session_url)
                    .header("Authorization", &ping_token)
                    .header("x-user-device-id", &ping_device)
                    .header("x-service-version", "v3")
                    .send()
                    .await;

                if let Err(e) = out {
                    warn!("Keep-Alive Ping failed: {}", e);
                } else if let Ok(resp) = out
                    && !resp.status().is_success()
                {
                    warn!(
                        "Keep-Alive Ping returned non-success status: {}",
                        resp.status()
                    );
                }
            }
        }.instrument(info_span!("keep_alive_ping")));

        manager._ping_handle = Some(ping_handle);

        Ok(manager)
    }
}

#[cfg(test)]
mod tests {
    use crate::models::events::ArloEvent;

    #[test]
    fn test_parse_sse_event_single() {
        let json_str = "{\"action\": \"is\", \"resource\": \"cameras/C1\", \"publishResponse\": false, \"properties\": {\"motionDetected\": true}}";
        let event: Result<ArloEvent, _> = serde_json::from_str(json_str);
        assert!(event.is_ok());
    }

    #[test]
    fn test_parse_sse_event_batch() {
        let json_str = "[{\"action\": \"is\", \"resource\": \"cameras/C1\", \"publishResponse\": false, \"properties\": {\"motionDetected\": true}}, {\"action\": \"is\", \"resource\": \"cameras/C2\", \"publishResponse\": false, \"properties\": {\"motionDetected\": false}}]";
        let events: Result<Vec<ArloEvent>, _> = serde_json::from_str(json_str);
        assert!(events.is_ok());
        assert_eq!(events.unwrap().len(), 2);
    }
}
