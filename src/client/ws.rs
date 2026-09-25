//! WebSocket port and its production adapter.
//!
//! Two Arlo channels are not request/response and therefore bypass
//! [`crate::HttpTransport`]: the MQTT-over-WSS event bus
//! (`crate::events`) and the WebRTC signaling socket
//! (`crate::client::livestream`). [`WsConnector`] is the seam they open
//! sockets through, so both can be driven by a scripted double in unit
//! tests, and so the adapter can later be swapped for one that shares the
//! HTTP transport's Chrome TLS fingerprint. [`TungsteniteConnector`] is
//! the production adapter (plain rustls; Arlo's WSS hosts are not behind
//! the Cloudflare fingerprint gate).

use crate::error::ArloError;
use async_trait::async_trait;
use futures_util::{Sink, Stream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};

/// Transport-level WebSocket error, as surfaced by [`WsStream`].
pub use tokio_tungstenite::tungstenite::Error as WsError;
/// A WebSocket frame, as sent and received through [`WsStream`].
pub use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

/// An open WebSocket: a stream of inbound frames and a sink for outbound
/// ones. Blanket-implemented for every type with that shape, including
/// `tokio_tungstenite::WebSocketStream`.
pub trait WsStream:
    Stream<Item = Result<WsMessage, WsError>> + Sink<WsMessage, Error = WsError> + Send + Unpin
{
}

impl<T> WsStream for T where
    T: Stream<Item = Result<WsMessage, WsError>> + Sink<WsMessage, Error = WsError> + Send + Unpin
{
}

/// Type-erased [`WsStream`] handed out by a [`WsConnector`].
pub type BoxWsStream = Box<dyn WsStream>;

/// Opens WebSockets. Implemented by [`TungsteniteConnector`] in
/// production and by a scripted double in tests.
#[async_trait]
pub trait WsConnector: Send + Sync + std::fmt::Debug {
    /// Performs the upgrade handshake to `url`, sending Arlo's
    /// non-standard extras: the `Origin` header and the requested
    /// subprotocol (`mqtt` for the event bus, `sip` for signaling).
    async fn connect(
        &self,
        url: &str,
        origin: &str,
        subprotocol: &str,
    ) -> Result<BoxWsStream, ArloError>;
}

/// Production adapter over `tokio-tungstenite` (rustls, WebPKI roots).
#[derive(Debug, Default, Clone, Copy)]
pub struct TungsteniteConnector;

#[async_trait]
impl WsConnector for TungsteniteConnector {
    async fn connect(
        &self,
        url: &str,
        origin: &str,
        subprotocol: &str,
    ) -> Result<BoxWsStream, ArloError> {
        let mut request = url
            .into_client_request()
            .map_err(|e| ArloError::ScraperError(format!("bad websocket url '{url}': {e}")))?;
        let headers = request.headers_mut();
        headers.insert(
            ORIGIN,
            origin
                .parse()
                .map_err(|_| ArloError::ScraperError(format!("invalid Origin '{origin}'")))?,
        );
        headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            subprotocol.parse().map_err(|_| {
                ArloError::ScraperError(format!("invalid subprotocol '{subprotocol}'"))
            })?,
        );
        let (ws, _response) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|e| ArloError::ScraperError(format!("WSS connect to {url} failed: {e}")))?;
        Ok(Box::new(ws))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Scripted WebSocket double: each `connect` hands out a socket that
    //! replays a pre-recorded list of inbound frames and records every
    //! outbound one.

    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::sync::Notify;

    /// One scripted socket. Yields its frames in order, then ends the
    /// stream (`None`) — or, with an empty script, stays silent forever,
    /// which keeps a reconnecting listener parked instead of spinning.
    pub struct ScriptedWs {
        inbound: VecDeque<WsMessage>,
        hang_when_empty: bool,
        sent: Arc<Mutex<Vec<WsMessage>>>,
    }

    impl Stream for ScriptedWs {
        type Item = Result<WsMessage, WsError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.inbound.pop_front() {
                Some(frame) => Poll::Ready(Some(Ok(frame))),
                None if self.hang_when_empty => Poll::Pending,
                None => Poll::Ready(None),
            }
        }
    }

    impl Sink<WsMessage> for ScriptedWs {
        type Error = WsError;

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: WsMessage) -> Result<(), WsError> {
            self.sent.lock().expect("SAFETY: test mutex").push(item);
            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Records every `connect` and serves scripted sockets in FIFO order.
    /// `connect` waits for [`MockWsConnector::release`] so a test can
    /// subscribe to a bus before the first frame is replayed.
    #[derive(Debug, Default)]
    pub struct MockWsConnector {
        scripts: Mutex<VecDeque<Vec<WsMessage>>>,
        sent: Arc<Mutex<Vec<WsMessage>>>,
        connects: Mutex<Vec<(String, String, String)>>,
        gate: Notify,
    }

    impl MockWsConnector {
        pub fn new() -> Self {
            Self::default()
        }

        /// Queues the inbound frames the next `connect` will replay.
        pub fn script(&self, frames: Vec<WsMessage>) {
            self.scripts
                .lock()
                .expect("SAFETY: test mutex")
                .push_back(frames);
        }

        /// Lets one pending (or the next) `connect` proceed.
        pub fn release(&self) {
            self.gate.notify_one();
        }

        /// Every frame written to any scripted socket, in order.
        pub fn sent(&self) -> Vec<WsMessage> {
            self.sent.lock().expect("SAFETY: test mutex").clone()
        }

        /// `(url, origin, subprotocol)` of every `connect`, in order.
        pub fn connects(&self) -> Vec<(String, String, String)> {
            self.connects.lock().expect("SAFETY: test mutex").clone()
        }
    }

    #[async_trait]
    impl WsConnector for MockWsConnector {
        async fn connect(
            &self,
            url: &str,
            origin: &str,
            subprotocol: &str,
        ) -> Result<BoxWsStream, ArloError> {
            self.gate.notified().await;
            self.connects.lock().expect("SAFETY: test mutex").push((
                url.to_string(),
                origin.to_string(),
                subprotocol.to_string(),
            ));
            let script = self.scripts.lock().expect("SAFETY: test mutex").pop_front();
            let hang_when_empty = script.is_none();
            Ok(Box::new(ScriptedWs {
                inbound: script.unwrap_or_default().into(),
                hang_when_empty,
                sent: Arc::clone(&self.sent),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tungstenite_connector_rejects_a_malformed_url_before_dialing() {
        let result = TungsteniteConnector
            .connect("not a url", "https://my.arlo.com", "mqtt")
            .await;
        match result {
            Err(ArloError::ScraperError(_)) => {}
            Err(other) => panic!("expected ScraperError, got {other:?}"),
            Ok(_) => panic!("a malformed URL must not connect"),
        }
    }
}
