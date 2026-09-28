---
name: protocol-specialist
description: Protocol emulation and state management for the Arlo ecosystem.
---
# Protocol Specialist Skill

## Arlo API Emulation
- When implementing new endpoints:
  1. Audit the `X-Arlo-...` headers (Telemetry, Browser version, App version).
  2. Ensure the User-Agent and `Sec-CH-UA*` hints come from the same `BrowserProfile` (`stealthscraper-rs`) as the `wreq` emulation.

## MQTT Event Management
- **Keep-Alives**: `PINGREQ` at half the 60 s keep-alive; reconnect with backoff on any stream end.
- **Actor Isolation**: the `EventBus` task publishes through `tokio::sync::broadcast` to prevent head-of-line blocking; never block it on a consumer.
- **Topics**: prefer the broker's `allowedMqttTopics`; the broad `d/<xCloudId>/out/#` wildcard is owner-only.
- **State Hydration**: Periodically refresh device states from the REST API to ensure events haven't been missed.

## MFA Flow Orchestration
- Manage the transition from `start_auth` to `finish_auth` using a clear state machine.
- Integrate IMAP/SMS solvers as injectable adapters.

## Arlo v3 Live Signaling (WebRTC)

Arlo v3 replaces the RTSP live source with a WebRTC call brokered by a **non-bundled `FreeSWITCH`** gateway. Signaling stays here in `arlo-rs`; media negotiation is delegated to a `webrtcbin` pipeline in the consumer (see the streamer's `media-specialist`).

1. **Discover ICE servers**: `GET /hmsweb/users/devices/sipInfo/v2` with `cameraId` + `xcloudId` headers → `SipInfo { domain, ws_endpoint, ice_servers: { data: [...] } }`. Filter out `transport=tcp` TURN entries (negotiates flakily); keep STUN + UDP TURN.
2. **Open the signaling WS**: `wss://{domain}:7443/`, WebSocket subprotocol `sip`, `Origin: https://my.arlo.com`. No auth header — the WS is authenticated by the session cookies attached to the SipInfo REST call.
3. **Send the offer as HTTP-over-WS**: `POST /hmswebsocketproxy/initiateOffer` with a JSON envelope carrying `sipCallInfo` (device IDs, session UUID) + the SDP offer as text. The response frame carries the SDP answer.
4. **Teardown**: `POST /hmswebsocketproxy/sessionDisconnected` on the same WS, **then** close the socket. Arlo does not clean the SIP session on a bare WS close — always send the disconnect frame first. This is `WebrtcSignaler::teardown`'s job on the consumer side.
5. **Answer shape**: two m-lines (audio + video), **separate ICE ufrag/pwd/candidate per m-line, no `a=group:BUNDLE`, same DTLS fingerprint + `a=setup:active`**. Apply the answer verbatim through `webrtcbin`; do not munge it into BUNDLE — ICE will fail.
6. **`webrtc-rs` is incompatible.** It is BUNDLE-only / single ICE transport (upstream `sdp/mod.rs:996`). Live v3 must go through GStreamer `webrtcbin`; don't reintroduce a `webrtc-rs` dependency for signaling *or* media here.

## Facts proven on a live account (2026-09-28)

Captured with `manual_examples/peek_stream_url.rs` and the streamer's event logging.
Do not re-derive them; extend this list when a capture adds one.

- **One live transport per camera.** While the mobile app views a camera (RTSP),
  `sipInfo` / the WebRTC offer is refused with `success:false` and
  `data.error = 14001` ("RTSP Streaming in progress, SIP Streaming is not allowed").
  `data.error` arrives as a **string or a number**; `success_false_error` accepts both
  and keeps `data.message`. Consumers match the numeric code, never the text.
- **The app's stream cannot be joined.** The watch-along DASH URL answers 502 from
  awselb for every variant tried.
- **`get_stream_url` (`action:"get"` on `/startStream`) is not passive**: it wakes an
  idle camera. Call it only after the bus reported `activityState == "userStreamActive"`,
  never on a timer or as a probe loop.
- **User views are visible on the bus**: `cameras/<id>` property events carry
  `activityState` (`userStreamActive` while the app streams, `idle` after).
- **Snapshots are announced on the bus**: `cameras/<id>` property events carry a fresh
  `presignedLastImageUrl`; `mediaUploadNotification` also carries one at top level and
  may arrive **without an `action`** (hence `#[serde(default)] action`).
- **Motion is a pulse train, not a state.** While motion lasts a camera repeats
  `activityState: fullFrameSnapshot` → `motionDetected: true` → `motionDetected: false`
  ~5 s later, about every 10 s (longest gap seen: 13 s). `false` ends a pulse, not the
  motion; consumers time their cooldown from the last `true`.
- Presigned URLs are capability URLs: redact them (`models/redact.rs`), never log them,
  accept https only, and treat them as short-lived.

## Design invariants (this crate is signaling-only)

- No `webrtc` or `webrtc-rs` dependency. Ever.
- `ArloClient` exposes `sip_info(device)` and `webrtc_negotiate(sip, offer_sdp) → (SignalingAnswer, SignalingSocket)`. The socket owns disconnect; drop closes it after `sessionDisconnected`.
- No RTP handling, no `AppSink`, no media conversion in this crate — pure protocol.
