---
name: protocol-specialist
description: Protocol emulation and state management for the Arlo ecosystem.
---
# Protocol Specialist Skill

## Arlo API Emulation
- When implementing new endpoints:
  1. Audit the `X-Arlo-...` headers (Telemetry, Browser version, App version).
  2. Ensure the User-Agent is consistent with the `BrowserProfile` provided by `rs-cloudscraper`.

## SSE & Event Management
- **Keep-Alives**: Implement a robust heartbeat mechanism for SSE connections.
- **Actor Isolation**: Ensure the `EventManager` uses `tokio::sync::broadcast` to prevent head-of-line blocking.
- **State Hydration**: Periodically refresh device states from the REST API to ensure SSE events haven't been missed.

## MFA Flow Orchestration
- Manage the transition from `start_auth` to `finish_auth` using a clear state machine.
- Integrate IMAP/SMS solvers as injectable adapters.

## Arlo v3 Live Signaling (WebRTC)

Arlo v3 replaces the RTSP live source with a WebRTC call brokered by a **non-bundled `FreeSWITCH`** gateway. Signaling stays here in `rs-arlo`; media negotiation is delegated to a `webrtcbin` pipeline in the consumer (see the streamer's `media-specialist`).

1. **Discover ICE servers**: `GET /hmsweb/users/devices/sipInfo/v2` with `cameraId` + `xcloudId` headers → `SipInfo { domain, ws_endpoint, ice_servers: { data: [...] } }`. Filter out `transport=tcp` TURN entries (negotiates flakily); keep STUN + UDP TURN.
2. **Open the signaling WS**: `wss://{domain}:7443/`, WebSocket subprotocol `sip`, `Origin: https://my.arlo.com`. No auth header — the WS is authenticated by the session cookies attached to the SipInfo REST call.
3. **Send the offer as HTTP-over-WS**: `POST /hmswebsocketproxy/initiateOffer` with a JSON envelope carrying `sipCallInfo` (device IDs, session UUID) + the SDP offer as text. The response frame carries the SDP answer.
4. **Teardown**: `POST /hmswebsocketproxy/sessionDisconnected` on the same WS, **then** close the socket. Arlo does not clean the SIP session on a bare WS close — always send the disconnect frame first. This is `WebrtcSignaler::teardown`'s job on the consumer side.
5. **Answer shape**: two m-lines (audio + video), **separate ICE ufrag/pwd/candidate per m-line, no `a=group:BUNDLE`, same DTLS fingerprint + `a=setup:active`**. Apply the answer verbatim through `webrtcbin`; do not munge it into BUNDLE — ICE will fail.
6. **`webrtc-rs` is incompatible.** It is BUNDLE-only / single ICE transport (upstream `sdp/mod.rs:996`). Live v3 must go through GStreamer `webrtcbin`; don't reintroduce a `webrtc-rs` dependency for signaling *or* media here.

## Design invariants (this crate is signaling-only)

- No `webrtc` or `webrtc-rs` dependency. Ever.
- `ArloClient` exposes `sip_info(device)` and `webrtc_negotiate(sip, offer_sdp) → (SignalingAnswer, SignalingSocket)`. The socket owns disconnect; drop closes it after `sessionDisconnected`.
- No RTP handling, no `AppSink`, no media conversion in this crate — pure protocol.
