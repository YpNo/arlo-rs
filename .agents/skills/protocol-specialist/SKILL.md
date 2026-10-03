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

`client/auth/{flow,ceremony,push}.rs`, `client/mfa.rs`, `client/auth_imap.rs`. Facts
(code and captures, 2026-10-02):

- **Order in `authenticate*`:** cached token → `session/v3` validation (only Arlo's own
  verdict discards it; network/5xx/429 keep it and surface, so an outage costs no OTP)
  → `login` → `auth_completed` short-cut → **trusted-browser fast path** → factor
  selection → `startAuth` → OTP via the `MfaHandler` (or push polling) → `finishAuth`
  → `complete_session` (pairing with `browserAuthCode`, V3 validation, cache write).
- **Trusted browser** (reference client 0.8.0.15+): `getFactorId {factorType:"BROWSER"}`
  succeeds only for a paired `device_id` + cookie jar; `startAuth` on that factor returns
  the full token, no OTP. 9204 (known device, untrusted) or 9261 (`Invalid factor data`: a device id Arlo never saw) = not trusted → OTP ceremony. The session cache therefore
  holds three things — token, cookies, `device_id` — and the pairing is what makes later
  logins silent; `logout()` keeps `device_id` + cookies on purpose.
- **Push** needs PUSH as the account's *primary* factor (`startAuth` with an empty
  `factorType` dispatches the primary one); `finishAuth` is polled without `otp`, 9233 /
  9276 / 9278 = pending, 200 + `data.token` = approved.
- **IMAP**: baseline of unseen mail (45 s budget), poll every 5 s within a 90 s budget,
  `From` must be an `arlo.com` address, newest first, 6-digit code from `<h1>`, a bare
  digit line, or a loose match; Gmail needs a mailbox refresh to see new mail.
- **Lockout** 9017 is fatal for 5 minutes; never retry a `Fatal` or probe a locked account.
- Classification lives in `models/error_codes.rs` (`ErrorAction`); consumers branch on
  codes, never on message text.

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
- **The stream format is keyed on `User-Agent`** (captures 2026-09-30/10-01). The same
  `get` stream query answers a browser identity with a watch-along MPEG-DASH URL (502
  from awselb, every variant) and the iOS app identity (`ios_app_user_agent(version)`,
  `(iPhone15,2 18_1_1) iOS Arlo <v>`) with `rtsps://<ip>:443/vzmodulelive/<cam>_<ts>?egressToken=…&watchalong=true`,
  during a view the view's own stream. A raw RTSPS client plays it (TLS validation off:
  the certificate cannot match an IP); GStreamer's `rtspsrc` is refused at `SETUP` (403).
- **That server's framing is sloppy**: the first RTCP SR after `PLAY` is `$`-framed, the
  periodic ones arrive bare; the AAC audio track's RTP (PT 0) arrives bare too, without
  any `SETUP` for it. Clients must resync on the next plausible `$` header.
- **A watch-along client counts as a viewer**: while one is connected the camera keeps
  streaming after the app closes its view and the bus never reports `idle`; it reports
  `idle` ~340 ms after the client's `TEARDOWN`. Consumers must release the stream
  periodically to learn whether the app still views.
- **`get_stream_url` (`action:"get"` on `/startStream`) is not passive**: it wakes an
  idle camera. Call it only after the bus reported `activityState == "userStreamActive"`,
  never on a timer or as a probe loop.
- **User views are visible on the bus**: `cameras/<id>` property events carry
  `activityState` (`userStreamActive` while the app streams, `idle` after).
- **Snapshots are announced on the bus**: `cameras/<id>` property events carry a fresh
  `presignedLastImageUrl`; `mediaUploadNotification` also carries one at top level and
  may arrive **without an `action`** (hence `#[serde(default)] action`).
- **`startUserStream` answers in the POST reply** (`data.url`), not on the bus (capture
  2026-09-29). During an app view the reply holds a watch-along DASH URL (502, like
  `get_stream_url`'s) plus `sipCallInfo` + `iceServers` with `callId` / `conferenceId`
  null; a WebRTC leg with those coordinates connects to the gateway and is refused with
  `code 3, NO_ROUTE_DESTINATION`. The view is joined through the `User-Agent`-keyed
  RTSPS stream above, not through these coordinates; the app is never disturbed.
- **An app view is announced twice**: `activityState: startUserStream`, then
  `userStreamActive` about 200 ms later; `idle` when it closes.
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
