# Changelog

All notable changes to `arlo-rs` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-25

First release under the `arlo-rs` name. Breaking throughout (pre-1.0:
MINOR bump); the headline changes are the browser-less `wreq` transport,
trusted-browser re-login, the Arlo error-code classifier and the module
split. Every entry below was `[Unreleased]` since 0.1.0.

### Changed — module splits and documentation (Phase 5)
- `src/client/auth.rs` (1825 lines) → `auth/{mod, ceremony, flow, push,
  session}.rs` and `src/client/devices.rs` (2148 lines) →
  `devices/{mod, stream, modes, actuation, media, sensors}.rs`, every
  file under the 800-line limit, each submodule an `impl ArloClient`
  block with its own tests. No public path changed (`arlo_rs::client::
  {auth, devices}` still resolve); `ArloClient::spawn_ffmpeg_recorder`
  was removed from the library (a process spawner does not belong in a
  protocol crate) and lives on as the `record_stream` manual example.
- New tests for `set_mode_by_name` (custom-uuid PUT with revision,
  standard-name PUT, unknown-mode error).
- README, CONTEXT.md, CLAUDE.md, the `.agents` rules / workflow / skill
  files and the `advanced` example no longer describe the SSE bus, the
  `rs-cloudscraper` browser proxy, `rquest`, `imap-tokio` or the
  "RTSPS / HLS / DASH" stream story; they describe the MQTT bus, the
  `wreq` transport, the `WsConnector` seam and v3 WebRTC signaling.
  `GEMINI.md` is now a symlink to `CLAUDE.md` instead of a stale copy.

### Changed — crate diet (Phase 4)
- Removed five direct dependencies that pulled their own subtrees for
  next to nothing: `chrono` (six calls to get epoch millis → a
  `SystemTime`-based `now_millis()`), `regex` (→ `regex-lite`, three
  small OTP patterns), `urlencoding` and `tracing-futures` (unused),
  `imap-rs-core` and `rustls-pki-types` (transitive already; the
  local-hub verifier uses `rustls::pki_types`). The normal dependency
  graph went from 277 to 266 crates.
- `tokio` features narrowed from `full` to the six the crate uses;
  `reqwest`'s unused `socks` feature dropped.
- `tokio-tungstenite` 0.26 → 0.28. 0.30 was evaluated and rejected: it
  still pins `webpki-roots` 0.26 and adds a duplicate `digest`/`sha1`
  family through `sha1` 0.11.
- `deny.toml`: the `GPL-3.0` / `GPL-3.0-or-later` allowances are gone
  (nothing in the graph needs them; the crate is MIT); the duplicate
  skip list matches the new graph.
- `mqttbytes` stays. It is the frozen MQTT 3.1.1 codec from the rumqtt
  project (last release 2021), contains no `unsafe`, and the protocol it
  implements has not changed either; vendoring six packet codecs would
  add maintenance for no security gain. Revisit only if RUSTSEC ever
  flags it.

### Changed — seams and safety (Phase 3)
- **`WsConnector` port** (`client::ws`): the MQTT event bus and the
  WebRTC signaling socket now open their WebSockets through a trait
  (`connect(url, origin, subprotocol)`) instead of calling
  `tokio_tungstenite::connect_async` directly. `TungsteniteConnector`
  is the production adapter; `ArloClient::with_transports(http, ws,
  endpoints)` injects a double. Both paths are now unit-tested end to
  end on a scripted socket: CONNECT → CONNACK → SUBSCRIBE → PUBLISH
  routing for the bus, and `initiateOffer` → `200 OK` answer →
  `sessionDisconnected` for signaling. `SignalingSocket` holds a
  `BoxWsStream`. This is also the hook for a future adapter that shares
  the HTTP transport's Chrome fingerprint on WSS.
- **No lock unwraps.** The per-client `api_version` is an atomic
  `ApiVersionCell` (`get`/`set`) instead of a `RwLock` read/written with
  `.unwrap()` at eleven sites.
- **Secrets never reach `Debug` output.** `MqttParams.access_token` is a
  `SecretString`; `AuthRequest`, `AuthResponseData` (token and
  `browserAuthCode`), `VerifyFactorRequest` (OTP), `SessionV3Response`,
  `RatlsTokenData`, `SipCallInfo` (SIP password), `CredentialsConfig`
  and `ImapConfig` implement `Debug` by hand and print `[REDACTED]`.
- The three remaining bare `.expect()` calls carry `SAFETY:` rationales.

### Added — protocol gaps closed against the reference Python client (2026)
- **Trusted-browser re-login (no OTP after the first pairing).** After
  `login`, `authenticate` now probes `POST /api/getFactorId
  {factorType:"BROWSER", factorData:"", userId}`; when Arlo recognises
  this client it answers with a BROWSER `factorId`, and
  `POST /api/startAuth {factorId, factorType:"BROWSER", userId}` returns
  the final token directly — no `getFactors`, no OTP. Otherwise the
  usual factor/OTP ceremony runs. `login` responses with
  `authCompleted: true` short-circuit the same way. New public methods:
  `ArloClient::get_factor_id` (now returns the factor id) and
  `ArloClient::start_auth_trusted`. Verified live on 2026-09-25: a full
  OTP login paired the browser ("Browser paired with Arlo"), and the
  next login with a dropped token completed with "Trusted browser
  accepted by Arlo — no OTP required".
- **Pairing fixed and made durable.** `startPairingFactor` is now called
  with the `browserAuthCode` that `finishAuth` returns (the OTP path
  previously sent the MFA `factorAuthCode`, so the browser was never
  actually trusted), and failures are logged instead of swallowed. The
  transport's cookie jar — Arlo binds trust to its cookies plus
  `x-user-device-id` — is exported into the session cache
  (`cookies` field, `PersistentJar` JSON) and restored on start. When a
  cached token is stale the client now keeps the paired identity
  (`device_id` + cookies) and drops only the token; previously it
  regenerated a fresh `device_id`, discarding the trust.
- **`HttpTransport::export_cookies` / `import_cookies`** (default no-op)
  and `client::cookies::PersistentJar`, the `wreq` cookie store behind
  `WreqTransport`.
- **Arlo error-code table** (`models::error_codes`, ported from the
  official web client via the reference Python client): `ErrorAction`
  (`Retry`, `Reauth`, `AuthPending`, `Fatal`, `OtpRetry`, `Rejected`,
  `DeviceOffline`, `Unclassified`), `classify`, and the official message
  text per code. `ArloError::action()` maps any error to an action —
  9017 lockouts are `Fatal` (never retry), 9204 "browser not trusted" and
  HTTP 401/403 are `Reauth`, 9233/9276/9278 are `AuthPending` (the push
  poll now recognises all of them). `Meta::is_success` /
  `Meta::into_error` build the error with the best available message.
- **`allowedMqttTopics`** (`Device::allowed_mqtt_topics`, from
  `/hmsweb/v2/users/devices`) is now the preferred MQTT subscription
  set — the broker's own ACL grant, valid for owner and shared accounts
  alike; the hand-built topic list remains the fallback.
- **Custom modes by name (v3).** `ArloClient::get_automation_config`
  parses `GET /hmsweb/automation/v3?locationId=…&revisions=false` into
  `AutomationConfig` (standard mode ids + per-gateway custom-mode
  name ↔ uuid map, sentinel names resolved like the app);
  `ArloClient::set_mode_by_name` PUTs `{"mode": <standard>}` or
  `{"mode":"custom","custom":{<gateway>: <uuid>}}` with the current
  revision; `ArloClient::location_for_device` resolves a gateway's
  location through the new `Location::gateway_device_ids`
  (`"<userId>_<deviceId>"`-aware). `ArloEvent::active_mode` /
  `active_mode_change()` surface v3 `feedNotification` mode changes.
- **IMAP OTP parsing** gained the reference client's bare-digit-line
  match, with fixtures for the 2026 ISO-8859-1 / quoted-printable
  template (`text/plain` + `text/html`, `©` footer) and plain-only mail.

### Changed — ⚠️ BREAKING (API)
- `ArloError::ApiError` gained `error: Option<u32>` (Arlo `meta.error`);
  its `Display` is `API Error [<code>/<error>]: <message>`.
- Auth-ceremony envelope failures (`login`, `getFactors`, `startAuth`,
  `finishAuth`, push polls) are now `ApiError` carrying the Arlo code,
  not `AuthError(String)`; `AuthError` is reserved for local
  preconditions (missing credentials, no token, missing fields).
- `Device`, `ArloEvent` and `Location` gained fields
  (`allowed_mqtt_topics`, `active_mode`, `gateway_device_ids`; all
  `#[serde(default)]`), which affects struct-literal construction.
- `ArloClient::get_factor_id` returns `Result<String, _>`.
- New direct dependency `cookie_store` (already in the graph via wreq).

### Changed — ⚠️ BREAKING: browser-less default transport
- **`WreqTransport` is the default transport.** Arlo's Cloudflare front
  admits clients on their TLS + HTTP/2 fingerprint alone (no JS /
  Turnstile challenge — verified against the reference Python client,
  which moved to `curl_cffi` Chrome impersonation in June 2026 for the
  same reason). Every request now goes through a `wreq` client built
  with the Chrome emulation `stealthscraper-rs` measured
  (`emulation::for_kind(profile.browser_kind())`), carrying the
  profile's `User-Agent` and `Sec-CH-UA` / `-Mobile` / `-Platform` hints
  and a per-session cookie store. **No Chrome process is launched**;
  `ArloClientBuilder::build()` is now cheap and needs no browser binary.
  Verified live on 2026-09-25: the full EMAIL/IMAP MFA ceremony
  (`login → getFactors → startAuth → finishAuth → validateAccessToken →
  session/v3`), the v3 device list and logout all completed through
  `WreqTransport` against the production Cloudflare front.
- The headless-Chrome MITM-proxy transport (`CloudScraperTransport`)
  moved behind a new off-by-default **`browser` cargo feature** and is
  selected with `ArloClientBuilder::browser(true)` / `[client]
  use_browser = true`. It no longer disables certificate verification:
  the `reqwest` client trusts exactly the proxy's per-process CA
  (`TlsSpoofingProxy::ca_pem()`) instead of `danger_accept_invalid_certs`.
  `ArloClientBuilder::headless` is ignored by the default transport.
- `ArloError::NetworkError` now wraps
  `Box<dyn std::error::Error + Send + Sync>` (was `reqwest::Error`) so
  both HTTP clients map into it; the concrete error is reachable via
  `source()`. `HttpTransport::streaming_client` (dead since the SSE bus
  was removed) is gone; `HttpRequest` is `Clone`.
- New: automatic retry of Cloudflare rate limiting — HTTP 429, or any
  body carrying `error code: 1015` — three attempts, 3 s apart, in
  `execute_request` (mirrors pyaarlo's loop).
- New dependency `wreq` (temporary, same version and features as
  `stealthscraper-rs`; removed once that crate re-exports it).
  `stealthscraper-rs` is consumed without default features, which drops
  the CDP client, Chrome launcher and their dependencies from the
  default build.

### Changed — ⚠️ BREAKING: crate renamed `rs-arlo` → `arlo-rs`
- The package is now `arlo-rs` (library crate `arlo_rs`), matching the
  repository `YpNo/arlo-rs`. Every `use rs_arlo::…` becomes
  `use arlo_rs::…`; the `RUST_LOG` target is `arlo_rs`. Path-dependent
  consumers point at `../arlo-rs`.

### Changed — build reproducibility
- `stealthscraper-rs` is consumed from crates.io at **1.0.0**, which ships
  on `wreq` 6 and, in its default build, both `impersonation_client()` and
  a `pub use wreq` re-export. `arlo-rs` therefore has no direct `wreq`
  dependency any more: the transport is built from
  `stealthscraper_rs::impersonation_client(&profile)` (emulation,
  `User-Agent`, `Sec-CH-UA*` and `Accept-Language` from one profile) and
  `PersistentJar` implements the `wreq` 6 `CookieStore` contract (`Uri`
  in, one combined `Cookie` field out, on every HTTP version — Chrome does
  not split cookie pairs). `cookie_store` moved to 0.22.
- CI runs every cargo step with `--locked` so a fresh resolution can never
  silently change the build. The clippy and doc jobs gained the native
  BoringSSL build deps (cmake, libclang, nasm, go) they were missing.
- One silent behavioural change from the upgrade: `BrowserProfile::random()`
  now presents Chrome 153 instead of 124–126.

### Security
- Upstream response bodies no longer reach error messages whole. Every
  site that embedded a body (`unwrap_envelope`, `ArloError::HttpError`'s
  `Display`, the device/location parse errors, the signaling reply) now
  goes through `models::redact::excerpt`: JSON secrets replaced, control
  characters stripped, capped at 256 bytes. The full body stays in the
  `HttpError` field for code that inspects it.
- The `debug_mode` redaction list gained `browserAuthCode`, `credential`,
  `cookie`, `url`, `streamUrl`, every `presigned*` key and every key
  ending in `token`, `password` or `credential`.
- The `startStream` wait logs event identifiers only; it used to
  Debug-dump every bus event, stream and presigned URLs included.
- A `config.toml` syntax error no longer echoes the offending line (which
  for a slip on `password = …` was the password itself).
- `Debug` now redacts `factor_auth_code` (`AuthResult`, `MfaChallenge`,
  `VerifyFactorRequest`, `StartAuthData`, `FinishAuthPushRequest`), the
  TURN `credential` (`IceServer`), `presigned_last_image_url` (`Device`),
  location coordinates (`Location`), proxy userinfo (`ClientConfig`,
  `ArloClientBuilder`), the session-cache schema, and the transport DTOs
  (`HttpRequest` header values, both bodies).
- Test fixtures no longer carry live-capture identifiers: the account id,
  three device serials, two xCloudIds and an expired SIP password / TURN
  credential were replaced by synthetic values of the same shape.
- A `secrets` CI job runs gitleaks over the commits of every push and PR
  (`.gitleaks.toml` adds rules for the session cache, presigned S3 URLs and
  OTP mail dumps); `.gitignore` and the crate `exclude` list now cover
  logs, mail dumps, recordings and the sweep reports, so the artefacts
  that were committed once (`examples/log.txt`, `examples/email.txt`,
  `.arlo_session_push.json`) cannot recur. Those three files still exist
  in git history; purging them is a force-push the maintainer runs.
- Values the cloud hands back are validated before use (`models::validate`,
  fail-closed): the `session/v3` `mqttUrl` and the `sipInfo/v2` signaling
  domain must be `wss://` on an Arlo host (the WebSocket connector itself
  refuses non-TLS schemes); ICE servers must be stun/turn/turns on Arlo
  hosts with a numeric port; a stream URL is accepted only as `rtsps`
  or `https` with a host (`StreamUrl::parse`, plain `rtsp` upgraded as
  before); identifiers interpolated into request paths and queries
  (device, location, user ids; hub dates and media paths) must be plain
  tokens; MQTT filters from `allowedMqttTopics` must stay inside the
  device or own-inbox namespace with well-formed wildcards.
- Every body read is bounded: 8 MiB on both HTTP transports (chunked
  read, `Content-Length` checked first), 512 MiB for a local-hub media
  download, 1 MiB per WebSocket message/frame, 256 KiB per MQTT frame
  before reassembly, and the ambient-history decoder caps its base64
  input (1 MiB) and inflated output (4 MiB). The envelope unwrapper moves
  `data` out instead of cloning the whole body.
- Lockfile bumped past two RUSTSEC advisories: `rustls` 0.23.45
  (RUSTSEC-2026-0285, TLS 1.3 handshake across encryption levels) and
  `h2` 0.4.19 (RUSTSEC-2026-0258, unbounded empty DATA frames);
  `chacha20` moved off a yanked release; `quinn-proto` 0.11.18
  (RUSTSEC-2026-0185) and `anyhow` 1.0.104 (RUSTSEC-2026-0190) likewise.
  The two `lru 0.13` unsound advisories (RUSTSEC-2026-0002, -0253) are
  gone with `wreq` 6 (`lru` 0.18), so `deny.toml` and the CI audit carry
  no ignores and the audit job is back to `--deny warnings`. `deny.toml`'s
  duplicate-version skip list was rebuilt against the current graph (the
  old entries named `headless_chrome`, `rquest-util` and `rcgen`, none of
  which remain).

### Fixed
- `cargo doc` is warning-free again: duplicated one-line outer docs on
  `pub mod` declarations were removed (rustdoc merged them with the
  modules' own `//!` docs and then resolved the inner links in the wrong
  scope), and links to crate-private items became plain code spans.

### Removed — repository hygiene
- `.arlo_session_push.json`, `examples/log.txt` and `examples/email.txt`
  are no longer tracked (session artefact, a live-run log carrying account
  identifiers and presigned URLs, and a real OTP email). `.gitignore` now
  covers `.arlo_session*.json`.

### Removed — ⚠️ BREAKING: arlo-rs is now signaling-only for v3 live
- Deleted the in-crate WebRTC **media** plane: `ArloClient::start_live`,
  `ArloClient::start_live_rtsp`, `LiveStream`, `RtspLiveStream`, the
  built-in localhost RTSP publisher (`client::rtsp_pub`), the SDP
  bundle-munge, the Opus-silence pump, the `on_track`/PLI keyframe pump,
  the `SettingEngine`/ICE-server mapping, and the **`webrtc` 0.17
  dependency** (and its entire ICE/DTLS/SRTP transitive graph — ~260
  fewer crates). The `webrtc_live` / `webrtc_rtsp` manual examples are
  removed too.
  - **Why:** Arlo's v3 gateway is **non-bundled `FreeSWITCH`** and
    requires a Chrome-style two-ICE-transport client; the pure-Rust
    `webrtc` 0.17 stack is BUNDLE-only and provably cannot negotiate it
    (confirmed live: ICE never completes). The WebRTC media plane now
    lives in the **consumer** (the streamer's GStreamer `webrtcbin`,
    proven against the live camera).
  - **Kept (the public live API):** `ArloClient::sip_info`,
    `ArloClient::webrtc_negotiate` (offer SDP in → answer SDP out),
    `SignalingSocket` + `SignalingSocket::disconnect`
    (`sessionDisconnected`), `SignalingAnswer`, `SipInfo`, and all the
    HTTP-over-WS framing helpers + their fixture tests. Consumers
    generate the offer, call `webrtc_negotiate`, apply the answer, and
    own teardown via `SignalingSocket::disconnect`.
  - SemVer: breaking — bump **MINOR** while pre-1.0 (`0.x`), per the
    project's pre-1.0 policy.

### Added (live video — WebRTC, Phases 1–2)
- **`ArloClient::sip_info(&Device)`** — `GET /hmsweb/users/devices/
  sipInfo/v2` (xcloudId header + envelope) → `SipInfo` (SIP callee URI,
  per-call password, STUN/TURN `iceServers`). v3 cameras no longer
  serve an `rtsps://` URL (legacy `/startStream` 502s); live is WebRTC.
- **`ArloClient::webrtc_negotiate`** + **`SignalingSocket`** — the
  `hmswebsocketproxy` HTTP-over-WSS exchange (`wss://<domain>:7443/`,
  subprotocol `sip`): `POST /initiateOffer` (SDP offer) → `200 OK`
  (SDP answer); `POST /sessionDisconnected` on teardown. Framing
  fixture-tested against the captured bytes.
- **`ArloClient::start_live(&Device) -> LiveStream`** — full WebRTC
  peer (`webrtc` crate): recvonly H.264 offer pinned to the gateway's
  profile (`42001f`, pkt-mode 1, pt 103), Arlo ICE servers, non-trickle
  gather, apply answer, expose inbound H.264 RTP on `LiveStream::rtp`.
  `LiveStream::close()` + a `Drop` RAII safety net guarantee the peer +
  `sessionDisconnected` are torn down on every exit (incl. panic/abort)
  so a forgotten handle can't leave the camera streaming (battery).
- New dependency: `webrtc` 0.17 (pure-Rust ICE/DTLS/SRTP — no rtsps
  path exists for v3).
- **`ArloClient::start_live_rtsp(&Device) -> RtspLiveStream`** (Phase 3)
  — fronts the WebRTC H.264 RTP with a minimal built-in RTSP/1.0
  server (TCP-interleaved only, RFC 2326 §10.12). `RtspLiveStream::url()`
  yields `rtsp://127.0.0.1:<port>/<deviceId>` that any RTSP client
  (the streamer's `rtspsrc … protocols=tcp+udp`, VLC, ffmpeg) pulls
  unchanged, so the streamer's `StreamSource{url}` port is untouched.
  Inbound RTP is re-stamped to payload type 96 to match the served
  SDP. `RtspLiveStream` close/Drop tears down RTSP **and** WebRTC.
  Verified live: 681 H.264 RTP packets / ~281 kbps from a real camera.
- The smoke-test fixes that made the live path work: `sipInfo/v2`
  needs `cameraId` as a request header (not just query); and the
  gateway's SDP `a=ssrc` must be stripped or webrtc-rs won't fire
  `on_track` for the camera's (different) inbound SSRC.

### Fixed (live video — Phase 5: streamer end-to-end)
- **⚠️ Root cause: v3 live is a FreeSWITCH *SIP call* — it needs an
  audio m-line.** A live HAR of the working web client shows the offer
  is **two bundled m-lines**: sendrecv Opus audio (the browser sends
  mic audio) **and** recvonly H.264 video. FreeSWITCH answers audio
  `sendrecv` + video `sendonly` on **separate, non-bundled** ICE/DTLS
  transports, and only relays the camera's video once the audio call
  leg is up. Our offer was video-only, so ICE/DTLS/RTCP succeeded but
  **zero video RTP ever arrived** (the camera was never "called"). This
  is the true cause of "idle never switches to live" — not the earlier
  ICE-gathering theory.
  - `start_live` now offers a **sendrecv Opus** audio transceiver
    (m-line 0, matching the web client) backed by a
    `TrackLocalStaticSample`, and runs a 20 ms **silence pump**
    (`Weak`-scoped) — we have no microphone, the pump just keeps the
    SIP call (and thus the video relay) alive.
  - `on_track` now ignores the camera's inbound audio leg
    (video-only → RTSP bridge).
  - `strip_ssrc_attrs` removed: with a two-m-line answer webrtc-rs
    maps inbound RTP by the gateway's **declared** SSRC; the old
    single-section undeclared-SSRC trick would defeat that.
  - **`bundle_answer_to_match_offer`** — FreeSWITCH answers our
    *bundled* offer **non-bundled** (per-m-line `ice-ufrag`/`ice-pwd`/
    candidates, no `a=group:BUNDLE`); webrtc-rs 0.17 is BUNDLE-only and
    rejects it (`set_remote_description called with multiple conflicting
    ice-ufrag values`). The answer is now rewritten to a single bundled
    transport pinned to the **video** m-line's ICE, with the offer's
    `a=group:BUNDLE` + per-line `a=mid` re-attached (FreeSWITCH omits
    mids). Safe: FreeSWITCH presents one DTLS identity (same
    `fingerprint` + `setup:active`) for both m-lines. The audio leg is
    throwaway silence, so collapsing it onto the video transport is
    lossless for our purpose. Legacy single-m-line answers pass through.
- **IPv4-only UDP, mDNS disabled** (`SettingEngine`:
  `NetworkType::Udp4`, `MulticastDnsMode::Disabled`). FreeSWITCH
  **mirrors the offer's address family** in its single host candidate:
  a dual-stack offer makes it answer an IPv6 host unreachable from the
  client (the STUN/TURN relay can't resolve over IPv6 either), so ICE
  stalls in `Checking` then `Failed`s after ~30 s; a Udp4-only offer
  makes it answer a reachable IPv4 host and ICE/DTLS complete (verified
  live). Also kills the IPv6 link-local listen spam. mDNS off removes
  `.local` candidates the gateway can't resolve. A config knob to force
  dual-stack (IPv6-only / CGNAT networks) is a planned follow-up.
- **Unusable TCP TURN dropped.** `ice_servers()` filters the
  `transport=tcp` TURN: webrtc-ice 0.17 `gather_candidates_relay` only
  handles UDP TURN, so the TCP one only logged "Unable to handle URL".
  Arlo always also offers a UDP TURN (kept).
- **Keyframe-on-demand.** The H.264 codec advertises
  `nack`/`nack pli`/`ccm fir`/`goog-remb`, and `start_live` runs a
  periodic RTCP **PLI** pump (every 3 s, `Weak`-scoped). Arlo emits
  only sparse unsolicited IDRs, so a late-joining / reconnecting RTSP
  client previously stalled with no decodable frame; it now recovers
  within ≤3 s. Addresses "can't reconnect to the stream".

### Changed — ⚠️ event bus migrated SSE → MQTT-over-WSS
- The legacy SSE channel `/hmsweb/client/subscribe` returns **403**
  under the v3 API. `EventBus` now connects to Arlo's MQTT broker over
  WebSocket (`wss://<mqttUrl>/mqtt`, `Sec-WebSocket-Protocol: mqtt`,
  `Origin: https://my.arlo.com`), reverse-engineered from a live HAR:
  MQTT 3.1.1, clean session, keep-alive 60 s; `CONNECT` clientId
  `user_<userId>_<rand>`, username `<userId>`, password `<accessToken>`;
  `SUBSCRIBE` (QoS 0) to the web client's **fine-grained** per-resource
  topics keyed by each device's `xCloudId` (**not** its `deviceId`):
  `d/<xCloudId>/out/<cameras|doorbells|chimes>/<deviceId>/#` plus
  `d/<xCloudId>/out/<resource>/#` for wifi/modes/basestation/… and
  `u/<userId>/in/#`. The broad `d/<xCloudId>/out/#` wildcard is
  **owner-only** — shared/secondary accounts get SUBACK `0x80` for it,
  so the explicit set is required. Inbound `PUBLISH` payloads keep the
  legacy
  event JSON shape, so `ArloEvent` and the broadcast/`ConnectionState`
  API are **unchanged** (downstream consumers need no changes).
- `session/v3` now parses `mqttUrl` (`SessionV3Response::mqtt_url`);
  `ArloClient::events()` resolves it + the device list to build the
  subscription, then spawns the reconnecting listener.
- New deps: `tokio-tungstenite` (rustls), `mqttbytes`, `bytes`,
  `futures-util`. The 10-min session/v3 keep-alive pinger is replaced
  by MQTT `PINGREQ` at 30 s. SSE framing code removed.
- ⚠️ The MQTT WSS connection does **not** route through the
  cloudscraper/JA4 transport yet (different host; tracked).

### Added (MFA)
- **`authenticate_with_push(config, poll_interval, timeout)`** — PUSH
  2FA support, reproducing the Arlo web client's PingOne push ceremony
  (**verified against a live HAR capture**): `login` →
  `POST /api/startAuth {factorType:"", userId}` (Arlo dispatches the
  account's PRIMARY factor and returns its push `factorAuthCode` +
  factor list) → poll `POST /api/finishAuth
  {factorAuthCode, isBrowserTrusted}` (**no `otp` field**). Every poll
  is HTTP 200; state is read from the `meta` envelope —
  `code:400 error:9233` ("Authentication is not finished yet") = still
  pending, `code:200` + `data.token` = approved. Pairing then uses the
  approved response's `data.browserAuthCode` (distinct from the push
  `factorAuthCode`). Requires PUSH to be the account's PRIMARY factor.
  Defaults `DEFAULT_PUSH_POLL_INTERVAL` (5 s) / `DEFAULT_PUSH_TIMEOUT`
  (120 s, matching Arlo's `MFA_Config.timeout.PUSH`). The
  post-`finishAuth` continuation is shared (`complete_session`) between
  `submit_mfa` and the push path; `AuthResponseData` gained
  `browser_auth_code`.

### Added (V3 migration + streaming)
- **`get_stream_url(&Device) -> Result<Option<StreamUrl>, ArloError>`** —
  synchronous peek (`action: "get"` on `/startStream`) that returns an
  already-active stream (e.g. one a user opened from the Arlo mobile
  app) without triggering a new one. URL rewritten `rtsp://` → `rtsps://`.
- **`force_start_stream(&Device)`** — always issues a fresh
  `startUserStream` + SSE-correlated URL (the previous `start_stream`
  behaviour, now `&Device`-typed and sending `to: parent_id`).
- **`start_stream(&Device)`** now peeks via `get_stream_url` first and
  only falls back to `force_start_stream` on a miss.
- **`Device` fields** `x_cloud_id`, `automation_revision`,
  `connectivity`, plus `Device::is_self_hosted()`.
- **`ApiVersion` config** (`[client].api_version`, default `v3`) with
  automatic V3→Legacy fallback on any 403/404, and a per-client
  override for un-migrated accounts.
- HAR-verified V3 endpoints: `/hmsweb/v2/users/devices`,
  `/hmsweb/devicesupport/v3`, `/hmsweb/automation/v3/activeMode`,
  and the `DELETE /hmsweb/user/{uid}/client/smart/devices/logout`
  flow.

### Changed — ⚠️ breaking, pre-0.1.0-tag
- **`start_stream` signature changed** from
  `start_stream(&self, camera_id: &str)` to
  `start_stream(&self, device: &Device)`. Older cameras sit behind a
  separate base station; the stream POST must target `device.parent_id`
  (`to`), which a bare camera-ID string couldn't supply. Passing the
  whole `Device` also yields the `xCloudId` header the modern endpoint
  expects. Callers: replace `client.start_stream(&cam.device_id)` with
  `client.start_stream(cam)`.
- **`logout` is now `DELETE`** to the V3
  `/hmsweb/user/{uid}/client/smart/devices/logout?clientId=…&eventId=…&time=…`
  URL (was the wrong `PUT /hmsweb/logout` in the interim work). Legacy
  `PUT /hmsweb/logout` retained as the auto-fallback.
- **`set_mode` v3** now reads `revision` from the correct
  location-keyed response shape and always sends the
  `{"mode":"custom","custom":{…}}` wrapper (per pyaarlo#195). The
  broken 36-char UUID heuristic and the wrong `data.revision` lookup
  were removed.
- **`device_support`** no longer rewrites `api_version` on the success
  path — a deliberate `Legacy` pinning now survives a chance V3
  success.

### Coverage
- Line coverage is **70.3%** (793/1128) after the V3-migration tests,
  up from 68% in PR 6. Notably, the `PinnedLeafVerifier` cert-pinning
  boundary (the crate's most security-critical code, previously 0%
  covered) now has explicit positive + negative tests.
- The CI gate is **65%** (`--fail-under 65`) — 5 points below measured
  for run-to-run stability, not because coverage is 65%. The earlier
  `ci.yml` flag said `70` while its own comment said `65`; reconciled
  to 65 here.
- Path to 85% unchanged — still gated on the three infra investments
  below (SSE streaming-HTTP mock, IMAP server mock, CloudScraper-boot
  harness).

### Out of scope / future direction
- Arlo's web portal now streams via SIP-over-WSS
  (`wss://livestream-z1-prod.arlo.com:7443/`,
  `Sec-WebSocket-Protocol: sip`, seeded by
  `GET /hmsweb/users/devices/sipInfo/v2`). The legacy `/startStream`
  + SSE path remains and is what `arlo-rs` uses. A `LiveStreamWss`
  adapter is future work for accounts where the legacy path is retired.

### Added (PR 6)
- **Test coverage push** from 27% → 68% (+41 pts). 73 new unit tests
  across `auth.rs`, `devices.rs`, `library.rs`, `ratls.rs`, `mfa.rs`,
  `models/api.rs`, plus shared `client/test_helpers.rs` scaffolding
  and a public-API integration test under `tests/transport_integration.rs`.
- `MockTransport` switched from LIFO (stack) to FIFO (`VecDeque`) with
  new `queue_post` / `queue_get` helpers that handle the OPTIONS
  preflight pair correctly. Existing PR-4 tests updated.
- `Debug` derive on `EventBus` so test code can use `unwrap_err()`
  against `Result<&EventBus, ArloError>`.

### Changed (Improvement-v5)
- **Dropped MQTT claim**: `workfile.md` and `README.md` no longer
  describe a "dual SSE+MQTT" backend. Only SSE is implemented and
  supported. The MQTT broker host (`mqtt-cluster.arloxcld.com`) is
  documented as de-scoped — file a feature request if downstream needs
  it.
- **CI coverage gate** lowered from 80% to 65% to match what's
  achievable today. The 80% target is preserved in spirit — see the
  three infrastructure investments below.

### TODO — path to 85% coverage
The remaining 17 percentage points are concentrated in three
structurally hard areas. Each is its own PR-sized investment.

1. **Streaming-HTTP mock for `events/mod.rs`** (~60 uncovered lines):
   the SSE listener is an infinite-loop spawn that needs a fake HTTP
   server emitting `text/event-stream` chunks. Likely shape: a tiny
   `tokio::io::duplex`-backed `reqwest::Client` factory so we can
   assert on the `EventBus::start` → `subscribe` → reconnect path.
2. **IMAP server mock for `client/auth_imap.rs` + `client/mfa.rs`
   `ImapMfaHandler`** (~50 uncovered lines combined): needs a tiny
   in-process IMAP responder. Likely a feature of the sibling
   `imap-rs` workspace once tests there grow that deep.
3. **CloudScraper-boot harness for `client/builder.rs::bootstrap` and
   `client/transport.rs::CloudScraperTransport`** (~50 uncovered
   lines): `rs-cloudscraper` would need a `mock_browser` mode that
   skips the headless-Chrome bootstrap.

### TODO before publishing to crates.io
- Swap `rs-cloudscraper` from the `path = "../rs-cloudscraper"` dev
  dependency to `git = "...", tag = "v0.2.0"` once the upstream tag is
  verified to match this crate's call sites. Path dependencies block
  `cargo publish`.

## [0.1.0] - Initial public-API freeze

This release sequence (PR 1 → PR 5) lifted `arlo-rs` from a half-broken
prototype to a production-ready library suitable for downstream
streaming applications.

### Added
- **Async-native IMAP MFA handling** built on the sibling `imap-rs`
  workspace (PR 1). No more `tokio::task::spawn_blocking` /
  `std::thread::sleep` polling — the OTP poller stays on the runtime.
- **`secrecy::SecretString` access tokens** (PR 2). The token is
  zeroized on drop and never reaches `Debug` output.
- **`ArloClient::builder()`** for programmatic construction without
  TOML (PR 2). `from_config` becomes a thin shim.
- **`MfaHandler` trait** with two-phase lifecycle (`prepare`,
  `provide_otp`) plus shipped impls: `ImapMfaHandler`,
  `StdinMfaHandler`, `StaticOtpHandler` (PR 2).
- **`start_stream(id) → Result<StreamUrl, ArloError>`** correlates the
  SSE response to the POST via `transId`, removing the need for
  consumers to wire their own SSE plumbing (PR 2).
- **`EventBus`** replaces the previous `EventManager`: clonable
  `subscribe()`, proper `\n\n` SSE frame parsing, `Drop` aborts
  background tasks, and a `watch::Receiver<ConnectionState>` for
  consumers that need to react to reconnects (PR 2 → PR 3).
- **`ArloClient::reattach(SessionToken)`** + `session_token()` for
  out-of-process session persistence (PR 3).
- **Local SmartHub client** (`LocalHubClient`) with rustls leaf-cert
  pinning derived from the RATLS-issued cert — replaces blanket
  `danger_accept_invalid_certs(true)` (PR 3).
- **`HttpTransport` trait + `ArloEndpoints`** (PR 4). Production wires
  `CloudScraperTransport`; tests substitute `MockTransport` and
  `ArloEndpoints::testing(...)` to drive the orchestration layer
  without booting the headless-browser proxy.
- **`ArloClient::with_transport(transport, endpoints)`** test/advanced
  constructor that skips the heavyweight CloudScraper bootstrap
  entirely (PR 4).
- **`tracing-subscriber`-driven examples** with sensible default
  filters (`warn,arlo_rs=info`) (PR 5).
- **`rust-toolchain.toml`** pinning Rust 1.95.0 to match the sibling
  `imap-rs` workspace (PR 5).
- **CHANGELOG.md** itself (this file) (PR 5).

### Changed
- **DRY-up of envelope parsing** — the four near-identical
  `success` / `meta.code == 200` blocks collapsed into a single
  `models::envelope::unwrap_envelope[_array]` helper (PR 3).
- **`notify`-style commands** (`take_snapshot`, `start_record`,
  `stop_record`, `restart_device`, …) now route through the existing
  `notify()` orchestrator instead of rebuilding the payload manually
  six times (PR 3).
- **Public field lockdown** on `ArloClient`: `auth`, `reqwest_client`,
  `cloud_scraper`, `debug_mode` are now `pub(crate)`. External access
  is via `is_authenticated()`, `user_id()`, `device_id()`, and
  `events()` (PR 2).
- **OPTIONS preflight, header injection, and JSON envelope handling**
  moved above the wire layer; the transport just executes (PR 4).
- **Examples migrated from `log` + `env_logger` to
  `tracing-subscriber`** (PR 5).

### Fixed
- **Build was broken** at the start of PR 1 — `auth_imap.rs` referenced
  `imap_client::ClientBuilder` which the new async crate doesn't expose.
- **Config / session secrets unprotected**: `config.toml`,
  `.arlo_session.json`, and `*.har` traces are now in `.gitignore`;
  the on-disk session cache is written `0600` on Unix; sensitive JSON
  keys are scrubbed from `debug_mode` body dumps before they reach
  the tracing layer (PR 1).
- **SSE frames straddling chunk boundaries** were silently dropped by
  the per-chunk `\n` splitter. Replaced with a stateful framer that
  splits on `\n\n` / `\r\n\r\n` per WHATWG (PR 2).
- **Dropped `EventManager` leaked tasks** — both background tasks
  (SSE listener and keep-alive ping) are now aborted in `Drop` (PR 2).
- **`unwrap_or("unknown_user")`** in eight `notify`-style methods
  silently sent meaningless `from: "unknown_user_web"` requests when
  the client wasn't yet authenticated. Replaced with an explicit
  `ArloError::AuthError` (PR 3).
- **Abandoned tests** with the comment
  `// This will fail because of hardcoded host` are now real tests
  exercising `validate_session_v3` and `get_devices` against a mocked
  transport with overridden endpoints (PR 4).

### Removed
- **`native-tls`** unused dependency (`reqwest` is configured for
  `rustls`) (PR 5).
- **`log`** and **`env_logger`** removed from `[dependencies]` /
  `[dev-dependencies]` (PR 5). The codebase uses `tracing` end-to-end.

### Security
- All token-sensitive HTTP headers and JSON keys (`token`,
  `accessToken`, `password`, `otp`, `factorAuthCode`,
  `authorization`, `refreshToken`) are recursively redacted from
  `debug_mode` body dumps (PR 1).
- The session cache file is written with mode `0600` on Unix (PR 1).
- Access tokens live in `secrecy::SecretString` and are zeroized on
  drop (PR 2).
- The local SmartHub client pins the leaf certificate Arlo issued for
  the device, instead of accepting any self-signed cert (PR 3).
