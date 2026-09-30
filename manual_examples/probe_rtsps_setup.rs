//! Manual probe: which SETUP URL form does Arlo's RTSPS server accept for
//! the app's watch-along stream (obtained as the iOS app identity)?
//!
//! Background: pyaarlo PR #166 (`get_stream_url`, 2025-01) returned an
//! `rtsp://` URL for a running stream; our 2026-09 captures of the same
//! request, sent as a browser, got a DASH URL. pyaarlo documents that the
//! stream format follows the `User-Agent`.
//!
//! ## ⚠️ Hits your live Arlo account
//!
//! The query reaches the camera, so it is sent at most **three times per
//! camera per run** — as the app at `ARLO_PROBE_APP_VERSION` (default
//! 6.46.0), then as pyaarlo's 5.4.3 agent, then as the legacy Vuezone
//! agent, stopping at the first `rtsps://` — and only after the bus
//! reported `activityState == "userStreamActive"`. It never polls.
//!
//! Same prerequisites as `list_cameras`. Stop the streamer daemon first.
//! Start the probe, open a live view of a camera in the app, keep it open
//! until the probe reports, then close it:
//!
//! ```bash
//! cargo run --example probe_app_ua_stream_url
//! ARLO_PROBE_PLAY=1 cargo run --example probe_app_ua_stream_url  # also try playback
//! ARLO_PROBE_SECS=180 cargo run --example probe_app_ua_stream_url
//! ```
//!
//! Reports the URL's `scheme://host`, kind (path extension) and whether
//! it is a watch-along; with `ARLO_PROBE_PLAY=1`, three `gst-launch-1.0`
//! run on it (URL stripped from the output). Never prints the URL's path
//! or query: they carry the stream's token.

use arlo_rs::client::devices::{
    IOS_APP_USER_AGENT_LEGACY, PYAARLO_IOS_APP_VERSION, ios_app_user_agent,
};
use arlo_rs::config::ArloConfig;
use arlo_rs::models::api::{Device, StreamUrl};
use arlo_rs::models::events::ArloEvent;
use arlo_rs::{ArloClient, ArloError, ImapMfaHandler};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const CONFIG_PATH: &str = "config.toml";
const CACHE_PATH: &str = ".arlo_session.json";
const DEFAULT_WINDOW_SECS: u64 = 120;
const USER_STREAM_ACTIVE: &str = "userStreamActive";
/// The owner's app version on 2026-09-30; `ARLO_PROBE_APP_VERSION` overrides.
const DEFAULT_APP_VERSION: &str = "6.46.0";

/// When the probe sent `startUserStream` to a camera.
type Requested = HashMap<String, Instant>;

/// The in-flight `startUserStream` and the camera it targets.
type Pending<'a> =
    Pin<Box<dyn Future<Output = (&'a Device, Result<Option<StreamUrl>, ArloError>)> + 'a>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("arlo_rs=warn")),
        )
        .init();
    println!("=== arlo-rs manual probe: stream URL as the iOS app, during an app view ===\n");

    let config = match load_and_validate_config() {
        Ok(c) => c,
        Err(why) => {
            eprintln!("✗ {why}");
            std::process::exit(2);
        }
    };
    let play = std::env::var("ARLO_PROBE_PLAY").is_ok_and(|v| v == "1");
    let window_secs = std::env::var("ARLO_PROBE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_WINDOW_SECS);

    let mut client = authenticate(&config).await?;
    let devices = client.get_devices().await?;
    let cameras: Vec<&Device> = devices
        .iter()
        .filter(|d| matches!(d.device_type.as_str(), "camera" | "arloq" | "doorbell"))
        .collect();
    println!(
        "✓ {} camera(s). Listening for {window_secs} s — open a live view in the app now.\n",
        cameras.len()
    );

    listen(&client, &cameras, window_secs, play).await?;

    println!("\n→ Logging out...");
    client.logout().await?;
    println!("✓ Done.");
    Ok(())
}

/// Print camera events for `window_secs`; send `startUserStream` next to
/// the loop, so the events Arlo sends while it waits print as they arrive.
async fn listen(
    client: &ArloClient,
    cameras: &[&Device],
    window_secs: u64,
    play: bool,
) -> Result<(), ArloError> {
    let bus = client.events().await?;
    let mut rx = bus.subscribe();
    let deadline = Instant::now() + Duration::from_secs(window_secs);
    let mut requested = Requested::new();
    let mut pending: Option<Pending<'_>> = None;
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(()),
            Some((cam, result)) = poll_pending(&mut pending) => {
                pending = None;
                match result {
                    Ok(Some(url)) => {
                        report_url(cam, &url, false);
                        if play {
                            setup_forms(client, cam, url).await;
                        }
                    }
                    Ok(None) => println!("  [probe] {}: no URL although the camera reports a user view", cam.device_name),
                    Err(e) => println!("  [probe] {}: query refused: {e}", cam.device_name),
                }
            }
            msg = rx.recv() => match msg {
                Ok(event) => {
                    if let Some(cam) = on_event(cameras, &event, &mut requested)
                        && pending.is_none()
                    {
                        pending = Some(Box::pin(async move { (cam, query_as_app(client, cam).await) }));
                    }
                }
                Err(RecvError::Lagged(n)) => println!("  [bus] lagged, {n} events skipped"),
                Err(RecvError::Closed) => return Ok(()),
            },
        }
    }
}

/// Await the in-flight request, or never resolve when there is none.
async fn poll_pending<'a>(
    pending: &mut Option<Pending<'a>>,
) -> Option<(&'a Device, Result<Option<StreamUrl>, ArloError>)> {
    match pending.as_mut() {
        Some(fut) => Some(fut.await),
        None => std::future::pending().await,
    }
}

async fn authenticate(config: &ArloConfig) -> Result<ArloClient, Box<dyn std::error::Error>> {
    let mut client = ArloClient::builder()
        .session_cache(CACHE_PATH)
        .build()
        .await?;
    if client.is_authenticated() {
        println!("✓ Restored a valid session from `{CACHE_PATH}`.");
        return Ok(client);
    }
    println!("→ No valid cached session; running IMAP-automated MFA...");
    let imap_cfg = config
        .mfa
        .as_ref()
        .and_then(|m| m.imap.clone())
        .ok_or("validated config lost its [mfa.imap] block")?;
    client
        .authenticate_with_handler(config, ImapMfaHandler::new(imap_cfg))
        .await?;
    println!("✓ Authenticated.");
    Ok(client)
}

/// Report a camera event (keys, `activityState`, whether it carries a
/// URL or a `transId`); on a camera's first user view, return it so the
/// caller sends `startUserStream` once.
fn on_event<'a>(
    cameras: &[&'a Device],
    event: &ArloEvent,
    requested: &mut Requested,
) -> Option<&'a Device> {
    let id = event.resource.strip_prefix("cameras/")?;
    let since = requested
        .get(id)
        .map(|at| format!(" ({:.1} s after our request)", at.elapsed().as_secs_f32()))
        .unwrap_or_default();
    println!(
        "  [bus] {id}: action={} keys={:?} transId={} url-keys={:?} activityState={:?}{since}",
        event.action,
        property_keys(event),
        event.trans_id.is_some(),
        url_keys(event),
        activity_state(event),
    );
    if activity_state(event) != Some(USER_STREAM_ACTIVE) || requested.contains_key(id) {
        return None;
    }
    let cam = cameras.iter().copied().find(|d| d.device_id == id)?;
    requested.insert(id.to_string(), Instant::now());
    println!(
        "  [probe] {}: user view seen; querying the stream URL as the iOS app",
        cam.device_name
    );
    Some(cam)
}

/// The `get` query under each app identity in turn, stopping at the
/// first `rtsps://` answer; the last answer otherwise.
async fn query_as_app(client: &ArloClient, cam: &Device) -> Result<Option<StreamUrl>, ArloError> {
    let version =
        std::env::var("ARLO_PROBE_APP_VERSION").unwrap_or_else(|_| DEFAULT_APP_VERSION.to_string());
    let identities = [
        (format!("iOS app {version}"), ios_app_user_agent(&version)),
        (
            format!("iOS app {PYAARLO_IOS_APP_VERSION} (pyaarlo)"),
            ios_app_user_agent(PYAARLO_IOS_APP_VERSION),
        ),
        (
            "legacy Vuezone app".to_string(),
            IOS_APP_USER_AGENT_LEGACY.to_string(),
        ),
    ];
    let mut last = None;
    for (label, ua) in &identities {
        let answer = client.get_stream_url_as(cam, Some(ua)).await?;
        match &answer {
            Some(url) if url.as_str().starts_with("rtsps://") => {
                println!("  [probe] {}: {label} → RTSPS", cam.device_name);
                return Ok(answer);
            }
            Some(url) => println!(
                "  [probe] {}: {label} → {} kind={} watchalong={}",
                cam.device_name,
                url.redacted(),
                url_kind(url.as_str()),
                is_watchalong(url.as_str())
            ),
            None => println!("  [probe] {}: {label} → no URL", cam.device_name),
        }
        last = answer;
    }
    Ok(last)
}

fn report_url(cam: &Device, url: &StreamUrl, play: bool) {
    println!(
        "  [probe] {}: URL {} kind={} watchalong={}",
        cam.device_name,
        url.redacted(),
        url_kind(url.as_str()),
        is_watchalong(url.as_str())
    );
    if !play {
        println!("  [probe] rerun with ARLO_PROBE_PLAY=1 to test playback");
    }
}

/// Seconds of interleaved data read after a successful PLAY.
const PLAY_READ_SECS: u64 = 3;
/// Per-request RTSP timeout.
const RTSP_TIMEOUT: Duration = Duration::from_secs(10);
const TRACK: &str = "trackid=1";

/// One RTSP session per SETUP form, each on a fresh watch-along URL.
async fn setup_forms(client: &ArloClient, cam: &Device, first: StreamUrl) {
    let app_ua = ios_app_user_agent(
        &std::env::var("ARLO_PROBE_APP_VERSION")
            .unwrap_or_else(|_| DEFAULT_APP_VERSION.to_string()),
    );
    let mut next = Some(first);
    for form in [Form::Base, Form::BaseQuery, Form::UrlTrack] {
        let url = match next.take() {
            Some(u) => u,
            None => match client.get_stream_url_as(cam, Some(&app_ua)).await {
                Ok(Some(u)) if u.as_str().starts_with("rtsps://") => u,
                other => {
                    println!(
                        "  [rtsp] {}: no fresh RTSPS URL ({other:?}); stopping",
                        form.label()
                    );
                    return;
                }
            },
        };
        match run_form(form, url.as_str(), &app_ua).await {
            Ok(true) => {
                println!("  [rtsp] {}: ACCEPTED, RTP flowing", form.label());
                return;
            }
            Ok(false) => println!("  [rtsp] {}: refused", form.label()),
            Err(e) => println!("  [rtsp] {}: failed: {e}", form.label()),
        }
    }
}

#[derive(Clone, Copy)]
enum Form {
    Base,
    BaseQuery,
    UrlTrack,
}

impl Form {
    const fn label(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::BaseQuery => "base+query",
            Self::UrlTrack => "url/track",
        }
    }
}

struct Response {
    code: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct Rtsp {
    stream: BufReader<TlsStream<TcpStream>>,
    cseq: u32,
    session: Option<String>,
    user_agent: String,
    /// Strings never to print: the original query and the session id.
    secrets: Vec<String>,
}

impl Rtsp {
    async fn connect(url: &url::Url, user_agent: &str) -> Result<Self, String> {
        let host = url.host_str().ok_or("URL without host")?.to_string();
        let port = url.port().unwrap_or(443);
        let tcp = tokio::time::timeout(RTSP_TIMEOUT, TcpStream::connect((host.as_str(), port)))
            .await
            .map_err(|_| "TCP connect timed out")?
            .map_err(|e| format!("TCP connect: {e}"))?;
        let provider = rustls::crypto::ring::default_provider();
        let config = rustls::ClientConfig::builder_with_provider(provider.clone().into())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS config: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| format!("server name: {e}"))?;
        let tls = tokio::time::timeout(
            RTSP_TIMEOUT,
            TlsConnector::from(std::sync::Arc::new(config)).connect(name, tcp),
        )
        .await
        .map_err(|_| "TLS handshake timed out")?
        .map_err(|e| format!("TLS handshake: {e}"))?;
        let query = url.query().unwrap_or_default().to_string();
        Ok(Self {
            stream: BufReader::new(tls),
            cseq: 0,
            session: None,
            user_agent: user_agent.to_string(),
            secrets: if query.is_empty() {
                Vec::new()
            } else {
                vec![query]
            },
        })
    }

    fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for s in &self.secrets {
            out = out.replace(s.as_str(), "<redacted>");
        }
        out
    }

    async fn request(
        &mut self,
        method: &str,
        uri: &str,
        extra: &[(&str, &str)],
    ) -> Result<Response, String> {
        self.cseq += 1;
        let mut req = format!(
            "{method} {uri} RTSP/1.0\r\nCSeq: {}\r\nUser-Agent: {}\r\n",
            self.cseq, self.user_agent
        );
        if let Some(s) = &self.session {
            req.push_str(&format!("Session: {s}\r\n"));
        }
        for (k, v) in extra {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        println!("  [rtsp]   → {method} {}", self.redact(uri));
        self.stream
            .get_mut()
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("send {method}: {e}"))?;
        let resp = tokio::time::timeout(RTSP_TIMEOUT, self.read_response())
            .await
            .map_err(|_| format!("{method}: no response within {RTSP_TIMEOUT:?}"))??;
        println!(
            "  [rtsp]   ← {} ({} header(s), {} body bytes)",
            resp.code,
            resp.headers.len(),
            resp.body.len()
        );
        if let Some(s) = resp.header("Session") {
            let id = s.split(';').next().unwrap_or(s).trim().to_string();
            self.secrets.push(id.clone());
            self.session = Some(id);
        }
        Ok(resp)
    }

    async fn read_response(&mut self) -> Result<Response, String> {
        let mut line = String::new();
        self.stream
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;
        let code: u16 = line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| format!("bad status line: {line:?}"))?;
        let mut headers = Vec::new();
        loop {
            line.clear();
            self.stream
                .read_line(&mut line)
                .await
                .map_err(|e| e.to_string())?;
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let len: usize = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        if len > 0 {
            self.stream
                .read_exact(&mut body)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(Response {
            code,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }
}

/// Run one form end to end; `Ok(true)` when SETUP was accepted and
/// interleaved RTP followed PLAY.
async fn run_form(form: Form, original: &str, user_agent: &str) -> Result<bool, String> {
    let parsed = url::Url::parse(original).map_err(|e| format!("URL: {e}"))?;
    let query = parsed.query().unwrap_or_default().to_string();
    let mut rtsp = Rtsp::connect(&parsed, user_agent).await?;
    println!("  [rtsp] {}: connected (TLS, validation off)", form.label());

    rtsp.request("OPTIONS", original, &[]).await?;
    let describe = rtsp
        .request("DESCRIBE", original, &[("Accept", "application/sdp")])
        .await?;
    if describe.code != 200 {
        return Ok(false);
    }
    let base = describe
        .header("Content-Base")
        .map(str::to_string)
        .unwrap_or_else(|| original.to_string());
    let controls: Vec<&str> = describe
        .body
        .lines()
        .filter(|l| l.starts_with("a=control:"))
        .collect();
    println!(
        "  [rtsp]   Content-Base has query: {}; controls: {:?}",
        base.contains('?'),
        controls
    );
    let joined = |b: &str| {
        if b.ends_with('/') {
            format!("{b}{TRACK}")
        } else {
            format!("{b}/{TRACK}")
        }
    };
    let (setup_uri, play_uri) = match form {
        Form::Base => (joined(&base), base.clone()),
        Form::BaseQuery => (
            format!("{}?{query}", joined(&base)),
            format!("{base}?{query}"),
        ),
        Form::UrlTrack => (format!("{original}/{TRACK}"), original.to_string()),
    };
    let setup = rtsp
        .request(
            "SETUP",
            &setup_uri,
            &[("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1")],
        )
        .await?;
    if setup.code != 200 {
        return Ok(false);
    }
    println!("  [rtsp]   Transport: {:?}", setup.header("Transport"));
    let play = rtsp
        .request("PLAY", &play_uri, &[("Range", "npt=0.000-")])
        .await?;
    if play.code != 200 {
        return Ok(false);
    }
    let mut buf = vec![0u8; 65536];
    let mut total = 0usize;
    let mut frames = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(PLAY_READ_SECS);
    while tokio::time::Instant::now() < deadline {
        let n = match tokio::time::timeout_at(deadline, rtsp.stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(format!("read after PLAY: {e}")),
        };
        total += n;
        frames += buf[..n].iter().filter(|&&b| b == b'$').count();
    }
    println!(
        "  [rtsp]   {total} bytes in {PLAY_READ_SECS} s after PLAY (~{frames} interleaved frame markers)"
    );
    let _ = rtsp.request("TEARDOWN", &play_uri, &[]).await;
    Ok(total > 0)
}

/// Accepts any certificate: the URL names a raw IP no certificate can
/// match. Probe only; the token in the URL is the real access control.
#[derive(Debug)]
struct NoVerify(rustls::crypto::CryptoProvider);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn property_keys(event: &ArloEvent) -> Vec<&str> {
    let mut keys: Vec<&str> = event
        .properties
        .as_ref()
        .and_then(|p| p.as_object())
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    keys
}

/// Property names whose value is a URL (`name:scheme`, never the value).
fn url_keys(event: &ArloEvent) -> Vec<String> {
    let Some(map) = event.properties.as_ref().and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    let mut found: Vec<String> = map
        .iter()
        .filter_map(|(k, v)| {
            let u = url::Url::parse(v.as_str()?).ok()?;
            u.has_host().then(|| format!("{k}:{}", u.scheme()))
        })
        .collect();
    found.sort_unstable();
    found
}

/// The extension of the URL's last path segment (`mpd`, `m3u8`, `sdp`…),
/// which says what kind of stream it is without revealing the token.
fn url_kind(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            let last = u.path_segments()?.next_back()?.to_string();
            last.rsplit_once('.')
                .map(|(_, ext)| ext.to_ascii_lowercase())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn is_watchalong(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| {
        u.query_pairs()
            .any(|(k, v)| k == "watchalong" && v == "true")
    })
}

fn activity_state(event: &ArloEvent) -> Option<&str> {
    event
        .properties
        .as_ref()?
        .get("activityState")
        .and_then(|v| v.as_str())
}

fn load_and_validate_config() -> Result<ArloConfig, String> {
    if !Path::new(CONFIG_PATH).exists() {
        return Err(format!(
            "`{CONFIG_PATH}` not found. Copy `config.toml.example` and fill it in."
        ));
    }
    let config = ArloConfig::load_from_file(CONFIG_PATH)
        .map_err(|e| format!("Failed to parse `{CONFIG_PATH}`: {e}"))?;
    let imap_ok = config
        .mfa
        .as_ref()
        .and_then(|m| m.imap.as_ref())
        .is_some_and(|i| i.enabled.unwrap_or(false));
    if !imap_ok {
        return Err("this probe needs `[mfa.imap].enabled = true` (see list_cameras)".to_string());
    }
    Ok(config)
}
