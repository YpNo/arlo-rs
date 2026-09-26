//! Boundary checks for values the cloud hands back before they become a
//! host we dial, a path or query segment we send, or an MQTT filter we
//! subscribe to. Pure functions: no I/O, no transport types.
//!
//! The rule is fail-closed: a value that does not match the shape Arlo
//! has always used is rejected with [`ArloError::ParseError`] rather
//! than forwarded on the assumption that the upstream is honest.

use crate::error::ArloError;
use url::Url;

/// Domains Arlo serves from. A host must equal one of these or end with
/// `.<suffix>`; the check is on the parsed host component, so
/// `evil.example/?x=.arlo.com` cannot pass.
const ARLO_HOST_SUFFIXES: &[&str] = &["arlo.com", "arloxcld.com"];

/// Identifiers (device serials, xCloudIds, user and location ids) never
/// exceed this; Arlo's longest is the `<userId>_<deviceId>` unique id.
const MAX_ID_LEN: usize = 128;

/// Upper bound on one MQTT topic filter (the spec allows 65 535; Arlo's
/// longest observed is under 100 bytes).
const MAX_TOPIC_FILTER_BYTES: usize = 512;

/// True when `host` is Arlo's own (see [`ARLO_HOST_SUFFIXES`]).
pub(crate) fn is_arlo_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    ARLO_HOST_SUFFIXES
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{s}")))
}

/// Parses a WebSocket URL received from Arlo and accepts it only when it
/// is `wss://`, carries no userinfo, points at an Arlo host and, when
/// `port` is given, uses that port. `what` names the field for the error.
pub(crate) fn arlo_wss_url(what: &str, raw: &str, port: Option<u16>) -> Result<Url, ArloError> {
    let reject = |why: &str| ArloError::ParseError(format!("{what}: {why}"));
    let u = Url::parse(raw).map_err(|e| reject(&format!("not a URL ({e})")))?;
    if u.scheme() != "wss" {
        return Err(reject(&format!(
            "refusing non-TLS websocket scheme '{}'",
            u.scheme()
        )));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(reject("URL carries userinfo"));
    }
    match u.host_str() {
        Some(h) if is_arlo_host(h) => {}
        Some(h) => return Err(reject(&format!("host '{h}' is not an Arlo domain"))),
        None => return Err(reject("URL has no host")),
    }
    if let Some(p) = port
        && u.port_or_known_default() != Some(p)
    {
        return Err(reject(&format!("expected port {p}")));
    }
    Ok(u)
}

/// An identifier that may be interpolated verbatim into a URL path or
/// query: ASCII letters, digits, `_`, `-` and `.`, non-empty, at most
/// [`MAX_ID_LEN`] bytes, and not a dot segment. Anything else (`/`, `?`,
/// `#`, `&`, whitespace, control characters) would re-target the
/// authenticated request.
pub(crate) fn id_segment<'a>(what: &str, id: &'a str) -> Result<&'a str, ArloError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if ok {
        Ok(id)
    } else {
        Err(ArloError::ParseError(format!(
            "{what} is not a valid identifier ({} bytes)",
            id.len()
        )))
    }
}

/// A `YYYYMMDD` date as the local-hub media API expects it.
pub(crate) fn date_yyyymmdd<'a>(what: &str, s: &'a str) -> Result<&'a str, ArloError> {
    if s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit()) {
        Ok(s)
    } else {
        Err(ArloError::ParseError(format!("{what} must be YYYYMMDD")))
    }
}

/// A path suffix for the local hub: no query, fragment, dot segments or
/// control characters, so it cannot escape the media namespace or carry
/// the bearer token somewhere unexpected.
pub(crate) fn hub_media_path(path: &str) -> Result<&str, ArloError> {
    let ok = !path.is_empty()
        && !path.contains(['?', '#', '\\'])
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|seg| seg == "..");
    if ok {
        Ok(path)
    } else {
        Err(ArloError::ParseError(
            "hub media path is not a plain path".into(),
        ))
    }
}

/// True when `filter` is an MQTT topic filter this client is willing to
/// send: bounded, NUL-free, inside the `d/…` device namespace or this
/// user's own `u/<userId>/in/` inbox, `#` only as the final segment and
/// `+` only as a whole segment, no dot segments.
pub(crate) fn mqtt_filter_ok(filter: &str, user_id: &str) -> bool {
    if filter.is_empty() || filter.len() > MAX_TOPIC_FILTER_BYTES || filter.contains('\0') {
        return false;
    }
    let inbox = format!("u/{user_id}/in/");
    if !(filter.starts_with("d/") || filter.starts_with(&inbox)) {
        return false;
    }
    let segments: Vec<&str> = filter.split('/').collect();
    let last = segments.len() - 1;
    segments.iter().enumerate().all(|(i, seg)| {
        let hash_ok = !seg.contains('#') || (*seg == "#" && i == last);
        let plus_ok = !seg.contains('+') || *seg == "+";
        hash_ok && plus_ok && *seg != ".."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arlo_hosts_are_recognised_by_parsed_host_only() {
        assert!(is_arlo_host("livestream-z1-prod.arlo.com"));
        assert!(is_arlo_host("mqtt-cluster-z1-1.arloxcld.com"));
        assert!(is_arlo_host("ARLO.COM"));
        assert!(!is_arlo_host("arlo.com.evil.example"));
        assert!(!is_arlo_host("notarlo.com"));
        assert!(!is_arlo_host("evil.example"));
    }

    #[test]
    fn wss_url_rejects_downgrades_foreign_hosts_and_userinfo() {
        assert!(arlo_wss_url("t", "wss://mqtt-cluster-z1-1.arloxcld.com:8084", None).is_ok());
        assert!(arlo_wss_url("t", "wss://livestream-z1-prod.arlo.com:7443/", Some(7443)).is_ok());
        for bad in [
            "ws://mqtt-cluster-z1-1.arloxcld.com:8084",
            "wss://evil.example:7443/",
            "wss://evil.example/?x=.arlo.com",
            "wss://arlo.com.evil.example/",
            "wss://u:p@livestream-z1-prod.arlo.com:7443/",
            "not a url",
            "",
        ] {
            let err = arlo_wss_url("field", bad, None).unwrap_err().to_string();
            assert!(err.contains("field"), "{bad}: {err}");
        }
        assert!(arlo_wss_url("t", "wss://livestream-z1-prod.arlo.com:8443/", Some(7443)).is_err());
    }

    #[test]
    fn id_segments_are_plain_tokens() {
        for ok in [
            "A0A0000YA0D00",
            "UXXX-000-00000000",
            "RXXXXXXX-0000-000-000000000",
            "u_dev.1",
            "3f2b1c8e-0000-4000-8000-000000000000",
        ] {
            assert_eq!(id_segment("id", ok).unwrap(), ok);
        }
        for bad in [
            "",
            "..",
            ".",
            "a/b",
            "a?b",
            "a#b",
            "a&b",
            "a b",
            "a\nb",
            "a%2fb",
            &"x".repeat(129),
        ] {
            assert!(id_segment("id", bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn dates_and_hub_paths() {
        assert!(date_yyyymmdd("d", "20260926").is_ok());
        for bad in ["2026-09-26", "2026092", "202609261", "2026092x"] {
            assert!(date_yyyymmdd("d", bad).is_err(), "{bad}");
        }
        assert!(hub_media_path("hmsls/media/abc.mp4").is_ok());
        for bad in ["", "../etc", "a/../b", "a?x=1", "a#f", "a\\b", "a\nb"] {
            assert!(hub_media_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mqtt_filters_follow_namespace_and_wildcard_rules() {
        let u = "UXXX-000-00000000";
        for ok in [
            "d/X/out/cameras/A0A0000YA0D00/#",
            "d/X/out/basestation/#",
            "u/UXXX-000-00000000/in/#",
            "d/X/out/+/status",
        ] {
            assert!(mqtt_filter_ok(ok, u), "{ok}");
        }
        for bad in [
            "#",
            "d/x/out/../#",
            "d/x\0/out/#",
            "u/OTHER/in/#",
            "d/X/out/#/more",
            "d/X/out/a#b",
            "d/X/out/a+b",
            "",
            &format!("d/{}/#", "x".repeat(600)),
        ] {
            assert!(!mqtt_filter_ok(bad, u), "{bad:?}");
        }
    }
}
