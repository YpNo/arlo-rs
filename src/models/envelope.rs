//! Envelope-detection helpers shared by every endpoint that parses an
//! Arlo JSON response.
//!
//! Arlo's APIs use three slightly different success conventions
//! interchangeably (the same endpoint may even switch between them
//! depending on the account's region):
//!
//! 1. `{ "success": true, "data": ... }` — the legacy `hmsweb` shape.
//! 2. `{ "meta": { "code": 200 }, "data": ... }` — the modern `ocapi`
//!    shape used by the auth flow.
//! 3. A bare JSON array — some `/devices` and `/locations` responses
//!    elide the wrapper entirely.
//!
//! `unwrap_envelope` (crate-internal) normalises all three into a single
//! `Result<serde_json::Value, ArloError>` so callers can stop reinventing
//! the same dispatch.

use crate::error::ArloError;
use serde_json::Value;

/// Returns the data payload of an Arlo success envelope, regardless of
/// which of the three wrapper conventions Arlo used:
///
/// - For `{ "success": true, ... }` and `{ "meta": { "code": 200 }, ... }`
///   the value of `data` is returned (or `Value::Null` if `data` is
///   absent — some endpoints succeed with no body).
/// - For bare arrays the whole value is returned as-is.
///
/// Returns [`ArloError::ApiError`] if neither convention indicates
/// success, with the wire-side `meta.message` (when present) preserved
/// in the error.
pub(crate) fn unwrap_envelope(body: &str) -> Result<Value, ArloError> {
    let mut parsed: Value = serde_json::from_str(body)?;

    // Bare array — the whole body is the data.
    if parsed.is_array() {
        return Ok(parsed);
    }

    // `success: bool`
    if let Some(success) = parsed.get("success").and_then(|s| s.as_bool()) {
        if success {
            return Ok(take_data(&mut parsed));
        }
        return Err(success_false_error(&parsed, body));
    }

    // `meta.code: u64`
    if let Some(code) = parsed
        .get("meta")
        .and_then(|m| m.get("code"))
        .and_then(|c| c.as_u64())
    {
        if code == 200 {
            return Ok(take_data(&mut parsed));
        }
        let error = parsed
            .get("meta")
            .and_then(|m| m.get("error"))
            .and_then(|e| e.as_u64())
            .and_then(|e| u32::try_from(e).ok());
        let message = parsed
            .get("meta")
            .and_then(|m| m.get("message"))
            .and_then(|v| v.as_str())
            .filter(|m| !m.is_empty())
            .map(crate::models::redact::excerpt)
            .or_else(|| {
                error
                    .and_then(crate::models::error_codes::message_for)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "Envelope reports non-200 meta.code".to_string());
        return Err(ArloError::ApiError {
            code: i32::try_from(code).unwrap_or(i32::MAX),
            error,
            message,
        });
    }

    Err(ArloError::ApiError {
        code: 500,
        error: None,
        message: format!(
            "Response is not a recognised Arlo envelope; body: {}",
            crate::models::redact::excerpt(body)
        ),
    })
}

/// For endpoints whose success body is empty or shapeless (`{}`): fails
/// only on an explicit negative verdict — `success: false` or a `meta.code`
/// other than 200 — and treats everything else as success. Arlo signals
/// failure as HTTP 200 with a non-200 `meta.code`, so a caller that
/// ignored the body used to report success on a rejection.
pub(crate) fn check_envelope_status(body: &str) -> Result<(), ArloError> {
    let Ok(parsed) = serde_json::from_str::<Value>(body) else {
        return Ok(());
    };
    let failed = parsed.get("success").and_then(Value::as_bool) == Some(false)
        || parsed
            .get("meta")
            .and_then(|m| m.get("code"))
            .and_then(Value::as_u64)
            .is_some_and(|c| c != 200);
    if failed {
        unwrap_envelope(body).map(|_| ())
    } else {
        Ok(())
    }
}

/// Moves `data` out of the envelope instead of cloning it, so a large
/// body is held once, not twice.
fn take_data(parsed: &mut Value) -> Value {
    parsed
        .get_mut("data")
        .map(Value::take)
        .unwrap_or(Value::Null)
}

/// Convenience for the deeply-wrapped list endpoints (`get_devices`,
/// `get_locations`): unwraps the envelope, then if the payload is a JSON
/// object, falls through to `<object>.<inner_key>` to find the array.
/// Bare-array responses pass through directly.
///
/// `null` or an empty object mean "nothing here yet" and become `[]`. A
/// non-empty object without `inner_key` is a schema change and is an
/// error (naming the keys, never the body): reporting it as "no devices"
/// would make every camera vanish silently.
pub(crate) fn unwrap_envelope_array(body: &str, inner_key: &str) -> Result<Value, ArloError> {
    match unwrap_envelope(body)? {
        Value::Array(items) => Ok(Value::Array(items)),
        Value::Null => Ok(Value::Array(vec![])),
        Value::Object(mut map) => match map.remove(inner_key) {
            Some(Value::Array(items)) => Ok(Value::Array(items)),
            Some(_) => Err(ArloError::ParseError(format!(
                "`{inner_key}` in the response is not an array"
            ))),
            None if map.is_empty() => Ok(Value::Array(vec![])),
            None => Err(ArloError::ParseError(format!(
                "expected a `{inner_key}` array in the response, found keys {:?}",
                map.keys().collect::<Vec<_>>()
            ))),
        },
        other => Err(ArloError::ParseError(format!(
            "expected a `{inner_key}` array in the response, found a JSON {}",
            json_kind(&other)
        ))),
    }
}

/// `success: false` envelopes carry Arlo's own code and text under `data`
/// (`{"data":{"error":"14001","message":"…","reason":"…"},"success":false}`,
/// the code as a string). Keeping the code structured lets
/// [`ArloError::action`] classify it and callers branch on it; the message
/// falls back to a redacted body excerpt when `data.message` is absent.
fn success_false_error(parsed: &Value, body: &str) -> ArloError {
    let data = parsed.get("data");
    let error = data.and_then(|d| d.get("error")).and_then(|e| match e {
        Value::String(s) => s.trim().parse::<u32>().ok(),
        Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        _ => None,
    });
    let message = data
        .and_then(|d| d.get("message"))
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .map(crate::models::redact::excerpt)
        .unwrap_or_else(|| {
            format!(
                "Envelope reports success=false; body: {}",
                crate::models::redact::excerpt(body)
            )
        });
    ArloError::ApiError {
        code: 500,
        error,
        message,
    }
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn success_false_keeps_arlo_code_and_message_from_data() {
        // Shape captured live on 2026-09-27 (sipInfo while the app streams).
        let body = r#"{"data":{"error":"14001","message":"RTSP Streaming in progress, SIP Streaming is not allowed, try after some time !!!","reason":"x"},"success":false}"#;
        match super::unwrap_envelope(body) {
            Err(crate::error::ArloError::ApiError {
                code,
                error,
                message,
            }) => {
                assert_eq!(code, 500);
                assert_eq!(error, Some(14001));
                assert!(message.starts_with("RTSP Streaming in progress"));
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[test]
    fn success_false_accepts_numeric_code_and_falls_back_to_excerpt() {
        let body = r#"{"data":{"error":2059},"success":false}"#;
        match super::unwrap_envelope(body) {
            Err(crate::error::ArloError::ApiError { error, message, .. }) => {
                assert_eq!(error, Some(2059));
                assert!(message.starts_with("Envelope reports success=false"));
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
        let body = r#"{"success":false}"#;
        assert!(matches!(
            super::unwrap_envelope(body),
            Err(crate::error::ArloError::ApiError { error: None, .. })
        ));
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn unwrap_envelope_extracts_legacy_success_data() {
        let body = r#"{"success":true,"data":{"x":1}}"#;
        assert_eq!(unwrap_envelope(body).unwrap(), json!({"x":1}));
    }

    #[test]
    fn unwrap_envelope_extracts_modern_meta_data() {
        let body = r#"{"meta":{"code":200,"message":"ok"},"data":{"y":2}}"#;
        assert_eq!(unwrap_envelope(body).unwrap(), json!({"y":2}));
    }

    #[test]
    fn unwrap_envelope_passes_through_bare_array() {
        let body = r#"[{"id":1},{"id":2}]"#;
        let v = unwrap_envelope(body).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 2);
    }

    #[test]
    fn unwrap_envelope_returns_null_when_data_absent_on_success() {
        let body = r#"{"success":true}"#;
        assert_eq!(unwrap_envelope(body).unwrap(), Value::Null);
    }

    #[test]
    fn unwrap_envelope_propagates_meta_failure_message() {
        let body = r#"{"meta":{"code":403,"message":"forbidden"}}"#;
        let err = unwrap_envelope(body).unwrap_err();
        match err {
            ArloError::ApiError {
                code,
                error,
                message,
            } => {
                assert_eq!(code, 403);
                assert_eq!(error, None);
                assert_eq!(message, "forbidden");
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_envelope_carries_arlo_error_code_and_official_text() {
        // Arlo often sends meta.error with an empty/absent message; the
        // official web-client text fills the gap.
        let body = r#"{"meta":{"code":400,"error":9017}}"#;
        match unwrap_envelope(body).unwrap_err() {
            ArloError::ApiError {
                code,
                error,
                message,
            } => {
                assert_eq!(code, 400);
                assert_eq!(error, Some(9017));
                assert!(message.contains("locked"));
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_envelope_rejects_explicit_failure() {
        let body = r#"{"success":false}"#;
        assert!(matches!(
            unwrap_envelope(body).unwrap_err(),
            ArloError::ApiError { .. }
        ));
    }

    #[test]
    fn unwrap_envelope_rejects_unrecognised_shape() {
        let body = r#"{"random":"junk"}"#;
        assert!(matches!(
            unwrap_envelope(body).unwrap_err(),
            ArloError::ApiError { .. }
        ));
    }

    #[test]
    fn unwrap_envelope_array_finds_nested_list() {
        let body = r#"{"success":true,"data":{"devices":[{"id":1}]}}"#;
        let arr = unwrap_envelope_array(body, "devices").unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 1);
    }

    #[test]
    fn unwrap_envelope_array_passes_through_top_level_array_inside_data() {
        let body = r#"{"success":true,"data":[{"id":1},{"id":2}]}"#;
        let arr = unwrap_envelope_array(body, "devices").unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 2);
    }

    #[test]
    fn unwrap_envelope_array_passes_through_bare_array() {
        let body = r#"[{"id":1}]"#;
        let arr = unwrap_envelope_array(body, "devices").unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 1);
    }

    #[test]
    fn unwrap_envelope_array_errors_on_a_drifted_shape_but_tolerates_emptiness() {
        let drifted = r#"{"success":true,"data":{"items":[1,2]}}"#;
        let err = unwrap_envelope_array(drifted, "devices")
            .unwrap_err()
            .to_string();
        assert!(err.contains("`devices`") && err.contains("items"), "{err}");
        assert!(!err.contains("[1,2]"), "body must not be echoed: {err}");

        for empty in [
            r#"{"success":true,"data":null}"#,
            r#"{"success":true,"data":{}}"#,
            r#"{"success":true}"#,
        ] {
            let arr = unwrap_envelope_array(empty, "devices").unwrap();
            assert_eq!(arr.as_array().unwrap().len(), 0, "{empty}");
        }
        assert!(unwrap_envelope_array(r#"{"success":true,"data":"nope"}"#, "devices").is_err());
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn unrecognised_envelope_error_never_carries_a_secret() {
        let body = r#"{"token":"TOKEN-SECRET","accessToken":"ALSO-SECRET","weird":true}"#;
        let err = unwrap_envelope(body).unwrap_err().to_string();
        assert!(err.contains("not a recognised Arlo envelope"), "{err}");
        assert!(
            !err.contains("TOKEN-SECRET") && !err.contains("ALSO-SECRET"),
            "{err}"
        );

        let body = r#"{"success":false,"data":{"sipCallInfo":{"password":"SIP-SECRET"}}}"#;
        let err = unwrap_envelope(body).unwrap_err().to_string();
        assert!(!err.contains("SIP-SECRET"), "{err}");
    }
}

#[cfg(test)]
mod status_check_tests {
    use super::*;

    #[test]
    fn shapeless_and_empty_bodies_pass_but_explicit_failures_do_not() {
        assert!(check_envelope_status("").is_ok());
        assert!(check_envelope_status("{}").is_ok());
        assert!(check_envelope_status(r#"{"meta":{"code":200}}"#).is_ok());
        assert!(check_envelope_status(r#"{"success":true}"#).is_ok());
        let err = check_envelope_status(r#"{"meta":{"code":400,"error":9204}}"#).unwrap_err();
        assert!(
            matches!(
                err,
                ArloError::ApiError {
                    code: 400,
                    error: Some(9204),
                    ..
                }
            ),
            "{err}"
        );
        assert!(check_envelope_status(r#"{"success":false}"#).is_err());
    }

    #[test]
    fn out_of_range_codes_do_not_alias() {
        let err =
            unwrap_envelope(r#"{"meta":{"code":4294976313,"error":4294976313}}"#).unwrap_err();
        assert!(
            matches!(
                err,
                ArloError::ApiError {
                    code: i32::MAX,
                    error: None,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn unwrap_envelope_strips_control_characters_from_meta_message() {
        let body = "{\"meta\":{\"code\":400,\"message\":\"x\\ny\\u001b[0m\"}}";
        let err = unwrap_envelope(body).unwrap_err();
        let text = err.to_string();
        assert!(!text.contains('\n') && !text.contains('\x1b'), "{text}");
        assert!(text.contains("x") && text.contains("y"), "{text}");
    }
}
