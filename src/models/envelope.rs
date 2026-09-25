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
    let parsed: Value = serde_json::from_str(body)?;

    // Bare array — the whole body is the data.
    if parsed.is_array() {
        return Ok(parsed);
    }

    // `success: bool`
    if let Some(success) = parsed.get("success").and_then(|s| s.as_bool()) {
        if success {
            return Ok(parsed.get("data").cloned().unwrap_or(Value::Null));
        }
        return Err(ArloError::ApiError {
            code: 500,
            error: None,
            message: format!("Envelope reports success=false. Body: {body}"),
        });
    }

    // `meta.code: u64`
    if let Some(code) = parsed
        .get("meta")
        .and_then(|m| m.get("code"))
        .and_then(|c| c.as_u64())
    {
        if code == 200 {
            return Ok(parsed.get("data").cloned().unwrap_or(Value::Null));
        }
        let error = parsed
            .get("meta")
            .and_then(|m| m.get("error"))
            .and_then(|e| e.as_u64())
            .map(|e| e as u32);
        let message = parsed
            .get("meta")
            .and_then(|m| m.get("message"))
            .and_then(|v| v.as_str())
            .filter(|m| !m.is_empty())
            .map(str::to_string)
            .or_else(|| {
                error
                    .and_then(crate::models::error_codes::message_for)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "Envelope reports non-200 meta.code".to_string());
        return Err(ArloError::ApiError {
            code: code as i32,
            error,
            message,
        });
    }

    Err(ArloError::ApiError {
        code: 500,
        error: None,
        message: format!("Response is not a recognised Arlo envelope. Body: {body}"),
    })
}

/// Convenience for the deeply-wrapped list endpoints (`get_devices`,
/// `get_locations`): unwraps the envelope, then if the payload is a JSON
/// object, falls through to `<object>.<inner_key>` to find the array.
/// Bare-array responses pass through directly.
pub(crate) fn unwrap_envelope_array(body: &str, inner_key: &str) -> Result<Value, ArloError> {
    let payload = unwrap_envelope(body)?;
    if payload.is_array() {
        return Ok(payload);
    }
    if let Some(inner) = payload.get(inner_key).cloned()
        && inner.is_array()
    {
        return Ok(inner);
    }
    // No array could be located — return an empty array so callers
    // observing "no devices yet" get a sensible value, not an error.
    Ok(Value::Array(vec![]))
}

#[cfg(test)]
mod tests {
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
    fn unwrap_envelope_array_returns_empty_when_inner_key_missing() {
        let body = r#"{"success":true,"data":{"other":[1,2]}}"#;
        let arr = unwrap_envelope_array(body, "devices").unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 0);
    }
}
