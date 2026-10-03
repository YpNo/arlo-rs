//! Arlo `meta.error` codes and the action a caller should take.
//!
//! Arlo answers most requests with HTTP 200 and an envelope such as
//! `{"meta":{"code":400,"error":9276,"message":"…"},"data":…}`, so the
//! HTTP status alone says little: the outcome is `meta.code` (HTTP-like)
//! plus `meta.error` (an Arlo-specific number). The groups below come
//! from the official web client (`ConstantsService` /
//! `CamSdkApiService.onResponseSuccess`), as transcribed by the reference
//! Python client. That client distinguishes a handful of *behaviours* and
//! has no blind retry: it drops the token and returns to login when the
//! server says the session is gone. Callers should branch on
//! [`ErrorAction`], never on individual codes — Arlo reuses numbers across
//! endpoints.
//!
//! Pure data: no I/O. See [`crate::error::ArloError::action`] for the
//! bridge from an error value to an action.

/// What a caller should do about a failed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorAction {
    /// Transient. Retry the same request after a backoff.
    Retry,
    /// The session is dead server-side (or the browser is no longer
    /// trusted). Discard the saved session and log in again from scratch;
    /// retrying the request as-is can never succeed.
    Reauth,
    /// Two-step authentication is not finished yet. Not a failure: keep
    /// polling (PUSH) or carry on with the MFA flow.
    AuthPending,
    /// Permanent: wrong credentials, expired password, or a locked
    /// account. Never retry — retrying a lockout extends it.
    Fatal,
    /// The one-time code was wrong, expired, or exhausted. A fresh code is
    /// needed; resubmitting the current one cannot work.
    OtpRetry,
    /// The user actively denied the authentication request.
    Rejected,
    /// The device (typically a base station) is unreachable. Stop polling
    /// it rather than retrying; unrelated to authentication.
    DeviceOffline,
    /// No rule applies. The caller decides; blind retries are discouraged
    /// because an unknown code may be a lockout in disguise.
    Unclassified,
}

/// Session gone server-side (`ERROR_CODES_SESSION_EXPIRE` in the web
/// client). 9328 additionally means the password must be re-entered on
/// every signed-in device, so a saved token is worthless.
pub const SESSION_EXPIRED: &[u32] = &[9002, 9022, 9025, 9328];
/// Two-step authentication not finished. 9233 is load-bearing for PUSH:
/// `finishAuth` returns it while the push notification is unanswered.
pub const AUTH_PENDING: &[u32] = &[9233, 9276, 9278];
/// Permanent authentication failures. 9017 is a 5-minute lockout.
/// 9307 ("MFA is limited for the region") is permanent for the account.
pub const FATAL_AUTH: &[u32] = &[9001, 9004, 9015, 9016, 9017, 9019, 9058, 9307, 9340];
/// A new one-time code is required.
pub const OTP_ERRORS: &[u32] = &[9234, 9236, 9237, 9238, 9243, 9301];
/// The user said no.
pub const REJECTED: &[u32] = &[9239];
/// Transient "something went wrong" family (0 is a server-side timeout).
/// 9306 shares the web client's "Something went wrong. Try again." text.
pub const TRANSIENT: &[u32] = &[0, 9000, 9029, 9241, 9306, 9316, 9334];
/// Base station unreachable; arrives on `notify` calls, not auth calls.
pub const DEVICE_OFFLINE: &[u32] = &[2059, 2222];
/// "This browser is not trusted, complete a login." (The official table
/// maps 9204 to an unrelated e-mail error; on the auth endpoints this is
/// the only meaning that makes sense.) 9261 ("Invalid factor data") is
/// what `getFactorId {factorType:"BROWSER"}` answers for a device id
/// Arlo has never seen — a fresh install (captured 2026-10-03).
pub const UNTRUSTED: &[u32] = &[9204, 9261];

/// Classifies an Arlo `meta.error` code on its own.
pub fn classify_arlo_error(error: u32) -> ErrorAction {
    if SESSION_EXPIRED.contains(&error) || UNTRUSTED.contains(&error) {
        ErrorAction::Reauth
    } else if AUTH_PENDING.contains(&error) {
        ErrorAction::AuthPending
    } else if FATAL_AUTH.contains(&error) {
        ErrorAction::Fatal
    } else if OTP_ERRORS.contains(&error) {
        ErrorAction::OtpRetry
    } else if REJECTED.contains(&error) {
        ErrorAction::Rejected
    } else if DEVICE_OFFLINE.contains(&error) {
        ErrorAction::DeviceOffline
    } else if TRANSIENT.contains(&error) {
        ErrorAction::Retry
    } else {
        ErrorAction::Unclassified
    }
}

/// Classifies a failed response from its HTTP-like code (`meta.code`
/// when the envelope carried one, else the HTTP status) and the optional
/// Arlo `meta.error`. The Arlo code wins when present: it is far more
/// specific than the HTTP-ish code, which is a flat 400 for wildly
/// different causes.
///
/// Without an Arlo code: 401/403 mean the token is no longer accepted
/// ([`ErrorAction::Reauth`]), 429 and 5xx are transient
/// ([`ErrorAction::Retry`]), anything else is
/// [`ErrorAction::Unclassified`].
pub fn classify(code: i32, error: Option<u32>) -> ErrorAction {
    if let Some(error) = error {
        return classify_arlo_error(error);
    }
    match code {
        401 | 403 => ErrorAction::Reauth,
        429 | 500..=599 => ErrorAction::Retry,
        _ => ErrorAction::Unclassified,
    }
}

/// The message the official web client shows for `error`, when known.
/// Useful when Arlo's own `meta.message` is missing or unhelpful.
pub fn message_for(error: u32) -> Option<&'static str> {
    Some(match error {
        0 => "Your request timed out.",
        1134 => "Invalid image.",
        2059 | 2222 => "Base station is not responding.",
        9000 | 9029 | 9241 | 9306 | 9316 | 9334 | 9361 => "Something went wrong. Try again.",
        9001 | 9058 => "Invalid email address.",
        9002 => "Your session expired. Please login to continue.",
        9004 => "Authentication failed for current credentials.",
        9013 => "Account already exists.",
        9015 => "Password not correct.",
        9016 => "Account not found.",
        9017 => "Due to multiple attempts account is locked. Please try again after 5 minutes.",
        9019 => "Email and password does not match.",
        9022 | 9025 => "Session expired. Sign in again.",
        9072 | 9261 => "Invalid phone number.",
        9204 => "Browser is not trusted, a full login is required.",
        9233 | 9276 => "Please complete two-step authentication successfully and then try again.",
        9234 | 9301 => "Code retry limit exceeded. Resend the code and try again.",
        9236 => "Incorrect code. Please try again.",
        9237 => "Code expired, please resend code.",
        9238 => "Authentication request timed-out. Try again.",
        9239 => "Your authentication request has been rejected.",
        9243 => "Please enter the code.",
        9262 => "Either number is not valid or region is not supported.",
        9263 => "Two-factor authentication for this account is already completed.",
        9264 => "Verification method already exists.",
        9271 => "Device limit reached, remove a device then try again.",
        9278 => "There is another pending authentication request.",
        9285 => "Email is already confirmed.",
        9286 => "New password matches one of the passwords you have used before.",
        9303..=9305 => "Application was removed from your device. Try another verification method.",
        9307 => "MFA is limited for the region.",
        9310 => "Our services are not supported in your country.",
        9328 => "Re-login required. You must re-enter your password on all signed in devices.",
        9340 => "Password expired.",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arlo_code_wins_over_http_code() {
        // A dead session arrives as meta.code 400 + error 9002.
        assert_eq!(classify(400, Some(9002)), ErrorAction::Reauth);
        // …and a pending push as the very same 400.
        assert_eq!(classify(400, Some(9233)), ErrorAction::AuthPending);
    }

    #[test]
    fn every_group_maps_to_its_action() {
        for (codes, action) in [
            (SESSION_EXPIRED, ErrorAction::Reauth),
            (UNTRUSTED, ErrorAction::Reauth),
            (AUTH_PENDING, ErrorAction::AuthPending),
            (FATAL_AUTH, ErrorAction::Fatal),
            (OTP_ERRORS, ErrorAction::OtpRetry),
            (REJECTED, ErrorAction::Rejected),
            (DEVICE_OFFLINE, ErrorAction::DeviceOffline),
            (TRANSIENT, ErrorAction::Retry),
        ] {
            for code in codes {
                assert_eq!(classify_arlo_error(*code), action, "code {code}");
            }
        }
    }

    #[test]
    fn groups_are_disjoint() {
        let groups = [
            SESSION_EXPIRED,
            UNTRUSTED,
            AUTH_PENDING,
            FATAL_AUTH,
            OTP_ERRORS,
            REJECTED,
            DEVICE_OFFLINE,
            TRANSIENT,
        ];
        for (i, a) in groups.iter().enumerate() {
            for b in &groups[i + 1..] {
                for code in *a {
                    assert!(!b.contains(code), "code {code} appears in two groups");
                }
            }
        }
    }

    #[test]
    fn unknown_arlo_code_is_unclassified_not_retried() {
        assert_eq!(classify(400, Some(9999)), ErrorAction::Unclassified);
    }

    #[test]
    fn http_only_codes() {
        assert_eq!(classify(401, None), ErrorAction::Reauth);
        assert_eq!(classify(403, None), ErrorAction::Reauth);
        assert_eq!(classify(429, None), ErrorAction::Retry);
        assert_eq!(classify(503, None), ErrorAction::Retry);
        assert_eq!(classify(404, None), ErrorAction::Unclassified);
    }

    #[test]
    fn lockout_is_fatal_and_has_the_official_text() {
        assert_eq!(classify_arlo_error(9017), ErrorAction::Fatal);
        assert!(message_for(9017).unwrap().contains("locked"));
        assert_eq!(message_for(424242), None);
    }
}
