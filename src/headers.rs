#![allow(missing_docs)]
/// Constant Headers observed from the `minimal_re_my.arlo.com.har` trace
pub const ARLO_ORIGIN: &str = "https://my.arlo.com";
pub const ARLO_REFERER: &str = "https://my.arlo.com/";
pub const ARLO_AUTH_HOST: &str = "https://ocapi-app.arlo.com";
pub const ARLO_API_HOST: &str = "https://myapi.arlo.com";

pub const HEADER_AUTH_VERSION: &str = "2";
pub const HEADER_SOURCE: &str = "arloCamWeb";
pub const HEADER_SERVICE_VERSION: &str = "v3";
pub const HEADER_USER_DEVICE_AUTOMATION_NAME: &str = "QlJPV1NFUg=="; // BROWSER (base64)
pub const HEADER_USER_DEVICE_TYPE: &str = "BROWSER";

/// `Accept-Language` the web dashboard sends on every request.
pub const ACCEPT_LANGUAGE: &str = "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7";

/// The custom headers a real CORS preflight asks permission for — keep in
/// step with the header set `ArloClient::build_headers` installs.
pub const PREFLIGHT_REQUEST_HEADERS: &str = "auth-version,content-type,source,x-service-version,x-user-device-automation-name,x-user-device-id,x-user-device-type";
