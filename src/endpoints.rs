#![allow(missing_docs)]
pub const AUTH_LOGIN: &str = "/api/auth";
pub const AUTH_GET_FACTORS: &str = "/api/getFactors";
pub const AUTH_START_AUTH: &str = "/api/startAuth";
pub const AUTH_FINISH_AUTH: &str = "/api/finishAuth";
pub const AUTH_GET_FACTOR_ID: &str = "/api/getFactorId";
pub const AUTH_VALIDATE_ACCESS_TOKEN: &str = "/api/validateAccessToken";
pub const AUTH_START_PAIRING_FACTOR: &str = "/api/startPairingFactor";
pub const AUTH_LOGIN_V2: &str = "/hmsweb/login/v2";
pub const AUTH_SESSION_V3: &str = "/hmsweb/users/session/v3";
pub const AUTH_DEVICE_SUPPORT_V2: &str = "/hmsweb/devicesupport/v2";
pub const AUTH_LOGOUT: &str = "/hmsweb/logout";

pub const API_DEVICES: &str = "/hmsweb/users/devices";
pub const API_START_STREAM: &str = "/hmsweb/users/devices/startStream";
pub const API_SET_MODE: &str = "/hmsweb/users/devices/automation/active";
pub const API_SUBSCRIBE: &str = "/hmsweb/client/subscribe";

pub const API_LOCATIONS: &str = "/hmsdevicemanagement/users/{user_id}/locations";
pub const API_AUTOMATION_MODES: &str = "/hmsweb/automation/v3/modes";
pub const API_AUTOMATION_DEFINITIONS: &str = "/hmsweb/users/automation/definitions";
pub const API_EMERGENCY_LOCATIONS: &str = "/hmsweb/users/emergency/locations";

pub const API_TAKE_SNAPSHOT: &str = "/hmsweb/users/devices/takeSnapshot";
pub const API_FULL_SNAPSHOT: &str = "/hmsweb/users/devices/fullFrameSnapshot";
pub const API_START_RECORD: &str = "/hmsweb/users/devices/startRecord";
pub const API_STOP_RECORD: &str = "/hmsweb/users/devices/stopRecord";
pub const API_RESTART: &str = "/hmsweb/users/devices/restart";
pub const API_NOTIFY: &str = "/hmsweb/users/devices/notify/";

pub const API_LIBRARY: &str = "/hmsweb/users/library";

pub const API_RATLS_CERT: &str = "/hmsweb/users/devices/v2/security/cert/create";
pub const API_RATLS_TOKEN: &str = "/hmsweb/users/device/ratls/token";
pub const API_HMSLS_CONNECTIVITY: &str = "/hmsls/connectivity";
pub const API_HMSLS_LIST: &str = "/hmsls/list";
pub const API_HMSLS_DOWNLOAD: &str = "/hmsls/download";
