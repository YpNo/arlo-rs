#![allow(missing_docs)]
use crate::error::ArloError;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fs;
use tracing::warn;

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ApiVersion {
    Legacy,
    #[default]
    V3,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ArloConfig {
    pub credentials: Option<CredentialsConfig>,
    pub mfa: Option<MfaConfig>,
    pub client: Option<ClientConfig>,
    pub streaming: Option<StreamingConfig>,
}

/// Arlo account credentials. `Debug` redacts the `password`, which is
/// held as a [`SecretString`] (zeroized on drop).
#[derive(Deserialize, Clone)]
pub struct CredentialsConfig {
    pub email: Option<String>,
    pub password: Option<SecretString>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MfaConfig {
    pub preferred_method: Option<String>,
    pub imap: Option<ImapConfig>,
}

/// IMAP mailbox used for automated OTP retrieval. `Debug` redacts the
/// app `password`, which is held as a [`SecretString`].
#[derive(Deserialize, Clone)]
pub struct ImapConfig {
    pub enabled: Option<bool>,
    pub provider: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub delete_after_read: Option<bool>,
}

/// Client tuning. `Debug` strips any `user:password@` from
/// `upstream_proxy`.
#[derive(Deserialize, Serialize, Clone, Default)]
pub struct ClientConfig {
    pub debug_mode: Option<bool>,
    pub user_agent: Option<String>,
    pub session_cache_path: Option<String>,
    /// Only meaningful with `use_browser = true` (headless Chrome).
    pub headless: Option<bool>,
    pub upstream_proxy: Option<String>,
    pub api_version: Option<ApiVersion>,
    /// Route traffic through the headless-Chrome MITM proxy instead of
    /// the default `wreq` impersonation client. Requires the crate's
    /// `browser` feature; defaults to `false`.
    pub use_browser: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StreamingConfig {
    pub preferred_protocol: Option<String>,
    pub media_path: Option<String>,
}

/// The rwx bits for group and others in a Unix mode.
const GROUP_OTHER_BITS: u32 = 0o077;
/// The permission bits of a Unix mode (rwx for owner/group/others plus
/// setuid/setgid/sticky), without the file-type bits.
const PERMISSION_BITS: u32 = 0o7777;

/// True when `mode` grants no permission to group or others — the only
/// acceptable mode for a file that holds a password.
pub(crate) const fn mode_is_private(mode: u32) -> bool {
    mode & GROUP_OTHER_BITS == 0
}

/// Warns when a file that carries a password is readable by other users.
/// A warning rather than a refusal: the file is the operator's, and the
/// session cache next to it is what the library itself controls.
#[cfg(unix)]
fn warn_if_shared(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(meta) if !mode_is_private(meta.permissions().mode()) => warn!(
            path,
            mode = format_args!("{:04o}", meta.permissions().mode() & PERMISSION_BITS),
            "config file holds a password but is readable by other users; chmod 600 it"
        ),
        Ok(_) => {}
        Err(e) => warn!(path, error = %e, "could not check config file permissions"),
    }
}

#[cfg(not(unix))]
fn warn_if_shared(_path: &str) {}

impl ArloConfig {
    /// True when the file contains an Arlo or IMAP password.
    fn holds_secret(&self) -> bool {
        let arlo = self
            .credentials
            .as_ref()
            .is_some_and(|c| c.password.is_some());
        let imap = self
            .mfa
            .as_ref()
            .and_then(|m| m.imap.as_ref())
            .is_some_and(|i| i.password.is_some());
        arlo || imap
    }

    /// Loads and parses the configuration file at the given path. On
    /// Unix, a file that holds a password and is readable by other users
    /// is reported at WARN.
    pub fn load_from_file(path: &str) -> Result<Self, ArloError> {
        let contents = fs::read_to_string(path).map_err(|e| {
            ArloError::ScraperError(format!("Failed to read config file {}: {}", path, e))
        })?;

        // `e.message()` + `e.span()` only: the full `Display` of a toml
        // error reprints the offending source line, which for a slip on
        // `password = "…"` would put the password into the error.
        let parsed: ArloConfig = toml::from_str(&contents).map_err(|e| {
            let at = e
                .span()
                .map(|r| format!(" (bytes {}..{})", r.start, r.end))
                .unwrap_or_default();
            ArloError::ScraperError(format!(
                "Failed to parse config file {path}{at}: {}",
                e.message()
            ))
        })?;

        if parsed.holds_secret() {
            warn_if_shared(path);
        }
        Ok(parsed)
    }
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("debug_mode", &self.debug_mode)
            .field("user_agent", &self.user_agent)
            .field("session_cache_path", &self.session_cache_path)
            .field("headless", &self.headless)
            .field(
                "upstream_proxy",
                &self
                    .upstream_proxy
                    .as_deref()
                    .map(crate::models::redact::redact_userinfo),
            )
            .field("api_version", &self.api_version)
            .field("use_browser", &self.use_browser)
            .finish()
    }
}

impl std::fmt::Debug for CredentialsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialsConfig")
            .field("email", &self.email)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl std::fmt::Debug for ImapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapConfig")
            .field("enabled", &self.enabled)
            .field("provider", &self.provider)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("delete_after_read", &self.delete_after_read)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_valid_config() {
        let toml_content = r#"
            [credentials]
            email = "test@example.com"
            password = "secure_password"

            [client]
            debug_mode = true
            session_cache_path = ".session"
            headless = false
            upstream_proxy = "http://localhost:8080"
        "#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let config = ArloConfig::load_from_file(file.path().to_str().unwrap()).unwrap();

        // Assert Credentials
        let creds = config.credentials.unwrap();
        assert_eq!(creds.email.unwrap(), "test@example.com");
        assert_eq!(
            secrecy::ExposeSecret::expose_secret(&creds.password.unwrap()),
            "secure_password"
        );

        // Assert Client Config
        let client = config.client.unwrap();
        assert!(client.debug_mode.unwrap());
        assert_eq!(client.session_cache_path.unwrap(), ".session");
        assert!(!client.headless.unwrap());
        assert_eq!(client.upstream_proxy.unwrap(), "http://localhost:8080");
    }

    #[test]
    fn test_parse_missing_file_errors() {
        let err = ArloConfig::load_from_file("/path/that/does/not/exist.toml");
        assert!(err.is_err());
        let e = err.unwrap_err();
        match e {
            ArloError::ScraperError(msg) => assert!(msg.contains("Failed to read config file")),
            _ => panic!("Expected ScraperError for missing file"),
        }
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn client_config_debug_strips_proxy_userinfo() {
        let cfg = ClientConfig {
            upstream_proxy: Some("http://user:hunter2@proxy.example:8080".into()),
            ..ClientConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("proxy.example:8080") && !dbg.contains("hunter2"),
            "{dbg}"
        );
    }

    #[test]
    fn parse_error_never_echoes_the_password_line() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"[credentials]\nemail = \"e@x\"\npassword = \"hun\"ter2\"\n")
            .unwrap();
        let err = ArloConfig::load_from_file(file.path().to_str().unwrap()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Failed to parse config file"), "{text}");
        assert!(!text.contains("hun") && !text.contains("ter2"), "{text}");
    }

    #[test]
    fn mode_is_private_accepts_only_owner_bits() {
        assert!(mode_is_private(0o100600));
        assert!(mode_is_private(0o400));
        assert!(!mode_is_private(0o100644));
        assert!(!mode_is_private(0o640));
        assert!(!mode_is_private(0o606));
    }

    #[test]
    fn holds_secret_reflects_arlo_and_imap_passwords() {
        let none: ArloConfig = toml::from_str("[credentials]\nemail = \"e@x\"\n").unwrap();
        assert!(!none.holds_secret());
        let arlo: ArloConfig = toml::from_str("[credentials]\npassword = \"p\"\n").unwrap();
        assert!(arlo.holds_secret());
        let imap: ArloConfig = toml::from_str("[mfa.imap]\npassword = \"p\"\n").unwrap();
        assert!(imap.holds_secret());
    }

    #[test]
    fn config_debug_never_prints_passwords() {
        let cfg: ArloConfig = toml::from_str(
            "[credentials]\npassword = \"arlo-pw\"\n[mfa.imap]\npassword = \"imap-pw\"\n",
        )
        .unwrap();
        let dump = format!("{cfg:?}");
        assert!(
            !dump.contains("arlo-pw") && !dump.contains("imap-pw"),
            "{dump}"
        );
    }
}
