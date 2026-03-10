#![allow(missing_docs)]
use crate::error::ArloError;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ArloConfig {
    pub credentials: Option<CredentialsConfig>,
    pub mfa: Option<MfaConfig>,
    pub client: Option<ClientConfig>,
    pub streaming: Option<StreamingConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CredentialsConfig {
    pub email: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MfaConfig {
    pub preferred_method: Option<String>,
    pub imap: Option<ImapConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ImapConfig {
    pub enabled: Option<bool>,
    pub provider: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub delete_after_read: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ClientConfig {
    pub debug_mode: Option<bool>,
    pub user_agent: Option<String>,
    pub session_cache_path: Option<String>,
    pub headless: Option<bool>,
    pub upstream_proxy: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StreamingConfig {
    pub preferred_protocol: Option<String>,
    pub media_path: Option<String>,
}

impl ArloConfig {
    /// Loads and parses the configuration file at the given path
    pub fn load_from_file(path: &str) -> Result<Self, ArloError> {
        let contents = fs::read_to_string(path).map_err(|e| {
            ArloError::ScraperError(format!("Failed to read config file {}: {}", path, e))
        })?;

        let parsed: ArloConfig = toml::from_str(&contents).map_err(|e| {
            ArloError::ScraperError(format!("Failed to parse config file {}: {}", path, e))
        })?;

        Ok(parsed)
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
        assert_eq!(creds.password.unwrap(), "secure_password");

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
