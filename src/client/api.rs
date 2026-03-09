use crate::client::ArloClient;
use crate::error::ArloError;
use crate::headers::*;
use reqwest::{Method, RequestBuilder};
use serde::Serialize;

impl ArloClient {
    /// Helper to inject standard Arlo dashboard headers
    fn inject_headers(&self, mut builder: RequestBuilder) -> RequestBuilder {
        builder = builder
            .header("Accept", "application/json, text/plain, */*")
            .header("Accept-Language", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7")
            .header("Origin", ARLO_ORIGIN)
            .header("Referer", ARLO_REFERER)
            .header("DNT", "1")
            .header("Pragma", "no-cache")
            .header("Cache-Control", "no-cache")
            .header("Source", HEADER_SOURCE)
            .header("auth-version", HEADER_AUTH_VERSION)
            .header("x-service-version", HEADER_SERVICE_VERSION)
            .header("x-user-device-type", HEADER_USER_DEVICE_TYPE)
            .header("x-user-device-id", self.auth.device_id.clone())
            .header(
                "x-user-device-automation-name",
                HEADER_USER_DEVICE_AUTOMATION_NAME,
            );

        // Inject authorization token if we have one
        if let Some(token) = &self.auth.access_token {
            builder = builder.header("Authorization", token);
        }

        builder
    }

    /// Executes an OPTIONS preflight request.
    /// To perfectly emulate a human browser, modern Single Page Applications fire an OPTIONS
    /// preflight before making a CORS POST/PUT/DELETE request.
    async fn perform_options_preflight(&self, method: &Method, url: &str) -> Result<(), ArloError> {
        let mut builder = self.reqwest_client.request(Method::OPTIONS, url)
            .header("Access-Control-Request-Method", method.as_str())
            .header("Access-Control-Request-Headers", "auth-version,content-type,source,x-service-version,x-user-device-automation-name,x-user-device-id,x-user-device-type");

        builder = self.inject_headers(builder);

        let response = builder.send().await?;
        if !response.status().is_success() {
            log::warn!(
                "OPTIONS preflight to {} returned non-200 status: {}",
                url,
                response.status()
            );
        }

        Ok(())
    }

    /// Primary engine to execute requests simulating the Web Dashboard.
    /// It automatically fires the OPTIONS preflight if necessary (e.g., POST/PUT).
    /// Returns the raw Response body text.
    pub async fn execute_request<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        payload: Option<&T>,
    ) -> Result<String, ArloError> {
        // 1. Simulate the browser's CORS OPTIONS pre-flight for state-mutating requests
        if method == Method::POST || method == Method::PUT || method == Method::DELETE {
            self.perform_options_preflight(&method, url).await?;
        }

        // 2. Build the actual request
        let mut builder = self.reqwest_client.request(method.clone(), url);
        builder = self.inject_headers(builder);

        let mut dump_pay = String::new();
        // 3. Attach payload if it's a POST/PUT
        if let Some(data) = payload {
            builder = builder.json(data);
            if self.debug_mode {
                if let Ok(json) = serde_json::to_string(data) {
                    dump_pay = json;
                }
            }
        }

        if self.debug_mode {
            println!("\n[DEBUG] --> Request:");
            println!("[DEBUG] Method: {}", method);
            println!("[DEBUG] URL: {}", url);
            if !dump_pay.is_empty() {
                println!("[DEBUG] Payload: {}", dump_pay);
            }
        }

        // 4. Send and consume body
        let response = builder.send().await?;
        let status = response.status();

        let body_str = response.text().await?;

        if self.debug_mode {
            println!("\n[DEBUG] <-- Response:");
            println!("[DEBUG] Status: {}", status);
            println!("[DEBUG] Body: {}", body_str);
        }

        if !status.is_success() {
            return Err(ArloError::HttpError {
                status,
                body: body_str,
            });
        }

        Ok(body_str)
    }
}
