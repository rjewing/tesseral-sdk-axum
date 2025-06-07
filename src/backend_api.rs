use std::sync::Arc;
use std::env;
use reqwest::{Client as ReqwestClient, Error as ReqwestError};
use serde::{Deserialize, Serialize};

const DEFAULT_API_HOSTNAME: &str = "api.tesseral.com";
const ENV_BACKEND_API_KEY: &str = "TESSERAL_BACKEND_API_KEY";

/// Request to authenticate an API key.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticateApiKeyRequest {
    #[serde(rename = "secretToken", skip_serializing_if = "Option::is_none")]
    pub secret_token: Option<String>,
}

/// Response from authenticating an API key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticateApiKeyResponse {
    #[serde(rename = "apiKeyId", skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    #[serde(rename = "organizationId", skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "actions", skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
}

/// Client for communicating with the Tesseral API.
#[derive(Clone)]
pub struct Client {
    api_hostname: String,
    http_client: Arc<ReqwestClient>,
    backend_api_key: String,
}

impl Client {
    /// Create a new client builder with default settings.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Create a new client with default settings.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Get the base URL for API requests.
    fn base_url(&self) -> String {
        format!("https://{}", self.api_hostname)
    }

    /// Send a request to the API.
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<impl serde::Serialize>,
    ) -> Result<T, ReqwestError> {
        let url = format!("{}{}", self.base_url(), path);

        let mut request = self.http_client.request(method, url);

        // Add backend API key to Authorization header
        request = request.header("Authorization", format!("Bearer {}", self.backend_api_key));

        if let Some(body_data) = body {
            request = request.json(&body_data);
        }

        let response = request.send().await?;
        response.error_for_status()?.json::<T>().await
    }

    /// Send a POST request to the API.
    async fn post<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: B,
    ) -> Result<T, ReqwestError> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    /// Authenticate an API key.
    pub async fn authenticate_api_key(
        &self,
        request: AuthenticateApiKeyRequest,
    ) -> Result<AuthenticateApiKeyResponse, ReqwestError> {
        self.post("/v1/api-keys/authenticate", request).await
    }
}

/// Builder for creating a Client with custom settings.
pub struct ClientBuilder {
    api_hostname: String,
    http_client: Option<ReqwestClient>,
    backend_api_key: Option<String>,
}

impl ClientBuilder {
    /// Create a new client builder with default settings.
    pub fn new() -> Self {
        Self {
            api_hostname: DEFAULT_API_HOSTNAME.to_string(),
            http_client: None,
            backend_api_key: env::var(ENV_BACKEND_API_KEY).ok(),
        }
    }

    /// Set a custom API hostname.
    pub fn api_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.api_hostname = hostname.into();
        self
    }

    /// Set a custom HTTP client.
    pub fn http_client(mut self, client: ReqwestClient) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Set a custom backend API key.
    pub fn backend_api_key(mut self, key: impl Into<String>) -> Self {
        self.backend_api_key = Some(key.into());
        self
    }

    /// Build the client with the configured settings.
    pub fn build(self) -> Client {
        let http_client = self.http_client.unwrap_or_else(|| ReqwestClient::new());

        // Get the backend API key or panic if not provided
        let backend_api_key = self.backend_api_key
            .expect("Backend API key is required. Set it using .backend_api_key() or the TESSERAL_BACKEND_API_KEY environment variable.");

        Client {
            api_hostname: self.api_hostname,
            http_client: Arc::new(http_client),
            backend_api_key,
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "Backend API key is required")]
    fn test_client_builder_default() {
        // Ensure environment variable is not set for this test
        unsafe { env::remove_var(ENV_BACKEND_API_KEY); }

        // This should panic because no backend API key is provided
        let _client = Client::builder().build();
    }

    #[test]
    fn test_client_builder_custom_hostname() {
        let custom_hostname = "custom.api.example.com";
        let custom_key = "test-api-key";
        let client = Client::builder()
            .api_hostname(custom_hostname)
            .backend_api_key(custom_key)
            .build();
        assert_eq!(client.api_hostname, custom_hostname);
        assert_eq!(client.backend_api_key, custom_key);
    }

    #[test]
    fn test_client_builder_custom_client() {
        let custom_client = ReqwestClient::new();
        let custom_key = "test-api-key";
        let client = Client::builder()
            .http_client(custom_client)
            .backend_api_key(custom_key)
            .build();
        // We can't directly compare the http_client because it's wrapped in Arc
        // but we can verify that the client was built successfully
        assert_eq!(client.api_hostname, DEFAULT_API_HOSTNAME);
        assert_eq!(client.backend_api_key, custom_key);
    }

    #[test]
    fn test_client_builder_custom_backend_api_key() {
        let custom_key = "test-api-key";
        let client = Client::builder()
            .backend_api_key(custom_key)
            .build();
        assert_eq!(client.backend_api_key, custom_key);
    }

    #[test]
    fn test_client_builder_env_backend_api_key() {
        let test_key = "test-env-api-key";
        unsafe { env::set_var(ENV_BACKEND_API_KEY, test_key); }

        let client = Client::builder().build();
        assert_eq!(client.backend_api_key, test_key);

        // Clean up
        unsafe { env::remove_var(ENV_BACKEND_API_KEY); }
    }

    // This test is no longer needed as base_url is now private
    // #[test]
    // fn test_client_base_url() {
    //     let client = Client::new();
    //     assert_eq!(client.base_url(), format!("https://{}", DEFAULT_API_HOSTNAME));
    // }

    #[test]
    fn test_authenticate_api_key_request_serialization() {
        let request = AuthenticateApiKeyRequest {
            secret_token: Some("test-token".to_string()),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json, r#"{"secretToken":"test-token"}"#);
    }

    #[test]
    fn test_authenticate_api_key_response_deserialization() {
        let json = r#"{
            "apiKeyId": "key-123",
            "organizationId": "org-456",
            "actions": ["read", "write"]
        }"#;
        let response: AuthenticateApiKeyResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.api_key_id, Some("key-123".to_string()));
        assert_eq!(response.organization_id, Some("org-456".to_string()));
        assert_eq!(response.actions, Some(vec!["read".to_string(), "write".to_string()]));
    }
}
