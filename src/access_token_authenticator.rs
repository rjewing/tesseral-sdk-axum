use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
use base64::{engine::general_purpose::{URL_SAFE_NO_PAD, URL_SAFE_NO_PAD as BASE64}, Engine as _};
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

use crate::access_token_claims::AccessTokenClaims;

/// Error types for the access token authenticator
#[derive(Error, Debug)]
pub enum AuthenticatorError {
    #[error("invalid access token")]
    InvalidAccessToken,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Options for configuring the Authenticator
#[derive(Clone)]
pub struct AuthenticatorOptions {
    publishable_key: String,
    config_api_hostname: String,
    http_client: Client,
    jwks_refresh_interval: Duration,
}

/// Builder for creating an Authenticator with custom settings
pub struct AuthenticatorBuilder {
    options: AuthenticatorOptions,
}

impl AuthenticatorBuilder {
    /// Create a new authenticator builder with default settings
    pub fn new(publishable_key: String) -> Self {
        Self {
            options: AuthenticatorOptions {
                publishable_key,
                config_api_hostname: "config.tesseral.com".to_string(),
                http_client: Client::new(),
                jwks_refresh_interval: Duration::from_secs(3600), // 1 hour
            },
        }
    }

    /// Set a custom config API hostname
    pub fn with_config_api_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.options.config_api_hostname = hostname.into();
        self
    }

    /// Set a custom HTTP client
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.options.http_client = client;
        self
    }

    /// Set a custom JWKS refresh interval
    pub fn with_jwks_refresh_interval(mut self, interval: Duration) -> Self {
        self.options.jwks_refresh_interval = interval;
        self
    }

    /// Build the authenticator with the configured settings
    pub fn build(self) -> Authenticator {
        Authenticator {
            options: self.options,
            project_id: Arc::new(RwLock::new(String::new())),
            jwks: Arc::new(RwLock::new(HashMap::new())),
            jwks_next_refresh: Arc::new(RwLock::new(SystemTime::UNIX_EPOCH)),
        }
    }
}

/// Authenticator verifies the authenticity of access tokens and returns the claims they encode.
///
/// Authenticator is safe for concurrent use and should be reused across requests.
#[derive(Clone)]
pub struct Authenticator {
    options: AuthenticatorOptions,
    project_id: Arc<RwLock<String>>,
    jwks: Arc<RwLock<HashMap<String, PublicKey>>>,
    jwks_next_refresh: Arc<RwLock<SystemTime>>,
}

impl Authenticator {
    /// Create a new authenticator with the given publishable key
    pub fn new(publishable_key: String) -> Self {
        AuthenticatorBuilder::new(publishable_key).build()
    }

    /// Get the project ID for this authenticator
    pub async fn project_id(&self) -> Result<String, AuthenticatorError> {
        self.update_config_data().await?;
        let project_id = self.project_id.read().unwrap().clone();
        Ok(project_id)
    }

    /// Authenticate an access token and return the claims it contains
    ///
    /// Returns an error if the access token is inauthentic, invalid, or expired
    pub async fn authenticate_access_token(
        &self,
        access_token: &str,
    ) -> Result<AccessTokenClaims, AuthenticatorError> {
        self.update_config_data().await?;
        let jwks = self.jwks.read().unwrap().clone();
        authenticate_access_token(&jwks, access_token)
    }

    /// Update the config data if needed
    async fn update_config_data(&self) -> Result<(), AuthenticatorError> {
        // Check if JWKS is fresh using a read lock
        {
            let next_refresh = self.jwks_next_refresh.read().unwrap();
            if SystemTime::now() < *next_refresh {
                return Ok(());
            }
        }

        // Need to (re)fetch, check again with write lock
        {
            let mut next_refresh = self.jwks_next_refresh.write().unwrap();

            // Double-check after acquiring the write lock
            if SystemTime::now() < *next_refresh {
                return Ok(());
            }

            // Set next refresh time to far in the future to prevent other threads from
            // also trying to refresh while we're fetching
            *next_refresh = SystemTime::now() + Duration::from_secs(24 * 60 * 60); // 24 hours
        } // Release the lock before the await point

        // Fetch new config without holding any locks
        let config = self.fetch_config().await?;

        // Update project ID
        {
            let mut project_id = self.project_id.write().unwrap();
            *project_id = config.project_id;
        }

        // Update JWKS
        {
            let mut jwks = self.jwks.write().unwrap();
            *jwks = config.keys;
        }

        // Update next refresh time with the actual interval
        {
            let mut next_refresh = self.jwks_next_refresh.write().unwrap();
            *next_refresh = SystemTime::now() + self.options.jwks_refresh_interval;
        }

        Ok(())
    }

    /// Fetch the config from the API
    async fn fetch_config(&self) -> Result<ConfigData, AuthenticatorError> {
        let url = format!(
            "https://{}/v1/config/{}",
            self.options.config_api_hostname, self.options.publishable_key
        );

        let response = self.options.http_client.get(&url).send().await
            .map_err(|e| AuthenticatorError::Other(anyhow::anyhow!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthenticatorError::Other(anyhow::anyhow!(
                "Bad response status code: {}", response.status()
            )));
        }

        let body = response.bytes().await
            .map_err(|e| AuthenticatorError::Other(anyhow::anyhow!("Failed to get response body: {}", e)))?;
        parse_config(&body).map_err(|e| AuthenticatorError::Other(anyhow::anyhow!("{}", e)))
    }
}

/// Wrapper around UnparsedPublicKey for ECDSA verification
#[derive(Clone)]
struct PublicKey {
    key: UnparsedPublicKey<Vec<u8>>,
}

/// Config data returned from the API
struct ConfigData {
    project_id: String,
    keys: HashMap<String, PublicKey>,
}

/// JWK structure for parsing the config response
#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    crv: String,
    x: String,
    y: String,
}

/// Config response structure
#[derive(Deserialize)]
struct ConfigResponse {
    #[serde(rename = "projectId")]
    project_id: String,
    keys: Vec<Jwk>,
}

/// Parse the config response into a ConfigData struct
fn parse_config(bytes: &[u8]) -> Result<ConfigData, AuthenticatorError> {
    let config_response: ConfigResponse = serde_json::from_slice(bytes)
        .map_err(|e| AuthenticatorError::Other(anyhow::anyhow!("Failed to parse config response: {}", e)))?;

    let mut keys = HashMap::new();

    for key in config_response.keys {
        if key.kty != "EC" || key.crv != "P-256" {
            return Err(AuthenticatorError::Other(anyhow::anyhow!(
                "Unsupported key type/curve: {}/{}", key.kty, key.crv
            )));
        }

        // Decode x and y coordinates
        let x_bytes = BASE64.decode(&key.x)
            .map_err(|e| AuthenticatorError::Other(anyhow::anyhow!("Failed to decode x coordinate: {}", e)))?;

        let y_bytes = BASE64.decode(&key.y)
            .map_err(|e| AuthenticatorError::Other(anyhow::anyhow!("Failed to decode y coordinate: {}", e)))?;

        // Concatenate x and y bytes into a single vec
        let mut public_key_bytes = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
        public_key_bytes.push(0x04);
        public_key_bytes.extend_from_slice(&x_bytes);
        public_key_bytes.extend_from_slice(&y_bytes);

        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_bytes);
        keys.insert(key.kid, PublicKey { key: public_key });
    }

    Ok(ConfigData {
        project_id: config_response.project_id,
        keys,
    })
}

/// JWT header structure
#[derive(Deserialize)]
struct JwtHeader {
    kid: String,
}

/// Authenticate an access token using the provided JWKS
fn authenticate_access_token(
    jwks: &HashMap<String, PublicKey>,
    access_token: &str,
) -> Result<AccessTokenClaims, AuthenticatorError> {
    // Split the token into parts
    let parts: Vec<&str> = access_token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthenticatorError::InvalidAccessToken);
    }

    // Decode the header
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])
        .map_err(|_| AuthenticatorError::InvalidAccessToken)?;

    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AuthenticatorError::InvalidAccessToken)?;

    // Get the public key
    let public_key = jwks.get(&header.kid)
        .ok_or(AuthenticatorError::InvalidAccessToken)?;

    // Decode the claims
    let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|_| AuthenticatorError::InvalidAccessToken)?;

    // Create the signed part
    let signed_part = format!("{}.{}", parts[0], parts[1]);

    // Decode the signature
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2])
        .map_err(|_| AuthenticatorError::InvalidAccessToken)?;

    if signature_bytes.len() != 64 {
        return Err(AuthenticatorError::InvalidAccessToken);
    }

    // Verify the signature using aws-lc-rs
    let result = public_key.key.verify(signed_part.as_bytes(), &signature_bytes);
    if let Err(_) = result {
        return Err(AuthenticatorError::InvalidAccessToken);
    }

    // Parse the claims
    let claims: AccessTokenClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| AuthenticatorError::Other(anyhow::anyhow!("Failed to parse claims: {}", e)))?;

    // Check token expiration
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    if now < claims.nbf || now > claims.exp {
        return Err(AuthenticatorError::InvalidAccessToken);
    }

    Ok(claims)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_smoke_authenticator() {
        let authenticator = AuthenticatorBuilder::new("publishable_key_en43cawcravxk7t2murwiz192".to_string()).build();
        dbg!(authenticator.authenticate_access_token("eyJraWQiOiJzZXNzaW9uX3NpZ25pbmdfa2V5X2FmYmxudmhyeG80OHQ5czVtZjcwdWE0OW0iLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Byb2plY3QtZXIyanloMmdvb2l1cXZieHh4dG80NXgxei50ZXNzZXJhbC5hcHAiLCJzdWIiOiJ1c2VyXzN4bGlmZmc3N2dtZTNyM29hbGY4MzM5OXIiLCJhdWQiOiJodHRwczovL3Byb2plY3QtZXIyanloMmdvb2l1cXZieHh4dG80NXgxei50ZXNzZXJhbC5hcHAiLCJleHAiOjE3NDkyNDIwODksIm5iZiI6MTc0OTI0MTc4OSwiaWF0IjoxNzQ5MjQxNzg5LCJzZXNzaW9uIjp7ImlkIjoic2Vzc2lvbl8wM2UyZGY3dGJjcGJ0bDZjeTFudGMyYmIwIn0sInVzZXIiOnsiaWQiOiJ1c2VyXzN4bGlmZmc3N2dtZTNyM29hbGY4MzM5OXIiLCJlbWFpbCI6InVseXNzZS5jYXJpb25Ac3NvcmVhZHkuY29tIn0sIm9yZ2FuaXphdGlvbiI6eyJpZCI6Im9yZ180aWptaTgxMmd0b3JheDltcm5qeTF4ZDB1IiwiZGlzcGxheU5hbWUiOiJGb29CYXIifX0.Bmeu2EqRZ-hzC3rKrEOdTIzf9SJKsEgATR1TmHU9HPlOSXKtZGkOB5k7Zz6I0-3Kx920bdIagUXhnJ6MO6zX3Q").await);
    }
}
