use crate::auth::{
    AccessTokenClaims, AccessTokenData, ApiKeyData, Auth, AuthData, AuthenticateApiKeyRequest,
    AuthenticateApiKeyResponse,
};
use crate::credentials::{is_api_key_format, is_jwt_format};
use anyhow::Context;
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::time::Instant;

/// Authenticates access tokens and API keys. Must be used with
/// [`require_auth`](`crate::require_auth`).
pub struct Authenticator {
    publishable_key: String,
    config_api_hostname: String,
    config_refresh_interval: Duration,
    config: Option<Config>,
    api_keys_enabled: bool,
    backend_api_key: Option<String>,
    backend_api_hostname: String,
    http_client: reqwest::Client,
}

struct Config {
    project_id: String,
    keys: HashMap<String, UnparsedPublicKey<Vec<u8>>>,
    next_refresh: Instant,
}

#[derive(Debug, Error)]
pub(crate) enum AuthenticateError {
    #[error("Unauthorized")]
    Unauthorized,

    #[error("Internal error: {0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthenticateApiKeyErrorResponse {
    message: String,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    kid: String,
}

impl Authenticator {
    /// Creates a new Authenticator with the given publishable key.
    ///
    /// Publishable keys start with `publishable_key_...`.
    pub fn new(publishable_key: String) -> Self {
        Self {
            publishable_key,
            config_api_hostname: "config.tesseral.com".to_owned(),
            config_refresh_interval: Duration::from_secs(60 * 60),
            config: None,
            api_keys_enabled: false,
            backend_api_key: env::var("TESSERAL_BACKEND_API_KEY").ok(),
            backend_api_hostname: "api.tesseral.com".to_owned(),
            http_client: reqwest::Client::new(),
        }
    }

    pub(crate) fn validate_backend_api_key(&self) {
        if self.api_keys_enabled && self.backend_api_key.is_none() {
            panic!("If you use authenticator.with_api_keys_enabled(true), then you must use authenticator.with_backend_api_key(...) or set a TESSERAL_BACKEND_API_KEY environment variable.")
        }
    }

    /// Sets the hostname for the Tesseral config API.
    ///
    /// The default is `config.tesseral.com`.
    pub fn with_config_api_hostname(mut self, config_api_hostname: String) -> Self {
        self.config_api_hostname = config_api_hostname;
        self
    }

    /// Sets how often to update the cache of public keys access tokens may be
    /// signed with.
    ///
    /// The default is 3600 seconds (1 hour).
    pub fn with_config_refresh_interval(mut self, config_refresh_interval: Duration) -> Self {
        self.config_refresh_interval = config_refresh_interval;
        self
    }

    /// Sets whether to accept API keys.
    ///
    /// The default is `false`.
    pub fn with_api_keys_enabled(mut self, api_keys_enabled: bool) -> Self {
        self.api_keys_enabled = api_keys_enabled;
        self
    }

    /// Sets the Backend API Key to use when authenticating API keys.
    ///
    /// The default is populated from the `TESSERAL_BACKEND_API_KEY` environment
    /// variable. If [`with_api_keys_enabled`] is set to `true`, then a Backend
    /// API Key is required.
    pub fn with_backend_api_key(mut self, backend_api_key: String) -> Self {
        self.backend_api_key = Some(backend_api_key);
        self
    }

    pub(crate) async fn authenticate_request(
        &mut self,
        request_headers: &HeaderMap,
    ) -> Result<Auth, AuthenticateError> {
        self.fetch_config()
            .await
            .context("Failed to fetch config")?;

        let project_id = &self.config.as_ref().unwrap().project_id;
        let keys = &self.config.as_ref().unwrap().keys;

        let credentials = Self::extract_credentials(&request_headers, project_id)
            .ok_or(AuthenticateError::Unauthorized)?;

        if is_jwt_format(&credentials) {
            let now_unix_seconds = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let access_token_claims =
                authenticate_access_token(keys, now_unix_seconds as i64, &credentials)
                    .ok_or(AuthenticateError::Unauthorized)?;
            dbg!(&access_token_claims);
            return Ok(Auth {
                data: AuthData::AccessToken(AccessTokenData {
                    access_token: credentials,
                    access_token_claims,
                }),
            });
        }

        if self.api_keys_enabled && is_api_key_format(&credentials) {
            let authenticate_api_key_response = self.authenticate_api_key(&credentials).await?;

            return Ok(Auth {
                data: AuthData::ApiKey(ApiKeyData {
                    api_key_secret_token: credentials,
                    authenticate_api_key_response,
                }),
            });
        }

        Err(AuthenticateError::Unauthorized)
    }

    fn extract_credentials(request_headers: &HeaderMap, project_id: &str) -> Option<String> {
        if let Some(authorization) = request_headers.get("Authorization") {
            if let Ok(authorization) = authorization.to_str() {
                return match authorization.strip_prefix("Bearer ") {
                    Some(s) => Some(s.to_owned()),
                    None => Some(authorization.to_owned()),
                };
            }
        }

        let cookie_name = format!("tesseral_{}_access_token", project_id);
        for cookie in request_headers.get_all("Cookie") {
            if let Ok(cookie) = cookie.to_str() {
                if let Some(credentials) = cookie.strip_prefix(&cookie_name) {
                    return Some(credentials.to_owned());
                }
            }
        }

        None
    }

    async fn fetch_config(&mut self) -> Result<(), anyhow::Error> {
        if let Some(ref config) = self.config {
            if config.next_refresh > Instant::now() {
                return Ok(());
            }
        }

        #[derive(Deserialize)]
        struct ConfigResponse {
            #[serde(rename = "projectId")]
            project_id: String,
            keys: Vec<Jwk>,
        }

        #[derive(Deserialize)]
        struct Jwk {
            kid: String,
            kty: String,
            crv: String,
            x: String,
            y: String,
        }

        let config_response: ConfigResponse = self
            .http_client
            .get(format!(
                "https://{}/v1/config/{}",
                self.config_api_hostname, self.publishable_key
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut keys = HashMap::new();
        for jwk in config_response.keys {
            if jwk.kty != "EC" || jwk.crv != "P-256" {
                anyhow::bail!("Unsupported key type/curve: {}/{}", jwk.kty, jwk.crv);
            }

            let x = BASE64_URL_SAFE_NO_PAD.decode(jwk.x)?;
            let y = BASE64_URL_SAFE_NO_PAD.decode(jwk.y)?;
            let mut buf = Vec::with_capacity(1 + x.len() + y.len());
            buf.push(0x04);
            buf.extend(&x);
            buf.extend(&y);

            keys.insert(
                jwk.kid,
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, buf),
            );
        }

        self.config = Some(Config {
            next_refresh: Instant::now() + self.config_refresh_interval,
            project_id: config_response.project_id,
            keys,
        });
        Ok(())
    }

    async fn authenticate_api_key(
        &self,
        api_key_secret_token: &str,
    ) -> Result<AuthenticateApiKeyResponse, AuthenticateError> {
        let response = self
            .http_client
            .post(format!(
                "https://{}/v1/api-keys/authenticate",
                self.backend_api_hostname
            ))
            .bearer_auth(self.backend_api_key.clone().unwrap())
            .json(&AuthenticateApiKeyRequest {
                secret_token: Some(api_key_secret_token.to_owned()),
            })
            .send()
            .await
            .map_err(|e| AuthenticateError::Other(e.into()))?;

        // Handle HTTP status errors
        if let Err(err) = response.error_for_status_ref() {
            // If it's a 400 status, check if it's an "unauthenticated_api_key" error
            if err.status() == Some(reqwest::StatusCode::BAD_REQUEST) {
                // Get the response body
                let response_body = response
                    .text()
                    .await
                    .map_err(|e| AuthenticateError::Other(e.into()))?;

                // Try to parse the error response body
                if let Ok(error_response) =
                    serde_json::from_str::<AuthenticateApiKeyErrorResponse>(&response_body)
                {
                    // Check if the error message matches what we expect
                    if error_response.message == "unauthenticated_api_key" {
                        return Err(AuthenticateError::Unauthorized);
                    }
                }
                // If we couldn't parse the response or the message didn't match, treat as Other error
                return Err(AuthenticateError::Other(anyhow::anyhow!(
                    "Bad request: {}",
                    response_body
                )));
            } else {
                // For other status codes, return Other error
                return Err(AuthenticateError::Other(err.into()));
            }
        }

        let response = response;

        // Parse the JSON response
        let res: AuthenticateApiKeyResponse = response
            .json()
            .await
            .map_err(|e| AuthenticateError::Other(e.into()))?;

        Ok(res)
    }
}

fn authenticate_access_token(
    keys: &HashMap<String, UnparsedPublicKey<Vec<u8>>>,
    now_unix_seconds: i64,
    access_token: &str,
) -> Option<AccessTokenClaims> {
    // Split the JWT token into its three parts: header, payload, signature
    let parts: Vec<&str> = access_token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Decode the header
    let header_bytes = BASE64_URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes).ok()?;

    // Extract the key ID (kid) from the header
    let kid = &header.kid;

    // Find the corresponding public key
    let public_key = keys.get(kid)?;

    // Prepare the data to be verified (header.payload)
    let signed_data = format!("{}.{}", header_b64, payload_b64);

    // Decode the signature
    let signature = BASE64_URL_SAFE_NO_PAD.decode(signature_b64).ok()?;

    // Verify the signature
    if public_key
        .verify(signed_data.as_bytes(), &signature)
        .is_err()
    {
        return None;
    }

    // Decode and parse the payload
    let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: AccessTokenClaims = serde_json::from_slice(&payload_bytes).ok()?;

    if claims.exp < now_unix_seconds || claims.nbf > now_unix_seconds {
        return None;
    }

    Some(claims)
}
