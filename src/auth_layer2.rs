use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use thiserror::Error;

pub struct Authenticator {
    publishable_key: String,
    config_api_hostname: String,
    jwks_refresh_interval: Duration,
    config: Config,

    api_keys_enabled: bool,
    backend_api_hostname: String,
    backend_api_key: Option<String>,

    http_client: reqwest::Client,
}

struct Config {
    jwks_next_refresh: SystemTime,
    project_id: String,
    jwks: HashMap<String, UnparsedPublicKey<Vec<u8>>>,
}

#[derive(Error, Debug)]
pub enum AuthenticatorError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Authenticator {
    async fn authenticate_api_key(
        &self,
        api_key_secret_token: &str,
    ) -> Result<AuthenticateApiKeyResponse, AuthenticatorError> {
        self.http_client
            .post(format!(
                "https://{}/v1/api-keys/authenticate",
                self.backend_api_hostname
            ))
            .bearer_auth(self.backend_api_key)
            .json(&Aut)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }

    async fn fetch_config(&self) -> Result<Config, anyhow::Error> {
        #[derive(Deserialize)]
        struct ConfigResponse {
            #[serde(rename = "projectId")]
            project_id: String,
            #[serde(rename = "jwks")]
            jwks: Vec<Jwk>,
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
                "{}/v1/config/{}",
                self.config_api_hostname, self.publishable_key
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut jwks = HashMap::new();
        for jwk in config_response.jwks {
            if jwk.kty != "EC" || jwk.crv != "P-256" {
                anyhow::bail!("Unsupported key type/curve: {}/{}", jwk.kty, jwk.crv);
            }

            let x_bytes = URL_SAFE_NO_PAD.decode(&jwk.x).map_err(|e| {
                crate::access_token_authenticator::AuthenticatorError::Other(anyhow::anyhow!(
                    "Failed to decode x coordinate: {}",
                    e
                ))
            })?;

            let y_bytes = URL_SAFE_NO_PAD.decode(&jwk.y).map_err(|e| {
                crate::access_token_authenticator::AuthenticatorError::Other(anyhow::anyhow!(
                    "Failed to decode y coordinate: {}",
                    e
                ))
            })?;

            let mut public_key_bytes = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
            public_key_bytes.push(0x04);
            public_key_bytes.extend_from_slice(&x_bytes);
            public_key_bytes.extend_from_slice(&y_bytes);

            let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_bytes);
            jwks.insert(jwk.kid, public_key);
        }

        Ok(Config {
            jwks_next_refresh: SystemTime::now() + self.jwks_refresh_interval,
            project_id: config_response.project_id,
            jwks,
        })
    }
}

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
