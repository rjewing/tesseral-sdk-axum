pub mod backend_api;
pub mod access_token_authenticator;

use serde::{Deserialize, Serialize};
//
// use tower::Layer;
// use axum::extract::Request;
// use axum::http::StatusCode;
// use axum::middleware::Next;
// use axum::response::Response;
//
// #[derive(Clone)]
// pub struct Auth {
//     auth_data: AuthData,
// }
//
// #[derive(Clone)]
// enum AuthData {
//     AccessToken(AccessTokenData),
//     ApiKey(ApiKeyData),
// }
//
// impl Auth {
//     pub fn credentials(&self) -> &str {
//         match &self.auth_data {
//             AuthData::AccessToken(token_data) => &token_data.credentials,
//             AuthData::ApiKey(key_data) => &key_data.api_key_secret_token,
//         }
//     }
//
//     pub fn access_token_claims(&self) -> Option<AccessTokenClaims> {
//         match &self.auth_data {
//             AuthData::AccessToken(token_data) => Some(token_data.claims.clone()),
//             AuthData::ApiKey(_) => None,
//         }
//     }
//
//     pub fn has_permission(&self, action: &str) -> bool {
//         match &self.auth_data {
//             AuthData::AccessToken(token_data) => token_data
//                 .claims
//                 .actions
//                 .as_ref()
//                 .map_or(false, |actions| actions.contains(&action.to_string())),
//             AuthData::ApiKey(key_data) => key_data
//                 .authenticate_api_key_response
//                 .actions
//                 .contains(&action.to_string()),
//         }
//     }
//
//     pub fn credentials_type(&self) -> CredentialsType {
//         match &self.auth_data {
//             AuthData::AccessToken(_) => CredentialsType::AccessToken,
//             AuthData::ApiKey(_) => CredentialsType::ApiKey,
//         }
//     }
// }
//
// #[derive(Clone, Debug)]
// pub enum CredentialsType {
//     AccessToken,
//     ApiKey,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct AccessTokenData {
//     credentials: String,
//     claims: AccessTokenClaims,
// }
//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub nbf: i64,
    pub iat: i64,
    pub actions: Option<Vec<String>>,
    pub organization: AccessTokenOrganization,
    pub user: AccessTokenUser,
    pub session: AccessTokenSession,
    pub impersonator: Option<AccessTokenImpersonator>,
}
//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenSession {
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenOrganization {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenUser {
    // Example fields — replace with actual ones
    pub id: String,
    pub email: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "profilePictureUrl")]
    pub profile_picture_url: Option<String>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessTokenImpersonator {
    pub email: String,
}
//
// #[derive(Clone, Debug)]
// struct ApiKeyData {
//     api_key_secret_token: String,
//     authenticate_api_key_response: AuthenticateApiKeyResponse,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct AuthenticateApiKeyResponse {
//     #[serde(rename = "apiKeyId")]
//     api_key_id: String,
//     #[serde(rename = "organizationId")]
//     organization_id: String,
//     #[serde(rename = "actions")]
//     actions: Vec<String>,
// }
//
// pub struct Options {
//     pub publishable_key: String,
//     pub config_api_hostname: String,
//     pub jwks_refresh_interval_seconds: i64,
//     pub api_keys_enabled: bool,
//     pub backend_api_client: reqwest::Client,
// }
//
// pub struct RequireAuthLayer {
//
// }
//
// impl Layer<S> for RequireAuthLayer {
//     type Service = RequireAuthService<S>;
//
//     fn layer(&self, inner: S) -> Self::Service {
//         todo!()
//     }
// }
//
// pub struct RequireAuthService<S> {
//     inner: S,
//
// }
//
// pub async fn require_auth(mut req: Request, next: Next) -> Result<Response, StatusCode> {
//     Ok(next.run(req).await)
// }
