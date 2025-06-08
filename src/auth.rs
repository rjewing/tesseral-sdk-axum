use axum::extract::{FromRequest, FromRequestParts};
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

/// Represents an authenticated user or API key.
///
/// This struct is extracted from request extensions and provides methods to access
/// authentication information such as organization ID, access token claims, credentials,
/// and permissions.
///
/// # Example
///
/// ```
/// async fn handler(auth: Auth) -> String {
///     let org_id = auth.organization_id();
///     let has_permission = auth.has_permission("foo.bar.baz");
///     // ...
/// }
/// ```
#[derive(Clone)]
pub struct Auth {
    pub(crate) data: AuthData,
}

impl<S> FromRequestParts<S> for Auth
where
    S: Send + Sync,
{
    type Rejection = ();

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Auth>()
            .cloned()
            .ok_or(())
    }
}

impl Auth {
    /// Returns the organization ID of the authenticated user or API key.
    ///
    /// This method works for both access token and API key authentication.
    pub fn organization_id(&self) -> &str {
        match self.data {
            AuthData::AccessToken(ref data) => &data.access_token_claims.organization.id,
            AuthData::ApiKey(ref data) => data
                .authenticate_api_key_response
                .organization_id
                .as_deref()
                .unwrap(),
        }
    }

    /// Returns the access token claims if the authentication was done with an access token.
    ///
    /// Returns `None` if the authentication was done with an API key.
    pub fn access_token_claims(&self) -> Option<&AccessTokenClaims> {
        match self.data {
            AuthData::AccessToken(ref data) => Some(&data.access_token_claims),
            AuthData::ApiKey(_) => None,
        }
    }

    /// Returns the credentials used for authentication.
    ///
    /// This will be either the access token or the API key secret token.
    pub fn credentials(&self) -> &str {
        match self.data {
            AuthData::AccessToken(ref data) => &data.access_token,
            AuthData::ApiKey(ref data) => &data.api_key_secret_token,
        }
    }

    /// Checks if the authenticated user or API key has the specified permission.
    ///
    /// # Arguments
    ///
    /// * `action` - The permission to check for, e.g., "foo.bar.baz"
    ///
    /// # Returns
    ///
    /// `true` if the user or API key has the specified permission, `false` otherwise.
    pub fn has_permission(&self, action: &str) -> bool {
        match self.data {
            AuthData::AccessToken(ref data) => data
                .access_token_claims
                .actions
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .any(|a| a == action),
            AuthData::ApiKey(ref data) => data
                .authenticate_api_key_response
                .actions
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .any(|a| a == action),
        }
    }
}

#[derive(Clone)]
pub(crate) enum AuthData {
    AccessToken(AccessTokenData),
    ApiKey(ApiKeyData),
}

#[derive(Clone)]
pub(crate) struct AccessTokenData {
    pub(crate) access_token: String,
    pub(crate) access_token_claims: AccessTokenClaims,
}

#[derive(Clone)]
pub(crate) struct ApiKeyData {
    pub(crate) api_key_secret_token: String,
    pub(crate) authenticate_api_key_response: AuthenticateApiKeyResponse,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AuthenticateApiKeyRequest {
    #[serde(rename = "secretToken", skip_serializing_if = "Option::is_none")]
    pub secret_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AuthenticateApiKeyResponse {
    #[serde(rename = "apiKeyId", skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    #[serde(rename = "organizationId", skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "actions", skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
}
