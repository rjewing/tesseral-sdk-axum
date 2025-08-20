use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};

#[cfg(feature = "test-utils")]
use std::time::{Duration, Instant};

/// Represents an authenticated user or API key. Must be used with
/// [`require_auth`](`crate::require_auth`).
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
        parts.extensions.get::<Auth>().cloned().ok_or(())
    }
}

impl Auth {
    /// The type of credentials used to authenticate the request.
    pub fn credentials_type(&self) -> CredentialsType {
        match self.data {
            AuthData::AccessToken(_) => CredentialsType::AccessToken,
            AuthData::ApiKey(_) => CredentialsType::ApiKey,
        }
    }

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

    /// The claims inside the request's access token, if any.
    ///
    /// Returns `None` if the request was authenticated with an API key.
    pub fn access_token_claims(&self) -> Option<&AccessTokenClaims> {
        match self.data {
            AuthData::AccessToken(ref data) => Some(&data.access_token_claims),
            AuthData::ApiKey(_) => None,
        }
    }

    /// Returns the request's original credentials.
    pub fn credentials(&self) -> &str {
        match self.data {
            AuthData::AccessToken(ref data) => &data.access_token,
            AuthData::ApiKey(ref data) => &data.api_key_secret_token,
        }
    }

    /// Returns whether the requester has permission to carry out the given
    /// action.
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

#[cfg(feature = "test-utils")]
impl Auth {
    /// Returns a mock access token for use in tests with custom access token claims.
    pub fn test_access_token_with_claims(access_token_claims: AccessTokenClaims) -> Self {
        Self {
            data: AuthData::AccessToken(AccessTokenData {
                // JWT header uses mock data: {"kid":"session_signing_key_example1234567890abcdefgh","alg":"ES256"}
                access_token: "eyJraWQiOiJzZXNzaW9uX3NpZ25pbmdfa2V5X2V4YW1wbGUxMjM0NTY3ODkwYWJjZGVmZ2giLCJhbGciOiJFUzI1NiJ9Cg.example.token".to_string(),
                access_token_claims,
            })
        }
    }

    /// Returns a mock access token for use in tests.
    pub fn test_access_token() -> Self {
        Self::test_access_token_with_claims(AccessTokenClaims {
            iss: "https://project-example1234567890abcdefgh.tesseral.app".to_string(),
            sub: "user_1234567890abcdefghijklmno".to_string(),
            aud: "https://project-example1234567890abcdefgh.tesseral.app".to_string(),
            exp: (Instant::now() + Duration::from_secs(5 * 60))
                .elapsed()
                .as_secs() as i64,
            nbf: Instant::now().elapsed().as_secs() as i64,
            iat: Instant::now().elapsed().as_secs() as i64,
            session: AccessTokenSession {
                id: "session_example1234567890abcdefgh".to_string(),
            },
            user: AccessTokenUser {
                id: "user_example1234567890abcdefgh".to_string(),
                email: "user@example.com".to_string(),
                display_name: Some("Example User".to_string()),
                profile_picture_url: None,
            },
            organization: AccessTokenOrganization {
                id: "org_example1234567890abcdefgh".to_string(),
                display_name: "Acme".to_string(),
            },
            actions: None,
            impersonator: None,
        })
    }
}

/// Returned from [`Auth::credentials_type`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialsType {
    /// The request was authenticated with an access token.
    AccessToken,

    /// The request was authenticated with an API key.
    ApiKey,
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

/// The claims encoded in an Access Token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Will always be of the form "https://project-xxx.tesseral.app", where
    /// "project-xxx" is your Project ID.
    pub iss: String,
    /// Will always be equal to the `user.id` claim.
    pub sub: String,
    /// Will always be equal to the `iss` claim.
    pub aud: String,
    /// When this Access Token expires, in seconds since the unix epoch.
    pub exp: i64,
    /// When this Access Token was issued, in seconds since the unix epoch.
    pub nbf: i64,
    /// Will always be equal to the `nbf` claim.
    pub iat: i64,
    /// The set of actions the User has permission to carry out.
    pub actions: Option<Vec<String>>,
    /// The Organization the User is logged into.
    pub organization: AccessTokenOrganization,
    /// The User that's logged in.
    pub user: AccessTokenUser,
    /// The user's current Session.
    pub session: AccessTokenSession,
    /// If this is an impersonated Session, this contains information about who on
    /// your staff is impersonating the user.
    pub impersonator: Option<AccessTokenImpersonator>,
}

/// Information in an Access Token about the current Session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenSession {
    /// The Session ID.
    pub id: String,
}

/// Information in an Access Token about the Organization the User is logged
/// into.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenOrganization {
    /// The Organization's ID.
    pub id: String,
    /// The Organization's display name.
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Information in an Access Token about the logged-in User.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenUser {
    /// The User's ID.
    pub id: String,
    /// The User's email.
    pub email: String,
    /// The User's full name.
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    /// A URL of the User's profile picture.
    #[serde(rename = "profilePictureUrl")]
    pub profile_picture_url: Option<String>,
}

/// Information in an Access Token about who is impersonating the User.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenImpersonator {
    /// The email address of the individual on your staff impersonating the User.
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
