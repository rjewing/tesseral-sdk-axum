use crate::access_token_claims::AccessTokenClaims;
use crate::backend_api::AuthenticateApiKeyResponse;

pub struct Auth {
    data: AuthData,
}

impl Auth {
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

    pub fn access_token_claims(&self) -> Option<&AccessTokenClaims> {
        match self.data {
            AuthData::AccessToken(ref data) => Some(&data.access_token_claims),
            AuthData::ApiKey(_) => None,
        }
    }

    pub fn credentials(&self) -> &str {
        match self.data {
            AuthData::AccessToken(ref data) => &data.access_token,
            AuthData::ApiKey(ref data) => &data.api_key_secret_token,
        }
    }

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

enum AuthData {
    AccessToken(AccessTokenData),
    ApiKey(ApiKeyData),
}

struct AccessTokenData {
    access_token: String,
    access_token_claims: AccessTokenClaims,
}

struct ApiKeyData {
    api_key_secret_token: String,
    authenticate_api_key_response: AuthenticateApiKeyResponse,
}
