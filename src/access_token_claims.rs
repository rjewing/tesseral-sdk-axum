use serde::{Deserialize, Serialize};

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
