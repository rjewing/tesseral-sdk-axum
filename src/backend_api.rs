use serde::{Deserialize, Serialize};


pub async fn authenticate_api_key(
    client: &reqwest::Client,
    backend_api_hostname: &str,
    backend_api_key: &str,
    req: &AuthenticateApiKeyRequest,
) -> Result<AuthenticateApiKeyResponse, reqwest::Error> {
}
