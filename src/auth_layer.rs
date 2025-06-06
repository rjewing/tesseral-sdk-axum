use std::future::Future;
use std::task::Poll;
use std::pin::Pin;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{from_fn, FromFnLayer};
use axum::response::Response;
use axum::body::Body;
use tower::{Layer, Service};
use crate::access_token_authenticator::Authenticator;
use crate::auth::Auth;
use crate::backend_api;

/// A marker struct to indicate that API key authentication was successful.
#[derive(Clone, Debug)]
pub struct ApiKeyAuthenticated(pub bool);

pub struct RequireAuthBuilder {
    access_token_authenticator: Authenticator,
    api_keys_enabled: bool,
    backend_api_client: backend_api::Client,
}

impl RequireAuthBuilder {
    /// Creates a new `RequireAuthBuilder` with the given authenticator.
    pub fn new(access_token_authenticator: Authenticator) -> Self {
        Self {
            access_token_authenticator,
            api_keys_enabled: false,
            backend_api_client: backend_api::Client::new(),
        }
    }

    /// Enables or disables API key authentication.
    pub fn with_api_keys_enabled(mut self, enabled: bool) -> Self {
        self.api_keys_enabled = enabled;
        self
    }

    /// Sets the backend API client to use for API key authentication.
    pub fn with_backend_api_client(mut self, client: backend_api::Client) -> Self {
        self.backend_api_client = client;
        self
    }

    /// Builds a `RequireAuthLayer` that can be used with Axum's middleware system.
    pub fn build(self) -> RequireAuthLayer {
        RequireAuthLayer {
            access_token_authenticator: self.access_token_authenticator,
            api_keys_enabled: self.api_keys_enabled,
            backend_api_client: self.backend_api_client,
        }
    }
}

/// A layer that requires authentication for all requests.
pub struct RequireAuthLayer {
    access_token_authenticator: Authenticator,
    api_keys_enabled: bool,
    backend_api_client: backend_api::Client,
}

impl<S> Layer<S> for RequireAuthLayer {
    type Service = RequireAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireAuthService {
            inner,
            access_token_authenticator: self.access_token_authenticator.clone(),
            api_keys_enabled: self.api_keys_enabled,
            backend_api_client: self.backend_api_client.clone(),
        }
    }
}

/// A service that requires authentication for all requests.
pub struct RequireAuthService<S> {
    inner: S,
    access_token_authenticator: Authenticator,
    api_keys_enabled: bool,
    backend_api_client: backend_api::Client,
}

impl<S> Service<Request> for RequireAuthService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        // Clone what we need to avoid Send issues
        let authenticator = self.access_token_authenticator.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Try to get the project_id, return 500 if it fails
            let project_id = match authenticator.project_id().await {
                Ok(id) => id,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap())
                }
            };

            // Try to extract credentials, return 401 if none found
            let credentials = match extract_credentials(&project_id, &request) {
                Some(creds) => creds,
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::empty())
                        .unwrap())
                }
            };

            inner.call(request).await
        })
    }
}

fn extract_credentials<'a>(project_id: &str, request: &'a Request) -> Option<&'a str> {
    if let Some(authorization) = request.headers().get("Authorization") {
        return authorization.to_str().ok()?.strip_prefix("Bearer ");
    }

    let cookie_prefix = format!("tesseral_{}_access_token=", project_id);
    let cookies = request.headers().get_all("Cookie");
    for cookie in cookies {
        if let Ok(cookie) = cookie.to_str() {
            if cookie.starts_with(&cookie_prefix) {
                return Some(&cookie[cookie_prefix.len()..]);
            }
        }
    }

    None
}
