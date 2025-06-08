use axum::{body::Body, extract::Request, response::Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::Mutex;
use tower::{Layer, Service};

// Re-export only the necessary items
pub use crate::auth::Auth;
pub use crate::authenticator::{AuthenticateError, Authenticator};

// Keep modules private except for the re-exported items
mod auth;
mod authenticator;
mod credentials;

/// Creates a middleware layer that requires authentication for all requests.
///
/// This function takes an Authenticator instance and returns a middleware layer
/// that can be added to an Axum Router. The middleware will authenticate all
/// incoming requests and reject unauthorized requests with a 401 status code.
///
/// # Example
///
/// ```
/// let authenticator = Authenticator::new("publishable_key")
///     .with_api_keys_enabled(true)
///     .with_backend_api_key("backend_api_key");
///
/// let app = Router::new()
///     .route("/", get(handler))
///     .layer(require_auth(authenticator));
/// ```
pub fn require_auth(authenticator: Authenticator) -> RequireAuthLayer {
    authenticator.validate_backend_api_key();
    RequireAuthLayer {
        authenticator: Arc::new(Mutex::new(authenticator)),
    }
}

/// A middleware layer that requires authentication for all requests.
///
/// This layer is created by the [`require_auth`] function and can be added to an Axum Router
/// to authenticate all incoming requests.
#[derive(Clone)]
pub struct RequireAuthLayer {
    authenticator: Arc<Mutex<Authenticator>>,
}

impl<S> Layer<S> for RequireAuthLayer {
    type Service = RequireAuth<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireAuth {
            authenticator: self.authenticator.clone(),
            inner,
        }
    }
}

/// A middleware service that requires authentication for all requests.
///
/// This service is created by the [`require_auth`] function (via
/// [`RequireAuthLayer`]) and is responsible for authenticating requests and
/// adding the [`Auth`] object to request extensions. 
#[derive(Clone)]
pub struct RequireAuth<S> {
    authenticator: Arc<Mutex<Authenticator>>,
    inner: S,
}

impl<S> Service<Request<Body>> for RequireAuth<S>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let authenticator = self.authenticator.clone();
        let request_headers = request.headers().clone();
        // Clone the inner service to avoid lifetime issues
        let mut inner = self.inner.clone();

        Box::pin(async move {
            match authenticator
                .lock()
                .await
                .authenticate_request(&request_headers)
                .await
            {
                Ok(auth) => {
                    // Add the auth object to request extensions
                    request.extensions_mut().insert(auth);
                    inner.call(request).await
                }
                Err(AuthenticateError::Unauthorized) => {
                    Ok(Response::builder().status(401).body(Body::empty()).unwrap())
                }
                Err(AuthenticateError::Other(e)) => Ok(Response::builder()
                    .status(500)
                    .body(Body::from(format!(
                        "Internal server error in tesseral_axum: {:#}",
                        e
                    )))
                    .unwrap()),
            }
        })
    }
}
