use crate::authenticator::{AuthenticateError, Authenticator};
use axum::{body::Body, extract::Request, response::Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::Mutex;
use tower::{Layer, Service};

mod auth;
pub mod authenticator;

pub fn require_auth(authenticator: Authenticator) -> RequireAuthLayer {
    RequireAuthLayer {
        authenticator: Arc::new(Mutex::new(authenticator)),
    }
}

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

#[derive(Clone)]
pub struct RequireAuth<S> {
    authenticator: Arc<Mutex<Authenticator>>,
    inner: S,
}

impl<S> Service<Request<Body>> for RequireAuth<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
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
        let request = Arc::new(request);

        Box::pin(async move {
            match authenticator.lock().await.authenticate_request(&request_headers).await {
                Ok(auth) => {
                    return self.inner.call(request).await;
                }
                Err(AuthenticateError::Unauthorized) => {
                    return Ok(Response::builder().status(401).body(Body::empty()).unwrap());
                }
                Err(AuthenticateError::Other(e)) =>  {
                    return Ok(Response::builder().status(500).body(Body::from(e.to_string())).unwrap());
                },
            }
        })
    }
}
