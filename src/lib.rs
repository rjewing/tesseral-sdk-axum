use crate::authenticator::Authenticator;
use axum::{body::Body, extract::Request, response::Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

pub mod authenticator;
mod auth;

pub fn require_auth(authenticator: Authenticator) -> RequireAuthLayer {
    RequireAuthLayer {
        authenticator: Arc::new(authenticator),
    }
}

#[derive(Clone)]
pub struct RequireAuthLayer {
    authenticator: Arc<Authenticator>,
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
    authenticator: Arc<Authenticator>,
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
        let future = self.inner.call(request);
        Box::pin(async move {
            let response: Response = future.await?;
            Ok(response)
        })
    }
}
