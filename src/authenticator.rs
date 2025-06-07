use axum::body::Body;
use axum::extract::Request;
use thiserror::Error;
use crate::auth::Auth;

pub struct Authenticator {
    publishable_key: String,
}

impl Authenticator {
    pub fn new(publishable_key: String) -> Self {
        Self { publishable_key }
    }

    pub(crate) fn authenticate_request(&mut self, request: Request<Body>) -> Result<Auth, AuthenticateError> {

    }
}

#[derive(Debug, Error)]
pub enum AuthenticateError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    Other(#[from] anyhow::Error),
}
