use std::future::Future;
use axum::extract::Request;
use axum::middleware::{FromFnLayer, Next};
use axum::response::Response;
use tower::{Layer, Service};


pub struct Authenticator {}

impl Authenticator {
    pub fn new() -> Self {
        Self {}
    }
}
