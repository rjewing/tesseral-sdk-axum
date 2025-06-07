use axum::{routing::get, Router};
use std::net::SocketAddr;
use tesseral_axum::authenticator::Authenticator;
use tesseral_axum::require_auth;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let authenticator = Authenticator::new("publishable_key_en43cawcravxk7t2murwiz192".to_string());

    // Build our application with a single route
    let app = Router::new()
        .route("/", get(handler))
        .layer(require_auth(authenticator));

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handler() -> String {
    "Hello, World!".to_owned()
}
