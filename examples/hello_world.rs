// //! Hello World example for tesseral-axum
// //!
// //! This example demonstrates a simple Axum web server that responds with "Hello, World!"
// //! to HTTP requests.
//
use axum::{middleware, routing::get, Extension, Router};
use std::net::SocketAddr;
use tesseral_axum::auth::Auth;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Initialize tracing for better debugging
    tracing_subscriber::fmt::init();

    let require_auth_layer = tesseral_axum::auth_layer::RequireAuthBuilder::new(
        tesseral_axum::access_token_authenticator::AuthenticatorBuilder::new(
            "publishable_key_en43cawcravxk7t2murwiz192".to_owned(),
        )
        .build(),
    )
    .with_backend_api_client(
        tesseral_axum::backend_api::ClientBuilder::new()
            .backend_api_key("asdf")
            .build(),
    )
    .build();

    // Build our application with a single route
    let app = Router::new()
        .route("/", get(handler))
        .layer(require_auth_layer);

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Our handler function
async fn handler(Extension(auth): Extension<Auth>) -> String {
    dbg!(auth.organization_id());
    dbg!(auth.credentials());
    dbg!(auth.access_token_claims());
    dbg!(auth.has_permission("foo.bar.baz"));
    "Hello, World!".to_owned()
}
