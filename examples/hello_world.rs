// //! Hello World example for tesseral-axum
// //!
// //! This example demonstrates a simple Axum web server that responds with "Hello, World!"
// //! to HTTP requests.
//
// use axum::{middleware, routing::get, Extension, Router};
// use std::net::SocketAddr;
// use tokio::net::TcpListener;
// use tesseral_axum::Auth;
//
// #[tokio::main]
// async fn main() {
//     // Initialize tracing for better debugging
//     tracing_subscriber::fmt::init();
//
//     // Build our application with a single route
//     let app = Router::new()
//         .route("/", get(handler))
//         .layer(middleware::from_fn(tesseral_axum::require_auth));
//
//     // Run the server
//     let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
//     println!("Listening on {}", addr);
//
//     let listener = TcpListener::bind(addr).await.unwrap();
//     axum::serve(listener, app).await.unwrap();
// }
//
// // Our handler function
// async fn handler(Extension(auth): Extension<Auth>) -> String {
//     auth.credentials().to_owned()
// }

#[tokio::main]
async fn main() {
    let client = tesseral_axum::backend_api::Client::new();
    dbg!(client.authenticate_api_key(tesseral_axum::backend_api::AuthenticateApiKeyRequest {
        secret_token: Some("axum_test_026i7umqfrdryokddawwwf8n3dehnz60bznczbmi6wdznfvjlqsp0x3".to_owned()),
    }).await.unwrap());
}