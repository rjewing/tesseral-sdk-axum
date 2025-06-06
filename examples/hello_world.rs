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

use aws_lc_rs::signature::UnparsedPublicKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine as _};

#[tokio::main]
async fn main() {
    // let client = tesseral_axum::backend_api::Client::new();
    // dbg!(client.authenticate_api_key(tesseral_axum::backend_api::AuthenticateApiKeyRequest {
    //     secret_token: Some("axum_test_026i7umqfrdryokddawwwf8n3dehnz60bznczbmi6wdznfvjlqsp0x3".to_owned()),
    // }).await.unwrap());

    let jwt = "eyJraWQiOiJzZXNzaW9uX3NpZ25pbmdfa2V5X2MzODR1Y2Exc2J1czR4cGtpN2oya2dhcXQiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Byb2plY3QtNTR2d2YwY2xoaDBjYXFlMjBldWp4Z3BlcS50ZXNzZXJhbC5hcHAiLCJzdWIiOiJ1c2VyXzk3dXJxb2lwNXE3a2VmODd3cG90dnp6eHoiLCJhdWQiOiJodHRwczovL3Byb2plY3QtNTR2d2YwY2xoaDBjYXFlMjBldWp4Z3BlcS50ZXNzZXJhbC5hcHAiLCJleHAiOjE3NDExOTU0NjgsIm5iZiI6MTc0MTE5NTE2OCwiaWF0IjoxNzQxMTk1MTY4LCJvcmdhbml6YXRpb24iOnsiaWQiOiJvcmdfNzkwOG16MnVsOXVzZGh5MGdkZDN0aWVhbiIsImRpc3BsYXlOYW1lIjoicHJvamVjdF81NHZ3ZjBjbGhoMGNhcWUyMGV1anhncGVxIEJhY2tpbmcgT3JnYW5pemF0aW9uIn0sInVzZXIiOnsiaWQiOiJ1c2VyXzk3dXJxb2lwNXE3a2VmODd3cG90dnp6eHoiLCJlbWFpbCI6InJvb3RAYXBwLnRlc3NlcmFsLmV4YW1wbGUuY29tIn0sInNlc3Npb24iOnsiaWQiOiJzZXNzaW9uXzAzZGkwbmtqbG1yNmh3cWQ0ejA4OTlvMnIifX0.utyHAIubtDLJAY9b3Ec_rMBOX9ejOA21sh2fpVHm34S3ywBpiM7Pe0SvsDWhZQh_GG7Il1-H3Eju7dBIDgvEEA";

    // Split the JWT token into its three parts (header, payload, signature)
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        panic!("Invalid JWT token format");
    }

    // Create the signed part by concatenating the header and payload with a dot
    let jwt_signed = format!("{}.{}", parts[0], parts[1]).into_bytes();

    let x_base64 = "qCByog0iFwVfDF-fkoPhKNW8JjNLGQJMk_atUGGbvoM";
    let y_base64 = "vFZaL73AXgLcPxRS_yc9fsJTTiy-f-OVRD2IexKN17g";

    // Parse x and y from base64
    let x_bytes = BASE64.decode(x_base64).expect("Failed to decode x_base64");
    let y_bytes = BASE64.decode(y_base64).expect("Failed to decode y_base64");

    // Concatenate x and y bytes into a single vec
    let mut public_key_bytes = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    public_key_bytes.push(0x04);
    public_key_bytes.extend_from_slice(&x_bytes);
    public_key_bytes.extend_from_slice(&y_bytes);

    let public_key = UnparsedPublicKey::new(&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED, public_key_bytes);

    // Decode the signature part
    let signature_bytes = BASE64.decode(parts[2]).expect("Failed to decode signature");

    dbg!(&signature_bytes);

    // Now we have:
    // - jwt_signed: the bytes that need to be signed (header.payload)
    // - public_key: the public key to verify the signature
    // - signature_bytes: the signature to verify

    // In a real application, you would verify the signature like this:
    public_key.verify(&jwt_signed, &signature_bytes).expect("Signature verification failed");

    println!("JWT parsed successfully. Bytes to be signed extracted.");
}
