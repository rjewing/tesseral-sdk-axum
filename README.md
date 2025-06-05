# Tesseral Axum SDK

A Rust library that provides integration between Tesseral and the [Axum](https://github.com/tokio-rs/axum) web framework.

## Features

This is a minimal setup that will be expanded with more functionality in the future.

- Re-exports Axum for convenience
- Provides a simple API for integrating Tesseral with Axum

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tesseral-axum = "0.1.0"
```

## Example

A simple hello world example is included in the `examples` directory:

```rust
use axum::{
    routing::get,
    Router,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // Initialize tracing for better debugging
    tracing_subscriber::fmt::init();

    // Build our application with a single route
    let app = Router::new()
        .route("/", get(handler));

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);
    
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Our handler function
async fn handler() -> &'static str {
    "Hello, World!"
}
```

To run the example:

```bash
cargo run --example hello_world
```

Then visit [http://localhost:3000](http://localhost:3000) in your browser.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.