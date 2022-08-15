#![deny(warnings)]

use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use hyper::{server::conn::Http, service::service_fn};
use hyper::{Body, Error, Response};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

    // For the most basic of state, we just share a counter, that increments
    // with each request, and we send its value back in the response.
    let counter = Arc::new(AtomicUsize::new(0));

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);
    loop {
        let (stream, _) = listener.accept().await?;

        // Each connection could send multiple requests, so
        // the `Service` needs a clone to handle later requests.
        let counter = counter.clone();

        // This is the `Service` that will handle the connection.
        // `service_fn` is a helper to convert a function that
        // returns a Response into a `Service`.
        let service = service_fn(move |_req| {
            // Get the current count, and also increment by 1, in a single
            // atomic operation.
            let count = counter.fetch_add(1, Ordering::AcqRel);
            async move { Ok::<_, Error>(Response::new(Body::from(format!("Request #{}", count)))) }
        });

        if let Err(err) = Http::new().serve_connection(stream, service).await {
            println!("Error serving connection: {:?}", err);
        }
    }
}
