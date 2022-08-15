#![deny(warnings)]
#![warn(rust_2018_idioms)]

use std::net::SocketAddr;

use futures_util::future::join;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use tokio::net::TcpListener;

static INDEX1: &[u8] = b"The 1st service!";
static INDEX2: &[u8] = b"The 2nd service!";

async fn index1(_: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    Ok(Response::new(Body::from(INDEX1)))
}

async fn index2(_: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    Ok(Response::new(Body::from(INDEX2)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pretty_env_logger::init();

    let addr1: SocketAddr = ([127, 0, 0, 1], 1337).into();
    let addr2: SocketAddr = ([127, 0, 0, 1], 1338).into();

    let srv1 = async move {
        let listener = TcpListener::bind(addr1).await.unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();

            tokio::task::spawn(async move {
                if let Err(err) = Http::new()
                    .serve_connection(stream, service_fn(index1))
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
    };

    let srv2 = async move {
        let listener = TcpListener::bind(addr2).await.unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();

            tokio::task::spawn(async move {
                if let Err(err) = Http::new()
                    .serve_connection(stream, service_fn(index2))
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
    };

    println!("Listening on http://{} and http://{}", addr1, addr2);

    let _ret = join(srv1, srv2).await;

    Ok(())
}
