use axum::{routing::get, Router};

use axum::{body::Bytes, extract::Path, http::StatusCode, response::Response};

use http_body_util::Full;

use std::fs;
// use std::fs::File;
// use std::io::prelude::*;

static CHALLENGE_DIR: &str = "/app/acme/challenges/";

#[tokio::main]
async fn main() {
    start_server().await;
}

async fn start_server() {
    let app = Router::new().route(
        "/.well-known/acme-challenge/:token",
        get(challenge_response),
    );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

pub async fn challenge_response(Path(file_name): Path<String>) -> Response<Full<Bytes>> {
    let file_path = format!("{}{}", CHALLENGE_DIR, file_name);
    let mime_type = "application/octet-stream";

    let mut status_code = StatusCode::OK;
    let body: Vec<u8>;
    match std::path::Path::new(&file_path).exists() {
        true => body = fs::read(&file_path).unwrap(),
        false => {
            println!("Path not found: {}", file_path);
            body = b"Challenge not present.".to_vec();
            status_code = StatusCode::NOT_FOUND;
        }
    }
    Response::builder()
        .status(status_code)
        .header("Content-Type", mime_type)
        .body(Full::from(body))
        .unwrap()
}

// fn populate_challenge(proof: String) -> std::io::Result<()> {
//     let path = format!("{}{}", CHALLENGE_DIR, proof);
//     let mut file = File::create(path)?;
//     file.write_all(proof.as_bytes())?;
//     Ok(())
// }
