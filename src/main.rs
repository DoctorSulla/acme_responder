use acme_lib::create_p384_key;
use acme_lib::persist::FilePersist;
use acme_lib::{Directory, DirectoryUrl, Error};
use std::thread;

use axum::{routing::get, Router};

use axum::{body::Bytes, extract::Path, http::StatusCode, response::Response};

use http_body_util::Full;

use std::fs;
use std::fs::File;
use std::io::prelude::*;

static CHALLENGE_DIR: &str = "./acme/challenges/";

#[tokio::main]
async fn main() {
    start_server().await
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

fn populate_challenge(proof: String) -> std::io::Result<()> {
    let path = format!("{}{}", CHALLENGE_DIR, proof);
    let mut file = File::create(path)?;
    file.write_all(proof.as_bytes())?;
    Ok(())
}

fn request_cert() -> Result<(), Error> {
    // Use DirectoryUrl::LetsEncrypStaging for dev/testing.
    let url = DirectoryUrl::LetsEncryptStaging;

    // Save/load keys and certificates to current dir.
    let persist = FilePersist::new(&CHALLENGE_DIR);

    // Create a directory entrypoint.
    let dir = Directory::from_url(persist, url)?;

    // Reads the private account key from persistence, or
    // creates a new one before accessing the API to establish
    // that it's there.
    let acc = dir.account("matthew.halliday@gmail.com")?;

    // Order a new TLS certificate for a domain.
    let mut ord_new = acc.new_order("christmaslist.xyz", &[])?;

    // If the ownership of the domain(s) have already been
    // authorized in a previous order, you might be able to
    // skip validation. The ACME API provider decides.
    let ord_csr = loop {
        // are we done?
        if let Some(ord_csr) = ord_new.confirm_validations() {
            break ord_csr;
        }

        // Get the possible authorizations (for a single domain
        // this will only be one element).
        let auths = ord_new.authorizations()?;

        // For HTTP, the challenge is a text file that needs to
        // be placed in your web server's root:
        //
        // /var/www/.well-known/acme-challenge/<token>
        //
        // The important thing is that it's accessible over the
        // web for the domain(s) you are trying to get a
        // certificate for:
        //
        // http://mydomain.io/.well-known/acme-challenge/<token>
        let chall = auths[0].http_challenge();

        // The token is the filename.
        let token = chall.http_token();
        let path = format!(".well-known/acme-challenge/{}", token);

        // The proof is the contents of the file
        let proof = chall.http_proof();

        // Here you must do "something" to place
        // the file/contents in the correct place.
        // update_my_web_server(&path, &proof);

        // After the file is accessible from the web, the calls
        // this to tell the ACME API to start checking the
        // existence of the proof.
        //
        // The order at ACME will change status to either
        // confirm ownership of the domain, or fail due to the
        // not finding the proof. To see the change, we poll
        // the API with 5000 milliseconds wait between.
        chall.validate(5000)?;

        // Update the state against the ACME API.
        ord_new.refresh()?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience, you
    // can provide your own keypair instead if you want.
    let pkey_pri = create_p384_key();

    // Submit the CSR. This causes the ACME provider to enter a
    // state of "processing" that must be polled until the
    // certificate is either issued or rejected. Again we poll
    // for the status change.
    let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000)?;

    // Now download the certificate. Also stores the cert in
    // the persistence.
    let cert = ord_cert.download_and_save_cert()?;

    Ok(())
}
