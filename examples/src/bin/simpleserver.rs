//! This is the simplest possible server using rustls that does something useful:
//! it accepts the default configuration, loads a server certificate and private key,
//! and then accepts a single client connection.
//!
//! Usage: cargo r --bin simpleserver <path/to/cert.pem> <path/to/privatekey.pem>
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::error::Error as StdError;
use std::fs::File;
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use rustls_pemfile::certs;
use rustls::fido::enums::{FidoAuthenticatorAttachment, FidoPolicy};
use rustls::fido::state::FidoServer;
use rustls::server::WebPkiClientVerifier;

fn load_ca_certs() -> RootCertStore {
    let mut reader = BufReader::new(File::open("/home/triton/Development/rustls/target/debug/tls-certs/ca.cert.pem").expect("cannot open CA file"));
    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut store = RootCertStore::empty();
    for cert in certs {
        store.add(cert).unwrap();
    }
    store
}


fn handle_client(stream: TcpStream, config: Arc<ServerConfig>) -> Result<(), Box<dyn std::error::Error>> {
    stream.set_nonblocking(false)?; // Optional: force blocking mode

    let conn = ServerConnection::new(config)?;
    let mut tls = StreamOwned::new(conn, stream);

    // Complete TLS handshake
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }

    // Example: send a message
    tls.write_all(b"Hello from the server")?;
    tls.flush()?;

    // Clean shutdown
    tls.conn.send_close_notify();
    let _ = tls.conn.complete_io(&mut tls.sock);

    Ok(())
}

fn main() -> Result<(), Box<dyn StdError>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let cert_file = "/home/triton/Development/rustls/target/debug/tls-certs/server.cert.pem";
    let private_key_file = "/home/triton/Development/rustls/target/debug/tls-certs/server.key.pem";

    let certs = CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();

    // In your main():
    let ca_store = load_ca_certs();
    let verifier = WebPkiClientVerifier::builder(ca_store.into()).build().unwrap();

    let fido_config = FidoServer::new(
        "localhost".to_string(),
        "localhost".to_string(),
        FidoPolicy::Preferred,
        FidoPolicy::Required,
        FidoAuthenticatorAttachment::CrossPlatform,
        60000,
        vec![4, 3, 2, 1]
    );

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_fido(fido_config)
        .with_single_cert(certs, private_key)?;

    let listener = TcpListener::bind("[::]:4443")?;
    let config = Arc::new(config);

    println!("Server listening on port 4443");

    for stream_result in listener.incoming() {
        match stream_result {
            Ok(stream) => {
                if let Err(e) = handle_client(stream, Arc::clone(&config)) {
                    eprintln!("Error handling client: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    Ok(())
}
