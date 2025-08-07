//! This is the simplest possible client using rustls that does something useful:
//! it accepts the default configuration, loads some root certs, and then connects
//! to rust-lang.org and issues a basic HTTP request.  The response is printed to stdout.
//!
//! It makes use of rustls::Stream to treat the underlying TLS connection as a basic
//! bi-directional stream -- the underlying IO is performed transparently.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::fs::File;
use std::io::{stdout, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use log::info;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConnection, RootCertStore, Stream};
use rustls_pemfile::certs;
use rustls_fido::enums::FidoMode;
use rustls_fido::client::FidoClient;
// This is the function you're missing

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let cert_file = File::open("/home/triton/Development/rustls/tls-certs/ca.cert.pem").expect("cannot open cert file");
    //let cert_file = File::open("/home/triton/Development/fidoSSL/test/certs/ca.crt").expect("cannot open cert file");
    let mut reader = BufReader::new(cert_file);

    // Parse the certificate(s)
    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Create a root store and add the certs
    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .expect("failed to add cert to root store");
    }

    let client_cert = CertificateDer::pem_file_iter("/home/triton/Development/rustls/tls-certs/client.cert.pem")
        .unwrap()
        .map(Result::unwrap) 
        .collect();
    let client_key = PrivateKeyDer::from_pem_file("/home/triton/Development/rustls/tls-certs/client.key.pem").unwrap();
        
    let ticket = vec![4,3,2,1];

    //let address = "127.0.0.1:12345";
    let address = "localhost:4443";

    //let servername = "demo.fido2.tls.edu";
    let servername = "localhost";

    let mode = FidoMode::Authentication;
    let fido = FidoClient::new(
        mode,
        Some("emily".to_string()),
        Some("emily".to_string()),
        Some(ticket),
        "1234".to_string()
    );

    let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
        .with_client_auth_fido(client_cert, client_key, fido)
        .unwrap();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    if mode == FidoMode::Registration {
        let server_name = servername.try_into().unwrap();
        let mut conn = ClientConnection::new(Arc::new(config.clone()), server_name).unwrap();
        let mut sock = TcpStream::connect(address).unwrap();
        let mut tls = Stream::new(&mut conn, &mut sock);
        tls.flush().unwrap();
        info!("fido: first handshake succeeded!");
        sleep(Duration::from_secs(1));
    }

    sleep(Duration::from_secs(1));

    let server_name = servername.try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(address).unwrap();
    let mut tls = Stream::new(&mut conn, &mut sock);

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
