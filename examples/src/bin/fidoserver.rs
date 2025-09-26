use std::error::Error as StdError;
use std::fs::File;
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::env;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use rustls_pemfile::certs;
use rustls_fido::enums::{FidoAuthenticatorAttachment, FidoPolicy};
use rustls_fido::server::FidoServer;
use rustls::server::WebPkiClientVerifier;

fn load_ca_certs(ca_cert_path: &str) -> RootCertStore {
    let mut reader = BufReader::new(File::open(ca_cert_path).expect("cannot open CA file"));
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
    stream.set_nonblocking(false)?;
    let conn = ServerConnection::new(config)?;
    let mut tls = StreamOwned::new(conn, stream);

    // Complete TLS handshake
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }

    tls.write_all(b"Hello from the server")?;
    tls.flush()?;

    // Clean shutdown
    tls.conn.send_close_notify();
    let _ = tls.conn.complete_io(&mut tls.sock);

    Ok(())
}

fn main() -> Result<(), Box<dyn StdError>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    // Read environment variables
    let ca_cert_path = env::var("CA_CERT_PATH").unwrap_or_else(|_| "./tls-certs/ca.cert.pem".to_string());
    let server_cert_path = env::var("SERVER_CERT_PATH").unwrap_or_else(|_| "./tls-certs/server.cert.pem".to_string());
    let server_key_path = env::var("SERVER_KEY_PATH").unwrap_or_else(|_| "./tls-certs/server.key.pem".to_string());
    let server_address = env::var("SERVER_ADDRESS").unwrap_or_else(|_| "[::]:4443".to_string());
    let fido_rp_id = env::var("FIDO_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let fido_rp_name = env::var("FIDO_RP_NAME").unwrap_or_else(|_| "localhost".to_string());
    let fido_user_verification = env::var("FIDO_USER_VERIFICATION").unwrap_or_else(|_| "preferred".to_string());
    let fido_authenticator_attachment = env::var("FIDO_AUTHENTICATOR_ATTACHMENT").unwrap_or_else(|_| "CrossPlatform".to_string());
    let fido_timeout = env::var("FIDO_TIMEOUT").unwrap_or_else(|_| "60000".to_string()).parse::<u32>().unwrap();
    let fido_ticket = env::var("FIDO_TICKET").unwrap_or_else(|_| "4,3,2,1".to_string());
    let fido_mandatory = env::var("FIDO_DEBUG").unwrap_or_else(|_| "true".to_string()).parse::<bool>().unwrap();
    let fido_db_path = env::var("FIDO_DB_PATH").unwrap_or_else(|_| "./fido.db3".to_string());

    // Parse FIDO ticket
    let ticket: Vec<u8> = fido_ticket.split(',').map(|s| s.trim().parse().unwrap()).collect();

    // Parse FIDO user verification policy
    let user_verification = match fido_user_verification.to_lowercase().as_str() {
        "required" => FidoPolicy::Required,
        "preferred" => FidoPolicy::Preferred,
        _ => FidoPolicy::Discouraged,
    };

    // Parse FIDO authenticator attachment
    let attachment = match fido_authenticator_attachment.to_lowercase().as_str() {
        "platform" => FidoAuthenticatorAttachment::Platform,
        _ => FidoAuthenticatorAttachment::CrossPlatform,
    };

    // Load server certificate and key
    let certs = CertificateDer::pem_file_iter(server_cert_path)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(server_key_path).unwrap();

    // Load CA certificates
    let ca_store = load_ca_certs(&ca_cert_path);
    let verifier = WebPkiClientVerifier::builder(ca_store.into())
        .allow_unauthenticated()
        .build()
        .expect("failed to build client verifier");

    // Initialize FIDO server
    let fido_config = FidoServer::new(
        fido_rp_id,
        fido_rp_name,
        user_verification,
        FidoPolicy::Required,
        attachment,
        fido_timeout,
        ticket,
        fido_mandatory,
        &fido_db_path,
    );

    // Configure TLS server
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_fido(fido_config)
        .with_single_cert(certs, private_key)?;

    // Start server
    let listener = TcpListener::bind(server_address.clone())?;
    let config = Arc::new(config);
    println!("Server listening on {}", server_address);

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
