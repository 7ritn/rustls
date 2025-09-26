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

macro_rules! env_var_or_default {
    ($name:expr, $default:expr) => {
        std::env::var($name).unwrap_or_else(|_| $default.to_string())
    };
}

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
    let ca_cert_path = env_var_or_default!("CA_CERT_PATH", "./tls-certs/ca.cert.pem");
    let server_cert_path = env_var_or_default!("SERVER_CERT_PATH", "./tls-certs/server.cert.pem");
    let server_key_path = env_var_or_default!("SERVER_KEY_PATH", "./tls-certs/server.key.pem");
    let server_address = env_var_or_default!("SERVER_ADDRESS", "[::]:4443");
    let fido_rp_id = env_var_or_default!("FIDO_RP_ID", "localhost");
    let fido_rp_name = env_var_or_default!("FIDO_RP_NAME", "localhost");
    let fido_user_verification = env_var_or_default!("FIDO_USER_VERIFICATION", "preferred");
    let fido_authenticator_attachment = env_var_or_default!("FIDO_AUTHENTICATOR_ATTACHMENT", "CrossPlatform");
    let fido_ticket = env_var_or_default!("FIDO_TICKET", "4,3,2,1");
    let fido_timeout = env_var_or_default!("FIDO_TIMEOUT", "60000").parse::<u32>().unwrap();
    let fido_mandatory = env_var_or_default!("FIDO_DEBUG", "true").parse::<bool>().unwrap();
    let fido_db_path = env_var_or_default!("FIDO_DB_PATH", "./fido.db3");

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
