use std::fs::File;
use std::io::{stdout, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use log::info;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConnection, RootCertStore, Stream};
use rustls_pemfile::certs;
use rustls_fido::enums::FidoMode;
use rustls_fido::client::FidoClient;
use std::env;

macro_rules! env_var_or_default {
    ($name:expr, $default:expr) => {
        std::env::var($name).unwrap_or_else(|_| $default.to_string())
    };
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    // Read environment variables
    let ca_cert_path = env_var_or_default!("CA_CERT_PATH", "./tls-certs/ca.cert.pem");
    let client_cert_path = env_var_or_default!("CLIENT_CERT_PATH", "./tls-certs/client.cert.pem");
    let client_key_path = env_var_or_default!("CLIENT_KEY_PATH", "./tls-certs/client.key.pem");
    let address = env_var_or_default!("SERVER_ADDRESS", "localhost:4443");
    let servername = env_var_or_default!("SERVER_NAME", "localhost");
    let mut fido_mode = env_var_or_default!("FIDO_MODE", "registration");
    let fido_username = env_var_or_default!("FIDO_USER_NAME", "user");
    let fido_displayname = env_var_or_default!("FIDO_DISPLAY_NAME", "User");
    let fido_pin = env_var_or_default!("FIDO_DEVICE_PIN", "1234");
    let fido_ticket = env_var_or_default!("FIDO_TICKET", "4,3,2,1");

    // Read command line FIDO mode
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--authenticate".to_string()) {
        fido_mode = "authentication".to_string();
    } else if args.contains(&"--register".to_string()) {
        fido_mode = "registration".to_string();
    }

    // Parse FIDO ticket
    let ticket: Vec<u8> = fido_ticket.split(',').map(|s| s.trim().parse().unwrap()).collect();

    // Parse FIDO mode
    let mode = match fido_mode.to_lowercase().as_str() {
        "registration" => FidoMode::Registration,
        _ => FidoMode::Authentication,
    };

    // Load CA certificate
    let cert_file = File::open(&ca_cert_path).expect("cannot open CA cert file");
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

    // Load client certificate and key
    let client_cert = CertificateDer::pem_file_iter(&client_cert_path)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let client_key = PrivateKeyDer::from_pem_file(&client_key_path).unwrap();

    // Initialize FIDO client
    let fido = FidoClient::new(
        mode,
        Some(fido_username),
        Some(fido_displayname),
        Some(ticket),
        fido_pin,
    );

    // Configure TLS
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_fido(client_cert, client_key, fido)
        .unwrap();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    // Handle pre registration handshake
    if mode == FidoMode::Registration {
        let server_name = servername.clone().try_into().unwrap();
        let mut conn = ClientConnection::new(Arc::new(config.clone()), server_name).unwrap();
        let mut sock = TcpStream::connect(&address).unwrap();
        let mut tls = Stream::new(&mut conn, &mut sock);
        tls.flush().unwrap();
        info!("fido: first handshake succeeded!");
        sleep(Duration::from_secs(1));
    }

    // Main connection
    sleep(Duration::from_secs(1));

    let server_name = servername.try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(address).unwrap();
    let mut tls = Stream::new(&mut conn, &mut sock);

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
