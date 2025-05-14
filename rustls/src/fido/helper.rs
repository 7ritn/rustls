use std::prelude::rust_2015::Vec;
use std::prelude::rust_2024::String;
use std::vec;
use pki_types::{CertificateDer, UnixTime};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
use crate::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use crate::verify::{ClientCertVerified, ClientCertVerifier, HandshakeSignatureValid};

pub(crate) fn validate_server_name(server_name: &str, server_cert_der: Option<&CertificateDer<'_>>, rp_id: Option<&String>) -> Option<bool> {
    if let Some(rp_id) = rp_id {
        if server_name == rp_id { return Some(true) }
    }

    let server_cert = X509Certificate::from_der(server_cert_der?).ok()?.1;
    Some(server_cert
        .subject_alternative_name()
        .ok()
        .flatten()?
        .value
        .general_names
        .iter()
        .any(|gn| matches!(gn, GeneralName::DNSName(dns) if *dns == server_name)))
}

#[derive(Debug)]
/// FIDO client auth verifier.
pub struct FidoClientAuth;

impl ClientCertVerifier for FidoClientAuth {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool { false }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Err(Error::General("Not used for FIDO".into()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("Not used for FIDO".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("Not used for FIDO".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![]
    }
}