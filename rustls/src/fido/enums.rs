use std::vec::Vec;

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::DiscoverableAuthentication;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MessageType {
    PreRegistrationIndication = 0x01,
    PreRegistrationRequest = 0x02,
    PreRegistrationResponse = 0x03,
    RegistrationIndication = 0x05,
    RegistrationRequest = 0x06,
    RegistrationResponse = 0x07,
    AuthenticationIndication = 0x0a,
    AuthenticationRequest = 0x0b,
    AuthenticationResponse = 0x0c
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
/// Mode of operation
pub enum FidoMode {
    /// Requires double handshake
    Registration = 1,
    /// Authentication
    Authentication = 2
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum FidoState {
    #[default]
    Initial,
    AuthInitial,
    AuthIndicationSent,
    AuthIndicationReceived,
    AuthRequestSent,
    AuthRequestReceived,
    AuthResponseSent,
    AuthResponseReceived,
    AuthSuccess,
    AuthFailure,
    RegInitial,
    PreRegIndicationSent,
    PreRegIndicationReceived,
    PreRegRequestSent,
    PreRegRequestReceived,
    PreRegResponseSent,
    PreRegResponseReceived,
    RegIndicationSent,
    RegIndicationReceived,
    RegRequestSent,
    RegRequestReceived,
    RegResponseSent,
    RegResponseReceived,
    RegSuccess,
    RegFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub(crate) enum FidoPublicKeyAlgorithms {
    #[allow(non_camel_case_types)]
    COSE_ES256 = 0,
    #[allow(non_camel_case_types)]
    COSE_ES384 = 1,
    #[allow(non_camel_case_types)]
    COSE_EDDSA = 2,
    #[allow(non_camel_case_types)]
    COSE_ECDH_ES256 = 3,
    #[allow(non_camel_case_types)]
    COSE_RS256 = 4,
    #[allow(non_camel_case_types)]
    COSE_RS1 = 5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
/// FidoAuthenticatorAttachment
pub enum FidoAuthenticatorAttachment {
    /// Platform
    Platform = 0,
    /// CrossPlatform
    CrossPlatform = 1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
/// FidoPolicy
pub enum FidoPolicy {
    /// Required
    Required = 0,
    /// Preferred
    Preferred = 1,
    /// Discouraged
    Discouraged = 2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub(crate) enum FidoAuthenticatorTransport {
    USB = 0,
    NFC = 1,
    BLE = 2,
    INTERNAL = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub(crate) enum FidoRegistrationAttestation {
    None = 0,
    Indirect = 1,
    Direct = 2,
    Enterprise = 3,
}

#[derive(Debug, Clone)]
pub(crate) enum FidoHandshakeState {
    SAS(DiscoverableAuthentication),
    UserId(Vec<u8>),
    EphemUserId(Vec<u8>)
}