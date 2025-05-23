use std::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use serde_cbor::ser::to_vec_packed;

use crate::{msgs::codec::{Codec, Reader}, InvalidMessage};

use super::enums::{FidoAuthenticatorAttachment, FidoAuthenticatorTransport, FidoPolicy, FidoPublicKeyAlgorithms, MessageType};

/// FidoPreRegistrationIndication
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoPreRegistrationIndication {
    /// message_type
    pub message_type: u8,
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoPreRegistrationRequest {
    pub message_type: u8,
    pub ephem_user_id: Vec<u8>,
    pub gcm_key: Vec<u8>
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoPreRegistrationResponse {
    pub message_type: u8,
    pub user_name: String,
    pub user_display_name: String,
    pub ticket: Vec<u8>
}

/// FidoRegistrationIndication
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoRegistrationIndication {
    /// message_type
    pub message_type: u8,
    /// ephem_user_id
    pub ephem_user_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoRegistrationRequest {
    pub message_type: u8,
    pub challenge: Vec<u8>,
    pub rp_id: String,
    pub rp_name: String,
    pub enc_user_name: Vec<u8>,
    pub enc_user_display_name: Vec<u8>,
    pub enc_user_id: Vec<u8>,
    pub pubkey_cred_params: Vec<FidoPublicKeyAlgorithms>,
    pub optionals: FidoRegistrationRequestOptionals
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct FidoRegistrationRequestOptionals {
    #[serde(rename = "1")]
    pub timeout: Option<u32>,
    #[serde(rename = "2")]
    pub enc_authenticator_selection: Option<Vec<u8>>,
    #[serde(rename = "3")]
    pub enc_excluded_credentials: Option<Vec<u8>>,
    #[serde(rename = "4")]
    pub enc_attestation: Option<Vec<u8>>,
    #[serde(rename = "5")]
    pub enc_extensions: Option<Vec<u8>>
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoRegistrationAuthenticatorSelection {
    pub attachment: FidoAuthenticatorAttachment,
    pub resident_key: FidoPolicy,
    pub user_verification: FidoPolicy
}


#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoRegistrationResponse {
    pub message_type: u8,
    pub attestation_object: Vec<u8>,
    pub client_data_json: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate)  struct FidoClientData {
    #[serde(rename = "type")]
    pub mode: String,
    pub challenge_b64: String,
    pub origin: String,
    pub cross_origin: bool

}

/// FidoAuthenticationIndication
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoAuthenticationIndication {
    /// message_type
    pub message_type: u8
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoAuthenticationRequest {
    pub message_type: u8,
    pub challenge: Vec<u8>,
    pub optionals: FidoAuthenticationRequestOptionals
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct FidoAuthenticationRequestOptionals {
    #[serde(rename = "1")]
    pub timeout: Option<u32>,
    #[serde(rename = "2")]
    pub rpid: Option<String>,
    #[serde(rename = "3")]
    pub user_verification: Option<FidoPolicy>,
    #[serde(rename = "4")]
    pub allow_credentials: Option<Vec<FidoCredential>>,
    #[serde(rename = "5")]
    pub extensions: Option<Vec<FidoExtension>>
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoCredential {
    pub credential_type: u8,
    pub credential_id: Vec<u8>,
    pub transports: FidoAuthenticatorTransport,
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoExtension {
    pub extension_id: String,
    pub extension_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoAuthenticationResponse {
    pub message_type: u8,
    pub client_data_json: String,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub optionals: FidoAuthenticationResponseOptionals
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct FidoAuthenticationResponseOptionals {
    #[serde(rename = "1")]
    pub user_handle: Option<Vec<u8>>,
    #[serde(rename = "2")]
    pub selected_credential_id: Option<Vec<u8>>,
    #[serde(rename = "3")]
    pub client_extension_output: Option<Vec<FidoExtension>>
}

// Group Enums

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FidoIndication {
    PreRegistration(FidoPreRegistrationIndication),
    Registration(FidoRegistrationIndication),
    Authentication(FidoAuthenticationIndication)
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum FidoRequest {
    PreRegistration(FidoPreRegistrationRequest),
    Registration(FidoRegistrationRequest),
    Authentication(FidoAuthenticationRequest)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum FidoResponse {
    PreRegistration(FidoPreRegistrationResponse),
    Registration(FidoRegistrationResponse),
    Authentication(FidoAuthenticationResponse)
}

// Implement Constructors

impl FidoPreRegistrationIndication {
    pub(crate) fn new() -> Self {
        Self { 
            message_type: MessageType::PreRegistrationIndication as u8,
        }
    }
}

impl FidoPreRegistrationRequest {
    pub(crate) fn new(ephem_user_id: Vec<u8>, gcm_key: Vec<u8>) -> Self {
        Self { 
            message_type: MessageType::PreRegistrationRequest as u8,
            ephem_user_id,
            gcm_key
        }
    }
}

impl FidoPreRegistrationResponse {
    pub(crate) fn new(user_name: String, user_display_name: String, ticket: Vec<u8>) -> Self {
        Self { 
            message_type: MessageType::PreRegistrationResponse as u8,
            user_name,
            user_display_name,
            ticket
        }
    }
}

impl FidoRegistrationIndication {
    pub(crate) fn new(ephem_user_id: Vec<u8>) -> Self {
        Self { 
            message_type: MessageType::RegistrationIndication as u8,
            ephem_user_id
        }
    }
}

impl FidoRegistrationRequest {
    pub(crate) fn new(
        challenge: Vec<u8>, 
        rp_id: String, 
        rp_name: String, 
        user_name: Vec<u8>, 
        user_display_name: Vec<u8>, 
        user_id: Vec<u8>, 
        pubkey_cred_params: Vec<FidoPublicKeyAlgorithms>, 
        options: Option<FidoRegistrationRequestOptionals>
    ) -> Self {
        Self { 
            message_type: MessageType::RegistrationRequest as u8,
            challenge,
            rp_id,
            rp_name,
            enc_user_name: user_name,
            enc_user_display_name: user_display_name,
            enc_user_id: user_id,
            pubkey_cred_params,
            optionals: options.unwrap_or_default()
        }
    }
}
impl Default for FidoRegistrationAuthenticatorSelection {
    fn default() -> Self {
        Self {
            attachment: FidoAuthenticatorAttachment::CrossPlatform,
            resident_key: FidoPolicy::Required,
            user_verification: FidoPolicy::Preferred,
        }
    }
}

impl FidoRegistrationResponse {
    pub(crate) fn new(attestation_object: Vec<u8>, client_data_json: String) -> Self {
        Self { 
            message_type: MessageType::RegistrationResponse as u8,
            attestation_object,
            client_data_json
        }
    }
}

impl FidoAuthenticationIndication {
    pub(crate) fn new() -> Self {
        Self { 
            message_type: MessageType::AuthenticationIndication as u8
        }
    }
}

impl FidoAuthenticationRequest {
    pub(crate) fn new(challenge: Vec<u8>, options: Option<FidoAuthenticationRequestOptionals>) -> Self {
        Self { 
            message_type: MessageType::AuthenticationRequest as u8,
            challenge,
            optionals: options.unwrap_or_default()
        }
    }
}

impl FidoAuthenticationResponse {
    pub(crate) fn new(client_data_json: String, authenticator_data: Vec<u8>, signature: Vec<u8>, options: Option<FidoAuthenticationResponseOptionals>) -> Self {
        Self { 
            message_type: MessageType::AuthenticationResponse as u8,
            client_data_json,
            authenticator_data,
            signature,
            optionals: options.unwrap_or_default()
        }
    }
}

// Implement encodings

macro_rules! impl_codec_for {
    ($type:ty, $error_msg:expr) => {
        impl Codec<'_> for $type {
            fn encode(&self, bytes: &mut Vec<u8>) {
                let mut serialized = to_vec_packed(self).unwrap();
                bytes.append(&mut serialized);
            }

            fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
                serde_cbor::from_slice(r.rest()).map_err(|_| InvalidMessage::MissingData($error_msg))
            }
        }
    };
}

impl_codec_for!(FidoPreRegistrationIndication, "Could not parse FIDO pre registration indication");
impl_codec_for!(FidoPreRegistrationRequest, "Could not parse FIDO pre registration request");
impl_codec_for!(FidoPreRegistrationResponse, "Could not parse FIDO pre registration response");
impl_codec_for!(FidoRegistrationIndication, "Could not parse FIDO registration indication");
impl_codec_for!(FidoRegistrationRequest, "Could not parse FIDO registration request");
impl_codec_for!(FidoRegistrationResponse, "Could not parse FIDO registration response");
impl_codec_for!(FidoAuthenticationIndication, "Could not parse FIDO authentication indication");
impl_codec_for!(FidoAuthenticationRequest, "Could not parse FIDO authentication request");
impl_codec_for!(FidoAuthenticationResponse, "Could not parse FIDO authentication response");

impl_codec_for!(FidoIndication, "Could not parse FIDO indication");
impl_codec_for!(FidoRequest, "Could not parse FIDO request");
impl_codec_for!(FidoResponse, "Could not parse FIDO response");