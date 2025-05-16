use std::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use serde_cbor::ser::to_vec_packed;

use crate::{msgs::codec::{Codec, Reader}, InvalidMessage};

use super::enums::{FidoAuthenticatorAttachment, FidoAuthenticatorTransport, FidoPolicy, FidoPublicKeyAlgorithms, FidoRegistrationAttestation, MessageType};

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoPreRegistrationIndication {
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

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoRegistrationIndication {
    pub message_type: u8,
    pub ephem_user_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoRegistrationRequest {
    pub message_type: u8,
    pub challenge: Vec<u8>,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_id: Vec<u8>,
    pub pubkey_cred_params: Vec<FidoPublicKeyAlgorithms>,
    pub optionals: FidoRegistrationRequestOptionals
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct FidoRegistrationRequestOptionals {
    #[serde(rename = "1")]
    pub timeout: Option<u32>,
    #[serde(rename = "2")]
    pub authenticator_selection: Option<FidoRegistrationAuthenticatorSelection>,
    #[serde(rename = "3")]
    pub excluded_credentials: Option<Vec<FidoCredential>>,
    #[serde(rename = "4")]
    pub attestation: Option<FidoRegistrationAttestation>,
    #[serde(rename = "5")]
    pub extensions: Option<Vec<FidoExtension>>
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

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoAuthenticationIndication {
    pub message_type: u8,
    pub ephem_user_id: Vec<u8>
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

// Implement Constructors

impl FidoPreRegistrationIndication {
    pub(crate) fn new() -> Self {
        Self { 
            message_type: MessageType::PreRegistrationIndication.into(), 
        }
    }
}

impl FidoPreRegistrationRequest {
    pub(crate) fn new(ephem_user_id: Vec<u8>, gcm_key: Vec<u8>) -> Self {
        Self { 
            message_type: MessageType::PreRegistrationRequest.into(),
            ephem_user_id,
            gcm_key
        }
    }
}

impl FidoPreRegistrationResponse {
    pub(crate) fn new(user_name: String, user_display_name: String, ticket: Vec<u8>) -> Self {
        Self { 
            message_type: MessageType::PreRegistrationResponse.into(),
            user_name,
            user_display_name,
            ticket
        }
    }
}

impl FidoRegistrationIndication {
    pub(crate) fn new(user_id: Vec<u8>) -> Self {
        Self { 
            message_type: MessageType::RegistrationIndication.into(), 
            ephem_user_id: user_id
        }
    }
}

impl FidoRegistrationRequest {
    pub(crate) fn new(
        challenge: Vec<u8>, 
        rp_id: String, 
        rp_name: String, 
        user_name: String, 
        user_display_name: String, 
        user_id: Vec<u8>, 
        pubkey_cred_params: Vec<FidoPublicKeyAlgorithms>, 
        options: Option<FidoRegistrationRequestOptionals>
    ) -> Self {
        Self { 
            message_type: MessageType::RegistrationRequest.into(),
            challenge,
            rp_id,
            rp_name,
            user_name,
            user_display_name,
            user_id,
            pubkey_cred_params,
            optionals: options.unwrap_or_default()
        }
    }
}

impl FidoRegistrationResponse {
    pub(crate) fn new(attestation_object: Vec<u8>, client_data_json: String) -> Self {
        Self { 
            message_type: MessageType::RegistrationResponse.into(), 
            attestation_object,
            client_data_json
        }
    }
}

impl FidoAuthenticationIndication {
    pub fn new(user_id: Vec<u8>) -> Self {
        Self { 
            message_type: MessageType::AuthenticationIndication.into(), 
            ephem_user_id: user_id
        }
    }
}

impl FidoAuthenticationRequest {
    pub(crate) fn new(challenge: Vec<u8>, options: Option<FidoAuthenticationRequestOptionals>) -> Self {
        Self { 
            message_type: MessageType::AuthenticationRequest.into(), 
            challenge,
            optionals: options.unwrap_or_default()
        }
    }
}

impl FidoAuthenticationResponse {
    pub(crate) fn new(client_data_json: String, authenticator_data: Vec<u8>, signature: Vec<u8>, options: Option<FidoAuthenticationResponseOptionals>) -> Self {
        Self { 
            message_type: MessageType::AuthenticationResponse.into(), 
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
