use std::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};
use serde_cbor::ser::to_vec_packed;

use crate::{msgs::codec::{Codec, Reader}, InvalidMessage};

use super::enums::MessageType;

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct FidoAuthenticationIndication {
    pub message_type: u8,
    pub user_id: Vec<u8>
}

impl FidoAuthenticationIndication {
    pub fn new(user_id: Vec<u8>) -> Self {
        Self { 
            message_type: MessageType::AuthenticationIndication.into(), 
            user_id
        }
    }
}

impl Codec<'_> for FidoAuthenticationIndication {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut serialized = to_vec_packed(self).unwrap();
        bytes.append(&mut serialized);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        serde_cbor::from_slice(r.rest()).map_err(|_| InvalidMessage::MissingData("Could not parse FIDO authentication indication"))
    }
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoAuthenticationRequest {
    pub(crate) message_type: u8,
    pub(crate) challenge: Vec<u8>,
    pub(crate) optionals: FidoAuthenticationRequestOptionals
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct FidoAuthenticationRequestOptionals {
    #[serde(rename = "1")]
    pub(crate) timeout: Option<u32>,
    #[serde(rename = "2")]
    pub(crate) rpid: Option<String>,
    #[serde(rename = "3")]
    pub(crate) user_verification: Option<UserVerificationRequirement>,
    #[serde(rename = "4")]
    pub(crate) allow_credentials: Option<Vec<FidoAuthenticationCredential>>,
    #[serde(rename = "5")]
    pub(crate) extensions: Option<Vec<FidoAuthenticationExtension>>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub(crate) enum UserVerificationRequirement {
    Required = 0,
    Preferred = 1,
    Discouraged = 2,
}


#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoAuthenticationCredential {
    pub(crate) credential_type: u8,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) transports: u8,
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoAuthenticationExtension {
    pub(crate) extension_id: String,
    pub(crate) extension_data: Vec<u8>,
}

impl FidoAuthenticationRequest {
    pub fn new(challenge: Vec<u8>, options: Option<FidoAuthenticationRequestOptionals>) -> Self {
        Self { 
            message_type: MessageType::AuthenticationRequest.into(), 
            challenge,
            optionals: options.unwrap_or_default()
        }
    }
}

impl Codec<'_> for FidoAuthenticationRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut serialized = to_vec_packed(self).unwrap();
        bytes.append(&mut serialized);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        serde_cbor::from_slice(r.rest()).map_err(|_| InvalidMessage::MissingData("Could not parse FIDO authentication request"))
    }
}

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub(crate) struct FidoAuthenticationResponse {
    pub(crate) message_type: u8,
    pub(crate) client_data_json: String,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) optionals: FidoAuthenticationResponseOptionals
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct FidoAuthenticationResponseOptionals {
    #[serde(rename = "1")]
    pub(crate) user_handle: Option<Vec<u8>>,
    #[serde(rename = "2")]
    pub(crate) selected_credential_id: Option<Vec<u8>>,
    #[serde(rename = "3")]
    pub(crate) client_extension_output: Option<Vec<FidoAuthenticationExtension>>
}

impl FidoAuthenticationResponse {
    pub fn new(client_data_json: String, authenticator_data: Vec<u8>, signature: Vec<u8>, options: Option<FidoAuthenticationResponseOptionals>) -> Self {
        Self { 
            message_type: MessageType::AuthenticationResponse.into(), 
            client_data_json,
            authenticator_data,
            signature,
            optionals: options.unwrap_or_default()
        }
    }
}

impl Codec<'_> for FidoAuthenticationResponse {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut serialized = to_vec_packed(self).unwrap();
        bytes.append(&mut serialized);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        serde_cbor::from_slice(r.rest()).map_err(|_| InvalidMessage::MissingData("Could not parse FIDO authentication request"))
    }
}