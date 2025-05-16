use std::{borrow::ToOwned, collections::HashMap, string::String, vec::{self, Vec}};

use webauthn_rs::prelude::*;
use webauthn_rs_device_catalog::Data;
use webauthn_rs_proto::AuthenticatorAttestationResponseRaw;

use crate::{sync::Arc, Error};

use super::{db::FidoDB, enums::{FidoAuthenticatorAttachment, FidoAuthenticatorTransport, FidoPolicy, FidoPublicKeyAlgorithms, FidoState}, messages::{FidoCredential, FidoRegistrationRequest}};

#[derive(Debug, Clone, Default)]
pub(crate) struct FidoServer {
    pub webauthn: Option<Webauthn>,
    pub challenge: Option<Vec<u8>>,
    pub ticket: Option<Vec<u8>>,
    pub registration_state: HashMap<Vec<u8>, (FidoRegistrationRequest, PasskeyRegistration)>
}

impl FidoServer {
    pub(crate) fn start_register_fido(mut self, ephem_user_id: Vec<u8>, ticket: Vec<u8>, user_name: String, user_display_name: String) -> Result<(), Error>{
        if self.ticket.unwrap() != ticket {
            return Err(Error::General("Fido registration failed".to_owned()))
        }
        let user_id = Uuid::new_v4();

        let (ccr, skr) = self.webauthn
            .unwrap()
            .start_passkey_registration(
                user_id,
                &user_name,
                &user_display_name,
                None
            )
            .expect("Failed to start registration.");

        let registration_request = FidoRegistrationRequest::new(
            ccr.public_key.challenge.to_vec(), 
            ccr.public_key.rp.id, 
            ccr.public_key.rp.name,
            user_name, 
            user_display_name, 
            user_id.as_bytes().to_vec(),
            std::vec![FidoPublicKeyAlgorithms::COSE_ES256],
            None
        );

        self.registration_state.insert(ephem_user_id, (registration_request, skr));

        Ok(())
    }

    pub(crate) fn finish_register_fido(mut self, ephem_user_id: Vec<u8>, client_data_json: String, attestation_object: Vec<u8>) -> Result<(), Error>{
        if let Some((_, skr)) = self.registration_state.remove(&ephem_user_id) {
            let attestation_response = AuthenticatorAttestationResponseRaw{
                attestation_object: attestation_object.into(),
                client_data_json: client_data_json.as_bytes().to_vec().into(),
                transports: None
            };

            let reg = RegisterPublicKeyCredential{
                id: "".to_owned(),
                raw_id: std::vec![].into(),
                response: attestation_response,
                type_: "".to_owned(),
                extensions: Default::default()
            };

            let passkey = self.webauthn.unwrap().finish_passkey_registration(&reg, &skr).unwrap();
            return Ok(())
        }

        Err(Error::General("User not registered".to_owned()))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FidoClient {
    pub state: FidoState,
    pub challenge: Option<Vec<u8>>,
    pub rp_id: Option<String>,
    pub rp_name: Option<String>,
    pub user_verification: Option<FidoPolicy>,
    pub user_presence: Option<FidoPolicy>,
    pub resident_key: Option<FidoPolicy>,
    // Only CROSS_PLATFORM is supported
    pub auth_attach: Option<FidoAuthenticatorAttachment>,
    // Only USB is supported
    pub transport: Option<FidoAuthenticatorTransport>,
    pub timeout: Option<usize>,
    pub authdata: Option<Vec<u8>>,
    pub clientdata_json: Option<String>,
    pub signature: Option<Vec<u8>>,
    pub user_id: Option<Vec<u8>>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub eph_user_id: Option<Vec<u8>>,
    pub gcm_key: Option<Vec<u8>>,
    pub cred_id: Option<Vec<u8>>,
    pub ticket: Option<Vec<u8>>,
    pub exclude_creds: Option<Vec<FidoCredential>>,
    pub pin: Option<String>,
    pub origin: Option<String>,
    pub cred_params: Option<Vec<i32>>,
}