use std::{borrow::ToOwned, collections::HashMap, string::String, vec::Vec};

use aws_lc_rs::aead::{self, LessSafeKey, Nonce, UnboundKey};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::AuthenticatorAttestationResponseRaw;

use crate::Error;

use super::{db::{FidoDB, User}, enums::{FidoAuthenticatorAttachment, FidoAuthenticatorTransport, FidoPolicy, FidoPublicKeyAlgorithms, FidoState}, messages::{FidoAuthenticationRequest, FidoAuthenticationRequestOptionals, FidoCredential, FidoRegistrationRequest}};

#[derive(Debug, Clone)]
pub(crate) struct FidoServer {
    pub webauthn: Webauthn,
    pub db: FidoDB,
    pub challenge: Option<Vec<u8>>,
    pub ticket: Vec<u8>,
    pub registration_state: HashMap<Vec<u8>, (FidoRegistrationRequest, PasskeyRegistration)>
}

impl FidoServer {
    pub(crate) fn start_register_fido(&mut self, ephem_user_id: Vec<u8>, gcm_key: Vec<u8>, ticket: Vec<u8>, user_name: String, user_display_name: String) -> Result<(), Error>{
        if self.ticket != ticket {
            return Err(Error::General("Fido registration failed".to_owned()))
        }
        let user_id = Uuid::new_v4();

        let (ccr, skr) = self.webauthn
            .start_passkey_registration(
                user_id,
                &user_name,
                &user_display_name,
                None
            )
            .expect("Failed to start registration.");
            
            let mut enc_user_name = user_name.clone().as_bytes().to_vec();
            let mut enc_user_display_name = user_display_name.clone().as_bytes().to_vec();
            let mut enc_user_id = user_id.clone().as_bytes().to_vec();

            encrypt_in_place(&gcm_key, &mut enc_user_name);
            encrypt_in_place(&gcm_key, &mut enc_user_display_name);
            encrypt_in_place(&gcm_key, &mut enc_user_id);

            let registration_request = FidoRegistrationRequest::new(
                ccr.public_key.challenge.to_vec(), 
                ccr.public_key.rp.id, 
                ccr.public_key.rp.name,
                enc_user_name,
                enc_user_display_name,
                enc_user_id,
                std::vec![FidoPublicKeyAlgorithms::COSE_ES256],
                None
            );

        self.registration_state.insert(ephem_user_id, (registration_request, skr));

        Ok(())
    }

    pub(crate) fn finish_register_fido(&mut self, ephem_user_id: Vec<u8>, user_id: Vec<u8>, client_data_json: String, attestation_object: Vec<u8>) -> Result<(), Error> {
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

            let passkey = self.webauthn.finish_passkey_registration(&reg, &skr).unwrap();
            self.db.add_user(User{user_id, passkey});
            return Ok(())
        }

        Err(Error::General("User not registered".to_owned()))
    }

    pub(crate) fn start_authentication_fido(&self) -> Result<(FidoAuthenticationRequest, DiscoverableAuthentication), Error> {
        let (ar, sas) = self.webauthn.start_discoverable_authentication().expect("Fail");

        let authentication_request = FidoAuthenticationRequest::new(
            ar.public_key.challenge.to_vec(),
            Some(FidoAuthenticationRequestOptionals{
                timeout: ar.public_key.timeout,
                rpid: Some(ar.public_key.rp_id),
                ..Default::default()
            })
        );

        return Ok((authentication_request, sas));
    }

    pub(crate) fn get_registration_request(&mut self, ephem_user_id: &Vec<u8>) ->  Result<&FidoRegistrationRequest, Error> {
        if let Some(state) = self.registration_state.get(ephem_user_id){
            Ok(&state.0)
        } else {
            Err(Error::General("Bad".to_owned()))
        }
    }
}

fn encrypt_in_place(key: &Vec<u8>, in_out: &mut Vec<u8>) -> Result<(), Error>{
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).unwrap();
    let key = LessSafeKey::new(unbound_key);

    // 12 bytes = standard GCM nonce size
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), in_out)
        .map_err(|_| Error::General("Encrypt".to_owned()))
}

fn decrypt_in_place(key: &[u8], in_out: &mut Vec<u8>) -> Result<(), Error>{
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).unwrap();
    let key = LessSafeKey::new(unbound_key);

    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    key.open_in_place(nonce, aead::Aad::empty(),in_out)
        .map_err(|_| Error::General("Decrypt failed".to_owned()))?;

    Ok(())
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