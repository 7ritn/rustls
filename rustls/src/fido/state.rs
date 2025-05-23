use std::{borrow::ToOwned, collections::HashMap, format, string::String, vec, vec::Vec};
use std::prelude::rust_2024::{Box, ToString};
use std::sync::mpsc::channel;
use std::time::Duration;
use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
use authenticator::ctap2::server::{AuthenticationExtensionsClientInputs, PublicKeyCredentialUserEntity, RelyingParty};
use authenticator::{Pin, StatusUpdate};
use authenticator::statecallback::StateCallback;
use aws_lc_rs::aead::{self, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::digest;
use aws_lc_rs::digest::digest;
use base64::Engine;
use base64::engine::general_purpose;
use webauthn_rs::prelude::{Base64UrlSafeData, DiscoverableAuthentication, PasskeyRegistration, Url, Uuid};
use webauthn_rs::{Webauthn, WebauthnBuilder};
use webauthn_rs_proto::{AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential, RegisterPublicKeyCredential};
use crate::Error;
use crate::fido::enums::{FidoAuthenticatorAttachment, FidoMode, FidoPolicy};
use crate::fido::messages::{FidoAuthenticationResponseOptionals, FidoClientData, FidoCredential, FidoPreRegistrationRequest, FidoPreRegistrationResponse, FidoRegistrationAuthenticatorSelection, FidoRegistrationRequestOptionals, FidoRegistrationResponse, FidoResponse};
use crate::lock::Mutex;
use crate::sync::Arc;
use super::{db::{FidoDB, User}, enums::FidoPublicKeyAlgorithms, messages::{FidoAuthenticationRequest, FidoAuthenticationRequestOptionals, FidoAuthenticationResponse, FidoRegistrationRequest}};

/// State and configuration for Fido TLS Extension server-side
#[derive(Debug, Clone)]
pub struct FidoServer {
    pub(crate) webauthn: Webauthn,
    pub(crate) db: FidoDB,
    pub(crate) user_verification: FidoPolicy,
    pub(crate) resident_key: FidoPolicy,
    pub(crate) authenticator_attachment: FidoAuthenticatorAttachment,
    pub(crate) timeout: u32,
    pub(crate) ticket: Vec<u8>,
    pub(crate) registration_state: HashMap<Vec<u8>, (FidoRegistrationRequest, PasskeyRegistration)>,
    pub(crate) pre_registration_state: HashMap<Vec<u8>, Vec<u8>>
}

impl FidoServer {
    /// Create new configuration for Fido TLS Extension server-side
    pub  fn new(
        rp_id: String,
        rp_name: String,
        user_verification: FidoPolicy,
        resident_key: FidoPolicy,
        authenticator_attachment: FidoAuthenticatorAttachment,
        timeout: u32,
        ticket: Vec<u8>
    ) -> Self {
        let rp_origin = Url::parse(&format!("https://{}", rp_id.clone()))
            .expect("Invalid DN");
        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("Invalid configuration")
            .rp_name(&rp_name)
            .timeout(Duration::new(timeout.try_into().unwrap_or_default(), 0))
            .build()
            .expect("Couldn't build FIDO verifier");

        Self{
            webauthn,
            db: FidoDB::new("./fido.db3"),
            user_verification,
            resident_key,
            authenticator_attachment,
            timeout,
            ticket,
            registration_state: Default::default(),
            pre_registration_state: Default::default()
        }
    }
    pub(crate) fn start_register_fido(&mut self, ephem_user_id: Vec<u8>, ticket: Vec<u8>, user_name: String, user_display_name: String) -> Result<(), Error>{
        if self.ticket != ticket {
            return Err(Error::General("fido registration ticket invalid".to_string()))
        }
        let gcm_key = self.pre_registration_state
            .get(&ephem_user_id)
            .ok_or(Error::General("client did not pre-register".to_string()))?;
        let user_id = Uuid::new_v4();

        let (ccr, skr) = self.webauthn
            .start_passkey_registration(
                user_id,
                &user_name,
                &user_display_name,
                None
            )
            .map_err(|e| Error::General(e.to_string()))?;
            
        let mut enc_user_name = user_name.clone().as_bytes().to_vec();
        let mut enc_user_display_name = user_display_name.clone().as_bytes().to_vec();
        let mut enc_user_id = user_id.clone().as_bytes().to_vec();

        let authenticator_selection = FidoRegistrationAuthenticatorSelection{
            attachment: self.authenticator_attachment.clone(),
            resident_key: self.resident_key.clone(),
            user_verification: self.user_verification.clone()
        };
        let mut enc_authenticator_selection = serde_cbor::to_vec(&authenticator_selection).expect("serializing authenticator_selection");

        let excluded_credentials: Vec<FidoCredential> = vec![];
        let mut enc_excluded_credentials = serde_cbor::to_vec(&excluded_credentials).expect("serializing excluded_credentials");

        encrypt_in_place(&gcm_key, &mut enc_user_name)?;
        encrypt_in_place(&gcm_key, &mut enc_user_display_name)?;
        encrypt_in_place(&gcm_key, &mut enc_user_id)?;
        encrypt_in_place(&gcm_key, &mut enc_authenticator_selection)?;
        encrypt_in_place(&gcm_key, &mut enc_excluded_credentials)?;

        let optionals = FidoRegistrationRequestOptionals{
            timeout: Some(self.timeout),
            enc_authenticator_selection: Some(enc_authenticator_selection),
            enc_excluded_credentials: Some(enc_excluded_credentials),
            enc_attestation: None,
            enc_extensions: None,
        };

        let registration_request = FidoRegistrationRequest::new(
            ccr.public_key.challenge.to_vec(),
            ccr.public_key.rp.id,
            ccr.public_key.rp.name,
            enc_user_name,
            enc_user_display_name,
            enc_user_id,
            std::vec![FidoPublicKeyAlgorithms::COSE_ES256],
            Some(optionals)
        );

        self.registration_state.insert(user_id.clone().as_bytes().to_vec(), (registration_request, skr));

        Ok(())
    }

    pub(crate) fn finish_register_fido(&mut self, user_id: Vec<u8>, client_data_json: String, attestation_object: Vec<u8>) -> Result<(), Error> {
        let (_, skr) = self.registration_state.remove(&user_id).ok_or(Error::General("no registration state found".to_string()))?;

        let attestation_response = AuthenticatorAttestationResponseRaw{
            attestation_object: attestation_object.into(),
            client_data_json: client_data_json.as_bytes().to_vec().into(),
            transports: None
        };

        let reg = RegisterPublicKeyCredential{
            id: String::new(),
            raw_id: Base64UrlSafeData::new(),
            response: attestation_response,
            type_: String::new(),
            extensions: Default::default()
        };

        let passkey = self.webauthn.finish_passkey_registration(&reg, &skr).map_err(|e| Error::General(e.to_string()))?;

        self.db.add_user(User{user_id, passkey})?;

        Ok(())
    }

    pub(crate) fn start_authentication_fido(&self) -> Result<(FidoAuthenticationRequest, DiscoverableAuthentication), Error> {
        let (ar, sas) = self.webauthn.start_discoverable_authentication().map_err(|e| Error::General(e.to_string()))?;

        let authentication_request = FidoAuthenticationRequest::new(
            ar.public_key.challenge.to_vec(),
            Some(FidoAuthenticationRequestOptionals{
                timeout: ar.public_key.timeout,
                rpid: Some(ar.public_key.rp_id),
                ..Default::default()
            })
        );

        Ok((authentication_request, sas))
    }

    pub(crate) fn finish_authentication_fido(&self, fido_response: FidoAuthenticationResponse, sas: DiscoverableAuthentication) -> Result<(), Error>{

        let user_handle = match fido_response.optionals.user_handle {
            Some(user_handle) => Some(user_handle.into()),
            None => None
        };
        let credential_id = fido_response.optionals.selected_credential_id.unwrap_or_default();
        let credential_id_string = String::from_utf8(credential_id.clone()).unwrap_or_default();

        let authentication_response = AuthenticatorAssertionResponseRaw{
            authenticator_data: fido_response.authenticator_data.into(),
            client_data_json: fido_response.client_data_json.as_bytes().to_vec().into(),
            signature: fido_response.signature.into(),
            user_handle
        };

        let reg = PublicKeyCredential { 
            id: credential_id_string,
            raw_id: credential_id.into(),
            response: authentication_response, 
            type_: String::new(),
            extensions: Default::default()
        };
        let (uuid, _) = self.webauthn.identify_discoverable_authentication(&reg).map_err(|e| Error::General(e.to_string()))?;

        let user_id = uuid.clone().as_bytes().to_vec();
        let passkey = self.db.get_passkey(&user_id)?;

        let _authentication_result = self.webauthn.finish_discoverable_authentication(&reg, sas, &[passkey.into()]).map_err(|e| Error::General(e.to_string()))?;

        // ToDo: verify counter

        Ok(())
    }

    pub(crate) fn add_ephem_user(&mut self, ephem_user_id: Vec<u8>, gcm_key: Vec<u8>) ->  FidoPreRegistrationRequest {
        self.pre_registration_state.insert(ephem_user_id.clone(), gcm_key.clone());
        FidoPreRegistrationRequest::new(ephem_user_id, gcm_key)
    }

    pub(crate) fn get_registration_request(&mut self, ephem_user_id: &Vec<u8>) ->  Result<&FidoRegistrationRequest, Error> {
        if let Some(state) = self.registration_state.get(ephem_user_id){
            Ok(&state.0)
        } else {
            Err(Error::General("No pre reg request has been made".to_owned()))
        }
    }
}

/// FidoClient
#[derive(Debug, Clone)]
pub struct FidoClient {
    /// mode
    pub mode: FidoMode,
    /// user_name
    pub user_name: String,
    /// user_display_name
    pub user_display_name: String,
    /// user_id
    pub user_id: Vec<u8>,
    /// ticket
    pub ticket: Option<Vec<u8>>,
    /// ticket
    pub fido_device_pin: String,
    /// persistent_reg_state
    pub persistent_reg_state: Arc<Mutex<Option<RegistrationState>>>,
    /// response_buffer
    pub response_buffer: Arc<Mutex<Option<FidoResponse>>>,
}

/// state to be remembered between handshakes
#[derive(Debug, Clone)]
pub struct RegistrationState {
    /// ephem_user_id
    pub ephem_user_id: Vec<u8>,
    /// ephem encryption key
    pub gcm_key: Vec<u8>
}

impl FidoClient {
    pub(crate) fn pre_register_fido(&self, ephem_user_id: Vec<u8>, gcm_key: Vec<u8>) {
        let mut binding = self.persistent_reg_state.lock().expect("lock persistent_reg_state");
        *binding = Some(RegistrationState{ephem_user_id, gcm_key});

        let mut response = self.response_buffer.lock().expect("lock response_buffer");
        *response = Some(FidoResponse::PreRegistration(FidoPreRegistrationResponse::new(
            self.user_name.clone(),
            self.user_display_name.clone(),
            self.ticket.as_ref().expect("no ticket").clone(),
        )));
    }

    pub(crate) fn register_fido(&self, request: FidoRegistrationRequest) -> Result<(), Error> {
        let mut manager = AuthenticatorService::new().expect("AuthenticatorService::new");
        manager.add_u2f_usb_hid_platform_transports();

        let gcm_key = self.persistent_reg_state
            .lock()
            .expect("lock persistent_reg_state")
            .take()
            .ok_or(Error::General("no pre_reg_state available".to_string()))?
            .gcm_key;

        // ToDo verify request and actual user info match
        let user = PublicKeyCredentialUserEntity {
            id: self.user_id.clone(),
            name: Some(self.user_name.clone()),
            display_name: Some(self.user_display_name.clone())
        };

        let origin = "https://".to_string() + &*request.rp_id;
        let challenge_b64 = general_purpose::STANDARD.encode(&request.challenge);

        let client_data = FidoClientData{
            mode: "webauthn.create".to_string(),
            challenge_b64,
            origin: origin.clone(),
            cross_origin: false,
        };
        let client_data_json = serde_json::to_string(&client_data).expect("serialize client_data_json");
        let binding = digest(&digest::SHA256, client_data_json.as_bytes());
        let client_data_hash = binding.as_ref().try_into().expect("digest client_data_json");

        let authenticator_selection: FidoRegistrationAuthenticatorSelection;
        if let Some(enc_authenticator_selection) = request.optionals.enc_authenticator_selection.clone().as_mut() {
            decrypt_in_place(&gcm_key, enc_authenticator_selection)?;
            authenticator_selection = serde_cbor::from_slice(enc_authenticator_selection).map_err(|e| Error::General(e.to_string()))?;
        } else {
            authenticator_selection = Default::default();
        }

        let excluded_credentials: Vec<FidoCredential>;
        if let Some(enc_excluded_credentials) = request.optionals.enc_excluded_credentials.clone().as_mut() {
            decrypt_in_place(&gcm_key, enc_excluded_credentials)?;
            excluded_credentials = serde_cbor::from_slice(enc_excluded_credentials).map_err(|e| Error::General(e.to_string()))?;
        } else {
            excluded_credentials = Default::default();
        }

        let ctap_args = RegisterArgs {
            client_data_hash,
            relying_party: RelyingParty {
                id: request.rp_id.into(),
                name: Some(request.rp_name.into()),
            },
            origin,
            user,
            pub_cred_params: request.pubkey_cred_params.iter().map(|alg| alg.clone().try_into().expect("convert pubkey_cred_params")).collect(),
            exclude_list: excluded_credentials.iter().map(|cred| cred.clone().into()).collect(),
            user_verification_req: authenticator_selection.user_verification.into(),
            resident_key_req: authenticator_selection.resident_key.into(),
            extensions: AuthenticationExtensionsClientInputs {
                ..Default::default()
            },
            pin: Some(Pin::new(&self.fido_device_pin)),
            use_ctap1_fallback: false,
        };

        let (register_tx, register_rx) = channel();
        let (status_tx, _status_rx) = channel::<StatusUpdate>();
        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx.send(rv).expect("register_tx send");
        }));

        manager.register(request.optionals.timeout.unwrap_or(10000).into(), ctap_args, status_tx, callback)
            .map_err(|e| Error::General(e.to_string()))?;

        let register_result = register_rx
            .recv()
            .map_err(|e| Error::General(e.to_string()))?
            .map_err(|e| Error::General(e.to_string()))?;

        let mut response = self.response_buffer.lock().unwrap();
        *response = Some(FidoResponse::Registration(FidoRegistrationResponse::new(
            serde_cbor::to_vec(&register_result.att_obj).expect("serialize register_result"),
            client_data_json
        )));

        Ok(())
    }

    pub(crate) fn authenticate_fido(&self, request: FidoAuthenticationRequest) -> Result<(), Error> {
        let mut manager = AuthenticatorService::new().map_err(|e| Error::General(e.to_string()))?;
        manager.add_u2f_usb_hid_platform_transports();

        // Discovering creds:
        let allow_list = Vec::new();
        let rp_id = request.optionals.rpid.ok_or(Error::General("missing required rp_id".into()))?;
        let origin = "https://".to_string() + &*rp_id.clone();
        let binding = digest(&digest::SHA256, &request.challenge);
        let challenge_hash = binding.as_ref().try_into().expect("challenge_hash");
        let challenge_b64 = general_purpose::STANDARD.encode(&request.challenge);

        let client_data = FidoClientData{
            mode: "webauthn.get".to_string(),
            challenge_b64,
            origin: origin.clone(),
            cross_origin: false,
        };

        let (status_tx, _status_rx) = channel::<StatusUpdate>();

        let ctap_args = SignArgs {
            client_data_hash: challenge_hash,
            origin,
            relying_party_id: rp_id,
            allow_list,
            user_verification_req: request.optionals.user_verification.unwrap_or(FidoPolicy::Preferred).into(),
            user_presence_req: true,
            extensions: Default::default(),
            pin: None,
            use_ctap1_fallback: false,
        };

        let sign_result;

        let (sign_tx, sign_rx) = channel();

        let callback = StateCallback::new(Box::new(move |rv| {
            sign_tx.send(rv).expect("failed to send sign");
        }));

        manager
            .sign(request.optionals.timeout.unwrap_or(10000) as u64, ctap_args, status_tx, callback)
            .map_err(|e| Error::General(format!("{:?}", e)))?;

        sign_result = sign_rx
            .recv()
            .map_err(|e| Error::General(format!("{:?}", e)))?
            .map_err(|e| Error::General(format!("{:?}", e)))?;

        let user_handle = match sign_result.assertion.user {
            Some(user) => Some(user.id),
            None => None
        };

        let selected_credential_id = match sign_result.assertion.credentials {
            Some(cred) => Some(cred.id),
            None => None
        };

        let options = FidoAuthenticationResponseOptionals{
            user_handle,
            selected_credential_id,
            client_extension_output: None,
        };

        let mut response = self.response_buffer.lock().unwrap();
        *response = Some(FidoResponse::Authentication(FidoAuthenticationResponse::new(
            serde_json::to_string(&client_data).expect("serialize client_data"),
            serde_cbor::to_vec(&sign_result.assertion.auth_data).expect("serialize auth_data"),
            sign_result.assertion.signature,
            Some(options)
        )));
        
        Ok(())
    }
}

fn encrypt_in_place(key: &Vec<u8>, in_out: &mut Vec<u8>) -> Result<(), Error>{
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|e| Error::General(e.to_string()))?;
    let key = LessSafeKey::new(unbound_key);

    // 12 bytes = standard GCM nonce size
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), in_out)
        .map_err(|e| Error::General(e.to_string()))
}

fn decrypt_in_place(key: &[u8], in_out: &mut Vec<u8>) -> Result<(), Error>{
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|e| Error::General(e.to_string()))?;
    let key = LessSafeKey::new(unbound_key);

    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    key.open_in_place(nonce, aead::Aad::empty(),in_out)
        .map_err(|e| Error::General(e.to_string()))?;

    Ok(())
}