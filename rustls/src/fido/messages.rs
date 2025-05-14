use crate::{msgs::codec::{Codec, Reader}, InvalidMessage};
use std::vec::Vec;
use rustls_fido::messages::{FidoAuthenticationIndication, FidoAuthenticationRequest, FidoAuthenticationResponse, FidoIndication, FidoPreRegistrationIndication, FidoPreRegistrationRequest, FidoPreRegistrationResponse, FidoRegistrationIndication, FidoRegistrationRequest, FidoRegistrationResponse, FidoRequest, FidoResponse};
// Implement encodings
macro_rules! impl_codec_for {
    ($type:ty, $error_msg:expr) => {
        impl Codec<'_> for $type {
            fn encode(&self, bytes: &mut Vec<u8>) {
                let mut serialized = serde_cbor::ser::to_vec_packed(self).unwrap();
                bytes.append(&mut serialized);
            }

            fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
                let bytes = r.rest();
                serde_cbor::from_slice(bytes).map_err(|_| InvalidMessage::MissingData($error_msg))
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