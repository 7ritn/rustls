use crate::msgs::codec::{Codec, Reader};

enum_builder! {
    #[repr(u8)]
    pub enum MessageType {
        AuthenticationIndication => 0x0a,
        AuthenticationRequest => 0x0b,
        AuthenticationResponse => 0x0c
    }
}