use std::vec::Vec;

#[derive(Debug, Clone, Default)]
pub struct Fido {
    pub(crate) challenge: Option<Vec<u8>>
}

#[derive(Debug, Clone, Default)]
pub struct FidoClient {
    pub(crate) challenge: Option<Vec<u8>>
}