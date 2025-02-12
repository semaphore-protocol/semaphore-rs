use anyhow::Result;
use ruint::aliases::U256;

#[allow(dead_code)]
pub struct Identity {
    private_key: Vec<u8>,
    secret_scalar: U256,
    public_key: Vec<u8>,
    commitment: U256,
}

#[allow(dead_code)]
impl Identity {
    fn sign_message(&self, _message: &[u8]) -> Result<()> {
        unimplemented!()
    }

    fn verify_signature(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<()> {
        unimplemented!()
    }

    fn generate_commitment(_public_key: &[u8]) -> Result<()> {
        unimplemented!()
    }
}
