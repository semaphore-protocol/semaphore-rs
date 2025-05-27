use ark_ed_on_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};
use ethers_core::utils::keccak256;
use num_bigint::BigUint;
use reqwest::blocking::Client;
use std::error::Error;
use std::fs::File;
use std::io::copy;

use crate::group::{EMPTY_ELEMENT, Element};

pub fn string_to_biguint(num_str: &str) -> BigUint {
    num_str
        .parse()
        .expect("Failed to parse the string into BigUint")
}

pub fn hash(message: BigUint) -> String {
    let mut h = BigUint::from_bytes_be(&keccak256(message.to_bytes_be()));
    h >>= 8;
    h.to_string()
}

/// Converts a decimal string to BigUint and zero-pads it to 32 bytes (big-endian).
pub fn to_big_uint(str: &String) -> BigUint {
    let bytes = str.as_bytes();
    assert!(bytes.len() <= 32, "BigUint too large: exceeds 32 bytes");
    let mut fixed_bytes = [0u8; 32];
    fixed_bytes[0..bytes.len()].copy_from_slice(bytes);
    BigUint::from_bytes_be(&fixed_bytes)
}

/// Converts Fq to Element in little-endian order
pub fn to_element(value: Fq) -> Element {
    let mut element = EMPTY_ELEMENT;
    let bytes = value.into_bigint().to_bytes_le();
    element[..bytes.len()].copy_from_slice(&bytes);
    element
}

/// Download zkey from artifacts: https://snark-artifacts.pse.dev/
pub fn download_zkey(depth: u16) -> Result<String, Box<dyn Error>> {
    let base_url = "https://snark-artifacts.pse.dev/semaphore/latest/";
    let filename = format!("semaphore-{}.zkey", depth);
    let out_dir = std::env::temp_dir();
    let dest_path = out_dir.join(filename.clone());
    if !dest_path.exists() {
        let url = format!("{}{}", base_url, filename);
        let client = Client::new();
        let mut resp = client.get(&url).send()?.error_for_status()?;
        let mut out = File::create(&dest_path)?;
        copy(&mut resp, &mut out)?;
    }
    Ok(dest_path.to_string_lossy().into_owned())
}
