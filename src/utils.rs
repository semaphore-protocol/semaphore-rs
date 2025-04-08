use ethers_core::utils::keccak256;
use num_bigint::BigUint;

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
    fixed_bytes[0..bytes.len()].copy_from_slice(&bytes);
    BigUint::from_bytes_be(&fixed_bytes)
}
