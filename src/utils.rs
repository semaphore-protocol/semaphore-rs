use num_bigint::BigUint;

pub fn string_to_biguint(num_str: &str) -> BigUint {
    num_str
        .parse()
        .expect("Failed to parse the string into BigUint")
}
