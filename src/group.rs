//! Group Module

use crate::error::SemaphoreError;
use ark_ed_on_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use zk_kit_lean_imt::hashed_tree::{HashedLeanIMT, LeanIMTHasher};

/// Element size in bytes
pub const ELEMENT_SIZE: usize = 32;

/// Leaf type
type Leaf = [u8; ELEMENT_SIZE];
/// Poseidon-based LeanIMT
pub type LeanIMT = HashedLeanIMT<PoseidonHash>;

/// Poseidon LeanIMTHasher
#[derive(Debug, Clone)]
pub struct PoseidonHash;

impl LeanIMTHasher for PoseidonHash {
    fn hash(input: &[u8]) -> Vec<u8> {
        if input.len() != ELEMENT_SIZE * 2 {
            panic!("Poseidon hash function expects two little-endian 32-byte elements");
        }

        let mut poseidon = Poseidon::<Fq>::new_circom(2).unwrap();
        let hash_fq = poseidon
            .hash(&[
                Fq::from_le_bytes_mod_order(&input[..ELEMENT_SIZE]),
                Fq::from_le_bytes_mod_order(&input[ELEMENT_SIZE..]),
            ])
            .unwrap();

        fq_to_leaf(&hash_fq).to_vec()
    }
}

/// Leaf from base field element
pub fn fq_to_leaf(fq: &Fq) -> Leaf {
    let mut leaf = [0u8; ELEMENT_SIZE];

    let fq_bytes = fq.into_bigint().to_bytes_le();
    leaf[..fq_bytes.len()].copy_from_slice(&fq_bytes);

    leaf
}

/// Bytes to leaf
pub fn bytes_to_leaf(bytes: &[u8]) -> Result<Leaf, SemaphoreError> {
    if bytes.len() > ELEMENT_SIZE {
        return Err(SemaphoreError::ArrayTooLong);
    }

    let mut leaf = [0u8; ELEMENT_SIZE];
    leaf[..bytes.len()].copy_from_slice(bytes);

    Ok(leaf)
}

/// Base field element from leaf
pub fn leaf_to_fq(leaf: &Leaf) -> Fq {
    Fq::from_le_bytes_mod_order(leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_conversion() {
        let test_value: [u8; 16] = [
            2, 234, 237, 230, 80, 122, 153, 195, 63, 142, 196, 130, 148, 129, 61, 227,
        ];

        let leaf = bytes_to_leaf(&test_value);
        assert!(leaf.is_ok());

        let ok_leaf = leaf.unwrap();

        let fq = leaf_to_fq(&ok_leaf);
        assert_eq!(fq, Fq::from_le_bytes_mod_order(&test_value));

        let leaf_from_fq = fq_to_leaf(&fq);
        assert_eq!(leaf_from_fq, ok_leaf);

        let test_wrong_value: [u8; 33] = [1; 33];
        let wrong_leaf = bytes_to_leaf(&test_wrong_value);
        assert_eq!(wrong_leaf, Err(SemaphoreError::ArrayTooLong));
    }

    #[test]
    fn test_hash() {
        let fq1 = Fq::from(1u64);
        let fq2 = Fq::from(2u64);

        let mut input = Vec::with_capacity(ELEMENT_SIZE * 2);
        input.extend_from_slice(&fq_to_leaf(&fq1));
        input.extend_from_slice(&fq_to_leaf(&fq2));

        let result = PoseidonHash::hash(&input);
        let result_fq = leaf_to_fq(&result[0..ELEMENT_SIZE].try_into().unwrap());

        assert_eq!(result, fq_to_leaf(&result_fq));
    }

    #[test]
    fn test_poseidon_leanimt() {
        let leaves: Vec<Vec<u8>> = (1..=4)
            .map(|i| fq_to_leaf(&Fq::from(i as u64)).to_vec())
            .collect();

        let tree = LeanIMT::new(&leaves, PoseidonHash).unwrap();

        let proof = tree.generate_proof(2).unwrap();
        assert!(LeanIMT::verify_proof(&proof));

        let single_tree =
            LeanIMT::new(&[fq_to_leaf(&Fq::from(1u64)).to_vec()], PoseidonHash).unwrap();

        let single_proof = single_tree.generate_proof(0).unwrap();
        assert!(LeanIMT::verify_proof(&single_proof));
    }
}
