//! Group module integration tests
//!
//! The constants were generated using the TypeScript Semaphore V4 implementation.
//!
//! - https://github.com/brech1/sem-test-values
//!
//! All byte values are in big endian format.

// Initial Members Group
const INITIAL_MEMBERS_ROOT_STR: &str =
    "9130007428544271791338115123915220727467361888518863494831750410170124565752";
const INITIAL_MEMBERS: [&str; 3] = [
    "100000000000000000000000000000",
    "200000000000000000000000000000",
    "300000000000000000000000000000",
];

// Add Members Group
const ADD_MEMBERS_ROOT_STR: &str =
    "6982876087413765702847094329357954484405070236699469184558186311499667292397";
const ADDED_MEMBERS: [&str; 2] = [
    "2000000000000000000000000000000",
    "20000000000000000000000000000001",
];

// Index Lookup Constants
const INDEX_LOOKUP_EXISTING_MEMBER: &str = "200000000000000000000000000000";
const INDEX_LOOKUP_EXISTING_INDEX: usize = 1;
const INDEX_LOOKUP_NON_EXISTING_MEMBER: &str = "999999999999999999999999999999";

// Merkle Proof Constants
const MERKLE_PROOF_ROOT_STR: &str =
    "9130007428544271791338115123915220727467361888518863494831750410170124565752";
const MERKLE_PROOF_LEAF: &str = "100000000000000000000000000000";
const MERKLE_PROOF_INDEX: usize = 0;
const MERKLE_PROOF_SIBLINGS: [&str; 2] = [
    "200000000000000000000000000000",
    "300000000000000000000000000000",
];
const MERKLE_PROOF_INVALID_INDEX: usize = 999;

// Update Member Group
const UPDATE_MEMBER_ROOT_STR: &str =
    "11698254358747948552441141621532898036199784096354171759939257930719916843614";
const UPDATE_MEMBER_BEFORE: [&str; 3] = [
    "100000000000000000000000000000",
    "200000000000000000000000000000",
    "300000000000000000000000000000",
];
const UPDATE_MEMBER_INDEX: usize = 1;
const UPDATE_NEW_VALUE: &str = "3000000000000000000000000000000";

// Sequential Operations Group
const SEQUENTIAL_OPS_ROOT_STR: &str =
    "4382838098257486169531967821059829509336344667844562046304959594145268687258";
const SEQUENTIAL_OPS_INITIAL: [&str; 3] = [
    "100000000000000000000000000000",
    "200000000000000000000000000000",
    "300000000000000000000000000000",
];
const SEQUENTIAL_OPS_MEMBERS: [&str; 4] = [
    "100000000000000000000000000000",
    "500000000000000000000000000000",
    "0",
    "400000000000000000000000000000",
];

#[cfg(test)]
mod group {
    use super::*;
    use ark_ed_on_bn254::Fq;
    use ark_ff::{BigInteger, PrimeField};
    use num_bigint::BigInt;
    use semaphore_protocol::group::{EMPTY_ELEMENT, Element, Group};
    use std::str::FromStr;

    fn str_to_element(s: &str) -> Element {
        let big_int = BigInt::from_str(s).unwrap();
        let fq = Fq::from_le_bytes_mod_order(&big_int.to_bytes_le().1);

        let mut element = EMPTY_ELEMENT;

        let bytes = fq.into_bigint().to_bytes_le();
        element[..bytes.len()].copy_from_slice(&bytes);
        element
    }

    fn leaf_to_str(leaf: &[u8]) -> String {
        Fq::from_le_bytes_mod_order(leaf).to_string()
    }

    #[test]
    fn empty_group() {
        let group = Group::default();

        assert_eq!(group.root(), None);
        assert_eq!(group.depth(), 0);
        assert_eq!(group.size(), 0);
        assert_eq!(group.members(), Vec::<Element>::new());
    }

    #[test]
    fn initial_members() {
        let elements: Vec<Element> = INITIAL_MEMBERS.iter().map(|s| str_to_element(s)).collect();
        let group = Group::new(&elements).unwrap();

        let root = group.root().unwrap();
        assert_eq!(leaf_to_str(&root), INITIAL_MEMBERS_ROOT_STR);
        assert_eq!(group.depth(), 2);
        assert_eq!(group.size(), 3);

        let group_members: Vec<String> = group.members().iter().map(|l| leaf_to_str(l)).collect();
        assert_eq!(
            group_members,
            INITIAL_MEMBERS
                .iter()
                .map(|&s| s.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn add_members() {
        let mut group = Group::default();
        let elements: Vec<Element> = ADDED_MEMBERS.iter().map(|s| str_to_element(s)).collect();
        group.add_members(&elements).unwrap();

        let root = group.root().unwrap();
        assert_eq!(leaf_to_str(&root), ADD_MEMBERS_ROOT_STR);
        assert_eq!(group.depth(), 1);
        assert_eq!(group.size(), 2);

        let group_members: Vec<String> = group.members().iter().map(|l| leaf_to_str(l)).collect();
        assert_eq!(
            group_members,
            ADDED_MEMBERS
                .iter()
                .map(|&s| s.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn index_lookup() {
        let elements: Vec<Element> = INITIAL_MEMBERS.iter().map(|s| str_to_element(s)).collect();
        let group = Group::new(&elements).unwrap();

        assert_eq!(
            group.index_of(str_to_element(INDEX_LOOKUP_EXISTING_MEMBER)),
            Some(INDEX_LOOKUP_EXISTING_INDEX)
        );
        assert_eq!(
            group.index_of(str_to_element(INDEX_LOOKUP_NON_EXISTING_MEMBER)),
            None
        );
    }

    #[test]
    fn merkle_proof() {
        let elements: Vec<Element> = INITIAL_MEMBERS.iter().map(|s| str_to_element(s)).collect();
        let group = Group::new(&elements).unwrap();

        let proof = group.generate_proof(MERKLE_PROOF_INDEX).unwrap();

        assert_eq!(leaf_to_str(&proof.root), MERKLE_PROOF_ROOT_STR);
        assert_eq!(leaf_to_str(&proof.leaf), MERKLE_PROOF_LEAF);
        assert_eq!(proof.index, MERKLE_PROOF_INDEX);

        let sibling_strs: Vec<String> = proof.siblings.iter().map(|s| leaf_to_str(s)).collect();
        assert_eq!(
            sibling_strs,
            MERKLE_PROOF_SIBLINGS
                .iter()
                .map(|&s| s.to_string())
                .collect::<Vec<_>>()
        );

        assert_eq!(Group::verify_proof(&proof), true);

        let mut invalid_proof = proof.clone();
        invalid_proof.leaf = str_to_element(INDEX_LOOKUP_NON_EXISTING_MEMBER);
        assert_eq!(Group::verify_proof(&invalid_proof), false);

        assert!(group.generate_proof(MERKLE_PROOF_INVALID_INDEX).is_err());
    }

    #[test]
    fn update_member() {
        let elements: Vec<Element> = UPDATE_MEMBER_BEFORE
            .iter()
            .map(|s| str_to_element(s))
            .collect();
        let mut group = Group::new(&elements).unwrap();

        group
            .update_member(UPDATE_MEMBER_INDEX, str_to_element(UPDATE_NEW_VALUE))
            .unwrap();

        let root = group.root().unwrap();

        assert_eq!(leaf_to_str(&root), UPDATE_MEMBER_ROOT_STR);
        assert_eq!(
            leaf_to_str(&group.members()[UPDATE_MEMBER_INDEX]),
            UPDATE_NEW_VALUE
        );
        assert_eq!(group.depth(), 2);
        assert_eq!(group.size(), 3);
    }

    #[test]
    fn sequential_operations() {
        let mut group = Group::default();
        let initial_elements: Vec<Element> = SEQUENTIAL_OPS_INITIAL
            .iter()
            .map(|s| str_to_element(s))
            .collect();

        group.add_members(&initial_elements).unwrap();
        group
            .add_member(str_to_element("400000000000000000000000000000"))
            .unwrap();
        group
            .update_member(1, str_to_element("500000000000000000000000000000"))
            .unwrap();
        group.remove_member(2).unwrap();

        let root = group.root().unwrap();
        assert_eq!(leaf_to_str(&root), SEQUENTIAL_OPS_ROOT_STR);
        assert_eq!(group.depth(), 2);
        assert_eq!(group.size(), 4);

        let group_members: Vec<String> = group.members().iter().map(|l| leaf_to_str(l)).collect();
        assert_eq!(
            group_members,
            SEQUENTIAL_OPS_MEMBERS
                .iter()
                .map(|&s| s.to_string())
                .collect::<Vec<_>>()
        );
    }
}
