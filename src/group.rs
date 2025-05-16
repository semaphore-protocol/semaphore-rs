//! Group module
//!
//! This module is a wrapper around the `HashedLeanIMT` struct with some utility methods.
//!
//! Leaves and nodes are the same size, 32 bytes.

use crate::error::SemaphoreError;
use ark_ed_on_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};
use lean_imt::hashed_tree::{HashedLeanIMT, LeanIMTHasher};
use light_poseidon::{Poseidon, PoseidonHasher};

/// Size of nodes and leaves in bytes
pub const ELEMENT_SIZE: usize = 32;
/// Empty element
pub const EMPTY_ELEMENT: Element = [0u8; ELEMENT_SIZE];

/// Element type alias
pub type Element = [u8; ELEMENT_SIZE];

/// Merkle proof alias
pub type MerkleProof = lean_imt::lean_imt::MerkleProof<ELEMENT_SIZE>;

/// Poseidon LeanIMT hasher
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PoseidonHash;

impl LeanIMTHasher<ELEMENT_SIZE> for PoseidonHash {
    fn hash(input: &[u8]) -> [u8; ELEMENT_SIZE] {
        let hash = Poseidon::<Fq>::new_circom(2)
            .expect("Failed to initialize Poseidon")
            .hash(&[
                Fq::from_le_bytes_mod_order(&input[..ELEMENT_SIZE]),
                Fq::from_le_bytes_mod_order(&input[ELEMENT_SIZE..]),
            ])
            .expect("Poseidon hash failed");

        let mut hash_bytes = [0u8; ELEMENT_SIZE];
        hash_bytes.copy_from_slice(&hash.into_bigint().to_bytes_le());

        hash_bytes
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Group {
    /// Hashed LeanIMT
    pub tree: HashedLeanIMT<ELEMENT_SIZE, PoseidonHash>,
}

impl Group {
    /// Creates a new instance of the Group with optional initial members
    pub fn new(members: &[Element]) -> Result<Self, SemaphoreError> {
        if members.is_empty() {
            return Ok(Group {
                tree: HashedLeanIMT::<ELEMENT_SIZE, PoseidonHash>::new(&[], PoseidonHash)?,
            });
        }

        for &member in members {
            if member == EMPTY_ELEMENT {
                return Err(SemaphoreError::EmptyLeaf);
            }
        }

        Ok(Group {
            tree: HashedLeanIMT::<ELEMENT_SIZE, PoseidonHash>::new(members, PoseidonHash)?,
        })
    }

    /// Returns the root hash of the tree, or None if the tree is empty
    pub fn root(&self) -> Option<Element> {
        self.tree.root()
    }

    /// Returns the depth of the tree
    pub fn depth(&self) -> usize {
        self.tree.depth()
    }

    /// Returns the size of the tree (number of leaves)
    pub fn size(&self) -> usize {
        self.tree.size()
    }

    /// Returns the group members
    pub fn members(&self) -> Vec<Element> {
        self.tree
            .leaves()
            .iter()
            .map(|v| v.as_slice().try_into().unwrap())
            .collect()
    }

    /// Returns the index of a member if it exists
    pub fn index_of(&self, member: Element) -> Option<usize> {
        self.tree.index_of(&member)
    }

    /// Adds a new member to the group
    pub fn add_member(&mut self, member: Element) -> Result<(), SemaphoreError> {
        if member == EMPTY_ELEMENT {
            return Err(SemaphoreError::EmptyLeaf);
        }

        self.tree.insert(&member);
        Ok(())
    }

    /// Adds a set of members to the group
    pub fn add_members(&mut self, members: &[Element]) -> Result<(), SemaphoreError> {
        for &member in members {
            if member == EMPTY_ELEMENT {
                return Err(SemaphoreError::EmptyLeaf);
            }
        }

        self.tree.insert_many(members)?;
        Ok(())
    }

    /// Updates a group member
    pub fn update_member(&mut self, index: usize, member: Element) -> Result<(), SemaphoreError> {
        if self.members()[index] == EMPTY_ELEMENT {
            return Err(SemaphoreError::RemovedMember);
        }

        self.tree.update(index, &member)?;
        Ok(())
    }

    /// Removes a member from the group
    pub fn remove_member(&mut self, index: usize) -> Result<(), SemaphoreError> {
        if self.members()[index] == EMPTY_ELEMENT {
            return Err(SemaphoreError::AlreadyRemovedMember);
        }

        self.tree.update(index, &EMPTY_ELEMENT)?;
        Ok(())
    }

    /// Creates a proof of membership for a member
    pub fn generate_proof(&self, index: usize) -> Result<MerkleProof, SemaphoreError> {
        self.tree
            .generate_proof(index)
            .map_err(SemaphoreError::LeanIMTError)
    }

    /// Verifies a proof of membership for a member
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        HashedLeanIMT::<ELEMENT_SIZE, PoseidonHash>::verify_proof(proof)
    }
}

#[cfg(feature = "serde")]
impl Group {
    /// Exports the LeanIMT tree to a JSON.
    pub fn export(&self) -> Result<String, SemaphoreError> {
        serde_json::to_string(&self.tree.tree())
            .map_err(|e| SemaphoreError::SerializationError(e.to_string()))
    }

    /// Imports a Group from a JSON string representing a LeanIMT tree.
    pub fn import(json: &str) -> Result<Self, SemaphoreError> {
        let lean_imt_tree: lean_imt::lean_imt::LeanIMT<ELEMENT_SIZE> =
            serde_json::from_str(json)
                .map_err(|e| SemaphoreError::SerializationError(e.to_string()))?;

        Ok(Group {
            tree: HashedLeanIMT::new_from_tree(lean_imt_tree, PoseidonHash),
        })
    }
}

/// Converts a byte array to an element
pub fn bytes_to_element(bytes: &[u8]) -> Result<Element, SemaphoreError> {
    if bytes.len() > ELEMENT_SIZE {
        return Err(SemaphoreError::InputSizeExceeded(bytes.len()));
    }

    let mut element = EMPTY_ELEMENT;
    element[..bytes.len()].copy_from_slice(bytes);

    Ok(element)
}

/// Converts a scalar to an element
pub fn fq_to_element(fq: &Fq) -> Element {
    let mut element = EMPTY_ELEMENT;
    let bytes = fq.into_bigint().to_bytes_le();
    element[..bytes.len()].copy_from_slice(&bytes);
    element
}

/// Converts an element to a scalar
pub fn element_to_fq(element: &Element) -> Fq {
    Fq::from_le_bytes_mod_order(element)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversions() {
        let test_bytes = [
            59, 227, 30, 252, 212, 244, 251, 255, 228, 174, 31, 212, 161, 61, 184, 169, 200, 50, 7,
            84, 65, 96,
        ];
        let element = bytes_to_element(&test_bytes).unwrap();
        let fq = element_to_fq(&element);
        let element_back = fq_to_element(&fq);

        assert_eq!(element, element_back);
        assert_eq!(fq, Fq::from_le_bytes_mod_order(&test_bytes));
        assert_eq!(
            bytes_to_element(&[0; 33]),
            Err(SemaphoreError::InputSizeExceeded(33))
        );
    }

    #[test]
    fn test_create_empty_group() {
        let group = Group::default();

        assert_eq!(group.root(), None);
        assert_eq!(group.depth(), 0);
        assert_eq!(group.size(), 0);
    }

    #[test]
    fn test_create_group_with_members() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let member3 = [3; 32];

        let group1 = Group::new(&[member1, member2, member3]).unwrap();

        let mut group2 = Group::default();
        group2.add_member(member1).unwrap();
        group2.add_member(member2).unwrap();
        group2.add_member(member3).unwrap();

        assert_eq!(group1.root(), group2.root());
        assert_eq!(group1.depth(), 2);
        assert_eq!(group1.size(), 3);
    }

    #[test]
    fn test_create_group_with_zero_member() {
        let member1 = [1; 32];
        let zero = [0u8; ELEMENT_SIZE];

        let result = Group::new(&[member1, zero]);

        assert!(result.is_err());
        assert_eq!(result, Err(SemaphoreError::EmptyLeaf));
    }

    #[test]
    fn test_add_member() {
        let mut group = Group::default();
        let member = [1; 32];
        group.add_member(member).unwrap();

        assert_eq!(group.size(), 1);
    }

    #[test]
    fn test_add_zero_member() {
        let mut group = Group::default();
        let zero = [0u8; ELEMENT_SIZE];
        let result = group.add_member(zero);

        assert!(result.is_err());
        assert_eq!(result, Err(SemaphoreError::EmptyLeaf));
    }

    #[test]
    fn test_add_members() {
        let mut group = Group::default();
        let member1 = [1; 32];
        let member2 = [2; 32];

        group.add_members(&[member1, member2]).unwrap();

        assert_eq!(group.size(), 2);
    }

    #[test]
    fn test_add_members_with_zero() {
        let mut group = Group::default();
        let member1 = [1; 32];
        let zero = [0u8; ELEMENT_SIZE];

        let result = group.add_members(&[member1, zero]);

        assert!(result.is_err());
        assert_eq!(result, Err(SemaphoreError::EmptyLeaf));
    }

    #[test]
    fn test_index_of() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(&[member1, member2]).unwrap();
        let index = group.index_of(member2);

        assert_eq!(index, Some(1));
    }

    #[test]
    fn test_update_member() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(&[member1, member2]).unwrap();

        group.update_member(0, member1).unwrap();
        assert_eq!(group.size(), 2);

        let members = group.members();
        assert_eq!(members[0], member1);
    }

    #[test]
    fn test_update_removed_member() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(&[member1, member2]).unwrap();
        group.remove_member(0).unwrap();

        let result = group.update_member(0, member1);
        assert!(result.is_err());
        assert_eq!(result, Err(SemaphoreError::RemovedMember));
    }

    #[test]
    fn test_remove_member() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(&[member1, member2]).unwrap();
        group.remove_member(0).unwrap();

        let members = group.members();
        assert_eq!(members[0], [0u8; ELEMENT_SIZE]);
        assert_eq!(group.size(), 2);
    }

    #[test]
    fn test_remove_member_already_removed() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(&[member1, member2]).unwrap();
        group.remove_member(0).unwrap();

        let result = group.remove_member(0);

        assert!(result.is_err());
        assert_eq!(result, Err(SemaphoreError::AlreadyRemovedMember));
    }

    #[test]
    fn test_generate_merkle_proof() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(&[member1, member2]).unwrap();

        let proof = group.generate_proof(0).unwrap();
        assert_eq!(proof.leaf, member1);
    }

    #[test]
    fn test_verify_proof() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(&[member1, member2]).unwrap();

        let proof_0 = group.generate_proof(0).unwrap();
        assert_eq!(Group::verify_proof(&proof_0), true);

        let mut proof_1 = group.generate_proof(1).unwrap();
        assert_eq!(Group::verify_proof(&proof_1), true);

        proof_1.leaf = member1;
        assert_eq!(Group::verify_proof(&proof_1), false);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_export_import() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let member3 = [3; 32];
        let group = Group::new(&[member1, member2, member3]).unwrap();

        let json = group.export().unwrap();
        let imported_group = Group::import(&json).unwrap();

        assert_eq!(group, imported_group);
    }
}
