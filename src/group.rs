use crate::error::SemaphoreError;
use ark_ed_on_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use zk_kit_lean_imt::{
    hashed_tree::{HashedLeanIMT, LeanIMTHasher},
    lean_imt::MerkleProof,
};

/// Size of elements in bytes
pub const ELEMENT_SIZE: usize = 32;

/// Leaf type representing a 32-byte array
pub type Leaf = [u8; ELEMENT_SIZE];

/// Poseidon LeanIMT hasher
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoseidonHash;

impl LeanIMTHasher for PoseidonHash {
    fn hash(input: &[u8]) -> Vec<u8> {
        let hash = Poseidon::<Fq>::new_circom(2)
            .expect("Failed to initialize Poseidon")
            .hash(&[
                Fq::from_le_bytes_mod_order(&input[..ELEMENT_SIZE]),
                Fq::from_le_bytes_mod_order(&input[ELEMENT_SIZE..]),
            ])
            .expect("Poseidon hash failed");

        fq_to_leaf(&hash).to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub tree: HashedLeanIMT<PoseidonHash>,
}

impl Default for Group {
    fn default() -> Self {
        Group {
            tree: HashedLeanIMT::<PoseidonHash>::new(&[], PoseidonHash).unwrap(),
        }
    }
}

impl Group {
    /// Creates a new instance of the Group with optional initial members
    pub fn new(members: &[Leaf]) -> Result<Self, SemaphoreError> {
        let leaves: Vec<Vec<u8>> = match members.len() {
            0 => Vec::new(),
            _ => {
                let mut leaves = Vec::new();

                for &member in members {
                    if member == [0u8; ELEMENT_SIZE] {
                        return Err(SemaphoreError::EmptyLeaf);
                    }

                    leaves.push(member.to_vec());
                }
                leaves
            }
        };

        Ok(Group {
            tree: HashedLeanIMT::<PoseidonHash>::new(&leaves, PoseidonHash)?,
        })
    }

    /// Returns the root hash of the tree, or None if the tree is empty
    pub fn root(&self) -> Option<Leaf> {
        match self.tree.root() {
            Some(r) => bytes_to_leaf(&r).ok(),
            None => None,
        }
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
    pub fn members(&self) -> Vec<Leaf> {
        self.tree
            .leaves()
            .iter()
            .map(|v| v.as_slice().try_into().unwrap())
            .collect()
    }

    /// Returns the index of a member if it exists
    pub fn index_of(&self, member: Leaf) -> Option<usize> {
        self.tree.index_of(&member)
    }

    /// Adds a new member to the group
    pub fn add_member(&mut self, member: Leaf) -> Result<(), SemaphoreError> {
        if member == [0u8; ELEMENT_SIZE] {
            return Err(SemaphoreError::EmptyLeaf);
        }

        self.tree.insert(&member);
        Ok(())
    }

    /// Adds a set of members to the group
    pub fn add_members(&mut self, members: Vec<Leaf>) -> Result<(), SemaphoreError> {
        let mut members_vec: Vec<Vec<u8>> = Vec::new();

        for member in members {
            if member == [0u8; ELEMENT_SIZE] {
                return Err(SemaphoreError::EmptyLeaf);
            }

            members_vec.push(member.to_vec());
        }

        self.tree.insert_many(&members_vec)?;

        Ok(())
    }

    /// Updates a group member
    pub fn update_member(&mut self, index: usize, member: Leaf) -> Result<(), SemaphoreError> {
        if self.members()[index] == [0u8; ELEMENT_SIZE] {
            return Err(SemaphoreError::RemovedMember);
        }

        self.tree.update(index, &member)?;
        Ok(())
    }

    /// Removes a member from the group
    pub fn remove_member(&mut self, index: usize) -> Result<(), SemaphoreError> {
        if self.members()[index] == [0u8; ELEMENT_SIZE] {
            return Err(SemaphoreError::AlreadyRemovedMember);
        }

        self.tree.update(index, &[0u8; ELEMENT_SIZE])?;
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
        HashedLeanIMT::<PoseidonHash>::verify_proof(proof)
    }
}

/// Converts a byte array to a Leaf
pub fn bytes_to_leaf(bytes: &[u8]) -> Result<Leaf, SemaphoreError> {
    if bytes.len() > ELEMENT_SIZE {
        return Err(SemaphoreError::InputSizeExceeded(bytes.len()));
    }

    let mut leaf = [0; ELEMENT_SIZE];
    leaf[..bytes.len()].copy_from_slice(bytes);

    Ok(leaf)
}

/// Converts a scalar to a Leaf
pub fn fq_to_leaf(fq: &Fq) -> Leaf {
    let mut leaf = [0; ELEMENT_SIZE];
    let bytes = fq.into_bigint().to_bytes_le();
    leaf[..bytes.len()].copy_from_slice(&bytes);
    leaf
}

/// Converts a Leaf to a scalar
pub fn leaf_to_fq(leaf: &Leaf) -> Fq {
    Fq::from_le_bytes_mod_order(leaf)
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
        let leaf = bytes_to_leaf(&test_bytes).unwrap();
        let fq = leaf_to_fq(&leaf);
        let leaf_back = fq_to_leaf(&fq);

        assert_eq!(leaf, leaf_back);
        assert_eq!(fq, Fq::from_le_bytes_mod_order(&test_bytes));
        assert_eq!(
            bytes_to_leaf(&[0; 33]),
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

        let mut group2 = Group::new(&[]).unwrap();
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

        group.add_members(vec![member1, member2]).unwrap();

        assert_eq!(group.size(), 2);
    }

    #[test]
    fn test_add_members_with_zero() {
        let mut group = Group::default();
        let member1 = [1; 32];
        let zero = [0u8; ELEMENT_SIZE];

        let result = group.add_members(vec![member1, zero]);

        assert!(result.is_err());
        assert_eq!(result, Err(SemaphoreError::EmptyLeaf));
    }

    #[test]
    fn test_index_of() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(vec![member1, member2]).unwrap();
        let index = group.index_of(member2);

        assert_eq!(index, Some(1));
    }

    #[test]
    fn test_update_member() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(vec![member1, member2]).unwrap();

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

        group.add_members(vec![member1, member2]).unwrap();
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

        group.add_members(vec![member1, member2]).unwrap();
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

        group.add_members(vec![member1, member2]).unwrap();
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

        group.add_members(vec![member1, member2]).unwrap();

        let proof = group.generate_proof(0).unwrap();
        assert_eq!(proof.leaf, member1);
    }

    #[test]
    fn test_verify_proof() {
        let member1 = [1; 32];
        let member2 = [2; 32];
        let mut group = Group::default();

        group.add_members(vec![member1, member2]).unwrap();

        let proof_0 = group.generate_proof(0).unwrap();
        assert_eq!(Group::verify_proof(&proof_0), true);

        let mut proof_1 = group.generate_proof(1).unwrap();
        assert_eq!(Group::verify_proof(&proof_1), true);

        proof_1.leaf = member1.to_vec();
        assert_eq!(Group::verify_proof(&proof_1), false);
    }
}
