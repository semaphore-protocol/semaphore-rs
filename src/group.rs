use anyhow::{Ok, Result};

use ark_bn254::Fr;
use leanimt_rs::*;
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::utils::string_to_biguint;

pub struct Group {
    lean_imt: LeanIMT,
}

impl Group {
    pub fn new(leaves: Vec<LeanIMTNode>) -> Self {
        if !leaves.is_empty() {
            leaves.iter().for_each(|m| {
                assert!(
                    Group::is_valid_leaf(m.clone()),
                    "Failed to add member: value can't be 0"
                );
            });
        }

        Group {
            lean_imt: LeanIMT::new(Group::hash, leaves).unwrap(),
        }
    }

    fn hash(nodes: Vec<String>) -> String {
        let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();

        let input1 = Fr::from(string_to_biguint(&nodes[0]));
        let input2 = Fr::from(string_to_biguint(&nodes[1]));
        let hash = poseidon.hash(&[input1, input2]).unwrap();

        hash.to_string()
    }

    pub fn add_member(&mut self, member: LeanIMTNode) -> Result<()> {
        assert!(
            Group::is_valid_leaf(member.clone()),
            "Failed to add member: value can't be empty"
        );
        self.lean_imt.insert(member.to_string()).unwrap();
        Ok(())
    }

    pub fn add_members(&mut self, members: Vec<LeanIMTNode>) -> Result<()> {
        members.iter().for_each(|m| {
            assert!(
                Group::is_valid_leaf(m.clone()),
                "Failed to add member: value can't be 0"
            );
        });
        self.lean_imt.insert_many(members).unwrap();
        Ok(())
    }

    pub fn update_member(&mut self, index: usize, member: LeanIMTNode) -> Result<()> {
        let members = self.lean_imt.leaves();
        assert!(
            Group::is_valid_leaf(members[index].clone()),
            "Failed to update member: it has been removed"
        );

        self.lean_imt.update(index, member.to_string()).unwrap();
        Ok(())
    }

    pub fn remove_member(&mut self, index: usize) -> Result<()> {
        let members = self.lean_imt.leaves();
        assert!(
            Group::is_valid_leaf(members[index].clone()),
            "Failed to remove member: it has been removed"
        );

        self.lean_imt.update(index, "0".to_string()).unwrap();
        Ok(())
    }

    pub fn generate_merkle_proof(&self, index: usize) -> Result<LeanIMTMerkleProof> {
        Ok(self.lean_imt.generate_proof(index).unwrap())
    }

    pub fn root(&mut self) -> Option<LeanIMTNode> {
        self.lean_imt.root()
    }

    pub fn depth(&self) -> usize {
        self.lean_imt.depth()
    }

    pub fn members(&self) -> Vec<LeanIMTNode> {
        self.lean_imt.leaves()
    }

    pub fn size(&self) -> usize {
        self.lean_imt.size()
    }

    fn is_valid_leaf(leaf: LeanIMTNode) -> bool {
        !leaf.is_empty() && leaf.ne("0")
    }

    // TODO wait for LeanIMT support
    pub fn export(&self) -> String {
        unimplemented!("Unsupported.");
    }

    // TODO wait for LeanIMT support
    pub fn import(_json: &str) -> Self {
        unimplemented!("Unsupported.");
    }
}

#[cfg(test)]
mod tests {
    use super::Group;

    #[cfg(test)]
    mod group {
        use crate::group::Group;
        use std::panic;

        #[test]
        fn test_empty() {
            let mut group = Group::new(vec![]);

            assert_eq!(group.root(), None);
            assert_eq!(group.depth(), 0);
            assert_eq!(group.size(), 0);
        }

        #[test]
        fn test_with_a_list_members() {
            let mut group = Group::new(vec!["1".to_string(), "2".to_string(), "3".to_string()]);

            let mut group2 = Group::new(vec![]);
            group2.add_member("1".to_string()).unwrap();
            group2.add_member("2".to_string()).unwrap();
            group2.add_member("3".to_string()).unwrap();

            assert_eq!(group.root(), group2.root());
            assert_eq!(group.depth(), group2.depth());
            assert_eq!(group.size(), group2.size());
        }

        #[test]
        fn test_panic_value_is_zero() {
            let err = panic::catch_unwind(|| Group::new(vec!["1".to_string(), "0".to_string()]));

            assert!(err.is_err());
            if let Err(err) = err {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "Failed to add member: value can't be 0");
                }
            }
        }
    }

    #[cfg(test)]
    mod add_member {
        use crate::group::Group;
        use std::panic::{self, AssertUnwindSafe};

        #[test]
        fn test_add_members() {
            let mut group = Group::new(vec![]);
            group.add_member("1".to_string()).unwrap();
            assert_eq!(group.size(), 1);

            group.add_member("2".to_string()).unwrap();
            assert_eq!(group.size(), 2);
        }

        #[test]
        fn test_panic_value_is_zero() {
            let mut group = Group::new(vec![]);
            let err = panic::catch_unwind(AssertUnwindSafe(|| {
                group.add_member("0".to_string()).unwrap()
            }));

            assert!(err.is_err());
            if let Err(err) = err {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "Failed to add member: value can't be 0");
                }
            }
        }
    }

    #[cfg(test)]
    mod add_members {
        use crate::group::Group;
        use std::panic::{self, AssertUnwindSafe};

        #[test]
        fn test_add_members() {
            let mut group = Group::new(vec![]);
            group
                .add_members(vec!["1".to_string(), "2".to_string()])
                .unwrap();
            assert_eq!(group.size(), 2);
        }

        #[test]
        fn test_add_members_in_existing_group() {
            let mut group = Group::new(vec!["1".to_string()]);
            group
                .add_members(vec!["2".to_string(), "3".to_string()])
                .unwrap();
            assert_eq!(group.size(), 3);
        }

        #[test]
        fn test_panic_value_is_zero() {
            let mut group = Group::new(vec![]);
            let err = panic::catch_unwind(AssertUnwindSafe(|| {
                group
                    .add_members(vec!["1".to_string(), "0".to_string()])
                    .unwrap()
            }));

            assert!(err.is_err());
            if let Err(err) = err {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "Failed to add member: value can't be 0");
                }
            }
        }
    }

    #[cfg(test)]
    mod remove_member {
        use crate::group::Group;
        use std::panic::{self, AssertUnwindSafe};

        #[test]
        fn test_remove_member() {
            let mut group = Group::new(vec![]);
            group
                .add_members(vec!["1".to_string(), "2".to_string()])
                .unwrap();

            group.remove_member(0).unwrap();
            assert_eq!(group.size(), 2);
            assert_eq!(group.members()[0], "0".to_string())
        }

        #[test]
        fn test_panic_removed_member() {
            let mut group = Group::new(vec![]);
            group
                .add_members(vec!["1".to_string(), "2".to_string()])
                .unwrap();
            group.remove_member(0).unwrap();

            let err = panic::catch_unwind(AssertUnwindSafe(|| {
                group.remove_member(0).unwrap();
            }));

            assert!(err.is_err());
            if let Err(err) = err {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "Failed to update member: it has been removed");
                }
            }
        }
    }

    #[cfg(test)]
    mod update_member {
        use crate::group::Group;
        use std::panic::{self, AssertUnwindSafe};

        #[test]
        fn test_update_member() {
            let mut group = Group::new(vec![]);
            group
                .add_members(vec!["1".to_string(), "2".to_string()])
                .unwrap();

            group.update_member(0, "3".to_string()).unwrap();
            assert_eq!(group.size(), 2);
            assert_eq!(group.members()[0], "3".to_string())
        }

        #[test]
        fn test_update_member_with_same_value() {
            let mut group = Group::new(vec![]);
            group
                .add_members(vec!["1".to_string(), "2".to_string()])
                .unwrap();

            group.update_member(0, "1".to_string()).unwrap();
            assert_eq!(group.size(), 2);
            assert_eq!(group.members()[0], "1".to_string())
        }

        #[test]
        fn test_panic_removed_member() {
            let mut group = Group::new(vec![]);
            group
                .add_members(vec!["1".to_string(), "2".to_string()])
                .unwrap();
            group.remove_member(0).unwrap();

            let err = panic::catch_unwind(AssertUnwindSafe(|| {
                group.update_member(0, "1".to_string()).unwrap();
            }));

            assert!(err.is_err());
            if let Err(err) = err {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "Failed to update member: it has been removed");
                }
            }
        }
    }

    #[test]
    fn test_generate_merkle_proof() {
        let group = Group::new(vec!["1".to_string(), "2".to_string()]);
        let proof = group.generate_merkle_proof(0).unwrap();

        assert_eq!(proof.leaf, "1".to_string())
    }
}
