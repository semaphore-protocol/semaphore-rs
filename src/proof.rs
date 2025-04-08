use anyhow::{bail, Ok, Result};
use circom_prover::{
    prover::{
        circom::{self, CURVE_BN254, G1, G2, PROTOCOL_GROTH16},
        CircomProof, ProofLib, PublicInputs,
    },
    witness::WitnessFn,
    CircomProver,
};
use leanimt_rs::LeanIMTNode;
use num_bigint::BigUint;
use num_traits::{identities::One, Zero};
use std::{collections::HashMap, str::FromStr};

use crate::{
    group::{Group, MerkleProof},
    identity::Identity,
    utils::{hash, to_big_uint},
    MAX_TREE_DEPTH, MIN_TREE_DEPTH,
};

pub type PackedGroth16Proof = [BigUint; 8];

// Prepare witness generator
rust_witness::witness!(semaphore);

#[derive(Debug, Clone)]
pub struct SemaphoreProof {
    merkle_tree_depth: u16,
    merkle_tree_root: BigUint,
    message: BigUint,
    nullifier: BigUint,
    scope: BigUint,
    points: PackedGroth16Proof,
}

pub enum GroupOrMerkleProof {
    Group(Group),
    MerkleProof(MerkleProof),
}

impl GroupOrMerkleProof {
    fn merkle_proof(&self, leaf: &LeanIMTNode) -> MerkleProof {
        match self {
            GroupOrMerkleProof::Group(group) => {
                let idx = group.index_of(leaf).unwrap();
                group.generate_merkle_proof(idx).unwrap()
            }
            GroupOrMerkleProof::MerkleProof(proof) => {
                // A workaourd because `LeanIMTMerkleProof` doesn"t impl `clone` trait
                MerkleProof {
                    root: proof.root.clone(),
                    leaf: proof.leaf.clone(),
                    index: proof.index.clone(),
                    siblings: proof.siblings.clone(),
                }
            }
        }
    }
}

pub struct Proof {}

#[allow(dead_code)]
impl Proof {
    pub fn generate_proof(
        identity: Identity,
        group: GroupOrMerkleProof,
        message: String,
        scope: String,
        merkle_tree_depth: u16,
    ) -> Result<SemaphoreProof> {
        // check tree depth
        if merkle_tree_depth < MIN_TREE_DEPTH || merkle_tree_depth > MAX_TREE_DEPTH {
            bail!(format!(
                "The tree depth must be a number between {} and {}",
                MIN_TREE_DEPTH, MAX_TREE_DEPTH
            ));
        }

        // TODO auto-download
        let zkey_path = "./test-vector/semaphore.zkey";

        let merkle_proof = group.merkle_proof(&identity.commitment.to_string());
        let merkle_proof_length = merkle_proof.siblings.len();

        // The index must be converted to a list of indices, 1 for each tree level.
        // The missing siblings can be set to 0, as they won"t be used in the circuit.
        let mut merkle_proof_indices = Vec::new();
        let mut merkle_proof_siblings = Vec::new();
        for i in 0..merkle_tree_depth {
            merkle_proof_indices.push((merkle_proof.index >> i) & 1);

            if let Some(sibling) = merkle_proof.siblings.get(i as usize) {
                merkle_proof_siblings.push(sibling.clone());
            } else {
                merkle_proof_siblings.push("0".to_string());
            }
        }

        let scope_uint = to_big_uint(&scope);
        let message_uint = to_big_uint(&message);
        let inputs = HashMap::from([
            (
                "secret".to_string(),
                vec![identity.secret_scalar.to_string()],
            ),
            (
                "merkleProofLength".to_string(),
                vec![merkle_proof_length.to_string()],
            ),
            (
                "merkleProofIndices".to_string(),
                merkle_proof_indices.iter().map(|i| i.to_string()).collect(),
            ),
            ("merkleProofSiblings".to_string(), merkle_proof_siblings),
            ("scope".to_string(), vec![hash(scope_uint.clone())]),
            ("message".to_string(), vec![hash(message_uint.clone())]),
        ]);

        let circom_proof = CircomProver::prove(
            ProofLib::Arkworks,
            WitnessFn::RustWitness(semaphore_witness),
            serde_json::to_string(&inputs).unwrap(),
            zkey_path.to_string(),
        )?;

        Ok(SemaphoreProof {
            merkle_tree_depth,
            merkle_tree_root: BigUint::from_str(merkle_proof.root.as_ref()).unwrap(),
            message: message_uint,
            nullifier: circom_proof.pub_inputs.0.get(1).unwrap().clone(),
            scope: scope_uint,
            points: Self::pack_groth16_proof(circom_proof.proof),
        })
    }

    pub fn verify_proof(proof: SemaphoreProof) -> bool {
        // check tree depth
        if proof.merkle_tree_depth < MIN_TREE_DEPTH || proof.merkle_tree_depth > MAX_TREE_DEPTH {
            panic!("The tree depth must be a number between and");
        }

        // TODO auto-download
        let zkey_path = "./test-vector/semaphore.zkey";

        let scope = BigUint::from_str(hash(proof.scope).as_str()).unwrap();
        let message = BigUint::from_str(hash(proof.message).as_str()).unwrap();

        let pub_inputs = PublicInputs(vec![
            proof.merkle_tree_root,
            proof.nullifier,
            message,
            scope,
        ]);
        let p = CircomProof {
            proof: Self::unpack_groth16_proof(proof.points),
            pub_inputs,
        };
        CircomProver::verify(ProofLib::Arkworks, p, zkey_path.to_string()).unwrap()
    }

    pub fn pack_groth16_proof(p: circom::Proof) -> PackedGroth16Proof {
        [
            p.a.x,
            p.a.y,
            p.b.x[0].clone(),
            p.b.x[1].clone(),
            p.b.y[0].clone(),
            p.b.y[1].clone(),
            p.c.x,
            p.c.y,
        ]
    }

    pub fn unpack_groth16_proof(packed: PackedGroth16Proof) -> circom::Proof {
        let a = G1 {
            x: packed[0].clone(),
            y: packed[1].clone(),
            z: BigUint::one(),
        };
        let b = G2 {
            x: [packed[2].clone(), packed[3].clone()],
            y: [packed[4].clone(), packed[5].clone()],
            z: [BigUint::one(), BigUint::zero()],
        };
        let c = G1 {
            x: packed[6].clone(),
            y: packed[7].clone(),
            z: BigUint::one(),
        };

        circom::Proof {
            a,
            b,
            c,
            protocol: PROTOCOL_GROTH16.to_string(),
            curve: CURVE_BN254.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num_bigint::BigUint;

    use super::{GroupOrMerkleProof, Proof};
    use crate::{group::Group, identity::Identity, proof::SemaphoreProof};

    const TREE_DEPTH: usize = 10;
    const MESSAGE: &str = "Hello world";
    const SCOPE: &str = "Scope";

    #[test]
    fn test_proof() {
        let identity = Identity::new("secret".as_bytes().to_vec());
        let group = Group::new(vec![
            "1".to_string(),
            "2".to_string(),
            identity.commitment.to_string(),
        ]);

        let proof = Proof::generate_proof(
            identity,
            GroupOrMerkleProof::Group(group),
            MESSAGE.to_string(),
            SCOPE.to_string(),
            TREE_DEPTH as u16,
        )
        .unwrap();

        assert!(Proof::verify_proof(proof));
    }
}
*/
