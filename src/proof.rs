use anyhow::Result;
use ruint::aliases::U256;

use crate::{group::Group, identity::Identity};

type PackedGroth16Proof = [U256; 8];

// Matches the private G1Tup type in ark-circom.
pub type G1 = (U256, U256);

// Matches the private G2Tup type in ark-circom.
pub type G2 = ([U256; 2], [U256; 2]);
pub struct Groth16Proof(pub G1, pub G2, pub G1);

#[allow(dead_code)]
pub struct SemaphorProof {
    merkle_tree_depth: u16,
    merkle_tree_root: U256,
    message: String,
    nullifier: String,
    scope: String,
    points: PackedGroth16Proof,
}

pub struct Proof {}

#[allow(dead_code)]
impl Proof {
    fn generate_proof(
        _identity: Identity,
        _group: Group,
        _message: String,
        _scope: String,
        _merkle_tree_depth: u16,
    ) -> Result<SemaphorProof> {
        unimplemented!()
    }

    fn verify_proof(_proof: SemaphorProof) -> bool {
        unimplemented!()
    }

    fn pack_groth16_proof(_proof: Groth16Proof) -> PackedGroth16Proof {
        unimplemented!()
    }

    fn unpack_groth16_proof(_proof: PackedGroth16Proof) -> Groth16Proof {
        unimplemented!()
    }
}
