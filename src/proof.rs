use crate::{
    MAX_TREE_DEPTH, MIN_TREE_DEPTH,
    group::{EMPTY_ELEMENT, Element, Group, MerkleProof},
    identity::Identity,
    utils::{hash, to_big_uint, to_element},
};
use anyhow::{Ok, Result, bail};
use circom_prover::{
    CircomProver,
    prover::{
        CircomProof, ProofLib, PublicInputs,
        circom::{self, CURVE_BN254, G1, G2, PROTOCOL_GROTH16},
    },
    witness::WitnessFn,
};
use num_bigint::BigUint;
use num_traits::{Zero, identities::One};
use std::{collections::HashMap, str::FromStr};

// Prepare witness generator
rust_witness::witness!(semaphore);

pub type PackedGroth16Proof = [BigUint; 8];

const ZKEY_PATH: &str = "./zkey/semaphore.zkey";

pub enum GroupOrMerkleProof {
    Group(Group),
    MerkleProof(MerkleProof),
}

impl GroupOrMerkleProof {
    fn merkle_proof(&self, leaf: &Element) -> MerkleProof {
        match self {
            GroupOrMerkleProof::Group(group) => {
                let idx = group.index_of(*leaf).expect("The identity does not exist");
                group.generate_proof(idx).unwrap()
            }
            GroupOrMerkleProof::MerkleProof(proof) => proof.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SemaphoreProof {
    merkle_tree_depth: u16,
    merkle_tree_root: BigUint,
    message: BigUint,
    nullifier: BigUint,
    scope: BigUint,
    points: PackedGroth16Proof,
}

pub struct Proof {}

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

        let merkle_proof = group.merkle_proof(&to_element(identity.commitment().clone()));
        let merkle_proof_length = merkle_proof.siblings.len();

        // The index must be converted to a list of indices, 1 for each tree level.
        // The missing siblings can be set to 0, as they won"t be used in the circuit.
        let mut merkle_proof_indices = Vec::new();
        let mut merkle_proof_siblings = Vec::<Element>::new();
        for i in 0..merkle_tree_depth {
            merkle_proof_indices.push((merkle_proof.index >> i) & 1);

            if let Some(sibling) = merkle_proof.siblings.get(i as usize) {
                merkle_proof_siblings.push(sibling.clone());
            } else {
                merkle_proof_siblings.push(EMPTY_ELEMENT);
            }
        }

        let scope_uint = to_big_uint(&scope);
        let message_uint = to_big_uint(&message);
        let inputs = HashMap::from([
            (
                "secret".to_string(),
                vec![identity.secret_scalar().to_string()],
            ),
            (
                "merkleProofLength".to_string(),
                vec![merkle_proof_length.to_string()],
            ),
            (
                "merkleProofIndices".to_string(),
                merkle_proof_indices.iter().map(|i| i.to_string()).collect(),
            ),
            (
                "merkleProofSiblings".to_string(),
                merkle_proof_siblings
                    .iter()
                    .map(|s| BigUint::from_bytes_le(s.to_vec().as_ref()).to_string())
                    .collect(),
            ),
            ("scope".to_string(), vec![hash(scope_uint.clone())]),
            ("message".to_string(), vec![hash(message_uint.clone())]),
        ]);

        let circom_proof = CircomProver::prove(
            ProofLib::Arkworks,
            WitnessFn::RustWitness(semaphore_witness),
            serde_json::to_string(&inputs).unwrap(),
            ZKEY_PATH.to_string(),
        )?;

        Ok(SemaphoreProof {
            merkle_tree_depth,
            merkle_tree_root: BigUint::from_bytes_le(merkle_proof.root.as_ref()),
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

        CircomProver::verify(ProofLib::Arkworks, p, ZKEY_PATH.to_string()).unwrap()
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
    use super::*;
    use crate::{
        group::{Element, Group},
        identity::Identity,
        proof::SemaphoreProof,
    };
    use num_bigint::BigUint;
    use std::str::FromStr;

    const TREE_DEPTH: usize = 10;
    const MESSAGE: &str = "Hello world";
    const SCOPE: &str = "Scope";

    const MEMBER1: Element = [1; 32];
    const MEMBER2: Element = [2; 32];

    #[cfg(test)]
    mod gen_proof {
        use super::*;
        use std::panic::{self, AssertUnwindSafe};

        #[test]
        fn test_proof() {
            let identity = Identity::new("secret".as_bytes());
            let group =
                Group::new(&[MEMBER1, MEMBER2, to_element(*identity.commitment())]).unwrap();
            let root = group.root().unwrap();

            let proof = Proof::generate_proof(
                identity,
                GroupOrMerkleProof::Group(group),
                MESSAGE.to_string(),
                SCOPE.to_string(),
                TREE_DEPTH as u16,
            )
            .unwrap();

            assert_eq!(proof.merkle_tree_root, BigUint::from_bytes_le(&root));
        }

        #[test]
        fn test_proof_1_member() {
            let identity = Identity::new("secret".as_bytes());
            let group = Group::new(&[to_element(*identity.commitment())]).unwrap();
            let root = group.root().unwrap();

            let proof = Proof::generate_proof(
                identity,
                GroupOrMerkleProof::Group(group),
                MESSAGE.to_string(),
                SCOPE.to_string(),
                TREE_DEPTH as u16,
            )
            .unwrap();

            assert_eq!(proof.merkle_tree_root, BigUint::from_bytes_le(&root));
        }

        #[test]
        fn test_proof_with_semaphore_proof() {
            let identity = Identity::new("secret".as_bytes());
            let group =
                Group::new(&[MEMBER1, MEMBER2, to_element(*identity.commitment())]).unwrap();
            let root = group.root().unwrap();

            let proof = Proof::generate_proof(
                identity,
                GroupOrMerkleProof::MerkleProof(group.generate_proof(2).unwrap()),
                MESSAGE.to_string(),
                SCOPE.to_string(),
                TREE_DEPTH as u16,
            )
            .unwrap();

            assert_eq!(proof.merkle_tree_root, BigUint::from_bytes_le(&root));
        }

        #[test]
        fn test_error_invalid_tree_depth() {
            let identity = Identity::new("secret".as_bytes());
            let group =
                Group::new(&[MEMBER1, MEMBER2, to_element(*identity.commitment())]).unwrap();

            let result = Proof::generate_proof(
                identity,
                GroupOrMerkleProof::Group(group),
                MESSAGE.to_string(),
                SCOPE.to_string(),
                33u16,
            );

            assert!(result.is_err());
            if let Err(err) = result {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "The tree depth must be a number between 1 and 32");
                }
            }
        }

        #[test]
        fn test_panic_id_not_in_group() {
            let identity = Identity::new("secret".as_bytes());
            let group = Group::new(&[MEMBER1, MEMBER2]).unwrap();

            let err = panic::catch_unwind(AssertUnwindSafe(|| {
                Proof::generate_proof(
                    identity,
                    GroupOrMerkleProof::Group(group),
                    MESSAGE.to_string(),
                    SCOPE.to_string(),
                    TREE_DEPTH as u16,
                )
                .unwrap()
            }));

            assert!(err.is_err());
            if let Err(err) = err {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "The identity does not exist");
                }
            }
        }

        #[test]
        fn test_panic_message_over_32bytes() {
            let identity = Identity::new("secret".as_bytes());
            let group =
                Group::new(&[MEMBER1, MEMBER2, to_element(*identity.commitment())]).unwrap();

            let err = panic::catch_unwind(AssertUnwindSafe(|| {
                Proof::generate_proof(
                    identity,
                    GroupOrMerkleProof::Group(group),
                    "This message is over 32 bytes long!!".to_string(),
                    SCOPE.to_string(),
                    TREE_DEPTH as u16,
                )
                .unwrap()
            }));

            assert!(err.is_err());
            if let Err(err) = err {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "BigUint too large: exceeds 32 bytes");
                }
            }
        }

        #[test]
        fn test_panic_scope_over_32bytes() {
            let identity = Identity::new("secret".as_bytes());
            let group =
                Group::new(&[MEMBER1, MEMBER2, to_element(*identity.commitment())]).unwrap();

            let err = panic::catch_unwind(AssertUnwindSafe(|| {
                Proof::generate_proof(
                    identity,
                    GroupOrMerkleProof::Group(group),
                    MESSAGE.to_string(),
                    "This scope is over 32 bytes long!!".to_string(),
                    TREE_DEPTH as u16,
                )
                .unwrap()
            }));

            assert!(err.is_err());
            if let Err(err) = err {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "BigUint too large: exceeds 32 bytes");
                }
            }
        }
    }

    #[cfg(test)]
    mod verify_proof {
        use super::*;
        use std::panic::{self, AssertUnwindSafe};

        #[test]
        fn test_verify_proof() {
            let identity = Identity::new("secret".as_bytes());
            let group =
                Group::new(&[MEMBER1, MEMBER2, to_element(*identity.commitment())]).unwrap();

            let proof = Proof::generate_proof(
                identity,
                GroupOrMerkleProof::Group(group),
                MESSAGE.to_string(),
                SCOPE.to_string(),
                TREE_DEPTH as u16,
            )
            .unwrap();

            assert!(Proof::verify_proof(proof))
        }

        #[test]
        fn test_panic_verify_invalid_tree_depth() {
            let identity = Identity::new("secret".as_bytes());
            let group =
                Group::new(&[MEMBER1, MEMBER2, to_element(*identity.commitment())]).unwrap();

            let mut proof = Proof::generate_proof(
                identity,
                GroupOrMerkleProof::Group(group),
                MESSAGE.to_string(),
                SCOPE.to_string(),
                TREE_DEPTH as u16,
            )
            .unwrap();
            proof.merkle_tree_depth = 40;

            let err = panic::catch_unwind(AssertUnwindSafe(|| Proof::verify_proof(proof)));
            assert!(err.is_err());
            if let Err(err) = err {
                if let Some(msg) = err.downcast_ref::<String>() {
                    assert_eq!(msg, "The tree depth must be a number between 1 and 32");
                }
            }
        }

        #[test]
        fn test_error_verify_invalid_proof() {
            let identity = Identity::new("secret".as_bytes());
            let group =
                Group::new(&[MEMBER1, MEMBER2, to_element(*identity.commitment())]).unwrap();

            let proof = Proof::generate_proof(
                identity,
                GroupOrMerkleProof::MerkleProof(group.generate_proof(0).unwrap()),
                MESSAGE.to_string(),
                SCOPE.to_string(),
                TREE_DEPTH as u16,
            )
            .unwrap();

            assert_eq!(Proof::verify_proof(proof), false)
        }

        // TODO fix it and remove #[ignore]
        // This test case is to test a semaphore-js proof can be verified by semaphore-rs verifier.
        #[test]
        #[ignore]
        fn test_semaphore_js_proof() {
            let points = [
                "295506195053657996543684079369282736491989370579592913124057536888855423796",
                "19815953998514576246488219178892684638226811708745908886782347604708935067095",
                "2328822589178611823527788148652183666924529164409257329409528192632149447408",
                "11539195047507357771307954059820020016014487935389334547419157174749447496942",
                "15003275093273171034895839912317447266095533353048813255314812547318796639767",
                "11081590418144905304290708191103158700191438642540253256124800534142848542048",
                "18156598254597299137691303527713519772389043452467253010766414291819443647431",
                "15733519144564958218973898608909712089708389642311757076012451880917955388102",
            ]
            .iter()
            .map(|&p| BigUint::from_str(p).unwrap())
            .collect::<Vec<BigUint>>()
            .try_into()
            .expect("Expected exactly 8 elements");

            let proof = SemaphoreProof {
                merkle_tree_depth: 10,
                merkle_tree_root: BigUint::from_str(
                    "4990292586352433503726012711155167179034286198473030768981544541070532815155",
                )
                .unwrap(),
                nullifier: BigUint::from_str(
                    "17540473064543782218297133630279824063352907908315494138425986188962403570231",
                )
                .unwrap(),
                message: BigUint::from_str(
                    "32745724963520510550185023804391900974863477733501474067656557556163468591104",
                )
                .unwrap(),
                scope: BigUint::from_str(
                    "37717653415819232215590989865455204849443869931268328771929128739472152723456",
                )
                .unwrap(),
                points,
            };

            assert!(Proof::verify_proof(proof));
        }
    }
}
