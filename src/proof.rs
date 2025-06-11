use crate::{
    MAX_TREE_DEPTH, MIN_TREE_DEPTH,
    group::{EMPTY_ELEMENT, Element, Group, MerkleProof},
    identity::Identity,
    utils::{download_zkey, hash, to_big_uint, to_element},
    witness::dispatch_witness,
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

pub type PackedGroth16Proof = [BigUint; 8];

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
    pub merkle_tree_depth: u16,
    pub merkle_tree_root: BigUint,
    pub message: BigUint,
    pub nullifier: BigUint,
    pub scope: BigUint,
    pub points: PackedGroth16Proof,
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
        if !(MIN_TREE_DEPTH..=MAX_TREE_DEPTH).contains(&merkle_tree_depth) {
            bail!(format!(
                "The tree depth must be a number between {} and {}",
                MIN_TREE_DEPTH, MAX_TREE_DEPTH
            ));
        }

        let merkle_proof = group.merkle_proof(&to_element(*identity.commitment()));
        let merkle_proof_length = merkle_proof.siblings.len();

        // The index must be converted to a list of indices, 1 for each tree level.
        // The missing siblings can be set to 0, as they won"t be used in the circuit.
        let mut merkle_proof_indices = Vec::new();
        let mut merkle_proof_siblings = Vec::<Element>::new();
        for i in 0..merkle_tree_depth {
            merkle_proof_indices.push((merkle_proof.index >> i) & 1);

            if let Some(sibling) = merkle_proof.siblings.get(i as usize) {
                merkle_proof_siblings.push(*sibling);
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

        let zkey_path = download_zkey(merkle_tree_depth).expect("Failed to download zkey");
        let witness_fn = dispatch_witness(merkle_tree_depth);

        let circom_proof = CircomProver::prove(
            ProofLib::Arkworks,
            WitnessFn::CircomWitnessCalc(witness_fn),
            serde_json::to_string(&inputs).unwrap(),
            zkey_path,
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

        let zkey_path = download_zkey(proof.merkle_tree_depth).expect("Failed to download zkey");
        CircomProver::verify(ProofLib::Arkworks, p, zkey_path).unwrap()
    }

    pub fn pack_groth16_proof(p: circom::Proof) -> PackedGroth16Proof {
        [
            p.a.x,
            p.a.y,
            p.b.x[1].clone(),
            p.b.x[0].clone(),
            p.b.y[1].clone(),
            p.b.y[0].clone(),
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
            x: [packed[3].clone(), packed[2].clone()],
            y: [packed[5].clone(), packed[4].clone()],
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
            assert_eq!(proof.message, to_big_uint(&MESSAGE.to_string()));
            assert_eq!(proof.scope, to_big_uint(&SCOPE.to_string()));
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
        fn test_verify_proof_with_different_depth() {
            for depth in MIN_TREE_DEPTH..=MAX_TREE_DEPTH {
                let identity = Identity::new("secret".as_bytes());
                let group =
                    Group::new(&[MEMBER1, MEMBER2, to_element(*identity.commitment())]).unwrap();

                let proof = Proof::generate_proof(
                    identity,
                    GroupOrMerkleProof::Group(group),
                    MESSAGE.to_string(),
                    SCOPE.to_string(),
                    depth as u16,
                )
                .unwrap();

                assert!(Proof::verify_proof(proof));
            }
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

        // This test case is to test a semaphore-js proof can be verified by semaphore-rs verifier.
        #[test]
        fn test_semaphore_js_proof() {
            let points = [
                // Proof generated from `Semaphore-js`
                "12803714274658725282520630356048215594611199462892068647123162130999777821470",
                "14790427909013880978103423555540996578520237818660256715698081866578524307407",
                "3103638479093034897036418556462341694689838452017242207620861422678426008987",
                "13727581952519649861097277152692845564872363841132502933894854130976607522628",
                "9411534790044921634269896122419705846815252106674427620586249081562203834159",
                "10009619289272081097084761045154085973406496068797344071367935854823051916935",
                "19672409605818107675150930119466509196235828486217699330399295338263828234556",
                "15472461797587690185190826432462453505284546376663377924961837387512711582919",
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
