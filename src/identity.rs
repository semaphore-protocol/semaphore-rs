//! Identity Module

use crate::{
    baby_jubjub::{BabyJubjubConfig, EdwardsAffine},
    error::SemaphoreError,
};
use ark_ec::{CurveConfig, CurveGroup, twisted_edwards::TECurveConfig};
use ark_ed_on_bn254::{Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use blake::Blake;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::{BigInt, Sign};
use std::ops::Mul;

/// Semaphore identity
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Private key
    private_key: Vec<u8>,
    /// Secret scalar
    secret_scalar: Fr,
    /// Public key
    public_key: PublicKey,
    /// Identity commitment
    commitment: Fq,
}

impl Identity {
    /// Creates a new identity from a private key
    pub fn new(private_key: &[u8]) -> Self {
        // Hash the private key
        let secret_scalar = Self::gen_secret_scalar(private_key);

        // Get the public key by multiplying the secret scalar by the base point
        let public_key = PublicKey::from_scalar(&secret_scalar);

        // Generate the identity commitment
        let commitment = public_key.commitment();

        Self {
            private_key: private_key.to_vec(),
            secret_scalar,
            public_key,
            commitment,
        }
    }

    /// Returns the private key
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Returns the secret scalar
    pub fn secret_scalar(&self) -> &Fr {
        &self.secret_scalar
    }

    /// Returns the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the identity commitment
    pub fn commitment(&self) -> &Fq {
        &self.commitment
    }

    /// Signs a message
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature, SemaphoreError> {
        if message.len() > 32 {
            return Err(SemaphoreError::MessageSizeExceeded(message.len()));
        }

        // Hash the private key and prune
        let mut priv_key_hash = blake_512(&self.private_key);
        priv_key_hash[0] &= 0xF8;
        priv_key_hash[31] &= 0x7F;
        priv_key_hash[31] |= 0x40;

        // Prepare the message in little-endian format
        let mut message_le = message.to_vec();
        message_le.reverse();

        // Compute ephemeral nonce scalar
        let mut k_input = [0u8; 64];
        k_input[..32].copy_from_slice(&priv_key_hash[32..]);
        k_input[32..32 + message.len()].copy_from_slice(&message_le);
        let k_fr = Fr::from_le_bytes_mod_order(&blake_512(&k_input));

        // Calculate ephemeral point r = k * base point
        let r = BabyJubjubConfig::GENERATOR.mul(k_fr).into_affine();

        // Compute challenge scalar
        let poseidon_inputs = [
            r.x,
            r.y,
            self.public_key.x(),
            self.public_key.y(),
            Fq::from_be_bytes_mod_order(message),
        ];
        let c_fq = Poseidon::<Fq>::new_circom(5)
            .unwrap()
            .hash(&poseidon_inputs)
            .unwrap();
        let c_fr = Fr::from_le_bytes_mod_order(&c_fq.into_bigint().to_bytes_le());

        // Calculate secret scalar (without dividing by cofactor)
        let secret_scalar = Fr::from_le_bytes_mod_order(&priv_key_hash[..32]);

        // s = nonce + challenge * secret
        let s = k_fr + c_fr * secret_scalar;

        Ok(Signature::new(r, s))
    }

    /// Generates the secret scalar from the private key
    fn gen_secret_scalar(private_key: &[u8]) -> Fr {
        // Hash the private key
        let mut hash = blake_512(private_key);

        // Prune hash
        hash[0] &= 0xF8;
        hash[31] &= 0x7F;
        hash[31] |= 0x40;

        // Use first half of hash and divide by cofactor (equivalent to shifting right by 3 bits)
        let shifted: BigInt = BigInt::from_bytes_le(Sign::Plus, &hash[..32]) >> 3;

        Fr::from_le_bytes_mod_order(&shifted.to_bytes_le().1)
    }
}

/// Semaphore public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    point: EdwardsAffine,
}

impl PublicKey {
    /// Creates a new public key instance from a point
    pub fn from_point(point: EdwardsAffine) -> Self {
        Self { point }
    }

    /// Creates a new subgroup public key from a scalar
    pub fn from_scalar(secret_scalar: &Fr) -> Self {
        let point = BabyJubjubConfig::GENERATOR.mul(secret_scalar).into_affine();

        Self { point }
    }

    /// Generates an identity commitment
    pub fn commitment(&self) -> Fq {
        Poseidon::<Fq>::new_circom(2)
            .unwrap()
            .hash(&[self.point.x, self.point.y])
            .unwrap()
    }

    /// Returns the public key point in Affine form
    pub fn point(&self) -> EdwardsAffine {
        self.point
    }

    /// Returns the x coordinate of the public key point
    pub fn x(&self) -> Fq {
        self.point.x
    }

    /// Returns the y coordinate of the public key point
    pub fn y(&self) -> Fq {
        self.point.y
    }
}

/// Signature
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// `r` point
    pub r: EdwardsAffine,
    /// `s` scalar
    pub s: Fr,
}

impl Signature {
    /// Creates a new signature from a point and scalar
    pub fn new(r: EdwardsAffine, s: Fr) -> Self {
        Self { r, s }
    }

    /// Verifies against a public key and message
    pub fn verify(&self, public_key: &PublicKey, message: &[u8]) -> Result<(), SemaphoreError> {
        if message.len() > 32 {
            return Err(SemaphoreError::MessageSizeExceeded(message.len()));
        }

        if !self.r.is_on_curve() {
            return Err(SemaphoreError::SignaturePointNotOnCurve);
        }

        if !public_key.point().is_on_curve() {
            return Err(SemaphoreError::PublicKeyNotOnCurve);
        }

        // Compute challenge scalar
        let poseidon_inputs = [
            self.r.x,
            self.r.y,
            public_key.x(),
            public_key.y(),
            Fq::from_be_bytes_mod_order(message),
        ];
        let c_fq = Poseidon::<Fq>::new_circom(5)
            .unwrap()
            .hash(&poseidon_inputs)
            .unwrap();
        let mut c_fr = Fr::from_le_bytes_mod_order(&c_fq.into_bigint().to_bytes_le());

        // Multiply challenge scalar by cofactor
        c_fr *= Fr::from_be_bytes_mod_order(&[BabyJubjubConfig::COFACTOR[0] as u8]);

        // s * generator
        let left = BabyJubjubConfig::GENERATOR.mul(self.s);

        // nonce + challenge * public_key
        let right = self.r + public_key.point().mul(c_fr);

        // s * generator = nonce + challenge * public_key
        if left != right {
            return Err(SemaphoreError::SignatureVerificationFailed);
        }

        Ok(())
    }
}

/// Computes Blake 512 hash
pub fn blake_512(input: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    let mut hasher = Blake::new(512).unwrap();

    hasher.update(input);
    hasher.finalise(&mut output);

    output
}
