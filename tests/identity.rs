//! Identity module integration tests
//!
//! The constants were generated using the typescript Semaphore V4 implementation.
//!
//! - https://github.com/brech1/sem-test-values
//!
//! All byte values are in big endian format.

// Inputs
const PRIVATE_KEY_BYTES: [u8; 10] = [112, 114, 105, 118, 97, 116, 101, 75, 101, 121];
const MESSAGE_BYTES: [u8; 7] = [109, 101, 115, 115, 97, 103, 101];

// Secret Scalar
const SECRET_SCALAR_STR: &str =
    "1319709833472015827730826418408303647941748850729897255051940662182776719635";
const SECRET_SCALAR_BYTES: [u8; 32] = [
    2, 234, 237, 230, 80, 122, 153, 195, 63, 142, 196, 130, 148, 129, 61, 227, 71, 127, 38, 235,
    161, 55, 179, 143, 5, 158, 187, 138, 221, 88, 201, 19,
];

// Public Key
const PUBLIC_KEY_STR: &str = "(20191161190634177714856258432742391014210684311546132016070244128804840948064, 15209227963454794938053687888234270810990820964270375245744800564428536818120)";
const PUBLIC_KEY_X_BYTES: [u8; 32] = [
    44, 163, 202, 208, 199, 57, 16, 211, 82, 180, 59, 227, 30, 252, 212, 244, 251, 255, 228, 174,
    31, 212, 161, 61, 184, 169, 200, 50, 7, 84, 65, 96,
];
const PUBLIC_KEY_Y_BYTES: [u8; 32] = [
    33, 160, 30, 51, 23, 176, 120, 182, 143, 13, 107, 115, 65, 222, 145, 126, 149, 154, 43, 209,
    80, 105, 239, 250, 176, 136, 240, 236, 63, 128, 41, 200,
];

// Commitment
const COMMITMENT_STR: &str =
    "11372478937056182347300323057848769551333725898578571354328589544822167334484";
const COMMITMENT_BYTES: [u8; 32] = [
    25, 36, 152, 80, 56, 11, 26, 2, 17, 243, 115, 82, 175, 106, 167, 84, 119, 125, 231, 4, 147, 4,
    199, 208, 152, 164, 217, 145, 36, 212, 110, 84,
];

// Signature
const SIGNATURE_R8_STR: &str = "(15692604209546184713306928546008997717398425098370611740032900661941398951046, 9561160056878562889932140991915362529009920711886027675468824242797436205292)";
const SIGNATURE_R8_X_BYTES: [u8; 32] = [
    34, 177, 179, 0, 139, 36, 37, 68, 198, 92, 159, 9, 236, 31, 168, 86, 199, 99, 218, 146, 74,
    170, 134, 26, 114, 113, 31, 133, 13, 204, 84, 134,
];
const SIGNATURE_R8_Y_BYTES: [u8; 32] = [
    21, 35, 108, 192, 232, 36, 155, 242, 251, 145, 16, 62, 78, 177, 155, 18, 237, 74, 38, 7, 185,
    83, 80, 124, 252, 124, 125, 15, 187, 139, 248, 236,
];
const SIGNATURE_S_STR: &str =
    "463050405688667311380335008913093928239282429722515841444688860881221420599";
const SIGNATURE_S_BYTES: [u8; 32] = [
    1, 6, 19, 198, 32, 235, 21, 163, 223, 208, 109, 6, 140, 118, 120, 45, 10, 180, 61, 58, 2, 39,
    62, 249, 210, 16, 126, 67, 124, 237, 134, 55,
];

#[cfg(test)]
mod identity {
    use super::*;
    use ark_ed_on_bn254::{Fq, Fr};
    use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
    use semaphore_rs::{
        baby_jubjub::EdwardsAffine,
        error::SemaphoreError,
        identity::{Identity, Signature},
    };

    #[test]
    fn secret_scalar() {
        let identity = Identity::new(&PRIVATE_KEY_BYTES);

        // Verify Secret Scalar
        assert_eq!(SECRET_SCALAR_STR, identity.secret_scalar().to_string());
        assert_eq!(
            SECRET_SCALAR_BYTES,
            identity
                .secret_scalar()
                .into_bigint()
                .to_bytes_be()
                .to_vec()
                .as_slice()
        );
    }

    #[test]
    fn public_key() {
        let identity = Identity::new(&PRIVATE_KEY_BYTES);

        // Verify generated public key
        assert_eq!(PUBLIC_KEY_STR, identity.public_key().point().to_string());
        assert_eq!(
            PUBLIC_KEY_X_BYTES,
            identity
                .public_key()
                .x()
                .into_bigint()
                .to_bytes_be()
                .to_vec()
                .as_slice()
        );
        assert_eq!(
            PUBLIC_KEY_Y_BYTES,
            identity
                .public_key()
                .y()
                .into_bigint()
                .to_bytes_be()
                .to_vec()
                .as_slice()
        );
    }

    #[test]
    fn commitment() {
        let identity = Identity::new(&PRIVATE_KEY_BYTES);

        // Verify generated commitment
        assert_eq!(COMMITMENT_STR, identity.commitment().to_string());
        assert_eq!(
            COMMITMENT_BYTES,
            identity.commitment().into_bigint().to_bytes_be().as_slice()
        );
    }

    #[test]
    fn sign_message() {
        let identity = Identity::new(&PRIVATE_KEY_BYTES);

        let signature = identity.sign_message(&MESSAGE_BYTES).unwrap();

        assert_eq!(SIGNATURE_R8_STR, signature.r.to_string());
        assert_eq!(
            SIGNATURE_R8_X_BYTES,
            signature.r.x.into_bigint().to_bytes_be().as_slice()
        );
        assert_eq!(
            SIGNATURE_R8_Y_BYTES,
            signature.r.y.into_bigint().to_bytes_be().as_slice()
        );

        assert_eq!(SIGNATURE_S_STR, signature.s.to_string());
        assert_eq!(
            SIGNATURE_S_BYTES,
            signature.s.into_bigint().to_bytes_be().as_slice()
        );
    }

    #[test]
    fn verify_signature() {
        let identity = Identity::new(&PRIVATE_KEY_BYTES);
        let signature = identity.sign_message(&MESSAGE_BYTES).unwrap();

        assert_eq!(
            signature
                .verify(identity.public_key(), &MESSAGE_BYTES)
                .unwrap(),
            ()
        );

        let provided_signature = Signature {
            r: EdwardsAffine::new_unchecked(
                Fq::from_be_bytes_mod_order(&SIGNATURE_R8_X_BYTES),
                Fq::from_be_bytes_mod_order(&SIGNATURE_R8_Y_BYTES),
            ),
            s: Fr::from_be_bytes_mod_order(&SIGNATURE_S_BYTES),
        };
        assert_eq!(
            provided_signature
                .verify(identity.public_key(), &MESSAGE_BYTES)
                .unwrap(),
            ()
        );

        let invalid_message = [0u8; 7];
        assert_eq!(
            provided_signature
                .verify(identity.public_key(), &invalid_message)
                .unwrap_err(),
            SemaphoreError::SignatureVerificationFailed
        );

        let long_message = [0u8; 33];
        assert_eq!(
            provided_signature
                .verify(identity.public_key(), &long_message)
                .unwrap_err(),
            SemaphoreError::MessageSizeExceeded(33)
        );

        let invalid_signature = Signature {
            r: EdwardsAffine::new_unchecked(Fq::ZERO, Fq::ZERO),
            s: signature.s,
        };
        assert_eq!(
            invalid_signature
                .verify(identity.public_key(), &MESSAGE_BYTES)
                .unwrap_err(),
            SemaphoreError::SignaturePointNotOnCurve
        );
    }
}
