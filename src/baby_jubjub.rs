//! EIP-2494 Baby Jubjub Curve
//!
//! This is an append to the the `ark-ed-on-bn254` crate to use the EIP-2494 defined Baby Jubjub curve parameters.
//!
//! - https://eips.ethereum.org/EIPS/eip-2494
//!
//! - Base field: q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//! - Scalar field: r = 2736030358979909402780800718157159386076813972158567259200215660948447373041
//! - Order: n = l * cofactor = 21888242871839275222246405745257275088614511777268538073601725287587578984328
//! - Cofactor: 8
//! - Subgroup order: l = 2736030358979909402780800718157159386076813972158567259200215660948447373041
//! - Curve equation: ax² + y² = 1 + d·x²y², where
//!    - a = 168700
//!    - d = 168696
//! - Generator point:
//!    (995203441582195749578291179787384436505546430278305826713579947235728471134,
//!     5472060717959818805561601436314318772137091100104008585924551046643952123905)
//! - Base point:
//!    (5299619240641551281634865583518297030282874472190772894086521144482721001553,
//!     16950150798460657717958625567821834550301663161624707787222815936182638968203)

use ark_ec::{
    models::CurveConfig,
    twisted_edwards::{Affine, MontCurveConfig, Projective, TECurveConfig},
};
use ark_ed_on_bn254::{Fq, Fr};
use ark_ff::{Field, MontFp};

pub type EdwardsAffine = Affine<BabyJubjubConfig>;
pub type EdwardsProjective = Projective<BabyJubjubConfig>;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct BabyJubjubConfig;

impl CurveConfig for BabyJubjubConfig {
    type BaseField = Fq;
    type ScalarField = Fr;

    // h = 8
    const COFACTOR: &'static [u64] = &[8];

    // h^(-1) (mod r)
    const COFACTOR_INV: Fr =
        MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

// Twisted Edwards form
// ax^2 + y^2 = 1 + dx^2y^2
impl TECurveConfig for BabyJubjubConfig {
    // a = 168700
    const COEFF_A: Fq = MontFp!("168700");

    #[inline(always)]
    fn mul_by_a(elem: Self::BaseField) -> Self::BaseField {
        elem * <BabyJubjubConfig as TECurveConfig>::COEFF_A
    }

    // d = 168696
    const COEFF_D: Fq = MontFp!("168696");

    // Base point is used as generator to operate in subgroup
    const GENERATOR: EdwardsAffine = EdwardsAffine::new_unchecked(BASE_X, BASE_Y);

    type MontCurveConfig = BabyJubjubConfig;
}

// Montgomery form
// By^2 = x^3 + A x^2 + x
impl MontCurveConfig for BabyJubjubConfig {
    // A = 168698
    const COEFF_A: Fq = MontFp!("168698");
    // B = 1
    const COEFF_B: Fq = Fq::ONE;

    type TECurveConfig = BabyJubjubConfig;
}

/// Generator point x-coordinate
pub const GENERATOR_X: Fq =
    MontFp!("995203441582195749578291179787384436505546430278305826713579947235728471134");
/// Generator point y-coordinate
pub const GENERATOR_Y: Fq =
    MontFp!("5472060717959818805561601436314318772137091100104008585924551046643952123905");

/// Subgroup order `l`
pub const SUBGROUP_ORDER: Fr =
    MontFp!("2736030358979909402780800718157159386076813972158567259200215660948447373041");

// Subgroup generator
// Generates subgroup l * P = O

/// Base point x-coordinate
pub const BASE_X: Fq =
    MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");
/// Base point y-coordinate
pub const BASE_Y: Fq =
    MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203");

#[cfg(test)]
mod tests {
    //! Implementation of the tests presented in the EIP-2494
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::{PrimeField, Zero};

    #[test]
    fn test_addition() {
        let p1 = EdwardsAffine::new_unchecked(
            MontFp!(
                "17777552123799933955779906779655732241715742912184938656739573121738514868268"
            ),
            MontFp!("2626589144620713026669568689430873010625803728049924121243784502389097019475"),
        );

        let p2 = EdwardsAffine::new_unchecked(
            MontFp!(
                "16540640123574156134436876038791482806971768689494387082833631921987005038935"
            ),
            MontFp!(
                "20819045374670962167435360035096875258406992893633759881276124905556507972311"
            ),
        );

        let result = (p1 + p2).into_affine();

        assert_eq!(
            result,
            EdwardsAffine::new_unchecked(
                MontFp!(
                    "7916061937171219682591368294088513039687205273691143098332585753343424131937"
                ),
                MontFp!(
                    "14035240266687799601661095864649209771790948434046947201833777492504781204499"
                )
            )
        );
    }

    #[test]
    fn test_doubling() {
        let p1 = EdwardsAffine::new_unchecked(
            MontFp!(
                "17777552123799933955779906779655732241715742912184938656739573121738514868268"
            ),
            MontFp!("2626589144620713026669568689430873010625803728049924121243784502389097019475"),
        );

        let result = (p1 + p1).into_affine();

        assert_eq!(
            result,
            EdwardsAffine::new_unchecked(
                MontFp!(
                    "6890855772600357754907169075114257697580319025794532037257385534741338397365"
                ),
                MontFp!(
                    "4338620300185947561074059802482547481416142213883829469920100239455078257889"
                )
            )
        );
    }

    #[test]
    fn test_doubling_identity() {
        let identity = EdwardsAffine::new_unchecked(Fq::zero(), Fq::ONE);
        let result = (identity + identity).into_affine();

        assert_eq!(result, identity);
    }

    #[test]
    fn test_curve_membership() {
        let valid_point = EdwardsAffine::new_unchecked(Fq::zero(), Fq::ONE);
        assert!(valid_point.is_on_curve());

        let invalid_point = EdwardsAffine::new_unchecked(Fq::ONE, Fq::zero());
        assert!(!invalid_point.is_on_curve());
    }

    #[test]
    fn test_base_point_choice() {
        let g = EdwardsAffine::new_unchecked(GENERATOR_X, GENERATOR_Y);

        let expected_base_point = EdwardsAffine::new_unchecked(BASE_X, BASE_Y);
        let cofactor = Fr::from_be_bytes_mod_order(&[BabyJubjubConfig::COFACTOR[0] as u8]);
        let calculated_base_point = (g * cofactor).into_affine();

        assert_eq!(calculated_base_point, expected_base_point);
    }

    #[test]
    fn test_base_point_order() {
        let base_point = EdwardsAffine::new_unchecked(GENERATOR_X, GENERATOR_Y);

        let result = (base_point * SUBGROUP_ORDER).into_affine();
        let identity = EdwardsAffine::new_unchecked(Fq::zero(), Fq::ONE);

        assert_eq!(result, identity);
    }
}
