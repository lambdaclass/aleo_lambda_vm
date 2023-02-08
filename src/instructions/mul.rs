use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Result};
use indexmap::IndexMap;
use simpleworks::{gadgets::traits::ArithmeticGadget, marlin::ConstraintSystemRef};
pub use CircuitIOType::{SimpleInt8, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn mul(
    operands: &IndexMap<String, CircuitIOType>,
    constraint_system: ConstraintSystemRef,
) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(multiplicand), SimpleUInt8(multiplier)] => {
            let result = multiplicand.mul(multiplier, constraint_system)?;
            Ok(SimpleUInt8(result))
        }
        [SimpleUInt16(multiplicand), SimpleUInt16(multiplier)] => {
            let result = multiplicand.mul(multiplier, constraint_system)?;
            Ok(SimpleUInt16(result))
        }
        [SimpleUInt32(multiplicand), SimpleUInt32(multiplier)] => {
            let result = multiplicand.mul(multiplier, constraint_system)?;
            Ok(SimpleUInt32(result))
        }
        [SimpleUInt64(multiplicand), SimpleUInt64(multiplier)] => {
            let result = multiplicand.mul(multiplier, constraint_system)?;
            Ok(SimpleUInt64(result))
        }
        [SimpleInt8(multiplicand), SimpleInt8(multiplier)] => {
            let result = multiplicand.mul(multiplier, constraint_system)?;
            Ok(SimpleInt8(result))
        }
        [..] => bail!("Unsupported operand types for addmany"),
    }
}

// TODO: Tests with overflow.
#[cfg(test)]
mod tests {
    use crate::{
        instructions::mul::mul,
        CircuitIOType::{self, SimpleInt8, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8},
        UInt16Gadget, UInt32Gadget, UInt64Gadget,
    };
    use ark_r1cs_std::prelude::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::gadgets::{ConstraintF, Int8Gadget, UInt8Gadget};

    fn sample_operands(
        multiplicand: CircuitIOType,
        multiplier: CircuitIOType,
    ) -> IndexMap<String, CircuitIOType> {
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), multiplicand);
        operands.insert("r1".to_owned(), multiplier);
        operands
    }

    /* u8 multiplication with modified Booth's algorithm */

    #[test]
    fn test_u8_multiplying_by_zero_should_result_on_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = u8::MAX;
        let primitive_multiplier = 0_u8;

        let multiplicand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u8_multiplying_by_zero_should_result_on_zero_commutative() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 0_u8;
        let primitive_multiplier = u8::MAX;

        let multiplicand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u8_multiplying_by_one_the_multiplicand_should_result_on_the_multiplicand() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 0x55;
        let primitive_multiplier = 1_u8;

        let multiplicand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u8_if_the_multiplicand_is_one_the_result_should_be_the_multiplier() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 1_u8;
        let primitive_multiplier = 0x55;

        let multiplicand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    /* u16 multiplication with modified Booth's algorithm */

    #[test]
    fn test_u16_multiplying_by_zero_should_result_on_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = u16::MAX;
        let primitive_multiplier = 0_u16;

        let multiplicand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u16_multiplying_by_zero_should_result_on_zero_commutative() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 0_u16;
        let primitive_multiplier = u16::MAX;

        let multiplicand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u16_multiplying_by_one_the_multiplicand_should_result_on_the_multiplicand() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 0x5555;
        let primitive_multiplier = 1_u16;

        let multiplicand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u16_if_the_multiplicand_is_one_the_result_should_be_the_multiplier() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 1_u16;
        let primitive_multiplier = 0x5555;

        let multiplicand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    /* u32 multiplication with modified Booth's algorithm */

    #[test]
    fn test_u32_multiplying_by_zero_should_result_on_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = u32::MAX;
        let primitive_multiplier = 0_u32;

        let multiplicand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u32_multiplying_by_zero_should_result_on_zero_commutative() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 0_u32;
        let primitive_multiplier = u32::MAX;

        let multiplicand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u32_multiplying_by_one_the_multiplicand_should_result_on_the_multiplicand() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 0x55555555;
        let primitive_multiplier = 1_u32;

        let multiplicand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u32_if_the_multiplicand_is_one_the_result_should_be_the_multiplier() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 1_u32;
        let primitive_multiplier = 0x55555555;

        let multiplicand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    /* u64 multiplication with modified Booth's algorithm */

    #[test]
    fn test_u64_multiplying_by_zero_should_result_on_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = u64::MAX;
        let primitive_multiplier = 0_u64;

        let multiplicand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u64_multiplying_by_zero_should_result_on_zero_commutative() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 0_u64;
        let primitive_multiplier = u64::MAX;

        let multiplicand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u64_multiplying_by_one_the_multiplicand_should_result_on_the_multiplicand() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 0x5555555555555555;
        let primitive_multiplier = 1_u64;

        let multiplicand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_u64_if_the_multiplicand_is_one_the_result_should_be_the_multiplier() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 1_u64;
        let primitive_multiplier = 0x5555555555555555;

        let multiplicand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap(),
        );
        let multiplier = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap(),
        );
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_i8_multiplying_by_zero_should_result_on_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = i8::MAX;
        let primitive_multiplier = 0_i8;

        let multiplicand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap());
        let multiplier =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_i8_multiplying_by_zero_should_result_on_zero_commutative() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 0_i8;
        let primitive_multiplier = i8::MAX;

        let multiplicand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap());
        let multiplier =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_i8_multiplying_by_one_the_multiplicand_should_result_on_the_multiplicand() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 20_i8;
        let primitive_multiplier = 1_i8;

        let multiplicand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap());
        let multiplier =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product = multiplicand.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_i8_if_the_multiplicand_is_one_the_result_should_be_the_multiplier() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 1_i8;
        let primitive_multiplier = 20_i8;

        let multiplicand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap());
        let multiplier =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product = multiplier.clone();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_i8_multiply_two_positive_numbers_result_is_correct() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = 10_i8;
        let primitive_multiplier = 10_i8;
        let primitive_result = 100_i8;

        let multiplicand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap());
        let multiplier =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_i8_multiply_two_negative_numbers_result_is_correct() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = -10_i8;
        let primitive_multiplier = -10_i8;
        let primitive_result = 100_i8;

        let multiplicand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap());
        let multiplier =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }

    #[test]
    fn test_i8_multiply_negative_and_positive_numbers_result_is_correct() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_multiplicand = -10_i8;
        let primitive_multiplier = 10_i8;
        let primitive_result = -100_i8;

        let multiplicand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplicand)).unwrap());
        let multiplier =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_multiplier)).unwrap());
        let expected_product =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            mul(&sample_operands(multiplicand, multiplier), cs)
                .unwrap()
                .value()
                .unwrap(),
            expected_product.value().unwrap()
        );
    }
}
