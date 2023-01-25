use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Ok, Result};
use ark_r1cs_std::prelude::Boolean;
use indexmap::IndexMap;
use simpleworks::gadgets::traits::BitwiseOperationGadget;
pub use CircuitIOType::{
    SimpleBoolean, SimpleInt8, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
};

pub fn nand(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleBoolean(left_operand), SimpleBoolean(right_operand)] => {
            let result = Boolean::kary_nand(&[left_operand.clone(), right_operand.clone()])?;
            Ok(SimpleBoolean(result))
        }
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            let result = left_operand.nand(right_operand.clone())?;
            Ok(SimpleUInt8(result))
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            let result = left_operand.nand(right_operand.clone())?;
            Ok(SimpleUInt16(result))
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            let result = left_operand.nand(right_operand.clone())?;
            Ok(SimpleUInt32(result))
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            let result = left_operand.nand(right_operand.clone())?;
            Ok(SimpleUInt64(result))
        }
        [SimpleInt8(left_operand), SimpleInt8(right_operand)] => {
            let result = left_operand.nand(right_operand.clone())?;
            Ok(SimpleInt8(result))
        }
        [_, _] => bail!("nand is not supported for the given types"),
        [..] => bail!("nand requires two operands"),
    }
}

#[cfg(test)]
mod nand_unit_tests {

    use crate::CircuitIOType::{
        self, SimpleBoolean, SimpleInt8, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
    };
    use ark_r1cs_std::prelude::{AllocVar, Boolean};
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::{
        gadgets::{ConstraintF, Int8Gadget, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget},
        marlin::ConstraintSystemRef,
    };

    use super::nand;

    fn sample_operands(
        first_operand: CircuitIOType,
        second_operand: CircuitIOType,
    ) -> IndexMap<String, CircuitIOType> {
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), first_operand);
        operands.insert("r1".to_owned(), second_operand);
        operands
    }

    #[allow(clippy::unwrap_used)]
    fn assert_that_nand_with_two_operands_result_is_correct(
        constraint_system: ConstraintSystemRef,
        first_operand: CircuitIOType,
        second_operand: CircuitIOType,
        expected_result: CircuitIOType,
    ) {
        assert!(constraint_system.is_satisfied().unwrap());

        let result = nand(&sample_operands(first_operand, second_operand)).unwrap();
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap())
    }

    #[test]
    fn test_booleans_with_two_true_operands_should_be_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand_true = true;
        let primitive_operand_false = false;

        let operand =
            SimpleBoolean(Boolean::new_witness(cs.clone(), || Ok(primitive_operand_true)).unwrap());
        let expected_result = SimpleBoolean(
            Boolean::new_witness(cs.clone(), || Ok(primitive_operand_false)).unwrap(),
        );
        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_booleans_with_two_false_operands_should_be_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_false_operand = false;
        let primitive_true_operand = true;

        let operand = SimpleBoolean(
            Boolean::new_witness(cs.clone(), || Ok(primitive_false_operand)).unwrap(),
        );
        let expected_result =
            SimpleBoolean(Boolean::new_witness(cs.clone(), || Ok(primitive_true_operand)).unwrap());

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_booleans_with_one_false_and_one_true_operand_should_be_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let false_primitive_operand = false;
        let true_primitive_operand = true;

        let operand = SimpleBoolean(
            Boolean::new_witness(cs.clone(), || Ok(false_primitive_operand)).unwrap(),
        );
        let another_operand =
            SimpleBoolean(Boolean::new_witness(cs.clone(), || Ok(true_primitive_operand)).unwrap());
        let expected_result = another_operand.clone();

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_nand_with_zero_should_return_max_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u8;
        let max_primitive_operand = u8::MAX;

        let operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_nand_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u8;
        let max_primitive_operand = u8::MAX;

        let operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_nand_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u8; // 00001010
        let other_primitive_operand = 7_u8; // 00000111
        let primitive_result = 253_u8; // 11111101

        let operand =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_nand_with_zero_should_return_max_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u16;
        let max_primitive_operand = u16::MAX;

        let operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_nand_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u16;
        let max_primitive_operand = u16::MAX;

        let operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_nand_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u16; // 0..00001010
        let other_primitive_operand = 7_u16; // 0..00000111
        let primitive_result = 0xFFFD_u16; // 1..11111101

        let operand =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_nand_with_zero_should_return_max_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u32;
        let max_primitive_operand = u32::MAX;

        let operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_nand_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u32;
        let max_primitive_operand = u32::MAX;

        let operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_nand_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u32; // 0..00001010
        let other_primitive_operand = 7_u32; // 0..00000111
        let primitive_result = 0xFFFF_FFFD_u32; // 1..11111101

        let operand =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_nand_with_zero_should_return_max_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u64;
        let max_primitive_operand = u64::MAX;

        let operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_nand_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u64;
        let max_primitive_operand = u64::MAX;

        let operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_nand_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u64; // 0..00001010
        let other_primitive_operand = 7_u64; // 0..00000111
        let primitive_result = 0xFFFF_FFFF_FFFF_FFFD_u64; // 1..111111101

        let operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_i8_nand_with_zero_should_return_correct_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_i8; //10000000
        let max_primitive_operand = -1_i8; //10000001

        let operand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap());
        let expected_result =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap());

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_i8_nand_with_max_value_return_expected_result() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let result_primitive_operand = -128_i8;
        let max_primitive_operand = i8::MAX;

        let operand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap());
        let expected_result = SimpleInt8(
            Int8Gadget::new_witness(cs.clone(), || Ok(result_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_i8_nand_with_min_value_return_expected_result() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let result_primitive_operand = 127_i8;
        let max_primitive_operand = i8::MIN;

        let operand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(max_primitive_operand)).unwrap());
        let expected_result = SimpleInt8(
            Int8Gadget::new_witness(cs.clone(), || Ok(result_primitive_operand)).unwrap(),
        );

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_i8_nand_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 20_i8; // 00010100
        let other_primitive_operand = -15_i8; // 11110001
        let primitive_result = -17_i8; // 11101111

        let operand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleInt8(
            Int8Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_nand_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }
}
