use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Ok, Result};
pub use ark_r1cs_std::boolean::AllocatedBool;
use indexmap::IndexMap;
use simpleworks::gadgets::traits::BitwiseOperationGadget;
pub use CircuitIOType::{SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn nor(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleBoolean(left_operand), SimpleBoolean(right_operand)] => {
            let result = left_operand.or(right_operand)?.not();
            Ok(SimpleBoolean(result))
        }
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            let result = left_operand.nor(right_operand.clone())?;
            Ok(SimpleUInt8(result))
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            let result = left_operand.nor(right_operand.clone())?;
            Ok(SimpleUInt16(result))
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            let result = left_operand.nor(right_operand.clone())?;
            Ok(SimpleUInt32(result))
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            let result = left_operand.nor(right_operand.clone())?;
            Ok(SimpleUInt64(result))
        }
        [_, _] => bail!("nor is not supported for the given types"),
        [..] => bail!("nor requires two operands"),
    }
}

#[cfg(test)]
mod nor_unit_tests {
    use crate::CircuitIOType::{
        self, SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
    };
    use ark_r1cs_std::prelude::{AllocVar, Boolean};
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::{
        gadgets::{ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget},
        marlin::ConstraintSystemRef,
    };

    use super::nor;

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
    fn assert_that_nor_with_two_operands_result_is_correct(
        constraint_system: ConstraintSystemRef,
        first_operand: CircuitIOType,
        second_operand: CircuitIOType,
        expected_result: CircuitIOType,
    ) {
        assert!(constraint_system.is_satisfied().unwrap());

        let result = nor(&sample_operands(first_operand, second_operand)).unwrap();
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap())
    }

    #[test]
    fn test_booleans_with_two_true_operands_should_be_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let true_primitive_operand = true;
        let false_primitive_operand = false;

        let operand =
            SimpleBoolean(Boolean::new_witness(cs.clone(), || Ok(true_primitive_operand)).unwrap());
        let expected_result = SimpleBoolean(
            Boolean::new_witness(cs.clone(), || Ok(false_primitive_operand)).unwrap(),
        );
        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_booleans_with_two_false_operands_should_be_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let false_primitive_operand = false;
        let true_primitive_operand = true;

        let operand = SimpleBoolean(
            Boolean::new_witness(cs.clone(), || Ok(false_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleBoolean(Boolean::new_witness(cs.clone(), || Ok(true_primitive_operand)).unwrap());

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_booleans_with_one_false_and_one_true_operand_should_be_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = false;
        let other_primitive_operand = true;

        let operand =
            SimpleBoolean(Boolean::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleBoolean(
            Boolean::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result = operand.clone();

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_nor_with_zero_should_return_max_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u8;
        let max_value_primitive_operand = u8::MAX;

        let operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_nor_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = u8::MAX;
        let zero_primitive_operand = 0_u8;

        let operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_nor_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u8; // 00001010
        let other_primitive_operand = 7_u8; // 00000111
        let primitive_result = 240_u8; // 11110000

        let operand =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_nor_with_zero_should_return_max_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u16;
        let max_value_primitive_operand = u16::MAX;

        let operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_nor_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = u16::MAX;
        let zero_primitive_operand = 0_u16;

        let operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_nor_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u16; // 0...00001010
        let other_primitive_operand = 7_u16; // 0...00000111
        let primitive_result = 0xFFF0_u16; // 1...11110010

        let operand =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_nor_with_zero_should_return_max_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u32;
        let max_value_primitive_operand = u32::MAX;

        let operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_nor_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = u32::MAX;
        let zero_primitive_operand = 0_u32;

        let operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_nor_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u32; // 0..00001010
        let other_primitive_operand = 7_u32; // 0..00000111
        let primitive_result = 0xFFFF_FFF0_u32; // 1..11110000

        let operand =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_nor_with_zero_should_return_max_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let zero_primitive_operand = 0_u64;
        let max_value_primitive_operand = u64::MAX;

        let operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_nor_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = u64::MAX;
        let zero_primitive_operand = 0_u64;

        let operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_nor_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u64; // 0..00001010
        let other_primitive_operand = 7_u64; // 0..00000111
        let primitive_result = 0xFFFF_FFFF_FFFF_FFF0_u64; // 1..11110000

        let operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_nor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }
}
