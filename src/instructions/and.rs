use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Ok, Result};
use ark_r1cs_std::ToBitsGadget;
use indexmap::IndexMap;
use simpleworks::gadgets::{UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget};
pub use CircuitIOType::{SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn and(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleBoolean(left_operand), SimpleBoolean(right_operand)] => {
            let result = left_operand.and(right_operand)?;
            Ok(SimpleBoolean(result))
        }
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            let left_operand_raw_bits = left_operand.to_bits_le()?;
            let right_operand_raw_bits = right_operand.to_bits_le()?;
            let mut result = Vec::new();
            for (left_operand_bit, right_operand_bit) in left_operand_raw_bits
                .iter()
                .zip(right_operand_raw_bits.iter())
            {
                let operation_result = left_operand_bit.and(right_operand_bit)?;
                result.push(operation_result);
            }
            let new_value = UInt8Gadget::from_bits_le(&result);
            Ok(SimpleUInt8(new_value))
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            let left_operand_raw_bits = left_operand.to_bits_le();
            let right_operand_raw_bits = right_operand.to_bits_le();
            let mut result = Vec::new();
            for (left_operand_bit, right_operand_bit) in left_operand_raw_bits
                .iter()
                .zip(right_operand_raw_bits.iter())
            {
                let operation_result = left_operand_bit.and(right_operand_bit)?;
                result.push(operation_result);
            }
            let new_value = UInt16Gadget::from_bits_le(&result);
            Ok(SimpleUInt16(new_value))
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            let left_operand_raw_bits = left_operand.to_bits_le();
            let right_operand_raw_bits = right_operand.to_bits_le();
            let mut result = Vec::new();
            for (left_operand_bit, right_operand_bit) in left_operand_raw_bits
                .iter()
                .zip(right_operand_raw_bits.iter())
            {
                let operation_result = left_operand_bit.and(right_operand_bit)?;
                result.push(operation_result);
            }
            let new_value = UInt32Gadget::from_bits_le(&result);
            Ok(SimpleUInt32(new_value))
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            let left_operand_raw_bits = left_operand.to_bits_le();
            let right_operand_raw_bits = right_operand.to_bits_le();
            let mut result = Vec::new();
            for (left_operand_bit, right_operand_bit) in left_operand_raw_bits
                .iter()
                .zip(right_operand_raw_bits.iter())
            {
                let operation_result = left_operand_bit.and(right_operand_bit)?;
                result.push(operation_result);
            }
            let new_value = UInt64Gadget::from_bits_le(&result);
            Ok(SimpleUInt64(new_value))
        }
        [_, _] => bail!("and is not supported for the given types"),
        [..] => bail!("and requires two operands"),
    }
}

#[cfg(test)]
mod and_unit_tests {
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

    use super::and;

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
    fn assert_that_and_with_two_operands_result_is_correct(
        constraint_system: ConstraintSystemRef,
        first_operand: CircuitIOType,
        second_operand: CircuitIOType,
        expected_result: CircuitIOType,
    ) {
        assert!(constraint_system.is_satisfied().unwrap());

        let result = and(&sample_operands(first_operand, second_operand)).unwrap();
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap())
    }

    #[test]
    fn test_booleans_with_two_true_operands_should_be_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = true;

        let operand =
            SimpleBoolean(Boolean::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();
        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_booleans_with_two_false_operands_should_be_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = false;

        let operand =
            SimpleBoolean(Boolean::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_and_with_two_operands_result_is_correct(
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

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_and_with_zero_should_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 0_u8;

        let operand =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_and_with_max_value_return_same_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = u8::MAX;

        let operand =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_and_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u8; // 00001010
        let other_primitive_operand = 7_u8; // 00000111
        let primitive_result = 2_u8; //00000010

        let operand =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_and_with_zero_should_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 0_u16;

        let operand =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_and_with_max_value_return_same_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = u16::MAX;

        let operand =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_and_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u16; // 0...00001010
        let other_primitive_operand = 7_u16; // 0...00000111
        let primitive_result = 2_u16; // 0...00000010

        let operand =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_and_with_zero_should_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 0_u32;

        let operand =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_and_with_max_value_return_same_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = u32::MAX;

        let operand =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_and_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u32; // 0...00001010
        let other_primitive_operand = 7_u32; // 0...00000111
        let primitive_result = 2_u32; // 0...00000010

        let operand =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_and_with_zero_should_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 0_u64;

        let operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_and_with_max_value_return_same_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = u64::MAX;

        let operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_and_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u64; // 0...00001010
        let other_primitive_operand = 7_u64; // 0...00000111
        let primitive_result = 2_u64; // 0...00000010

        let operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_and_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }
}
