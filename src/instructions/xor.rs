use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Ok, Result};
use indexmap::IndexMap;
use simpleworks::gadgets::traits::BitwiseOperationGadget;
pub use CircuitIOType::{
    SimpleBoolean, SimpleInt8, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
};

pub fn xor(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleBoolean(left_operand), SimpleBoolean(right_operand)] => {
            let result = left_operand.xor(right_operand)?;
            Ok(SimpleBoolean(result))
        }
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            let result = left_operand.xor(right_operand)?;
            Ok(SimpleUInt8(result))
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            let result = left_operand.xor(right_operand)?;
            Ok(SimpleUInt16(result))
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            let result = left_operand.xor(right_operand)?;
            Ok(SimpleUInt32(result))
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            let result = left_operand.xor(right_operand)?;
            Ok(SimpleUInt64(result))
        }
        [SimpleInt8(left_operand), SimpleInt8(right_operand)] => {
            let result = left_operand.xor(right_operand)?;
            Ok(SimpleInt8(result))
        }
        [_, _] => bail!("xor is not supported for the given types"),
        [..] => bail!("xor requires two operands"),
    }
}

#[cfg(test)]
mod xor_unit_tests {
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

    use super::xor;

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
    fn assert_that_xor_with_two_operands_result_is_correct(
        constraint_system: ConstraintSystemRef,
        first_operand: CircuitIOType,
        second_operand: CircuitIOType,
        expected_result: CircuitIOType,
    ) {
        assert!(constraint_system.is_satisfied().unwrap());

        let result = xor(&sample_operands(first_operand, second_operand)).unwrap();
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
        assert_that_xor_with_two_operands_result_is_correct(
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

        assert_that_xor_with_two_operands_result_is_correct(
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

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_xor_with_zero_should_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 0_u8;

        let operand =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_xor_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = u8::MAX;
        let zero_primitive_operand = 0_u8;

        let operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u8_xor_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u8; // 00001010
        let other_primitive_operand = 7_u8; // 00000111
        let primitive_result = 13_u8; //00001101

        let operand =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_xor_with_zero_should_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 0_u16;

        let operand =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_xor_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = u16::MAX;
        let zero_primitive_operand = 0_u16;

        let operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u16_xor_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u16; // 0...00001010
        let other_primitive_operand = 7_u16; // 0...00000111
        let primitive_result = 13_u16; // 0...00001101

        let operand =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt16(UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_xor_with_zero_should_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 0_u32;

        let operand =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_xor_with_max_value_return_same_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = u32::MAX;
        let zero_primitive_operand = 0_u32;

        let operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u32_xor_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u32; // 0...00001010
        let other_primitive_operand = 7_u32; // 0...00000111
        let primitive_result = 13_u32; // 0...00001101

        let operand =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt32(UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_xor_with_zero_should_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 0_u64;

        let operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_xor_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = u64::MAX;
        let zero_primitive_operand = 0_u64;

        let operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap(),
        );

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_xor_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 10_u64; // 0...00001010
        let other_primitive_operand = 7_u64; // 0...00000111
        let primitive_result = 13_u64; // 0...00001101

        let operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }

    #[test]
    fn test_i8_xor_with_zero_should_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 0_i8;

        let operand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let expected_result = operand.clone();

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_i8_xor_with_max_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = i8::MAX;
        let zero_primitive_operand = 0_i8;

        let operand = SimpleInt8(
            Int8Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap());

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_u64_xor_with_min_value_return_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let max_value_primitive_operand = i8::MIN;
        let zero_primitive_operand = 0_i8;

        let operand = SimpleInt8(
            Int8Gadget::new_witness(cs.clone(), || Ok(max_value_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(zero_primitive_operand)).unwrap());

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand.clone(),
            operand,
            expected_result,
        );
    }

    #[test]
    fn test_i8_xor_with_two_numbers_return_correct_new_number() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_operand = 20_i8; // 0...00001010
        let other_primitive_operand = -15_i8; // 0...00000111
        let primitive_result = -27_i8; // 0...00001101

        let operand =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_operand)).unwrap());
        let another_operand = SimpleInt8(
            Int8Gadget::new_witness(cs.clone(), || Ok(other_primitive_operand)).unwrap(),
        );
        let expected_result =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_result)).unwrap());

        assert_that_xor_with_two_operands_result_is_correct(
            cs,
            operand,
            another_operand,
            expected_result,
        );
    }
}
