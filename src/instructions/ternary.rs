use crate::{
    circuit_io_type::CircuitIOType::{self, SimpleAddress},
    UInt16Gadget, UInt32Gadget, UInt64Gadget,
};
use anyhow::{bail, Result};
use ark_r1cs_std::{select::CondSelectGadget, R1CSVar};
use indexmap::IndexMap;
use simpleworks::gadgets::{Int8Gadget, UInt8Gadget};
pub use CircuitIOType::{
    SimpleBoolean, SimpleInt8, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
};

pub fn ternary(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleBoolean(condition), SimpleUInt8(true_value), SimpleUInt8(false_value)] => {
            Ok(SimpleUInt8(UInt8Gadget::conditionally_select(
                condition,
                true_value,
                false_value,
            )?))
        }
        [SimpleBoolean(condition), SimpleUInt16(true_value), SimpleUInt16(false_value)] => {
            Ok(SimpleUInt16(UInt16Gadget::conditionally_select(
                condition,
                true_value,
                false_value,
            )?))
        }
        [SimpleBoolean(condition), SimpleUInt32(true_value), SimpleUInt32(false_value)] => {
            Ok(SimpleUInt32(UInt32Gadget::conditionally_select(
                condition,
                true_value,
                false_value,
            )?))
        }
        [SimpleBoolean(condition), SimpleUInt64(true_value), SimpleUInt64(false_value)] => {
            Ok(SimpleUInt64(UInt64Gadget::conditionally_select(
                condition,
                true_value,
                false_value,
            )?))
        }
        [SimpleBoolean(condition), SimpleInt8(true_value), SimpleInt8(false_value)] => {
            Ok(SimpleInt8(Int8Gadget::conditionally_select(
                condition,
                true_value,
                false_value,
            )?))
        }
        // TODO: Replace with AddressGadget::conditionally_select when https://github.com/lambdaclass/simpleworks/pull/47 is merged.
        [SimpleBoolean(condition), SimpleAddress(true_value), SimpleAddress(false_value)] => {
            if condition.value()? {
                Ok(SimpleAddress(true_value.clone()))
            } else {
                Ok(SimpleAddress(false_value.clone()))
            }
        }
        [SimpleBoolean(_), _, _] => bail!("mismatching operand values in ternary instruction"),
        [_, _, _] => bail!("ternary is not supported for the given types"),
        [..] => bail!("ternary requires three operands"),
    }
}

#[cfg(test)]
mod ternary_tests {
    use ark_r1cs_std::prelude::{AllocVar, Boolean};
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::gadgets::{
        AddressGadget, ConstraintF, Int8Gadget, UInt16Gadget, UInt32Gadget, UInt64Gadget,
        UInt8Gadget,
    };

    use crate::{
        instructions::ternary::ternary,
        CircuitIOType::{
            self, SimpleAddress, SimpleBoolean, SimpleInt8, SimpleUInt16, SimpleUInt32,
            SimpleUInt64, SimpleUInt8,
        },
    };

    fn sample_ternary_operands(
        condition: CircuitIOType,
        true_value: CircuitIOType,
        false_value: CircuitIOType,
    ) -> IndexMap<String, CircuitIOType> {
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), condition);
        operands.insert("r1".to_owned(), true_value);
        operands.insert("r2".to_owned(), false_value);
        operands
    }

    #[test]
    fn test_u8_ternary_true_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = true;
        let primitive_true_value = 0_u8;
        let primitive_false_value = 0_u8;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap());
        let false_value = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );
        let expected_result = true_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleUInt8(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u8_ternary_false_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = false;
        let primitive_true_value = 0_u8;
        let primitive_false_value = 0_u8;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap());
        let false_value = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );
        let expected_result = false_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleUInt8(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u16_ternary_true_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = true;
        let primitive_true_value = 0_u16;
        let primitive_false_value = 0_u16;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );
        let expected_result = true_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleUInt16(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u16_ternary_false_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = false;
        let primitive_true_value = 0_u16;
        let primitive_false_value = 0_u16;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );
        let expected_result = false_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleUInt16(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u32_ternary_true_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = true;
        let primitive_true_value = 0_u32;
        let primitive_false_value = 0_u32;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );
        let expected_result = true_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleUInt32(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u32_ternary_false_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = false;
        let primitive_true_value = 0_u32;
        let primitive_false_value = 0_u32;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );
        let expected_result = false_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleUInt32(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u64_ternary_true_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = true;
        let primitive_true_value = 0_u64;
        let primitive_false_value = 0_u64;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );
        let expected_result = true_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleUInt64(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u64_ternary_false_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = false;
        let primitive_true_value = 0_u64;
        let primitive_false_value = 0_u64;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );
        let expected_result = false_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleUInt64(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_i8_ternary_true_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = true;
        let primitive_true_value = -1_i8;
        let primitive_false_value = 1_i8;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap());
        let false_value =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap());
        let expected_result = true_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleInt8(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_i8_ternary_false_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = false;
        let primitive_true_value = -1_i8;
        let primitive_false_value = 1_i8;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap());
        let false_value =
            SimpleInt8(Int8Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap());
        let expected_result = false_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleInt8(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_address_ternary_true_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = true;
        let primitive_true_value =
            b"aleo11111111111111111111111111111111111111111111111111111111111";
        let primitive_false_value =
            b"aleo13rgfynqdpvega6f5gwvajt8w0cnrmvy0zzg9tqmuc5y4upk2vs9sgk3a3d";

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );

        let expected_result = true_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleAddress(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_address_ternary_false_value() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = false;
        let primitive_true_value =
            b"aleo11111111111111111111111111111111111111111111111111111111111";
        let primitive_false_value =
            b"aleo13rgfynqdpvega6f5gwvajt8w0cnrmvy0zzg9tqmuc5y4upk2vs9sgk3a3d";

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );

        let expected_result = false_value.clone();

        let result = ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleAddress(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_ternary_with_invalid_condition() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = 0_u64;
        let primitive_true_value = 0_u64;
        let primitive_false_value = 0_u64;

        let condition = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_false_value)).unwrap());

        let result =
            ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap_err();

        assert_eq!(
            result.to_string(),
            "ternary is not supported for the given types"
        );
    }

    #[test]
    fn test_ternary_with_mismatching_values() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = true;
        let primitive_true_value = 0_u8;
        let primitive_false_value = 0_u64;

        let condition =
            SimpleBoolean(Boolean::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap());
        let true_value =
            SimpleUInt8(UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap());
        let false_value =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_false_value)).unwrap());

        let result =
            ternary(&sample_ternary_operands(condition, true_value, false_value)).unwrap_err();

        assert_eq!(
            result.to_string(),
            "mismatching operand values in ternary instruction"
        );
    }

    #[test]
    fn test_ternary_with_more_than_three_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = false;
        let primitive_true_value = 0_u64;
        let primitive_false_value = 0_u64;
        let primitive_fourth_operand = 0_u64;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_false_value)).unwrap(),
        );
        let fourth_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_fourth_operand)).unwrap());

        let mut operands = sample_ternary_operands(condition, true_value, false_value);
        operands.insert("r3".to_owned(), fourth_operand);

        let result = ternary(&operands).unwrap_err();

        assert_eq!(result.to_string(), "ternary requires three operands");
    }

    #[test]
    fn test_ternary_with_less_than_three_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_condition = false;
        let primitive_true_value = 0_u64;
        let primitive_false_value = 0_u64;

        let condition = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(primitive_condition)).unwrap(),
        );
        let true_value = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_true_value)).unwrap(),
        );
        let false_value =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_false_value)).unwrap());

        let mut operands = sample_ternary_operands(condition, true_value, false_value);
        operands.remove("r2");

        let result = ternary(&operands).unwrap_err();

        assert_eq!(result.to_string(), "ternary requires three operands");
    }
}
