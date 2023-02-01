/// This module contains code for partial order functions:
/// - GreaterThan (`gt`)
/// - GreaterThanOrEqual (`gte`)
/// - LessThanOrEqual (`lte`)
/// - LessThan (`lt`)
use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Result};

use indexmap::IndexMap;
use simpleworks::gadgets::traits::ComparisonGadget;
use simpleworks::gadgets::Comparison;
use simpleworks::marlin::ConstraintSystemRef;
pub use CircuitIOType::{SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn compare(
    operands: &IndexMap<String, CircuitIOType>,
    constraint_system: ConstraintSystemRef,
    comparison: Comparison,
) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            let result = left_operand.compare(right_operand, comparison, constraint_system)?;
            Ok(SimpleBoolean(result))
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            let result = left_operand.compare(right_operand, comparison, constraint_system)?;
            Ok(SimpleBoolean(result))
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            let result = left_operand.compare(right_operand, comparison, constraint_system)?;
            Ok(SimpleBoolean(result))
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            let result = left_operand.compare(right_operand, comparison, constraint_system)?;
            Ok(SimpleBoolean(result))
        }
        [_, _] => bail!(
            "{} is not supported for the given types",
            comparison.instruction()
        ),
        [..] => bail!("{} requires two operands", comparison.instruction()),
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod compare_tests {
    use crate::CircuitIOType::{
        SimpleAddress, SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
    };
    use ark_r1cs_std::prelude::{AllocVar, Boolean};
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::{gadgets::{
        AddressGadget, ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget,
    }, marlin::ConstraintSystemRef};

    use crate::{instructions::compare, CircuitIOType};

    use super::Comparison;

    fn address(n: u64) -> (String, [u8; 63]) {
        let mut address_bytes = [0_u8; 63];
        let address_string =
            format!("aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5z{n}");
        for (address_byte, address_string_byte) in
            address_bytes.iter_mut().zip(address_string.as_bytes())
        {
            *address_byte = *address_string_byte;
        }
        (address_string, address_bytes)
    }

    fn sample_operands(
        left_operand: CircuitIOType,
        right_operand: CircuitIOType,
    ) -> IndexMap<String, CircuitIOType> {
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), left_operand);
        operands.insert("r1".to_owned(), right_operand);
        operands
    }
    
    #[allow(clippy::unwrap_used)]
    fn compare_assert(left_operand: &CircuitIOType, right_operand: &CircuitIOType, cs: ConstraintSystemRef, comparison_method: Comparison, expected_result: bool) {
        let result = compare(&sample_operands(left_operand.clone(), right_operand.clone()), cs,comparison_method).unwrap();
        let expected_result = match expected_result {
            true => SimpleBoolean(Boolean::<ConstraintF>::TRUE),
            false => SimpleBoolean(Boolean::<ConstraintF>::FALSE)
        };

        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn compare_u8_equal() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u8;
        let primitive_right_operand = 0_u8;

        let left_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert!(cs.is_satisfied().unwrap());
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThan, false);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::LessThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs, Comparison::LessThan, false);
    }

    #[test]
    fn compare_u8_left_bigger() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u8;
        let primitive_right_operand = 0_u8;

        let left_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert!(cs.is_satisfied().unwrap());
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThan, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::LessThanOrEqual, false);
        compare_assert(&left_operand, &right_operand, cs, Comparison::LessThan, false);
    }

    #[test]
    fn compare_u16_left_bigger() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 10_u16;
        let primitive_right_operand = 0_u16;

        let left_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThan, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::LessThanOrEqual, false);
        compare_assert(&left_operand, &right_operand, cs, Comparison::LessThan, false);
    }

    #[test]
    fn compare_u16_right_bigger() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u16;
        let primitive_right_operand = 3_u16;

        let left_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThan, false);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThanOrEqual, false);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::LessThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs, Comparison::LessThan, true);
    }

    #[test]
    fn compare_u32_left_bigger() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 5_u32;
        let primitive_right_operand = 0_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThan, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::LessThanOrEqual, false);
        compare_assert(&left_operand, &right_operand, cs, Comparison::LessThan, false);
    }

    #[test]
    fn compare_u32_equal() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 6_u32;
        let primitive_right_operand = 6_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThan, false);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::LessThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs, Comparison::LessThan, false);
    }

    #[test]
    fn compare_u32_right_bigger() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 4_u32;
        let primitive_right_operand = 6_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThan, false);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThanOrEqual, false);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::LessThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs, Comparison::LessThan, true);
    }

    #[test]
    fn compare_u64_left_bigger() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThan, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::LessThanOrEqual, false);
        compare_assert(&left_operand, &right_operand, cs, Comparison::LessThan, false);
    }

    #[test]
    fn compare_u64_equal() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 1_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThan, false);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::GreaterThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs.clone(), Comparison::LessThanOrEqual, true);
        compare_assert(&left_operand, &right_operand, cs, Comparison::LessThan, false);
    }

    #[test]
    fn compare_with_more_than_two_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 2_u64;
        let primitive_third_operand = 3_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let third_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_third_operand)).unwrap(),
        );

        let mut operands = sample_operands(left_operand, right_operand);
        operands.insert("r2".to_owned(), third_operand);

        let result = compare(&operands, cs, Comparison::GreaterThan).unwrap_err();

        assert_eq!(result.to_string(), "gt requires two operands");
    }

    #[test]
    fn compare_with_less_than_two_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        let mut operands = sample_operands(left_operand, right_operand);
        operands.remove("r1");

        let result = compare(&operands, cs, Comparison::LessThanOrEqual).unwrap_err();

        assert!(result.to_string().contains("requires two operands"));
    }

    #[test]
    fn compare_with_invalid_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let (_address_string, primitive_left_operand) = address(0);
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        let result = compare(&sample_operands(left_operand, right_operand), cs, Comparison::GreaterThan).unwrap_err();

        assert!(
            result.to_string().contains("is not supported for the given types")
        );
    }
}
