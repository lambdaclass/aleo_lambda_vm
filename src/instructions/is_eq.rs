use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Result};
use ark_r1cs_std::prelude::EqGadget;
use indexmap::IndexMap;
pub use CircuitIOType::{SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn is_eq(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [_, _] => bail!("is.eq is not supported for the given types"),
        [..] => bail!("is.eq requires two operands"),
    }
}

pub fn is_neq(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_neq(left_operand)?))
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            Ok(SimpleBoolean(right_operand.is_eq(left_operand)?))
        }
        [_, _] => bail!("is.neq is not supported for the given types"),
        [..] => bail!("is.neq requires two operands"),
    }
}

#[cfg(test)]
mod equality_tests {
    use crate::{instructions::is_eq::is_eq, CircuitIOType};
    use crate::{
        instructions::is_eq::is_neq,
        CircuitIOType::{
            SimpleAddress, SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
        },
    };
    use anyhow::Result;
    use ark_r1cs_std::prelude::{AllocVar, Boolean};
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::{
        gadgets::{
            AddressGadget, ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget,
        },
        marlin::ConstraintSystemRef,
    };

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

    fn assert_equality_instructions(
        operands: &IndexMap<String, CircuitIOType>,
        cs: ConstraintSystemRef,
        expect_on_eq: bool,
    ) -> Result<()> {
        let result_eq = is_eq(operands)?;
        let result_neq = is_neq(operands)?;

        let (expect_eq, expect_neq) = match expect_on_eq {
            true => (
                SimpleBoolean(Boolean::<ConstraintF>::TRUE),
                SimpleBoolean(Boolean::<ConstraintF>::FALSE),
            ),
            false => (
                SimpleBoolean(Boolean::<ConstraintF>::FALSE),
                SimpleBoolean(Boolean::<ConstraintF>::TRUE),
            ),
        };

        assert!(cs.is_satisfied()?);

        assert!(matches!(result_eq, CircuitIOType::SimpleBoolean(_)));
        assert!(matches!(result_neq, CircuitIOType::SimpleBoolean(_)));

        assert_eq!(result_eq.value()?, expect_eq.value()?);
        assert_eq!(result_neq.value()?, expect_neq.value()?);
        Ok(())
    }

    #[test]
    fn test_u8_is_eq_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u8;
        let primitive_right_operand = 0_u8;

        let left_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert_equality_instructions(&sample_operands(left_operand, right_operand), cs, true)
            .unwrap();
    }

    #[test]
    fn test_u8_is_eq_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u8;
        let primitive_right_operand = 0_u8;

        let left_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert_equality_instructions(&sample_operands(left_operand, right_operand), cs, false)
            .unwrap();
    }

    #[test]
    fn test_u16_is_eq_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u16;
        let primitive_right_operand = 0_u16;

        let left_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert_equality_instructions(&sample_operands(left_operand, right_operand), cs, true)
            .unwrap();
    }

    #[test]
    fn test_u16_is_eq_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u16;
        let primitive_right_operand = 0_u16;

        let left_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert_equality_instructions(&sample_operands(left_operand, right_operand), cs, false)
            .unwrap();
    }

    #[test]
    fn test_u32_is_eq_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u32;
        let primitive_right_operand = 0_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert_equality_instructions(&sample_operands(left_operand, right_operand), cs, true)
            .unwrap();
    }

    #[test]
    fn test_u32_is_eq_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u32;
        let primitive_right_operand = 0_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert_equality_instructions(&sample_operands(left_operand, right_operand), cs, false)
            .unwrap();
    }

    #[test]
    fn test_u64_is_eq_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert_equality_instructions(&sample_operands(left_operand, right_operand), cs, true)
            .unwrap();
    }

    #[test]
    fn test_u64_is_eq_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        assert_equality_instructions(&sample_operands(left_operand, right_operand), cs, false)
            .unwrap();
    }

    #[test]
    fn test_is_eq_with_more_than_two_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;
        let primitive_third_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let third_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_third_operand)).unwrap());

        let mut operands = sample_operands(left_operand, right_operand);
        operands.insert("r2".to_owned(), third_operand);

        let result = is_eq(&operands).unwrap_err();

        assert_eq!(result.to_string(), "is.eq requires two operands");
    }

    #[test]
    fn test_is_eq_with_less_than_two_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_right_operand)).unwrap());

        let mut operands = sample_operands(left_operand, right_operand);
        operands.remove("r1");

        let result_neq = is_neq(&operands).unwrap_err();
        let result = is_eq(&operands).unwrap_err();

        assert!(result.to_string().contains("requires two operands"));
        assert!(result_neq.to_string().contains("requires two operands"));
    }

    #[test]
    fn test_is_eq_with_invalid_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let (_address_string, primitive_left_operand) = address(0);
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_right_operand)).unwrap());

        let result = is_eq(&sample_operands(
            left_operand.clone(),
            right_operand.clone(),
        ))
        .unwrap_err();

        assert_eq!(
            result.to_string(),
            "is.eq is not supported for the given types"
        );

        let result = is_neq(&sample_operands(left_operand, right_operand)).unwrap_err();

        assert_eq!(
            result.to_string(),
            "is.neq is not supported for the given types"
        );
    }
}
