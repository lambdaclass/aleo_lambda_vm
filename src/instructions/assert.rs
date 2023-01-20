use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Result};
use ark_r1cs_std::{prelude::{EqGadget, Boolean}, R1CSVar};
use indexmap::IndexMap;
pub use CircuitIOType::{SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};
use ark_r1cs_std::{
    prelude::{AllocVar},
};
use simpleworks::{marlin::ConstraintSystemRef, gadgets::ConstraintF};
pub fn assert_eq(operands: &IndexMap<String, CircuitIOType>, constraint_system: ConstraintSystemRef) -> Result<CircuitIOType> {
    let true_witness = Boolean::<ConstraintF>::new_witness(constraint_system.clone(), || Ok(true))?;

    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
             match right_operand.is_eq(left_operand)?.value() {
                Ok(true) => Ok(true_witness),
                _ => bail!("{} is not equal to {}", left_operand.value()?, right_operand.value()?),
            }
            
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            match right_operand.is_eq(left_operand)?.value() {
                 Ok(true) => Ok(true_witness),
                 _ => bail!("{} is not equal to {}", left_operand.value()?, right_operand.value()?),
            }
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            match right_operand.is_eq(left_operand)?.value() {
                 Ok(true) => Ok(true_witness),
                 _ => bail!("{} is not equal to {}", left_operand.value()?, right_operand.value()?),
            }
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            match right_operand.is_eq(left_operand)?.value() {
                 Ok(true) => Ok(true_witness),
                 _ => bail!("{} is not equal to {}", left_operand.value()?, right_operand.value()?),
            }
        }
        [_, _] => bail!("assert.eq is not supported for the given types"),
        [..] => bail!("assert.eq requires two operands"),
    }
}

pub fn assert_neq(operands: &IndexMap<String, CircuitIOType>, constraint_system: ConstraintSystemRef) -> Result<CircuitIOType> {
    let true_witness = Boolean::<ConstraintF>::new_witness(constraint_system.clone(), || Ok(true))?;

    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            match right_operand.is_eq(left_operand)?.not().value() {
                Ok(true) => Ok(true_witness),
                _ => bail!("{} is equal to {}", left_operand.value()?, right_operand.value()?),
           }
        }
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            match right_operand.is_eq(left_operand)?.not().value() {
                Ok(true) => Ok(true_witness),
                _ => bail!("{} is equal to {}", left_operand.value()?, right_operand.value()?),
           }
        }
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            match right_operand.is_eq(left_operand)?.not().value() {
                 Ok(true) => Ok(true_witness),
                 _ => bail!("{} is equal to {}", left_operand.value()?, right_operand.value()?),
            }
        }
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            match right_operand.is_eq(left_operand)?.not().value() {
                 Ok(true) => Ok(true_witness),
                 _ => bail!("{} is equal to {}", left_operand.value()?, right_operand.value()?),
            }
        }
        [_, _] => bail!("assert.neq is not supported for the given types"),
        [..] => bail!("assert.neq requires two operands"),
    }
}

#[cfg(test)]
mod assert_tests {
    use crate::{instructions::is_eq::is_eq, CircuitIOType};
    use crate::{
        instructions::assert::assert_eq,
        instructions::assert::assert_neq,
        CircuitIOType::{
            SimpleAddress, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
        },
    };
    use anyhow::Result;
    use ark_r1cs_std::prelude::{AllocVar};
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
        if expect_on_eq {
            assert!(assert_eq(operands, cs.clone()).is_ok());
            assert!(assert_neq(operands, cs.clone()).is_err());
        } else {
            assert!(assert_eq(operands, cs.clone()).is_err());
            assert!(assert_neq(operands, cs.clone()).is_ok());
        }

        assert!(cs.is_satisfied()?);

        Ok(())
    }

    #[test]
    fn test_u8_assert_is_true() {
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
    fn test_u8_assert_is_false() {
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
    fn test_u16_assert_is_true() {
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
    fn test_u16_assert_is_false() {
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
    fn test_u32_assert_is_true() {
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
    fn test_u32_assert_is_false() {
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
    fn test_u64_assert_is_true() {
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
    fn test_u64_assert_is_false() {
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
    fn test_assert_with_more_than_two_operands() {
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

        let result = assert_eq(&operands, cs).unwrap_err();

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

        let result_neq = assert_neq(&operands, cs).unwrap_err();
        let result = assert_eq(&operands, cs).unwrap_err();

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
            "assert.eq is not supported for the given types"
        );

        let result = assert_neq(&sample_operands(left_operand, right_operand), cs).unwrap_err();

        assert_eq!(
            result.to_string(),
            "assert.neq is not supported for the given types"
        );
    }
}
