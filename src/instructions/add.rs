use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Result};
use indexmap::IndexMap;
use simpleworks::gadgets::traits::ArithmeticGadget;
pub use CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

// Aleo instructions support the addition of two numbers and not for UInt8.
pub fn add(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(addend), SimpleUInt8(augend)] => {
            let result = addend.add(augend)?;
            Ok(SimpleUInt8(result))
        }
        [SimpleUInt16(addend), SimpleUInt16(augend)] => {
            let result = addend.add(augend)?;
            Ok(SimpleUInt16(result))
        }
        [SimpleUInt32(addend), SimpleUInt32(augend)] => {
            let result = addend.add(augend)?;
            Ok(SimpleUInt32(result))
        }
        [SimpleUInt64(addend), SimpleUInt64(augend)] => {
            let result = addend.add(augend)?;
            Ok(SimpleUInt64(result))
        }
        [_, _] => bail!("add is not supported for the given types"),
        [..] => bail!("add requires two operands"),
    }
}

#[cfg(test)]
mod add_tests {
    use crate::CircuitIOType::{
        SimpleAddress, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
    };
    use ark_r1cs_std::prelude::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::gadgets::{
        AddressGadget, ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget,
    };

    use crate::{instructions::add::add, CircuitIOType};

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

    #[test]
    fn test_u8_add() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 16_u8;
        let primitive_right_operand = 0_u8;

        let left_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleUInt8(UInt8Gadget::constant(primitive_left_operand));

        let result = add(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(&result, CircuitIOType::SimpleUInt8(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_add_u16() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 2_u16;
        let primitive_right_operand = 3_u16;

        let left_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        let expected_result = SimpleUInt16(UInt16Gadget::constant(
            primitive_left_operand + primitive_right_operand,
        ));
        let result = add(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(&result, CircuitIOType::SimpleUInt16(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_add_u32() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 5_u32;
        let primitive_right_operand = 10_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );

        let expected_result = SimpleUInt32(UInt32Gadget::constant(
            primitive_left_operand + primitive_right_operand,
        ));

        let result = add(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(&result, CircuitIOType::SimpleUInt32(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_add_u64() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 2_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleUInt64(UInt64Gadget::constant(primitive_left_operand));

        let result = add(&sample_operands(left_operand, right_operand)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(result, CircuitIOType::SimpleUInt64(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_add_with_more_than_two_operands() {
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

        let result = add(&operands).unwrap_err();

        assert_eq!(result.to_string(), "add requires two operands");
    }

    #[test]
    fn test_add_with_less_than_two_operands() {
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

        let result = add(&operands).unwrap_err();

        assert_eq!(result.to_string(), "add requires two operands");
    }

    #[test]
    fn test_add_with_invalid_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let (_address_string, primitive_left_operand) = address(0);
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_right_operand)).unwrap());

        let result = add(&sample_operands(left_operand, right_operand)).unwrap_err();

        assert_eq!(
            result.to_string(),
            "add is not supported for the given types"
        );
    }
}
