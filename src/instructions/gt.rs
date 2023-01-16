use crate::{
    circuit_io_type::CircuitIOType, ConstraintF
};
use anyhow::{bail, Result};
use ark_r1cs_std::{prelude::{Boolean, AllocVar}, R1CSVar, select::CondSelectGadget};
use indexmap::IndexMap;
pub use CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8, SimpleBoolean};
use simpleworks::{marlin::ConstraintSystemRef};

pub fn gt(
    operands: &IndexMap<String, CircuitIOType>,
    constraint_system: ConstraintSystemRef,
)  -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(left_operand), SimpleUInt8(right_operand)] => {
            let gt = left_operand.value()? > right_operand.value()?;
            Ok(SimpleBoolean(Boolean::conditionally_select(
                &Boolean::new_witness(constraint_system.clone(), || Ok(gt))?,
                &Boolean::<ConstraintF>::TRUE,
                &Boolean::<ConstraintF>::FALSE,
            )?))
        },
        [SimpleUInt16(left_operand), SimpleUInt16(right_operand)] => {
            let gt = left_operand.value()? > right_operand.value()?;
            Ok(SimpleBoolean(Boolean::conditionally_select(
                &Boolean::new_witness(constraint_system.clone(), || Ok(gt))?,
                &Boolean::<ConstraintF>::TRUE,
                &Boolean::<ConstraintF>::FALSE,
            )?))
        },
        [SimpleUInt32(left_operand), SimpleUInt32(right_operand)] => {
            let gt = left_operand.value()? > right_operand.value()?;
            Ok(SimpleBoolean(Boolean::conditionally_select(
                &Boolean::new_witness(constraint_system.clone(), || Ok(gt))?,
                &Boolean::<ConstraintF>::TRUE,
                &Boolean::<ConstraintF>::FALSE,
            )?))
        },
        [SimpleUInt64(left_operand), SimpleUInt64(right_operand)] => {
            let gt = left_operand.value()? > right_operand.value()?;
            Ok(SimpleBoolean(Boolean::conditionally_select(
                &Boolean::new_witness(constraint_system.clone(), || Ok(gt))?,
                &Boolean::<ConstraintF>::TRUE,
                &Boolean::<ConstraintF>::FALSE,
            )?))
        } 
        [_, _] => bail!("gt is not supported for the given types"),
        [..] => bail!("gt requires two operands"),
    }
}

#[cfg(test)]
mod gt_tests {
    use crate::CircuitIOType::{
        SimpleAddress, SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
    };
    use ark_r1cs_std::prelude::{AllocVar, Boolean};
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::gadgets::{
        AddressGadget, ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget,
    };

    use crate::{instructions::gt, CircuitIOType};

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
    fn test_equal_u8_gt_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 0_u8;
        let primitive_right_operand = 0_u8;

        let left_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::FALSE);

        assert!(cs.is_satisfied().unwrap());
        let result = gt(&sample_operands(left_operand, right_operand), cs).unwrap();

        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u8_gt_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u8;
        let primitive_right_operand = 0_u8;

        let left_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::TRUE);

        assert!(cs.is_satisfied().unwrap());
        let result = gt(&sample_operands(left_operand, right_operand), cs).unwrap();

        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u16_gt_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 10_u16;
        let primitive_right_operand = 0_u16;

        let left_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::TRUE);

        assert!(cs.is_satisfied().unwrap());
        let result = gt(&sample_operands(left_operand, right_operand), cs).unwrap();

        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u16_gt_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u16;
        let primitive_right_operand = 3_u16;

        let left_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::FALSE);

        assert!(cs.is_satisfied().unwrap());
        let result = gt(&sample_operands(left_operand, right_operand), cs).unwrap();

        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u32_gt_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 5_u32;
        let primitive_right_operand = 0_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::TRUE);

        assert!(cs.is_satisfied().unwrap());
        let result = gt(&sample_operands(left_operand, right_operand), cs).unwrap();

        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u32_gt_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 4_u32;
        let primitive_right_operand = 6_u32;

        let left_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::FALSE);

        assert!(cs.is_satisfied().unwrap());
        let result = gt(&sample_operands(left_operand, right_operand), cs).unwrap();

        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u64_gt_is_true() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::TRUE);

        assert!(cs.is_satisfied().unwrap());
        let result = gt(&sample_operands(left_operand, right_operand), cs).unwrap();

        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_u64_gt_is_false() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 1_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap(),
        );
        let expected_result = SimpleBoolean(Boolean::<ConstraintF>::FALSE);

        assert!(cs.is_satisfied().unwrap());
        let result = gt(&sample_operands(left_operand, right_operand), cs).unwrap();

        assert!(matches!(result, CircuitIOType::SimpleBoolean(_)));
        assert_eq!(result.value().unwrap(), expected_result.value().unwrap());
    }

    #[test]
    fn test_gt_with_more_than_two_operands() {
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
        let third_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_third_operand)).unwrap());

        let mut operands = sample_operands(left_operand, right_operand);
        operands.insert("r2".to_owned(), third_operand);

        let result = gt(&operands, cs).unwrap_err();

        assert_eq!(result.to_string(), "gt requires two operands");
    }

    #[test]
    fn test_gt_with_less_than_two_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_left_operand = 1_u64;
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap());

        let mut operands = sample_operands(left_operand, right_operand);
        operands.remove("r1");

        let result = gt(&operands, cs).unwrap_err();

        assert_eq!(result.to_string(), "gt requires two operands");
    }

    #[test]
    fn test_gt_with_invalid_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let (_address_string, primitive_left_operand) = address(0);
        let primitive_right_operand = 0_u64;

        let left_operand = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_left_operand)).unwrap(),
        );
        let right_operand =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_right_operand)).unwrap());

        let result = gt(&sample_operands(left_operand, right_operand), cs).unwrap_err();

        assert_eq!(
            result.to_string(),
            "gt is not supported for the given types"
        );
    }
}
