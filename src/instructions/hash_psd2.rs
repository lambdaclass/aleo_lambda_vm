use crate::circuit_io_type::CircuitIOType;
use anyhow::{bail, Result};
use ark_r1cs_std::{alloc::AllocVar, R1CSVar, ToBytesGadget};
use indexmap::IndexMap;
use simpleworks::{
    gadgets::{traits::IsWitness, FieldGadget},
    hash,
};
pub use CircuitIOType::{
    SimpleAddress, SimpleField, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
};

// TODO: Generate constraints. Use the Poseidon hash gadget.
pub fn hash_psd2(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt8(value)] => {
            let input = vec![value.clone()].value()?;
            let output = hash::poseidon2_hash(&input)?;

            Ok(SimpleField(FieldGadget::new_witness(value.cs(), || {
                Ok(output)
            })?))
        }
        [SimpleUInt16(value)] => {
            let input = value.to_bytes()?.value()?;
            let output = hash::poseidon2_hash(&input)?;

            Ok(SimpleField(FieldGadget::new_witness(value.cs(), || {
                Ok(output)
            })?))
        }
        [SimpleUInt32(value)] => {
            let input = value.to_bytes()?.value()?;
            let output = hash::poseidon2_hash(&input)?;

            Ok(SimpleField(FieldGadget::new_witness(value.cs(), || {
                Ok(output)
            })?))
        }
        [SimpleUInt64(value)] => {
            let input = value.to_bytes()?.value()?;
            let output = hash::poseidon2_hash(&input)?;

            Ok(SimpleField(FieldGadget::new_witness(value.cs(), || {
                Ok(output)
            })?))
        }
        [SimpleAddress(address)] => {
            let input = address.to_bytes()?.value()?;
            let output = hash::poseidon2_hash(&input)?;

            Ok(SimpleField(FieldGadget::new_witness(address.cs(), || {
                Ok(output)
            })?))
        }
        [_] => bail!("hash.psd2 is not supported for the given type"),
        [..] => bail!("hash.psd2 requires one operand"),
    }
}

#[cfg(test)]
mod hash_psd2_unit_tests {
    use ark_r1cs_std::prelude::{AllocVar, Boolean};
    use ark_relations::r1cs::ConstraintSystem;
    use indexmap::IndexMap;
    use simpleworks::gadgets::{
        AddressGadget, ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget, UInt8Gadget,
    };

    use crate::{
        instructions::hash_psd2::hash_psd2,
        CircuitIOType::{
            self, SimpleAddress, SimpleBoolean, SimpleUInt16, SimpleUInt32, SimpleUInt64,
            SimpleUInt8,
        },
    };

    fn sample_hash_operands(operand: CircuitIOType) -> IndexMap<String, CircuitIOType> {
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), operand);
        operands
    }

    #[test]
    fn test_u8_hash_psd2() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_input_value = 0x01_u8;

        let input = SimpleUInt8(
            UInt8Gadget::new_witness(cs.clone(), || Ok(primitive_input_value)).unwrap(),
        );

        let output = hash_psd2(&sample_hash_operands(input.clone())).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(output, CircuitIOType::SimpleField(_)));
        assert_ne!(output.value().unwrap(), input.value().unwrap())
    }

    #[test]
    fn test_u16_hash_psd2() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_input_value = 0x01_u16;

        let input = SimpleUInt16(
            UInt16Gadget::new_witness(cs.clone(), || Ok(primitive_input_value)).unwrap(),
        );

        let output = hash_psd2(&sample_hash_operands(input.clone())).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(output, CircuitIOType::SimpleField(_)));
        assert_ne!(output.value().unwrap(), input.value().unwrap())
    }

    #[test]
    fn test_u32_hash_psd2() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_input_value = 0x01_u32;

        let input = SimpleUInt32(
            UInt32Gadget::new_witness(cs.clone(), || Ok(primitive_input_value)).unwrap(),
        );

        let output = hash_psd2(&sample_hash_operands(input.clone())).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(output, CircuitIOType::SimpleField(_)));
        assert_ne!(output.value().unwrap(), input.value().unwrap())
    }

    #[test]
    fn test_u64_hash_psd2() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_input_value = 0x01_u64;

        let input = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_input_value)).unwrap(),
        );

        let output = hash_psd2(&sample_hash_operands(input.clone())).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(output, CircuitIOType::SimpleField(_)));
        assert_ne!(output.value().unwrap(), input.value().unwrap())
    }

    #[test]
    fn test_address_hash_psd2() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_address = b"aleo11111111111111111111111111111111111111111111111111111111111";

        let input = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_address)).unwrap(),
        );

        let output = hash_psd2(&sample_hash_operands(input)).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(matches!(output, CircuitIOType::SimpleField(_)));
        // Output value is not a valid utf8 so we can't compare it to the input
        // assert_ne!(output.value().unwrap(), input.value().unwrap())
    }

    #[test]
    fn test_hash_psd2_with_no_operands() {
        let result = hash_psd2(&IndexMap::new()).unwrap_err();

        assert_eq!(result.to_string(), "hash.psd2 requires one operand");
    }

    #[test]
    fn test_hash_psd2_with_multiple_operands() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_input_value = 0x01_u64;
        let primitive_second_value = 0x01_u64;

        let input = SimpleUInt64(
            UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_input_value)).unwrap(),
        );
        let second_value =
            SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_second_value)).unwrap());

        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), input);
        operands.insert("r1".to_owned(), second_value);

        let result = hash_psd2(&operands).unwrap_err();

        assert_eq!(result.to_string(), "hash.psd2 requires one operand");
    }

    #[test]
    fn test_hash_psd2_with_invalid_operand() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let primitive_input_value = true;

        let input = SimpleBoolean(
            Boolean::<ConstraintF>::new_witness(cs, || Ok(primitive_input_value)).unwrap(),
        );

        let result = hash_psd2(&sample_hash_operands(input)).unwrap_err();

        assert_eq!(
            result.to_string(),
            "hash.psd2 is not supported for the given type"
        );
    }
}
