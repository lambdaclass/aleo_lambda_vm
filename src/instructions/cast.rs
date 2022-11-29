use crate::{circuit_io_type::CircuitIOType, record::Record};
use anyhow::{bail, Result};
use std::collections::HashMap;

pub use CircuitIOType::{SimpleAddress, SimpleRecord, SimpleUInt64};

pub fn cast(operands: &[CircuitIOType]) -> Result<CircuitIOType> {
    match operands {
        [SimpleAddress(address), SimpleUInt64(gates)] => Ok(SimpleRecord(Record {
            owner: address.clone(),
            gates: gates.clone(),
            entries: HashMap::new(),
        })),
        [SimpleUInt64(_gates), SimpleAddress(_address)] => {
            bail!("The order of the operands when casting into a record is reversed")
        }
        [_, _] => bail!("Cast is not supported for the given types"),
        [..] => bail!("Cast is a binary operation"),
    }
}

#[cfg(test)]
mod cast_tests {
    use super::cast;
    use crate::{
        CircuitIOType::{SimpleAddress, SimpleUInt64},
        ConstraintF,
    };
    use ark_r1cs_std::prelude::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use simpleworks::gadgets::{AddressGadget, UInt64Gadget};

    fn address<'address>() -> (&'address str, [u8; 63]) {
        let mut address_bytes = [0_u8; 63];
        let address_str = "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5zh";
        for (address_byte, address_string_byte) in
            address_bytes.iter_mut().zip(address_str.as_bytes())
        {
            *address_byte = *address_string_byte;
        }
        (address_str, address_bytes)
    }

    #[test]
    fn test_successful_record_cast() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let (primitive_address_str, primitive_address_bytes) = address();
        let primitive_gates = 1_u64;

        let owner_address = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_address_bytes)).unwrap(),
        );
        let gates =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_gates)).unwrap());

        let record = cast(&[owner_address, gates]).unwrap();

        assert_eq!(
            record.value().unwrap(),
            format!("Record {{ owner: {primitive_address_str}, gates: {primitive_gates} }}")
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_right_operands_wrong_order_record_cast() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let (_primitive_address_str, primitive_address_bytes) = address();
        let primitive_gates = 1_u64;

        let owner_address = SimpleAddress(
            AddressGadget::new_witness(cs.clone(), || Ok(primitive_address_bytes)).unwrap(),
        );
        let gates = SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_gates)).unwrap());

        let cast_result = cast(&[gates, owner_address]);

        assert!(cast_result.is_err());
        assert_eq!(
            cast_result.err().unwrap().to_string(),
            "The order of the operands when casting into a record is reversed"
        );
    }

    #[test]
    fn test_unsupported_operand_types() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_gates = 1_u64;
        let gates = SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_gates)).unwrap());

        let cast_result = cast(&[gates.clone(), gates]);

        assert!(cast_result.is_err());
        assert_eq!(
            cast_result.err().unwrap().to_string(),
            "Cast is not supported for the given types"
        );
    }

    #[test]
    fn test_cast_is_a_binary_operation() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_gates = 1_u64;
        let gates = SimpleUInt64(UInt64Gadget::new_witness(cs, || Ok(primitive_gates)).unwrap());

        let cast_result = cast(&[gates.clone(), gates.clone(), gates]);

        assert!(cast_result.is_err());
        assert_eq!(
            cast_result.err().unwrap().to_string(),
            "Cast is a binary operation"
        );
    }
}
