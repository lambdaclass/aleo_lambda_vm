use crate::{circuit_io_type::CircuitIOType, record::Record, VMRecordEntriesMap};
use anyhow::{bail, Result};
use ark_ff::UniformRand;
use ark_std::rand::thread_rng;
use indexmap::IndexMap;
use simpleworks::gadgets::ConstraintF;
pub use CircuitIOType::{SimpleAddress, SimpleRecord, SimpleUInt64};

pub fn cast(operands: IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .into_iter()
        .collect::<Vec<(String, CircuitIOType)>>()
        .as_slice()
    {
        [(_, SimpleAddress(address)), (_, SimpleUInt64(gates)), entries @ ..] => {
            let mut entries_map = VMRecordEntriesMap::new();
            for (key, value) in entries {
                entries_map.insert(key.to_owned(), value.clone());
            }
            Ok(SimpleRecord(Record {
                owner: address.clone(),
                gates: gates.clone(),
                entries: entries_map,
                nonce: ConstraintF::rand(&mut thread_rng()),
            }))
        }
        [(_, SimpleUInt64(_gates)), (_, SimpleAddress(_address)), ..] => {
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
    use indexmap::IndexMap;
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

        let mut operands = IndexMap::new();
        operands.insert("owner".to_owned(), owner_address);
        operands.insert("gates".to_owned(), gates);
        let record = cast(operands).unwrap();

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

        let mut operands = IndexMap::new();
        operands.insert("owner".to_owned(), gates);
        operands.insert("gates".to_owned(), owner_address);
        let cast_result = cast(operands);

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

        let mut operands = IndexMap::new();
        operands.insert("owner".to_owned(), gates.clone());
        operands.insert("gates".to_owned(), gates);
        let cast_result = cast(operands);

        assert!(cast_result.is_err());
        assert_eq!(
            cast_result.err().unwrap().to_string(),
            "Cast is not supported for the given types"
        );
    }

    // TODO: Add tests for non binary casts
}
