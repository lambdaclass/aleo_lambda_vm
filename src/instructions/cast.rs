use crate::{circuit_io_type::CircuitIOType, record::Record, VMRecordEntriesMap};
use anyhow::{anyhow, bail, Result};
use ark_ff::UniformRand;
use ark_std::rand::thread_rng;
use indexmap::IndexMap;
use simpleworks::gadgets::ConstraintF;
use snarkvm::prelude::{EntryType, Identifier, Literal, Operand, Register, Testnet3};
pub use CircuitIOType::{SimpleAddress, SimpleRecord, SimpleUInt64};

pub fn cast(
    operands: &[Operand<Testnet3>],
    program_variables: &mut IndexMap<String, Option<CircuitIOType>>,
    aleo_record_entries: &IndexMap<Identifier<Testnet3>, EntryType<Testnet3>>,
) -> Result<CircuitIOType> {
    // instruction_operands is an IndexMap only to keep track of the
    // name of the record entries, so then when casting into records
    // we can know which entry is which.
    let mut instruction_operands: IndexMap<String, CircuitIOType> = IndexMap::new();
    for (operand_index, operand) in operands.iter().enumerate() {
        let variable_name = &operand.to_string();
        match (operand, program_variables.get(variable_name)) {
            (Operand::Register(Register::Member(locator, members)), Some(None)) => {
                if let Some(Some(SimpleRecord(record))) =
                    program_variables.get(&format!("r{locator}"))
                {
                    match members
                        .get(0)
                        .ok_or("Error getting the first member of a register member")
                        .map_err(|e| anyhow!("{}", e))?
                        .to_string()
                        .as_str()
                    {
                        "owner" => {
                            let owner_operand = SimpleAddress(record.owner.clone());
                            program_variables
                                .insert(variable_name.to_string(), Some(owner_operand.clone()));
                            instruction_operands.insert(variable_name.to_owned(), owner_operand);
                        }
                        "gates" => {
                            let gates_operand = SimpleUInt64(record.gates.clone());
                            program_variables
                                .insert(variable_name.to_string(), Some(gates_operand.clone()));
                            instruction_operands.insert(variable_name.to_owned(), gates_operand);
                        }
                        entry => {
                            let entry_operand = record
                                .entries
                                .get(entry)
                                .ok_or(format!("Could not find entry `{entry}` in record entries map. Record entries are {entries:?}", entries = record.entries.keys()))
                                .map_err(|e| anyhow!("{e}"))?
                                .clone();
                            program_variables
                                .insert(variable_name.to_string(), Some(entry_operand.clone()));
                            instruction_operands.insert(entry.to_owned(), entry_operand);
                        }
                    };
                }
            }
            (Operand::Register(_), Some(Some(operand))) => {
                // An operand is an entry of the record if the index is greater
                // than 1 because the index 0 is always for the record owner and
                // the index 1 is always for the record gates, the rest are entries.
                let operand_is_entry = operand_index > 1;
                if operand_is_entry {
                    let entry_name = aleo_record_entries
                        .keys()
                        .map(|identifier| identifier.to_string())
                        .collect::<Vec<String>>()
                        .get(operand_index - 2)
                        .ok_or_else(|| anyhow!("Error getting entry name from aleo entries"))?
                        .clone();
                    instruction_operands.insert(entry_name, operand.clone());
                } else {
                    instruction_operands.insert(variable_name.to_owned(), operand.clone());
                }
            }
            (Operand::Register(r), Some(None)) => {
                bail!("Register \"{}\" not assigned in registers", r.to_string())
            }
            (Operand::Register(r), None) => {
                bail!("Register \"{}\" not found in registers", r.to_string())
            }
            (Operand::Literal(Literal::Field(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::Field(v)), Some(None)) => bail!(
                "Literal \"{}\" not assigned in registers",
                Operand::Literal(Literal::Field(*v))
            ),
            (Operand::Literal(Literal::Boolean(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::Boolean(v)), Some(None)) => bail!(
                "Literal \"{}\" not assigned in registers",
                Operand::Literal(Literal::Boolean(*v))
            ),
            (Operand::Literal(Literal::Address(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::Address(v)), Some(None)) => bail!(
                "Literal \"{}\" not assigned in registers",
                Operand::Literal(Literal::Address(*v))
            ),
            (Operand::Literal(Literal::U8(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}u8", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::U8(v)), Some(None)) => bail!(
                "Literal \"{}\"u8 not assigned in registers",
                Operand::Literal(Literal::U8(*v))
            ),
            (Operand::Literal(Literal::U16(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}u16", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::U16(v)), Some(None)) => bail!(
                "Literal \"{}\"u16 not assigned in registers",
                Operand::Literal(Literal::U16(*v))
            ),
            (Operand::Literal(Literal::U32(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}u32", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::U32(v)), Some(None)) => bail!(
                "Literal \"{}\"u32 not assigned in registers",
                Operand::Literal(Literal::U32(*v))
            ),
            (Operand::Literal(Literal::U64(literal_value)), Some(Some(v))) => {
                instruction_operands.insert(format!("{}u64", **literal_value), v.clone());
            }
            (Operand::Literal(Literal::U64(v)), Some(None)) => bail!(
                "Literal \"{}\"u64 not assigned in registers",
                Operand::Literal(Literal::U64(*v))
            ),
            (Operand::Literal(_), _) => bail!("Literal operand not supported"),
            (Operand::ProgramID(_), _) => bail!("ProgramID operands are not supported"),
            (Operand::Caller, _) => bail!("Caller operands are not supported"),
        };
    }
    _cast(instruction_operands)
}

pub fn _cast(operands: IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
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
    use super::_cast;
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
        let record = _cast(operands).unwrap();

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
        let cast_result = _cast(operands);

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
        let cast_result = _cast(operands);

        assert!(cast_result.is_err());
        assert_eq!(
            cast_result.err().unwrap().to_string(),
            "Cast is not supported for the given types"
        );
    }

    // TODO: Add tests for non binary casts
}
