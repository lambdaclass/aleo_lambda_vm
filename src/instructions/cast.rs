use std::str::FromStr;

use crate::{circuit_io_type::CircuitIOType, helpers, record::Record, VMRecordEntriesMap};
use anyhow::{anyhow, bail, Result};
use ark_ff::UniformRand;
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean},
    R1CSVar,
};
use ark_std::rand::thread_rng;
use indexmap::IndexMap;
use simpleworks::{
    gadgets::{
        traits::IsWitness, AddressGadget, ConstraintF, FieldGadget, UInt16Gadget, UInt32Gadget,
        UInt64Gadget, UInt8Gadget,
    },
    marlin::ConstraintSystemRef,
};
use snarkvm::prelude::{
    EntryType, Identifier, Literal, LiteralType, Operand, PlaintextType, Register, Testnet3,
};
pub use CircuitIOType::{SimpleAddress, SimpleRecord, SimpleUInt64};

pub fn cast(
    operands: &[Operand<Testnet3>],
    program_variables: &mut IndexMap<String, Option<CircuitIOType>>,
    aleo_record_entries: &IndexMap<Identifier<Testnet3>, EntryType<Testnet3>>,
    constraint_system: ConstraintSystemRef,
) -> Result<CircuitIOType> {
    // instruction_operands is an IndexMap only to keep track of the
    // name of the record entries, so then when casting into records
    // we can know which entry is which.
    let mut instruction_operands: IndexMap<String, CircuitIOType> = IndexMap::new();
    for (operand_index, operand) in operands.iter().enumerate() {
        let variable_name = &operand.to_string();
        match (operand, program_variables.get(variable_name)) {
            // Handle register members
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
            // Handle registers
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
                    let entry = aleo_record_entries
                        .get(&Identifier::from_str(&entry_name)?)
                        .ok_or_else(|| anyhow!("Error getting entry name from aleo entries"))?;
                    let entry_operand: Result<CircuitIOType> = match (entry, operand) {
                        (
                            EntryType::Constant(PlaintextType::Literal(LiteralType::Address)),
                            CircuitIOType::SimpleAddress(operand_value),
                        ) => Ok(CircuitIOType::SimpleAddress(AddressGadget::new_constant(
                            constraint_system.clone(),
                            helpers::to_address(operand_value.value()?),
                        )?)),
                        (
                            EntryType::Constant(PlaintextType::Literal(LiteralType::Boolean)),
                            CircuitIOType::SimpleBoolean(operand_value),
                        ) => Ok(CircuitIOType::SimpleBoolean(
                            Boolean::<ConstraintF>::new_constant(
                                constraint_system.clone(),
                                operand_value.value()?,
                            )?,
                        )),
                        (
                            EntryType::Constant(PlaintextType::Literal(LiteralType::Field)),
                            CircuitIOType::SimpleField(operand_value),
                        ) => Ok(CircuitIOType::SimpleField(FieldGadget::new_constant(
                            constraint_system.clone(),
                            operand_value.value()?,
                        )?)),
                        (
                            EntryType::Constant(PlaintextType::Literal(LiteralType::U8)),
                            CircuitIOType::SimpleUInt8(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt8(UInt8Gadget::new_constant(
                            constraint_system.clone(),
                            operand_value.value()?,
                        )?)),
                        (
                            EntryType::Constant(PlaintextType::Literal(LiteralType::U16)),
                            CircuitIOType::SimpleUInt16(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt16(UInt16Gadget::new_constant(
                            constraint_system.clone(),
                            operand_value.value()?,
                        )?)),
                        (
                            EntryType::Constant(PlaintextType::Literal(LiteralType::U32)),
                            CircuitIOType::SimpleUInt32(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt32(UInt32Gadget::new_constant(
                            constraint_system.clone(),
                            operand_value.value()?,
                        )?)),
                        (
                            EntryType::Constant(PlaintextType::Literal(LiteralType::U64)),
                            CircuitIOType::SimpleUInt64(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt64(UInt64Gadget::new_constant(
                            constraint_system.clone(),
                            operand_value.value()?,
                        )?)),
                        (
                            EntryType::Public(PlaintextType::Literal(LiteralType::Address)),
                            CircuitIOType::SimpleAddress(operand_value),
                        ) => Ok(CircuitIOType::SimpleAddress(AddressGadget::new_input(
                            constraint_system.clone(),
                            || Ok(helpers::to_address(operand_value.value()?)),
                        )?)),
                        (
                            EntryType::Public(PlaintextType::Literal(LiteralType::Boolean)),
                            CircuitIOType::SimpleBoolean(operand_value),
                        ) => Ok(CircuitIOType::SimpleBoolean(
                            Boolean::<ConstraintF>::new_input(constraint_system.clone(), || {
                                operand_value.value()
                            })?,
                        )),
                        (
                            EntryType::Public(PlaintextType::Literal(LiteralType::Field)),
                            CircuitIOType::SimpleField(operand_value),
                        ) => Ok(CircuitIOType::SimpleField(FieldGadget::new_input(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Public(PlaintextType::Literal(LiteralType::U8)),
                            CircuitIOType::SimpleUInt8(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt8(UInt8Gadget::new_input(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Public(PlaintextType::Literal(LiteralType::U16)),
                            CircuitIOType::SimpleUInt16(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt16(UInt16Gadget::new_input(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Public(PlaintextType::Literal(LiteralType::U32)),
                            CircuitIOType::SimpleUInt32(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt32(UInt32Gadget::new_input(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Public(PlaintextType::Literal(LiteralType::U64)),
                            CircuitIOType::SimpleUInt64(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt64(UInt64Gadget::new_input(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Private(PlaintextType::Literal(LiteralType::Address)),
                            CircuitIOType::SimpleAddress(operand_value),
                        ) => Ok(CircuitIOType::SimpleAddress(AddressGadget::new_witness(
                            constraint_system.clone(),
                            || Ok(helpers::to_address(operand_value.value()?)),
                        )?)),
                        (
                            EntryType::Private(PlaintextType::Literal(LiteralType::Boolean)),
                            CircuitIOType::SimpleBoolean(operand_value),
                        ) => Ok(CircuitIOType::SimpleBoolean(
                            Boolean::<ConstraintF>::new_witness(constraint_system.clone(), || {
                                operand_value.value()
                            })?,
                        )),
                        (
                            EntryType::Private(PlaintextType::Literal(LiteralType::Field)),
                            CircuitIOType::SimpleField(operand_value),
                        ) => Ok(CircuitIOType::SimpleField(FieldGadget::new_witness(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Private(PlaintextType::Literal(LiteralType::U8)),
                            CircuitIOType::SimpleUInt8(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt8(UInt8Gadget::new_witness(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Private(PlaintextType::Literal(LiteralType::U16)),
                            CircuitIOType::SimpleUInt16(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt16(UInt16Gadget::new_witness(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Private(PlaintextType::Literal(LiteralType::U32)),
                            CircuitIOType::SimpleUInt32(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt32(UInt32Gadget::new_witness(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Private(PlaintextType::Literal(LiteralType::U64)),
                            CircuitIOType::SimpleUInt64(operand_value),
                        ) => Ok(CircuitIOType::SimpleUInt64(UInt64Gadget::new_witness(
                            constraint_system.clone(),
                            || operand_value.value(),
                        )?)),
                        (
                            EntryType::Constant(PlaintextType::Literal(_))
                            | EntryType::Public(PlaintextType::Literal(_))
                            | EntryType::Private(PlaintextType::Literal(_)),
                            _,
                        ) => bail!("Unsupported literal type as entry"),
                        (
                            EntryType::Constant(PlaintextType::Interface(_))
                            | EntryType::Public(PlaintextType::Interface(_))
                            | EntryType::Private(PlaintextType::Interface(_)),
                            _,
                        ) => bail!("Interface types are not supported yet as entries"),
                    };
                    instruction_operands.insert(entry_name, entry_operand?);
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
    _cast(instruction_operands, constraint_system)
}

pub fn _cast(
    operands: IndexMap<String, CircuitIOType>,
    constraint_system: ConstraintSystemRef,
) -> Result<CircuitIOType> {
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

            let (address, gates) =
                match (address.is_witness()?, gates.is_witness()?) {
                    (true, true) => (address.clone(), gates.clone()),
                    (true, false) => {
                        let gates = UInt64Gadget::new_witness(constraint_system, || {
                            gates.value()
                        })?;
                        (address.clone(), gates)
                    }
                    (false, true) => {
                        let address =
                            AddressGadget::new_witness(constraint_system, || {
                                Ok(helpers::to_address(address.value()?))
                            })?;
                        (address, gates.clone())
                    }
                    (false, false) => {
                        let address =
                            AddressGadget::new_witness(constraint_system.clone(), || {
                                Ok(helpers::to_address(address.value()?))
                            })?;
                        let gates = UInt64Gadget::new_witness(constraint_system, || {
                            gates.value()
                        })?;
                        (address, gates)
                    }
                };

            Ok(SimpleRecord(Record {
                owner: address,
                gates,
                entries: entries_map,
                nonce: ConstraintF::rand(&mut thread_rng()),
            }))
        }
        [] | [_] => bail!("Cast is a two or more operands instruction"),
        _ => bail!("Cast is not supported for the given types"),
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
        let record = _cast(operands, cs.clone()).unwrap();

        assert_eq!(
            record.value().unwrap(),
            format!("Record {{ owner: {primitive_address_str}, gates: {primitive_gates} }}")
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_unsupported_operand_types() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_gates = 1_u64;
        let gates =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_gates)).unwrap());

        let mut operands = IndexMap::new();
        operands.insert("owner".to_owned(), gates.clone());
        operands.insert("gates".to_owned(), gates);
        let cast_result = _cast(operands, cs);

        assert!(cast_result.is_err());
        assert_eq!(
            cast_result.err().unwrap().to_string(),
            "Cast is not supported for the given types"
        );
    }

    #[test]
    fn test_cast_is_a_two_or_more_operand_instruction() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_gates = 1_u64;
        let gates =
            SimpleUInt64(UInt64Gadget::new_witness(cs.clone(), || Ok(primitive_gates)).unwrap());

        let mut operands = IndexMap::new();
        operands.insert("owner".to_owned(), gates);
        let cast_result = _cast(operands, cs);

        assert!(cast_result.is_err());
        assert_eq!(
            cast_result.err().unwrap().to_string(),
            "Cast is a two or more operands instruction"
        );
    }
}
