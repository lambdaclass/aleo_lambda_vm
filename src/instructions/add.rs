use crate::{
    circuit_io_type::CircuitIOType::{self, SimpleAddress, SimpleRecord},
    UInt16Gadget, UInt32Gadget, UInt64Gadget,
};

use anyhow::{anyhow, bail, Result};

use indexmap::IndexMap;
use snarkvm::prelude::{Literal, Operand, Register, Testnet3};
pub use CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn add(
    operands: &[Operand<Testnet3>],
    program_variables: &mut IndexMap<String, Option<CircuitIOType>>,
) -> Result<CircuitIOType> {
    // instruction_operands is an IndexMap only to keep track of the
    // name of the record entries, so then when casting into records
    // we can know which entry is which.
    let mut instruction_operands: IndexMap<String, CircuitIOType> = IndexMap::new();
    for operand in operands {
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
                instruction_operands.insert(variable_name.to_owned(), operand.clone());
            }
            (Operand::Register(r), Some(None)) => {
                bail!("Register \"{}\" not assigned in registers", r.to_string())
            }
            (Operand::Register(r), None) => {
                bail!("Register \"{}\" not found in registers", r.to_string())
            }
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
    _add(&instruction_operands)
}

// Aleo instructions support the addition of two numbers and not for UInt8.
pub fn _add(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        // [SimpleUInt8(addend), SimpleUInt8(augend)] => Ok(SimpleUInt8(UInt8::<ConstraintF>::addmany(&[addend.clone(), augend.clone()])?)),
        [SimpleUInt16(addend), SimpleUInt16(augend)] => {
            Ok(SimpleUInt16(UInt16Gadget::addmany(&[
                addend.clone(),
                augend.clone(),
            ])?))
        }
        [SimpleUInt32(addend), SimpleUInt32(augend)] => {
            Ok(SimpleUInt32(UInt32Gadget::addmany(&[
                addend.clone(),
                augend.clone(),
            ])?))
        }
        [SimpleUInt64(addend), SimpleUInt64(augend)] => {
            Ok(SimpleUInt64(UInt64Gadget::addmany(&[
                addend.clone(),
                augend.clone(),
            ])?))
        }
        [..] => bail!("Unsupported operand types for addmany"),
    }
}
