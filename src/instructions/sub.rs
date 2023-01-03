use crate::{
    circuit_io_type::CircuitIOType::{self, SimpleAddress, SimpleRecord},
    ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget,
};
use ark_r1cs_std::{prelude::Boolean, R1CSVar};

use anyhow::{anyhow, bail, ensure, Result};

use indexmap::IndexMap;
use snarkvm::prelude::{Literal, Operand, Register, Testnet3};
pub use CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8};

pub fn sub(
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
    _sub(&instruction_operands)
}

// Aleo instructions support the subtraction of two numbers and not for UInt8.
// We compute the subtraction as an addition thanks to the following:
// minuend - subtrahend = difference
// minuend + module - subtrahend - module = difference
// module - (minuend + module - subtrahend) = difference
// not(minuend + not(subtrahend)) = difference
// where module = 2^size and module - n could be done negating bit by bit in binary so there are no subtractions.
pub fn _sub(operands: &IndexMap<String, CircuitIOType>) -> Result<CircuitIOType> {
    match operands
        .values()
        .collect::<Vec<&CircuitIOType>>()
        .as_slice()
    {
        [SimpleUInt16(minuend), SimpleUInt16(subtrahend)] => {
            ensure!(
                minuend.value()? >= subtrahend.value()?,
                "Subtraction underflow"
            );

            let minuend_as_augend: Vec<Boolean<ConstraintF>> = negate(minuend.to_bits_le());
            let subtrahend_as_addend: Vec<Boolean<ConstraintF>> = subtrahend.to_bits_le();

            let minuend_as_augend_var = UInt16Gadget::from_bits_le(&minuend_as_augend);
            let subtrahend_as_addend_var = UInt16Gadget::from_bits_le(&subtrahend_as_addend);

            let partial_result =
                UInt16Gadget::addmany(&[minuend_as_augend_var, subtrahend_as_addend_var])?;

            let difference = UInt16Gadget::from_bits_le(
                &partial_result
                    .to_bits_le()
                    .into_iter()
                    .map(|bit| bit.not())
                    .collect::<Vec<Boolean<ConstraintF>>>(),
            );

            Ok(SimpleUInt16(difference))
        }
        [SimpleUInt32(minuend), SimpleUInt32(subtrahend)] => {
            ensure!(
                minuend.value()? >= subtrahend.value()?,
                "Subtraction underflow"
            );

            let minuend_as_augend: Vec<Boolean<ConstraintF>> = negate(minuend.to_bits_le());
            let subtrahend_as_addend: Vec<Boolean<ConstraintF>> = subtrahend.to_bits_le();

            let minuend_as_augend_var = UInt32Gadget::from_bits_le(&minuend_as_augend);
            let subtrahend_as_addend_var = UInt32Gadget::from_bits_le(&subtrahend_as_addend);

            let partial_result =
                UInt32Gadget::addmany(&[minuend_as_augend_var, subtrahend_as_addend_var])?;

            let difference = UInt32Gadget::from_bits_le(
                &partial_result
                    .to_bits_le()
                    .into_iter()
                    .map(|bit| bit.not())
                    .collect::<Vec<Boolean<ConstraintF>>>(),
            );

            Ok(SimpleUInt32(difference))
        }
        [SimpleUInt64(minuend), SimpleUInt64(subtrahend)] => {
            ensure!(
                minuend.value()? >= subtrahend.value()?,
                "Subtraction underflow"
            );

            let minuend_as_augend: Vec<Boolean<ConstraintF>> = negate(minuend.to_bits_le());
            let subtrahend_as_addend: Vec<Boolean<ConstraintF>> = subtrahend.to_bits_le();

            let minuend_as_augend_var = UInt64Gadget::from_bits_le(&minuend_as_augend);
            let subtrahend_as_addend_var = UInt64Gadget::from_bits_le(&subtrahend_as_addend);

            let partial_result =
                UInt64Gadget::addmany(&[minuend_as_augend_var, subtrahend_as_addend_var])?;

            let difference = UInt64Gadget::from_bits_le(
                &partial_result
                    .to_bits_le()
                    .into_iter()
                    .map(|bit| bit.not())
                    .collect::<Vec<Boolean<ConstraintF>>>(),
            );

            Ok(SimpleUInt64(difference))
        }
        [_, _] => bail!("Subtraction is not supported for the given types"),
        [..] => bail!("Subtraction requires two operands"),
    }
}

fn negate(bits: Vec<Boolean<ConstraintF>>) -> Vec<Boolean<ConstraintF>> {
    bits.into_iter()
        .map(|bit| bit.not())
        .collect::<Vec<Boolean<ConstraintF>>>()
}

#[cfg(test)]
mod subtract_tests {
    use ark_r1cs_std::prelude::AllocVar;
    use ark_relations::r1cs::{ConstraintSystem, Namespace};
    use indexmap::IndexMap;

    use crate::{
        CircuitIOType::{SimpleUInt16, SimpleUInt32, SimpleUInt64},
        ConstraintF, UInt16Gadget, UInt32Gadget, UInt64Gadget,
    };

    #[test]
    fn test_u16_difference_is_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u16;
        let primitive_subtrahend = 1_u16;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::_sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u16_difference_is_positive() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 2_u16;
        let primitive_subtrahend = 1_u16;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::_sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u16_negative_difference_should_not_be_possible() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u16;
        let primitive_subtrahend = 2_u16;

        let minuend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt16(
            UInt16Gadget::new_witness(Namespace::new(cs, None), || Ok(primitive_subtrahend))
                .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::_sub(&operands);

        if let Err(err) = result_var {
            assert_eq!(err.to_string(), "Subtraction underflow");
        } else {
            panic!("Subtraction should have failed");
        }
    }

    #[test]
    fn test_u32_difference_is_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u32;
        let primitive_subtrahend = 1_u32;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::_sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u32_difference_is_positive() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 2_u32;
        let primitive_subtrahend = 1_u32;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::_sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u32_negative_difference_should_not_be_possible() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u32;
        let primitive_subtrahend = 2_u32;

        let minuend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt32(
            UInt32Gadget::new_witness(Namespace::new(cs, None), || Ok(primitive_subtrahend))
                .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::_sub(&operands);

        if let Err(err) = result_var {
            assert_eq!(err.to_string(), "Subtraction underflow");
        } else {
            panic!("Subtraction should have failed");
        }
    }

    #[test]
    fn test_u64_difference_is_zero() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u64;
        let primitive_subtrahend = 1_u64;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::_sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u64_difference_is_positive() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 2_u64;
        let primitive_subtrahend = 1_u64;
        let primitive_result = primitive_minuend - primitive_subtrahend;

        let minuend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                Ok(primitive_subtrahend)
            })
            .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::_sub(&operands).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(primitive_result.to_string(), result_var.value().unwrap());
    }

    #[test]
    fn test_u64_negative_difference_should_not_be_possible() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let primitive_minuend = 1_u64;
        let primitive_subtrahend = 2_u64;

        let minuend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(primitive_minuend))
                .unwrap(),
        );
        let subtrahend_var = SimpleUInt64(
            UInt64Gadget::new_witness(Namespace::new(cs, None), || Ok(primitive_subtrahend))
                .unwrap(),
        );
        let mut operands = IndexMap::new();
        operands.insert("r0".to_owned(), minuend_var);
        operands.insert("r1".to_owned(), subtrahend_var);
        let result_var = super::_sub(&operands);

        if let Err(err) = result_var {
            assert_eq!(err.to_string(), "Subtraction underflow");
        } else {
            panic!("Subtraction should have failed");
        }
    }
}
