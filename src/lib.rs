#![warn(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![warn(
    clippy::allow_attributes_without_reason,
    clippy::as_conversions,
    clippy::unnecessary_cast,
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::default_numeric_fallback,
    clippy::deref_by_slicing,
    clippy::empty_structs_with_brackets,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::indexing_slicing,
    clippy::map_err_ignore,
    clippy::single_char_lifetime_names,
    clippy::str_to_string,
    clippy::string_add,
    clippy::string_slice,
    clippy::string_to_string,
    clippy::todo,
    clippy::try_err,
    clippy::unseparated_literal_suffix
)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::let_underscore_must_use
)]

use std::cell::RefCell;
use std::rc::Rc;

use crate::circuit_io_type::{
    CircuitIOType, SimpleAddress, SimpleRecord, SimpleUInt128, SimpleUInt16, SimpleUInt32,
    SimpleUInt64, SimpleUInt8,
};
use anyhow::{anyhow, bail, Result};
use ark_r1cs_std::prelude::AllocVar;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace};
use ark_serialize::CanonicalDeserialize;
use indexmap::IndexMap;
use simpleworks::marlin::{MarlinProof, VerifyingKey};
use simpleworks::types::value::SimpleworksValueType;
use snarkvm::prelude::{Function, Instruction, LiteralType, PlaintextType, Testnet3, ValueType};
use snarkvm::prelude::{Operand, Register};
use std::collections::HashMap;

pub mod circuit_io_type;
pub mod circuit_param_type;
pub mod instructions;
pub mod record;

use simpleworks::gadgets::traits::ToFieldElements;

use record::Record;

use simpleworks::gadgets::{
    AddressGadget, ConstraintF, UInt128Gadget, UInt16Gadget, UInt32Gadget, UInt64Gadget,
    UInt8Gadget,
};
pub type CircuitOutputType = IndexMap<String, CircuitIOType>;

pub type SimpleProgramVariables = IndexMap<String, Option<CircuitIOType>>;

pub fn execute_function(
    function: Function<Testnet3>,
    user_inputs: &[SimpleworksValueType],
) -> Result<(bool, CircuitOutputType, Vec<u8>)> {
    let cs = ConstraintSystem::<ConstraintF>::new_ref();

    let mut program_variables = program_variables(&function);

    process_inputs(&function, &cs, user_inputs, &mut program_variables)?;
    process_outputs(&function, &mut program_variables)?;

    let circuit_outputs = circuit_outputs(&function, &program_variables)?;

    let is_satisfied = cs.is_satisfied().map_err(|e| anyhow!("{}", e))?;

    let cs_clone = (*cs
        .borrow()
        .ok_or("Error borrowing")
        .map_err(|e| anyhow!("{}", e))?)
    .clone();
    let cs_ref_clone = ConstraintSystemRef::CS(Rc::new(RefCell::new(cs_clone)));

    let mut rng = simpleworks::marlin::generate_rand();
    let universal_srs = simpleworks::marlin::generate_universal_srs(&mut rng)?;
    let bytes_proof = simpleworks::marlin::generate_proof(&universal_srs, &mut rng, cs_ref_clone)?;

    Ok((is_satisfied, circuit_outputs, bytes_proof))
}

pub fn verify_execution(
    verifying_key_serialized: Vec<u8>,
    public_inputs: &[CircuitIOType],
    proof_serialized: Vec<u8>,
) -> Result<bool> {
    let verifying_key = VerifyingKey::deserialize(&mut verifying_key_serialized.as_slice())?;
    let proof = MarlinProof::deserialize(&mut proof_serialized.as_slice())?;

    let mut inputs = vec![];
    for gadget in public_inputs {
        inputs.push(gadget.to_field_elements()?);
    }
    let inputs_flattened: Vec<ConstraintF> = inputs.into_iter().flatten().collect();

    simpleworks::marlin::verify_proof(verifying_key, &inputs_flattened, proof)
}

// This function builds the scaffold of the program variables.
// We use a hash map for such variables, where the key is the variable name
// and the value is the variable type.
// All the values start as None, and will be filled in the next steps.
// For example, this would be the output of executing this function for
// credits.aleo's transfer function:
// {
//     "r0": None,
//     "r0.gates": None,
//     "r0.owner": None,
//     "r1": None,
//     "r2": None,
//     "r3": None,
//     "r4": None,
//     "r5": None,
// }
fn program_variables(function: &Function<Testnet3>) -> SimpleProgramVariables {
    let mut registers: SimpleProgramVariables = IndexMap::new();

    let function_inputs: Vec<String> = function
        .inputs()
        .into_iter()
        .map(|i| i.register().to_string())
        .collect();

    let function_outputs: Vec<String> = function
        .outputs()
        .into_iter()
        .map(|o| o.register().to_string())
        .collect();

    function.inputs().into_iter().for_each(|i| {
        registers.insert(i.register().to_string(), None);
    });
    function.instructions().iter().for_each(|i| {
        i.operands().iter().for_each(|o| {
            if !function_outputs.contains(&o.to_string())
                && !function_inputs.contains(&o.to_string())
            {
                registers.insert(o.to_string(), None);
            }
        });
        i.destinations().iter().for_each(|d| {
            if !function_outputs.contains(&d.to_string()) {
                registers.insert(d.to_string(), None);
            }
        });
    });

    for function_output in function_outputs {
        registers.insert(function_output, None);
    }

    registers
}

fn circuit_outputs(
    function: &Function<Testnet3>,
    program_variables: &SimpleProgramVariables,
) -> Result<CircuitOutputType> {
    let mut circuit_outputs = IndexMap::new();
    function.outputs().iter().try_for_each(|o| {
        let register = o.register().to_string();
        let result = program_variables
            .get(&register)
            .ok_or_else(|| anyhow!("Register not found"))
            .and_then(|r| r.clone().ok_or_else(|| anyhow!("Register not assigned")))?;
        circuit_outputs.insert(register, result);
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(circuit_outputs)
}

fn process_inputs(
    function: &Function<Testnet3>,
    cs: &ConstraintSystemRef<ConstraintF>,
    user_inputs: &[SimpleworksValueType],
    program_variables: &mut SimpleProgramVariables,
) -> Result<()> {
    for (function_input, user_input) in function.inputs().iter().zip(user_inputs) {
        let register = function_input.register();
        let circuit_input = match (function_input.value_type(), user_input) {
            // Public UInt
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U8)),
                SimpleworksValueType::U8(v),
            ) => SimpleUInt8(UInt8Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U16)),
                SimpleworksValueType::U16(v),
            ) => SimpleUInt16(UInt16Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U32)),
                SimpleworksValueType::U32(v),
            ) => SimpleUInt32(UInt32Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U64)),
                SimpleworksValueType::U64(v),
            ) => SimpleUInt64(UInt64Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::U128)),
                SimpleworksValueType::U128(v),
            ) => SimpleUInt128(UInt128Gadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            // Public Address
            (
                ValueType::Public(PlaintextType::Literal(LiteralType::Address)),
                SimpleworksValueType::Address(a),
            ) => SimpleAddress(AddressGadget::new_input(
                Namespace::new(cs.clone(), None),
                || Ok(a),
            )?),
            // Private UInt
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U8)),
                SimpleworksValueType::U8(v),
            ) => SimpleUInt8(UInt8Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U16)),
                SimpleworksValueType::U16(v),
            ) => SimpleUInt16(UInt16Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U32)),
                SimpleworksValueType::U32(v),
            ) => SimpleUInt32(UInt32Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U64)),
                SimpleworksValueType::U64(v),
            ) => SimpleUInt64(UInt64Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::U128)),
                SimpleworksValueType::U128(v),
            ) => SimpleUInt128(UInt128Gadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(v),
            )?),
            // Private Address
            (
                ValueType::Private(PlaintextType::Literal(LiteralType::Address)),
                SimpleworksValueType::Address(a),
            ) => SimpleAddress(AddressGadget::new_witness(
                Namespace::new(cs.clone(), None),
                || Ok(a),
            )?),
            // Literal Type Error Cases
            (
                ValueType::Private(PlaintextType::Literal(
                    LiteralType::Address
                    | LiteralType::U128
                    | LiteralType::U64
                    | LiteralType::U32
                    | LiteralType::U16
                    | LiteralType::U8,
                ))
                | ValueType::Public(PlaintextType::Literal(
                    LiteralType::Address
                    | LiteralType::U128
                    | LiteralType::U64
                    | LiteralType::U32
                    | LiteralType::U16
                    | LiteralType::U8,
                )),
                _,
            ) => {
                bail!("Mismatched function input type with user input type")
            }
            // Unsupported Cases
            (ValueType::Public(_) | ValueType::Private(_), _) => bail!("Unsupported type"),
            // Records
            // TODO: User input should be SimpleworksValueType::Record.
            (ValueType::Record(_), SimpleworksValueType::Record(address, gates)) => {
                SimpleRecord(Record {
                    owner: AddressGadget::new_witness(Namespace::new(cs.clone(), None), || {
                        Ok(address)
                    })?,
                    gates: UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                        Ok(gates)
                    })?,
                    entries: HashMap::new(),
                })
            }
            (ValueType::Record(_), _) => {
                bail!("Mismatched function input type with user input type")
            }
            // Constant Types
            (ValueType::Constant(_), _) => bail!("Constant types are not supported"),
            // External Records
            (ValueType::ExternalRecord(_), _) => bail!("ExternalRecord types are not supported"),
        };
        program_variables.insert(register.to_string(), Some(circuit_input));
    }

    Ok(())
}

fn process_outputs(
    function: &Function<Testnet3>,
    program_variables: &mut SimpleProgramVariables,
) -> Result<()> {
    for instruction in function.instructions() {
        let mut instruction_operands = Vec::new();
        for operand in instruction.operands() {
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
                                instruction_operands.push(owner_operand);
                            }
                            "gates" => {
                                let gates_operand = SimpleUInt64(record.gates.clone());
                                program_variables
                                    .insert(variable_name.to_string(), Some(gates_operand.clone()));
                                instruction_operands.push(gates_operand);
                            }
                            _ => bail!("Unsupported record member"),
                        };
                    }
                }
                (Operand::Register(_), Some(Some(operand))) => {
                    instruction_operands.push(operand.clone());
                }
                (Operand::Register(_), Some(None)) => bail!("Register not assigned in registers"),
                (Operand::Register(_), None) => bail!("Register not found in registers"),
                (Operand::Literal(_), _) => bail!("Literal operands are not supported"),
                (Operand::ProgramID(_), _) => bail!("ProgramID operands are not supported"),
                (Operand::Caller, _) => bail!("Caller operands are not supported"),
            };
        }

        let circuit_output = match instruction {
            Instruction::Add(_) => instructions::add(&instruction_operands)?,
            Instruction::Cast(_) => instructions::cast(&instruction_operands)?,
            Instruction::Sub(_) => instructions::subtract(&instruction_operands)?,
            _ => bail!(
                "{} instruction is not supported currently",
                instruction.opcode()
            ),
        };

        let destination = instruction
            .destinations()
            .get(0)
            .ok_or_else(|| anyhow!("Error getting the destination register"))?
            .to_string();

        program_variables.insert(destination, Some(circuit_output));
    }
    Ok(())
}
