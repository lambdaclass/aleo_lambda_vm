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
use ark_r1cs_std::{
    uint128::UInt128, uint16::UInt16, uint32::UInt32, uint64::UInt64, uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace};
use simpleworks::gadgets::AddressGadget;
use simpleworks::types::value::SimpleworksValueType;
use snarkvm::prelude::{Operand, Register};
use snarkvm::{
    circuit::IndexMap,
    prelude::{
        Function, Identifier, LiteralType, Opcode, Parser, PlaintextType, Program, Testnet3,
        ValueType,
    },
};

pub mod circuit_io_type;
pub mod circuit_param_type;
pub mod instructions;
pub mod record;

use record::Record;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

pub type UInt8Gadget = UInt8<ConstraintF>;
pub type UInt16Gadget = UInt16<ConstraintF>;
pub type UInt32Gadget = UInt32<ConstraintF>;
pub type UInt64Gadget = UInt64<ConstraintF>;
pub type UInt128Gadget = UInt128<ConstraintF>;

pub type CircuitOutputType = IndexMap<String, CircuitIOType>;

pub fn execute_function(
    program_string: &str,
    function_name: &str,
    user_inputs: &[SimpleworksValueType],
) -> Result<(bool, CircuitOutputType, Vec<u8>)> {
    let (_, program) = Program::<Testnet3>::parse(program_string).map_err(|e| anyhow!("{}", e))?;

    let function_name = &Identifier::try_from(function_name).map_err(|e| anyhow!("{}", e))?;
    let function = program
        .get_function(function_name)
        .map_err(|e| anyhow!("{}", e))?;

    let cs = ConstraintSystem::<ConstraintF>::new_ref();

    let circuit_inputs =
        circuit_inputs(&function, &cs, user_inputs).map_err(|e| anyhow!("{}", e))?;

    let circuit_outputs =
        circuit_outputs(&function, &circuit_inputs).map_err(|e| anyhow!("{}", e))?;

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

fn circuit_inputs(
    function: &Function<Testnet3>,
    cs: &ConstraintSystemRef<ConstraintF>,
    user_inputs: &[SimpleworksValueType],
) -> Result<IndexMap<String, CircuitIOType>> {
    let mut circuit_inputs = IndexMap::new();
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
            (ValueType::Record(_), SimpleworksValueType::U64(gates)) => {
                let mut address = [0_u8; 63];
                let address_string =
                    "aleo1sk339wl3ch4ee5k3y6f6yrmvs9w63yfsmrs9w0wwkx5a9pgjqggqlkx5zh".as_bytes();
                for (address_byte, address_string_byte) in address.iter_mut().zip(address_string) {
                    *address_byte = *address_string_byte;
                }
                SimpleRecord(Record {
                    owner: AddressGadget::new_witness(Namespace::new(cs.clone(), None), || {
                        Ok(address)
                    })?,
                    gates: UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || {
                        Ok(gates)
                    })?,
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
        circuit_inputs.insert(register.to_string(), circuit_input);
    }
    Ok(circuit_inputs)
}

fn circuit_outputs(
    function: &Function<Testnet3>,
    circuit_inputs: &IndexMap<String, CircuitIOType>,
) -> Result<IndexMap<String, CircuitIOType>> {
    let mut circuit_outputs = IndexMap::new();
    for instruction in function.instructions() {
        let mut instruction_operands_data = Vec::new();
        for operand in instruction.operands() {
            instruction_operands_data.push(match operand {
                // This is the case where the input is a register of record type accessing a field,
                // so something of the form `r0.credits`. The locator is the register number, in this
                // example 0.
                Operand::Register(Register::Member(locator, members)) => {
                    match circuit_inputs.get(&format!("r{locator}")) {
                        Some(circuit_input) => (circuit_input.clone(), Some(members)),
                        None => bail!(
                            "Operand was Register::Member and was not found in the circuit inputs"
                        ),
                    }
                }
                // This is the case where the input is a register which is not a record,  so no field accessing.
                Operand::Register(Register::Locator(_)) => {
                    match circuit_inputs.get(&operand.to_string()) {
                        Some(circuit_input) => (circuit_input.clone(), None),
                        None => bail!(
                            "Operand was Register::Locator and was not found in the circuit inputs"
                        ),
                    }
                }
                Operand::Literal(_) => bail!("Literal operands are not supported"),
                Operand::ProgramID(_) => bail!("ProgramID operands are not supported"),
                Operand::Caller => bail!("Caller operands are not supported"),
            });
        }

        let mut instruction_operands: Vec<CircuitIOType> = Vec::new();
        for operand_data in instruction_operands_data {
            let operand = match operand_data {
                (SimpleRecord(record), Some(members)) => {
                    match members
                        .get(0)
                        .ok_or("Error getting the first member of a register member")
                        .map_err(|e| anyhow!("{}", e))?
                        .to_string()
                        .as_str()
                    {
                        "gates" => SimpleUInt64(record.gates.clone()),
                        _ => bail!("Unsupported record member"),
                    }
                }
                (operand, None) => operand,
                (_, Some(_)) => bail!("Invalid program, tried to add a record"),
            };
            instruction_operands.push(operand);
        }

        let circuit_output = match instruction.opcode() {
            Opcode::Assert(_) => bail!("Assert operations are not supported"),
            Opcode::Call => bail!("Call operation is not supported"),
            Opcode::Cast => bail!("Cast operation is not supported"),
            Opcode::Command(_) => bail!("Command operations are not supported"),
            Opcode::Commit(_) => bail!("Commit operations are not supported"),
            Opcode::Finalize(_) => bail!("Finalize operations are not supported"),
            Opcode::Hash(_) => bail!("Hash operations are not supported"),
            Opcode::Is(_) => bail!("Is operations are not supported"),
            Opcode::Literal("add") => instructions::add(&instruction_operands)?,
            Opcode::Literal("sub") => instructions::subtract(&instruction_operands)?,
            Opcode::Literal(_) => bail!("Unsupported Literal operation"),
        };

        circuit_outputs.insert(
            instruction
                .destinations()
                .get(0)
                .ok_or_else(|| anyhow!("Error getting the destination register"))?
                .to_string(),
            circuit_output,
        );
    }
    Ok(circuit_outputs)
}
