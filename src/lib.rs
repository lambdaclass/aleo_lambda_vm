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
    // Maybe we could not use this one.
    // clippy::todo,
    clippy::try_err,
    clippy::unseparated_literal_suffix
)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::let_underscore_must_use
)]

use crate::circuit_io_type::{
    CircuitIOType, SimpleUInt16, SimpleUInt32, SimpleUInt64, SimpleUInt8,
};
use anyhow::{anyhow, Result};
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::{
    uint128::UInt128, uint16::UInt16, uint32::UInt32, uint64::UInt64, uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace};
use snarkvm::{
    circuit::IndexMap,
    prelude::{
        Function, Identifier, LiteralType, Opcode, Parser, PlaintextType, Program, Testnet3,
        ValueType,
    },
};

pub mod circuit_io_type;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

// TODO: Move these to simpleworks.
pub type UInt8Gadget = UInt8<ConstraintF>;
pub type UInt16Gadget = UInt16<ConstraintF>;
pub type UInt32Gadget = UInt32<ConstraintF>;
pub type UInt64Gadget = UInt64<ConstraintF>;
pub type UInt128Gadget = UInt128<ConstraintF>;

pub type CircuitOutputType = IndexMap<String, CircuitIOType>;

pub fn execute_function(
    program_string: &str,
    function_name: &str,
) -> Result<(bool, CircuitOutputType)> {
    // FIXME: Maybe the program should be parsed once and then passed to the execute_function.
    // Parse Aleo Program
    let (_, program) = Program::<Testnet3>::parse(program_string).map_err(|e| anyhow!("{}", e))?;

    // Retrieve the function.
    let function_name = &Identifier::try_from(function_name).map_err(|e| anyhow!("{}", e))?;
    let function = program
        .get_function(function_name)
        .map_err(|e| anyhow!("{}", e))?;

    // Now we create a constraint system and the circuit that will verify
    // the signature, but we'll send a bad message.
    let cs = ConstraintSystem::<ConstraintF>::new_ref();
    // Here we map the parse inputs to circuit inputs.
    let circuit_inputs = circuit_inputs(&function, &cs).map_err(|e| anyhow!("{}", e))?;

    // Here we map the parse inputs to circuit outputs.
    let circuit_outputs =
        circuit_outputs(&function, &circuit_inputs).map_err(|e| anyhow!("{}", e))?;

    let is_satisfied = cs.is_satisfied().map_err(|e| anyhow!("{}", e))?;
    Ok((is_satisfied, circuit_outputs))
}

/*
    fn generate_proof() {
        let mut rng = ark_std::test_rng();
        let universal_srs = MarlinInst::universal_setup(100000, 25000, 300000, &mut rng).unwrap();

        // Now, try to generate the verifying key and proving key with Marlin
        let (index_proving_key, index_verifying_key) =
            MarlinInst::index_from_constraint_system(&universal_srs, cs.clone()).unwrap();

        let proof = MarlinInst::prove_from_constraint_system(&index_proving_key, cs, &mut rng).unwrap();

        assert!(MarlinInst::verify(&index_verifying_key, &[], &proof, &mut rng).unwrap());

        let mut bytes = Vec::new();
        proof.serialize(&mut bytes).unwrap();
        println!("Proof bytes: {:?}", bytes);
    }
*/

// TODO: The input values and the function result type are hardcoded.
fn circuit_inputs(
    function: &Function<Testnet3>,
    cs: &ConstraintSystemRef<ConstraintF>,
) -> Result<IndexMap<String, CircuitIOType>> {
    let mut circuit_inputs = IndexMap::new();
    for input in function.inputs() {
        let register = input.register();
        let circuit_input = match input.value_type() {
            ValueType::Constant(_) => todo!(),
            // Public UInt
            ValueType::Public(PlaintextType::Literal(LiteralType::U8)) => SimpleUInt8(
                UInt8Gadget::new_input(Namespace::new(cs.clone(), None), || Ok(0))?,
            ),
            ValueType::Public(PlaintextType::Literal(LiteralType::U16)) => SimpleUInt16(
                UInt16Gadget::new_input(Namespace::new(cs.clone(), None), || Ok(0))?,
            ),
            ValueType::Public(PlaintextType::Literal(LiteralType::U32)) => SimpleUInt32(
                UInt32Gadget::new_input(Namespace::new(cs.clone(), None), || Ok(0))?,
            ),
            ValueType::Public(PlaintextType::Literal(LiteralType::U64)) => SimpleUInt64(
                UInt64Gadget::new_input(Namespace::new(cs.clone(), None), || Ok(0))?,
            ),
            ValueType::Public(PlaintextType::Literal(LiteralType::U128)) => {
                unimplemented!("TODO: Figure out if we want to support U128 operations")
            }
            ValueType::Public(PlaintextType::Literal(_)) => todo!(),
            ValueType::Public(_) => todo!(),
            // Private UInt
            ValueType::Private(PlaintextType::Literal(LiteralType::U8)) => SimpleUInt8(
                UInt8Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(0))?,
            ),
            ValueType::Private(PlaintextType::Literal(LiteralType::U16)) => SimpleUInt16(
                UInt16Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(0))?,
            ),
            ValueType::Private(PlaintextType::Literal(LiteralType::U32)) => SimpleUInt32(
                UInt32Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(0))?,
            ),
            ValueType::Private(PlaintextType::Literal(LiteralType::U64)) => SimpleUInt64(
                UInt64Gadget::new_witness(Namespace::new(cs.clone(), None), || Ok(0))?,
            ),
            ValueType::Private(PlaintextType::Literal(LiteralType::U128)) => {
                unimplemented!("TODO: Figure out if we want to support U128 operations")
            }
            ValueType::Private(PlaintextType::Literal(_)) => todo!(),
            ValueType::Private(_) => todo!(),
            ValueType::Record(_) => todo!(),
            ValueType::ExternalRecord(_) => todo!(),
        };
        circuit_inputs.insert(register.to_string(), circuit_input);
    }
    Ok(circuit_inputs)
}

// TODO: The circuit_inputs and the function result types are hardcoded to
// we could use a generic type here because we except different value types.
fn circuit_outputs(
    function: &Function<Testnet3>,
    circuit_inputs: &IndexMap<String, CircuitIOType>,
) -> Result<IndexMap<String, CircuitIOType>> {
    let mut circuit_outputs = IndexMap::new();
    for instruction in function.instructions() {
        let instruction_operands = instruction
            .operands()
            .iter()
            .map(|o| match circuit_inputs.get(&o.to_string()) {
                Some(circuit_input) => circuit_input.clone(),
                None => todo!(),
            })
            .collect::<Vec<_>>();

        let circuit_output = match instruction.opcode() {
            Opcode::Assert(_) => todo!(),
            Opcode::Call => todo!(),
            Opcode::Cast => todo!(),
            Opcode::Command(_) => todo!(),
            Opcode::Commit(_) => todo!(),
            Opcode::Finalize(_) => todo!(),
            Opcode::Hash(_) => todo!(),
            Opcode::Is(_) => todo!(),
            // FIXME: I don't know if it would be better to move
            // CircuitIOType::addmany implementation here.
            Opcode::Literal("add") => CircuitIOType::addmany(&instruction_operands)?,
            Opcode::Literal(_) => todo!(),
        };
        // TODO: Destinations should be handled better.
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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    fn read_add_program() -> Result<String> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("programs/add/main.aleo");
        // let value = value.value().unwrap_or("".to_owned());
        let program = std::fs::read_to_string(path).unwrap_or_else(|_| "".to_owned());
        Ok(program)
    }

    #[test]
    fn test01_add_with_u16_public_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(&program_string, "hello_1").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test02_add_with_u16_private_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_2").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test03_add_with_u16_private_and_public_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_3").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test04_add_with_u32_public_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_4").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test05_add_with_u32_private_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_5").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test06_add_with_u32_private_and_public_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_6").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test07_add_with_u64_public_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_7").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test08_add_with_u64_private_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_8").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    fn test09_add_with_u64_private_and_public_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_9").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test10_add_with_u128_public_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_10").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test11_add_with_u128_private_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_11").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }

    #[test]
    #[ignore = "U128 is supported in certain fields, TODO: Figure out if we want to support U128 operations"]
    fn test12_add_with_u128_private_and_public_inputs() {
        let program_string = read_add_program().unwrap();

        let (ret_ok, circuit_outputs) =
            super::execute_function(program_string.as_str(), "hello_12").unwrap();
        assert!(ret_ok);

        for (register, output) in circuit_outputs {
            println!("{}: {:?}", register, output.value().unwrap());
        }
    }
}
