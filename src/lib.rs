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

use anyhow::{anyhow, bail, Result};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_std::rand::rngs::StdRng;
use circuit_io_type::CircuitIOType;
use indexmap::IndexMap;
use simpleworks::{
    gadgets::{
        traits::ToFieldElements, AddressGadget, ConstraintF, UInt16Gadget, UInt32Gadget,
        UInt64Gadget,
    },
    marlin::{MarlinProof, ProvingKey, UniversalSRS, VerifyingKey},
};
use snarkvm::prelude::{Function, Parser, Program, Testnet3};
use std::cell::RefCell;
use std::rc::Rc;
pub use variable_type::VariableType;

pub mod circuit_io_type;
mod helpers;
pub mod instructions;
pub mod record;
pub use simpleworks::types::value::SimpleworksValueType;
pub mod variable_type;

pub type CircuitOutputType = IndexMap<String, VariableType>;
pub type SimpleFunctionVariables = IndexMap<String, Option<CircuitIOType>>;
pub type ProgramBuild = IndexMap<String, FunctionKeys>;
pub type FunctionKeys = (ProvingKey, VerifyingKey);

/// Returns the circuit outputs and the marlin proof.
///
/// # Parameters
/// - `function` - function to be analyzed.
/// - `user_inputs` - user inputs of the function.
///  
/// # Returns
/// -  indicates if it´s satisfied the `ConstraintSystem`.
/// -  Circuit Output of the function.
/// -  Marlin Proof of the function.
///
pub fn execute_function(
    function: &Function<Testnet3>,
    user_inputs: &[SimpleworksValueType],
    rng: &mut StdRng,
) -> Result<(CircuitOutputType, MarlinProof)> {
    let universal_srs = simpleworks::marlin::generate_universal_srs(rng)?;
    let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();

    let mut function_variables = helpers::function_variables(function);
    let (function_proving_key, _function_verifying_key) = helpers::build_function(
        function,
        user_inputs,
        constraint_system.clone(),
        &universal_srs,
        &mut function_variables,
    )?;

    let circuit_outputs = helpers::circuit_outputs(function, &function_variables)?;

    // Here we clone the constraint system because deep down when generating
    // the proof the constraint system is consumed and it has to have one
    // reference for it to be consumed.
    let cs_clone = (*constraint_system
        .borrow()
        .ok_or("Error borrowing")
        .map_err(|e| anyhow!("{}", e))?)
    .clone();
    let cs_ref_clone = ConstraintSystemRef::CS(Rc::new(RefCell::new(cs_clone)));

    let proof = simpleworks::marlin::generate_proof(cs_ref_clone, function_proving_key, rng)?;

    Ok((circuit_outputs, proof))
}

/// Builds a program, which means generating the proving and verifying keys
/// for each function in the program.
pub fn build_program(program_string: &str) -> Result<ProgramBuild> {
    let mut rng = simpleworks::marlin::generate_rand();
    let universal_srs = simpleworks::marlin::generate_universal_srs(&mut rng)?;

    let (_, program) = Program::<Testnet3>::parse(program_string).map_err(|e| anyhow!("{}", e))?;

    let mut program_build: ProgramBuild = IndexMap::new();
    for (function_identifier, function) in program.functions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();
        let inputs = helpers::default_user_inputs(function)?;
        let (function_proving_key, function_verifying_key) = match helpers::build_function(
            function,
            &inputs,
            constraint_system.clone(),
            &universal_srs,
            &mut helpers::function_variables(function),
        ) {
            Ok((function_proving_key, function_verifying_key)) => {
                (function_proving_key, function_verifying_key)
            }
            Err(e) => {
                bail!(
                    "Couldn't build function \"{}\": {}",
                    function_identifier.to_string(),
                    e
                );
            }
        };
        program_build.insert(
            function.name().to_string(),
            (function_proving_key, function_verifying_key),
        );
    }

    Ok(program_build)
}

/// Note: this function will always generate the same universal parameters because
/// the rng seed is hardcoded. This is not going to be the case forever, though, as eventually
/// these parameters will be something generated in a setup ceremony and thus it will not be possible
/// to derive them deterministically like this.
pub fn generate_universal_srs() -> Result<UniversalSRS> {
    let rng = &mut simpleworks::marlin::generate_rand();
    simpleworks::marlin::generate_universal_srs(rng)
}

pub fn verify_proof(
    verifying_key: VerifyingKey,
    public_inputs: &[SimpleworksValueType],
    proof: &MarlinProof,
    rng: &mut StdRng,
) -> Result<bool> {
    let mut inputs = vec![];
    for gadget in public_inputs {
        inputs.extend_from_slice(&gadget.to_field_elements()?);
    }
    simpleworks::marlin::verify_proof(verifying_key, &inputs, proof, rng)
}
