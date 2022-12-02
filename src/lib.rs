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
use indexmap::IndexMap;
use jaleo::{Identifier, UserInputValueType};
pub use simpleworks::marlin::serialization::{deserialize_verifying_key, serialize_verifying_key};
use simpleworks::{
    gadgets::{
        traits::ToFieldElements, AddressGadget, ConstraintF, UInt16Gadget, UInt32Gadget,
        UInt64Gadget,
    },
    marlin::{MarlinProof, ProvingKey, VerifyingKey},
    types::value::SimpleworksValueType,
};
use snarkvm::prelude::{Function, Parser, Program, Testnet3};
use std::cell::RefCell;
use std::rc::Rc;
use universal_srs::load_universal_srs_from_file;

pub mod circuit_io_type;
mod helpers;
pub mod instructions;
pub mod jaleo;
mod record;
pub use record::{Record, VMRecordEntriesMap};
mod variable_type;
pub use variable_type::VariableType;
mod program_build;
pub use program_build::ProgramBuild;
pub use simpleworks::marlin::generate_rand;
pub mod universal_srs;

pub type CircuitOutputType = IndexMap<String, SimpleworksValueType>;
pub type SimpleFunctionVariables = IndexMap<String, Option<CircuitIOType>>;
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
    program: &Program<Testnet3>,
    function_name: &str,
    user_inputs: &[UserInputValueType],
) -> Result<(SimpleFunctionVariables, MarlinProof)> {
    let rng = &mut simpleworks::marlin::generate_rand();
    let universal_srs = simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng)?;
    let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();
    let function = program.get_function(&Identifier::try_from(function_name)?)?;

    let mut function_variables = helpers::function_variables(&function, constraint_system.clone())?;
    let (function_proving_key, _function_verifying_key) = build_function(
        program,
        &function,
        user_inputs,
        constraint_system.clone(),
        &universal_srs,
        &mut function_variables,
    )?;

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

    Ok((function_variables, proof))
}

/// Builds a program, which means generating the proving and verifying keys
/// for each function in the program.
pub fn build_program(program_string: &str) -> Result<ProgramBuild> {
    let universal_srs = load_universal_srs_from_file()?;

    let (_, program) = Program::<Testnet3>::parse(program_string).map_err(|e| anyhow!("{}", e))?;

    let mut program_build = ProgramBuild {
        map: IndexMap::new(),
    };
    for (function_name, function) in program.functions() {
        let constraint_system = ConstraintSystem::<ConstraintF>::new_ref();
        let inputs = helpers::default_user_inputs(&program, function_name)?;
        let (function_proving_key, function_verifying_key) = match build_function(
            &program,
            function,
            &inputs,
            constraint_system.clone(),
            &universal_srs,
            &mut helpers::function_variables(function, constraint_system.clone())?,
        ) {
            Ok((function_proving_key, function_verifying_key)) => {
                (function_proving_key, function_verifying_key)
            }
            Err(e) => {
                bail!(
                    "Couldn't build function \"{}\": {}",
                    function_name.to_string(),
                    e
                );
            }
        };
        program_build.map.insert(
            *function.name(),
            (function_proving_key, function_verifying_key),
        );
    }

    Ok((program, program_build))
}

/// Builds a function, which means generating its proving and verifying keys.
pub fn build_function(
    program: &Program<Testnet3>,
    function: &Function<Testnet3>,
    user_inputs: &[UserInputValueType],
    constraint_system: ConstraintSystemRef<ConstraintF>,
    universal_srs: &UniversalSRS,
    function_variables: &mut SimpleFunctionVariables,
) -> Result<FunctionKeys> {
    helpers::process_inputs(
        function,
        &constraint_system,
        user_inputs,
        function_variables,
    )?;
    helpers::process_outputs(
        program,
        function,
        function_variables,
        constraint_system.clone(),
    )?;
    simpleworks::marlin::generate_proving_and_verifying_keys(universal_srs, constraint_system)
}

/// Note: this function will always generate the same universal parameters because
/// the rng seed is hardcoded. This is not going to be the case forever, though, as eventually
/// these parameters will be something generated in a setup ceremony and thus it will not be possible
/// to derive them deterministically like this.
pub fn generate_universal_srs() -> Result<Box<UniversalSRS>> {
    let rng = &mut simpleworks::marlin::generate_rand();
    simpleworks::marlin::generate_universal_srs(100000, 25000, 300000, rng)
}

pub fn verify_proof(
    verifying_key: VerifyingKey,
    public_inputs: &[UserInputValueType],
    proof: &MarlinProof,
) -> Result<bool> {
    let mut inputs = vec![];
    for gadget in public_inputs {
        inputs.extend_from_slice(&gadget.to_field_elements()?);
    }
    simpleworks::marlin::verify_proof(
        verifying_key,
        &inputs,
        proof,
        &mut simpleworks::marlin::generate_rand(),
    )
}
