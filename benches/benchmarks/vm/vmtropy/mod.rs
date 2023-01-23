use anyhow::{anyhow, Result};
use rand::rngs::StdRng;
use simpleworks::marlin::{ConstraintSystemRef, MarlinProof, UniversalSRS};
use std::cell::RefCell;
use std::rc::Rc;
pub use vmtropy::build_program;
pub use vmtropy::jaleo::{get_credits_key, mint_credits};
pub use vmtropy::jaleo::{Itertools, UserInputValueType};
use vmtropy::SimpleFunctionVariables;

pub type Function = snarkvm::prelude::Function<snarkvm::prelude::Testnet3>;
pub type Address = vmtropy::jaleo::Address;
pub type Identifier = vmtropy::jaleo::Identifier;
pub type Program = vmtropy::jaleo::Program;
pub type ProgramBuild = vmtropy::ProgramBuild;
pub type Record = vmtropy::jaleo::Record;
pub type EncryptedRecord = vmtropy::jaleo::EncryptedRecord;
pub type ViewKey = vmtropy::jaleo::ViewKey;
pub type PrivateKey = vmtropy::jaleo::PrivateKey;
pub type Field = vmtropy::jaleo::Field;
pub type ProgramID = vmtropy::jaleo::ProgramID;
pub type VerifyingKey = vmtropy::jaleo::VerifyingKey;
pub type ProvingKey = vmtropy::jaleo::ProvingKey;
pub type Deployment = vmtropy::jaleo::Deployment;
pub type Transition = vmtropy::jaleo::Transition;
pub type VerifyingKeyMap = vmtropy::jaleo::VerifyingKeyMap;

// This allows us to execute functions without depending on generating the
// universal srs.
pub fn execute_function(
    program: &Program,
    function_name: &Identifier,
    inputs: &[UserInputValueType],
    private_key: &PrivateKey,
    universal_srs: &UniversalSRS,
    constraint_system: ConstraintSystemRef,
    rng: &mut StdRng,
) -> Result<(SimpleFunctionVariables, MarlinProof)> {
    let function = program.get_function(function_name)?;
    let mut function_variables =
        vmtropy::helpers::function_variables(&function, constraint_system.clone())?;
    let (function_proving_key, _function_verifying_key) = vmtropy::build_function(
        program,
        &function,
        inputs,
        constraint_system.clone(),
        universal_srs,
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
