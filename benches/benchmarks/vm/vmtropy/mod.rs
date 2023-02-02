use anyhow::{anyhow, Result};
use rand::rngs::StdRng;
use simpleworks::marlin::{ConstraintSystemRef, MarlinProof, UniversalSRS};
use std::cell::RefCell;
use std::rc::Rc;
pub use lambdavm::build_program;
pub use lambdavm::jaleo::{get_credits_key, mint_credits};
pub use lambdavm::jaleo::{Itertools, UserInputValueType};
use lambdavm::SimpleFunctionVariables;

pub type Function = snarkvm::prelude::Function<snarkvm::prelude::Testnet3>;
pub type Address = lambdavm::jaleo::Address;
pub type Identifier = lambdavm::jaleo::Identifier;
pub type Program = lambdavm::jaleo::Program;
pub type ProgramBuild = lambdavm::ProgramBuild;
pub type Record = lambdavm::jaleo::Record;
pub type EncryptedRecord = lambdavm::jaleo::EncryptedRecord;
pub type ViewKey = lambdavm::jaleo::ViewKey;
pub type PrivateKey = lambdavm::jaleo::PrivateKey;
pub type Field = lambdavm::jaleo::Field;
pub type ProgramID = lambdavm::jaleo::ProgramID;
pub type VerifyingKey = lambdavm::jaleo::VerifyingKey;
pub type ProvingKey = lambdavm::jaleo::ProvingKey;
pub type Deployment = lambdavm::jaleo::Deployment;
pub type Transition = lambdavm::jaleo::Transition;
pub type VerifyingKeyMap = lambdavm::jaleo::VerifyingKeyMap;

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
        lambdavm::helpers::function_variables(&function, constraint_system.clone())?;
    let (function_proving_key, _function_verifying_key) = lambdavm::build_function(
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
