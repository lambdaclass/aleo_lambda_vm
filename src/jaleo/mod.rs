use std::str::FromStr;

pub mod address;

use anyhow::{anyhow, Result};
use simpleworks::{gadgets::ConstraintF, marlin::generate_rand};
pub use snarkvm::prelude::Itertools;
use snarkvm::prelude::Testnet3;

mod execute;
pub use execute::{credits_execution, execution, verify_execution};

mod deploy;
pub use deploy::{generate_deployment, verify_deployment, Deployment, VerifyingKeyMap};

mod types;
pub use types::{Address as AddressBytes, RecordEntriesMap, UserInputValueType};

mod record;
// Rename to Record when we get rid of snarkVM's.
pub use record::{EncryptedRecord, Record};

mod transition;
pub use transition::Transition;

use crate::{
    build_function,
    helpers::{self, default_user_inputs},
    FunctionKeys,
};

pub type Address = snarkvm::prelude::Address<Testnet3>;
pub type Identifier = snarkvm::prelude::Identifier<Testnet3>;
pub type Program = snarkvm::prelude::Program<Testnet3>;
pub type ViewKey = snarkvm::prelude::ViewKey<Testnet3>;
// This should be ConstraintF in the future (revisit when commitment() returns ConstraintF).
pub type Field = String;
pub type ProgramID = String;
pub type VerifyingKey = simpleworks::marlin::VerifyingKey;
pub type PrivateKey = snarkvm::prelude::PrivateKey<Testnet3>;

type Function = snarkvm::prelude::Function<Testnet3>;

pub fn program_is_coinbase(program_id: &str, function_name: &str) -> bool {
    (function_name == "mint" || function_name == "genesis") && program_id == "credits.aleo"
}

pub fn credits() -> Result<Program> {
    let mut credits_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    credits_path.push("programs/credits.aleo");
    let program_string = std::fs::read_to_string(credits_path).map_err(|e| anyhow!("{}", e))?;
    generate_program(&program_string)
}

// Generates a program deployment for source transactions
pub fn generate_program(program_string: &str) -> Result<Program> {
    // Verify program is valid by parsing it and returning it
    Program::from_str(program_string)
}

/// Generate a credits record of the given amount for the given owner,
/// by using the given seed to deterministically generate a nonce.
pub fn mint_credits(owner_address: &Address, credits: u64) -> Result<(Field, EncryptedRecord)> {
    // TODO have someone verify/audit this, probably it's unsafe or breaks cryptographic assumptions

    let mut address = [0_u8; 63];
    let owner_address = owner_address.to_string();
    for (address_byte, owner_address_byte) in address.iter_mut().zip(owner_address.as_bytes()) {
        *address_byte = *owner_address_byte;
    }

    let non_encrypted_record = Record::new(address, credits, RecordEntriesMap::default(), None);

    Ok((non_encrypted_record.commitment()?, non_encrypted_record))
}

pub fn get_credits_key(function: &Function) -> Result<FunctionKeys> {
    let universal_srs = simpleworks::marlin::generate_universal_srs(&mut generate_rand())?;
    let constraint_system = ark_relations::r1cs::ConstraintSystem::<ConstraintF>::new_ref();
    build_function(
        function,
        &default_user_inputs(function)?,
        constraint_system,
        &universal_srs,
        &mut helpers::function_variables(function),
    )
}
