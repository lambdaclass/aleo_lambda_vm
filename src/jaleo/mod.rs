use std::str::FromStr;

use anyhow::{anyhow, Result};
use simpleworks::{
    marlin::serialization::{deserialize_proving_key, deserialize_verifying_key},
    types::value::RecordEntriesMap,
};
pub use snarkvm::prelude::Itertools;
use snarkvm::prelude::Testnet3;

mod execute;
pub use execute::{credits_execution, execution, verify_execution};

mod deploy;
pub use deploy::{generate_deployment, verify_deployment, Deployment, VerifyingKeyMap};

mod record;
// Rename to Record when we get rid of snarkVM's.
pub use record::Record as JAleoRecord;

mod transaction;
pub use transaction::Transaction;

mod transition;
pub use transition::Transition;

use crate::FunctionKeys;

pub type Address = snarkvm::prelude::Address<Testnet3>;
pub type Identifier = snarkvm::prelude::Identifier<Testnet3>;
pub type Value = snarkvm::prelude::Value<Testnet3>;
pub type Program = snarkvm::prelude::Program<Testnet3>;
pub type Ciphertext = snarkvm::prelude::Ciphertext<Testnet3>;
pub type Record = snarkvm::prelude::Record<Testnet3, snarkvm::prelude::Plaintext<Testnet3>>;
pub type EncryptedRecord = snarkvm::prelude::Record<Testnet3, Ciphertext>;
pub type ViewKey = snarkvm::prelude::ViewKey<Testnet3>;
pub type PrivateKey = snarkvm::prelude::PrivateKey<Testnet3>;
// This should be ConstraintF in the future (revisit when commitment() returns ConstraintF).
pub type Field = String;
pub type Origin = snarkvm::prelude::Origin<Testnet3>;
pub type Output = snarkvm::prelude::Output<Testnet3>;
pub type ProgramID = snarkvm::prelude::ProgramID<Testnet3>;
pub type VerifyingKey = simpleworks::marlin::VerifyingKey;

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
pub fn mint_credits(owner_address: &Address, credits: u64) -> Result<(Field, JAleoRecord)> {
    // TODO have someone verify/audit this, probably it's unsafe or breaks cryptographic assumptions

    let mut address = [0_u8; 63];
    let owner_address = owner_address.to_string();
    for (address_byte, owner_address_byte) in address.iter_mut().zip(owner_address.as_bytes()) {
        *address_byte = *owner_address_byte;
    }

    let non_encrypted_record = JAleoRecord::new(address, credits, RecordEntriesMap::default());

    Ok((non_encrypted_record.commitment()?, non_encrypted_record))
}

pub fn get_credits_key(function_name: &Identifier) -> Result<FunctionKeys> {
    let (bytes_proving_key, bytes_verifying_key) =
        snarkvm::parameters::testnet3::TESTNET3_CREDITS_PROGRAM
            .get(&function_name.to_string())
            .ok_or_else(|| anyhow!("Circuit keys for credits.aleo/{function_name}' not found"))?;

    let verifying_key = deserialize_verifying_key(bytes_verifying_key.to_vec())?;
    let proving_key = deserialize_proving_key(bytes_proving_key.to_vec())?;

    Ok((proving_key, verifying_key))
}
