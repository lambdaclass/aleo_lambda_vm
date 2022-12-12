use std::str::FromStr;

use crate::variable_type::VariableType;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use snarkvm::prelude::Testnet3;

mod execute;
pub use execute::{credits_execution, generate_execution, verify_execution};

mod deploy;
pub use deploy::{generate_deployment, verify_deployment, Deployment, VerifyingKeyMap};

pub type Address = snarkvm::prelude::Address<Testnet3>;
pub type Identifier = snarkvm::prelude::Identifier<Testnet3>;
pub type Value = snarkvm::prelude::Value<Testnet3>;
pub type Program = snarkvm::prelude::Program<Testnet3>;
pub type Ciphertext = snarkvm::prelude::Ciphertext<Testnet3>;
pub type Record = snarkvm::prelude::Record<Testnet3, snarkvm::prelude::Plaintext<Testnet3>>;
pub type EncryptedRecord = snarkvm::prelude::Record<Testnet3, Ciphertext>;
pub type ViewKey = snarkvm::prelude::ViewKey<Testnet3>;
pub type PrivateKey = snarkvm::prelude::PrivateKey<Testnet3>;
pub type Field = snarkvm::prelude::Field<Testnet3>;
pub type Origin = snarkvm::prelude::Origin<Testnet3>;
pub type Output = snarkvm::prelude::Output<Testnet3>;
pub type ProgramID = snarkvm::prelude::ProgramID<Testnet3>;
pub type VerifyingKey = snarkvm::prelude::VerifyingKey<Testnet3>;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transition {
    // /// The transition ID.
    // id: String,
    /// The program ID.
    pub program_id: String,
    /// The function name.
    function_name: String,
    /// The transition inputs.
    inputs: Vec<VariableType>,
    /// The transition outputs.
    outputs: Vec<VariableType>,
    // /// The inputs for finalize.
    // finalize: Option<Vec<Value>>,
    /// The transition proof.
    proof: String,
    // /// The transition public key.
    // tpk: Group,
    // /// The transition commitment.
    // tcm: Field,
    /// The network fee.
    pub fee: i64,
}

impl Transition {
    pub fn output_records(&self) -> Vec<VariableType> {
        self.outputs
            .clone()
            .into_iter()
            .filter(|o| matches!(o, VariableType::Record(..)))
            .collect()
    }

    pub fn origins(&self) -> Vec<String> {
        self.input_records()
            .iter()
            .filter_map(|r| {
                if let VariableType::Record(_serial_number, origin, _record) = r {
                    Some(origin.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    fn input_records(&self) -> Vec<VariableType> {
        self.inputs
            .clone()
            .into_iter()
            .filter(|o| matches!(o, VariableType::Record(..)))
            .collect()
    }
}

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
