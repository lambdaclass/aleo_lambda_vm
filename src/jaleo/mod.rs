use std::str::FromStr;

use crate::ProgramBuild;
use anyhow::{anyhow, ensure, Result};
use ark_std::rand::rngs::StdRng;
use log::debug;
use serde::{Deserialize, Serialize};
use simpleworks::{
    marlin::{deserialize_proof, serialize_proof},
    types::value::SimpleworksValueType,
};
use snarkvm::prelude::{Identifier, Itertools, PrivateKey, Program, Testnet3};

const MAX_INPUTS: usize = 8;
const MAX_OUTPUTS: usize = 8;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum XXX {
    /// The plaintext hash and (optional) plaintext.
    // Constant(ConstraintF, SimpleworksValueType),
    /// The plaintext hash and (optional) plaintext.
    Public(String, SimpleworksValueType),
    /// The ciphertext hash and (optional) ciphertext.
    // Private(ConstraintF, Option<Ciphertext>),
    /// The serial number, and the origin of the record.
    Record(String, String),
    // The input commitment to the external record. Note: This is **not** the record commitment.
    // ExternalRecord(ConstraintF),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transition {
    // /// The transition ID.
    // id: String,
    /// The program ID.
    pub program_id: String,
    /// The function name.
    function_name: String,
    /// The transition inputs.
    inputs: Vec<XXX>,
    /// The transition outputs.
    outputs: Vec<XXX>,
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
    pub fn output_records(&self) -> Vec<XXX> {
        self.outputs.clone().into_iter().filter(|o| matches!(o, XXX::Record(..))).collect()
    }
    
    pub fn origins(&self) -> Vec<String> {
        self
            .input_records()
            .iter()
            .map(|r| {
                let XXX::Record(serial_number, origin) = r;
                origin.clone()
            })
            .collect()
    }

    fn input_records(&self) -> Vec<XXX> {
        self.inputs.clone().into_iter().filter(|o| matches!(o, XXX::Record(..))).collect()
    }
}

pub fn program_is_coinbase(program_id: &str, function_name: &str) -> bool {
    (function_name == "mint" || function_name == "genesis") && program_id == "credits.aleo"
}

pub fn verify_execution(transitions: &Vec<Transition>, program_build: &ProgramBuild) -> Result<()> {
    // Ensure the number of transitions matches the program function.
    ensure!(
        !transitions.is_empty(),
        "There are no transitions in the execution"
    );

    // Verify each transition.
    for transition in transitions {
        debug!(
            "Verifying transition for {}/{}...",
            transition.program_id, transition.function_name
        );
        // Ensure an external execution isn't attempting to create credits
        // The assumption at this point is that credits can only be created in the genesis block
        // We may revisit if we add validator rewards, at which point some credits may be minted, although
        // still not by external function calls
        ensure!(
            !program_is_coinbase(&transition.program_id, &transition.function_name),
            "Coinbase functions cannot be called"
        );
        // // Ensure the transition ID is correct.
        // ensure!(
        //     **transition == transition.to_root()?,
        //     "The transition ID is incorrect"
        // );
        // Ensure the number of inputs is within the allowed range.
        ensure!(
            transition.inputs.len() <= MAX_INPUTS,
            "Transition exceeded maximum number of inputs"
        );
        // Ensure the number of outputs is within the allowed range.
        ensure!(
            transition.outputs.len() <= MAX_OUTPUTS,
            "Transition exceeded maximum number of outputs"
        );
        // // Ensure each input is valid.
        // if transition
        //     .inputs
        //     .iter()
        //     .enumerate()
        //     .any(|(index, input)| !input.verify(transition.tcm(), index))
        // {
        //     bail!("Failed to verify a transition input")
        // }
        // // Ensure each output is valid.
        // let num_inputs = transition.inputs.len();
        // if transition
        //     .outputs
        //     .iter()
        //     .enumerate()
        //     .any(|(index, output)| !output.verify(transition.tcm(), num_inputs + index))
        // {
        //     bail!("Failed to verify a transition output")
        // }

        // Retrieve the verifying key.
        let (_proving_key, verifying_key) = program_build
            .get(&transition.function_name)
            .ok_or_else(|| anyhow!("missing verifying key"))?;

        // Decode and deserialize the proof.
        let proof_bytes = hex::decode(&transition.proof)?;
        let proof = deserialize_proof(proof_bytes)?;

        let inputs: Vec<SimpleworksValueType> = transition
            .inputs
            .iter()
            .filter_map(|i| {
                match i {
                    XXX::Public(_, value) => Some(value.clone()),
                    _ => None,
                }
            })
            .collect();

        // Ensure the proof is valid.
        ensure!(
            crate::verify_proof(
                verifying_key.clone(),
                &inputs,
                &proof,
                &mut simpleworks::marlin::generate_rand()
            )?,
            "Transition is invalid"
        );
    }
    Ok(())
}

pub fn credits() -> Result<Program<Testnet3>> {
    let mut credits_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    credits_path.push("programs/credits.aleo");
    let program_string = std::fs::read_to_string(credits_path).map_err(|e| anyhow!("{}", e))?;
    generate_program(&program_string)
}

pub fn credits_execution(
    function_name: Identifier<Testnet3>,
    inputs: &[SimpleworksValueType],
    private_key: &PrivateKey<Testnet3>,
    rng: &mut StdRng,
) -> Result<Vec<Transition>> {
    let credits_program = credits()?;
    execute(credits_program, function_name, inputs, private_key, rng)
}

// Generates a program deployment for source transactions
fn generate_program(program_string: &str) -> Result<Program<Testnet3>> {
    // Verify program is valid by parsing it and returning it
    Program::from_str(program_string)
}

pub fn generate_execution(
    program_str: &str,
    function_str: &str,
    inputs: &[SimpleworksValueType],
    private_key: &PrivateKey<Testnet3>,
    rng: &mut StdRng,
) -> Result<Vec<Transition>> {
    println!("Executing function {}...", function_str);

    let program_string = std::fs::read_to_string(program_str).map_err(|e| anyhow!("{}", e))?;
    let program = generate_program(&program_string)?;

    let function_name = Identifier::try_from(function_str).map_err(|e| anyhow!("{}", e))?;

    ensure!(
        program.contains_function(&function_name),
        "Function '{function_name}' does not exist."
    );

    debug!(
        "executing program {} function {} inputs {:?}",
        program, function_name, inputs
    );

    execute(program, function_name, inputs, private_key, rng)
}

fn execute(
    program: Program<Testnet3>,
    function_name: Identifier<Testnet3>,
    inputs: &[SimpleworksValueType],
    _private_key: &PrivateKey<Testnet3>,
    rng: &mut StdRng,
) -> Result<Vec<Transition>> {
    let function = program
        .get_function(&function_name)
        .map_err(|e| anyhow!("{}", e))?;

    let (outputs, proof) = crate::execute_function(&function, inputs, rng)?;

    let bytes_proof = serialize_proof(proof)?;
    let encoded_proof = hex::encode(bytes_proof);

    // TODO: Map SimpleworksValueType inputs to XXX
    // TODO: Map SimpleworksValueType outputs to XXX

    let transtition = Transition {
        program_id: program.id().to_string(),
        function_name: function_name.to_string(),
        inputs: inputs.to_vec(),
        outputs: outputs.into_values().collect_vec(),
        proof: encoded_proof,
        fee: 0,
    };

    Ok(vec![transtition])
}
